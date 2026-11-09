/*
 * probe.c
 * Source probing used before or during recovery setup.
 *
 * The probe stays intentionally non-destructive: it classifies the input,
 * tries to resolve mounted sources back to their devices, and gathers
 * passive platform metadata that can help a human understand what Carv is
 * about to read.
 */

#define _POSIX_C_SOURCE 200809L

#include "probe.h"

#include "fs_backend.h"
#include "platform.h"
#include "reader.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <dirent.h>
#endif

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#define PROBE_MAX_STEPS 16U
#define PROBE_MAX_DETAIL 256U
#define PROBE_MAX_TEXT 8192U
#define PROBE_MAX_INVENTORY 8192U
#define PROBE_PATH_MAX 2048U
#define PROBE_COMMAND_TIMEOUT_SEC 15
#if defined(__GNUC__) || defined(__clang__)
#define PROBE_MAYBE_UNUSED __attribute__((unused))
#else
#define PROBE_MAYBE_UNUSED
#endif

typedef struct {
    char name[48];
    char outcome[12];
    char detail[PROBE_MAX_DETAIL];
} SourceProbeStep;

typedef struct {
    char requested_source[PROBE_PATH_MAX];
    char effective_source[PROBE_PATH_MAX];
    char platform_name[32];
    char classification[64];
    char summary[256];
    char model[128];
    char serial[128];
    char filesystem[64];
    char transport[64];
    char mountpoint[256];
    char by_id[512];
    char smart_status[64];
    char source_health[32];
    char source_health_detail[256];
    char media_type[32];
    char encryption_kind[64];
    char encryption_detail[256];
    char inventory_excerpt[PROBE_MAX_INVENTORY];
    uint64_t size_bytes;
    int source_given;
    int exists;
    int requested_was_directory;
    int is_directory;
    int is_regular_file;
    int is_block_device;
    int resolved_from_mount;
    int readable;
    int read_only;
    int smart_seen;
    int source_problem_detected;
    int rotational_known;
    int rotational;
    int encryption_detected;
    int encryption_locked;
    int encryption_unlocked;
    int soft_wake_attempted;
    int soft_wake_changed;
    SourceProbeStep steps[PROBE_MAX_STEPS];
    size_t step_count;
} SourceProbeReport;

static void snprintf_safe(char *out, size_t out_size, const char *fmt, ...);

static int has_nonempty_text_probe(const char *text)
{
    return text != NULL && text[0] != '\0';
}

static void sanitize_newlines(char *text)
{
    size_t i;

    if (text == NULL) {
        return;
    }

    for (i = 0; text[i] != '\0'; i++) {
        if (text[i] == '\r' || text[i] == '\n') {
            text[i] = ' ';
        }
    }
}

static void trim_trailing_whitespace(char *text)
{
    size_t length;

    if (text == NULL) {
        return;
    }

    length = strlen(text);
    while (length > 0U) {
        char ch = text[length - 1U];
        if (ch != ' ' && ch != '\t' && ch != '\r' && ch != '\n') {
            break;
        }
        text[length - 1U] = '\0';
        length--;
    }
}

static void trim_leading_whitespace(char *text)
{
    size_t start = 0U;
    size_t length;

    if (text == NULL) {
        return;
    }

    while (text[start] == ' ' || text[start] == '\t' ||
           text[start] == '\r' || text[start] == '\n') {
        start++;
    }
    if (start == 0U) {
        return;
    }
    length = strlen(text + start);
    memmove(text, text + start, length + 1U);
}

static void trim_whitespace(char *text)
{
    trim_trailing_whitespace(text);
    trim_leading_whitespace(text);
}

static int contains_ascii_case_insensitive_probe(
    const char *haystack,
    const char *needle
)
{
    size_t needle_length;
    const unsigned char *scan;

    if (haystack == NULL || needle == NULL || needle[0] == '\0') {
        return 0;
    }

    needle_length = strlen(needle);
    if (needle_length == 0U) {
        return 0;
    }

    for (scan = (const unsigned char *)haystack; *scan != '\0'; ++scan) {
        size_t index = 0U;

        while (index < needle_length &&
               scan[index] != '\0' &&
               tolower(scan[index]) == tolower((unsigned char)needle[index])) {
            index++;
        }
        if (index == needle_length) {
            return 1;
        }
    }

    return 0;
}

static int PROBE_MAYBE_UNUSED value_means_yes_probe(const char *text)
{
    return contains_ascii_case_insensitive_probe(text, "yes") ||
           contains_ascii_case_insensitive_probe(text, "true") ||
           contains_ascii_case_insensitive_probe(text, "locked");
}

static int PROBE_MAYBE_UNUSED value_means_no_probe(const char *text)
{
    return contains_ascii_case_insensitive_probe(text, "no") ||
           contains_ascii_case_insensitive_probe(text, "false");
}

static int PROBE_MAYBE_UNUSED parse_rotational_value_probe(const char *text, int *rotational_out)
{
    if (rotational_out != NULL) {
        *rotational_out = 0;
    }
    if (!has_nonempty_text_probe(text)) {
        return 0;
    }

    if (strcmp(text, "0") == 0 ||
        value_means_no_probe(text) ||
        contains_ascii_case_insensitive_probe(text, "solid") ||
        contains_ascii_case_insensitive_probe(text, "ssd") ||
        contains_ascii_case_insensitive_probe(text, "non-rotational")) {
        if (rotational_out != NULL) {
            *rotational_out = 0;
        }
        return 1;
    }

    if (strcmp(text, "1") == 0 ||
        value_means_yes_probe(text) ||
        contains_ascii_case_insensitive_probe(text, "rotational") ||
        contains_ascii_case_insensitive_probe(text, "hdd")) {
        if (rotational_out != NULL) {
            *rotational_out = 1;
        }
        return 1;
    }

    return 0;
}

static void set_probe_media_from_rotational(
    SourceProbeReport *report,
    int rotational
)
{
    if (report == NULL) {
        return;
    }

    report->rotational_known = 1;
    report->rotational = rotational ? 1 : 0;
    snprintf_safe(
        report->media_type,
        sizeof(report->media_type),
        "%s",
        rotational ? "HDD" : "SSD/non-rotational"
    );
}

static int probe_health_rank(const char *status)
{
    if (status == NULL) {
        return 0;
    }
    if (strcasecmp(status, "fail") == 0) {
        return 3;
    }
    if (strcasecmp(status, "warn") == 0) {
        return 2;
    }
    if (strcasecmp(status, "ok") == 0) {
        return 1;
    }
    return 0;
}

static void set_probe_health_state(
    SourceProbeReport *report,
    const char *status,
    const char *detail
)
{
    int current_rank;
    int new_rank;

    if (report == NULL || !has_nonempty_text_probe(status)) {
        return;
    }

    current_rank = probe_health_rank(report->source_health);
    new_rank = probe_health_rank(status);
    if (new_rank < current_rank) {
        return;
    }
    if (new_rank == current_rank &&
        has_nonempty_text_probe(report->source_health_detail) &&
        !has_nonempty_text_probe(detail)) {
        return;
    }

    snprintf_safe(
        report->source_health,
        sizeof(report->source_health),
        "%s",
        new_rank > 0 ? status : "unknown"
    );
    if (has_nonempty_text_probe(detail)) {
        snprintf_safe(
            report->source_health_detail,
            sizeof(report->source_health_detail),
            "%s",
            detail
        );
        sanitize_newlines(report->source_health_detail);
        trim_whitespace(report->source_health_detail);
    }
    if (new_rank >= 2) {
        report->source_problem_detected = 1;
    }
}

static void set_probe_encryption_state(
    SourceProbeReport *report,
    const char *kind,
    int locked,
    int unlocked,
    const char *detail
)
{
    int current_rank;
    int new_rank;

    if (report == NULL) {
        return;
    }

    current_rank = report->encryption_locked ? 3 :
                   report->encryption_detected ? 2 : 0;
    new_rank = locked ? 3 : 2;
    if (new_rank < current_rank) {
        return;
    }

    report->encryption_detected = 1;
    report->encryption_locked = locked ? 1 : 0;
    report->encryption_unlocked = (!locked && unlocked) ? 1 : 0;
    snprintf_safe(
        report->encryption_kind,
        sizeof(report->encryption_kind),
        "%s",
        has_nonempty_text_probe(kind) ? kind : "Encrypted source"
    );
    snprintf_safe(
        report->encryption_detail,
        sizeof(report->encryption_detail),
        "%s",
        has_nonempty_text_probe(detail)
            ? detail
            : (locked
                   ? "The selected source appears to be encrypted and locked."
                   : "The selected source appears to be encrypted.")
    );
}

static void snprintf_safe(char *out, size_t out_size, const char *fmt, ...)
{
    va_list args;

    if (out == NULL || out_size == 0U) {
        return;
    }

    va_start(args, fmt);
    vsnprintf(out, out_size, fmt, args);
    va_end(args);
}

static void shell_quote_single(const char *input, char *out, size_t out_size)
{
    size_t written = 0U;
    const char *cursor = input;

    if (out == NULL || out_size == 0U) {
        return;
    }

    out[0] = '\0';
    if (input == NULL) {
        return;
    }

    if (written + 1U < out_size) {
        out[written++] = '\'';
    }

    while (*cursor != '\0' && written + 1U < out_size) {
        if (*cursor == '\'') {
            static const char escaped[] = "'\\''";
            size_t j;
            for (j = 0U; j < sizeof(escaped) - 1U && written + 1U < out_size; j++) {
                out[written++] = escaped[j];
            }
        } else {
            out[written++] = *cursor;
        }
        cursor++;
    }

    if (written + 1U < out_size) {
        out[written++] = '\'';
    }
    out[written < out_size ? written : out_size - 1U] = '\0';
}

#ifdef __linux__
static int command_exists(const char *name)
{
    const char *path_env;
    char *paths;
    char *cursor;

    if (!has_nonempty_text_probe(name)) {
        return 0;
    }

    path_env = getenv("PATH");
    if (!has_nonempty_text_probe(path_env)) {
        return 0;
    }

    paths = strdup(path_env);
    if (paths == NULL) {
        return 0;
    }

    cursor = paths;
    while (cursor != NULL) {
        char *next = strchr(cursor, ':');
        char candidate[PATH_MAX];

        if (next != NULL) {
            *next = '\0';
            next++;
        }

        if (snprintf(candidate, sizeof(candidate), "%s/%s", cursor, name) < (int)sizeof(candidate) &&
            access(candidate, X_OK) == 0) {
            free(paths);
            return 1;
        }

        cursor = next;
    }

    free(paths);
    return 0;
}
#endif

static int run_command_capture(
    const char *command,
    char *output,
    size_t output_size,
    int *out_exit_status
)
{
    int pipefd[2] = {-1, -1};
    pid_t child_pid;
    size_t used = 0U;
    int status = 0;
    int child_exited = 0;
    int timed_out = 0;
    int read_eof = 0;
    time_t start_time;

    if (output != NULL && output_size > 0U) {
        output[0] = '\0';
    }
    if (out_exit_status != NULL) {
        *out_exit_status = -1;
    }
    if (!has_nonempty_text_probe(command)) {
        return 0;
    }

    if (pipe(pipefd) != 0) {
        return 0;
    }

    child_pid = fork();
    if (child_pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }

    if (child_pid == 0) {
        (void)setpgid(0, 0);
        (void)dup2(pipefd[1], STDOUT_FILENO);
        (void)dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execl("/bin/sh", "sh", "-c", command, (char *)NULL);
        _exit(127);
    }

    close(pipefd[1]);
    pipefd[1] = -1;
    (void)fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL, 0) | O_NONBLOCK);
    start_time = time(NULL);

    while (!child_exited || !read_eof) {
        fd_set readfds;
        struct timeval tv;
        int select_result;
        char buffer[512];
        ssize_t got;

        if (!child_exited) {
            pid_t wait_result = waitpid(child_pid, &status, WNOHANG);
            if (wait_result == child_pid) {
                child_exited = 1;
            } else if (wait_result < 0) {
                status = 127;
                child_exited = 1;
            }
        }

        if (!child_exited &&
            difftime(time(NULL), start_time) >= PROBE_COMMAND_TIMEOUT_SEC) {
            timed_out = 1;
            (void)kill(-child_pid, SIGKILL);
            (void)kill(child_pid, SIGKILL);
            (void)waitpid(child_pid, &status, 0);
            child_exited = 1;
            read_eof = 1;
            break;
        }

        FD_ZERO(&readfds);
        FD_SET(pipefd[0], &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        select_result = select(pipefd[0] + 1, &readfds, NULL, NULL, &tv);
        if (select_result <= 0 || !FD_ISSET(pipefd[0], &readfds)) {
            continue;
        }

        got = read(pipefd[0], buffer, sizeof(buffer));
        if (got == 0) {
            read_eof = 1;
            continue;
        }
        if (got < 0) {
            if (errno == EINTR || errno == EAGAIN) {
                continue;
            }
            read_eof = 1;
            continue;
        }

        if (output != NULL && output_size > 1U) {
            size_t remaining = output_size - used - 1U;
            size_t to_copy = (size_t)got < remaining ? (size_t)got : remaining;
            if (to_copy > 0U) {
                memcpy(output + used, buffer, to_copy);
                used += to_copy;
                output[used] = '\0';
            }
        }
    }

    close(pipefd[0]);

    if (out_exit_status != NULL) {
        if (timed_out) {
            *out_exit_status = 124;
        } else if (WIFEXITED(status)) {
            *out_exit_status = WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            *out_exit_status = 128 + WTERMSIG(status);
        } else {
            *out_exit_status = -1;
        }
    }

    return 1;
}

static int run_command_success(const char *command, char *output, size_t output_size)
{
    int exit_status = -1;

    if (!run_command_capture(command, output, output_size, &exit_status)) {
        return 0;
    }

    return exit_status == 0;
}

static void add_step(
    SourceProbeReport *report,
    const char *name,
    const char *outcome,
    const char *detail
)
{
    SourceProbeStep *step;

    if (report == NULL || report->step_count >= PROBE_MAX_STEPS) {
        return;
    }

    step = &report->steps[report->step_count++];
    snprintf_safe(step->name, sizeof(step->name), "%s", name != NULL ? name : "step");
    snprintf_safe(step->outcome, sizeof(step->outcome), "%s", outcome != NULL ? outcome : "info");
    snprintf_safe(step->detail, sizeof(step->detail), "%s", detail != NULL ? detail : "");
    sanitize_newlines(step->detail);
    trim_whitespace(step->detail);
}

static int ensure_directory_path_local(const char *path)
{
    char buffer[PATH_MAX];
    size_t i;

    if (!has_nonempty_text_probe(path)) {
        return 0;
    }
    if (strlen(path) >= sizeof(buffer)) {
        return 0;
    }
    if (!fs_backend_output_path_write_guard_allows(path)) {
        return 0;
    }

    snprintf(buffer, sizeof(buffer), "%s", path);
    trim_trailing_whitespace(buffer);

    for (i = 1U; buffer[i] != '\0'; i++) {
        if (buffer[i] == '/') {
            buffer[i] = '\0';
            if (!fs_backend_output_path_write_guard_allows(buffer)) {
                return 0;
            }
            if (buffer[0] != '\0' && mkdir(buffer, 0777) != 0 && errno != EEXIST) {
                return 0;
            }
            buffer[i] = '/';
        }
    }

    if (!fs_backend_output_path_write_guard_allows(buffer)) {
        return 0;
    }
    if (mkdir(buffer, 0777) != 0 && errno != EEXIST) {
        return 0;
    }

    return 1;
}

static int build_state_dir_path(const char *run_dir, char *out, size_t out_size)
{
    if (!has_nonempty_text_probe(run_dir) || out == NULL || out_size == 0U) {
        return 0;
    }

    if (snprintf(out, out_size, "%s/state", run_dir) >= (int)out_size) {
        return 0;
    }

    return ensure_directory_path_local(out);
}

static const char *yesno(int value)
{
    return value ? "yes" : "no";
}

static void format_size_human(uint64_t size_bytes, char *out, size_t out_size)
{
    static const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = (double)size_bytes;
    size_t unit = 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }

    while (value >= 1024.0 && unit + 1U < sizeof(units) / sizeof(units[0])) {
        value /= 1024.0;
        unit++;
    }

    if (unit == 0U) {
        snprintf_safe(out, out_size, "%llu %s",
                      (unsigned long long)size_bytes,
                      units[unit]);
    } else {
        snprintf_safe(out, out_size, "%.1f %s", value, units[unit]);
    }
}

static void json_write_escaped(FILE *file, const char *text)
{
    const unsigned char *cursor = (const unsigned char *)(text != NULL ? text : "");

    while (*cursor != '\0') {
        switch (*cursor) {
            case '\\': fputs("\\\\", file); break;
            case '"':  fputs("\\\"", file); break;
            case '\n': fputs("\\n", file); break;
            case '\r': fputs("\\r", file); break;
            case '\t': fputs("\\t", file); break;
            default:
                if (*cursor < 32U) {
                    fprintf(file, "\\u%04x", (unsigned int)*cursor);
                } else {
                    fputc((int)*cursor, file);
                }
                break;
        }
        cursor++;
    }
}

#ifdef __linux__
static void maybe_mark_probe_encryption_from_filesystem(
    SourceProbeReport *report,
    const char *filesystem_value,
    const char *origin
)
{
    char detail[PROBE_MAX_DETAIL];

    if (report == NULL || !has_nonempty_text_probe(filesystem_value)) {
        return;
    }

    if (contains_ascii_case_insensitive_probe(filesystem_value, "bitlocker") ||
        contains_ascii_case_insensitive_probe(filesystem_value, "fve")) {
        snprintf_safe(
            detail,
            sizeof(detail),
            "BitLocker signature reported by %s (%s)",
            has_nonempty_text_probe(origin) ? origin : "metadata",
            filesystem_value
        );
        set_probe_encryption_state(report, "BitLocker", 1, 0, detail);
        if (report->filesystem[0] == '\0') {
            snprintf_safe(report->filesystem, sizeof(report->filesystem), "%s", "BitLocker");
        }
        return;
    }

    if (contains_ascii_case_insensitive_probe(filesystem_value, "crypto_luks") ||
        contains_ascii_case_insensitive_probe(filesystem_value, "luks") ||
        contains_ascii_case_insensitive_probe(filesystem_value, "veracrypt")) {
        snprintf_safe(
            detail,
            sizeof(detail),
            "Encrypted container reported by %s (%s)",
            has_nonempty_text_probe(origin) ? origin : "metadata",
            filesystem_value
        );
        set_probe_encryption_state(report, "Encrypted container", 1, 0, detail);
    }
}

static void parse_key_value_row(
    const char *row,
    const char *key,
    char *out,
    size_t out_size
)
{
    char pattern[64];
    const char *hit;
    const char *value_start;
    const char *value_end;
    size_t length;

    if (!has_nonempty_text_probe(row) ||
        !has_nonempty_text_probe(key) ||
        out == NULL || out_size == 0U) {
        return;
    }

    snprintf_safe(pattern, sizeof(pattern), "%s=\"", key);
    hit = strstr(row, pattern);
    if (hit == NULL) {
        return;
    }

    value_start = hit + strlen(pattern);
    value_end = strchr(value_start, '"');
    if (value_end == NULL) {
        return;
    }

    length = (size_t)(value_end - value_start);
    if (length >= out_size) {
        length = out_size - 1U;
    }
    memcpy(out, value_start, length);
    out[length] = '\0';
}

static void parse_export_value(
    const char *text,
    const char *key,
    char *out,
    size_t out_size
)
{
    const char *cursor = text;
    size_t key_len;

    if (!has_nonempty_text_probe(text) ||
        !has_nonempty_text_probe(key) ||
        out == NULL || out_size == 0U) {
        return;
    }

    key_len = strlen(key);
    while (*cursor != '\0') {
        const char *line_end = strchr(cursor, '\n');
        size_t line_len = line_end != NULL ? (size_t)(line_end - cursor) : strlen(cursor);

        if (line_len > key_len + 1U &&
            strncmp(cursor, key, key_len) == 0 &&
            cursor[key_len] == '=') {
            size_t copy_len = line_len - key_len - 1U;
            if (copy_len >= out_size) {
                copy_len = out_size - 1U;
            }
            memcpy(out, cursor + key_len + 1U, copy_len);
            out[copy_len] = '\0';
            return;
        }

        if (line_end == NULL) {
            break;
        }
        cursor = line_end + 1U;
    }
}
#endif

static void PROBE_MAYBE_UNUSED parse_colon_value(
    const char *text,
    const char *key,
    char *out,
    size_t out_size
)
{
    const char *cursor = text;
    size_t key_len;

    if (!has_nonempty_text_probe(text) ||
        !has_nonempty_text_probe(key) ||
        out == NULL || out_size == 0U) {
        return;
    }

    key_len = strlen(key);
    while (*cursor != '\0') {
        const char *line_end = strchr(cursor, '\n');
        size_t line_len = line_end != NULL ? (size_t)(line_end - cursor) : strlen(cursor);
        const char *colon = memchr(cursor, ':', line_len);

        if (colon != NULL) {
            const char *line_key_start = cursor;
            const char *line_key_end = colon;
            const char *value_start = colon + 1;
            const char *value_end = cursor + line_len;
            size_t copy_len;

            while (line_key_start < line_key_end &&
                   (*line_key_start == ' ' || *line_key_start == '\t')) {
                line_key_start++;
            }
            while (line_key_end > line_key_start &&
                   (line_key_end[-1] == ' ' || line_key_end[-1] == '\t')) {
                line_key_end--;
            }

            if ((size_t)(line_key_end - line_key_start) == key_len &&
                strncasecmp(line_key_start, key, key_len) == 0) {
                while (value_start < value_end &&
                       (*value_start == ' ' || *value_start == '\t')) {
                    value_start++;
                }
                while (value_end > value_start &&
                       (value_end[-1] == ' ' || value_end[-1] == '\t' ||
                        value_end[-1] == '\r')) {
                    value_end--;
                }

                copy_len = (size_t)(value_end - value_start);
                if (copy_len >= out_size) {
                    copy_len = out_size - 1U;
                }
                memcpy(out, value_start, copy_len);
                out[copy_len] = '\0';
                return;
            }
        }

        if (line_end == NULL) {
            break;
        }
        cursor = line_end + 1U;
    }
}

static uint32_t read_u32_le_probe(const unsigned char *data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint64_t read_u64_le_probe(const unsigned char *data)
{
    return (uint64_t)read_u32_le_probe(data) |
           ((uint64_t)read_u32_le_probe(data + 4U) << 32);
}

static int read_bytes_from_source_path_probe(
    const char *path,
    uint64_t absolute_offset,
    void *buffer,
    size_t buffer_size
)
{
    FILE *file;
    int ok = 0;

    if (!has_nonempty_text_probe(path) || buffer == NULL || buffer_size == 0U) {
        return 0;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }

    if (absolute_offset <= (uint64_t)LLONG_MAX &&
        fseeko(file, (off_t)absolute_offset, SEEK_SET) == 0 &&
        fread(buffer, 1, buffer_size, file) == buffer_size) {
        ok = 1;
    }

    fclose(file);
    return ok;
}

static int sector_has_valid_signature_probe(
    const unsigned char *sector,
    size_t length
)
{
    return sector != NULL &&
           length >= 512U &&
           sector[510] == 0x55U &&
           sector[511] == 0xAAU;
}

static int sector_has_bitlocker_signature_probe(
    const unsigned char *sector,
    size_t length
)
{
    return sector != NULL &&
           length >= 11U &&
           memcmp(sector + 3U, "-FVE-FS-", 8U) == 0;
}

static void sniff_raw_encryption_signatures(SourceProbeReport *report)
{
    unsigned char sector[512];
    char detail[PROBE_MAX_DETAIL];
    int i;

    if (report == NULL ||
        (!report->is_regular_file && !report->is_block_device) ||
        !has_nonempty_text_probe(report->effective_source)) {
        return;
    }

    if (!read_bytes_from_source_path_probe(
            report->effective_source,
            0U,
            sector,
            sizeof(sector))) {
        return;
    }

    if (sector_has_bitlocker_signature_probe(sector, sizeof(sector))) {
        snprintf_safe(
            detail,
            sizeof(detail),
            "%s",
            "BitLocker signature (-FVE-FS-) found at the source volume start"
        );
        set_probe_encryption_state(report, "BitLocker", 1, 0, detail);
        return;
    }

    if (sector_has_valid_signature_probe(sector, sizeof(sector))) {
        for (i = 0; i < 4; ++i) {
            const unsigned char *entry = sector + 446U + ((size_t)i * 16U);
            uint32_t start_lba = read_u32_le_probe(entry + 8U);
            uint32_t sector_count = read_u32_le_probe(entry + 12U);
            uint64_t partition_offset;

            if (entry[4] == 0x00U || start_lba == 0U || sector_count == 0U) {
                continue;
            }
            partition_offset = (uint64_t)start_lba * 512U;
            if (!read_bytes_from_source_path_probe(
                    report->effective_source,
                    partition_offset,
                    sector,
                    sizeof(sector))) {
                continue;
            }
            if (sector_has_bitlocker_signature_probe(sector, sizeof(sector))) {
                snprintf_safe(
                    detail,
                    sizeof(detail),
                    "BitLocker signature (-FVE-FS-) found in MBR partition %d at byte %llu",
                    i + 1,
                    (unsigned long long)partition_offset
                );
                set_probe_encryption_state(report, "BitLocker", 1, 0, detail);
                return;
            }
        }
    }

    if (read_bytes_from_source_path_probe(
            report->effective_source,
            512U,
            sector,
            sizeof(sector)) &&
        memcmp(sector, "EFI PART", 8U) == 0) {
        uint64_t entries_lba = read_u64_le_probe(sector + 72U);
        uint32_t entry_count = read_u32_le_probe(sector + 80U);
        uint32_t entry_size = read_u32_le_probe(sector + 84U);
        unsigned char partition_entry[512];

        if (entries_lba != 0U &&
            entry_count > 0U &&
            entry_size >= 128U &&
            entry_size <= sizeof(partition_entry)) {
            uint32_t limit = entry_count > 256U ? 256U : entry_count;

            for (i = 0; i < (int)limit; ++i) {
                uint64_t entry_offset =
                    (entries_lba * 512U) + ((uint64_t)(uint32_t)i * entry_size);
                uint64_t first_lba;
                uint64_t partition_offset;

                if (!read_bytes_from_source_path_probe(
                        report->effective_source,
                        entry_offset,
                        partition_entry,
                        entry_size)) {
                    continue;
                }
                if (memcmp(partition_entry, "\0\0\0\0\0\0\0\0", 8U) == 0 &&
                    memcmp(partition_entry + 8U, "\0\0\0\0\0\0\0\0", 8U) == 0) {
                    continue;
                }

                first_lba = read_u64_le_probe(partition_entry + 32U);
                if (first_lba == 0U) {
                    continue;
                }
                partition_offset = first_lba * 512U;
                if (!read_bytes_from_source_path_probe(
                        report->effective_source,
                        partition_offset,
                        sector,
                        sizeof(sector))) {
                    continue;
                }
                if (sector_has_bitlocker_signature_probe(sector, sizeof(sector))) {
                    snprintf_safe(
                        detail,
                        sizeof(detail),
                        "BitLocker signature (-FVE-FS-) found in GPT partition %d at byte %llu",
                        i + 1,
                        (unsigned long long)partition_offset
                    );
                    set_probe_encryption_state(report, "BitLocker", 1, 0, detail);
                    return;
                }
            }
        }
    }
}

static void stat_source_path(SourceProbeReport *report, const char *path)
{
    struct stat st;

    if (report == NULL || !has_nonempty_text_probe(path)) {
        return;
    }

    if (stat(path, &st) != 0) {
        report->exists = 0;
        return;
    }

    report->exists = 1;
    report->is_directory = S_ISDIR(st.st_mode);
    if (strcmp(path, report->requested_source) == 0 && report->is_directory) {
        report->requested_was_directory = 1;
    }
    report->is_regular_file = S_ISREG(st.st_mode);
    report->is_block_device =
        S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode);
    if ((report->is_regular_file || report->is_block_device) && st.st_size > 0) {
        report->size_bytes = (uint64_t)st.st_size;
    }
    report->read_only = access(path, W_OK) != 0;
}

static void resolve_effective_source(SourceProbeReport *report)
{
    char resolved_device[PROBE_PATH_MAX];

    if (report == NULL || !report->source_given) {
        return;
    }

    snprintf_safe(report->effective_source,
                  sizeof(report->effective_source),
                  "%s",
                  report->requested_source);
    stat_source_path(report, report->requested_source);
    if (!report->is_directory) {
        return;
    }

    if (reader_resolve_mounted_source_device(
            report->requested_source,
            resolved_device,
            sizeof(resolved_device))) {
        report->resolved_from_mount = 1;
        snprintf_safe(report->effective_source,
                      sizeof(report->effective_source),
                      "%s",
                      resolved_device);
        stat_source_path(report, report->effective_source);
        add_step(report,
                 "resolve_mounted_source",
                 "ok",
                 "Resolved mounted source to backing device");
    } else {
        add_step(report,
                 "resolve_mounted_source",
                 "fail",
                 reader_last_error());
    }
}

 #ifdef __linux__
static void collect_inventory_linux(SourceProbeReport *report)
{
    char output[PROBE_MAX_INVENTORY];
    const char *command =
        "lsblk -P -b -n -o PATH,SIZE,FSTYPE,TYPE,MOUNTPOINT,LABEL,MODEL,SERIAL,RO,TRAN,HOTPLUG,ROTA 2>/dev/null";
    const char *fallback_command =
        "lsblk -P -b -n -o PATH,SIZE,FSTYPE,TYPE,MOUNTPOINT,LABEL,MODEL,SERIAL,RO,TRAN,HOTPLUG 2>/dev/null";

    if (run_command_success(command, output, sizeof(output)) ||
        run_command_success(fallback_command, output, sizeof(output))) {
        snprintf_safe(report->inventory_excerpt,
                      sizeof(report->inventory_excerpt),
                      "%s",
                      output);
        trim_whitespace(report->inventory_excerpt);
        add_step(report, "passive_inventory", "ok", "Collected lsblk inventory");
    } else {
        add_step(report, "passive_inventory", "fail", "lsblk inventory failed");
    }
}
#endif

#ifdef __APPLE__
static void collect_inventory_macos(SourceProbeReport *report)
{
    char output[PROBE_MAX_INVENTORY];

    if (run_command_success("diskutil list 2>/dev/null", output, sizeof(output))) {
        snprintf_safe(report->inventory_excerpt,
                      sizeof(report->inventory_excerpt),
                      "%s",
                      output);
        trim_whitespace(report->inventory_excerpt);
        add_step(report, "passive_inventory", "ok", "Collected diskutil inventory");
    } else {
        add_step(report, "passive_inventory", "fail", "diskutil inventory failed");
    }
}
#endif

#ifdef __linux__
/*
 * Linux probing is split by data source so missing tools degrade
 * gracefully: `lsblk` gives the broad shape, `blkid` adds filesystem
 * hints, `udevadm` contributes stable identifiers, and `smartctl`
 * advertises whether SMART can see the device at all.
 */
static void collect_linux_device_info_from_lsblk(
    SourceProbeReport *report,
    const char *quoted_path
)
{
    char command[PROBE_PATH_MAX + 256];
    char output[2048];
    char value[512];

    if (report == NULL || !has_nonempty_text_probe(quoted_path)) {
        return;
    }

    snprintf_safe(
        command,
        sizeof(command),
        "lsblk -P -b -n -o PATH,SIZE,FSTYPE,TYPE,MOUNTPOINT,LABEL,MODEL,SERIAL,RO,TRAN,HOTPLUG,ROTA %s 2>/dev/null",
        quoted_path
    );

    if (!run_command_success(command, output, sizeof(output))) {
        snprintf_safe(
            command,
            sizeof(command),
            "lsblk -P -b -n -o PATH,SIZE,FSTYPE,TYPE,MOUNTPOINT,LABEL,MODEL,SERIAL,RO,TRAN,HOTPLUG %s 2>/dev/null",
            quoted_path
        );
        if (!run_command_success(command, output, sizeof(output))) {
            add_step(report, "lsblk_device", "fail", "Could not inspect device with lsblk");
            return;
        }
    }

    value[0] = '\0';
    parse_key_value_row(output, "SIZE", value, sizeof(value));
    if (value[0] != '\0') {
        report->size_bytes = strtoull(value, NULL, 10);
    }

    value[0] = '\0';
    parse_key_value_row(output, "FSTYPE", value, sizeof(value));
    if (value[0] != '\0') {
        snprintf_safe(report->filesystem, sizeof(report->filesystem), "%s", value);
        maybe_mark_probe_encryption_from_filesystem(report, value, "lsblk FSTYPE");
    }

    value[0] = '\0';
    parse_key_value_row(output, "MOUNTPOINT", value, sizeof(value));
    if (value[0] != '\0') {
        snprintf_safe(report->mountpoint, sizeof(report->mountpoint), "%s", value);
    }

    value[0] = '\0';
    parse_key_value_row(output, "MODEL", value, sizeof(value));
    if (value[0] != '\0') {
        snprintf_safe(report->model, sizeof(report->model), "%s", value);
    }

    value[0] = '\0';
    parse_key_value_row(output, "SERIAL", value, sizeof(value));
    if (value[0] != '\0') {
        snprintf_safe(report->serial, sizeof(report->serial), "%s", value);
    }

    value[0] = '\0';
    parse_key_value_row(output, "RO", value, sizeof(value));
    if (strcmp(value, "1") == 0) {
        report->read_only = 1;
    }

    value[0] = '\0';
    parse_key_value_row(output, "TRAN", value, sizeof(value));
    if (value[0] != '\0') {
        snprintf_safe(report->transport, sizeof(report->transport), "%s", value);
    }

    value[0] = '\0';
    parse_key_value_row(output, "ROTA", value, sizeof(value));
    {
        int rotational = 0;
        if (parse_rotational_value_probe(value, &rotational)) {
            set_probe_media_from_rotational(report, rotational);
        }
    }

    add_step(report, "lsblk_device", "ok", "Collected device details from lsblk");
}

static void collect_linux_device_info_from_blkid(
    SourceProbeReport *report,
    const char *quoted_path
)
{
    char command[PROBE_PATH_MAX + 256];
    char output[2048];
    char value[512];

    if (report == NULL || !has_nonempty_text_probe(quoted_path)) {
        return;
    }

    if (!command_exists("blkid")) {
        add_step(report, "blkid", "skip", "blkid is not installed");
        return;
    }

    snprintf_safe(command, sizeof(command), "blkid -o export %s 2>/dev/null", quoted_path);
    if (!run_command_success(command, output, sizeof(output))) {
        add_step(report, "blkid", "fail", "blkid did not identify this device");
        return;
    }

    value[0] = '\0';
    parse_export_value(output, "TYPE", value, sizeof(value));
    if (value[0] != '\0' && report->filesystem[0] == '\0') {
        snprintf_safe(report->filesystem, sizeof(report->filesystem), "%s", value);
    }
    if (value[0] != '\0') {
        maybe_mark_probe_encryption_from_filesystem(report, value, "blkid TYPE");
    }

    add_step(report, "blkid", "ok", "Collected blkid metadata");
}

static void collect_linux_device_info_from_udevadm(
    SourceProbeReport *report,
    const char *quoted_path
)
{
    char command[PROBE_PATH_MAX + 256];
    char output[2048];
    char value[512];

    if (report == NULL || !has_nonempty_text_probe(quoted_path)) {
        return;
    }

    if (!command_exists("udevadm")) {
        add_step(report, "udevadm_info", "skip", "udevadm is not installed");
        return;
    }

    snprintf_safe(
        command,
        sizeof(command),
        "udevadm info --query=property --name %s 2>/dev/null",
        quoted_path
    );
    if (!run_command_success(command, output, sizeof(output))) {
        add_step(report, "udevadm_info", "fail", "udevadm info failed");
        return;
    }

    value[0] = '\0';
    parse_export_value(output, "ID_MODEL", value, sizeof(value));
    if (value[0] != '\0' && report->model[0] == '\0') {
        snprintf_safe(report->model, sizeof(report->model), "%s", value);
    }

    value[0] = '\0';
    parse_export_value(output, "ID_SERIAL_SHORT", value, sizeof(value));
    if (value[0] != '\0' && report->serial[0] == '\0') {
        snprintf_safe(report->serial, sizeof(report->serial), "%s", value);
    }

    value[0] = '\0';
    parse_export_value(output, "ID_BUS", value, sizeof(value));
    if (value[0] != '\0' && report->transport[0] == '\0') {
        snprintf_safe(report->transport, sizeof(report->transport), "%s", value);
    }

    value[0] = '\0';
    parse_export_value(output, "DEVLINKS", value, sizeof(value));
    if (value[0] != '\0') {
        snprintf_safe(report->by_id, sizeof(report->by_id), "%s", value);
    }

    value[0] = '\0';
    parse_export_value(output, "ID_FS_TYPE", value, sizeof(value));
    if (value[0] != '\0') {
        if (report->filesystem[0] == '\0') {
            snprintf_safe(report->filesystem, sizeof(report->filesystem), "%s", value);
        }
        maybe_mark_probe_encryption_from_filesystem(report, value, "udevadm ID_FS_TYPE");
    }

    add_step(report, "udevadm_info", "ok", "Collected udev properties");
}

static int last_unsigned_number_in_line_probe(
    const char *line,
    unsigned long long *value_out
)
{
    const char *cursor;
    unsigned long long last_value = 0ULL;
    int found = 0;

    if (value_out != NULL) {
        *value_out = 0ULL;
    }
    if (line == NULL) {
        return 0;
    }

    cursor = line;
    while (*cursor != '\0') {
        if (isdigit((unsigned char)*cursor)) {
            char *endptr = NULL;
            int base = (cursor[0] == '0' && (cursor[1] == 'x' || cursor[1] == 'X')) ? 0 : 10;
            last_value = strtoull(cursor, &endptr, base);
            found = 1;
            cursor = (endptr != NULL && endptr > cursor) ? endptr : cursor + 1;
        } else {
            cursor++;
        }
    }

    if (found && value_out != NULL) {
        *value_out = last_value;
    }
    return found;
}

static int smart_count_line_has_value_probe(
    const char *line,
    const char *needle,
    unsigned long long *value_out
)
{
    unsigned long long value = 0ULL;

    if (!contains_ascii_case_insensitive_probe(line, needle)) {
        return 0;
    }
    if (!last_unsigned_number_in_line_probe(line, &value)) {
        return 0;
    }
    if (value_out != NULL) {
        *value_out = value;
    }
    return value > 0ULL;
}

static int smart_line_indicates_good_health_probe(const char *line)
{
    return contains_ascii_case_insensitive_probe(line, "PASSED") ||
           contains_ascii_case_insensitive_probe(line, "Verified") ||
           contains_ascii_case_insensitive_probe(line, "OK");
}

static int smart_line_indicates_bad_health_probe(const char *line)
{
    return contains_ascii_case_insensitive_probe(line, "FAILED") ||
           contains_ascii_case_insensitive_probe(line, "FAILING") ||
           contains_ascii_case_insensitive_probe(line, "BAD");
}

static void note_smart_counter_problem_probe(
    SourceProbeReport *report,
    const char *line,
    const char *needle,
    const char *label,
    char *first_detail,
    size_t first_detail_size
)
{
    unsigned long long value = 0ULL;

    if (!smart_count_line_has_value_probe(line, needle, &value)) {
        return;
    }

    if (first_detail != NULL && first_detail_size > 0U && first_detail[0] == '\0') {
        snprintf_safe(
            first_detail,
            first_detail_size,
            "SMART reports %s = %llu",
            label,
            value
        );
    }
    set_probe_health_state(report, "warn", first_detail);
}

static void analyze_smart_output_probe(SourceProbeReport *report, char *output)
{
    char *cursor;
    int saw_good_health = 0;
    int saw_smart_content = 0;
    char first_warning[PROBE_MAX_DETAIL];

    if (report == NULL || output == NULL) {
        return;
    }

    first_warning[0] = '\0';
    cursor = output;
    while (cursor != NULL && *cursor != '\0') {
        char *line_end = strchr(cursor, '\n');
        char *next = NULL;
        char *line = cursor;

        if (line_end != NULL) {
            *line_end = '\0';
            next = line_end + 1;
        }
        trim_whitespace(line);

        if (contains_ascii_case_insensitive_probe(line, "SMART") ||
            contains_ascii_case_insensitive_probe(line, "Reallocated") ||
            contains_ascii_case_insensitive_probe(line, "Pending") ||
            contains_ascii_case_insensitive_probe(line, "Uncorrectable") ||
            contains_ascii_case_insensitive_probe(line, "Critical Warning")) {
            saw_smart_content = 1;
        }

        if (contains_ascii_case_insensitive_probe(line, "overall-health") ||
            contains_ascii_case_insensitive_probe(line, "self-assessment") ||
            contains_ascii_case_insensitive_probe(line, "SMART Health Status")) {
            if (smart_line_indicates_bad_health_probe(line)) {
                set_probe_health_state(report, "fail", "SMART reports failing overall health");
                snprintf_safe(report->smart_status, sizeof(report->smart_status), "%s", "SMART health FAILED");
            } else if (smart_line_indicates_good_health_probe(line)) {
                saw_good_health = 1;
            }
        }

        if (contains_ascii_case_insensitive_probe(line, "Critical Warning")) {
            unsigned long long value = 0ULL;
            if (last_unsigned_number_in_line_probe(line, &value) && value > 0ULL) {
                snprintf_safe(
                    first_warning,
                    sizeof(first_warning),
                    "%s",
                    "SMART/NVMe critical warning is non-zero"
                );
                set_probe_health_state(report, "warn", first_warning);
            }
        }

        note_smart_counter_problem_probe(report, line, "Reallocated_Sector_Ct", "reallocated sectors", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "Reallocated_Event_Count", "reallocation events", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "Current_Pending_Sector", "pending sectors", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "Offline_Uncorrectable", "offline uncorrectable sectors", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "Reported_Uncorrect", "reported uncorrectable errors", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "Command_Timeout", "command timeouts", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "UDMA_CRC_Error_Count", "UDMA CRC errors", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "CRC_Error_Count", "CRC errors", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "Media and Data Integrity Errors", "media/data integrity errors", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "Error Information Log Entries", "NVMe error log entries", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "ATA Error Count", "ATA error log entries", first_warning, sizeof(first_warning));
        note_smart_counter_problem_probe(report, line, "Elements in grown defect list", "grown defect list entries", first_warning, sizeof(first_warning));

        if (contains_ascii_case_insensitive_probe(line, "Percentage Used")) {
            unsigned long long value = 0ULL;
            if (last_unsigned_number_in_line_probe(line, &value) && value >= 90ULL) {
                snprintf_safe(
                    first_warning,
                    sizeof(first_warning),
                    "SMART reports SSD percentage used = %llu%%",
                    value
                );
                set_probe_health_state(report, "warn", first_warning);
            }
        }

        if (contains_ascii_case_insensitive_probe(line, "Available Spare") &&
            !contains_ascii_case_insensitive_probe(line, "Threshold")) {
            unsigned long long value = 0ULL;
            if (last_unsigned_number_in_line_probe(line, &value) && value < 10ULL) {
                snprintf_safe(
                    first_warning,
                    sizeof(first_warning),
                    "SMART reports low NVMe available spare = %llu%%",
                    value
                );
                set_probe_health_state(report, "warn", first_warning);
            }
        }

        cursor = next;
    }

    if (report->source_problem_detected) {
        if (strcmp(report->smart_status, "SMART health FAILED") != 0) {
            snprintf_safe(report->smart_status, sizeof(report->smart_status), "%s", "SMART attributes warn");
        }
        return;
    }

    if (saw_good_health) {
        snprintf_safe(report->smart_status, sizeof(report->smart_status), "%s", "SMART health PASSED");
        set_probe_health_state(
            report,
            "ok",
            "SMART overall health passed; this is not a full guarantee."
        );
    } else if (saw_smart_content && !has_nonempty_text_probe(report->smart_status)) {
        snprintf_safe(report->smart_status, sizeof(report->smart_status), "%s", "SMART queried");
    }
}

static int span_contains_text_probe(
    const char *text,
    size_t text_len,
    const char *needle
)
{
    size_t needle_len;
    size_t i;

    if (text == NULL || needle == NULL) {
        return 0;
    }

    needle_len = strlen(needle);
    if (needle_len == 0U || needle_len > text_len) {
        return 0;
    }

    for (i = 0U; i + needle_len <= text_len; i++) {
        if (memcmp(text + i, needle, needle_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static int extract_smart_device_type_from_scan_probe(
    const char *scan_output,
    const char *source_path,
    char *out,
    size_t out_size
)
{
    const char *base;
    const char *cursor;

    if (out != NULL && out_size > 0U) {
        out[0] = '\0';
    }
    if (!has_nonempty_text_probe(scan_output) ||
        !has_nonempty_text_probe(source_path) ||
        out == NULL || out_size == 0U) {
        return 0;
    }

    base = strrchr(source_path, '/');
    base = base != NULL ? base + 1 : source_path;
    cursor = scan_output;
    while (*cursor != '\0') {
        const char *line_end = strchr(cursor, '\n');
        size_t line_len = line_end != NULL ? (size_t)(line_end - cursor) : strlen(cursor);

        if (span_contains_text_probe(cursor, line_len, source_path) ||
            (has_nonempty_text_probe(base) &&
             span_contains_text_probe(cursor, line_len, base))) {
            size_t i;
            for (i = 0U; i + 3U <= line_len; i++) {
                if (memcmp(cursor + i, "-d ", 3U) != 0) {
                    continue;
                }
                {
                    const char *type_start = cursor + i + 3U;
                    const char *type_end = type_start;
                    size_t copy_len;

                    while (type_end < cursor + line_len &&
                           *type_end != ' ' && *type_end != '\t' && *type_end != '#') {
                        type_end++;
                    }
                    copy_len = (size_t)(type_end - type_start);
                    if (copy_len > 0U) {
                        if (copy_len >= out_size) {
                            copy_len = out_size - 1U;
                        }
                        memcpy(out, type_start, copy_len);
                        out[copy_len] = '\0';
                        return 1;
                    }
                }
            }
        }

        if (line_end == NULL) {
            break;
        }
        cursor = line_end + 1;
    }

    return 0;
}

static int smart_output_has_meaning_probe(const char *output)
{
    return contains_ascii_case_insensitive_probe(output, "SMART") ||
           contains_ascii_case_insensitive_probe(output, "Reallocated") ||
           contains_ascii_case_insensitive_probe(output, "Critical Warning") ||
           contains_ascii_case_insensitive_probe(output, "NVMe");
}

static int query_smart_health_probe(
    SourceProbeReport *report,
    const char *device_type
)
{
    char command[PROBE_PATH_MAX * 2U + 256];
    char quoted_path[PROBE_PATH_MAX * 2U];
    char quoted_type[128];
    char output[16384];
    const char *timeout_prefix;
    int exit_status = -1;

    if (report == NULL || !has_nonempty_text_probe(report->effective_source)) {
        return 0;
    }

    shell_quote_single(report->effective_source, quoted_path, sizeof(quoted_path));
    timeout_prefix = command_exists("timeout") ? "timeout 8 " : "";
    if (has_nonempty_text_probe(device_type)) {
        shell_quote_single(device_type, quoted_type, sizeof(quoted_type));
        snprintf_safe(
            command,
            sizeof(command),
            "%ssmartctl -H -A -d %s %s 2>&1",
            timeout_prefix,
            quoted_type,
            quoted_path
        );
    } else {
        snprintf_safe(
            command,
            sizeof(command),
            "%ssmartctl -H -A %s 2>&1",
            timeout_prefix,
            quoted_path
        );
    }

    output[0] = '\0';
    if (!run_command_capture(command, output, sizeof(output), &exit_status)) {
        return 0;
    }

    if (!smart_output_has_meaning_probe(output)) {
        return 0;
    }

    analyze_smart_output_probe(report, output);
    return 1;
}

static void collect_linux_device_info_from_smartctl(SourceProbeReport *report)
{
    char output[8192];
    char device_type[64];
#ifdef PATH_MAX
    char resolved_source[PATH_MAX];
#else
    char resolved_source[PROBE_PATH_MAX];
#endif
    const char *base;
    int advertised = 0;
    int health_queried = 0;

    if (report == NULL || !has_nonempty_text_probe(report->effective_source)) {
        return;
    }

    if (!command_exists("smartctl")) {
        add_step(report, "smart_scan", "skip", "smartctl is not installed");
        return;
    }

    if (!run_command_success("smartctl --scan-open 2>/dev/null", output, sizeof(output))) {
        add_step(report, "smart_scan", "fail", "smartctl --scan-open failed");
        output[0] = '\0';
    }

    base = strrchr(report->effective_source, '/');
    base = base != NULL ? base + 1 : report->effective_source;
    if (strstr(output, report->effective_source) != NULL ||
        strstr(output, base) != NULL) {
        advertised = 1;
        report->smart_seen = 1;
        snprintf_safe(
            report->smart_status,
            sizeof(report->smart_status),
            "%s",
            "scan-open detected"
        );
    } else {
        snprintf_safe(
            report->smart_status,
            sizeof(report->smart_status),
            "%s",
            "smartctl present, device not advertised"
        );
    }

    add_step(
        report,
        "smart_scan",
        output[0] != '\0' ? "ok" : "fail",
        output[0] != '\0'
            ? "Collected smartctl scan-open inventory"
            : "smartctl --scan-open produced no usable inventory"
    );

    device_type[0] = '\0';
    resolved_source[0] = '\0';
    if (realpath(report->effective_source, resolved_source) == NULL) {
        resolved_source[0] = '\0';
    }
    if (advertised) {
        (void)extract_smart_device_type_from_scan_probe(
            output,
            report->effective_source,
            device_type,
            sizeof(device_type)
        );
        if (!has_nonempty_text_probe(device_type) &&
            has_nonempty_text_probe(resolved_source)) {
            (void)extract_smart_device_type_from_scan_probe(
                output,
                resolved_source,
                device_type,
                sizeof(device_type)
            );
        }
    }

    if (has_nonempty_text_probe(device_type)) {
        health_queried = query_smart_health_probe(report, device_type);
    }
    if (!health_queried) {
        health_queried = query_smart_health_probe(report, NULL);
    }
    if (!health_queried &&
        contains_ascii_case_insensitive_probe(report->transport, "usb")) {
        health_queried = query_smart_health_probe(report, "sat");
    }
    add_step(
        report,
        "smart_health",
        health_queried ? (report->source_problem_detected ? "warn" : "ok") : "fail",
        health_queried
            ? "Queried SMART health and attributes"
            : "Could not read SMART health or attributes"
    );
}

static void collect_linux_device_info(SourceProbeReport *report)
{
    char quoted[PROBE_PATH_MAX * 2U];

    if (report == NULL || !report->is_block_device ||
        !has_nonempty_text_probe(report->effective_source)) {
        return;
    }

    shell_quote_single(report->effective_source, quoted, sizeof(quoted));
    collect_linux_device_info_from_lsblk(report, quoted);
    collect_linux_device_info_from_blkid(report, quoted);
    collect_linux_device_info_from_udevadm(report, quoted);
    collect_linux_device_info_from_smartctl(report);
}
#endif

#ifdef __APPLE__
static void collect_macos_device_info(SourceProbeReport *report)
{
    char command[PROBE_PATH_MAX + 256];
    char quoted[PROBE_PATH_MAX * 2U];
    char output[4096];
    char value[256];
    int locked = 0;
    int encrypted = 0;
    int filevault = 0;

    if (report == NULL || !has_nonempty_text_probe(report->effective_source)) {
        return;
    }

    shell_quote_single(report->effective_source, quoted, sizeof(quoted));
    snprintf_safe(command, sizeof(command), "diskutil info %s 2>/dev/null", quoted);
    if (run_command_success(command, output, sizeof(output))) {
        if (strstr(output, "Read-Only Media:") != NULL &&
            strstr(output, "Yes") != NULL) {
            report->read_only = 1;
        }
        value[0] = '\0';
        parse_colon_value(output, "Solid State", value, sizeof(value));
        if (value[0] != '\0') {
            int solid_state = value_means_yes_probe(value);
            if (solid_state || value_means_no_probe(value)) {
                set_probe_media_from_rotational(report, solid_state ? 0 : 1);
            }
        }
        value[0] = '\0';
        parse_colon_value(output, "SMART Status", value, sizeof(value));
        if (value[0] != '\0') {
            snprintf_safe(
                report->smart_status,
                sizeof(report->smart_status),
                "%s",
                value
            );
            report->smart_seen = 1;
            if (contains_ascii_case_insensitive_probe(value, "FAILED") ||
                contains_ascii_case_insensitive_probe(value, "FAILING") ||
                contains_ascii_case_insensitive_probe(value, "BAD")) {
                set_probe_health_state(report, "fail", "diskutil reports failing SMART status");
            } else if (contains_ascii_case_insensitive_probe(value, "Verified") ||
                       contains_ascii_case_insensitive_probe(value, "PASSED") ||
                       contains_ascii_case_insensitive_probe(value, "OK")) {
                set_probe_health_state(
                    report,
                    "ok",
                    "diskutil reports verified SMART status; this is not a full guarantee."
                );
            }
        }
        value[0] = '\0';
        parse_colon_value(output, "Locked", value, sizeof(value));
        locked = value_means_yes_probe(value);
        value[0] = '\0';
        parse_colon_value(output, "Encrypted", value, sizeof(value));
        encrypted = value_means_yes_probe(value);
        value[0] = '\0';
        parse_colon_value(output, "FileVault", value, sizeof(value));
        if (value[0] != '\0') {
            filevault = value_means_yes_probe(value);
            if (!locked &&
                (contains_ascii_case_insensitive_probe(value, "locked") ||
                 contains_ascii_case_insensitive_probe(value, "no (locked)"))) {
                locked = 1;
            }
        }
        if (locked || encrypted || filevault) {
            char detail[PROBE_MAX_DETAIL];
            const char *kind = filevault ? "FileVault" : "Encrypted macOS volume";

            snprintf_safe(
                detail,
                sizeof(detail),
                "%s reported by diskutil%s",
                kind,
                locked ? " (locked)" : ""
            );
            set_probe_encryption_state(
                report,
                kind,
                locked ? 1 : 0,
                locked ? 0 : 1,
                detail
            );
        }
        add_step(report, "diskutil_info", "ok", "Collected diskutil info");
    } else {
        add_step(report, "diskutil_info", "fail", "diskutil info failed");
    }
}
#endif

static void collect_regular_file_info(SourceProbeReport *report)
{
    FILE *file;

    if (report == NULL || !report->is_regular_file ||
        !has_nonempty_text_probe(report->effective_source)) {
        return;
    }

    file = fopen(report->effective_source, "rb");
    if (file == NULL) {
        report->readable = 0;
        set_probe_health_state(report, "fail", "The selected image/source file could not be opened.");
        add_step(report, "file_open", "fail", strerror(errno));
        return;
    }

    report->readable = 1;
    set_probe_health_state(report, "ok", "The selected image/source file opened successfully.");
    fclose(file);
    add_step(report, "file_open", "ok", "Regular file opened successfully");
    sniff_raw_encryption_signatures(report);
}

#ifdef __linux__
static void collect_gentle_read_test_linux(SourceProbeReport *report)
{
    char command[PROBE_PATH_MAX + 256];
    char quoted[PROBE_PATH_MAX * 2U];
    char output[512];
    int exit_status = -1;

    if (report == NULL || !report->is_block_device ||
        !has_nonempty_text_probe(report->effective_source)) {
        return;
    }

    if (!command_exists("timeout")) {
        add_step(report, "gentle_read_test", "skip", "timeout is not installed");
        return;
    }

    shell_quote_single(report->effective_source, quoted, sizeof(quoted));
    snprintf_safe(
        command,
        sizeof(command),
        "timeout 3 dd if=%s of=/dev/null bs=4096 count=1 iflag=direct status=none 2>&1",
        quoted
    );
    if (!run_command_capture(command, output, sizeof(output), &exit_status)) {
        report->readable = 0;
        set_probe_health_state(report, "fail", "Could not start the gentle read test.");
        add_step(report, "gentle_read_test", "fail", "Could not start dd read test");
        return;
    }

    sanitize_newlines(output);
    trim_whitespace(output);
    if (exit_status == 0) {
        report->readable = 1;
        set_probe_health_state(
            report,
            "ok",
            "The source answered a minimal 4 KiB read test; this is not a full guarantee."
        );
        add_step(report, "gentle_read_test", "ok", "Read first 4 KiB successfully");
    } else if (exit_status == 124) {
        report->readable = 0;
        set_probe_health_state(report, "fail", "Timed out while reading the first 4 KiB.");
        add_step(report, "gentle_read_test", "fail", "Timed out while reading first 4 KiB");
    } else {
        report->readable = 0;
        set_probe_health_state(
            report,
            "fail",
            output[0] != '\0' ? output : "The first 4 KiB read test failed."
        );
        add_step(report, "gentle_read_test", "fail", output[0] != '\0' ? output : "Read test failed");
    }
}
#endif

static void probe_collect_passive(SourceProbeReport *report)
{
    PlatformInfo platform = {0};

    if (report == NULL) {
        return;
    }

    if (platform_detect(&platform)) {
        snprintf_safe(report->platform_name,
                      sizeof(report->platform_name),
                      "%s",
                      platform.name != NULL ? platform.name : "unknown");
    }

#ifdef __linux__
    collect_inventory_linux(report);
#elif defined(__APPLE__)
    collect_inventory_macos(report);
#endif

    resolve_effective_source(report);

    if (!report->source_given) {
        return;
    }

    if (!report->exists) {
        add_step(report, "source_stat", "fail", "Requested source path is not present");
        return;
    }

    if (report->is_regular_file) {
        collect_regular_file_info(report);
        return;
    }

    if (report->is_block_device) {
#ifdef __linux__
        collect_linux_device_info(report);
        collect_gentle_read_test_linux(report);
#elif defined(__APPLE__)
        collect_macos_device_info(report);
#endif
        sniff_raw_encryption_signatures(report);
    }
}

#ifdef __linux__
static void probe_soft_wake_linux(SourceProbeReport *report)
{
    char command[PROBE_PATH_MAX + 256];
    char quoted[PROBE_PATH_MAX * 2U];
    int ok_any = 0;
    const char *before_classification;

    if (report == NULL) {
        return;
    }

    report->soft_wake_attempted = 1;
    before_classification = report->classification;

    if (access("/sys/class/scsi_host", F_OK) == 0) {
        if (run_command_success(
                "sh -c 'for host in /sys/class/scsi_host/host*/scan; do printf -- \"- - -\" > \"$host\" || exit 1; done'",
                NULL,
                0U)) {
            ok_any = 1;
            add_step(report, "scsi_rescan", "ok", "Requested a cautious SCSI host rescan");
        } else {
            add_step(report, "scsi_rescan", "fail", "Could not write to /sys/class/scsi_host/.../scan");
        }
    } else {
        add_step(report, "scsi_rescan", "skip", "No /sys/class/scsi_host found");
    }

    if (command_exists("udevadm")) {
        if (run_command_success("udevadm settle --timeout=10 2>/dev/null", NULL, 0U)) {
            ok_any = 1;
            add_step(report, "udevadm_settle", "ok", "udevadm settle completed");
        } else {
            add_step(report, "udevadm_settle", "fail", "udevadm settle failed");
        }
    } else {
        add_step(report, "udevadm_settle", "skip", "udevadm is not installed");
    }

    if (report->is_block_device &&
        has_nonempty_text_probe(report->effective_source) &&
        command_exists("blockdev")) {
        shell_quote_single(report->effective_source, quoted, sizeof(quoted));
        snprintf_safe(command, sizeof(command), "blockdev --rereadpt %s 2>/dev/null", quoted);
        if (run_command_success(command, NULL, 0U)) {
            ok_any = 1;
            add_step(report, "reread_partition_table", "ok", "Asked the kernel to reread the partition table");
        } else {
            add_step(report, "reread_partition_table", "fail", "blockdev --rereadpt failed");
        }
    } else if (report->source_given) {
        add_step(report, "reread_partition_table", "skip", "No block device selected for partition reread");
    }

    if (!ok_any) {
        return;
    }

    {
        int previous_exists = report->exists;
        int previous_readable = report->readable;
        uint64_t previous_size = report->size_bytes;
        char previous_effective[PROBE_PATH_MAX];

        snprintf_safe(previous_effective,
                      sizeof(previous_effective),
                      "%s",
                      report->effective_source);

        report->exists = 0;
        report->is_directory = 0;
        report->is_regular_file = 0;
        report->is_block_device = 0;
        report->resolved_from_mount = 0;
        report->readable = 0;
        report->read_only = 0;
        report->smart_seen = 0;
        report->source_problem_detected = 0;
        report->size_bytes = 0U;
        report->model[0] = '\0';
        report->serial[0] = '\0';
        report->filesystem[0] = '\0';
        report->transport[0] = '\0';
        report->mountpoint[0] = '\0';
        report->by_id[0] = '\0';
        report->smart_status[0] = '\0';
        report->source_health[0] = '\0';
        report->source_health_detail[0] = '\0';
        report->media_type[0] = '\0';
        report->rotational_known = 0;
        report->rotational = 0;
        snprintf_safe(report->effective_source,
                      sizeof(report->effective_source),
                      "%s",
                      report->requested_source);

        probe_collect_passive(report);
        if (report->exists != previous_exists ||
            report->readable != previous_readable ||
            report->size_bytes != previous_size ||
            strcmp(previous_effective, report->effective_source) != 0 ||
            strcmp(before_classification, report->classification) != 0) {
            report->soft_wake_changed = 1;
        }
    }
}
#endif

static void classify_report(SourceProbeReport *report)
{
    if (report == NULL) {
        return;
    }

    if (!report->source_given) {
        snprintf_safe(report->classification,
                      sizeof(report->classification),
                      "%s",
                      "inventory_only");
        snprintf_safe(report->summary,
                      sizeof(report->summary),
                      "%s",
                      "Listed visible sources and tried a cautious Linux rescan.");
        return;
    }

    if (!report->exists) {
        snprintf_safe(report->classification, sizeof(report->classification), "%s", "source_not_visible");
        snprintf_safe(report->summary,
                      sizeof(report->summary),
                      "%s",
                      "The requested source path is not currently visible as a file or block device.");
        return;
    }

    if (report->is_regular_file) {
        snprintf_safe(report->classification,
                      sizeof(report->classification),
                      "%s",
                      report->readable ? "readable_image_file" : "image_file_unreadable");
        snprintf_safe(report->summary,
                      sizeof(report->summary),
                      "%s",
                      report->readable
                          ? "The selected image/source file is readable."
                          : "The selected image/source file exists but could not be opened.");
        return;
    }

    if (report->is_block_device) {
        if (report->requested_was_directory) {
            snprintf_safe(report->classification,
                          sizeof(report->classification),
                          "%s",
                          report->readable
                              ? "mounted_source_resolved_readable"
                              : "mounted_source_resolved");
            snprintf_safe(report->summary,
                          sizeof(report->summary),
                          "%s",
                          report->readable
                              ? "The mounted source was resolved to a backing device that answered a gentle read test."
                              : "The mounted source was resolved to a backing device for later recovery work.");
            return;
        }
        if (report->readable) {
            snprintf_safe(report->classification,
                          sizeof(report->classification),
                          "%s",
                          "block_device_readable");
            snprintf_safe(report->summary,
                          sizeof(report->summary),
                          "%s",
                          "The block device is present and answered a gentle read test.");
        } else {
            snprintf_safe(report->classification,
                          sizeof(report->classification),
                          "%s",
                          "block_device_present_but_troubled");
            snprintf_safe(report->summary,
                          sizeof(report->summary),
                          "%s",
                          "The block device is visible, but a gentle read test failed or timed out.");
        }
        return;
    }

    if (report->is_directory) {
        snprintf_safe(report->classification,
                      sizeof(report->classification),
                      "%s",
                      report->resolved_from_mount ? "mounted_source_resolved" : "mounted_source_only");
        snprintf_safe(report->summary,
                      sizeof(report->summary),
                      "%s",
                      report->resolved_from_mount
                          ? "The mounted source was resolved to a backing device."
                          : "The selected folder exists, but no backing device was resolved.");
        return;
    }

    snprintf_safe(report->classification, sizeof(report->classification), "%s", "source_visible_unknown_kind");
    snprintf_safe(report->summary,
                  sizeof(report->summary),
                  "%s",
                  "The source path exists, but it is neither a regular file, a directory, nor a block device.");
}

static void emit_text_report(FILE *file, const SourceProbeReport *report)
{
    char size_text[64];
    size_t i;

    if (file == NULL || report == NULL) {
        return;
    }

    format_size_human(report->size_bytes, size_text, sizeof(size_text));

    fprintf(file, "source probe\n");
    fprintf(file, "classification: %s\n", report->classification);
    fprintf(file, "summary: %s\n", report->summary);
    fprintf(file, "platform: %s\n", has_nonempty_text_probe(report->platform_name) ? report->platform_name : "unknown");
    fprintf(file, "requested_source: %s\n", report->source_given ? report->requested_source : "(none)");
    fprintf(file, "effective_source: %s\n",
            has_nonempty_text_probe(report->effective_source) ? report->effective_source : "(none)");
    fprintf(file, "exists: %s\n", yesno(report->exists));
    fprintf(file, "is_directory: %s\n", yesno(report->is_directory));
    fprintf(file, "is_regular_file: %s\n", yesno(report->is_regular_file));
    fprintf(file, "is_block_device: %s\n", yesno(report->is_block_device));
    fprintf(file, "resolved_from_mount: %s\n", yesno(report->resolved_from_mount));
    fprintf(file, "readable: %s\n", yesno(report->readable));
    fprintf(file, "read_only: %s\n", yesno(report->read_only));
    if (report->size_bytes > 0U) {
        fprintf(file, "size: %s\n", size_text);
    }
    if (has_nonempty_text_probe(report->media_type)) {
        fprintf(file, "media: %s\n", report->media_type);
    }
    if (report->rotational_known) {
        fprintf(file, "rotational: %s\n", yesno(report->rotational));
    }
    if (has_nonempty_text_probe(report->filesystem)) {
        fprintf(file, "filesystem: %s\n", report->filesystem);
    }
    if (has_nonempty_text_probe(report->transport)) {
        fprintf(file, "transport: %s\n", report->transport);
    }
    if (has_nonempty_text_probe(report->model)) {
        fprintf(file, "model: %s\n", report->model);
    }
    if (has_nonempty_text_probe(report->serial)) {
        fprintf(file, "serial: %s\n", report->serial);
    }
    if (has_nonempty_text_probe(report->mountpoint)) {
        fprintf(file, "mountpoint: %s\n", report->mountpoint);
    }
    if (has_nonempty_text_probe(report->by_id)) {
        fprintf(file, "by_id: %s\n", report->by_id);
    }
    if (has_nonempty_text_probe(report->smart_status)) {
        fprintf(file, "smart: %s\n", report->smart_status);
    }
    if (has_nonempty_text_probe(report->source_health)) {
        fprintf(file, "source_health: %s\n", report->source_health);
        if (has_nonempty_text_probe(report->source_health_detail)) {
            fprintf(file, "source_health_detail: %s\n", report->source_health_detail);
        }
    }
    fprintf(file, "source_problem_detected: %s\n", yesno(report->source_problem_detected));
    if (report->encryption_detected) {
        fprintf(file, "encryption_detected: %s\n", yesno(report->encryption_detected));
        fprintf(file, "encryption_locked: %s\n", yesno(report->encryption_locked));
        if (has_nonempty_text_probe(report->encryption_kind)) {
            fprintf(file, "encryption_kind: %s\n", report->encryption_kind);
        }
        if (has_nonempty_text_probe(report->encryption_detail)) {
            fprintf(file, "encryption_detail: %s\n", report->encryption_detail);
        }
    }
    fprintf(file, "soft_wake_attempted: %s\n", yesno(report->soft_wake_attempted));
    fprintf(file, "soft_wake_changed: %s\n", yesno(report->soft_wake_changed));

    if (has_nonempty_text_probe(report->inventory_excerpt)) {
        fprintf(file, "\ninventory_excerpt:\n%s\n", report->inventory_excerpt);
    }

    if (report->step_count > 0U) {
        fprintf(file, "\nsteps:\n");
        for (i = 0U; i < report->step_count; i++) {
            fprintf(file,
                    "- %s: %s%s%s\n",
                    report->steps[i].name,
                    report->steps[i].outcome,
                    has_nonempty_text_probe(report->steps[i].detail) ? " - " : "",
                    has_nonempty_text_probe(report->steps[i].detail) ? report->steps[i].detail : "");
        }
    }
}

static int write_json_report(const char *path, const SourceProbeReport *report)
{
    FILE *file;
    size_t i;

    if (!has_nonempty_text_probe(path) || report == NULL) {
        return 0;
    }

    file = fopen(path, "w");
    if (file == NULL) {
        return 0;
    }

    fputs("{\n", file);
    fputs("  \"version\": 1,\n", file);
    fputs("  \"classification\": \"", file);
    json_write_escaped(file, report->classification);
    fputs("\",\n  \"summary\": \"", file);
    json_write_escaped(file, report->summary);
    fputs("\",\n  \"platform\": \"", file);
    json_write_escaped(file, report->platform_name);
    fputs("\",\n  \"requested_source\": ", file);
    if (report->source_given) {
        fputc('"', file);
        json_write_escaped(file, report->requested_source);
        fputc('"', file);
    } else {
        fputs("null", file);
    }
    fputs(",\n  \"effective_source\": ", file);
    if (has_nonempty_text_probe(report->effective_source)) {
        fputc('"', file);
        json_write_escaped(file, report->effective_source);
        fputc('"', file);
    } else {
        fputs("null", file);
    }
    fprintf(file,
            ",\n  \"exists\": %s,\n  \"is_directory\": %s,\n  \"is_regular_file\": %s,\n  \"is_block_device\": %s,\n  \"resolved_from_mount\": %s,\n  \"readable\": %s,\n  \"read_only\": %s,\n  \"size_bytes\": %llu,\n  \"soft_wake_attempted\": %s,\n  \"soft_wake_changed\": %s,\n",
            report->exists ? "true" : "false",
            report->is_directory ? "true" : "false",
            report->is_regular_file ? "true" : "false",
            report->is_block_device ? "true" : "false",
            report->resolved_from_mount ? "true" : "false",
            report->readable ? "true" : "false",
            report->read_only ? "true" : "false",
            (unsigned long long)report->size_bytes,
            report->soft_wake_attempted ? "true" : "false",
            report->soft_wake_changed ? "true" : "false");

    fputs("  \"model\": \"", file); json_write_escaped(file, report->model); fputs("\",\n", file);
    fputs("  \"serial\": \"", file); json_write_escaped(file, report->serial); fputs("\",\n", file);
    fputs("  \"filesystem\": \"", file); json_write_escaped(file, report->filesystem); fputs("\",\n", file);
    fputs("  \"transport\": \"", file); json_write_escaped(file, report->transport); fputs("\",\n", file);
    fputs("  \"mountpoint\": \"", file); json_write_escaped(file, report->mountpoint); fputs("\",\n", file);
    fputs("  \"by_id\": \"", file); json_write_escaped(file, report->by_id); fputs("\",\n", file);
    fputs("  \"smart_status\": \"", file); json_write_escaped(file, report->smart_status); fputs("\",\n", file);
    fputs("  \"source_health\": \"", file); json_write_escaped(file, report->source_health); fputs("\",\n", file);
    fputs("  \"source_health_detail\": \"", file); json_write_escaped(file, report->source_health_detail); fputs("\",\n", file);
    fprintf(file, "  \"source_problem_detected\": %s,\n", report->source_problem_detected ? "true" : "false");
    fputs("  \"media_type\": \"", file); json_write_escaped(file, report->media_type); fputs("\",\n", file);
    fprintf(file,
            "  \"rotational_known\": %s,\n  \"rotational\": %s,\n",
            report->rotational_known ? "true" : "false",
            report->rotational ? "true" : "false");
    fprintf(file,
            "  \"encryption_detected\": %s,\n  \"encryption_locked\": %s,\n  \"encryption_unlocked\": %s,\n",
            report->encryption_detected ? "true" : "false",
            report->encryption_locked ? "true" : "false",
            report->encryption_unlocked ? "true" : "false");
    fputs("  \"encryption_kind\": \"", file); json_write_escaped(file, report->encryption_kind); fputs("\",\n", file);
    fputs("  \"encryption_detail\": \"", file); json_write_escaped(file, report->encryption_detail); fputs("\",\n", file);
    fputs("  \"inventory_excerpt\": \"", file); json_write_escaped(file, report->inventory_excerpt); fputs("\",\n", file);
    fputs("  \"steps\": [\n", file);
    for (i = 0U; i < report->step_count; i++) {
        fprintf(file, "    {\"name\": \"");
        json_write_escaped(file, report->steps[i].name);
        fputs("\", \"outcome\": \"", file);
        json_write_escaped(file, report->steps[i].outcome);
        fputs("\", \"detail\": \"", file);
        json_write_escaped(file, report->steps[i].detail);
        fprintf(file, "\"}%s\n", (i + 1U < report->step_count) ? "," : "");
    }
    fputs("  ]\n}\n", file);

    fclose(file);
    return 1;
}

static int write_text_report_to_path(const char *path, const SourceProbeReport *report)
{
    FILE *file;

    if (!has_nonempty_text_probe(path) || report == NULL) {
        return 0;
    }

    file = fopen(path, "w");
    if (file == NULL) {
        return 0;
    }
    emit_text_report(file, report);
    fclose(file);
    return 1;
}

static void write_report_files(const char *run_dir, const SourceProbeReport *report)
{
    char state_dir[PROBE_PATH_MAX];
    char json_path[PROBE_PATH_MAX];
    char text_path[PROBE_PATH_MAX];

    if (!has_nonempty_text_probe(run_dir) || report == NULL) {
        return;
    }

    if (!build_state_dir_path(run_dir, state_dir, sizeof(state_dir))) {
        return;
    }

    if (snprintf(json_path, sizeof(json_path), "%s/source_probe.json", state_dir) >= (int)sizeof(json_path) ||
        snprintf(text_path, sizeof(text_path), "%s/source_probe.txt", state_dir) >= (int)sizeof(text_path)) {
        return;
    }

    (void)write_json_report(json_path, report);
    (void)write_text_report_to_path(text_path, report);
}

/*
 * Main probe entry point: collect passive facts, optionally attempt the
 * Linux soft-wake/rescan helpers, classify the result, then emit both
 * console and state-directory reports when requested.
 */
int source_probe_run(
    const char *requested_source,
    const char *report_run_dir,
    FILE *stream
)
{
    SourceProbeReport report;

    memset(&report, 0, sizeof(report));
    report.source_given = has_nonempty_text_probe(requested_source);
    if (report.source_given) {
        snprintf_safe(report.requested_source,
                      sizeof(report.requested_source),
                      "%s",
                      requested_source);
    }

    probe_collect_passive(&report);
#ifdef __linux__
    probe_soft_wake_linux(&report);
#endif
    classify_report(&report);
    if (report.encryption_locked) {
        size_t summary_length = strlen(report.summary);
        if (summary_length + 39U < sizeof(report.summary)) {
            snprintf_safe(
                report.summary + summary_length,
                sizeof(report.summary) - summary_length,
                "%sSource appears encrypted and locked.",
                summary_length > 0U ? " " : ""
            );
        }
    }
    if (report.source_problem_detected &&
        has_nonempty_text_probe(report.source_health_detail)) {
        size_t summary_length = strlen(report.summary);
        size_t remaining = summary_length < sizeof(report.summary)
                               ? sizeof(report.summary) - summary_length
                               : 0U;
        if (remaining > 32U) {
            snprintf_safe(
                report.summary + summary_length,
                remaining,
                "%sSource health warning: %s",
                summary_length > 0U ? " " : "",
                report.source_health_detail
            );
        }
    }

    if (stream != NULL) {
        emit_text_report(stream, &report);
        fflush(stream);
    }

    write_report_files(report_run_dir, &report);
    return 1;
}
