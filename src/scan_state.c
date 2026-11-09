/*
 * scan_state.c
 * Shared scan state persistence for resumable scans.
 */

#include "scan_state.h"
#include "fs_backend.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#define SCAN_STATE_DEFAULT_EMERGENCY_DIR "/tmp/carv_scan_state"

static uint64_t g_state_source_ntfs_serial = 0ULL;
static uint64_t g_state_accepted_ntfs_serials[SCAN_STATE_MAX_ACCEPTED_NTFS_SERIALS];
static size_t g_state_accepted_ntfs_serial_count = 0U;
static char g_state_source_device_name[128] = "";
static int g_state_source_is_internal = -1;

static int ensure_parent_dirs(const char *path)
{
    char temp[1200];
    char *cursor;

    if (path == NULL || path[0] == '\0' || strlen(path) >= sizeof(temp)) {
        return 0;
    }
    if (!fs_backend_output_path_write_guard_allows(path)) {
        return 0;
    }

    snprintf(temp, sizeof(temp), "%s", path);
    cursor = temp;

    while ((cursor = strchr(cursor + 1, '/')) != NULL) {
        *cursor = '\0';
        if (!fs_backend_output_path_write_guard_allows(temp)) {
            return 0;
        }
        if (mkdir(temp, 0777) != 0 && errno != EEXIST) {
            return 0;
        }
        *cursor = '/';
    }

    return 1;
}

static void sanitize_emergency_component_local(
    const char *input,
    char *out,
    size_t out_size
)
{
    size_t i;
    size_t j = 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }
    out[0] = '\0';
    if (input == NULL || input[0] == '\0') {
        snprintf(out, out_size, "run");
        return;
    }

    for (i = 0U; input[i] != '\0' && j + 1U < out_size; i++) {
        unsigned char ch = (unsigned char)input[i];

        if ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') ||
            ch == '.' ||
            ch == '-' ||
            ch == '_') {
            out[j++] = (char)ch;
        } else {
            out[j++] = '_';
        }
    }
    out[j] = '\0';
    if (out[0] == '\0') {
        snprintf(out, out_size, "run");
    }
}

static int scan_state_run_leaf_from_path_local(
    const char *path,
    char *out,
    size_t out_size
)
{
    char work[1400];
    char *slash;
    const char *leaf;

    if (out != NULL && out_size > 0U) {
        out[0] = '\0';
    }
    if (path == NULL ||
        path[0] == '\0' ||
        out == NULL ||
        out_size == 0U ||
        strlen(path) >= sizeof(work)) {
        return 0;
    }

    snprintf(work, sizeof(work), "%s", path);
    slash = strrchr(work, '/');
    if (slash == NULL || slash == work) {
        return 0;
    }
    *slash = '\0';
    slash = strrchr(work, '/');
    if (slash == NULL || slash == work) {
        return 0;
    }
    *slash = '\0';
    slash = strrchr(work, '/');
    leaf = slash != NULL ? slash + 1 : work;
    if (leaf == NULL || leaf[0] == '\0') {
        return 0;
    }
    sanitize_emergency_component_local(leaf, out, out_size);
    return out[0] != '\0';
}

static int scan_state_emergency_dir_local(char *out, size_t out_size);

static int scan_state_build_emergency_mirror_path_local(
    const char *path,
    char *out,
    size_t out_size
)
{
    char run_leaf[256];
    char emergency_dir[1000];

    if (out == NULL || out_size == 0U) {
        return 0;
    }
    out[0] = '\0';
    if (!scan_state_run_leaf_from_path_local(path, run_leaf, sizeof(run_leaf))) {
        return 0;
    }
    if (!scan_state_emergency_dir_local(emergency_dir, sizeof(emergency_dir))) {
        return 0;
    }
    return snprintf(
               out,
               out_size,
               "%s/%s-latest.txt",
               emergency_dir,
               run_leaf
           ) < (int)out_size;
}

static int scan_state_emergency_dir_local(char *out, size_t out_size)
{
    const char *override_dir;
    const char *tmp_dir;

    if (out == NULL || out_size == 0U) {
        return 0;
    }
    out[0] = '\0';

    override_dir = getenv("CARV_SCAN_STATE_EMERGENCY_DIR");
    if (override_dir != NULL && override_dir[0] != '\0') {
        return snprintf(out, out_size, "%s", override_dir) < (int)out_size;
    }

    tmp_dir = getenv("TMPDIR");
    if (tmp_dir != NULL && tmp_dir[0] != '\0') {
        size_t len = strlen(tmp_dir);

        return snprintf(
                   out,
                   out_size,
                   "%s%scarv_scan_state",
                   tmp_dir,
                   len > 0U && tmp_dir[len - 1U] == '/' ? "" : "/"
               ) < (int)out_size;
    }

    return snprintf(out, out_size, "%s", SCAN_STATE_DEFAULT_EMERGENCY_DIR) <
           (int)out_size;
}

static int scan_state_write_body_local(
    FILE *state,
    const char *source_path,
    const char *scan_mode,
    uint64_t source_size,
    uint64_t scan_offset,
    int scan_completed,
    int completed
)
{
    if (state == NULL || source_path == NULL) {
        return 0;
    }

    fprintf(state, "version=1\n");
    fprintf(state, "source_path=%s\n", source_path);
    if (g_state_source_device_name[0] != '\0') {
        fprintf(state, "source_device_name=%s\n", g_state_source_device_name);
    }
    if (scan_mode != NULL && scan_mode[0] != '\0') {
        fprintf(state, "scan_mode=%s\n", scan_mode);
    }
    if (g_state_source_ntfs_serial != 0ULL) {
        char serial_text[32];

        scan_state_format_ntfs_serial(
            g_state_source_ntfs_serial,
            serial_text,
            sizeof(serial_text)
        );
        fprintf(state, "source_ntfs_serial=%s\n", serial_text);
    }
    if (g_state_accepted_ntfs_serial_count > 0U) {
        size_t i;

        fprintf(state, "accepted_ntfs_serials=");
        for (i = 0U; i < g_state_accepted_ntfs_serial_count; i++) {
            char serial_text[32];

            scan_state_format_ntfs_serial(
                g_state_accepted_ntfs_serials[i],
                serial_text,
                sizeof(serial_text)
            );
            fprintf(state, "%s%s", i == 0U ? "" : ",", serial_text);
        }
        fprintf(state, "\n");
    }
    fprintf(state, "source_size=%llu\n", (unsigned long long)source_size);
    fprintf(state, "scan_offset=%llu\n", (unsigned long long)scan_offset);
    if (g_state_source_is_internal >= 0) {
        fprintf(state, "source_is_internal=%d\n", g_state_source_is_internal ? 1 : 0);
    }
    fprintf(state, "scan_completed=%d\n", scan_completed ? 1 : 0);
    fprintf(state, "completed=%d\n", completed ? 1 : 0);
    return ferror(state) ? 0 : 1;
}

static int scan_state_write_emergency_mirror_local(
    const char *state_path,
    const char *source_path,
    const char *scan_mode,
    uint64_t source_size,
    uint64_t scan_offset,
    int scan_completed,
    int completed
)
{
    char mirror_path[1400];
    char temp_path[1432];
    char emergency_dir[1000];
    FILE *state;

    if (!scan_state_build_emergency_mirror_path_local(
            state_path,
            mirror_path,
            sizeof(mirror_path))) {
        return 0;
    }
    if (!scan_state_emergency_dir_local(emergency_dir, sizeof(emergency_dir))) {
        return 0;
    }
    if (mkdir(emergency_dir, 0777) != 0 && errno != EEXIST) {
        return 0;
    }
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", mirror_path) >=
        (int)sizeof(temp_path)) {
        return 0;
    }

    state = fopen(temp_path, "w");
    if (state == NULL) {
        return 0;
    }
    {
        int body_ok = scan_state_write_body_local(
            state,
            source_path,
            scan_mode,
            source_size,
            scan_offset,
            scan_completed,
            completed
        );
        int close_ok = fclose(state) == 0;

        if (!body_ok || !close_ok) {
            (void)remove(temp_path);
            return 0;
        }
    }
    if (rename(temp_path, mirror_path) != 0) {
        (void)remove(temp_path);
        return 0;
    }
    return 1;
}

static int parse_state_value(
    const char *line,
    const char *key,
    char *out,
    size_t out_size
)
{
    size_t key_len;
    size_t value_len;

    if (line == NULL || key == NULL || out == NULL || out_size == 0) {
        return 0;
    }

    key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0 || line[key_len] != '=') {
        return 0;
    }

    value_len = strcspn(line + key_len + 1U, "\r\n");
    if (value_len >= out_size) {
        value_len = out_size - 1U;
    }

    memcpy(out, line + key_len + 1U, value_len);
    out[value_len] = '\0';
    return 1;
}

static int parse_u64_hex_value_local(const char *text, uint64_t *out_value)
{
    char *end = NULL;
    unsigned long long parsed = 0ULL;

    if (text == NULL || out_value == NULL || text[0] == '\0') {
        return 0;
    }

    parsed = strtoull(text, &end, 16);
    if (end == text || (end != NULL && *end != '\0')) {
        return 0;
    }

    *out_value = (uint64_t)parsed;
    return 1;
}

static uint64_t clamp_scan_offset_to_source_size_local(
    uint64_t source_size,
    uint64_t scan_offset
)
{
    if (source_size > 0U && scan_offset > source_size) {
        return source_size;
    }
    return scan_offset;
}

static int ntfs_serials_contains_local(
    const uint64_t *serials,
    size_t count,
    uint64_t serial
)
{
    size_t i;

    if (serial == 0ULL || serials == NULL) {
        return 0;
    }

    for (i = 0U; i < count; i++) {
        if (serials[i] == serial) {
            return 1;
        }
    }

    return 0;
}

static void ntfs_serials_add_unique_local(
    uint64_t *serials,
    size_t *count,
    uint64_t serial
)
{
    if (serial == 0ULL ||
        serials == NULL ||
        count == NULL ||
        *count >= SCAN_STATE_MAX_ACCEPTED_NTFS_SERIALS ||
        ntfs_serials_contains_local(serials, *count, serial)) {
        return;
    }

    serials[*count] = serial;
    (*count)++;
}

static void parse_ntfs_serial_csv_local(
    const char *csv,
    uint64_t *serials,
    size_t *count
)
{
    char work[512];
    char *token;

    if (count != NULL) {
        *count = 0U;
    }
    if (csv == NULL || csv[0] == '\0' ||
        serials == NULL || count == NULL ||
        strlen(csv) >= sizeof(work)) {
        return;
    }

    snprintf(work, sizeof(work), "%s", csv);
    token = strtok(work, ",");
    while (token != NULL) {
        uint64_t serial = 0ULL;

        if (parse_u64_hex_value_local(token, &serial)) {
            ntfs_serials_add_unique_local(serials, count, serial);
        }
        token = strtok(NULL, ",");
    }
}

void scan_state_format_ntfs_serial(uint64_t serial, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0U) {
        return;
    }

    if (serial == 0ULL) {
        out[0] = '\0';
        return;
    }

    snprintf(out, out_size, "%016llx", (unsigned long long)serial);
}

int scan_state_write(
    const char *path,
    const char *source_path,
    const char *scan_mode,
    uint64_t source_size,
    uint64_t scan_offset,
    int scan_completed,
    int completed
)
{
    char temp_path[1400];
    FILE *state;
    int write_ok = 0;

    if (path == NULL || path[0] == '\0' || source_path == NULL) {
        return 0;
    }

    /* A late post-scan worker can temporarily lose the kernel-reported size
     * even though the already saved state still knows it.  Never replace a
     * useful size with zero for the same source/mode: doing so destroys the
     * resume boundary and makes an otherwise complete run look malformed. */
    if (source_size == 0ULL) {
        ScanState previous = {0};

        if (scan_state_load(path, &previous) &&
            previous.source_size > 0ULL &&
            strcmp(previous.source_path, source_path) == 0 &&
            ((scan_mode == NULL && previous.scan_mode[0] == '\0') ||
             (scan_mode != NULL &&
              strcmp(previous.scan_mode, scan_mode) == 0))) {
            source_size = previous.source_size;
        }
    }
    scan_offset = clamp_scan_offset_to_source_size_local(source_size, scan_offset);
    if (source_size > 0ULL && scan_offset < source_size) {
        scan_completed = 0;
        completed = 0;
    }
    if (completed && !scan_completed) {
        completed = 0;
    }
    if (!ensure_parent_dirs(path)) {
        (void)scan_state_write_emergency_mirror_local(
            path,
            source_path,
            scan_mode,
            source_size,
            scan_offset,
            scan_completed,
            completed
        );
        return 0;
    }

    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >=
        (int)sizeof(temp_path)) {
        (void)scan_state_write_emergency_mirror_local(
            path,
            source_path,
            scan_mode,
            source_size,
            scan_offset,
            scan_completed,
            completed
        );
        return 0;
    }

    state = fopen(temp_path, "w");
    if (state == NULL) {
        (void)scan_state_write_emergency_mirror_local(
            path,
            source_path,
            scan_mode,
            source_size,
            scan_offset,
            scan_completed,
            completed
        );
        return 0;
    }

    {
        int body_ok = scan_state_write_body_local(
            state,
            source_path,
            scan_mode,
            source_size,
            scan_offset,
            scan_completed,
            completed
        );
        int close_ok = fclose(state) == 0;

        write_ok = body_ok && close_ok;
    }
    if (!write_ok) {
        (void)remove(temp_path);
        (void)scan_state_write_emergency_mirror_local(
            path,
            source_path,
            scan_mode,
            source_size,
            scan_offset,
            scan_completed,
            completed
        );
        return 0;
    }

    if (rename(temp_path, path) != 0) {
        (void)remove(temp_path);
        (void)scan_state_write_emergency_mirror_local(
            path,
            source_path,
            scan_mode,
            source_size,
            scan_offset,
            scan_completed,
            completed
        );
        return 0;
    }

    (void)scan_state_remove_emergency_mirror(path);
    return 1;
}

int scan_state_load(const char *path, ScanState *out)
{
    FILE *state;
    char line[1200];
    char value[256];

    if (path == NULL || path[0] == '\0' || out == NULL) {
        return 0;
    }

    state = fopen(path, "r");
    if (state == NULL) {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    while (fgets(line, sizeof(line), state) != NULL) {
        if (parse_state_value(line, "source_path", out->source_path, sizeof(out->source_path))) {
            continue;
        }
        if (parse_state_value(
                line,
                "source_device_name",
                out->source_device_name,
                sizeof(out->source_device_name))) {
            continue;
        }
        if (parse_state_value(line, "scan_mode", out->scan_mode, sizeof(out->scan_mode))) {
            continue;
        }
        if (parse_state_value(line, "source_ntfs_serial", value, sizeof(value))) {
            (void)parse_u64_hex_value_local(value, &out->source_ntfs_serial);
            continue;
        }
        if (parse_state_value(line, "accepted_ntfs_serials", value, sizeof(value))) {
            parse_ntfs_serial_csv_local(
                value,
                out->accepted_ntfs_serials,
                &out->accepted_ntfs_serial_count
            );
            continue;
        }
        if (parse_state_value(line, "source_size", value, sizeof(value))) {
            out->source_size = strtoull(value, NULL, 10);
            continue;
        }
        if (parse_state_value(line, "source_is_internal", value, sizeof(value))) {
            out->source_is_internal = atoi(value);
            continue;
        }
        if (parse_state_value(line, "scan_offset", value, sizeof(value))) {
            out->scan_offset = strtoull(value, NULL, 10);
            continue;
        }
        if (parse_state_value(line, "scan_completed", value, sizeof(value))) {
            out->scan_completed = atoi(value) != 0;
            continue;
        }
        if (parse_state_value(line, "completed", value, sizeof(value))) {
            out->completed = atoi(value) != 0;
            continue;
        }
    }

    fclose(state);
    if (out->scan_completed == 0 && out->completed) {
        out->scan_completed = 1;
    }
    out->scan_offset = clamp_scan_offset_to_source_size_local(
        out->source_size,
        out->scan_offset
    );
    return out->source_path[0] != '\0';
}

int scan_state_load_emergency_mirror(const char *path, ScanState *out)
{
    char mirror_path[1400];

    if (out == NULL ||
        !scan_state_build_emergency_mirror_path_local(
            path,
            mirror_path,
            sizeof(mirror_path))) {
        return 0;
    }

    return scan_state_load(mirror_path, out);
}

int scan_state_remove_emergency_mirror(const char *path)
{
    char mirror_path[1400];

    if (!scan_state_build_emergency_mirror_path_local(
            path,
            mirror_path,
            sizeof(mirror_path))) {
        return 0;
    }
    return remove(mirror_path) == 0 || errno == ENOENT;
}

int scan_state_emergency_mirror_is_older_than_path(
    const char *path,
    const char *reference_path
)
{
    char mirror_path[1400];
    struct stat mirror_st;
    struct stat reference_st;

    if (reference_path == NULL ||
        reference_path[0] == '\0' ||
        !scan_state_build_emergency_mirror_path_local(
            path,
            mirror_path,
            sizeof(mirror_path)) ||
        stat(mirror_path, &mirror_st) != 0 ||
        stat(reference_path, &reference_st) != 0) {
        return 0;
    }

    return mirror_st.st_mtime < reference_st.st_mtime;
}

void scan_state_identity_reset(void)
{
    g_state_source_ntfs_serial = 0ULL;
    memset(g_state_accepted_ntfs_serials, 0, sizeof(g_state_accepted_ntfs_serials));
    g_state_accepted_ntfs_serial_count = 0U;
    g_state_source_device_name[0] = '\0';
    g_state_source_is_internal = -1;
}

void scan_state_identity_seed_from_loaded(const ScanState *state)
{
    scan_state_identity_reset();

    if (state == NULL) {
        return;
    }

    g_state_source_ntfs_serial = state->source_ntfs_serial;
    snprintf(
        g_state_source_device_name,
        sizeof(g_state_source_device_name),
        "%s",
        state->source_device_name
    );
    g_state_source_is_internal = state->source_is_internal;
    memcpy(
        g_state_accepted_ntfs_serials,
        state->accepted_ntfs_serials,
        sizeof(g_state_accepted_ntfs_serials)
    );
    g_state_accepted_ntfs_serial_count = state->accepted_ntfs_serial_count;
    if (g_state_accepted_ntfs_serial_count > SCAN_STATE_MAX_ACCEPTED_NTFS_SERIALS) {
        g_state_accepted_ntfs_serial_count = SCAN_STATE_MAX_ACCEPTED_NTFS_SERIALS;
    }
}

void scan_state_identity_set_current_ntfs_serial(uint64_t serial)
{
    if (serial == 0ULL) {
        return;
    }

    if (g_state_source_ntfs_serial == 0ULL) {
        g_state_source_ntfs_serial = serial;
        return;
    }

    if (g_state_source_ntfs_serial != serial) {
        ntfs_serials_add_unique_local(
            g_state_accepted_ntfs_serials,
            &g_state_accepted_ntfs_serial_count,
            serial
        );
    }
}

void scan_state_identity_note_confirmed_ntfs_serial(uint64_t serial)
{
    if (serial == 0ULL) {
        return;
    }

    if (g_state_source_ntfs_serial == 0ULL) {
        g_state_source_ntfs_serial = serial;
        return;
    }

    if (g_state_source_ntfs_serial != serial) {
        ntfs_serials_add_unique_local(
            g_state_accepted_ntfs_serials,
            &g_state_accepted_ntfs_serial_count,
            serial
        );
    }
}

void scan_state_identity_set_source_device_info(const char *device_name, int is_internal)
{
    if (device_name != NULL && device_name[0] != '\0') {
        snprintf(
            g_state_source_device_name,
            sizeof(g_state_source_device_name),
            "%s",
            device_name
        );
    }
    if (is_internal >= 0) {
        g_state_source_is_internal = is_internal ? 1 : 0;
    }
}

int scan_state_has_ntfs_serial_match(const ScanState *state, uint64_t serial)
{
    if (state == NULL || serial == 0ULL) {
        return 0;
    }

    return state->source_ntfs_serial == serial ||
           ntfs_serials_contains_local(
               state->accepted_ntfs_serials,
               state->accepted_ntfs_serial_count,
               serial
           );
}
