#define _POSIX_C_SOURCE 200809L

/*
 * reader.c
 * Reader abstraction for regular files and raw devices.
 *
 * This file centralizes:
 * - open/seek/read behavior shared across scan modes
 * - Linux/macOS device-specific buffering and alignment hints
 * - bad-read tracking, clustering, and on-disk reports
 */

#include "reader.h"
#include "app.h"
#include "fs_backend.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <fcntl.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#endif

#ifdef __linux__
#include <fcntl.h>
#include <linux/fs.h>
#include <mntent.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif
#ifndef BLKSSZGET
#define BLKSSZGET _IO(0x12, 104)
#endif
#endif

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

static char g_reader_last_error[256] = "no error";
static int g_reader_last_errno = 0;

#define READER_BAD_READ_MIN_SPAN 512U
#define READER_BAD_READ_CLUSTER_GAP_BYTES (1ULL * 1024ULL * 1024ULL)
#define READER_TROUBLE_MAP_MAX_CLUSTER_BYTES (512ULL * 1024ULL * 1024ULL)
#define READER_MAX_ERROR_REPORT_FILE_BYTES (64ULL * 1024ULL * 1024ULL)
#define READER_TROUBLE_MAP_MAX_ENTRIES 256U
#define READER_REPEAT_TROUBLE_FORCE_SKIP_HITS 3U
#define READER_REPEAT_TROUBLE_SKIP_BYTES_L1 (4U * 1024U * 1024U)
#define READER_REPEAT_TROUBLE_SKIP_BYTES_L2 (16U * 1024U * 1024U)
#define READER_REPEAT_TROUBLE_SKIP_BYTES_L3 (64U * 1024U * 1024U)
#define READER_PRECISE_RECORD_MIN_FIRST_SECTOR_BYTES 128U
#define READER_REGULAR_FILE_PREFETCH_MIN_BYTES (16U * 1024U * 1024U)
#define READER_REGULAR_FILE_PREFETCH_MAX_BYTES (128U * 1024U * 1024U)
#define READER_REGULAR_FILE_RELEASE_MIN_BYTES (64U * 1024U * 1024U)
#define READER_REGULAR_FILE_RELEASE_MAX_BYTES (512U * 1024U * 1024U)

typedef struct {
    char source[256];
    char target[256];
} MountEntry;

typedef struct {
    uint64_t offset;
    uint64_t end_offset;
    uint64_t bytes;
    int errno_code;
    uint64_t hit_count;
    time_t first_seen_unix;
    time_t last_seen_unix;
} ReaderTroubleMapEntry;

static int is_power_of_two_u64(uint64_t value);

static size_t clamp_size_t_local(size_t value, size_t minimum, size_t maximum)
{
    if (value < minimum) {
        return minimum;
    }
    if (value > maximum) {
        return maximum;
    }
    return value;
}

static int reader_error_is_fatal_device_error_local(int error_code)
{
    if (error_code == ENXIO ||
        error_code == ENODEV ||
        error_code == EBADF) {
        return 1;
    }
#ifdef ENOMEDIUM
    if (error_code == ENOMEDIUM) {
        return 1;
    }
#endif
    return 0;
}

static void reader_write_bad_read_state(
    Reader *reader,
    const char *kind,
    uint64_t offset,
    uint64_t length,
    uint64_t end_offset,
    uint64_t span_count,
    int saved_errno
)
{
    char temp_path[1100];
    FILE *file;
    time_t now;

    if (reader == NULL ||
        reader->bad_read_state_path[0] == '\0' ||
        kind == NULL ||
        kind[0] == '\0') {
        return;
    }

    if (snprintf(
            temp_path,
            sizeof(temp_path),
            "%s.tmp",
            reader->bad_read_state_path) >= (int)sizeof(temp_path)) {
        return;
    }

    file = fopen(temp_path, "w");
    if (file == NULL) {
        return;
    }

    now = time(NULL);
    fprintf(file, "version=1\n");
    fprintf(file, "updated_unix=%lld\n", (long long)now);
    fprintf(file, "kind=%s\n", kind);
    fprintf(file, "offset=%llu\n", (unsigned long long)offset);
    fprintf(file, "length=%llu\n", (unsigned long long)length);
    fprintf(file, "end_offset=%llu\n", (unsigned long long)end_offset);
    fprintf(file, "span_count=%llu\n", (unsigned long long)span_count);
    fprintf(file, "errno=%d\n", saved_errno);

    if (fclose(file) != 0) {
        (void)unlink(temp_path);
        return;
    }
    if (rename(temp_path, reader->bad_read_state_path) != 0) {
        (void)unlink(temp_path);
    }
}

static int compare_trouble_map_entry_offset_asc(const void *left, const void *right)
{
    const ReaderTroubleMapEntry *a = (const ReaderTroubleMapEntry *)left;
    const ReaderTroubleMapEntry *b = (const ReaderTroubleMapEntry *)right;

    if (a->offset < b->offset) {
        return -1;
    }
    if (a->offset > b->offset) {
        return 1;
    }
    return 0;
}

static size_t reader_load_trouble_map(
    const char *path,
    ReaderTroubleMapEntry *entries,
    size_t capacity
)
{
    FILE *file;
    char line[256];
    size_t count = 0U;

    if (path == NULL || path[0] == '\0' || entries == NULL || capacity == 0U) {
        return 0U;
    }

    file = fopen(path, "r");
    if (file == NULL) {
        return 0U;
    }

    while (fgets(line, sizeof(line), file) != NULL && count < capacity) {
        ReaderTroubleMapEntry parsed = {0};
        unsigned long long first_seen = 0ULL;
        unsigned long long last_seen = 0ULL;

        if (strncmp(line, "offset\t", 7U) == 0) {
            continue;
        }

        if (sscanf(
                line,
                "%llu\t%llu\t%llu\t%d\t%llu\t%llu\t%llu",
                (unsigned long long *)&parsed.offset,
                (unsigned long long *)&parsed.end_offset,
                (unsigned long long *)&parsed.bytes,
                &parsed.errno_code,
                (unsigned long long *)&parsed.hit_count,
                &first_seen,
                &last_seen) == 7) {
            parsed.first_seen_unix = (time_t)first_seen;
            parsed.last_seen_unix = (time_t)last_seen;
            if (parsed.end_offset > parsed.offset) {
                entries[count++] = parsed;
            }
        }
    }

    fclose(file);
    return count;
}

static void reader_save_trouble_map(
    const char *path,
    const ReaderTroubleMapEntry *entries,
    size_t count
)
{
    char temp_path[1100];
    FILE *file;
    size_t i;

    if (path == NULL || path[0] == '\0' || entries == NULL) {
        return;
    }
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >= (int)sizeof(temp_path)) {
        return;
    }

    file = fopen(temp_path, "w");
    if (file == NULL) {
        return;
    }

    fprintf(
        file,
        "offset\tend_offset\tbytes\terrno_code\thit_count\tfirst_seen_unix\tlast_seen_unix\n"
    );
    for (i = 0U; i < count; i++) {
        fprintf(
            file,
            "%llu\t%llu\t%llu\t%d\t%llu\t%llu\t%llu\n",
            (unsigned long long)entries[i].offset,
            (unsigned long long)entries[i].end_offset,
            (unsigned long long)entries[i].bytes,
            entries[i].errno_code,
            (unsigned long long)entries[i].hit_count,
            (unsigned long long)entries[i].first_seen_unix,
            (unsigned long long)entries[i].last_seen_unix
        );
    }

    if (fclose(file) != 0) {
        (void)unlink(temp_path);
        return;
    }
    if (rename(temp_path, path) != 0) {
        (void)unlink(temp_path);
    }
}

static void reader_update_trouble_map(
    Reader *reader,
    uint64_t offset,
    uint64_t end_offset,
    uint64_t bytes,
    int saved_errno
)
{
    ReaderTroubleMapEntry entries[READER_TROUBLE_MAP_MAX_ENTRIES];
    size_t count;
    size_t i;
    int merged = 0;
    time_t now;

    if (reader == NULL ||
        reader->trouble_map_path[0] == '\0' ||
        end_offset <= offset ||
        bytes == 0U) {
        return;
    }

    count = reader_load_trouble_map(
        reader->trouble_map_path,
        entries,
        READER_TROUBLE_MAP_MAX_ENTRIES
    );
    now = time(NULL);

    for (i = 0U; i < count; i++) {
        uint64_t merged_offset;
        uint64_t merged_end_offset;
        uint64_t merged_bytes;

        if (end_offset + READER_BAD_READ_CLUSTER_GAP_BYTES < entries[i].offset ||
            offset > entries[i].end_offset + READER_BAD_READ_CLUSTER_GAP_BYTES) {
            continue;
        }

        merged_offset = offset < entries[i].offset ? offset : entries[i].offset;
        merged_end_offset =
            end_offset > entries[i].end_offset ? end_offset : entries[i].end_offset;
        merged_bytes = merged_end_offset - merged_offset;
        if (merged_bytes > READER_TROUBLE_MAP_MAX_CLUSTER_BYTES) {
            continue;
        }

        entries[i].offset = merged_offset;
        entries[i].end_offset = merged_end_offset;
        entries[i].bytes = merged_bytes;
        entries[i].errno_code = saved_errno;
        entries[i].hit_count++;
        entries[i].last_seen_unix = now;
        merged = 1;
        break;
    }

    if (!merged && count < READER_TROUBLE_MAP_MAX_ENTRIES) {
        entries[count].offset = offset;
        entries[count].end_offset = end_offset;
        entries[count].bytes = bytes;
        entries[count].errno_code = saved_errno;
        entries[count].hit_count = 1U;
        entries[count].first_seen_unix = now;
        entries[count].last_seen_unix = now;
        count++;
    }

    if (count > 1U) {
        qsort(entries, count, sizeof(*entries), compare_trouble_map_entry_offset_asc);
    }

    reader_save_trouble_map(reader->trouble_map_path, entries, count);
}

static int reader_find_matching_trouble_entry(
    const Reader *reader,
    uint64_t offset,
    uint64_t end_offset,
    ReaderTroubleMapEntry *out_entry
)
{
    ReaderTroubleMapEntry entries[READER_TROUBLE_MAP_MAX_ENTRIES];
    ReaderTroubleMapEntry best_entry = {0};
    size_t count;
    size_t i;
    int found = 0;

    if (out_entry != NULL) {
        memset(out_entry, 0, sizeof(*out_entry));
    }

    if (reader == NULL ||
        reader->trouble_map_path[0] == '\0' ||
        end_offset <= offset) {
        return 0;
    }

    count = reader_load_trouble_map(
        reader->trouble_map_path,
        entries,
        READER_TROUBLE_MAP_MAX_ENTRIES
    );

    for (i = 0U; i < count; i++) {
        if (end_offset + READER_BAD_READ_CLUSTER_GAP_BYTES < entries[i].offset ||
            offset > entries[i].end_offset + READER_BAD_READ_CLUSTER_GAP_BYTES) {
            continue;
        }

        if (!found ||
            entries[i].hit_count > best_entry.hit_count ||
            (entries[i].hit_count == best_entry.hit_count &&
             entries[i].bytes > best_entry.bytes)) {
            best_entry = entries[i];
            found = 1;
        }
    }

    if (found && out_entry != NULL) {
        *out_entry = best_entry;
    }

    return found;
}

static size_t reader_forced_skip_length_for_trouble(
    const ReaderTroubleMapEntry *entry,
    size_t requested_length
)
{
    size_t forced_length = 0U;
    LogTroubleBudgetState budget_state;
    uint64_t hit_count = 0ULL;
    unsigned long long observed_span_seconds = 0ULL;

    if (entry == NULL || requested_length == 0U) {
        return 0U;
    }

    hit_count = entry->hit_count;
    if (entry->last_seen_unix > entry->first_seen_unix) {
        observed_span_seconds =
            (unsigned long long)(entry->last_seen_unix - entry->first_seen_unix);
    }

    if (hit_count >= 8U) {
        forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L3;
    } else if (hit_count >= 5U) {
        forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L2;
    } else if (hit_count >= READER_REPEAT_TROUBLE_FORCE_SKIP_HITS) {
        forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L1;
    } else {
        return 0U;
    }

    budget_state = log_get_trouble_budget_state();
    if (observed_span_seconds >= 900ULL &&
        forced_length < READER_REPEAT_TROUBLE_SKIP_BYTES_L3) {
        forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L3;
    } else if (observed_span_seconds >= 300ULL &&
               forced_length < READER_REPEAT_TROUBLE_SKIP_BYTES_L2) {
        forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L2;
    }
    if (budget_state == LOG_TROUBLE_BUDGET_RED) {
        if (hit_count >= 2U &&
            forced_length < READER_REPEAT_TROUBLE_SKIP_BYTES_L2) {
            forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L2;
        }
        if (hit_count >= 5U &&
            forced_length < READER_REPEAT_TROUBLE_SKIP_BYTES_L3) {
            forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L3;
        }
        if (observed_span_seconds >= 180ULL &&
            forced_length < READER_REPEAT_TROUBLE_SKIP_BYTES_L2) {
            forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L2;
        }
        if (observed_span_seconds >= 600ULL &&
            forced_length < READER_REPEAT_TROUBLE_SKIP_BYTES_L3) {
            forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L3;
        }
    } else if (budget_state == LOG_TROUBLE_BUDGET_YELLOW) {
        if (hit_count >= READER_REPEAT_TROUBLE_FORCE_SKIP_HITS &&
            forced_length < READER_REPEAT_TROUBLE_SKIP_BYTES_L2) {
            forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L2;
        }
        if (observed_span_seconds >= 300ULL &&
            forced_length < READER_REPEAT_TROUBLE_SKIP_BYTES_L2) {
            forced_length = READER_REPEAT_TROUBLE_SKIP_BYTES_L2;
        }
    }

    if (forced_length > requested_length) {
        forced_length = requested_length;
    }
    forced_length -= forced_length % READER_BAD_READ_MIN_SPAN;
    if (forced_length == 0U) {
        forced_length = requested_length;
    }

    return forced_length;
}

static void reader_note_source_unavailable(
    Reader *reader,
    const char *context,
    uint64_t offset,
    size_t length,
    int saved_errno
)
{
    size_t state_length = length;

    if (!reader_error_is_fatal_device_error_local(saved_errno)) {
        return;
    }

    if (state_length == 0U) {
        state_length = reader != NULL && reader->direct_read_alignment > 0U
            ? reader->direct_read_alignment
            : READER_BAD_READ_MIN_SPAN;
    }

    reader_write_bad_read_state(
        reader,
        "device_unavailable",
        offset,
        (uint64_t)state_length,
        offset + (uint64_t)state_length,
        1U,
        saved_errno
    );
    app_gui_note_trouble(
        offset,
        offset + (uint64_t)state_length,
        "device_unavailable"
    );
    if (!app_source_reconnect_requested()) {
        log_runtime_event_error(
            "Reader lost contact with source during %s at byte %llu (%s); stopping this pass so the supervisor can reopen the disk and resume",
            context != NULL && context[0] != '\0' ? context : "read",
            (unsigned long long)offset,
            strerror(saved_errno)
        );
    }
    app_request_source_reconnect(context, saved_errno);
}

static int reader_regular_source_path_became_unavailable(const Reader *reader)
{
    struct stat st;

    if (reader == NULL ||
        !reader->source_is_regular_file ||
        reader->path == NULL ||
        reader->path[0] == '\0') {
        return 0;
    }

    if (stat(reader->path, &st) != 0) {
        return 1;
    }

    if (!S_ISREG(st.st_mode)) {
        return 1;
    }

    return st.st_dev != reader->source_open_dev ||
           st.st_ino != reader->source_open_ino;
}

static void reader_note_regular_source_path_unavailable(
    Reader *reader,
    const char *context,
    uint64_t offset,
    size_t length,
    int saved_errno
)
{
    size_t state_length = length;

    if (reader == NULL) {
        return;
    }
    if (state_length == 0U) {
        state_length = READER_BAD_READ_MIN_SPAN;
    }

    reader_write_bad_read_state(
        reader,
        "source_path_unavailable",
        offset,
        (uint64_t)state_length,
        offset + (uint64_t)state_length,
        1U,
        saved_errno
    );
    app_gui_note_trouble(
        offset,
        offset + (uint64_t)state_length,
        "source_path_unavailable"
    );
    if (!app_source_reconnect_requested()) {
        log_runtime_event_error(
            "Reader source path disappeared or remounted during %s at byte %llu: %s; stopping instead of treating this as unreadable source bytes",
            context != NULL && context[0] != '\0' ? context : "read",
            (unsigned long long)offset,
            reader->path != NULL ? reader->path : "(unknown source)"
        );
    }
    app_request_source_reconnect(context, saved_errno);
}

static void set_reader_error(const char *message)
{
    g_reader_last_errno = 0;
    if (message == NULL) {
        snprintf(g_reader_last_error, sizeof(g_reader_last_error), "unknown error");
        return;
    }

    snprintf(g_reader_last_error, sizeof(g_reader_last_error), "%s", message);
}

static void set_reader_errno_error(const char *context)
{
    g_reader_last_errno = errno != 0 ? errno : EIO;
    if (context == NULL) {
        context = "reader";
    }

    snprintf(
        g_reader_last_error,
        sizeof(g_reader_last_error),
        "%s: %s",
        context,
        strerror(g_reader_last_errno)
    );
}

static void set_reader_saved_errno_error(const char *context, int saved_errno)
{
    g_reader_last_errno = saved_errno != 0 ? saved_errno : EIO;
    if (context == NULL) {
        context = "reader";
    }

    snprintf(
        g_reader_last_error,
        sizeof(g_reader_last_error),
        "%s: %s",
        context,
        strerror(g_reader_last_errno)
    );
}

#ifdef __APPLE__
static void shell_quote_single(const char *input, char *out, size_t out_size)
{
    size_t out_pos = 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }

    out[0] = '\0';
    if (input == NULL) {
        return;
    }

    if (out_pos + 1U < out_size) {
        out[out_pos++] = '\'';
    } else {
        return;
    }

    while (*input != '\0' && out_pos + 1U < out_size) {
        if (*input == '\'') {
            static const char escaped_quote[] = "'\\''";
            size_t i;

            if (out_pos + sizeof(escaped_quote) - 1U >= out_size) {
                break;
            }
            for (i = 0; i < sizeof(escaped_quote) - 1U; i++) {
                out[out_pos++] = escaped_quote[i];
            }
        } else {
            out[out_pos++] = *input;
        }
        input++;
    }

    if (out_pos + 1U < out_size) {
        out[out_pos++] = '\'';
    }
    out[out_pos] = '\0';
}
#endif

static int stat_path(const char *path, struct stat *st)
{
    if (path == NULL || st == NULL) {
        return 0;
    }

    if (stat(path, st) != 0) {
        return 0;
    }

    return 1;
}

static void configure_sequential_io_hints(Reader *reader, const struct stat *st)
{
    if (reader == NULL || reader->file == NULL || st == NULL) {
        return;
    }

    reader->fd = fileno(reader->file);
    if (reader->fd < 0) {
        return;
    }

#ifdef __linux__
#ifdef POSIX_FADV_SEQUENTIAL
    (void)posix_fadvise(reader->fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif
#ifdef POSIX_FADV_WILLNEED
    (void)posix_fadvise(reader->fd, 0, 0, POSIX_FADV_WILLNEED);
#endif
#endif

#ifdef __APPLE__
#ifdef F_RDAHEAD
    (void)fcntl(reader->fd, F_RDAHEAD, 1);
#endif
#ifdef F_NOCACHE
    if ((S_ISBLK(st->st_mode) || S_ISCHR(st->st_mode)) &&
        !reader->use_stdio_device_reads) {
        (void)fcntl(reader->fd, F_NOCACHE, 1);
    }
#endif
    if (S_ISBLK(st->st_mode) || S_ISCHR(st->st_mode)) {
        uint32_t block_size = 0U;

        if (ioctl(reader->fd, DKIOCGETBLOCKSIZE, &block_size) == 0 &&
            block_size > 0U &&
            is_power_of_two_u64((uint64_t)block_size)) {
            reader->direct_read_alignment = (size_t)block_size;
        } else {
            reader->direct_read_alignment = 512U;
        }
    }
#endif

#ifdef __linux__
    if (S_ISBLK(st->st_mode)) {
        int logical_block_size = 0;

        if (ioctl(reader->fd, BLKSSZGET, &logical_block_size) == 0 &&
            logical_block_size > 0 &&
            is_power_of_two_u64((uint64_t)logical_block_size)) {
            reader->direct_read_alignment = (size_t)logical_block_size;
        } else {
            reader->direct_read_alignment = 512U;
        }
    }
#endif
}

static void reader_configure_regular_file_sequential_advice(Reader *reader)
{
    size_t prefetch_bytes;
    size_t release_bytes;

    if (reader == NULL) {
        return;
    }

    reader->sequential_advice_enabled = 0;
    reader->sequential_prefetch_bytes = 0U;
    reader->sequential_release_bytes = 0U;
    reader->sequential_last_read_offset = 0U;
    reader->sequential_last_read_end_offset = 0U;
    reader->sequential_prefetch_end_offset = 0U;
    reader->sequential_release_end_offset = 0U;

    if (!reader->source_is_regular_file ||
        reader->fd < 0 ||
        reader->chunk_size == 0U) {
        return;
    }

    prefetch_bytes = reader->chunk_size;
    if (prefetch_bytes <= SIZE_MAX / 2U) {
        prefetch_bytes *= 2U;
    } else {
        prefetch_bytes = SIZE_MAX;
    }
    prefetch_bytes = clamp_size_t_local(
        prefetch_bytes,
        READER_REGULAR_FILE_PREFETCH_MIN_BYTES,
        READER_REGULAR_FILE_PREFETCH_MAX_BYTES
    );

    release_bytes = reader->chunk_size;
    if (release_bytes <= SIZE_MAX / 8U) {
        release_bytes *= 8U;
    } else {
        release_bytes = SIZE_MAX;
    }
    release_bytes = clamp_size_t_local(
        release_bytes,
        READER_REGULAR_FILE_RELEASE_MIN_BYTES,
        READER_REGULAR_FILE_RELEASE_MAX_BYTES
    );

    reader->sequential_advice_enabled = 1;
    reader->sequential_prefetch_bytes = prefetch_bytes;
    reader->sequential_release_bytes = release_bytes;
}

static void reader_apply_regular_file_sequential_advice(
    Reader *reader,
    uint64_t read_offset,
    size_t bytes_read
)
{
    uint64_t read_end;

    if (reader == NULL ||
        !reader->sequential_advice_enabled ||
        reader->fd < 0 ||
        bytes_read == 0U) {
        return;
    }

    if (UINT64_MAX - read_offset < (uint64_t)bytes_read) {
        read_end = UINT64_MAX;
    } else {
        read_end = read_offset + (uint64_t)bytes_read;
    }

    if (reader->sequential_last_read_end_offset > 0U &&
        (read_offset < reader->sequential_last_read_offset ||
         read_offset >
             reader->sequential_last_read_end_offset + (uint64_t)reader->chunk_size)) {
        reader->sequential_prefetch_end_offset = read_end;
        reader->sequential_release_end_offset = read_offset;
    }

#ifdef __linux__
#ifdef POSIX_FADV_WILLNEED
    if (reader->sequential_prefetch_bytes > 0U &&
        (reader->source_size == 0U || read_end < reader->source_size)) {
        uint64_t desired_end = read_end + (uint64_t)reader->sequential_prefetch_bytes;
        uint64_t advise_start = read_end;

        if (desired_end < read_end) {
            desired_end = UINT64_MAX;
        }
        if (reader->source_size > 0U && desired_end > reader->source_size) {
            desired_end = reader->source_size;
        }
        if (reader->sequential_prefetch_end_offset > advise_start) {
            advise_start = reader->sequential_prefetch_end_offset;
        }
        if (desired_end > advise_start) {
            (void)posix_fadvise(
                reader->fd,
                (off_t)advise_start,
                (off_t)(desired_end - advise_start),
                POSIX_FADV_WILLNEED
            );
            reader->sequential_prefetch_end_offset = desired_end;
        }
    }
#endif
#ifdef POSIX_FADV_DONTNEED
    if (reader->sequential_release_bytes > 0U &&
        read_end > (uint64_t)reader->sequential_release_bytes) {
        uint64_t keep_start = read_end - (uint64_t)reader->sequential_release_bytes;

        if (keep_start > reader->sequential_release_end_offset) {
            uint64_t advise_start = reader->sequential_release_end_offset;
            uint64_t advise_end = keep_start;

            if (advise_end > advise_start) {
                (void)posix_fadvise(
                    reader->fd,
                    (off_t)advise_start,
                    (off_t)(advise_end - advise_start),
                    POSIX_FADV_DONTNEED
                );
                reader->sequential_release_end_offset = advise_end;
            }
        }
    }
#endif
#endif

    reader->sequential_last_read_offset = read_offset;
    reader->sequential_last_read_end_offset = read_end;
}
#ifdef __APPLE__
static int resolve_mounted_source_device_macos(
    const char *path,
    char *out,
    size_t out_size
)
{
    char quoted_path[PATH_MAX * 2U];
    char command[(PATH_MAX * 2U) + 64U];
    char line[1024];
    FILE *pipe;

    if (path == NULL || out == NULL || out_size == 0U) {
        set_reader_error("resolve mounted source: invalid macOS arguments");
        return 0;
    }

    shell_quote_single(path, quoted_path, sizeof(quoted_path));
    if (quoted_path[0] == '\0') {
        set_reader_error("resolve mounted source: failed to quote mount path");
        return 0;
    }

    if (snprintf(
            command,
            sizeof(command),
            "/bin/df -P %s 2>/dev/null",
            quoted_path) >= (int)sizeof(command)) {
        set_reader_error("resolve mounted source: df command too long");
        return 0;
    }

    pipe = popen(command, "r");
    if (pipe == NULL) {
        set_reader_errno_error("resolve mounted source df failed");
        return 0;
    }

    if (fgets(line, sizeof(line), pipe) == NULL ||
        fgets(line, sizeof(line), pipe) == NULL) {
        (void)pclose(pipe);
        set_reader_error("resolve mounted source: df returned no mount data");
        return 0;
    }

    (void)pclose(pipe);

    {
        char device[PATH_MAX];
        char mount_point[PATH_MAX];
        const char *scheme = NULL;
        const char *scheme_value = NULL;
        char line_copy[1024];
        char *saveptr = NULL;
        char *token = NULL;

        if (sscanf(line, "%1023s", device) != 1) {
            set_reader_error("resolve mounted source: failed to parse df output");
            return 0;
        }

        mount_point[0] = '\0';
        snprintf(line_copy, sizeof(line_copy), "%s", line);
        token = strtok_r(line_copy, " \t\r\n", &saveptr);
        while (token != NULL) {
            if (token[0] == '\0') {
                token = strtok_r(NULL, " \t\r\n", &saveptr);
                continue;
            }
            if (token[0] == '/') {
                snprintf(mount_point, sizeof(mount_point), "%s", token);
            }
            token = strtok_r(NULL, " \t\r\n", &saveptr);
        }

        if (mount_point[0] != '\0') {
            char mount_quoted[PATH_MAX * 2U];

            shell_quote_single(mount_point, mount_quoted, sizeof(mount_quoted));
            if (mount_quoted[0] != '\0' &&
                snprintf(
                    command,
                    sizeof(command),
                    "/usr/sbin/diskutil info %s 2>/dev/null",
                    mount_quoted) < (int)sizeof(command)) {
                pipe = popen(command, "r");
                if (pipe != NULL) {
                    while (fgets(line, sizeof(line), pipe) != NULL) {
                        char *value;

                        if (strncmp(line, "   Device Node:", 15) != 0 &&
                            strncmp(line, "Device Node:", 12) != 0) {
                            continue;
                        }
                        value = strchr(line, ':');
                        if (value == NULL) {
                            continue;
                        }
                        value++;
                        while (*value != '\0' && isspace((unsigned char)*value)) {
                            value++;
                        }
                        {
                            size_t len = strcspn(value, "\r\n");

                            if (len >= 5U &&
                                strncmp(value, "/dev/", 5) == 0 &&
                                len < out_size) {
                                memcpy(out, value, len);
                                out[len] = '\0';
                                (void)pclose(pipe);
                                return 1;
                            }
                        }
                    }
                    (void)pclose(pipe);
                }
            }
        }

        if (strncmp(device, "/dev/", 5) != 0 || device[5] == '\0') {
            scheme = strstr(device, "://");
            if (scheme != NULL) {
                char parsed_device[PATH_MAX];
                size_t parsed_len;

                scheme_value = scheme + 3;
                parsed_len = strcspn(scheme_value, "/");
                if (parsed_len > 0U &&
                    parsed_len < sizeof(parsed_device) &&
                    snprintf(
                        parsed_device,
                        sizeof(parsed_device),
                        "/dev/%.*s",
                        (int)parsed_len,
                        scheme_value) < (int)sizeof(parsed_device)) {
                    snprintf(device, sizeof(device), "%s", parsed_device);
                }
            }
        }
        if (strncmp(device, "/dev/", 5) != 0 || device[5] == '\0') {
            set_reader_error("resolve mounted source: df did not report a device path");
            return 0;
        }
        if (snprintf(out, out_size, "%s", device) >= (int)out_size) {
            set_reader_error("resolve mounted source: device path too long");
            return 0;
        }
    }

    return 1;
}
#endif

#ifdef __linux__
static int block_path_is_partition(const char *path)
{
    char basename[128];
    char sysfs_path[256];

    if (path == NULL || strncmp(path, "/dev/", 5) != 0) {
        return 0;
    }

    {
        const char *basename_ptr = strrchr(path, '/');

        if (basename_ptr == NULL) {
            basename_ptr = path;
        } else {
            basename_ptr++;
        }

        snprintf(basename, sizeof(basename), "%s", basename_ptr);
    }

    if (basename[0] == '\0') {
        return 0;
    }

    snprintf(
        sysfs_path,
        sizeof(sysfs_path),
        "/sys/class/block/%s/partition",
        basename
    );

    return access(sysfs_path, F_OK) == 0;
}

static int path_matches_device_or_partition(
    const char *requested_path,
    const char *mounted_source
)
{
    const char *suffix;

    if (requested_path == NULL || mounted_source == NULL) {
        return 0;
    }

    if (strcmp(requested_path, mounted_source) == 0) {
        return 1;
    }

    if (strncmp(requested_path, "/dev/", 5) != 0 ||
        strncmp(mounted_source, "/dev/", 5) != 0) {
        return 0;
    }

    if (block_path_is_partition(requested_path)) {
        return 0;
    }

    if (strncmp(mounted_source, requested_path, strlen(requested_path)) != 0) {
        return 0;
    }

    suffix = mounted_source + strlen(requested_path);
    if (*suffix == '\0') {
        return 1;
    }

    if (*suffix == 'p' && isdigit((unsigned char)suffix[1])) {
        return 1;
    }

    return isdigit((unsigned char)*suffix);
}

static int compare_mount_entries_by_target_desc(
    const void *left,
    const void *right
)
{
    const MountEntry *a = (const MountEntry *)left;
    const MountEntry *b = (const MountEntry *)right;
    size_t a_len = strlen(a->target);
    size_t b_len = strlen(b->target);

    if (a_len < b_len) {
        return 1;
    }

    if (a_len > b_len) {
        return -1;
    }

    return strcmp(a->target, b->target);
}

static size_t collect_related_mounts(
    const char *path,
    MountEntry **entries_out
)
{
#ifdef __linux__
    FILE *mounts;
    MountEntry *entries = NULL;
    size_t count = 0;
    size_t capacity = 0;
    char source[256];
    char target[256];
    char fstype[64];
    char options[256];

    if (entries_out == NULL) {
        return 0;
    }

    *entries_out = NULL;

    if (path == NULL) {
        return 0;
    }

    mounts = fopen("/proc/mounts", "r");
    if (mounts == NULL) {
        return 0;
    }

    while (fscanf(
               mounts,
               "%255s %255s %63s %255s %*d %*d",
               source,
               target,
               fstype,
               options) == 4) {
        MountEntry *new_entries;

        if (!path_matches_device_or_partition(path, source)) {
            continue;
        }

        if (count == capacity) {
            size_t new_capacity = (capacity == 0) ? 8 : capacity * 2;

            new_entries = (MountEntry *)realloc(
                entries,
                new_capacity * sizeof(*entries)
            );

            if (new_entries == NULL) {
                free(entries);
                fclose(mounts);
                return 0;
            }

            entries = new_entries;
            capacity = new_capacity;
        }

        snprintf(entries[count].source, sizeof(entries[count].source), "%s", source);
        snprintf(entries[count].target, sizeof(entries[count].target), "%s", target);
        count++;
    }

    fclose(mounts);

    if (count > 1) {
        qsort(entries, count, sizeof(*entries), compare_mount_entries_by_target_desc);
    }

    *entries_out = entries;
    return count;
#else
    (void)path;
    (void)entries_out;
    return 0;
#endif
}
#endif

const char *reader_last_error(void)
{
    return g_reader_last_error;
}

int reader_last_errno(void)
{
    return g_reader_last_errno;
}

int reader_error_is_fatal_device_error(int error_code)
{
    return reader_error_is_fatal_device_error_local(error_code);
}

static uint64_t determine_source_size(const char *path, const struct stat *st)
{
#ifdef __APPLE__
    int fd;
    uint64_t block_count = 0;
    uint32_t block_size = 0;
#endif
#ifdef __linux__
    int fd;
    unsigned long long block_size = 0;
#endif

    if (path == NULL || st == NULL) {
        return 0;
    }

    if (S_ISREG(st->st_mode)) {
        return (uint64_t)st->st_size;
    }

#ifdef __APPLE__
    if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode)) {
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            if (ioctl(fd, DKIOCGETBLOCKCOUNT, &block_count) == 0 &&
                ioctl(fd, DKIOCGETBLOCKSIZE, &block_size) == 0 &&
                block_size > 0) {
                close(fd);
                return block_count * (uint64_t)block_size;
            }

            close(fd);
        }
    }
#endif

#ifdef __linux__
    if (S_ISBLK(st->st_mode)) {
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            if (ioctl(fd, BLKGETSIZE64, &block_size) == 0) {
                close(fd);
                return (uint64_t)block_size;
            }

            close(fd);
        }
    }
#endif

    return 0;
}

uint64_t reader_detect_source_size(const char *path)
{
    struct stat st;

    if (path == NULL || path[0] == '\0' || stat(path, &st) != 0) {
        return 0U;
    }
    return determine_source_size(path, &st);
}

static int is_power_of_two_u64(uint64_t value)
{
    return value > 0U && (value & (value - 1U)) == 0U;
}

static void sanitize_read_error_note(char *note)
{
    size_t i;

    if (note == NULL) {
        return;
    }

    for (i = 0; note[i] != '\0'; i++) {
        if (note[i] == '\t' || note[i] == '\r' || note[i] == '\n') {
            note[i] = ' ';
        }
    }
}

static void sanitize_read_error_field(char *text)
{
    size_t i;

    if (text == NULL) {
        return;
    }

    for (i = 0; text[i] != '\0'; i++) {
        if (text[i] == '\t' || text[i] == '\r' || text[i] == '\n') {
            text[i] = ' ';
        }
    }
}

static int build_cluster_report_path_from_detail(
    const char *detail_path,
    char *out,
    size_t out_size
)
{
    const char *slash;
    size_t dir_len;

    if (out == NULL || out_size == 0U) {
        return 0;
    }

    out[0] = '\0';
    if (detail_path == NULL || detail_path[0] == '\0') {
        return 0;
    }

    slash = strrchr(detail_path, '/');
    if (slash == NULL) {
        return snprintf(out, out_size, "%s", "read_error_clusters.tsv") < (int)out_size;
    }

    dir_len = (size_t)(slash - detail_path);
    return snprintf(
               out,
               out_size,
               "%.*s/%s",
               (int)dir_len,
               detail_path,
               "read_error_clusters.tsv"
           ) < (int)out_size;
}

static int append_read_error_report_row(
    const char *path,
    uint64_t offset,
    uint64_t end_offset,
    uint64_t bad_bytes,
    int saved_errno,
    uint64_t granularity_bytes,
    const char *source_path,
    const char *run_id,
    const char *note
)
{
    FILE *report;
    int needs_header;

    if (path == NULL || path[0] == '\0' || end_offset <= offset || bad_bytes == 0U) {
        return 0;
    }

    needs_header = access(path, F_OK) != 0;
    report = fopen(path, "a");
    if (report == NULL) {
        return 0;
    }

    if (needs_header) {
        fprintf(
            report,
            "offset\tend_offset\tbytes\terrno_code\tgranularity_bytes\tsource_path\trun_id\tnote\n"
        );
    }

    fprintf(
        report,
        "%llu\t%llu\t%llu\t%d\t%llu\t%s\t%s\t%s\n",
        (unsigned long long)offset,
        (unsigned long long)end_offset,
        (unsigned long long)bad_bytes,
        saved_errno,
        (unsigned long long)granularity_bytes,
        source_path != NULL ? source_path : "",
        run_id != NULL ? run_id : "",
        note != NULL ? note : ""
    );
    fclose(report);
    return 1;
}

static void reader_flush_pending_bad_read_cluster(Reader *reader)
{
    char note[192];
    char source_path[1024];
    char run_id[256];

    if (reader == NULL || reader->pending_cluster_error_end_offset == 0U) {
        return;
    }

    snprintf(
        source_path,
        sizeof(source_path),
        "%s",
        reader->path != NULL ? reader->path : ""
    );
    snprintf(run_id, sizeof(run_id), "%s", reader->error_report_run_id);
    sanitize_read_error_field(source_path);
    sanitize_read_error_field(run_id);

    if (reader->pending_cluster_error_spans > 1U) {
        snprintf(
            note,
            sizeof(note),
            "clustered_zero_filled_preserved_offsets:%s spans=%llu gap_merge=%llu",
            strerror(reader->pending_cluster_error_errno),
            (unsigned long long)reader->pending_cluster_error_spans,
            (unsigned long long)READER_BAD_READ_CLUSTER_GAP_BYTES
        );
    } else {
        snprintf(
            note,
            sizeof(note),
            "clustered_zero_filled_preserved_offsets:%s",
            strerror(reader->pending_cluster_error_errno)
        );
    }
    sanitize_read_error_note(note);

    (void)append_read_error_report_row(
        reader->error_cluster_report_path,
        reader->pending_cluster_error_offset,
        reader->pending_cluster_error_end_offset,
        reader->pending_cluster_error_bytes,
        reader->pending_cluster_error_errno,
        READER_BAD_READ_CLUSTER_GAP_BYTES,
        source_path,
        run_id,
        note
    );

    reader_update_trouble_map(
        reader,
        reader->pending_cluster_error_offset,
        reader->pending_cluster_error_end_offset,
        reader->pending_cluster_error_bytes,
        reader->pending_cluster_error_errno
    );

    reader->pending_cluster_error_offset = 0U;
    reader->pending_cluster_error_end_offset = 0U;
    reader->pending_cluster_error_bytes = 0U;
    reader->pending_cluster_error_spans = 0U;
    reader->pending_cluster_error_errno = 0;
}

static void reader_note_bad_read_cluster(
    Reader *reader,
    uint64_t offset,
    size_t length,
    int saved_errno
)
{
    uint64_t end_offset;

    if (reader == NULL || length == 0U) {
        return;
    }

    end_offset = offset + (uint64_t)length;
    if (reader->pending_cluster_error_end_offset > 0U &&
        saved_errno == reader->pending_cluster_error_errno &&
        offset <= reader->pending_cluster_error_end_offset + READER_BAD_READ_CLUSTER_GAP_BYTES) {
        if (end_offset > reader->pending_cluster_error_end_offset) {
            reader->pending_cluster_error_end_offset = end_offset;
        }
        reader->pending_cluster_error_bytes += (uint64_t)length;
        reader->pending_cluster_error_spans++;
        return;
    }

    reader_flush_pending_bad_read_cluster(reader);
    reader->pending_cluster_error_offset = offset;
    reader->pending_cluster_error_end_offset = end_offset;
    reader->pending_cluster_error_bytes = (uint64_t)length;
    reader->pending_cluster_error_spans = 1U;
    reader->pending_cluster_error_errno = saved_errno;
}

static void reader_flush_pending_bad_read_span(Reader *reader)
{
    char note[192];
    char source_path[1024];
    char run_id[256];
    uint64_t bad_bytes = 0U;
    uint64_t offset = 0U;
    uint64_t end_offset = 0U;
    uint64_t span_count = 0U;
    int saved_errno = 0;
    uint64_t report_size = 0U;

    if (reader == NULL || reader->pending_read_error_end_offset == 0U) {
        return;
    }

    offset = reader->pending_read_error_offset;
    end_offset = reader->pending_read_error_end_offset;
    bad_bytes = reader->pending_read_error_bytes;
    span_count = reader->pending_read_error_spans;
    saved_errno = reader->pending_read_error_errno;
    snprintf(
        source_path,
        sizeof(source_path),
        "%s",
        reader->path != NULL ? reader->path : ""
    );
    snprintf(run_id, sizeof(run_id), "%s", reader->error_report_run_id);
    sanitize_read_error_field(source_path);
    sanitize_read_error_field(run_id);

    if (reader->error_report_path[0] != '\0' &&
        !reader->error_report_detail_suppressed) {
        struct stat st;

        if (stat(reader->error_report_path, &st) == 0 &&
            S_ISREG(st.st_mode) &&
            st.st_size >= 0) {
            report_size = (uint64_t)st.st_size;
        }

        if (report_size >= READER_MAX_ERROR_REPORT_FILE_BYTES) {
            reader->error_report_detail_suppressed = 1;
            log_runtime_event_info(
                "Read error detail report reached %.0f MiB; continuing with compact read_error_clusters.tsv only",
                (double)READER_MAX_ERROR_REPORT_FILE_BYTES / (1024.0 * 1024.0)
            );
        } else {
            if (span_count > 1U) {
                snprintf(
                    note,
                    sizeof(note),
                    "zero_filled_preserved_offsets:%s spans=%llu",
                    strerror(saved_errno),
                    (unsigned long long)span_count
                );
            } else {
                snprintf(
                    note,
                    sizeof(note),
                    "zero_filled_preserved_offsets:%s",
                    strerror(saved_errno)
                );
            }
            sanitize_read_error_note(note);

            if (append_read_error_report_row(
                    reader->error_report_path,
                    offset,
                    end_offset,
                    bad_bytes,
                    saved_errno,
                    READER_BAD_READ_MIN_SPAN,
                    source_path,
                    run_id,
                    note)) {
                reader->read_error_range_count++;
            }
        }
    }

    if (reader->precise_record_mode) {
        log_runtime_event_error(
            "Reader skipped unreadable range %llu..%llu (%llu bytes) during precise-record fallback; preserved absolute offsets with zero-fill (%s)",
            (unsigned long long)offset,
            (unsigned long long)end_offset,
            (unsigned long long)bad_bytes,
            strerror(saved_errno)
        );
    } else {
        log_runtime_event_error(
            "Reader skipped unreadable range %llu..%llu (%llu bytes) after smaller-read fallback; preserved absolute offsets with zero-fill (%s)",
            (unsigned long long)offset,
            (unsigned long long)end_offset,
            (unsigned long long)bad_bytes,
            strerror(saved_errno)
        );
    }

    reader_write_bad_read_state(
        reader,
        "skip_range",
        offset,
        bad_bytes,
        end_offset,
        span_count,
        saved_errno
    );

    reader->pending_read_error_offset = 0U;
    reader->pending_read_error_end_offset = 0U;
    reader->pending_read_error_bytes = 0U;
    reader->pending_read_error_spans = 0U;
    reader->pending_read_error_errno = 0;
}

static void reader_note_bad_read_span(
    Reader *reader,
    uint64_t offset,
    size_t length,
    int saved_errno
)
{
    uint64_t end_offset;

    if (reader == NULL || length == 0U) {
        return;
    }

    end_offset = offset + (uint64_t)length;

    reader->read_error_count++;
    reader->read_error_bytes += (uint64_t)length;
    reader->last_read_error_offset = offset;
    reader->last_read_error_length = (uint64_t)length;

    reader_write_bad_read_state(
        reader,
        "read_fail",
        offset,
        (uint64_t)length,
        offset + (uint64_t)length,
        1U,
        saved_errno
    );

    if (reader->read_error_count <= 8U ||
        is_power_of_two_u64(reader->read_error_count)) {
        log_info(
            "Read error at byte %llu for %zu bytes (%s); filling gap with zeroes and preserving offsets",
            (unsigned long long)offset,
            length,
            strerror(saved_errno)
        );
    }

    reader_note_bad_read_cluster(reader, offset, length, saved_errno);

    if (reader->pending_read_error_end_offset > 0U &&
        offset == reader->pending_read_error_end_offset &&
        saved_errno == reader->pending_read_error_errno) {
        reader->pending_read_error_end_offset = end_offset;
        reader->pending_read_error_bytes += (uint64_t)length;
        reader->pending_read_error_spans++;
        return;
    }

    reader_flush_pending_bad_read_span(reader);
    reader->pending_read_error_offset = offset;
    reader->pending_read_error_end_offset = end_offset;
    reader->pending_read_error_bytes = (uint64_t)length;
    reader->pending_read_error_spans = 1U;
    reader->pending_read_error_errno = saved_errno;
}

static ssize_t reader_pread_retry(
    Reader *reader,
    uint8_t *buffer,
    size_t length,
    uint64_t offset,
    int *out_errno
)
{
    size_t alignment = 0U;
    size_t request = length;
    ssize_t result;

    if (out_errno != NULL) {
        *out_errno = 0;
    }
    if (reader == NULL || reader->fd < 0 || buffer == NULL || length == 0U) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        return -1;
    }
    if (offset > (uint64_t)INT64_MAX) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        return -1;
    }
    if (request > (size_t)SSIZE_MAX) {
        request = (size_t)SSIZE_MAX;
    }

    alignment = reader->direct_read_alignment;
    if (alignment > 0U &&
        ((offset % (uint64_t)alignment) != 0U ||
         (request % alignment) != 0U)) {
        uint64_t aligned_offset = offset - (offset % (uint64_t)alignment);
        uint64_t prefix = offset - aligned_offset;
        uint64_t needed = prefix + (uint64_t)request;
        uint64_t aligned_request_u64 =
            ((needed + (uint64_t)alignment - 1U) / (uint64_t)alignment) *
            (uint64_t)alignment;
        size_t aligned_request;
        uint8_t *temp;
        size_t copied = 0U;

        if (aligned_request_u64 < needed ||
            aligned_request_u64 > (uint64_t)SIZE_MAX ||
            aligned_request_u64 > (uint64_t)SSIZE_MAX) {
            if (out_errno != NULL) {
                *out_errno = EINVAL;
            }
            return -1;
        }

        aligned_request = (size_t)aligned_request_u64;
        temp = (uint8_t *)malloc(aligned_request);
        if (temp == NULL) {
            if (out_errno != NULL) {
                *out_errno = ENOMEM;
            }
            return -1;
        }

        do {
            result = pread(reader->fd, temp, aligned_request, (off_t)aligned_offset);
        } while (result < 0 && errno == EINTR);

        if (result < 0) {
            if (out_errno != NULL) {
                *out_errno = errno;
            }
            free(temp);
            return -1;
        }

        if (result > 0 && (uint64_t)result > prefix) {
            copied = (size_t)((uint64_t)result - prefix);
            if (copied > request) {
                copied = request;
            }
            memcpy(buffer, temp + prefix, copied);
        }
        free(temp);
        return (ssize_t)copied;
    }

    do {
        result = pread(reader->fd, buffer, request, (off_t)offset);
    } while (result < 0 && errno == EINTR);

    if (result < 0 && out_errno != NULL) {
        *out_errno = errno;
    }

    return result;
}

static ssize_t reader_stream_read_retry(
    Reader *reader,
    uint8_t *buffer,
    size_t length,
    uint64_t offset,
    int *out_errno
)
{
    size_t alignment = 0U;
    size_t got;
    size_t small_want;
    int saved_errno = 0;

    if (out_errno != NULL) {
        *out_errno = 0;
    }
    if (reader == NULL || reader->file == NULL || buffer == NULL || length == 0U) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        return -1;
    }
    if (offset > (uint64_t)INT64_MAX) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        return -1;
    }

    alignment = reader->direct_read_alignment;
    if (alignment > 0U &&
        ((offset % (uint64_t)alignment) != 0U ||
         (length % alignment) != 0U)) {
        uint64_t aligned_offset = offset - (offset % (uint64_t)alignment);
        uint64_t prefix = offset - aligned_offset;
        uint64_t needed = prefix + (uint64_t)length;
        uint64_t aligned_request_u64 =
            ((needed + (uint64_t)alignment - 1U) / (uint64_t)alignment) *
            (uint64_t)alignment;
        size_t aligned_request;
        uint8_t *temp;
        size_t copied = 0U;

        if (aligned_request_u64 < needed ||
            aligned_request_u64 > (uint64_t)SIZE_MAX) {
            if (out_errno != NULL) {
                *out_errno = EINVAL;
            }
            return -1;
        }

        aligned_request = (size_t)aligned_request_u64;
        temp = (uint8_t *)malloc(aligned_request);
        if (temp == NULL) {
            if (out_errno != NULL) {
                *out_errno = ENOMEM;
            }
            return -1;
        }

        if (fseeko(reader->file, (off_t)aligned_offset, SEEK_SET) != 0) {
            saved_errno = errno;
            if (out_errno != NULL) {
                *out_errno = saved_errno;
            }
            free(temp);
            return -1;
        }

        errno = 0;
        got = fread(temp, 1, aligned_request, reader->file);
        if (got > 0) {
            if ((uint64_t)got > prefix) {
                copied = (size_t)((uint64_t)got - prefix);
                if (copied > length) {
                    copied = length;
                }
                memcpy(buffer, temp + prefix, copied);
            }
            clearerr(reader->file);
            free(temp);
            return (ssize_t)copied;
        }
        if (!ferror(reader->file)) {
            free(temp);
            return 0;
        }

        saved_errno = errno;
        clearerr(reader->file);
        free(temp);
        if (out_errno != NULL) {
            *out_errno = saved_errno;
        }
        return -1;
    }

    if (fseeko(reader->file, (off_t)offset, SEEK_SET) != 0) {
        if (out_errno != NULL) {
            *out_errno = errno;
        }
        return -1;
    }

    errno = 0;
    got = fread(buffer, 1, length, reader->file);
    if (got > 0) {
        clearerr(reader->file);
        return (ssize_t)got;
    }
    if (!ferror(reader->file)) {
        return 0;
    }

    saved_errno = errno;
    clearerr(reader->file);

    small_want = length / 4U;
    if (small_want > 1024U * 1024U) {
        small_want = 1024U * 1024U;
    }

    while (small_want >= READER_BAD_READ_MIN_SPAN) {
        if (fseeko(reader->file, (off_t)offset, SEEK_SET) != 0) {
            saved_errno = errno;
            if (out_errno != NULL) {
                *out_errno = saved_errno;
            }
            return -1;
        }

        errno = 0;
        got = fread(buffer, 1, small_want, reader->file);
        if (got > 0) {
            clearerr(reader->file);
            return (ssize_t)got;
        }
        if (!ferror(reader->file)) {
            return 0;
        }

        saved_errno = errno;
        clearerr(reader->file);
        small_want /= 4U;
    }

    if (out_errno != NULL) {
        *out_errno = saved_errno;
    }
    return -1;
}

static ssize_t reader_stream_read_once(
    Reader *reader,
    uint8_t *buffer,
    size_t length,
    uint64_t offset,
    int *out_errno
)
{
    size_t alignment = 0U;
    size_t got;
    int saved_errno = 0;

    if (out_errno != NULL) {
        *out_errno = 0;
    }
    if (reader == NULL || reader->file == NULL || buffer == NULL || length == 0U) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        return -1;
    }
    if (offset > (uint64_t)INT64_MAX) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        return -1;
    }

    alignment = reader->direct_read_alignment;
    if (alignment > 0U &&
        ((offset % (uint64_t)alignment) != 0U ||
         (length % alignment) != 0U)) {
        uint64_t aligned_offset = offset - (offset % (uint64_t)alignment);
        uint64_t prefix = offset - aligned_offset;
        uint64_t needed = prefix + (uint64_t)length;
        uint64_t aligned_request_u64 =
            ((needed + (uint64_t)alignment - 1U) / (uint64_t)alignment) *
            (uint64_t)alignment;
        size_t aligned_request;
        uint8_t *temp;
        size_t copied = 0U;

        if (aligned_request_u64 < needed ||
            aligned_request_u64 > (uint64_t)SIZE_MAX) {
            if (out_errno != NULL) {
                *out_errno = EINVAL;
            }
            return -1;
        }

        aligned_request = (size_t)aligned_request_u64;
        temp = (uint8_t *)malloc(aligned_request);
        if (temp == NULL) {
            if (out_errno != NULL) {
                *out_errno = ENOMEM;
            }
            return -1;
        }

        if (fseeko(reader->file, (off_t)aligned_offset, SEEK_SET) != 0) {
            saved_errno = errno;
            if (out_errno != NULL) {
                *out_errno = saved_errno;
            }
            free(temp);
            return -1;
        }

        errno = 0;
        got = fread(temp, 1, aligned_request, reader->file);
        if (got > 0U) {
            if ((uint64_t)got > prefix) {
                copied = (size_t)((uint64_t)got - prefix);
                if (copied > length) {
                    copied = length;
                }
                memcpy(buffer, temp + prefix, copied);
            }
            if (ferror(reader->file)) {
                saved_errno = errno != 0 ? errno : EIO;
                if (out_errno != NULL) {
                    *out_errno = saved_errno;
                }
            }
            clearerr(reader->file);
            free(temp);
            return (ssize_t)copied;
        }
        if (!ferror(reader->file)) {
            free(temp);
            return 0;
        }

        saved_errno = errno != 0 ? errno : EIO;
        clearerr(reader->file);
        free(temp);
        if (out_errno != NULL) {
            *out_errno = saved_errno;
        }
        return -1;
    }

    if (fseeko(reader->file, (off_t)offset, SEEK_SET) != 0) {
        if (out_errno != NULL) {
            *out_errno = errno;
        }
        return -1;
    }

    errno = 0;
    got = fread(buffer, 1, length, reader->file);
    if (got > 0U) {
        if (ferror(reader->file)) {
            saved_errno = errno != 0 ? errno : EIO;
            if (out_errno != NULL) {
                *out_errno = saved_errno;
            }
        }
        clearerr(reader->file);
        return (ssize_t)got;
    }
    if (!ferror(reader->file)) {
        return 0;
    }

    saved_errno = errno != 0 ? errno : EIO;
    clearerr(reader->file);
    if (out_errno != NULL) {
        *out_errno = saved_errno;
    }
    return -1;
}

static ssize_t reader_read_direct_once(
    Reader *reader,
    uint8_t *buffer,
    size_t length,
    uint64_t offset,
    int *out_errno
)
{
    if (reader == NULL) {
        if (out_errno != NULL) {
            *out_errno = EINVAL;
        }
        return -1;
    }

    if (reader->use_stdio_device_reads) {
        return reader_stream_read_once(reader, buffer, length, offset, out_errno);
    }

    return reader_pread_retry(reader, buffer, length, offset, out_errno);
}

static size_t reader_read_resilient_span_depth(
    Reader *reader,
    uint8_t *buffer,
    uint64_t offset,
    size_t length,
    unsigned int depth
)
{
    int saved_errno = 0;
    ssize_t bytes_read;
    ReaderTroubleMapEntry trouble_entry = {0};
    size_t forced_skip_length = 0U;

    if (reader == NULL || buffer == NULL || length == 0U) {
        return 0U;
    }

    if (reader->use_stdio_device_reads) {
        bytes_read = reader_stream_read_retry(
            reader,
            buffer,
            length,
            offset,
            &saved_errno
        );
    } else {
        bytes_read = reader_pread_retry(
            reader,
            buffer,
            length,
            offset,
            &saved_errno
        );
    }
    if (bytes_read > 0) {
        app_gui_note_read_coverage(
            offset,
            offset + (uint64_t)bytes_read
        );
        return (size_t)bytes_read;
    }
    if (bytes_read == 0) {
        return 0U;
    }

    if (reader_regular_source_path_became_unavailable(reader)) {
        set_reader_saved_errno_error("source path unavailable", saved_errno);
        reader_note_regular_source_path_unavailable(
            reader,
            "raw read",
            offset,
            length,
            saved_errno
        );
        return 0U;
    }

    if (reader_error_is_fatal_device_error_local(saved_errno)) {
        set_reader_saved_errno_error("read failed", saved_errno);
        reader_note_source_unavailable(
            reader,
            "raw read",
            offset,
            length,
            saved_errno
        );
        return 0U;
    }

    if (depth == 0U) {
        log_runtime_event_error(
            "Read failed at byte %llu for %zu bytes (%s); trying smaller reads before deciding whether to skip",
            (unsigned long long)offset,
            length,
            strerror(saved_errno)
        );
        reader_write_bad_read_state(
            reader,
            "read_fail",
            offset,
            (uint64_t)length,
            offset + (uint64_t)length,
            1U,
            saved_errno
        );
        app_gui_note_trouble(
            offset,
            offset + (uint64_t)length,
            "read_fail"
        );
        reader_update_trouble_map(
            reader,
            offset,
            offset + (uint64_t)length,
            (uint64_t)length,
            saved_errno
        );
        if (!reader->precise_record_mode &&
            reader_find_matching_trouble_entry(
                reader,
                offset,
                offset + (uint64_t)length,
                &trouble_entry)) {
            forced_skip_length = reader_forced_skip_length_for_trouble(
                &trouble_entry,
                length
            );
        }
        if (forced_skip_length > 0U) {
            memset(buffer, 0, forced_skip_length);
            app_gui_note_trouble(
                offset,
                offset + (uint64_t)forced_skip_length,
                "forced_skip"
            );
            log_runtime_event_error(
                "Reader recognized repeated trouble at byte %llu..%llu (hits=%llu); forcing a %zu-byte zero-filled skip now so the main scan can move on and revisit the zone later",
                (unsigned long long)trouble_entry.offset,
                (unsigned long long)trouble_entry.end_offset,
                (unsigned long long)trouble_entry.hit_count,
                forced_skip_length
            );
            reader_note_bad_read_span(
                reader,
                offset,
                forced_skip_length,
                saved_errno
            );
            return forced_skip_length;
        }
    }

    if (reader->source_size == 0U) {
        set_reader_errno_error("read failed");
        return 0U;
    }

    if (length > READER_BAD_READ_MIN_SPAN) {
        size_t half = length / 2U;

        if (half < READER_BAD_READ_MIN_SPAN) {
            half = READER_BAD_READ_MIN_SPAN;
        }
        half -= half % READER_BAD_READ_MIN_SPAN;
        if (half == 0U || half >= length) {
            half = length / 2U;
        }

        return reader_read_resilient_span_depth(
            reader,
            buffer,
            offset,
            half,
            depth + 1U
        );
    }

    memset(buffer, 0, length);
    reader_note_bad_read_span(reader, offset, length, saved_errno);
    return length;
}

static size_t reader_read_resilient_span(
    Reader *reader,
    uint8_t *buffer,
    uint64_t offset,
    size_t length
)
{
    return reader_read_resilient_span_depth(
        reader,
        buffer,
        offset,
        length,
        0U
    );
}

static size_t reader_read_resilient(
    Reader *reader,
    uint8_t *buffer,
    uint64_t offset,
    size_t length
)
{
    size_t total = 0U;

    while (total < length) {
        if (app_stop_requested() || app_supervisor_generation_stale()) {
            break;
        }

        size_t chunk = reader_read_resilient_span(
            reader,
            buffer + total,
            offset + (uint64_t)total,
            length - total
        );

        if (chunk == 0U) {
            break;
        }
        total += chunk;
    }

    return total;
}

size_t reader_read_at_resilient(
    Reader *reader,
    uint64_t absolute_offset,
    void *buffer,
    size_t length,
    uint64_t *out_new_error_bytes
)
{
    uint64_t errors_before;
    size_t bytes_read;

    if (out_new_error_bytes != NULL) {
        *out_new_error_bytes = 0U;
    }
    if (reader == NULL || reader->file == NULL || buffer == NULL || length == 0U) {
        return 0U;
    }
    errors_before = reader->read_error_bytes;
    bytes_read = reader_read_resilient(
        reader,
        (uint8_t *)buffer,
        absolute_offset,
        length
    );
    if (out_new_error_bytes != NULL && reader->read_error_bytes > errors_before) {
        *out_new_error_bytes = reader->read_error_bytes - errors_before;
    }
    return bytes_read;
}

static size_t reader_read_precise_record_chunk(
    Reader *reader,
    uint8_t *buffer,
    uint64_t offset,
    size_t length
)
{
    size_t sector_size;
    size_t total = 0U;

    if (reader == NULL || buffer == NULL || length == 0U) {
        return 0U;
    }

    sector_size = reader->direct_read_alignment;
    if (sector_size == 0U || sector_size > length) {
        sector_size = READER_BAD_READ_MIN_SPAN;
    }
    if (sector_size == 0U || sector_size > length) {
        sector_size = length;
    }

    reader->precise_record_sector_size = sector_size;
    reader->last_precise_record_first_sector_failed = 0;
    reader->last_precise_record_later_sector_failed = 0;
    reader->last_precise_record_first_sector_partial = 0;
    reader->last_precise_record_failed_sectors = 0U;
    reader->last_precise_record_skipped_sectors = 0U;
    reader->last_precise_record_first_sector_bytes_read = 0U;
    reader->last_precise_record_first_sector_bytes_read = 0U;

    while (total < length) {
        size_t span = sector_size;
        size_t attempted_span = 0U;
        uint64_t sector_offset;
        size_t got;
        size_t confirmed_bytes = 0U;
        ssize_t direct_result;
        int saved_errno = 0;
        int sector_failed = 0;

        if (app_supervisor_generation_stale()) {
            break;
        }

        if (span > length - total) {
            span = length - total;
        }

        sector_offset = offset + (uint64_t)total;
        attempted_span = span;
        if (total == 0U &&
            reader->precise_record_first_sector_cap_bytes > 0U &&
            reader->precise_record_first_sector_cap_bytes < attempted_span) {
            attempted_span = reader->precise_record_first_sector_cap_bytes;
        }
        if (total == 0U &&
            reader->precise_record_probe_bytes > 0U &&
            reader->precise_record_probe_bytes < attempted_span) {
            size_t probe_bytes = reader->precise_record_probe_bytes;
            size_t probe_got = 0U;
            int probe_errno = 0;

            if (probe_bytes > attempted_span) {
                probe_bytes = attempted_span;
            }

            if (fseeko(reader->file, (off_t)sector_offset, SEEK_SET) != 0) {
                probe_errno = errno != 0 ? errno : EIO;
            } else {
                errno = 0;
                probe_got = fread(buffer + total, 1, probe_bytes, reader->file);
                if (probe_got > 0U) {
                    if (ferror(reader->file)) {
                        probe_errno = errno != 0 ? errno : EIO;
                    }
                    clearerr(reader->file);
                } else if (ferror(reader->file)) {
                    probe_errno = errno != 0 ? errno : EIO;
                    clearerr(reader->file);
                }
            }

            if (probe_got < probe_bytes) {
                got = probe_got;
                saved_errno = probe_errno != 0 ? probe_errno : EIO;
                sector_failed = 1;
            } else {
                direct_result = reader_read_direct_once(
                    reader,
                    buffer + total,
                    attempted_span,
                    sector_offset,
                    &saved_errno
                );
                if (direct_result < 0) {
                    got = 0U;
                    sector_failed = 1;
                } else {
                    got = (size_t)direct_result;
                    if (got < attempted_span) {
                        if (saved_errno == 0 &&
                            (reader->source_size == 0U ||
                             sector_offset + (uint64_t)got < reader->source_size)) {
                            saved_errno = EIO;
                        }
                        if (saved_errno != 0) {
                            sector_failed = 1;
                        }
                    }
                }
            }
        } else {
            direct_result = reader_read_direct_once(
                reader,
                buffer + total,
                attempted_span,
                sector_offset,
                &saved_errno
            );
            if (direct_result < 0) {
                got = 0U;
                sector_failed = 1;
            } else {
                got = (size_t)direct_result;
                if (got < attempted_span) {
                    if (saved_errno == 0 &&
                        (reader->source_size == 0U ||
                         sector_offset + (uint64_t)got < reader->source_size)) {
                        saved_errno = EIO;
                    }
                    if (saved_errno != 0) {
                        sector_failed = 1;
                    }
                }
            }
        }

        if (got == 0U && !sector_failed) {
            break;
        }

        if (total == 0U) {
            reader->last_precise_record_first_sector_bytes_read = got;
        }
        confirmed_bytes = got;
        if (confirmed_bytes > 0U) {
            app_gui_note_read_coverage(
                sector_offset,
                sector_offset + (uint64_t)confirmed_bytes
            );
        }

        if (total == 0U &&
            ((confirmed_bytes > 0U && confirmed_bytes < span) ||
             (attempted_span > 0U && attempted_span < span))) {
            reader->last_precise_record_first_sector_partial = 1;
        }

        if (got < span) {
            if (sector_failed &&
                reader_regular_source_path_became_unavailable(reader)) {
                set_reader_saved_errno_error(
                    "precise-record source path unavailable",
                    saved_errno != 0 ? saved_errno : EIO
                );
                reader_note_regular_source_path_unavailable(
                    reader,
                    total == 0U
                        ? "precise-record first sector"
                        : "precise-record tail sector",
                    sector_offset + (uint64_t)got,
                    span > got ? span - got : span,
                    saved_errno != 0 ? saved_errno : EIO
                );
                return 0U;
            }
            if (sector_failed &&
                reader_error_is_fatal_device_error_local(saved_errno)) {
                set_reader_saved_errno_error(
                    "precise-record read failed",
                    saved_errno
                );
                reader_note_source_unavailable(
                    reader,
                    total == 0U
                        ? "precise-record first sector"
                        : "precise-record tail sector",
                    sector_offset + (uint64_t)got,
                    span > got ? span - got : span,
                    saved_errno
                );
                return 0U;
            }
            memset(buffer + total + got, 0, span - got);
            if (sector_failed) {
                size_t bad_length = span - got;
                uint64_t bad_offset = sector_offset + (uint64_t)got;

                reader_note_bad_read_span(
                    reader,
                    bad_offset,
                    bad_length,
                    saved_errno != 0 ? saved_errno : EIO
                );
            }
            got = span;
        }

        if (sector_failed) {
            reader->last_precise_record_failed_sectors++;
            reader->precise_record_total_failed_sectors++;
            if (total == 0U) {
                size_t keep_threshold = READER_PRECISE_RECORD_MIN_FIRST_SECTOR_BYTES;

                reader->last_precise_record_first_sector_bytes_read = confirmed_bytes;
                if (keep_threshold > span) {
                    keep_threshold = span;
                }
                if (confirmed_bytes < keep_threshold) {
                    size_t skipped_tail_sectors = 0U;

                    reader->last_precise_record_first_sector_failed = 1;
                    if (length > span) {
                        memset(buffer + span, 0, length - span);
                        skipped_tail_sectors =
                            (length - span + sector_size - 1U) / sector_size;
                        reader->last_precise_record_skipped_sectors +=
                            skipped_tail_sectors;
                        reader->precise_record_total_skipped_sectors +=
                            (uint64_t)skipped_tail_sectors;
                    }
                    log_runtime_event_error(
                        "Precise-record read: first %zu-byte sector at byte %llu yielded only %zu byte%s (<%zu); dropping the rest of this %zu-byte record and jumping to the next record boundary",
                        span,
                        (unsigned long long)offset,
                        confirmed_bytes,
                        confirmed_bytes == 1U ? "" : "s",
                        keep_threshold,
                        length
                    );
                    return length;
                }
            } else {
                reader->last_precise_record_later_sector_failed = 1;
            }
        }

        if (total == 0U &&
            reader->precise_record_first_sector_only &&
            length > span) {
            size_t skipped_tail_sectors =
                (length - span + sector_size - 1U) / sector_size;

            memset(buffer + span, 0, length - span);
            reader->last_precise_record_skipped_sectors += skipped_tail_sectors;
            reader->precise_record_total_skipped_sectors +=
                (uint64_t)skipped_tail_sectors;
            return length;
        }

        total += got;
    }

    return total;
}

static void reader_report_working_progress(Reader *reader, uint64_t processed_bytes)
{
    if (reader != NULL && reader->report_progress) {
        log_set_working_progress(processed_bytes, reader->source_size);
    }
}

int reader_path_is_block_device(const char *path)
{
    struct stat st;

    if (!stat_path(path, &st)) {
        return 0;
    }

    return S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode);
}

int reader_resolve_mounted_source_device(const char *path, char *out, size_t out_size)
{
    struct stat st;

    if (out == NULL || out_size == 0U) {
        set_reader_error("resolve mounted source: missing output buffer");
        return 0;
    }

    out[0] = '\0';
    if (path == NULL || path[0] == '\0') {
        set_reader_error("resolve mounted source: missing path");
        return 0;
    }
    if (!stat_path(path, &st)) {
        set_reader_errno_error("resolve mounted source stat failed");
        return 0;
    }
    if (!S_ISDIR(st.st_mode)) {
        set_reader_error("resolve mounted source: path is not a directory");
        return 0;
    }

#ifdef __APPLE__
    return resolve_mounted_source_device_macos(path, out, out_size);
#elif defined(__linux__)
    {
        FILE *mounts;
        struct mntent *entry;
        char resolved_path[PATH_MAX];
        const char *candidate_path = path;
        const char *best_source = NULL;
        size_t best_target_len = 0U;

        if (realpath(path, resolved_path) != NULL) {
            candidate_path = resolved_path;
        }

        mounts = setmntent("/proc/mounts", "r");
        if (mounts == NULL) {
            set_reader_errno_error("resolve mounted source setmntent failed");
            return 0;
        }

        while ((entry = getmntent(mounts)) != NULL) {
            size_t target_len;

            if (entry->mnt_fsname == NULL ||
                entry->mnt_dir == NULL ||
                strncmp(entry->mnt_fsname, "/dev/", 5) != 0) {
                continue;
            }

            target_len = strlen(entry->mnt_dir);
            if (strncmp(candidate_path, entry->mnt_dir, target_len) != 0) {
                continue;
            }
            if (candidate_path[target_len] != '\0' &&
                !(entry->mnt_dir[target_len - 1U] == '/' ||
                  candidate_path[target_len] == '/')) {
                continue;
            }
            if (target_len > best_target_len) {
                best_target_len = target_len;
                best_source = entry->mnt_fsname;
            }
        }

        endmntent(mounts);

        if (best_source == NULL) {
            set_reader_error("resolve mounted source: no backing block device was found");
            return 0;
        }
        if (snprintf(out, out_size, "%s", best_source) >= (int)out_size) {
            set_reader_error("resolve mounted source: device path too long");
            return 0;
        }
        return 1;
    }
#else
    (void)st;
    set_reader_error("resolve mounted source is unsupported on this platform");
    return 0;
#endif
}

int reader_path_is_mounted(const char *path)
{
#ifdef __linux__
    MountEntry *entries = NULL;
    size_t mount_count;

    if (path == NULL) {
        return 0;
    }

    mount_count = collect_related_mounts(path, &entries);
    free(entries);
    return mount_count > 0;
#else
    (void)path;
    return 0;
#endif
}

int reader_unmount_path(const char *path)
{
#ifdef __linux__
    MountEntry *entries = NULL;
    size_t mount_count;
    size_t i;

    if (path == NULL) {
        set_reader_error("unmount: missing path");
        return 0;
    }

    mount_count = collect_related_mounts(path, &entries);
    if (mount_count == 0) {
        return 1;
    }

    for (i = 0; i < mount_count; i++) {
        if (umount(entries[i].target) != 0) {
            set_reader_errno_error("unmount failed");
            free(entries);
            return 0;
        }

        log_info(
            "Unmounted %s from %s",
            entries[i].target,
            entries[i].source
        );
    }

    free(entries);
    return 1;
#else
    (void)path;
    set_reader_error("unmount is only supported on Linux");
    return 0;
#endif
}

int reader_block_device_is_read_only(const char *path)
{
#ifdef __linux__
    int fd;
    int read_only = 0;
    struct stat st;

    if (path == NULL || stat(path, &st) != 0 || !S_ISBLK(st.st_mode)) {
        return 0;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        set_reader_errno_error("open block device for read-only check failed");
        return 0;
    }
    if (ioctl(fd, BLKROGET, &read_only) != 0) {
        set_reader_errno_error("BLKROGET failed");
        close(fd);
        return 0;
    }
    close(fd);
    return read_only != 0;
#else
    (void)path;
    return 0;
#endif
}

int reader_set_block_device_read_only(const char *path)
{
#ifdef __linux__
    int fd;
    int read_only = 1;
    struct stat st;

    if (path == NULL) {
        set_reader_error("set block device read-only: missing path");
        return 0;
    }
    if (stat(path, &st) != 0) {
        set_reader_errno_error("set block device read-only stat failed");
        return 0;
    }
    if (!S_ISBLK(st.st_mode)) {
        set_reader_error("set block device read-only: path is not a block device");
        return 0;
    }

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        set_reader_errno_error("open block device for read-only protection failed");
        return 0;
    }
    if (ioctl(fd, BLKROSET, &read_only) != 0) {
        set_reader_errno_error("BLKROSET failed");
        close(fd);
        return 0;
    }
    close(fd);

    if (!reader_block_device_is_read_only(path)) {
        set_reader_error("kernel did not retain block-device read-only protection");
        return 0;
    }
    return 1;
#else
    (void)path;
    set_reader_error("block-device read-only protection is only supported on Linux");
    return 0;
#endif
}

/*
 * `reader_open()` expects a fully reset structure because many later paths
 * rely on counters, error ranges, and report paths starting from zero.
 */
static void reader_reset_open_state(
    Reader *reader,
    const char *path,
    size_t chunk_size,
    size_t overlap_size
)
{
    if (reader == NULL) {
        return;
    }

    memset(reader, 0, sizeof(*reader));
    reader->fd = -1;
    reader->path = path;
    reader->chunk_size = chunk_size;
    reader->overlap_size = overlap_size;
    reader->report_progress = 1;
    reader->is_first_chunk = 1;
}

static int reader_validate_open_source(const char *path, struct stat *st)
{
    if (!stat_path(path, st)) {
        set_reader_errno_error("stat failed");
        return 0;
    }

    if (!S_ISREG(st->st_mode) && !S_ISBLK(st->st_mode) && !S_ISCHR(st->st_mode)) {
        set_reader_error("input must be a regular file, block device, or raw character device");
        return 0;
    }

    return 1;
}

/*
 * Open the source first, then attach the device-specific hints derived
 * from the already-collected `stat()` result.
 */
static int reader_open_stream(
    Reader *reader,
    const char *path,
    const struct stat *st
)
{
    if (reader == NULL || path == NULL || st == NULL) {
        return 0;
    }

    reader->source_size = determine_source_size(path, st);
    reader->source_is_regular_file = S_ISREG(st->st_mode) ? 1 : 0;
    reader->source_open_dev = st->st_dev;
    reader->source_open_ino = st->st_ino;
    reader->file = fopen(path, "rb");
    if (reader->file == NULL) {
        set_reader_errno_error("fopen failed");
        return 0;
    }

    if (S_ISBLK(st->st_mode) || S_ISCHR(st->st_mode)) {
        reader->use_stdio_device_reads = 1;
    }
    configure_sequential_io_hints(reader, st);
    if (reader->use_stdio_device_reads) {
        log_verbose(
            "Reader: using stream-based resilient reads for raw device %s",
            path
        );
    }

    return 1;
}

static void reader_prepare_stream_buffer(Reader *reader)
{
    if (reader == NULL) {
        return;
    }

    reader->io_buffer_size = reader->chunk_size;
    if (reader->io_buffer_size < (4U * 1024U * 1024U)) {
        reader->io_buffer_size = 4U * 1024U * 1024U;
    }

    reader->io_buffer = (uint8_t *)malloc(reader->io_buffer_size);
    if (reader->io_buffer != NULL) {
        (void)setvbuf(
            reader->file,
            (char *)reader->io_buffer,
            _IOFBF,
            reader->io_buffer_size
        );
    }
}

static void reader_cleanup_failed_open(Reader *reader)
{
    if (reader == NULL) {
        return;
    }

    free(reader->buffer);
    reader->buffer = NULL;
    free(reader->io_buffer);
    reader->io_buffer = NULL;
    reader->io_buffer_size = 0U;
    reader->direct_read_alignment = 0U;
    reader->use_stdio_device_reads = 0;

    if (reader->file != NULL) {
        fclose(reader->file);
        reader->file = NULL;
    }
    reader->fd = -1;
}

/*
 * Central open path used by both raw scans and metadata-oriented passes.
 * Keep the order simple: reset state, validate the source, open/configure
 * the stream, then allocate the working buffers.
 */
int reader_open(Reader *reader, const char *path, size_t chunk_size, size_t overlap_size)
{
    struct stat st;

    if (reader == NULL || path == NULL || chunk_size == 0) {
        set_reader_error("invalid reader_open arguments");
        return 0;
    }

    reader_reset_open_state(reader, path, chunk_size, overlap_size);
    if (!reader_validate_open_source(path, &st)) {
        return 0;
    }

    if (!reader_open_stream(reader, path, &st)) {
        return 0;
    }

    reader_prepare_stream_buffer(reader);
    reader->buffer = (uint8_t *)malloc(reader->chunk_size + reader->overlap_size);
    if (reader->buffer == NULL) {
        reader_cleanup_failed_open(reader);
        set_reader_error("failed to allocate reader buffer");
        return 0;
    }
    reader_configure_regular_file_sequential_advice(reader);

    set_reader_error("no error");
    reader_report_working_progress(reader, 0);
    return 1;
}

int reader_seek_absolute(Reader *reader, uint64_t absolute_offset)
{
    uint64_t physical_seek_offset = absolute_offset;

    if (reader == NULL || reader->file == NULL) {
        set_reader_error("seek: reader not open");
        return 0;
    }

    if (reader->use_stdio_device_reads &&
        reader->direct_read_alignment > 0U) {
        physical_seek_offset -=
            physical_seek_offset % (uint64_t)reader->direct_read_alignment;
    }

    if (fseeko(reader->file, (off_t)physical_seek_offset, SEEK_SET) != 0) {
        set_reader_errno_error("seek failed");
        if (reader_error_is_fatal_device_error_local(g_reader_last_errno)) {
            reader_note_source_unavailable(
                reader,
                "seek",
                absolute_offset,
                reader->direct_read_alignment > 0U
                    ? reader->direct_read_alignment
                    : READER_BAD_READ_MIN_SPAN,
                g_reader_last_errno
            );
        }
        return 0;
    }

    reader->bytes_in_buffer = 0;
    reader->overlap_bytes = 0;
    reader->total_bytes_read = (size_t)absolute_offset;
    reader->is_first_chunk = 1;
    reader->progress_bytes_read = absolute_offset;
    reader->last_precise_record_first_sector_failed = 0;
    reader->last_precise_record_later_sector_failed = 0;
    reader->last_precise_record_first_sector_partial = 0;
    reader->last_precise_record_failed_sectors = 0U;
    reader->last_precise_record_skipped_sectors = 0U;
    reader->last_precise_record_first_sector_bytes_read = 0U;
    reader_report_working_progress(reader, absolute_offset);
    return 1;
}

int reader_set_progress_reporting(Reader *reader, int enabled)
{
    int previous;

    if (reader == NULL) {
        return 0;
    }

    previous = reader->report_progress;
    reader->report_progress = enabled ? 1 : 0;
    return previous;
}

void reader_set_sequential_chunk_observer(
    Reader *reader,
    ReaderSequentialChunkObserver observer,
    void *context)
{
    if (reader == NULL) {
        return;
    }
    reader->sequential_chunk_observer = observer;
    reader->sequential_chunk_observer_context = context;
}

int reader_set_error_report_path(Reader *reader, const char *path)
{
    if (reader == NULL) {
        return 0;
    }

    reader_flush_pending_bad_read_span(reader);
    reader_flush_pending_bad_read_cluster(reader);

    if (path == NULL || path[0] == '\0') {
        reader->error_report_path[0] = '\0';
        reader->error_cluster_report_path[0] = '\0';
        reader->error_report_detail_suppressed = 0;
        return 1;
    }

    if (snprintf(
            reader->error_report_path,
            sizeof(reader->error_report_path),
            "%s",
            path) >= (int)sizeof(reader->error_report_path)) {
        reader->error_report_path[0] = '\0';
        reader->error_cluster_report_path[0] = '\0';
        return 0;
    }

    if (!build_cluster_report_path_from_detail(
            reader->error_report_path,
            reader->error_cluster_report_path,
            sizeof(reader->error_cluster_report_path))) {
        reader->error_report_path[0] = '\0';
        reader->error_cluster_report_path[0] = '\0';
        return 0;
    }
    reader->error_report_detail_suppressed = 0;

    return 1;
}

int reader_set_error_report_run_id(Reader *reader, const char *run_id)
{
    if (reader == NULL) {
        return 0;
    }

    if (run_id == NULL || run_id[0] == '\0') {
        reader->error_report_run_id[0] = '\0';
        return 1;
    }

    if (snprintf(
            reader->error_report_run_id,
            sizeof(reader->error_report_run_id),
            "%s",
            run_id) >= (int)sizeof(reader->error_report_run_id)) {
        reader->error_report_run_id[0] = '\0';
        return 0;
    }

    sanitize_read_error_field(reader->error_report_run_id);
    return 1;
}

int reader_set_bad_read_state_path(Reader *reader, const char *path)
{
    if (reader == NULL) {
        return 0;
    }

    if (path == NULL || path[0] == '\0') {
        reader->bad_read_state_path[0] = '\0';
        return 1;
    }

    if (snprintf(
            reader->bad_read_state_path,
            sizeof(reader->bad_read_state_path),
            "%s",
            path) >= (int)sizeof(reader->bad_read_state_path)) {
        reader->bad_read_state_path[0] = '\0';
        return 0;
    }

    return 1;
}

int reader_set_trouble_map_path(Reader *reader, const char *path)
{
    if (reader == NULL) {
        return 0;
    }

    if (path == NULL || path[0] == '\0') {
        reader->trouble_map_path[0] = '\0';
        return 1;
    }

    if (snprintf(
            reader->trouble_map_path,
            sizeof(reader->trouble_map_path),
            "%s",
            path) >= (int)sizeof(reader->trouble_map_path)) {
        reader->trouble_map_path[0] = '\0';
        return 0;
    }

    return 1;
}

int reader_set_precise_record_mode(Reader *reader, int enabled)
{
    if (reader == NULL) {
        return 0;
    }

    reader->precise_record_mode = enabled ? 1 : 0;
    if (!reader->precise_record_mode) {
        reader->precise_record_first_sector_only = 0;
        reader->precise_record_probe_bytes = 0U;
        reader->precise_record_first_sector_cap_bytes = 0U;
    }
    return 1;
}

int reader_set_precise_record_first_sector_only(Reader *reader, int enabled)
{
    if (reader == NULL) {
        return 0;
    }

    reader->precise_record_first_sector_only =
        (reader->precise_record_mode && enabled) ? 1 : 0;
    return 1;
}

int reader_set_precise_record_probe_bytes(Reader *reader, size_t bytes)
{
    if (reader == NULL) {
        return 0;
    }

    if (!reader->precise_record_mode || bytes == 0U) {
        reader->precise_record_probe_bytes = 0U;
    } else {
        reader->precise_record_probe_bytes = bytes;
    }
    return 1;
}

int reader_set_precise_record_first_sector_cap_bytes(Reader *reader, size_t bytes)
{
    if (reader == NULL) {
        return 0;
    }

    if (!reader->precise_record_mode || bytes == 0U) {
        reader->precise_record_first_sector_cap_bytes = 0U;
    } else {
        reader->precise_record_first_sector_cap_bytes = bytes;
    }
    return 1;
}

uint64_t reader_get_read_error_count(const Reader *reader)
{
    return reader != NULL ? reader->read_error_count : 0U;
}

uint64_t reader_get_last_read_error_offset(const Reader *reader)
{
    return reader != NULL ? reader->last_read_error_offset : 0U;
}

uint64_t reader_get_last_read_error_length(const Reader *reader)
{
    return reader != NULL ? reader->last_read_error_length : 0U;
}

uint64_t reader_get_precise_record_total_failed_sectors(const Reader *reader)
{
    return reader != NULL ? reader->precise_record_total_failed_sectors : 0U;
}

uint64_t reader_get_precise_record_total_skipped_sectors(const Reader *reader)
{
    return reader != NULL ? reader->precise_record_total_skipped_sectors : 0U;
}

uint64_t reader_get_precise_record_total_partial_first_sectors(const Reader *reader)
{
    return reader != NULL ? reader->precise_record_total_partial_first_sectors : 0U;
}

size_t reader_read_next(Reader *reader)
{
    size_t bytes_to_keep = 0;
    uint64_t read_offset;
    size_t bytes_wanted;
    size_t bytes_read;

    if (reader == NULL || reader->file == NULL || reader->buffer == NULL) {
        return 0;
    }
    if (app_source_reconnect_requested()) {
        reader->bytes_in_buffer = 0U;
        reader->overlap_bytes = 0U;
        return 0U;
    }

    if (!reader->is_first_chunk) {
        bytes_to_keep = reader->bytes_in_buffer;

        if (bytes_to_keep > reader->overlap_size) {
            bytes_to_keep = reader->overlap_size;
        }

        if (bytes_to_keep > 0) {
            memmove(
                reader->buffer,
                reader->buffer + (reader->bytes_in_buffer - bytes_to_keep),
                bytes_to_keep
            );
        }
    }

    read_offset = reader->progress_bytes_read;
    if (reader->source_size > 0U) {
        uint64_t remaining;

        if (read_offset >= reader->source_size) {
            reader->overlap_bytes = 0;
            reader->bytes_in_buffer = 0;
            reader->is_first_chunk = 0;
            reader_report_working_progress(reader, reader->progress_bytes_read);
            return 0;
        }

        remaining = reader->source_size - read_offset;
        bytes_wanted =
            remaining < (uint64_t)reader->chunk_size
                ? (size_t)remaining
                : reader->chunk_size;
    } else {
        bytes_wanted = reader->chunk_size;
    }

    if (reader->report_progress) {
        log_set_working_activity("reading disk");
    }
    reader->last_precise_record_first_sector_failed = 0;
    reader->last_precise_record_later_sector_failed = 0;
    reader->last_precise_record_first_sector_partial = 0;
    reader->last_precise_record_failed_sectors = 0U;
    reader->last_precise_record_skipped_sectors = 0U;
    reader->last_precise_record_first_sector_bytes_read = 0U;
    if (reader->precise_record_mode && bytes_to_keep == 0U && reader->overlap_size == 0U) {
        bytes_read = reader_read_precise_record_chunk(
            reader,
            reader->buffer + bytes_to_keep,
            read_offset,
            bytes_wanted
        );
    } else {
        bytes_read = reader_read_resilient(
            reader,
            reader->buffer + bytes_to_keep,
            read_offset,
            bytes_wanted
        );
    }

    if (app_supervisor_generation_stale()) {
        reader->overlap_bytes = 0;
        reader->bytes_in_buffer = 0;
        reader->is_first_chunk = 0;
        return 0;
    }

    if (bytes_read == 0) {
        reader->overlap_bytes = 0;
        reader->bytes_in_buffer = 0;
        reader->is_first_chunk = 0;
        reader_report_working_progress(reader, reader->progress_bytes_read);
        return 0;
    }

    if (reader->precise_record_mode &&
        reader->last_precise_record_first_sector_partial) {
        reader->precise_record_total_partial_first_sectors++;
    }

    reader->overlap_bytes = bytes_to_keep;
    reader->bytes_in_buffer = bytes_to_keep + bytes_read;
    reader->total_bytes_read = (size_t)(read_offset + (uint64_t)bytes_read);
    reader->progress_bytes_read = read_offset + (uint64_t)bytes_read;
    reader->is_first_chunk = 0;
    reader_apply_regular_file_sequential_advice(reader, read_offset, bytes_read);
    reader_report_working_progress(reader, reader->progress_bytes_read);
    if (reader->sequential_chunk_observer != NULL) {
        reader->sequential_chunk_observer(
            read_offset,
            reader->buffer + bytes_to_keep,
            bytes_read,
            reader->sequential_chunk_observer_context
        );
    }

    return bytes_read;
}

void reader_close(Reader *reader)
{
    if (reader == NULL) {
        return;
    }

    reader_flush_pending_bad_read_span(reader);
    reader_flush_pending_bad_read_cluster(reader);

    if (reader->read_error_count > 0U) {
        log_info(
            "Read error summary: %llu bad span%s across %llu range%s, %.1f MiB zero-filled, last at byte %llu length %llu",
            (unsigned long long)reader->read_error_count,
            reader->read_error_count == 1U ? "" : "s",
            (unsigned long long)reader->read_error_range_count,
            reader->read_error_range_count == 1U ? "" : "s",
            (double)reader->read_error_bytes / (1024.0 * 1024.0),
            (unsigned long long)reader->last_read_error_offset,
            (unsigned long long)reader->last_read_error_length
        );
    }
    if (reader->precise_record_total_failed_sectors > 0U ||
        reader->precise_record_total_skipped_sectors > 0U ||
        reader->precise_record_total_partial_first_sectors > 0U) {
        log_info(
            "Precise-record summary: failed_sectors=%llu skipped_sectors=%llu partial_first_sectors=%llu",
            (unsigned long long)reader->precise_record_total_failed_sectors,
            (unsigned long long)reader->precise_record_total_skipped_sectors,
            (unsigned long long)reader->precise_record_total_partial_first_sectors
        );
    }

    if (reader->file != NULL) {
        fclose(reader->file);
        reader->file = NULL;
    }

    free(reader->buffer);
    reader->buffer = NULL;
    free(reader->io_buffer);
    reader->io_buffer = NULL;

    reader->fd = -1;
    reader->path = NULL;
    reader->io_buffer_size = 0;
    reader->direct_read_alignment = 0U;
    reader->use_stdio_device_reads = 0;
    reader->source_size = 0;
    reader->sequential_advice_enabled = 0;
    reader->sequential_prefetch_bytes = 0U;
    reader->sequential_release_bytes = 0U;
    reader->sequential_last_read_offset = 0U;
    reader->sequential_last_read_end_offset = 0U;
    reader->sequential_prefetch_end_offset = 0U;
    reader->sequential_release_end_offset = 0U;
    reader->chunk_size = 0;
    reader->overlap_size = 0;
    reader->bytes_in_buffer = 0;
    reader->overlap_bytes = 0;
    reader->total_bytes_read = 0;
    reader->progress_bytes_read = 0;
    reader->read_error_count = 0;
    reader->read_error_range_count = 0;
    reader->read_error_bytes = 0;
    reader->last_read_error_offset = 0;
    reader->last_read_error_length = 0;
    reader->pending_read_error_offset = 0;
    reader->pending_read_error_end_offset = 0;
    reader->pending_read_error_bytes = 0U;
    reader->pending_read_error_spans = 0;
    reader->pending_read_error_errno = 0;
    reader->bad_read_state_path[0] = '\0';
    reader->error_report_path[0] = '\0';
    reader->error_cluster_report_path[0] = '\0';
    reader->error_report_run_id[0] = '\0';
    reader->error_report_detail_suppressed = 0;
    reader->pending_cluster_error_offset = 0U;
    reader->pending_cluster_error_end_offset = 0U;
    reader->pending_cluster_error_bytes = 0U;
    reader->pending_cluster_error_spans = 0U;
    reader->pending_cluster_error_errno = 0;
    reader->report_progress = 1;
    reader->is_first_chunk = 1;
    reader->precise_record_mode = 0;
    reader->precise_record_first_sector_only = 0;
    reader->precise_record_probe_bytes = 0U;
    reader->precise_record_first_sector_cap_bytes = 0U;
    reader->last_precise_record_first_sector_failed = 0;
    reader->last_precise_record_later_sector_failed = 0;
    reader->last_precise_record_first_sector_partial = 0;
    reader->last_precise_record_failed_sectors = 0U;
    reader->last_precise_record_skipped_sectors = 0U;
    reader->last_precise_record_first_sector_bytes_read = 0U;
    reader->precise_record_total_failed_sectors = 0U;
    reader->precise_record_total_skipped_sectors = 0U;
    reader->precise_record_total_partial_first_sectors = 0U;
    reader->sequential_chunk_observer = NULL;
    reader->sequential_chunk_observer_context = NULL;
}

uint64_t reader_get_source_size(const Reader *reader)
{
    if (reader == NULL) {
        return 0;
    }

    return reader->source_size;
}
