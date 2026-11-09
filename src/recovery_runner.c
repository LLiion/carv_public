#define _POSIX_C_SOURCE 200809L

#include "recovery_runner.h"

#include "filtered_image_log.h"
#include "fs_backend.h"
#include "image_filter.h"
#include "mftprobe_format_api.h"
#include "mftprobe_format_jpeg_recovery.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#define RECOVERY_RUNNER_READ_SIZE (4U * 1024U * 1024U)
#define RECOVERY_RUNNER_READ_ERROR_MIN_SIZE 4096U
#define RECOVERY_RUNNER_DIRECT_ALIGNMENT 512ULL
#define RECOVERY_RUNNER_PATH_MAX 2048U
#define RECOVERY_RUNNER_BEST_EFFORT_MAX_ATTEMPTS 3U
#define RECOVERY_RUNNER_OUTPUT_MOUNT_GRACE_SECONDS 5U
#define RECOVERY_RUNNER_PNG_MIN_FILE_SIZE 45U
#define RECOVERY_RUNNER_PNG_SIGNATURE_SIZE 8U
#define RECOVERY_RUNNER_PNG_CHUNK_HEADER_SIZE 8U
#define RECOVERY_RUNNER_PNG_CHUNK_CRC_SIZE 4U
#define RECOVERY_RUNNER_PNG_MAX_DIMENSION 200000U
#define RECOVERY_RUNNER_PNG_REPLAY_BACKTRACK (64ULL * 1024ULL)
#define RECOVERY_RUNNER_PNG_REPLAY_FORWARD (16ULL * 1024ULL * 1024ULL)
#define RECOVERY_RUNNER_PNG_REPLAY_OVERLAP 256ULL
#define RECOVERY_RUNNER_MOV_MIN_ATOM_SIZE 8ULL
#define RECOVERY_RUNNER_MOV_REPLAY_BACKTRACK (1ULL * 1024ULL * 1024ULL)
#define RECOVERY_RUNNER_MOV_REPLAY_FORWARD (64ULL * 1024ULL * 1024ULL)
#define RECOVERY_RUNNER_MOV_REPLAY_OVERLAP 4096ULL
#define RECOVERY_RUNNER_MOV_MAX_VALIDATE_WINDOW (8ULL * 1024ULL * 1024ULL)

static void recovery_runner_preserve_direct_error_local(
    RecoveryTarget *target,
    const char *direct_error
);

static void recovery_runner_copy_text_local(
    char *dest,
    size_t dest_size,
    const char *src
);

static void recovery_runner_append_text_local(
    char *dest,
    size_t dest_size,
    const char *src
);

static void recovery_runner_join_error_pair_local(
    char *dest,
    size_t dest_size,
    const char *left_label,
    const char *left_value,
    const char *right_label,
    const char *right_value
);

static int recovery_runner_stop_requested(int (*stop_requested)(void))
{
    return stop_requested != NULL && stop_requested();
}

static void recovery_runner_copy_text_local(
    char *dest,
    size_t dest_size,
    const char *src
)
{
    size_t copy_length = 0U;

    if (dest == NULL || dest_size == 0U) {
        return;
    }

    if (src != NULL) {
        copy_length = strlen(src);
        if (copy_length >= dest_size) {
            copy_length = dest_size - 1U;
        }
        memcpy(dest, src, copy_length);
    }
    dest[copy_length] = '\0';
}

static void recovery_runner_append_text_local(
    char *dest,
    size_t dest_size,
    const char *src
)
{
    size_t used;
    size_t copy_length;

    if (dest == NULL || dest_size == 0U || src == NULL || src[0] == '\0') {
        return;
    }

    used = strlen(dest);
    if (used >= dest_size - 1U) {
        return;
    }

    copy_length = strlen(src);
    if (copy_length > dest_size - used - 1U) {
        copy_length = dest_size - used - 1U;
    }
    memcpy(dest + used, src, copy_length);
    dest[used + copy_length] = '\0';
}

static void recovery_runner_join_error_pair_local(
    char *dest,
    size_t dest_size,
    const char *left_label,
    const char *left_value,
    const char *right_label,
    const char *right_value
)
{
    recovery_runner_copy_text_local(dest, dest_size, "");
    recovery_runner_append_text_local(dest, dest_size, left_label);
    recovery_runner_append_text_local(dest, dest_size, left_value);
    recovery_runner_append_text_local(dest, dest_size, "; ");
    recovery_runner_append_text_local(dest, dest_size, right_label);
    recovery_runner_append_text_local(dest, dest_size, right_value);
}

static int read_error_is_fatal_device_error(int error_code)
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

static int ensure_dir_local(const char *path)
{
    if (!fs_backend_output_path_write_guard_allows(path)) {
        return 0;
    }
    return mkdir(path, 0775) == 0 || errno == EEXIST;
}

static int text_contains_local(const char *text, const char *needle)
{
    return text != NULL &&
           needle != NULL &&
           text[0] != '\0' &&
           needle[0] != '\0' &&
           strstr(text, needle) != NULL;
}

static void recovery_runner_log_image_filter_local(
    const RecoveryTarget *target,
    const char *reason,
    uint64_t expected_size,
    uint64_t detected_size,
    uint64_t width,
    uint64_t height
)
{
    const char *path = NULL;

    if (target == NULL) {
        return;
    }
    if (target->source_path[0] != '\0') {
        path = target->source_path;
    } else if (target->output_path[0] != '\0') {
        path = target->output_path;
    }

    filtered_image_log_append_current(
        "mft-direct",
        target->extension,
        reason,
        target->abs_offset,
        expected_size,
        detected_size,
        width,
        height,
        path
    );
}

static int recovery_runner_skip_small_unnamed_image_file_local(
    const RecoveryTarget *target,
    int named_mft_target,
    uint64_t file_size
)
{
    if (named_mft_target || !image_filter_is_below_min_file_size(file_size)) {
        return 0;
    }
    recovery_runner_log_image_filter_local(
        target,
        "small_file_filtered",
        file_size,
        0U,
        0U,
        0U
    );
    return 1;
}

static int output_mount_root_from_path_local(
    const char *path,
    char *out_root,
    size_t out_root_size
)
{
    if (out_root != NULL && out_root_size > 0U) {
        out_root[0] = '\0';
    }
    if (path == NULL || path[0] == '\0' || out_root == NULL || out_root_size == 0U) {
        return 0;
    }

    if (strncmp(path, "/media/", 7U) == 0) {
        const char *rest = path + 7U;
        const char *user_slash = strchr(rest, '/');
        const char *leaf_start;
        const char *leaf_slash;
        size_t root_len;

        if (user_slash == NULL || user_slash == rest || user_slash[1] == '\0') {
            return 0;
        }
        leaf_start = user_slash + 1;
        leaf_slash = strchr(leaf_start, '/');
        root_len = leaf_slash != NULL ? (size_t)(leaf_slash - path) : strlen(path);
        if (root_len == 0U || root_len >= out_root_size) {
            return 0;
        }
        memcpy(out_root, path, root_len);
        out_root[root_len] = '\0';
        return 1;
    }

    if (strncmp(path, "/Volumes/", 9U) == 0) {
        const char *leaf_start = path + 9U;
        const char *leaf_slash;
        size_t root_len;

        if (*leaf_start == '\0') {
            return 0;
        }
        leaf_slash = strchr(leaf_start, '/');
        root_len = leaf_slash != NULL ? (size_t)(leaf_slash - path) : strlen(path);
        if (root_len == 0U || root_len >= out_root_size) {
            return 0;
        }
        memcpy(out_root, path, root_len);
        out_root[root_len] = '\0';
        return 1;
    }

    return 0;
}

static int parent_path_local(
    const char *path,
    char *out_parent,
    size_t out_parent_size
)
{
    const char *last_slash;
    size_t parent_len;

    if (out_parent != NULL && out_parent_size > 0U) {
        out_parent[0] = '\0';
    }
    if (path == NULL || path[0] == '\0' || out_parent == NULL || out_parent_size == 0U) {
        return 0;
    }

    last_slash = strrchr(path, '/');
    if (last_slash == NULL) {
        return 0;
    }
    if (last_slash == path) {
        return snprintf(out_parent, out_parent_size, "/") < (int)out_parent_size;
    }
    parent_len = (size_t)(last_slash - path);
    if (parent_len == 0U || parent_len >= out_parent_size) {
        return 0;
    }
    memcpy(out_parent, path, parent_len);
    out_parent[parent_len] = '\0';
    return 1;
}

static int output_mount_root_is_live_local(const char *mount_root)
{
    char parent[RECOVERY_RUNNER_PATH_MAX];
    struct stat mount_st;
    struct stat parent_st;

    if (mount_root == NULL ||
        mount_root[0] == '\0' ||
        stat(mount_root, &mount_st) != 0 ||
        !S_ISDIR(mount_st.st_mode) ||
        !parent_path_local(mount_root, parent, sizeof(parent)) ||
        stat(parent, &parent_st) != 0) {
        return 0;
    }

    return mount_st.st_dev != parent_st.st_dev;
}

static int output_path_write_mount_guard_allows_local(const char *path)
{
    char mount_root[RECOVERY_RUNNER_PATH_MAX];
    unsigned int waited_seconds;

    if (!output_mount_root_from_path_local(path, mount_root, sizeof(mount_root))) {
        return 1;
    }
    if (output_mount_root_is_live_local(mount_root)) {
        return 1;
    }
    for (waited_seconds = 0U;
         waited_seconds < RECOVERY_RUNNER_OUTPUT_MOUNT_GRACE_SECONDS;
         waited_seconds++) {
        sleep(1);
        if (output_mount_root_is_live_local(mount_root)) {
            return 1;
        }
    }
    return 0;
}

static int streq_ci_local(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        unsigned char ca = (unsigned char)*a;
        unsigned char cb = (unsigned char)*b;

        if (ca >= 'A' && ca <= 'Z') {
            ca = (unsigned char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (unsigned char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static uint16_t read_u16_le_local(const unsigned char *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_u32_le_local(const unsigned char *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint16_t read_u16_be_local(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t read_u32_be_local(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static uint64_t read_u64_be_local(const unsigned char *p)
{
    return ((uint64_t)p[0] << 56) |
           ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) |
           ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) |
           ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) |
           (uint64_t)p[7];
}

static int jpeg_probe_dimensions_local(
    const unsigned char *buffer,
    size_t len,
    uint64_t *width_out,
    uint64_t *height_out
)
{
    size_t cursor = 0;

    if (width_out != NULL) {
        *width_out = 0;
    }
    if (height_out != NULL) {
        *height_out = 0;
    }
    if (buffer == NULL || len < 4U || buffer[0] != 0xFFU || buffer[1] != 0xD8U) {
        return 0;
    }

    cursor = 2U;
    while (cursor + 9U < len) {
        uint8_t marker;
        uint16_t segment_length;

        if (buffer[cursor] != 0xFFU) {
            cursor++;
            continue;
        }
        while (cursor < len && buffer[cursor] == 0xFFU) {
            cursor++;
        }
        if (cursor >= len) {
            break;
        }
        marker = buffer[cursor++];
        if (marker == 0xD8U || marker == 0xD9U) {
            continue;
        }
        if (marker == 0x01U || (marker >= 0xD0U && marker <= 0xD7U)) {
            continue;
        }
        if (cursor + 2U > len) {
            break;
        }
        segment_length = read_u16_be_local(buffer + cursor);
        if (segment_length < 2U || cursor + segment_length > len) {
            break;
        }
        if ((marker >= 0xC0U && marker <= 0xC3U) ||
            (marker >= 0xC5U && marker <= 0xC7U) ||
            (marker >= 0xC9U && marker <= 0xCBU) ||
            (marker >= 0xCDU && marker <= 0xCFU)) {
            if (segment_length >= 7U) {
                if (height_out != NULL) {
                    *height_out = read_u16_be_local(buffer + cursor + 3U);
                }
                if (width_out != NULL) {
                    *width_out = read_u16_be_local(buffer + cursor + 5U);
                }
                return 1;
            }
            break;
        }
        cursor += segment_length;
    }

    return 0;
}

static int probe_image_dimensions_local(
    const RecoveryTarget *target,
    const unsigned char *buffer,
    size_t len,
    uint64_t *width_out,
    uint64_t *height_out
)
{
    if (width_out != NULL) {
        *width_out = 0;
    }
    if (height_out != NULL) {
        *height_out = 0;
    }
    if (target == NULL || buffer == NULL) {
        return 0;
    }

    if (streq_ci_local(target->extension, "png")) {
        if (len >= 24U &&
            memcmp(buffer, "\x89PNG\r\n\x1a\n", 8) == 0 &&
            memcmp(buffer + 12U, "IHDR", 4) == 0) {
            if (width_out != NULL) {
                *width_out = read_u32_be_local(buffer + 16U);
            }
            if (height_out != NULL) {
                *height_out = read_u32_be_local(buffer + 20U);
            }
            return 1;
        }
        return 0;
    }
    if (streq_ci_local(target->extension, "gif")) {
        if (len >= 10U &&
            (memcmp(buffer, "GIF87a", 6) == 0 || memcmp(buffer, "GIF89a", 6) == 0)) {
            if (width_out != NULL) {
                *width_out = read_u16_le_local(buffer + 6U);
            }
            if (height_out != NULL) {
                *height_out = read_u16_le_local(buffer + 8U);
            }
            return 1;
        }
        return 0;
    }
    if (streq_ci_local(target->extension, "bmp")) {
        if (len >= 26U && buffer[0] == 'B' && buffer[1] == 'M') {
            uint32_t width = read_u32_le_local(buffer + 18U);
            uint32_t height = read_u32_le_local(buffer + 22U);

            if (width_out != NULL) {
                *width_out = width;
            }
            if (height_out != NULL) {
                *height_out = height;
            }
            return width != 0U && height != 0U;
        }
        return 0;
    }
    if (streq_ci_local(target->extension, "psd")) {
        if (len >= 22U && memcmp(buffer, "8BPS", 4) == 0) {
            if (height_out != NULL) {
                *height_out = read_u32_be_local(buffer + 14U);
            }
            if (width_out != NULL) {
                *width_out = read_u32_be_local(buffer + 18U);
            }
            return 1;
        }
        return 0;
    }
    if (streq_ci_local(target->extension, "jpg") ||
        streq_ci_local(target->extension, "jpeg")) {
        return jpeg_probe_dimensions_local(buffer, len, width_out, height_out);
    }

    return 0;
}

size_t recovery_runner_default_read_size(void)
{
    return RECOVERY_RUNNER_READ_SIZE;
}

int recovery_runner_ensure_parent_dirs(const char *path)
{
    char temp[RECOVERY_RUNNER_PATH_MAX];
    char *cursor;

    if (path == NULL || strlen(path) >= sizeof(temp)) {
        return 0;
    }
    if (!output_path_write_mount_guard_allows_local(path)) {
        return 0;
    }

    snprintf(temp, sizeof(temp), "%s", path);
    cursor = temp;

    while ((cursor = strchr(cursor + 1, '/')) != NULL) {
        *cursor = '\0';
        if (!output_path_write_mount_guard_allows_local(temp)) {
            return 0;
        }
        if (!ensure_dir_local(temp)) {
            return 0;
        }
        *cursor = '/';
    }

    return 1;
}

int recovery_runner_target_should_skip_image_fd(
    int image_fd,
    const RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size
)
{
    uint64_t failed_at = 0;
    uint64_t file_size;
    uint64_t width = 0;
    uint64_t height = 0;
    int named_mft_target;
    size_t want;
    size_t got;

    if (target == NULL || buffer == NULL || buffer_size == 0U) {
        return 0;
    }

    file_size = target->expected_size > 0U ? target->expected_size : target->size;
    named_mft_target = target->source_path[0] != '\0';
    if (image_fd < 0 || target->run_count == 0U || target->runs[0].byte_length == 0U) {
        return recovery_runner_skip_small_unnamed_image_file_local(
            target,
            named_mft_target,
            file_size
        );
    }

    want = buffer_size;
    if ((uint64_t)want > target->runs[0].byte_length) {
        want = (size_t)target->runs[0].byte_length;
    }
    if (want < 32U) {
        return recovery_runner_skip_small_unnamed_image_file_local(
            target,
            named_mft_target,
            file_size
        );
    }

    got = recovery_runner_read_with_fallback(
        image_fd,
        buffer,
        target->runs[0].abs_offset,
        want,
        &failed_at
    );
    (void)failed_at;
    if (got == 0U) {
        return recovery_runner_skip_small_unnamed_image_file_local(
            target,
            named_mft_target,
            file_size
        );
    }
    if (!probe_image_dimensions_local(target, buffer, got, &width, &height)) {
        return recovery_runner_skip_small_unnamed_image_file_local(
            target,
            named_mft_target,
            file_size
        );
    }

    if (named_mft_target) {
        if (image_filter_is_below_named_dimensions(width, height)) {
            recovery_runner_log_image_filter_local(
                target,
                "small_named_dimensions_filtered",
                file_size,
                file_size,
                width,
                height
            );
            return 1;
        }
        return 0;
    }
    if (image_filter_is_below_min_dimensions(width, height)) {
        recovery_runner_log_image_filter_local(
            target,
            "small_dimensions_filtered",
            file_size,
            file_size,
            width,
            height
        );
        return 1;
    }
    return 0;
}

static size_t recovery_runner_pread_aligned_with_fallback(
    int image_fd,
    unsigned char *buffer,
    uint64_t offset,
    size_t want,
    uint64_t *failed_at
)
{
    size_t attempt;
    size_t min_attempt;

    if (failed_at != NULL) {
        *failed_at = offset;
    }
    if (image_fd < 0 || buffer == NULL || want == 0) {
        return 0;
    }

    attempt = want;
    min_attempt = want < RECOVERY_RUNNER_READ_ERROR_MIN_SIZE
        ? want
        : RECOVERY_RUNNER_READ_ERROR_MIN_SIZE;
    if (min_attempt == 0U) {
        min_attempt = 1U;
    }

    while (attempt >= min_attempt && attempt > 0U) {
        ssize_t got;

        errno = 0;
        got = pread(image_fd, buffer, attempt, (off_t)offset);
        if (got > 0) {
            return (size_t)got;
        }
        if (got == 0) {
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (read_error_is_fatal_device_error(errno)) {
            return 0;
        }
        if (attempt == min_attempt) {
            break;
        }

        attempt /= 4U;
        if (attempt < min_attempt) {
            attempt = min_attempt;
        }
    }

    return 0;
}

size_t recovery_runner_read_with_fallback(
    int image_fd,
    unsigned char *buffer,
    uint64_t offset,
    size_t want,
    uint64_t *failed_at
)
{
    uint64_t aligned_offset;
    uint64_t prefix;
    uint64_t needed;
    uint64_t aligned_want_u64;
    unsigned char *temp = NULL;
    unsigned char *read_buffer = buffer;
    size_t aligned_want;
    size_t got;
    size_t copied = 0;

    if (failed_at != NULL) {
        *failed_at = offset;
    }
    if (image_fd < 0 || buffer == NULL || want == 0U) {
        return 0;
    }

    if ((offset % RECOVERY_RUNNER_DIRECT_ALIGNMENT) == 0ULL &&
        (((uint64_t)want % RECOVERY_RUNNER_DIRECT_ALIGNMENT) == 0ULL ||
         want < RECOVERY_RUNNER_DIRECT_ALIGNMENT)) {
        return recovery_runner_pread_aligned_with_fallback(
            image_fd,
            buffer,
            offset,
            want,
            failed_at
        );
    }

    aligned_offset = offset - (offset % RECOVERY_RUNNER_DIRECT_ALIGNMENT);
    prefix = offset - aligned_offset;
    needed = prefix + (uint64_t)want;
    aligned_want_u64 =
        ((needed + RECOVERY_RUNNER_DIRECT_ALIGNMENT - 1ULL) /
         RECOVERY_RUNNER_DIRECT_ALIGNMENT) *
        RECOVERY_RUNNER_DIRECT_ALIGNMENT;
    if (aligned_want_u64 < needed || aligned_want_u64 > SIZE_MAX) {
        if (failed_at != NULL) {
            *failed_at = offset;
        }
        return 0;
    }

    aligned_want = (size_t)aligned_want_u64;
    temp = (unsigned char *)malloc(aligned_want);
    if (temp == NULL) {
        return 0;
    }

    read_buffer = temp;
    got = recovery_runner_pread_aligned_with_fallback(
        image_fd,
        read_buffer,
        aligned_offset,
        aligned_want,
        failed_at
    );
    if ((uint64_t)got > prefix) {
        copied = got - (size_t)prefix;
        if (copied > want) {
            copied = want;
        }
        memcpy(buffer, read_buffer + prefix, copied);
    } else if (failed_at != NULL && *failed_at == aligned_offset) {
        *failed_at = offset;
    }

    free(temp);
    return copied;
}

int recovery_runner_recover_target_fd(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size,
    int (*stop_requested)(void)
)
{
    char direct_error[sizeof(target->last_error)];
    FILE *out = NULL;
    uint64_t remaining;
    size_t read_size;
    size_t run_index;
    int first_chunk = 1;

    if (image_fd < 0 || target == NULL || buffer == NULL ||
        buffer_size == 0U ||
        target->size == 0U ||
        target->run_count == 0U ||
        target->output_path[0] == '\0') {
        if (target != NULL) {
            snprintf(target->last_error, sizeof(target->last_error), "invalid recovery target");
        }
        return 0;
    }

    read_size = buffer_size;
    direct_error[0] = '\0';
    {
        MftprobeFormatIoOps format_io = {
            recovery_runner_ensure_parent_dirs,
            recovery_runner_read_with_fallback,
            stop_requested,
            read_size
        };
        MftprobeFormatRecoverStatus status = mftprobe_format_direct_recover(
            image_fd,
            target,
            buffer,
            &format_io
        );

        if (status == MFTPROBE_FORMAT_RECOVER_SUCCESS) {
            return 1;
        }
        if (status == MFTPROBE_FORMAT_RECOVER_FAILED) {
            snprintf(direct_error, sizeof(direct_error), "%s", target->last_error);
            target->last_error[0] = '\0';
        }
    }

    if (!recovery_runner_ensure_parent_dirs(target->output_path)) {
        snprintf(target->last_error, sizeof(target->last_error), "failed to create output directories");
        return 0;
    }

    mftprobe_format_validator_reset(target);
    remaining = target->size;

    for (run_index = 0; run_index < target->run_count && remaining > 0U; run_index++) {
        uint64_t run_remaining = target->runs[run_index].byte_length;
        uint64_t run_read = 0U;

        if (recovery_runner_stop_requested(stop_requested)) {
            snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
            if (out != NULL) {
                fclose(out);
                (void)remove(target->output_path);
            }
            return 0;
        }

        if (run_remaining > remaining) {
            run_remaining = remaining;
        }
        if (run_remaining == 0U) {
            continue;
        }

        while (run_remaining > 0U && remaining > 0U) {
            size_t want = run_remaining > read_size ? read_size : (size_t)run_remaining;
            uint64_t read_offset = target->runs[run_index].abs_offset + run_read;
            uint64_t failed_at = read_offset;
            size_t got = recovery_runner_read_with_fallback(
                image_fd,
                buffer,
                read_offset,
                want,
                &failed_at
            );

            if (recovery_runner_stop_requested(stop_requested)) {
                if (out != NULL) {
                    fclose(out);
                    (void)remove(target->output_path);
                }
                snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
                return 0;
            }

            if (got == 0U) {
                if (out != NULL) {
                    fclose(out);
                    (void)remove(target->output_path);
                }
                snprintf(
                    target->last_error,
                    sizeof(target->last_error),
                    "read failed at byte %llu",
                    (unsigned long long)failed_at
                );
                return 0;
            }

            if (first_chunk) {
                size_t skip_bytes = 0U;

                if (!mftprobe_format_validator_start(target, buffer, got, &skip_bytes)) {
                    recovery_runner_preserve_direct_error_local(target, direct_error);
                    return 0;
                }
                if (skip_bytes > 0U) {
                    if (skip_bytes >= got || (uint64_t)skip_bytes >= remaining) {
                        snprintf(target->last_error, sizeof(target->last_error), "JPEG SOI adjustment consumed target");
                        recovery_runner_preserve_direct_error_local(target, direct_error);
                        return 0;
                    }
                    memmove(buffer, buffer + skip_bytes, got - skip_bytes);
                    got -= skip_bytes;
                    remaining -= skip_bytes;
                    run_remaining -= skip_bytes;
                    run_read += skip_bytes;
                }

                if (!output_path_write_mount_guard_allows_local(target->output_path)) {
                    snprintf(target->last_error, sizeof(target->last_error), "output mount is not live");
                    return 0;
                }
                out = fopen(target->output_path, "wb");
                if (out == NULL) {
                    snprintf(target->last_error, sizeof(target->last_error), "failed to open output file");
                    return 0;
                }
                first_chunk = 0;
            }

            mftprobe_format_validator_update(target, buffer, got);

            if (fwrite(buffer, 1, got, out) != got) {
                fclose(out);
                (void)remove(target->output_path);
                snprintf(target->last_error, sizeof(target->last_error), "failed to write output file");
                return 0;
            }

            run_read += got;
            run_remaining -= got;
            remaining -= got;
        }
    }

    if (remaining > 0U) {
        if (out != NULL) {
            fclose(out);
            (void)remove(target->output_path);
        }
        snprintf(
            target->last_error,
            sizeof(target->last_error),
            "target runs ended %llu bytes before requested size",
            (unsigned long long)remaining
        );
        return 0;
    }

    if (!mftprobe_format_validator_finish(target)) {
        char generic_error[sizeof(target->last_error)];

        recovery_runner_copy_text_local(
            generic_error,
            sizeof(generic_error),
            target->last_error
        );
        if (out != NULL) {
            fclose(out);
        }
        (void)remove(target->output_path);
        if (direct_error[0] != '\0' && generic_error[0] != '\0') {
            recovery_runner_join_error_pair_local(
                target->last_error,
                sizeof(target->last_error),
                "direct=",
                direct_error,
                "runlist=",
                generic_error
            );
        } else if (generic_error[0] != '\0') {
            recovery_runner_copy_text_local(
                target->last_error,
                sizeof(target->last_error),
                generic_error
            );
        }
        return 0;
    }

    if (out == NULL || fclose(out) != 0) {
        if (out != NULL) {
            (void)remove(target->output_path);
        }
        snprintf(target->last_error, sizeof(target->last_error), "failed to close output file");
        return 0;
    }

    target->remaining = 0U;
    return 1;
}

static uint64_t recovery_runner_prefix_run_bytes_local(
    const RecoveryTarget *target,
    size_t keep_runs
)
{
    uint64_t total = 0U;
    size_t i;

    if (target == NULL || keep_runs == 0U || keep_runs > target->run_count) {
        return 0U;
    }

    for (i = 0; i < keep_runs; i++) {
        if (UINT64_MAX - total < target->runs[i].byte_length) {
            return 0U;
        }
        total += target->runs[i].byte_length;
    }
    return total;
}

static void recovery_runner_preserve_direct_error_local(
    RecoveryTarget *target,
    const char *direct_error
)
{
    char combined[sizeof(target->last_error)];

    if (target == NULL || direct_error == NULL || direct_error[0] == '\0') {
        return;
    }
    if (target->last_error[0] == '\0') {
        recovery_runner_copy_text_local(
            target->last_error,
            sizeof(target->last_error),
            direct_error
        );
        return;
    }
    if (strcmp(target->last_error, direct_error) == 0) {
        return;
    }

    recovery_runner_join_error_pair_local(
        combined,
        sizeof(combined),
        "direct=",
        direct_error,
        "runlist=",
        target->last_error
    );
    recovery_runner_copy_text_local(
        target->last_error,
        sizeof(target->last_error),
        combined
    );
}

static int recovery_runner_analyze_png_candidate_local(
    const unsigned char *buffer,
    size_t buffer_length,
    size_t start_offset,
    uint64_t expected_size,
    size_t *out_file_size
)
{
    static const unsigned char png_signature[RECOVERY_RUNNER_PNG_SIGNATURE_SIZE] =
        {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    size_t cursor;
    int first_chunk = 1;
    int saw_idat = 0;

    if (out_file_size != NULL) {
        *out_file_size = 0U;
    }
    if (buffer == NULL ||
        start_offset + RECOVERY_RUNNER_PNG_MIN_FILE_SIZE > buffer_length ||
        memcmp(buffer + start_offset, png_signature, sizeof(png_signature)) != 0) {
        return 0;
    }

    cursor = start_offset + RECOVERY_RUNNER_PNG_SIGNATURE_SIZE;
    while (cursor + RECOVERY_RUNNER_PNG_CHUNK_HEADER_SIZE + RECOVERY_RUNNER_PNG_CHUNK_CRC_SIZE <=
           buffer_length) {
        uint32_t chunk_length = read_u32_be_local(buffer + cursor);
        const unsigned char *chunk_type = buffer + cursor + 4U;
        size_t chunk_total_size =
            RECOVERY_RUNNER_PNG_CHUNK_HEADER_SIZE +
            (size_t)chunk_length +
            RECOVERY_RUNNER_PNG_CHUNK_CRC_SIZE;

        if (chunk_total_size <
                RECOVERY_RUNNER_PNG_CHUNK_HEADER_SIZE + RECOVERY_RUNNER_PNG_CHUNK_CRC_SIZE ||
            cursor + chunk_total_size > buffer_length) {
            return 0;
        }

        if (first_chunk) {
            uint32_t width;
            uint32_t height;

            if (memcmp(chunk_type, "IHDR", 4U) != 0 || chunk_length != 13U) {
                return 0;
            }
            width = read_u32_be_local(buffer + cursor + 8U);
            height = read_u32_be_local(buffer + cursor + 12U);
            if (width == 0U || height == 0U ||
                width > RECOVERY_RUNNER_PNG_MAX_DIMENSION ||
                height > RECOVERY_RUNNER_PNG_MAX_DIMENSION) {
                return 0;
            }
            first_chunk = 0;
        } else if (memcmp(chunk_type, "IDAT", 4U) == 0) {
            saw_idat = 1;
        } else if (memcmp(chunk_type, "IEND", 4U) == 0) {
            size_t file_size;

            if (chunk_length != 0U || !saw_idat) {
                return 0;
            }
            file_size = cursor + chunk_total_size - start_offset;
            if (expected_size > 0U && (uint64_t)file_size != expected_size) {
                return 0;
            }
            if (out_file_size != NULL) {
                *out_file_size = file_size;
            }
            return 1;
        }

        cursor += chunk_total_size;
    }

    return 0;
}

static size_t recovery_runner_find_png_start_local(
    const unsigned char *buffer,
    size_t len,
    uint64_t expected_size
)
{
    size_t i;
    size_t file_size = 0U;

    if (buffer == NULL || len < RECOVERY_RUNNER_PNG_MIN_FILE_SIZE) {
        return SIZE_MAX;
    }

    for (i = 0; i + RECOVERY_RUNNER_PNG_MIN_FILE_SIZE <= len; i++) {
        if (recovery_runner_analyze_png_candidate_local(
                buffer,
                len,
                i,
                expected_size,
                &file_size)) {
            return i;
        }
    }

    return SIZE_MAX;
}

static int recovery_runner_recover_png_target_replay_fd_local(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size,
    int (*stop_requested)(void)
)
{
    RecoveryTarget candidate;
    uint64_t search_offset;
    uint64_t search_origin;
    uint64_t search_budget;
    uint64_t search_window_offset;
    uint64_t failed_at = 0U;
    size_t read_size;
    size_t raw_got = 0U;
    size_t start_index = SIZE_MAX;

    if (image_fd < 0 || target == NULL || buffer == NULL || buffer_size == 0U ||
        target->run_count == 0U || target->runs[0].byte_length == 0U) {
        if (target != NULL) {
            snprintf(target->last_error, sizeof(target->last_error), "invalid PNG replay target");
        }
        return 0;
    }

    read_size = buffer_size;
    search_offset =
        target->runs[0].abs_offset > RECOVERY_RUNNER_PNG_REPLAY_BACKTRACK
            ? target->runs[0].abs_offset - RECOVERY_RUNNER_PNG_REPLAY_BACKTRACK
            : 0U;
    search_origin = search_offset;
    search_budget =
        target->runs[0].byte_length + (target->runs[0].abs_offset - search_offset);
    if (search_budget >
        (target->runs[0].abs_offset - search_offset) + RECOVERY_RUNNER_PNG_REPLAY_FORWARD) {
        search_budget =
            (target->runs[0].abs_offset - search_offset) + RECOVERY_RUNNER_PNG_REPLAY_FORWARD;
    }

    for (search_window_offset = search_offset;
         search_window_offset < search_origin + search_budget;
         ) {
        uint64_t remaining_search = (search_origin + search_budget) - search_window_offset;
        size_t want;
        size_t advance;

        if (recovery_runner_stop_requested(stop_requested)) {
            snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
            return 0;
        }

        want = remaining_search > read_size ? read_size : (size_t)remaining_search;
        if (want == 0U) {
            break;
        }

        raw_got = recovery_runner_read_with_fallback(
            image_fd,
            buffer,
            search_window_offset,
            want,
            &failed_at
        );
        if (raw_got == 0U) {
            snprintf(
                target->last_error,
                sizeof(target->last_error),
                "read failed at byte %llu",
                (unsigned long long)failed_at
            );
            return 0;
        }

        start_index = recovery_runner_find_png_start_local(buffer, raw_got, target->size);
        if (start_index != SIZE_MAX) {
            uint64_t adjusted_offset = search_window_offset + (uint64_t)start_index;
            uint64_t skipped = adjusted_offset - target->runs[0].abs_offset;
            uint64_t total_available = 0U;
            size_t i;

            if (adjusted_offset < target->runs[0].abs_offset) {
                break;
            }
            memcpy(&candidate, target, sizeof(candidate));
            candidate.abs_offset = adjusted_offset;
            candidate.runs[0].abs_offset = adjusted_offset;
            if (skipped >= candidate.runs[0].byte_length) {
                break;
            }
            candidate.runs[0].byte_length -= skipped;
            candidate.last_error[0] = '\0';

            for (i = 0; i < candidate.run_count; i++) {
                if (UINT64_MAX - total_available < candidate.runs[i].byte_length) {
                    total_available = UINT64_MAX;
                    break;
                }
                total_available += candidate.runs[i].byte_length;
            }
            if (total_available < candidate.size) {
                break;
            }

            if (recovery_runner_recover_target_fd(
                    image_fd,
                    &candidate,
                    buffer,
                    buffer_size,
                    stop_requested)) {
                memcpy(target, &candidate, sizeof(*target));
                return 1;
            }
        }

        if ((uint64_t)raw_got > RECOVERY_RUNNER_PNG_REPLAY_OVERLAP) {
            advance = (size_t)((uint64_t)raw_got - RECOVERY_RUNNER_PNG_REPLAY_OVERLAP);
        } else {
            advance = raw_got;
        }
        if (advance == 0U) {
            break;
        }
        search_window_offset += (uint64_t)advance;
    }

    snprintf(
        target->last_error,
        sizeof(target->last_error),
        "no plausible PNG start found near byte %llu",
        (unsigned long long)target->abs_offset
    );
    return 0;
}

static int mov_fourcc_equals_local(const unsigned char *type, const char *text)
{
    return type != NULL && text != NULL && memcmp(type, text, 4U) == 0;
}

static int recovery_runner_is_known_mov_brand_local(const unsigned char *brand)
{
    return mov_fourcc_equals_local(brand, "isom") ||
           mov_fourcc_equals_local(brand, "iso2") ||
           mov_fourcc_equals_local(brand, "mp41") ||
           mov_fourcc_equals_local(brand, "mp42") ||
           mov_fourcc_equals_local(brand, "M4A ") ||
           mov_fourcc_equals_local(brand, "M4B ") ||
           mov_fourcc_equals_local(brand, "M4V ") ||
           mov_fourcc_equals_local(brand, "3gp4") ||
           mov_fourcc_equals_local(brand, "3gp5") ||
           mov_fourcc_equals_local(brand, "3g2a") ||
           mov_fourcc_equals_local(brand, "qt  ") ||
           mov_fourcc_equals_local(brand, "avif") ||
           mov_fourcc_equals_local(brand, "heic") ||
           mov_fourcc_equals_local(brand, "heix") ||
           mov_fourcc_equals_local(brand, "hevc") ||
           mov_fourcc_equals_local(brand, "hevx") ||
           mov_fourcc_equals_local(brand, "mif1") ||
           mov_fourcc_equals_local(brand, "msf1");
}

static int recovery_runner_is_known_mov_atom_local(const unsigned char *type)
{
    return mov_fourcc_equals_local(type, "ftyp") ||
           mov_fourcc_equals_local(type, "moov") ||
           mov_fourcc_equals_local(type, "mdat") ||
           mov_fourcc_equals_local(type, "free") ||
           mov_fourcc_equals_local(type, "skip") ||
           mov_fourcc_equals_local(type, "wide") ||
           mov_fourcc_equals_local(type, "uuid") ||
           mov_fourcc_equals_local(type, "pnot") ||
           mov_fourcc_equals_local(type, "meta") ||
           mov_fourcc_equals_local(type, "pdin") ||
           mov_fourcc_equals_local(type, "moof") ||
           mov_fourcc_equals_local(type, "mfra");
}

static int recovery_runner_analyze_mov_candidate_local(
    const unsigned char *buffer,
    size_t buffer_length,
    size_t start_offset
)
{
    size_t cursor = start_offset;
    size_t atoms_seen = 0U;
    int has_media_payload = 0;
    int has_movie_metadata = 0;

    if (buffer == NULL || start_offset + 16U > buffer_length) {
        return 0;
    }
    if (!recovery_runner_is_known_mov_brand_local(buffer + start_offset + 8U)) {
        return 0;
    }

    while (cursor + 16U <= buffer_length && atoms_seen < 64U) {
        uint64_t atom_size = read_u32_be_local(buffer + cursor);
        const unsigned char *atom_type = buffer + cursor + 4U;
        size_t header_size = 8U;

        if (atom_size == 1ULL) {
            if (cursor + 16U > buffer_length) {
                return 0;
            }
            atom_size = read_u64_be_local(buffer + cursor + 8U);
            header_size = 16U;
        } else if (atom_size == 0ULL) {
            atom_size = buffer_length - cursor;
        }

        if (atom_size < RECOVERY_RUNNER_MOV_MIN_ATOM_SIZE ||
            cursor + atom_size > buffer_length ||
            !recovery_runner_is_known_mov_atom_local(atom_type)) {
            return 0;
        }

        if (atoms_seen == 0U) {
            if (!mov_fourcc_equals_local(atom_type, "ftyp") || atom_size < 16U) {
                return 0;
            }
        } else {
            if (mov_fourcc_equals_local(atom_type, "moov") ||
                mov_fourcc_equals_local(atom_type, "moof") ||
                mov_fourcc_equals_local(atom_type, "meta")) {
                has_movie_metadata = 1;
            }
            if (mov_fourcc_equals_local(atom_type, "mdat") ||
                mov_fourcc_equals_local(atom_type, "moof")) {
                has_media_payload = 1;
            }
        }

        atoms_seen++;
        cursor += (size_t)atom_size;
        if (has_media_payload && has_movie_metadata) {
            return 1;
        }
        if (cursor == start_offset + header_size) {
            return 0;
        }
    }

    return has_media_payload && has_movie_metadata;
}

static size_t recovery_runner_find_mov_start_local(
    const unsigned char *buffer,
    size_t len
)
{
    size_t i;

    if (buffer == NULL || len < 16U) {
        return SIZE_MAX;
    }

    for (i = 0; i + 16U <= len; i++) {
        if (recovery_runner_analyze_mov_candidate_local(buffer, len, i)) {
            return i;
        }
    }

    return SIZE_MAX;
}

static int recovery_runner_recover_mov_target_replay_fd_local(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size,
    int (*stop_requested)(void)
)
{
    RecoveryTarget candidate;
    uint64_t search_offset;
    uint64_t search_origin;
    uint64_t search_budget;
    uint64_t search_window_offset;
    uint64_t failed_at = 0U;
    size_t read_size;
    size_t raw_got = 0U;
    size_t start_index = SIZE_MAX;

    if (image_fd < 0 || target == NULL || buffer == NULL || buffer_size == 0U ||
        target->run_count == 0U || target->runs[0].byte_length == 0U) {
        if (target != NULL) {
            snprintf(target->last_error, sizeof(target->last_error), "invalid MOV replay target");
        }
        return 0;
    }

    read_size = buffer_size;
    if ((uint64_t)read_size > RECOVERY_RUNNER_MOV_MAX_VALIDATE_WINDOW) {
        read_size = (size_t)RECOVERY_RUNNER_MOV_MAX_VALIDATE_WINDOW;
    }
    search_offset =
        target->runs[0].abs_offset > RECOVERY_RUNNER_MOV_REPLAY_BACKTRACK
            ? target->runs[0].abs_offset - RECOVERY_RUNNER_MOV_REPLAY_BACKTRACK
            : 0U;
    search_origin = search_offset;
    search_budget =
        target->runs[0].byte_length + (target->runs[0].abs_offset - search_offset);
    if (search_budget >
        (target->runs[0].abs_offset - search_offset) + RECOVERY_RUNNER_MOV_REPLAY_FORWARD) {
        search_budget =
            (target->runs[0].abs_offset - search_offset) + RECOVERY_RUNNER_MOV_REPLAY_FORWARD;
    }

    for (search_window_offset = search_offset;
         search_window_offset < search_origin + search_budget;
         ) {
        uint64_t remaining_search = (search_origin + search_budget) - search_window_offset;
        size_t want;
        size_t advance;

        if (recovery_runner_stop_requested(stop_requested)) {
            snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
            return 0;
        }

        want = remaining_search > read_size ? read_size : (size_t)remaining_search;
        if (want == 0U) {
            break;
        }

        raw_got = recovery_runner_read_with_fallback(
            image_fd,
            buffer,
            search_window_offset,
            want,
            &failed_at
        );
        if (raw_got == 0U) {
            snprintf(
                target->last_error,
                sizeof(target->last_error),
                "read failed at byte %llu",
                (unsigned long long)failed_at
            );
            return 0;
        }

        start_index = recovery_runner_find_mov_start_local(buffer, raw_got);
        if (start_index != SIZE_MAX) {
            uint64_t adjusted_offset = search_window_offset + (uint64_t)start_index;
            uint64_t skipped = adjusted_offset - target->runs[0].abs_offset;
            uint64_t total_available = 0U;
            size_t i;

            if (adjusted_offset < target->runs[0].abs_offset) {
                break;
            }
            memcpy(&candidate, target, sizeof(candidate));
            candidate.abs_offset = adjusted_offset;
            candidate.runs[0].abs_offset = adjusted_offset;
            if (skipped >= candidate.runs[0].byte_length) {
                break;
            }
            candidate.runs[0].byte_length -= skipped;
            candidate.last_error[0] = '\0';

            for (i = 0; i < candidate.run_count; i++) {
                if (UINT64_MAX - total_available < candidate.runs[i].byte_length) {
                    total_available = UINT64_MAX;
                    break;
                }
                total_available += candidate.runs[i].byte_length;
            }
            if (total_available < candidate.size) {
                break;
            }

            if (recovery_runner_recover_target_fd(
                    image_fd,
                    &candidate,
                    buffer,
                    buffer_size,
                    stop_requested)) {
                memcpy(target, &candidate, sizeof(*target));
                return 1;
            }
        }

        if ((uint64_t)raw_got > RECOVERY_RUNNER_MOV_REPLAY_OVERLAP) {
            advance = (size_t)((uint64_t)raw_got - RECOVERY_RUNNER_MOV_REPLAY_OVERLAP);
        } else {
            advance = raw_got;
        }
        if (advance == 0U) {
            break;
        }
        search_window_offset += (uint64_t)advance;
    }

    snprintf(
        target->last_error,
        sizeof(target->last_error),
        "no plausible MOV start found near byte %llu",
        (unsigned long long)target->abs_offset
    );
    return 0;
}

static int recovery_runner_should_try_best_effort_local(
    const RecoveryTarget *target,
    const char *reason
)
{
    const char *failure_class;

    if (target == NULL || target->run_count < 2U) {
        return 0;
    }

    failure_class = recovery_runner_failure_class(reason);
    return strcmp(failure_class, "read_error") == 0 ||
           strcmp(failure_class, "truncated_or_end_mismatch") == 0 ||
           strcmp(failure_class, "unknown") == 0;
}

static void recovery_runner_prepare_best_effort_target_local(
    RecoveryTarget *candidate,
    const RecoveryTarget *source,
    size_t keep_runs,
    uint64_t recovered_size
)
{
    if (candidate == NULL || source == NULL) {
        return;
    }

    memcpy(candidate, source, sizeof(*candidate));
    candidate->size = recovered_size;
    candidate->remaining = recovered_size;
    candidate->next_offset = candidate->abs_offset;
    candidate->run_count = keep_runs;
    candidate->run_index = 0U;
    candidate->run_truncated = 1;
    candidate->last_error[0] = '\0';
    mftprobe_format_validator_reset(candidate);
}

int recovery_runner_recover_target_best_effort_fd(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size,
    int (*stop_requested)(void)
)
{
    RecoveryTarget original;
    RecoveryTarget candidate;
    char primary_error[sizeof(target->last_error)];
    char best_effort_error[sizeof(target->last_error)];
    size_t attempt_count = 0U;
    size_t keep_runs;

    if (target == NULL) {
        return 0;
    }

    memcpy(&original, target, sizeof(original));
    if (recovery_runner_recover_target_fd(
            image_fd,
            target,
            buffer,
            buffer_size,
            stop_requested)) {
        return 1;
    }

    snprintf(primary_error, sizeof(primary_error), "%s", target->last_error);
    best_effort_error[0] = '\0';
    if (recovery_runner_stop_requested(stop_requested) ||
        !recovery_runner_should_try_best_effort_local(&original, primary_error)) {
        return 0;
    }

    for (keep_runs = original.run_count; keep_runs > 1U; keep_runs--) {
        uint64_t available_bytes;

        if (attempt_count >= RECOVERY_RUNNER_BEST_EFFORT_MAX_ATTEMPTS) {
            break;
        }

        available_bytes = recovery_runner_prefix_run_bytes_local(&original, keep_runs - 1U);
        if (available_bytes == 0U ||
            available_bytes >= original.size ||
            !mftprobe_format_target_allows_partial_bytes(&original, available_bytes)) {
            continue;
        }

        recovery_runner_prepare_best_effort_target_local(
            &candidate,
            &original,
            keep_runs - 1U,
            available_bytes
        );
        attempt_count++;
        if (recovery_runner_recover_target_fd(
                image_fd,
                &candidate,
                buffer,
                buffer_size,
                stop_requested)) {
            memcpy(target, &candidate, sizeof(*target));
            return 1;
        }
        snprintf(best_effort_error, sizeof(best_effort_error), "%s", candidate.last_error);
    }

    memcpy(target, &original, sizeof(*target));
    if (best_effort_error[0] != '\0') {
        recovery_runner_join_error_pair_local(
            target->last_error,
            sizeof(target->last_error),
            "primary=",
            primary_error,
            "best_effort=",
            best_effort_error
        );
    } else {
        recovery_runner_copy_text_local(
            target->last_error,
            sizeof(target->last_error),
            primary_error
        );
    }
    return 0;
}

int recovery_runner_recover_target_replay_fd(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size,
    int (*stop_requested)(void)
)
{
    size_t read_size;
    MftprobeJpegRecoveryOps jpeg_ops;

    if (image_fd < 0 || target == NULL || buffer == NULL || buffer_size == 0U) {
        if (target != NULL) {
            snprintf(target->last_error, sizeof(target->last_error), "invalid replay target");
        }
        return 0;
    }

    if (target->validator_id != RECOVERY_VALIDATOR_JPEG) {
        if (streq_ci_local(target->extension, "png")) {
            return recovery_runner_recover_png_target_replay_fd_local(
                image_fd,
                target,
                buffer,
                buffer_size,
                stop_requested
            );
        }
        if (streq_ci_local(target->extension, "mov") ||
            streq_ci_local(target->extension, "mp4") ||
            streq_ci_local(target->extension, "m4v") ||
            streq_ci_local(target->extension, "3gp") ||
            streq_ci_local(target->extension, "3g2")) {
            return recovery_runner_recover_mov_target_replay_fd_local(
                image_fd,
                target,
                buffer,
                buffer_size,
                stop_requested
            );
        }
        return recovery_runner_recover_target_best_effort_fd(
            image_fd,
            target,
            buffer,
            buffer_size,
            stop_requested
        );
    }

    read_size = buffer_size;
    jpeg_ops.ensure_parent_dirs = recovery_runner_ensure_parent_dirs;
    jpeg_ops.read_with_fallback = recovery_runner_read_with_fallback;
    jpeg_ops.recovery_target_is_partial = mftprobe_format_target_is_partial;
    jpeg_ops.recovery_validator_reset = mftprobe_format_validator_reset;
    jpeg_ops.recovery_validator_start = mftprobe_format_validator_start;
    jpeg_ops.recovery_validator_update = mftprobe_format_validator_update;
    jpeg_ops.recovery_validator_finish = mftprobe_format_validator_finish;
    jpeg_ops.stop_requested = stop_requested;
    jpeg_ops.read_size = read_size;

    return mftprobe_direct_recover_jpeg_target_replay(
        image_fd,
        target,
        buffer,
        &jpeg_ops
    );
}

const char *recovery_runner_failure_class(const char *reason)
{
    if (reason == NULL || reason[0] == '\0') {
        return "unknown";
    }

    if (text_contains_local(reason, "interrupted")) {
        return "interrupted";
    }
    if (text_contains_local(reason, "read failed")) {
        return "read_error";
    }
    if (text_contains_local(reason, "did not match expected start bytes") ||
        text_contains_local(reason, "no plausible") ||
        text_contains_local(reason, "did not start") ||
        text_contains_local(reason, "SOI adjustment consumed")) {
        return "start_mismatch";
    }
    if (text_contains_local(reason, "did not end") ||
        text_contains_local(reason, "target runs ended") ||
        text_contains_local(reason, "before requested size")) {
        return "truncated_or_end_mismatch";
    }
    if (text_contains_local(reason, "failed to create output") ||
        text_contains_local(reason, "failed to open output") ||
        text_contains_local(reason, "failed to write output") ||
        text_contains_local(reason, "failed to close output")) {
        return "output_error";
    }
    if (text_contains_local(reason, "invalid")) {
        return "invalid_target";
    }

    return "unknown";
}
