#include "mftprobe_format_jpeg_recovery.h"

#include "mftprobe_embedded.h"
#include "fs_backend.h"
#include "mftprobe_format_jpeg_validator.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

static const uint64_t JPEG_DIRECT_START_BACKTRACK = 4096ULL;
static const uint64_t JPEG_DIRECT_START_SEARCH_FORWARD = 16ULL * 1024ULL * 1024ULL;
static const uint64_t JPEG_DIRECT_START_WINDOW_OVERLAP = 256ULL;
static const uint64_t JPEG_REPLAY_START_BACKTRACK = 65536ULL;
static const uint64_t JPEG_REPLAY_START_SEARCH_FORWARD = 64ULL * 1024ULL * 1024ULL;
static const uint64_t JPEG_REPLAY_START_WINDOW_OVERLAP = 4096ULL;
static const uint64_t JPEG_DIRECT_EOI_SLACK = 65536ULL;
static const uint64_t JPEG_DIRECT_MIN_UNKNOWN_SIZE_BUDGET = 4ULL * 1024ULL * 1024ULL;
static const size_t JPEG_RECOVERY_DEFAULT_READ_SIZE = 4U * 1024U * 1024U;

static int mftprobe_direct_recover_jpeg_target_with_search(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    const MftprobeJpegRecoveryOps *ops,
    uint64_t start_backtrack,
    uint64_t start_search_forward,
    uint64_t start_window_overlap
)
{
    FILE *out = NULL;
    MftprobeJpegStreamState jpeg_state;
    uint64_t original_size;
    uint64_t original_remaining;
    uint64_t container_offset;
    uint64_t search_offset;
    uint64_t search_budget;
    uint64_t search_consumed;
    uint64_t search_window_offset;
    uint64_t start_offset;
    uint64_t remaining_budget;
    uint64_t next_read_offset;
    uint64_t failed_at = 0;
    uint64_t available_bytes = 0;
    size_t read_size;
    size_t raw_got;
    size_t search_want;
    size_t start_index;
    size_t bytes_written = 0;
    size_t run_index;
    int found_eoi = 0;
    int success = 0;

    if (image_fd < 0 || target == NULL || buffer == NULL ||
        target->run_count == 0 || target->runs[0].byte_length == 0 ||
        ops == NULL ||
        ops->ensure_parent_dirs == NULL ||
        ops->read_with_fallback == NULL ||
        ops->recovery_target_is_partial == NULL ||
        ops->recovery_validator_reset == NULL ||
        ops->recovery_validator_start == NULL ||
        ops->recovery_validator_update == NULL ||
        ops->recovery_validator_finish == NULL) {
        if (target != NULL) {
            snprintf(target->last_error, sizeof(target->last_error), "invalid JPEG recovery target");
        }
        return 0;
    }
    read_size = ops->read_size > 0 ? ops->read_size : JPEG_RECOVERY_DEFAULT_READ_SIZE;

    if (!ops->ensure_parent_dirs(target->output_path)) {
        snprintf(target->last_error, sizeof(target->last_error), "failed to create output directories");
        return 0;
    }
    if (ops->stop_requested != NULL && ops->stop_requested()) {
        snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
        return 0;
    }

    original_size = target->size;
    original_remaining = target->remaining;
    search_offset =
        target->runs[0].abs_offset > start_backtrack
            ? target->runs[0].abs_offset - start_backtrack
            : 0;
    search_budget =
        target->runs[0].byte_length + (target->runs[0].abs_offset - search_offset);
    if (search_budget > (target->runs[0].abs_offset - search_offset) + start_search_forward) {
        search_budget =
            (target->runs[0].abs_offset - search_offset) + start_search_forward;
    }
    search_window_offset = search_offset;
    search_consumed = 0;
    start_index = SIZE_MAX;
    raw_got = 0;

    while (search_consumed < search_budget) {
        size_t advance;
        uint64_t remaining_search = search_budget - search_consumed;

        search_want = remaining_search > read_size ? read_size : (size_t)remaining_search;
        if (search_want == 0U) {
            break;
        }

        raw_got = ops->read_with_fallback(
            image_fd,
            buffer,
            search_window_offset,
            search_want,
            &failed_at
        );
        if (raw_got == 0U) {
            snprintf(target->last_error, sizeof(target->last_error), "read failed at byte %llu",
                     (unsigned long long)failed_at);
            return 0;
        }
        if (ops->stop_requested != NULL && ops->stop_requested()) {
            snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
            return 0;
        }

        start_index = mftprobe_jpeg_find_start_in_window(buffer, raw_got);
        if (start_index != SIZE_MAX) {
            search_offset = search_window_offset;
            break;
        }

        if ((uint64_t)raw_got >= start_window_overlap + 1ULL) {
            advance = (size_t)((uint64_t)raw_got - start_window_overlap);
        } else {
            advance = raw_got;
        }
        if (advance == 0U) {
            break;
        }
        search_window_offset += (uint64_t)advance;
        search_consumed = search_window_offset - search_offset;
    }

    if (start_index == SIZE_MAX) {
        snprintf(
            target->last_error,
            sizeof(target->last_error),
            "no plausible JPEG start found near byte %llu",
            (unsigned long long)target->abs_offset
        );
        return 0;
    }
    container_offset = search_offset + (uint64_t)start_index;
    if (mftprobe_jpeg_header_has_large_exif_app1(buffer + start_index, raw_got - start_index)) {
        uint64_t first_run_probe_available =
            target->runs[0].byte_length - (container_offset - target->runs[0].abs_offset);
        size_t probe_want =
            first_run_probe_available > read_size ? read_size : (size_t)first_run_probe_available;
        size_t probe_got = ops->read_with_fallback(
            image_fd,
            buffer,
            container_offset,
            probe_want,
            &failed_at
        );

        if (probe_got > 0) {
            size_t kodak_main_index = mftprobe_jpeg_find_kodak_embedded_main_image_start(
                buffer,
                probe_got
            );

            search_offset = container_offset;
            raw_got = probe_got;
            start_index = 0;
            if (kodak_main_index != SIZE_MAX) {
                start_index = kodak_main_index;
            }
        }
    }

    start_offset = search_offset + (uint64_t)start_index;
    if (start_offset >= target->runs[0].abs_offset + target->runs[0].byte_length) {
        snprintf(target->last_error, sizeof(target->last_error), "adjusted JPEG start is outside target run");
        return 0;
    }

    remaining_budget = target->size;
    if (target->expected_size > 0 &&
        target->expected_size < mftprobe_jpeg_partial_min_size() &&
        remaining_budget < JPEG_DIRECT_MIN_UNKNOWN_SIZE_BUDGET) {
        remaining_budget = JPEG_DIRECT_MIN_UNKNOWN_SIZE_BUDGET;
    } else if (!ops->recovery_target_is_partial(target)) {
        remaining_budget += JPEG_DIRECT_EOI_SLACK;
        if (remaining_budget < target->size) {
            remaining_budget = UINT64_MAX;
        }
    }

    for (run_index = 0; run_index < target->run_count; run_index++) {
        uint64_t run_bytes = target->runs[run_index].byte_length;

        if (ops->stop_requested != NULL && ops->stop_requested()) {
            snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
            return 0;
        }

        if (run_index == 0) {
            uint64_t skip = start_offset - target->runs[0].abs_offset;

            if (skip >= run_bytes) {
                snprintf(target->last_error, sizeof(target->last_error), "adjusted JPEG start skipped the first run");
                return 0;
            }
            run_bytes -= skip;
        }
        if (available_bytes > UINT64_MAX - run_bytes) {
            available_bytes = UINT64_MAX;
            break;
        }
        available_bytes += run_bytes;
    }
    if (remaining_budget > available_bytes) {
        remaining_budget = available_bytes;
    }

    ops->recovery_validator_reset(target);
    mftprobe_jpeg_stream_state_reset(&jpeg_state);
    out = fopen(target->output_path, "wb");
    if (out == NULL) {
        snprintf(target->last_error, sizeof(target->last_error), "failed to open output file");
        return 0;
    }
    if (ops->stop_requested != NULL && ops->stop_requested()) {
        snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
        goto cleanup;
    }

    {
        const unsigned char *data = buffer + start_index;
        size_t data_len = raw_got - start_index;
        size_t skip_bytes = 0;
        size_t write_len;
        ssize_t eoi_index;
        uint64_t first_run_remaining =
            target->runs[0].byte_length - (start_offset - target->runs[0].abs_offset);

        if ((uint64_t)data_len > first_run_remaining) {
            data_len = (size_t)first_run_remaining;
        }
        if ((uint64_t)data_len > remaining_budget) {
            data_len = (size_t)remaining_budget;
        }
        if (!ops->recovery_validator_start(target, data, data_len, &skip_bytes)) {
            goto cleanup;
        }
        if (skip_bytes > 0) {
            if (skip_bytes >= data_len) {
                snprintf(target->last_error, sizeof(target->last_error), "JPEG SOI adjustment consumed target");
                goto cleanup;
            }
            data += skip_bytes;
            data_len -= skip_bytes;
            start_offset += skip_bytes;
        }

        eoi_index = mftprobe_jpeg_stream_find_eoi(&jpeg_state, data, data_len);
        write_len = eoi_index >= 0 ? (size_t)eoi_index + 1U : data_len;
        ops->recovery_validator_update(target, data, write_len);
        if (fwrite(data, 1, write_len, out) != write_len) {
            snprintf(target->last_error, sizeof(target->last_error), "failed to write output file");
            goto cleanup;
        }

        bytes_written += write_len;
        remaining_budget -= write_len;
        if (eoi_index >= 0) {
            found_eoi = 1;
        }
    }

    next_read_offset = search_offset + (uint64_t)raw_got;
    for (run_index = 0; run_index < target->run_count && !found_eoi && remaining_budget > 0; run_index++) {
        uint64_t run_start = target->runs[run_index].abs_offset;
        uint64_t run_end = run_start + target->runs[run_index].byte_length;

        if (ops->stop_requested != NULL && ops->stop_requested()) {
            snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
            goto cleanup;
        }

        if (run_index == 0) {
            if (next_read_offset < run_start) {
                next_read_offset = run_start;
            }
        } else {
            next_read_offset = run_start;
        }

        while (!found_eoi && remaining_budget > 0 && next_read_offset < run_end) {
            size_t want = remaining_budget > read_size ? read_size : (size_t)remaining_budget;
            size_t write_len;
            ssize_t eoi_index;

            if (ops->stop_requested != NULL && ops->stop_requested()) {
                snprintf(target->last_error, sizeof(target->last_error), "interrupted by signal");
                goto cleanup;
            }

            if ((uint64_t)want > run_end - next_read_offset) {
                want = (size_t)(run_end - next_read_offset);
            }
            raw_got = ops->read_with_fallback(
                image_fd,
                buffer,
                next_read_offset,
                want,
                &failed_at
            );
            if (raw_got == 0) {
                snprintf(target->last_error, sizeof(target->last_error), "read failed at byte %llu",
                         (unsigned long long)failed_at);
                goto cleanup;
            }

            eoi_index = mftprobe_jpeg_stream_find_eoi(&jpeg_state, buffer, raw_got);
            write_len = eoi_index >= 0 ? (size_t)eoi_index + 1U : raw_got;
            ops->recovery_validator_update(target, buffer, write_len);
            if (fwrite(buffer, 1, write_len, out) != write_len) {
                snprintf(target->last_error, sizeof(target->last_error), "failed to write output file");
                goto cleanup;
            }

            bytes_written += write_len;
            remaining_budget -= write_len;
            if (eoi_index >= 0) {
                found_eoi = 1;
                break;
            }

            next_read_offset += raw_got;
        }
    }

    target->size = bytes_written;
    target->remaining = 0;
    if (!ops->recovery_validator_finish(target)) {
        goto cleanup;
    }

    if (fclose(out) != 0) {
        out = NULL;
        snprintf(target->last_error, sizeof(target->last_error), "failed to close output file");
        goto cleanup;
    }
    out = NULL;

    target->last_error[0] = '\0';
    success = 1;

cleanup:
    if (!success) {
        if (out != NULL) {
            fclose(out);
        }
        (void)remove(target->output_path);
        target->size = original_size;
        target->remaining = original_remaining;
    }
    return success;
}

int mftprobe_direct_recover_jpeg_target(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    const MftprobeJpegRecoveryOps *ops
)
{
    return mftprobe_direct_recover_jpeg_target_with_search(
        image_fd,
        target,
        buffer,
        ops,
        JPEG_DIRECT_START_BACKTRACK,
        JPEG_DIRECT_START_SEARCH_FORWARD,
        JPEG_DIRECT_START_WINDOW_OVERLAP
    );
}

int mftprobe_direct_recover_jpeg_target_replay(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    const MftprobeJpegRecoveryOps *ops
)
{
    return mftprobe_direct_recover_jpeg_target_with_search(
        image_fd,
        target,
        buffer,
        ops,
        JPEG_REPLAY_START_BACKTRACK,
        JPEG_REPLAY_START_SEARCH_FORWARD,
        JPEG_REPLAY_START_WINDOW_OVERLAP
    );
}
