#include "mftprobe_format_jpeg_validator.h"
#include "mftprobe_embedded.h"

#include <stdio.h>

static const uint64_t JPEG_PARTIAL_MIN_SIZE = 4096ULL;
static const uint64_t JPEG_PARTIAL_SIZE_TOLERANCE = 4096ULL;

uint64_t mftprobe_jpeg_partial_min_size(void)
{
    return JPEG_PARTIAL_MIN_SIZE;
}

uint64_t mftprobe_jpeg_partial_size_tolerance(void)
{
    return JPEG_PARTIAL_SIZE_TOLERANCE;
}

int mftprobe_jpeg_size_looks_partial(uint64_t size, uint64_t expected_size)
{
    return expected_size > 0 &&
           size > 0 &&
           size + JPEG_PARTIAL_SIZE_TOLERANCE < expected_size;
}

void mftprobe_jpeg_validator_update(
    unsigned char tail[2],
    size_t *tail_len,
    const unsigned char *buffer,
    size_t len
)
{
    if (tail == NULL || tail_len == NULL || buffer == NULL || len == 0) {
        return;
    }

    if (len >= 2) {
        tail[0] = buffer[len - 2U];
        tail[1] = buffer[len - 1U];
        *tail_len = 2;
    } else if (*tail_len == 0) {
        tail[0] = buffer[0];
        *tail_len = 1;
    } else {
        tail[0] = tail[1];
        tail[1] = buffer[0];
        *tail_len = 2;
    }
}

int mftprobe_jpeg_validator_start(
    uint64_t abs_offset,
    char *last_error,
    size_t last_error_size,
    const unsigned char *buffer,
    size_t len,
    size_t *skip_bytes
)
{
    size_t found;

    if (skip_bytes != NULL) {
        *skip_bytes = 0;
    }

    if (mftprobe_jpeg_header_looks_structured(buffer, len)) {
        return 1;
    }

    found = mftprobe_jpeg_find_start_in_window(buffer, len);
    if (found != SIZE_MAX) {
        if (skip_bytes != NULL) {
            *skip_bytes = found;
        }
        return 1;
    }

    if (last_error != NULL && last_error_size > 0) {
        snprintf(
            last_error,
            last_error_size,
            "data near byte %llu does not contain a plausible JPEG SOI",
            (unsigned long long)abs_offset
        );
    }
    return 0;
}

int mftprobe_jpeg_validator_finish(
    uint64_t abs_offset,
    uint64_t size,
    uint64_t expected_size,
    uint64_t partial_min_size,
    uint64_t partial_size_tolerance,
    const unsigned char tail[2],
    size_t tail_len,
    char *last_error,
    size_t last_error_size
)
{
    if (tail_len == 2 && tail[0] == 0xFFU && tail[1] == 0xD9U) {
        return 1;
    }

    if (partial_min_size == 0) {
        partial_min_size = JPEG_PARTIAL_MIN_SIZE;
    }
    if (partial_size_tolerance == 0) {
        partial_size_tolerance = JPEG_PARTIAL_SIZE_TOLERANCE;
    }

    if (expected_size > 0 &&
        size > 0 &&
        size + partial_size_tolerance < expected_size &&
        size >= partial_min_size) {
        return 1;
    }

    if (last_error != NULL && last_error_size > 0) {
        snprintf(
            last_error,
            last_error_size,
            "data at byte %llu did not end with JPEG EOI after %llu bytes",
            (unsigned long long)abs_offset,
            (unsigned long long)size
        );
    }
    return 0;
}
