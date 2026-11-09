#ifndef FILTERED_IMAGE_LOG_H
#define FILTERED_IMAGE_LOG_H

#include <stdint.h>

void filtered_image_log_append(
    const char *output_dir,
    const char *source,
    const char *format,
    const char *reason,
    uint64_t abs_offset,
    uint64_t expected_size,
    uint64_t detected_size,
    uint64_t width,
    uint64_t height,
    const char *path
);

void filtered_image_log_append_current(
    const char *source,
    const char *format,
    const char *reason,
    uint64_t abs_offset,
    uint64_t expected_size,
    uint64_t detected_size,
    uint64_t width,
    uint64_t height,
    const char *path
);

#endif
