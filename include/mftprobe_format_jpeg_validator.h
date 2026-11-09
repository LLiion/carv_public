#ifndef MFTPROBE_FORMAT_JPEG_VALIDATOR_H
#define MFTPROBE_FORMAT_JPEG_VALIDATOR_H

#include <stddef.h>
#include <stdint.h>

uint64_t mftprobe_jpeg_partial_min_size(void);
uint64_t mftprobe_jpeg_partial_size_tolerance(void);
int mftprobe_jpeg_size_looks_partial(uint64_t size, uint64_t expected_size);

int mftprobe_jpeg_validator_start(
    uint64_t abs_offset,
    char *last_error,
    size_t last_error_size,
    const unsigned char *buffer,
    size_t len,
    size_t *skip_bytes
);

void mftprobe_jpeg_validator_update(
    unsigned char tail[2],
    size_t *tail_len,
    const unsigned char *buffer,
    size_t len
);

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
);

#endif
