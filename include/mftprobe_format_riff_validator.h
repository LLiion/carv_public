#ifndef MFTPROBE_FORMAT_RIFF_VALIDATOR_H
#define MFTPROBE_FORMAT_RIFF_VALIDATOR_H

#include <stddef.h>
#include <stdint.h>

int mftprobe_riff_validator_start(
    uint64_t abs_offset,
    const char *extension,
    char *last_error,
    size_t last_error_size,
    const unsigned char *buffer,
    size_t len
);

int mftprobe_riff_validator_finish(
    uint64_t abs_offset,
    uint64_t size,
    const char *extension,
    char *last_error,
    size_t last_error_size
);

#endif
