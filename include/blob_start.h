#ifndef BLOB_START_H
#define BLOB_START_H

#include <stddef.h>

int blob_start_matches(
    const unsigned char *buffer,
    size_t buffer_len,
    const unsigned char *blob_start,
    size_t blob_start_len
);

#endif
