#include "blob_start.h"

#include <string.h>

int blob_start_matches(
    const unsigned char *buffer,
    size_t buffer_len,
    const unsigned char *blob_start,
    size_t blob_start_len
)
{
    if (blob_start == NULL || blob_start_len == 0) {
        return 1;
    }
    if (buffer == NULL || buffer_len == 0) {
        return 0;
    }
    if (buffer[0] != blob_start[0]) {
        return 0;
    }
    if (blob_start_len > 1) {
        if (buffer_len < 2 || buffer[1] != blob_start[1]) {
            return 0;
        }
    }
    if (buffer_len < blob_start_len) {
        return 0;
    }
    return memcmp(buffer, blob_start, blob_start_len) == 0;
}
