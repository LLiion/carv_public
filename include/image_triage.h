#ifndef IMAGE_TRIAGE_H
#define IMAGE_TRIAGE_H

#include <stdint.h>

typedef struct {
    uint64_t width;
    uint64_t height;
    uint64_t file_size;
    int recognized;
    int has_exif;
    int has_jfif;
    int score;
    const char *classification;
} ImageTriageResult;

/*
 * Reads only the recovered output, never the source device.  Classification
 * is advisory: callers must not discard a recovery based on this result.
 */
int image_triage_inspect_file(
    const char *path,
    const char *extension,
    uint64_t file_size,
    ImageTriageResult *result_out
);

#endif
