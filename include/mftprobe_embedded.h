#ifndef MFTPROBE_EMBEDDED_H
#define MFTPROBE_EMBEDDED_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

typedef enum {
    JPEG_PARSE_EXPECT_SOI_0 = 0,
    JPEG_PARSE_EXPECT_SOI_1,
    JPEG_PARSE_SEEK_MARKER_PREFIX,
    JPEG_PARSE_READ_MARKER,
    JPEG_PARSE_READ_LEN_HI,
    JPEG_PARSE_READ_LEN_LO,
    JPEG_PARSE_SKIP_SEGMENT_DATA,
    JPEG_PARSE_SCAN_DATA
} MftprobeJpegParseStage;

typedef struct {
    MftprobeJpegParseStage stage;
    uint8_t marker;
    uint16_t segment_length;
    uint16_t segment_remaining;
    unsigned char previous_scan_byte;
} MftprobeJpegStreamState;

int mftprobe_jpeg_header_looks_structured(const unsigned char *buffer, size_t len);
int mftprobe_jpeg_header_has_large_exif_app1(const unsigned char *buffer, size_t len);
size_t mftprobe_jpeg_find_start_in_window(const unsigned char *buffer, size_t len);
size_t mftprobe_jpeg_find_kodak_embedded_main_image_start(
    const unsigned char *buffer,
    size_t len
);
void mftprobe_jpeg_stream_state_reset(MftprobeJpegStreamState *state);
ssize_t mftprobe_jpeg_stream_find_eoi(
    MftprobeJpegStreamState *state,
    const unsigned char *buffer,
    size_t len
);

#endif
