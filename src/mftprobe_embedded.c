#include "mftprobe_embedded.h"

#include <limits.h>
#include <string.h>

#define JPEG_START_SEARCH_FORWARD (4U * 1024U * 1024U)
#define JPEG_KODAK_HEADER_SCAN_WINDOW (4U * 1024U * 1024U)
#define JPEG_KODAK_PREVIEW_MAX_SIZE (128ULL * 1024ULL)

static int buffer_starts_with_jpeg(const unsigned char *buffer, size_t len)
{
    return buffer != NULL && len >= 3 && buffer[0] == 0xFFU && buffer[1] == 0xD8U &&
           buffer[2] == 0xFFU;
}

static int buffer_contains_ascii_pattern(
    const unsigned char *buffer,
    size_t len,
    const char *pattern
)
{
    size_t i;
    size_t pattern_len;

    if (buffer == NULL || pattern == NULL) {
        return 0;
    }

    pattern_len = strlen(pattern);
    if (pattern_len == 0 || len < pattern_len) {
        return 0;
    }

    for (i = 0; i + pattern_len <= len; i++) {
        if (memcmp(buffer + i, pattern, pattern_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static int buffer_contains_utf16le_ascii_pattern(
    const unsigned char *buffer,
    size_t len,
    const char *pattern
)
{
    size_t i;
    size_t j;
    size_t pattern_len;

    if (buffer == NULL || pattern == NULL) {
        return 0;
    }

    pattern_len = strlen(pattern);
    if (pattern_len == 0 || len < pattern_len * 2U) {
        return 0;
    }

    for (i = 0; i + pattern_len * 2U <= len; i++) {
        int matched = 1;

        for (j = 0; j < pattern_len; j++) {
            if (buffer[i + j * 2U] != (unsigned char)pattern[j] ||
                buffer[i + j * 2U + 1U] != 0x00U) {
                matched = 0;
                break;
            }
        }
        if (matched) {
            return 1;
        }
    }

    return 0;
}

static int jpeg_marker_has_length(uint8_t marker)
{
    if (marker == 0xD8U ||
        marker == 0xD9U ||
        marker == 0x01U ||
        (marker >= 0xD0U && marker <= 0xD7U)) {
        return 0;
    }

    return 1;
}

int mftprobe_jpeg_header_looks_structured(const unsigned char *buffer, size_t len)
{
    uint8_t marker;
    uint16_t segment_len;

    if (!buffer_starts_with_jpeg(buffer, len)) {
        return 0;
    }
    if (len < 6) {
        return 1;
    }

    marker = buffer[3];
    if (marker == 0x00U || marker == 0xD8U || marker == 0xD9U) {
        return 0;
    }
    if (marker >= 0xD0U && marker <= 0xD7U) {
        return 1;
    }

    segment_len = (uint16_t)(((uint16_t)buffer[4] << 8) | buffer[5]);
    if (segment_len < 2U) {
        return 0;
    }

    return 1;
}

int mftprobe_jpeg_header_has_large_exif_app1(const unsigned char *buffer, size_t len)
{
    uint16_t segment_len;

    if (buffer == NULL || len < 12) {
        return 0;
    }
    if (!(buffer[0] == 0xFFU &&
          buffer[1] == 0xD8U &&
          buffer[2] == 0xFFU &&
          buffer[3] == 0xE1U)) {
        return 0;
    }
    segment_len = (uint16_t)(((uint16_t)buffer[4] << 8) | buffer[5]);
    if (segment_len < 4096U) {
        return 0;
    }
    return memcmp(buffer + 6, "Exif\0\0", 6) == 0;
}

size_t mftprobe_jpeg_find_start_in_window(const unsigned char *buffer, size_t len)
{
    size_t limit;
    size_t i;

    if (buffer == NULL || len < 3) {
        return SIZE_MAX;
    }

    limit = len < JPEG_START_SEARCH_FORWARD ? len : JPEG_START_SEARCH_FORWARD;
    for (i = 0; i + 3 <= limit; i++) {
        if (mftprobe_jpeg_header_looks_structured(buffer + i, len - i)) {
            return i;
        }
    }

    return SIZE_MAX;
}

void mftprobe_jpeg_stream_state_reset(MftprobeJpegStreamState *state)
{
    if (state == NULL) {
        return;
    }

    memset(state, 0, sizeof(*state));
    state->stage = JPEG_PARSE_EXPECT_SOI_0;
}

ssize_t mftprobe_jpeg_stream_find_eoi(
    MftprobeJpegStreamState *state,
    const unsigned char *buffer,
    size_t len
)
{
    size_t i;

    if (state == NULL || buffer == NULL) {
        return -1;
    }

    for (i = 0; i < len; i++) {
        unsigned char byte = buffer[i];

        switch (state->stage) {
            case JPEG_PARSE_EXPECT_SOI_0:
                if (byte != 0xFFU) {
                    return -1;
                }
                state->stage = JPEG_PARSE_EXPECT_SOI_1;
                break;

            case JPEG_PARSE_EXPECT_SOI_1:
                if (byte != 0xD8U) {
                    return -1;
                }
                state->stage = JPEG_PARSE_SEEK_MARKER_PREFIX;
                break;

            case JPEG_PARSE_SEEK_MARKER_PREFIX:
                if (byte == 0xFFU) {
                    state->stage = JPEG_PARSE_READ_MARKER;
                }
                break;

            case JPEG_PARSE_READ_MARKER:
                if (byte == 0xFFU) {
                    break;
                }
                if (byte == 0x00U) {
                    state->stage = JPEG_PARSE_SEEK_MARKER_PREFIX;
                    break;
                }
                state->marker = byte;
                if (!jpeg_marker_has_length(byte)) {
                    if (byte == 0xD9U) {
                        return -1;
                    }
                    state->stage = JPEG_PARSE_SEEK_MARKER_PREFIX;
                    break;
                }
                state->segment_length = 0;
                state->stage = JPEG_PARSE_READ_LEN_HI;
                break;

            case JPEG_PARSE_READ_LEN_HI:
                state->segment_length = (uint16_t)((uint16_t)byte << 8);
                state->stage = JPEG_PARSE_READ_LEN_LO;
                break;

            case JPEG_PARSE_READ_LEN_LO:
                state->segment_length =
                    (uint16_t)(state->segment_length | (uint16_t)byte);
                if (state->segment_length < 2U) {
                    return -1;
                }
                state->segment_remaining = (uint16_t)(state->segment_length - 2U);
                if (state->marker == 0xDAU) {
                    if (state->segment_remaining == 0U) {
                        state->stage = JPEG_PARSE_SCAN_DATA;
                        state->previous_scan_byte = 0;
                    } else {
                        state->stage = JPEG_PARSE_SKIP_SEGMENT_DATA;
                    }
                } else if (state->segment_remaining == 0U) {
                    state->stage = JPEG_PARSE_SEEK_MARKER_PREFIX;
                } else {
                    state->stage = JPEG_PARSE_SKIP_SEGMENT_DATA;
                }
                break;

            case JPEG_PARSE_SKIP_SEGMENT_DATA:
                if (state->segment_remaining > 0U) {
                    state->segment_remaining--;
                }
                if (state->segment_remaining == 0U) {
                    if (state->marker == 0xDAU) {
                        state->stage = JPEG_PARSE_SCAN_DATA;
                        state->previous_scan_byte = 0;
                    } else {
                        state->stage = JPEG_PARSE_SEEK_MARKER_PREFIX;
                    }
                }
                break;

            case JPEG_PARSE_SCAN_DATA:
                if (state->previous_scan_byte == 0xFFU && byte == 0xD9U) {
                    return (ssize_t)i;
                }
                state->previous_scan_byte = byte;
                break;
        }
    }

    return -1;
}

size_t mftprobe_jpeg_find_kodak_embedded_main_image_start(
    const unsigned char *buffer,
    size_t len
)
{
    size_t scan_len;
    size_t i;
    size_t best_offset = SIZE_MAX;
    size_t best_size = 0;
    int looks_kodak;

    if (buffer == NULL || len < 6) {
        return SIZE_MAX;
    }

    scan_len = len;
    if ((uint64_t)scan_len > JPEG_KODAK_HEADER_SCAN_WINDOW) {
        scan_len = (size_t)JPEG_KODAK_HEADER_SCAN_WINDOW;
    }

    looks_kodak =
        buffer_contains_ascii_pattern(buffer, scan_len, "KODAK") ||
        buffer_contains_ascii_pattern(buffer, scan_len, "Screen Nail") ||
        buffer_contains_ascii_pattern(buffer, scan_len, "Presized image for LCD display") ||
        buffer_contains_utf16le_ascii_pattern(buffer, scan_len, "Screen Nail") ||
        buffer_contains_utf16le_ascii_pattern(buffer, scan_len, "Presized image for LCD display");
    if (!looks_kodak) {
        return SIZE_MAX;
    }

    for (i = 0; i + 3U <= scan_len; i++) {
        MftprobeJpegStreamState state;
        ssize_t eoi_index;
        size_t candidate_size;

        if (!mftprobe_jpeg_header_looks_structured(buffer + i, scan_len - i)) {
            continue;
        }
        mftprobe_jpeg_stream_state_reset(&state);
        eoi_index = mftprobe_jpeg_stream_find_eoi(&state, buffer + i, scan_len - i);
        if (eoi_index < 0) {
            continue;
        }
        candidate_size = (size_t)eoi_index + 1U;

        if (i == 0 && candidate_size <= JPEG_KODAK_PREVIEW_MAX_SIZE) {
            continue;
        }
        if (candidate_size > best_size) {
            best_size = candidate_size;
            best_offset = i;
        }
    }

    return best_offset;
}
