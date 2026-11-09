#include "jpeg_stream_probe.h"

#include <stdlib.h>
#include <string.h>

#define JPEG_STREAM_PROBE_PREFIX_LIMIT (1024U * 1024U)

static uint16_t jpeg_stream_read_u16_be(const unsigned char *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static int jpeg_stream_marker_is_start_of_frame(uint8_t marker)
{
    switch (marker) {
        case 0xC0:
        case 0xC1:
        case 0xC2:
        case 0xC3:
        case 0xC5:
        case 0xC6:
        case 0xC7:
        case 0xC9:
        case 0xCA:
        case 0xCB:
        case 0xCD:
        case 0xCE:
        case 0xCF:
            return 1;
        default:
            return 0;
    }
}

static int jpeg_stream_marker_has_length(uint8_t marker)
{
    if (marker == 0xD8 ||
        marker == 0xD9 ||
        marker == 0x01 ||
        (marker >= 0xD0 && marker <= 0xD7)) {
        return 0;
    }

    return 1;
}

static int jpeg_stream_marker_supports_prefix(uint8_t marker)
{
    return (marker >= 0xE0U && marker <= 0xEFU) ||
           marker == 0xC4U ||
           marker == 0xCCU ||
           marker == 0xDBU ||
           marker == 0xDDU ||
           marker == 0xFEU;
}

static void jpeg_stream_note_breakpoint(
    JpegStreamProbe *probe,
    JpegStreamBreakpointKind kind,
    size_t offset,
    uint8_t marker
)
{
    if (probe == NULL) {
        return;
    }

    probe->result.breakpoint_kind = (uint8_t)kind;
    probe->result.breakpoint_marker = marker;
    probe->result.error_offset = offset;
}

static void jpeg_stream_note_tags(JpegStreamProbe *probe)
{
    size_t i;
    size_t max_scan;

    if (probe == NULL || probe->data == NULL) {
        return;
    }

    max_scan = probe->size;
    if (max_scan > 64U) {
        max_scan = 64U;
    }

    if (!probe->result.saw_jfif) {
        for (i = 0U; i + 5U <= max_scan; i++) {
            if (memcmp(probe->data + i, "JFIF\0", 5U) == 0) {
                probe->result.saw_jfif = 1;
                break;
            }
        }
    }

    if (!probe->result.saw_exif) {
        for (i = 0U; i + 6U <= max_scan; i++) {
            if (memcmp(probe->data + i, "Exif\0\0", 6U) == 0) {
                probe->result.saw_exif = 1;
                break;
            }
        }
    }
}

static JpegStreamProbeStatus jpeg_stream_parse_prefix(JpegStreamProbe *probe)
{
    size_t cursor;
    int saw_sof = 0;
    int saw_support_segment = 0;

    if (probe == NULL || probe->data == NULL) {
        return JPEG_STREAM_PROBE_INVALID;
    }

    if (probe->size < 3U) {
        return JPEG_STREAM_PROBE_NEED_MORE;
    }

    if (!(probe->data[0] == 0xFFU &&
          probe->data[1] == 0xD8U &&
          probe->data[2] == 0xFFU)) {
        probe->result.error_offset = 0U;
        return JPEG_STREAM_PROBE_INVALID;
    }

    probe->result.saw_soi = 1;
    jpeg_stream_note_tags(probe);

    cursor = 2U;
    while (cursor + 1U < probe->size) {
        uint8_t marker;
        uint16_t segment_length;

        while (cursor < probe->size && probe->data[cursor] == 0xFFU) {
            cursor++;
        }

        if (cursor >= probe->size) {
            return JPEG_STREAM_PROBE_NEED_MORE;
        }

        marker = probe->data[cursor++];
        if (probe->result.first_marker_after_soi == 0U) {
            probe->result.first_marker_after_soi = marker;
        }

        if (marker == 0x00U) {
            continue;
        }

        if (marker == 0xD9U) {
            jpeg_stream_note_breakpoint(
                probe,
                JPEG_STREAM_BREAKPOINT_PREFIX_EARLY_EOI,
                cursor - 1U,
                marker
            );
            return JPEG_STREAM_PROBE_INVALID;
        }

        if (marker == 0xDAU) {
            if (!saw_sof || !saw_support_segment) {
                jpeg_stream_note_breakpoint(
                    probe,
                    JPEG_STREAM_BREAKPOINT_PREFIX_SOS_WITHOUT_SUPPORT,
                    cursor - 1U,
                    marker
                );
                return JPEG_STREAM_PROBE_INVALID;
            }
            if (cursor + 2U > probe->size) {
                return JPEG_STREAM_PROBE_NEED_MORE;
            }

            segment_length = jpeg_stream_read_u16_be(probe->data + cursor);
            if (segment_length < 2U) {
                jpeg_stream_note_breakpoint(
                    probe,
                    JPEG_STREAM_BREAKPOINT_PREFIX_INVALID_SEGMENT,
                    cursor,
                    marker
                );
                return JPEG_STREAM_PROBE_INVALID;
            }
            if (cursor + segment_length > probe->size) {
                return JPEG_STREAM_PROBE_NEED_MORE;
            }

            probe->result.saw_sof = saw_sof;
            probe->result.saw_sos = 1;
            probe->entropy_start_offset = cursor + segment_length;
            probe->entropy_scan_offset = cursor + segment_length;
            return JPEG_STREAM_PROBE_NEED_MORE;
        }

        if (!jpeg_stream_marker_has_length(marker)) {
            continue;
        }

        if (cursor + 2U > probe->size) {
            return JPEG_STREAM_PROBE_NEED_MORE;
        }

        segment_length = jpeg_stream_read_u16_be(probe->data + cursor);
        if (segment_length < 2U) {
            jpeg_stream_note_breakpoint(
                probe,
                JPEG_STREAM_BREAKPOINT_PREFIX_INVALID_SEGMENT,
                cursor,
                marker
            );
            return JPEG_STREAM_PROBE_INVALID;
        }
        if (cursor + segment_length > probe->size) {
            if (probe->size > JPEG_STREAM_PROBE_PREFIX_LIMIT) {
                jpeg_stream_note_breakpoint(
                    probe,
                    JPEG_STREAM_BREAKPOINT_PREFIX_INVALID_SEGMENT,
                    cursor,
                    marker
                );
                return JPEG_STREAM_PROBE_INVALID;
            }
            return JPEG_STREAM_PROBE_NEED_MORE;
        }

        if (jpeg_stream_marker_is_start_of_frame(marker)) {
            uint16_t width;
            uint16_t height;

            if (segment_length < 8U) {
                jpeg_stream_note_breakpoint(
                    probe,
                    JPEG_STREAM_BREAKPOINT_PREFIX_INVALID_SEGMENT,
                    cursor,
                    marker
                );
                return JPEG_STREAM_PROBE_INVALID;
            }

            height = jpeg_stream_read_u16_be(probe->data + cursor + 3U);
            width = jpeg_stream_read_u16_be(probe->data + cursor + 5U);
            if (width == 0U || height == 0U) {
                jpeg_stream_note_breakpoint(
                    probe,
                    JPEG_STREAM_BREAKPOINT_PREFIX_INVALID_SEGMENT,
                    cursor,
                    marker
                );
                return JPEG_STREAM_PROBE_INVALID;
            }
            if (!saw_support_segment) {
                jpeg_stream_note_breakpoint(
                    probe,
                    JPEG_STREAM_BREAKPOINT_PREFIX_SOF_WITHOUT_SUPPORT,
                    cursor - 1U,
                    marker
                );
                return JPEG_STREAM_PROBE_INVALID;
            }

            probe->result.width = width;
            probe->result.height = height;
            saw_sof = 1;
            probe->result.saw_sof = 1;
        }

        if (jpeg_stream_marker_supports_prefix(marker)) {
            saw_support_segment = 1;
            probe->result.saw_prefix_support_segment = 1;
            if (marker >= 0xE0U && marker <= 0xEFU) {
                probe->result.saw_prefix_app_segment = 1;
            } else {
                probe->result.saw_prefix_table_segment = 1;
            }
        }

        cursor += segment_length;
    }

    if (probe->size > JPEG_STREAM_PROBE_PREFIX_LIMIT) {
        probe->result.error_offset = probe->size;
        return JPEG_STREAM_PROBE_INVALID;
    }
    return JPEG_STREAM_PROBE_NEED_MORE;
}

static JpegStreamProbeStatus jpeg_stream_scan_entropy(JpegStreamProbe *probe)
{
    size_t i;
    size_t entropy_start_offset;

    if (probe == NULL || probe->data == NULL) {
        return JPEG_STREAM_PROBE_INVALID;
    }
    if (!probe->result.saw_sos) {
        return JPEG_STREAM_PROBE_NEED_MORE;
    }

    entropy_start_offset = probe->entropy_start_offset;
    for (i = probe->entropy_scan_offset; i < probe->size; i++) {
        unsigned char value = probe->data[i];

        if (probe->entropy_prev_ff) {
            if (value == 0x00U) {
                probe->entropy_prev_ff = 0;
                continue;
            }
            if (value == 0xFFU) {
                probe->entropy_prev_ff = 1;
                continue;
            }
            if (value >= 0xD0U && value <= 0xD7U) {
                probe->result.saw_restart_marker = 1;
                probe->entropy_prev_ff = 0;
                continue;
            }
            if (value == 0xD9U) {
                probe->result.saw_eoi = 1;
                probe->result.eoi_offset = i - 1U;
                if (i >= entropy_start_offset + 1U) {
                    probe->result.entropy_data_bytes = (i - 1U) - entropy_start_offset;
                }
                return JPEG_STREAM_PROBE_COMPLETE;
            }

            probe->result.saw_entropy_marker_anomaly = 1;
            if (i >= entropy_start_offset + 1U) {
                probe->result.entropy_data_bytes = (i - 1U) - entropy_start_offset;
            }
            jpeg_stream_note_breakpoint(
                probe,
                JPEG_STREAM_BREAKPOINT_ENTROPY_MARKER,
                i - 1U,
                value
            );
            return JPEG_STREAM_PROBE_INVALID;
        }
        probe->entropy_prev_ff = (value == 0xFFU);
    }

    if (probe->size > entropy_start_offset) {
        probe->result.entropy_data_bytes = probe->size - entropy_start_offset;
    }
    probe->entropy_scan_offset = probe->size;
    return JPEG_STREAM_PROBE_NEED_MORE;
}

void jpeg_stream_probe_init(JpegStreamProbe *probe)
{
    if (probe == NULL) {
        return;
    }

    memset(probe, 0, sizeof(*probe));
    probe->status = JPEG_STREAM_PROBE_NEED_MORE;
}

void jpeg_stream_probe_free(JpegStreamProbe *probe)
{
    if (probe == NULL) {
        return;
    }

    free(probe->data);
    probe->data = NULL;
    probe->size = 0U;
    probe->capacity = 0U;
    probe->entropy_start_offset = 0U;
    probe->entropy_scan_offset = 0U;
    probe->entropy_prev_ff = 0;
    probe->status = JPEG_STREAM_PROBE_NEED_MORE;
    memset(&probe->result, 0, sizeof(probe->result));
}

int jpeg_stream_probe_append(
    JpegStreamProbe *probe,
    const unsigned char *data,
    size_t length
)
{
    size_t needed;
    size_t new_capacity;

    if (probe == NULL || data == NULL || length == 0U) {
        return 0;
    }
    if (probe->status == JPEG_STREAM_PROBE_COMPLETE ||
        probe->status == JPEG_STREAM_PROBE_INVALID) {
        return 1;
    }

    needed = probe->size + length;
    if (needed > probe->capacity) {
        unsigned char *replacement;

        new_capacity = probe->capacity == 0U ? 4096U : probe->capacity;
        while (new_capacity < needed) {
            if (new_capacity > (SIZE_MAX / 2U)) {
                return 0;
            }
            new_capacity *= 2U;
        }

        replacement = (unsigned char *)realloc(probe->data, new_capacity);
        if (replacement == NULL) {
            return 0;
        }
        probe->data = replacement;
        probe->capacity = new_capacity;
    }

    memcpy(probe->data + probe->size, data, length);
    probe->size += length;
    probe->result.total_size = probe->size;

    if (!probe->result.saw_sos) {
        probe->status = jpeg_stream_parse_prefix(probe);
        if (probe->status == JPEG_STREAM_PROBE_INVALID ||
            probe->status == JPEG_STREAM_PROBE_COMPLETE) {
            return 1;
        }
    }

    if (probe->result.saw_sos && !probe->result.saw_eoi) {
        probe->status = jpeg_stream_scan_entropy(probe);
    }

    return 1;
}

JpegStreamProbeStatus jpeg_stream_probe_status(const JpegStreamProbe *probe)
{
    if (probe == NULL) {
        return JPEG_STREAM_PROBE_INVALID;
    }

    return probe->status;
}

const JpegStreamProbeResult *jpeg_stream_probe_result(const JpegStreamProbe *probe)
{
    if (probe == NULL) {
        return NULL;
    }

    return &probe->result;
}

const unsigned char *jpeg_stream_probe_data(
    const JpegStreamProbe *probe,
    size_t *out_length
)
{
    if (out_length != NULL) {
        *out_length = 0U;
    }
    if (probe == NULL) {
        return NULL;
    }

    if (out_length != NULL) {
        *out_length = probe->size;
    }
    return probe->data;
}
