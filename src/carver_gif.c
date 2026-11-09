#include "carver_gif.h"

#include "carver_output.h"
#include "config.h"
#include "filtered_image_log.h"
#include "image_filter.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define GIF_HEADER_SIZE 6U
#define GIF_LSD_SIZE 7U
#define GIF_MIN_FILE_SIZE 20U
typedef struct {
    int valid_header;
    int valid_screen;
    int saw_image;
    int saw_trailer;
    uint16_t width;
    uint16_t height;
    size_t file_size;
} GifAnalysis;

static CarverAuditReport g_gif_last_audit;

void carver_gif_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_gif_last_audit);
}

void carver_gif_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_gif_last_audit;
}

static int should_skip_small_gif(
    const GifAnalysis *analysis
)
{
    if (analysis == NULL) {
        return 0;
    }

    return image_filter_should_skip_image(
        analysis->width,
        analysis->height,
        analysis->file_size
    );
}

static void log_filtered_gif_local(
    size_t absolute_offset,
    const GifAnalysis *analysis
)
{
    if (analysis == NULL) {
        return;
    }
    filtered_image_log_append_current(
        "raw-carver",
        "gif",
        "small_image_filtered",
        (uint64_t)absolute_offset,
        0U,
        (uint64_t)analysis->file_size,
        (uint64_t)analysis->width,
        (uint64_t)analysis->height,
        NULL
    );
}

static uint16_t read_u16_le_local(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static int advance_gif_sub_blocks(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t *cursor
)
{
    while (*cursor < buffer_length) {
        uint8_t block_size = buffer[*cursor];

        (*cursor)++;
        if (block_size == 0U) {
            return 1;
        }
        if (*cursor + block_size > buffer_length) {
            return 0;
        }
        *cursor += block_size;
    }

    return 0;
}

static int write_gif_file(
    const uint8_t *buffer,
    size_t start_offset,
    size_t file_size,
    size_t absolute_offset
)
{
    return carver_output_write_buffer(
        (long long)absolute_offset,
        APP_DEFAULT_UNIDENT_DIR,
        "recov",
        "gif",
        buffer + start_offset,
        file_size
    );
}

static GifAnalysis analyze_gif_candidate(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset
)
{
    GifAnalysis result = {0};
    size_t cursor;
    uint8_t packed;

    if (buffer == NULL || start_offset + GIF_HEADER_SIZE + GIF_LSD_SIZE > buffer_length) {
        return result;
    }

    if (memcmp(buffer + start_offset, "GIF87a", GIF_HEADER_SIZE) != 0 &&
        memcmp(buffer + start_offset, "GIF89a", GIF_HEADER_SIZE) != 0) {
        return result;
    }

    result.valid_header = 1;
    result.width = read_u16_le_local(buffer + start_offset + 6);
    result.height = read_u16_le_local(buffer + start_offset + 8);
    if (result.width == 0 || result.height == 0) {
        return result;
    }

    result.valid_screen = 1;
    cursor = start_offset + GIF_HEADER_SIZE + GIF_LSD_SIZE;
    packed = buffer[start_offset + GIF_HEADER_SIZE + 4];

    if ((packed & 0x80U) != 0U) {
        size_t table_size = 3U * (1U << ((packed & 0x07U) + 1U));

        if (cursor + table_size > buffer_length) {
            return result;
        }
        cursor += table_size;
    }

    while (cursor < buffer_length) {
        uint8_t marker = buffer[cursor];

        if (marker == 0x3BU) {
            result.saw_trailer = 1;
            result.file_size = cursor + 1U - start_offset;
            return result;
        }

        if (marker == 0x2CU) {
            uint8_t image_packed;

            if (cursor + 10U > buffer_length) {
                return result;
            }
            image_packed = buffer[cursor + 9U];
            cursor += 10U;

            if ((image_packed & 0x80U) != 0U) {
                size_t table_size = 3U * (1U << ((image_packed & 0x07U) + 1U));

                if (cursor + table_size > buffer_length) {
                    return result;
                }
                cursor += table_size;
            }

            if (cursor >= buffer_length) {
                return result;
            }
            cursor++;
            if (!advance_gif_sub_blocks(buffer, buffer_length, &cursor)) {
                return result;
            }

            result.saw_image = 1;
            continue;
        }

        if (marker == 0x21U) {
            uint8_t block_size;

            if (cursor + 3U > buffer_length) {
                return result;
            }
            cursor += 2U;
            block_size = buffer[cursor];
            cursor++;
            if (cursor + block_size > buffer_length) {
                return result;
            }
            cursor += block_size;
            if (!advance_gif_sub_blocks(buffer, buffer_length, &cursor)) {
                return result;
            }
            continue;
        }

        return result;
    }

    return result;
}

int carver_gif_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    GifAnalysis analysis;

    carver_gif_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0;
    }
    if (buffer == NULL || start_offset >= buffer_length) {
        carver_audit_set_inline(&g_gif_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    analysis = analyze_gif_candidate(buffer, buffer_length, start_offset);
    if (!analysis.valid_header ||
        !analysis.valid_screen ||
        !analysis.saw_image ||
        !analysis.saw_trailer ||
        analysis.file_size < GIF_MIN_FILE_SIZE) {
        carver_audit_set_inline(&g_gif_last_audit, "rejected", "invalid_gif_structure", 0U);
        return 0;
    }

    if (should_skip_small_gif(&analysis)) {
        if (confirmed_span_out != NULL) {
            *confirmed_span_out = analysis.file_size;
        }
        log_filtered_gif_local(absolute_offset, &analysis);
        carver_audit_set_inline(
            &g_gif_last_audit,
            "skipped",
            "small_image_filtered",
            analysis.file_size);
        return 1;
    }

    if (!write_gif_file(
            buffer,
            start_offset,
            analysis.file_size,
            absolute_offset)) {
        carver_audit_set_inline(
            &g_gif_last_audit,
            "rejected",
            "write_failed",
            analysis.file_size);
        return 0;
    }

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = analysis.file_size;
    }
    carver_audit_set_inline(
        &g_gif_last_audit,
        "recovered",
        "accepted",
        analysis.file_size);
    return 1;
}
