#include "carver_psd.h"

#include "carver_output.h"
#include "config.h"
#include "filtered_image_log.h"
#include "image_filter.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PSD_HEADER_SIZE 26U
#define PSD_MIN_FILE_SIZE 32U
#define PSD_MAX_DIMENSION 200000U

typedef struct {
    int valid_header;
    int supported_version;
    int supported_compression;
    uint16_t channels;
    uint32_t width;
    uint32_t height;
    uint16_t depth;
    uint16_t color_mode;
    uint16_t compression;
    size_t file_size;
} PsdAnalysis;

static CarverAuditReport g_psd_last_audit;

void carver_psd_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_psd_last_audit);
}

void carver_psd_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_psd_last_audit;
}

static uint16_t read_u16_be_local(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static uint32_t read_u32_be_local(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static int skip_sized_block(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t *cursor
)
{
    uint32_t block_size;

    if (buffer == NULL || cursor == NULL || *cursor + 4U > buffer_length) {
        return 0;
    }

    block_size = read_u32_be_local(buffer + *cursor);
    *cursor += 4U;

    if (*cursor > buffer_length || block_size > buffer_length - *cursor) {
        return 0;
    }

    *cursor += (size_t)block_size;
    return 1;
}

static int estimate_psd_image_data_size(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t image_data_offset,
    uint16_t channels,
    uint32_t width,
    uint32_t height,
    uint16_t depth,
    uint16_t compression,
    size_t *file_size_out
)
{
    uint64_t bytes_per_sample;
    uint64_t row_bytes;
    uint64_t image_bytes;

    if (file_size_out != NULL) {
        *file_size_out = 0;
    }
    if (buffer == NULL || file_size_out == NULL || image_data_offset + 2U > buffer_length) {
        return 0;
    }

    if (depth != 1U && depth != 8U && depth != 16U && depth != 32U) {
        return 0;
    }

    bytes_per_sample = (depth == 1U) ? 1U : ((uint64_t)depth / 8U);
    row_bytes = (depth == 1U)
        ? (((uint64_t)width + 7U) / 8U)
        : ((uint64_t)width * bytes_per_sample);

    if (compression == 0U) {
        image_bytes = (uint64_t)channels * (uint64_t)height * row_bytes;
        if (image_bytes > (uint64_t)(buffer_length - image_data_offset - 2U)) {
            return 0;
        }

        *file_size_out = image_data_offset + 2U + (size_t)image_bytes;
        return 1;
    }

    if (compression == 1U) {
        uint64_t row_count = (uint64_t)channels * (uint64_t)height;
        uint64_t table_bytes = row_count * 2U;
        uint64_t encoded_bytes = 0;
        size_t cursor;
        uint64_t i;

        if (table_bytes > (uint64_t)(buffer_length - image_data_offset - 2U)) {
            return 0;
        }

        cursor = image_data_offset + 2U;
        for (i = 0; i < row_count; i++) {
            encoded_bytes += (uint64_t)read_u16_be_local(buffer + cursor);
            cursor += 2U;
        }

        if (encoded_bytes > (uint64_t)(buffer_length - cursor)) {
            return 0;
        }

        *file_size_out = cursor + (size_t)encoded_bytes;
        return 1;
    }

    return 0;
}

static PsdAnalysis analyze_psd_candidate(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset
)
{
    PsdAnalysis result = {0};
    size_t cursor;

    if (buffer == NULL || start_offset + PSD_HEADER_SIZE > buffer_length) {
        return result;
    }

    if (memcmp(buffer + start_offset, "8BPS", 4U) != 0) {
        return result;
    }

    result.valid_header = 1;
    if (read_u16_be_local(buffer + start_offset + 4U) != 1U) {
        return result;
    }
    if (memcmp(buffer + start_offset + 6U, "\0\0\0\0\0\0", 6U) != 0) {
        return result;
    }

    result.supported_version = 1;
    result.channels = read_u16_be_local(buffer + start_offset + 12U);
    result.height = read_u32_be_local(buffer + start_offset + 14U);
    result.width = read_u32_be_local(buffer + start_offset + 18U);
    result.depth = read_u16_be_local(buffer + start_offset + 22U);
    result.color_mode = read_u16_be_local(buffer + start_offset + 24U);

    if (result.channels == 0U || result.channels > 56U ||
        result.width == 0U || result.height == 0U ||
        result.width > PSD_MAX_DIMENSION || result.height > PSD_MAX_DIMENSION) {
        return (PsdAnalysis){0};
    }

    switch (result.depth) {
        case 1U:
        case 8U:
        case 16U:
        case 32U:
            break;
        default:
            return (PsdAnalysis){0};
    }

    if (result.color_mode > 9U) {
        return (PsdAnalysis){0};
    }

    cursor = start_offset + PSD_HEADER_SIZE;
    if (!skip_sized_block(buffer, buffer_length, &cursor) ||
        !skip_sized_block(buffer, buffer_length, &cursor) ||
        !skip_sized_block(buffer, buffer_length, &cursor) ||
        cursor + 2U > buffer_length) {
        return (PsdAnalysis){0};
    }

    result.compression = read_u16_be_local(buffer + cursor);
    if (!estimate_psd_image_data_size(
            buffer,
            buffer_length,
            cursor,
            result.channels,
            result.width,
            result.height,
            result.depth,
            result.compression,
            &result.file_size)) {
        return (PsdAnalysis){0};
    }
    if (result.file_size < start_offset) {
        return (PsdAnalysis){0};
    }
    result.file_size -= start_offset;

    result.supported_compression = 1;
    return result;
}

static int should_skip_small_psd(const PsdAnalysis *analysis)
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

static void log_filtered_psd_local(
    size_t absolute_offset,
    const PsdAnalysis *analysis
)
{
    if (analysis == NULL) {
        return;
    }
    filtered_image_log_append_current(
        "raw-carver",
        "psd",
        "small_image_filtered",
        (uint64_t)absolute_offset,
        0U,
        (uint64_t)analysis->file_size,
        (uint64_t)analysis->width,
        (uint64_t)analysis->height,
        NULL
    );
}

static int write_psd_file(
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
        "psd",
        buffer + start_offset,
        file_size
    );
}

int carver_psd_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    PsdAnalysis analysis;

    carver_psd_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0;
    }
    if (buffer == NULL || start_offset >= buffer_length) {
        carver_audit_set_inline(&g_psd_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    analysis = analyze_psd_candidate(buffer, buffer_length, start_offset);
    if (!analysis.valid_header ||
        !analysis.supported_version ||
        !analysis.supported_compression ||
        analysis.file_size < PSD_MIN_FILE_SIZE) {
        carver_audit_set_inline(&g_psd_last_audit, "rejected", "invalid_psd_structure", 0U);
        return 0;
    }

    if (should_skip_small_psd(&analysis)) {
        if (confirmed_span_out != NULL) {
            *confirmed_span_out = analysis.file_size;
        }
        log_filtered_psd_local(absolute_offset, &analysis);
        carver_audit_set_inline(
            &g_psd_last_audit,
            "skipped",
            "small_image_filtered",
            analysis.file_size);
        return 1;
    }

    if (!write_psd_file(
            buffer,
            start_offset,
            analysis.file_size,
            absolute_offset)) {
        carver_audit_set_inline(
            &g_psd_last_audit,
            "rejected",
            "write_failed",
            analysis.file_size);
        return 0;
    }

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = analysis.file_size;
    }
    carver_audit_set_inline(
        &g_psd_last_audit,
        "recovered",
        "accepted",
        analysis.file_size);
    return 1;
}
