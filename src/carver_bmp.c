/*
 * carver_bmp.c
 * Validates BMP headers, estimates confidence, and recovers likely BMP files
 * from the current buffer.
 */

#include "carver_bmp.h"
#include "carver_output.h"
#include "config.h"
#include "filtered_image_log.h"
#include "fs_backend.h"
#include "image_filter.h"
#include "log.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BMP_SCORE_RECOVER_THRESHOLD 7
#define BMP_MIN_HEADER_SIZE 54

#define BMP_FILE_HEADER_SIZE 14U
#define BMP_CORE_HEADER_SIZE 12U
#define BMP_INFO_HEADER_SIZE 40U
#define BMP_V2_HEADER_SIZE 52U
#define BMP_V3_HEADER_SIZE 56U
#define BMP_V4_HEADER_SIZE 108U
#define BMP_V5_HEADER_SIZE 124U

#define BMP_COMPRESSION_RGB 0U
#define BMP_COMPRESSION_RLE8 1U
#define BMP_COMPRESSION_RLE4 2U
#define BMP_COMPRESSION_BITFIELDS 3U
#define BMP_COMPRESSION_ALPHABITFIELDS 6U

typedef struct {
    int score;
    int has_bm;
    int has_valid_file_size;
    int has_valid_pixel_offset;
    int has_valid_dib_size;
    int has_valid_planes;
    int has_valid_bpp;
    int has_valid_dimensions;
    int has_valid_compression;
    int has_valid_image_size;
    int has_mft_match;

    uint32_t file_size;
    uint32_t pixel_offset;
    uint32_t dib_size;
    uint32_t compression;
    uint32_t image_size;
    uint32_t colors_used;
    int32_t width;
    int32_t height;
    uint16_t planes;
    uint16_t bits_per_pixel;
} BmpAnalysis;

static CarverAuditReport g_bmp_last_audit;

void carver_bmp_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_bmp_last_audit);
}

void carver_bmp_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_bmp_last_audit;
}

static uint16_t read_u16_le(const uint8_t *data)
{
    return (uint16_t)(data[0] | (data[1] << 8));
}

static uint32_t read_u32_le(const uint8_t *data)
{
    return ((uint32_t)data[0]) |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static int32_t read_i32_le(const uint8_t *data)
{
    return (int32_t)read_u32_le(data);
}

static int is_known_dib_size(uint32_t dib_size)
{
    return dib_size == BMP_CORE_HEADER_SIZE ||
           dib_size == BMP_INFO_HEADER_SIZE ||
           dib_size == BMP_V2_HEADER_SIZE ||
           dib_size == BMP_V3_HEADER_SIZE ||
           dib_size == BMP_V4_HEADER_SIZE ||
           dib_size == BMP_V5_HEADER_SIZE;
}

static int should_skip_small_bmp(const BmpAnalysis *analysis)
{
    uint32_t abs_width;
    uint32_t abs_height;

    if (analysis == NULL) {
        return 0;
    }

    abs_width = (uint32_t)(analysis->width < 0
        ? -(int64_t)analysis->width
        : (int64_t)analysis->width);
    abs_height = (uint32_t)(analysis->height < 0
        ? -(int64_t)analysis->height
        : (int64_t)analysis->height);

    return image_filter_should_skip_image(
        abs_width,
        abs_height,
        analysis->file_size
    );
}

static void log_filtered_bmp_local(
    size_t absolute_offset,
    const BmpAnalysis *analysis
)
{
    uint32_t abs_width;
    uint32_t abs_height;

    if (analysis == NULL) {
        return;
    }

    abs_width = (uint32_t)(analysis->width < 0
        ? -(int64_t)analysis->width
        : (int64_t)analysis->width);
    abs_height = (uint32_t)(analysis->height < 0
        ? -(int64_t)analysis->height
        : (int64_t)analysis->height);

    filtered_image_log_append_current(
        "raw-carver",
        "bmp",
        "small_image_filtered",
        (uint64_t)absolute_offset,
        0U,
        (uint64_t)analysis->file_size,
        (uint64_t)abs_width,
        (uint64_t)abs_height,
        NULL
    );
}

static BmpAnalysis analyze_bmp_candidate(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset
)
{
    BmpAnalysis result = {0};
    int32_t abs_width;
    int32_t abs_height;
    uint64_t row_bits;
    uint64_t row_stride;
    uint64_t min_image_size;
    uint64_t minimum_pixel_offset = BMP_FILE_HEADER_SIZE;
    uint64_t palette_bytes = 0;
    uint64_t mask_bytes = 0;
    uint64_t color_entry_size = 4;
    FsScanHint mft_hint = {0};
    uint16_t reserved1;
    uint16_t reserved2;
    int is_core_header = 0;
    int compression_valid_for_bpp = 0;
    uint32_t max_palette_colors = 0;

    if (buffer == NULL || start_offset + BMP_MIN_HEADER_SIZE > buffer_length) {
        result.score = -100;
        return result;
    }

    if (buffer[start_offset] != 0x42 || buffer[start_offset + 1] != 0x4D) {
        result.score = -100;
        return result;
    }

    result.has_bm = 1;
    result.score += 3;

    result.file_size = read_u32_le(buffer + start_offset + 2);
    reserved1 = read_u16_le(buffer + start_offset + 6);
    reserved2 = read_u16_le(buffer + start_offset + 8);
    result.pixel_offset = read_u32_le(buffer + start_offset + 10);
    result.dib_size = read_u32_le(buffer + start_offset + 14);

    if (!is_known_dib_size(result.dib_size)) {
        result.score = -100;
        return result;
    }

    is_core_header = result.dib_size == BMP_CORE_HEADER_SIZE;
    if (is_core_header) {
        result.width = (int32_t)read_u16_le(buffer + start_offset + 18);
        result.height = (int32_t)read_u16_le(buffer + start_offset + 20);
        result.planes = read_u16_le(buffer + start_offset + 22);
        result.bits_per_pixel = read_u16_le(buffer + start_offset + 24);
        result.compression = BMP_COMPRESSION_RGB;
        result.image_size = 0;
        result.colors_used = 0;
        color_entry_size = 3U;
    } else {
        result.width = read_i32_le(buffer + start_offset + 18);
        result.height = read_i32_le(buffer + start_offset + 22);
        result.planes = read_u16_le(buffer + start_offset + 26);
        result.bits_per_pixel = read_u16_le(buffer + start_offset + 28);
        result.compression = read_u32_le(buffer + start_offset + 30);
        result.image_size = read_u32_le(buffer + start_offset + 34);
        result.colors_used = read_u32_le(buffer + start_offset + 46);
    }

    if (reserved1 == 0 && reserved2 == 0) {
        result.score += 1;
    } else {
        result.score -= 1;
    }

    if (result.file_size >= BMP_FILE_HEADER_SIZE + result.dib_size &&
        start_offset + result.file_size <= buffer_length) {
        result.has_valid_file_size = 1;
        result.score += 3;
    } else if (result.file_size >= BMP_FILE_HEADER_SIZE + result.dib_size) {
        result.score += 1;
    } else {
        result.score -= 4;
    }

    if (result.bits_per_pixel <= 8U) {
        max_palette_colors = 1U << result.bits_per_pixel;
        if (result.colors_used != 0U && result.colors_used <= max_palette_colors) {
            palette_bytes = (uint64_t)result.colors_used * color_entry_size;
        } else {
            palette_bytes = (uint64_t)max_palette_colors * color_entry_size;
        }
    }

    if (result.compression == BMP_COMPRESSION_BITFIELDS &&
        result.dib_size == BMP_INFO_HEADER_SIZE) {
        mask_bytes = 12U;
    }

    minimum_pixel_offset += (uint64_t)result.dib_size + palette_bytes + mask_bytes;
    if (result.pixel_offset >= minimum_pixel_offset &&
        result.pixel_offset < result.file_size) {
        result.has_valid_pixel_offset = 1;
        result.score += 2;
    } else {
        result.score -= 3;
    }

    result.has_valid_dib_size = 1;
    result.score += 2;

    if (result.planes == 1) {
        result.has_valid_planes = 1;
        result.score += 2;
    } else {
        result.score -= 3;
    }

    switch (result.bits_per_pixel) {
        case 1:
        case 4:
        case 8:
        case 16:
        case 24:
        case 32:
            result.has_valid_bpp = 1;
            result.score += 2;
            break;
        default:
            result.score -= 2;
            break;
    }

    switch (result.compression) {
        case BMP_COMPRESSION_RGB:
            compression_valid_for_bpp = 1;
            break;
        case BMP_COMPRESSION_RLE8:
            compression_valid_for_bpp = result.bits_per_pixel == 8U;
            break;
        case BMP_COMPRESSION_RLE4:
            compression_valid_for_bpp = result.bits_per_pixel == 4U;
            break;
        case BMP_COMPRESSION_BITFIELDS:
            compression_valid_for_bpp =
                (result.bits_per_pixel == 16U || result.bits_per_pixel == 32U);
            break;
        case BMP_COMPRESSION_ALPHABITFIELDS:
            compression_valid_for_bpp = result.bits_per_pixel == 32U;
            break;
        default:
            compression_valid_for_bpp = 0;
            break;
    }

    if (!is_core_header &&
        result.height < 0 &&
        result.compression != BMP_COMPRESSION_RGB &&
        result.compression != BMP_COMPRESSION_BITFIELDS) {
        compression_valid_for_bpp = 0;
    }

    if (!is_core_header &&
        (result.compression == BMP_COMPRESSION_RLE8 ||
         result.compression == BMP_COMPRESSION_RLE4) &&
        result.height < 0) {
        compression_valid_for_bpp = 0;
    }

    if (compression_valid_for_bpp) {
        result.has_valid_compression = 1;
        result.score += 2;
    } else {
        result.score -= 4;
    }

    abs_width = (result.width < 0) ? -result.width : result.width;
    abs_height = (result.height < 0) ? -result.height : result.height;

    if (abs_width > 0 && abs_height > 0 &&
        abs_width <= 100000 && abs_height <= 100000) {
        result.has_valid_dimensions = 1;
        result.score += 2;
    } else {
        result.score -= 3;
    }

    if (result.file_size > 0 && result.file_size < 128) {
        result.score -= 3;
    }

    if (result.file_size > (500U * 1024U * 1024U)) {
        result.score -= 2;
    }

    if (result.has_valid_dimensions && result.has_valid_bpp) {
        row_bits = (uint64_t)abs_width * (uint64_t)result.bits_per_pixel;
        row_stride = ((row_bits + 31ULL) / 32ULL) * 4ULL;
        min_image_size = row_stride * (uint64_t)abs_height;

        if ((result.compression == BMP_COMPRESSION_RGB ||
             result.compression == BMP_COMPRESSION_BITFIELDS ||
             result.compression == BMP_COMPRESSION_ALPHABITFIELDS) &&
            min_image_size > 0 &&
            result.file_size >= result.pixel_offset &&
            result.file_size - result.pixel_offset >= min_image_size) {
            result.has_valid_image_size = 1;
            result.score += 3;
        } else if (result.image_size != 0 &&
                   result.file_size >= result.pixel_offset &&
                   result.file_size - result.pixel_offset >= result.image_size) {
            result.has_valid_image_size = 1;
            result.score += 1;
        } else {
            result.score -= 4;
        }
    }

    if (fs_backend_lookup_scan_hint((long long)absolute_offset, &mft_hint)) {
        result.has_mft_match = 1;

        if (mft_hint.exact_data_match) {
            result.score += 2;
        } else if (mft_hint.inside_nonresident_run) {
            result.score += 1;
        }

        if (mft_hint.inside_resident_record) {
            result.score += 1;
        }
    }

    return result;
}

static int write_bmp_file(
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
        "bmp",
        buffer + start_offset,
        file_size
    );
}

int carver_bmp_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    BmpAnalysis analysis;

    carver_bmp_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0;
    }

    if (buffer == NULL || start_offset >= buffer_length) {
        carver_audit_set_inline(&g_bmp_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    analysis = analyze_bmp_candidate(
        buffer,
        buffer_length,
        start_offset,
        absolute_offset
    );
/*
    log_info(
        "BMP candidate at offset %zu: score=%d size=%u pixel_offset=%u dib=%u width=%d height=%d planes=%u bpp=%u",
        absolute_offset,
        analysis.score,
        analysis.file_size,
        analysis.pixel_offset,
        analysis.dib_size,
        analysis.width,
        analysis.height,
        analysis.planes,
        analysis.bits_per_pixel
    );*/

    if (analysis.score < BMP_SCORE_RECOVER_THRESHOLD) {
        carver_audit_set_inline(&g_bmp_last_audit, "rejected", "low_score", 0U);
        return 0;
    }

    if (!analysis.has_valid_file_size || !analysis.has_valid_image_size) {
        carver_audit_set_inline(&g_bmp_last_audit, "rejected", "invalid_size_fields", 0U);
        return 0;
    }

    if (should_skip_small_bmp(&analysis)) {
        if (confirmed_span_out != NULL) {
            *confirmed_span_out = (size_t)analysis.file_size;
        }
        log_filtered_bmp_local(absolute_offset, &analysis);
        carver_audit_set_inline(
            &g_bmp_last_audit,
            "skipped",
            "small_image_filtered",
            (size_t)analysis.file_size);
        return 1;
    }

    if (!write_bmp_file(
        buffer,
        start_offset,
        analysis.file_size,
        absolute_offset
    )) {
        carver_audit_set_inline(
            &g_bmp_last_audit,
            "rejected",
            "write_failed",
            (size_t)analysis.file_size);
        return 0;
    }

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = (size_t)analysis.file_size;
    }

    carver_audit_set_inline(
        &g_bmp_last_audit,
        "recovered",
        "accepted",
        (size_t)analysis.file_size);
    return 1;
}
