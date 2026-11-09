#include "carver_png.h"

#include "carver_output.h"
#include "config.h"
#include "filtered_image_log.h"
#include "fs_backend.h"
#include "image_filter.h"
#include "raw_candidate_stream.h"
#include "recovery_runner.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#define PNG_SIGNATURE_SIZE 8U
#define PNG_CHUNK_HEADER_SIZE 8U
#define PNG_CHUNK_CRC_SIZE 4U
#define PNG_MIN_FILE_SIZE 45U
#define PNG_MAX_DIMENSION 200000U
#define PNG_EXTENDED_FORWARD_SCAN_INITIAL (32U * 1024U * 1024U)
#define PNG_EXTENDED_FORWARD_SCAN_MAX (256U * 1024U * 1024U)
#define PNG_LOW_YIELD_REGION_BYTES (64ULL * 1024ULL * 1024ULL)
#define PNG_LOW_YIELD_STAGE1_MAX (96U * 1024U * 1024U)
#define PNG_LOW_YIELD_STAGE2_MAX (32U * 1024U * 1024U)
#define PNG_LOW_YIELD_STAGE3_MAX (8U * 1024U * 1024U)
#define PNG_BREAKPOINT_REPORT_NAME APP_STATE_DIR_NAME "/png_breakpoints.tsv"
#define PNG_BREAKPOINT_REPORT_MAX_BYTES (64U * 1024U * 1024U)

typedef enum {
    PNG_FAILURE_NONE = 0,
    PNG_FAILURE_BAD_SIGNATURE,
    PNG_FAILURE_BAD_FIRST_CHUNK,
    PNG_FAILURE_BAD_IHDR,
    PNG_FAILURE_DUPLICATE_IHDR,
    PNG_FAILURE_BAD_PLTE_POSITION,
    PNG_FAILURE_IDAT_AFTER_TRAILING,
    PNG_FAILURE_IEND_BEFORE_IDAT,
    PNG_FAILURE_IEND_WITH_LENGTH,
    PNG_FAILURE_CRITICAL_AFTER_IDAT,
    PNG_FAILURE_NON_ASCII_CHUNK,
    PNG_FAILURE_TRUNCATED_CHUNK,
    PNG_FAILURE_TRUNCATED_HEADER,
    PNG_FAILURE_CHUNK_OVERFLOW
} PngFailureReason;

typedef struct {
    int valid_signature;
    int valid_ihdr;
    int saw_idat;
    int saw_iend;
    uint32_t width;
    uint32_t height;
    size_t file_size;
    PngFailureReason failure_reason;
    size_t failure_offset;
    uint32_t failure_chunk_length;
    uint8_t failure_chunk_type[4];
    int failure_chunk_type_valid;
} PngAnalysis;

typedef struct {
    uint64_t region_base;
    uint64_t attempts;
    uint64_t recovered;
    uint64_t failed_no_iend;
} PngLowYieldRegionState;

static CarverPngStats g_png_stats = {0};
static CarverAuditReport g_png_last_audit;
static PngLowYieldRegionState g_png_low_yield_region = {0};
static int g_png_breakpoint_report_saturated = 0;

void carver_png_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_png_last_audit);
}

void carver_png_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_png_last_audit;
}

static int png_breakpoint_report_enabled(void)
{
    const char *breakpoint_logs = getenv("CARV_ENABLE_IMAGE_BREAKPOINT_LOGS");
    const char *debug_logs = getenv("CARV_DEBUG_LOGS");

    return (breakpoint_logs != NULL && breakpoint_logs[0] != '\0' && breakpoint_logs[0] != '0') ||
           (debug_logs != NULL && debug_logs[0] != '\0' && debug_logs[0] != '0');
}

static double png_now_seconds(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0) {
        return 0.0;
    }

    return (double)tv.tv_sec + ((double)tv.tv_usec / 1000000.0);
}

static uint32_t read_u32_be_local(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static int png_chunk_type_is_ascii_letters(const uint8_t *chunk_type)
{
    size_t i;

    if (chunk_type == NULL) {
        return 0;
    }

    for (i = 0U; i < 4U; i++) {
        if (!((chunk_type[i] >= 'A' && chunk_type[i] <= 'Z') ||
              (chunk_type[i] >= 'a' && chunk_type[i] <= 'z'))) {
            return 0;
        }
    }

    return 1;
}

static int png_bit_depth_valid_for_color_type(
    uint8_t bit_depth,
    uint8_t color_type
)
{
    switch (color_type) {
        case 0:
            return bit_depth == 1U || bit_depth == 2U ||
                   bit_depth == 4U || bit_depth == 8U ||
                   bit_depth == 16U;
        case 2:
            return bit_depth == 8U || bit_depth == 16U;
        case 3:
            return bit_depth == 1U || bit_depth == 2U ||
                   bit_depth == 4U || bit_depth == 8U;
        case 4:
            return bit_depth == 8U || bit_depth == 16U;
        case 6:
            return bit_depth == 8U || bit_depth == 16U;
        default:
            return 0;
    }
}

static int png_ihdr_fields_valid(
    const uint8_t *chunk_data,
    uint32_t *out_width,
    uint32_t *out_height
)
{
    uint32_t width;
    uint32_t height;
    uint8_t bit_depth;
    uint8_t color_type;
    uint8_t compression_method;
    uint8_t filter_method;
    uint8_t interlace_method;

    if (chunk_data == NULL) {
        return 0;
    }

    width = read_u32_be_local(chunk_data);
    height = read_u32_be_local(chunk_data + 4U);
    bit_depth = chunk_data[8U];
    color_type = chunk_data[9U];
    compression_method = chunk_data[10U];
    filter_method = chunk_data[11U];
    interlace_method = chunk_data[12U];

    if (width == 0U || height == 0U ||
        width > PNG_MAX_DIMENSION ||
        height > PNG_MAX_DIMENSION) {
        return 0;
    }
    if (!png_bit_depth_valid_for_color_type(bit_depth, color_type)) {
        return 0;
    }
    if (compression_method != 0U || filter_method != 0U) {
        return 0;
    }
    if (interlace_method > 1U) {
        return 0;
    }

    if (out_width != NULL) {
        *out_width = width;
    }
    if (out_height != NULL) {
        *out_height = height;
    }
    return 1;
}

static int png_chunk_is_critical(const uint8_t *chunk_type)
{
    return chunk_type != NULL &&
           chunk_type[0] >= 'A' &&
           chunk_type[0] <= 'Z';
}

static const char *png_failure_reason_name(PngFailureReason reason)
{
    switch (reason) {
        case PNG_FAILURE_NONE:
            return "none";
        case PNG_FAILURE_BAD_SIGNATURE:
            return "bad_signature";
        case PNG_FAILURE_BAD_FIRST_CHUNK:
            return "bad_first_chunk";
        case PNG_FAILURE_BAD_IHDR:
            return "bad_ihdr";
        case PNG_FAILURE_DUPLICATE_IHDR:
            return "duplicate_ihdr";
        case PNG_FAILURE_BAD_PLTE_POSITION:
            return "bad_plte_position";
        case PNG_FAILURE_IDAT_AFTER_TRAILING:
            return "idat_after_trailing";
        case PNG_FAILURE_IEND_BEFORE_IDAT:
            return "iend_before_idat";
        case PNG_FAILURE_IEND_WITH_LENGTH:
            return "iend_with_length";
        case PNG_FAILURE_CRITICAL_AFTER_IDAT:
            return "critical_after_idat";
        case PNG_FAILURE_NON_ASCII_CHUNK:
            return "non_ascii_chunk";
        case PNG_FAILURE_TRUNCATED_CHUNK:
            return "truncated_chunk";
        case PNG_FAILURE_TRUNCATED_HEADER:
            return "truncated_header";
        case PNG_FAILURE_CHUNK_OVERFLOW:
            return "chunk_overflow";
        default:
            return "unknown";
    }
}

static void png_analysis_note_failure(
    PngAnalysis *analysis,
    PngFailureReason reason,
    size_t failure_offset,
    const uint8_t *chunk_type,
    uint32_t chunk_length
)
{
    if (analysis == NULL || analysis->failure_reason != PNG_FAILURE_NONE) {
        return;
    }

    analysis->failure_reason = reason;
    analysis->failure_offset = failure_offset;
    analysis->failure_chunk_length = chunk_length;
    if (chunk_type != NULL) {
        memcpy(analysis->failure_chunk_type, chunk_type, 4U);
        analysis->failure_chunk_type_valid = 1;
    } else {
        memset(analysis->failure_chunk_type, 0, sizeof(analysis->failure_chunk_type));
        analysis->failure_chunk_type_valid = 0;
    }
}

static void png_format_chunk_type_printable(
    const PngAnalysis *analysis,
    char *out,
    size_t out_size
)
{
    size_t i;

    if (out == NULL || out_size == 0U) {
        return;
    }

    if (analysis == NULL || !analysis->failure_chunk_type_valid || out_size < 5U) {
        snprintf(out, out_size, "----");
        return;
    }

    for (i = 0U; i < 4U && i + 1U < out_size; i++) {
        uint8_t c = analysis->failure_chunk_type[i];

        out[i] = (c >= 32U && c <= 126U) ? (char)c : '.';
    }
    out[(out_size > 4U) ? 4U : (out_size - 1U)] = '\0';
}

static void png_format_chunk_type_hex(
    const PngAnalysis *analysis,
    char *out,
    size_t out_size
)
{
    if (out == NULL || out_size == 0U) {
        return;
    }

    if (analysis == NULL || !analysis->failure_chunk_type_valid || out_size < 9U) {
        snprintf(out, out_size, "--------");
        return;
    }

    snprintf(
        out,
        out_size,
        "%02X%02X%02X%02X",
        (unsigned int)analysis->failure_chunk_type[0],
        (unsigned int)analysis->failure_chunk_type[1],
        (unsigned int)analysis->failure_chunk_type[2],
        (unsigned int)analysis->failure_chunk_type[3]
    );
}

static void append_png_breakpoint_report(
    size_t absolute_offset,
    const char *stage,
    size_t total_bytes,
    size_t max_scan_bytes,
    const PngAnalysis *analysis
)
{
    char report_path[1024];
    char chunk_type_printable[8];
    char chunk_type_hex[16];
    struct stat st;
    FILE *report;
    int have_existing_file = 0;

    if (!png_breakpoint_report_enabled()) {
        (void)absolute_offset;
        (void)stage;
        (void)total_bytes;
        (void)max_scan_bytes;
        (void)analysis;
        return;
    }

    if (g_png_breakpoint_report_saturated ||
        stage == NULL ||
        analysis == NULL ||
        analysis->failure_reason == PNG_FAILURE_NONE ||
        !fs_backend_build_output_path(
            report_path,
            sizeof(report_path),
            PNG_BREAKPOINT_REPORT_NAME) ||
        !recovery_runner_ensure_parent_dirs(report_path)) {
        return;
    }

    if (stat(report_path, &st) == 0) {
        have_existing_file = 1;
        if ((uint64_t)st.st_size >= PNG_BREAKPOINT_REPORT_MAX_BYTES) {
            g_png_breakpoint_report_saturated = 1;
            return;
        }
    }

    report = fopen(report_path, "a");
    if (report == NULL) {
        return;
    }

    if (!have_existing_file || (have_existing_file && st.st_size == 0)) {
        fprintf(
            report,
            "abs_offset\tstage\treason\tchunk_type\tchunk_type_hex\tchunk_length\tfailure_offset\ttotal_bytes\tmax_scan_bytes\tfile_size\twidth\theight\tvalid_signature\tvalid_ihdr\tsaw_idat\tsaw_iend\n"
        );
    }

    png_format_chunk_type_printable(analysis, chunk_type_printable, sizeof(chunk_type_printable));
    png_format_chunk_type_hex(analysis, chunk_type_hex, sizeof(chunk_type_hex));

    fprintf(
        report,
        "%zu\t%s\t%s\t%s\t%s\t%u\t%zu\t%zu\t%zu\t%zu\t%u\t%u\t%d\t%d\t%d\t%d\n",
        absolute_offset,
        stage,
        png_failure_reason_name(analysis->failure_reason),
        chunk_type_printable,
        chunk_type_hex,
        (unsigned int)analysis->failure_chunk_length,
        analysis->failure_offset,
        total_bytes,
        max_scan_bytes,
        analysis->file_size,
        (unsigned int)analysis->width,
        (unsigned int)analysis->height,
        analysis->valid_signature,
        analysis->valid_ihdr,
        analysis->saw_idat,
        analysis->saw_iend
    );

    fclose(report);

    if (stat(report_path, &st) == 0 &&
        (uint64_t)st.st_size >= PNG_BREAKPOINT_REPORT_MAX_BYTES) {
        g_png_breakpoint_report_saturated = 1;
    }
}

static void png_low_yield_region_reset(uint64_t absolute_offset)
{
    g_png_low_yield_region.region_base =
        (absolute_offset / PNG_LOW_YIELD_REGION_BYTES) *
        PNG_LOW_YIELD_REGION_BYTES;
    g_png_low_yield_region.attempts = 0U;
    g_png_low_yield_region.recovered = 0U;
    g_png_low_yield_region.failed_no_iend = 0U;
}

static void png_low_yield_region_ensure(uint64_t absolute_offset)
{
    uint64_t region_base =
        (absolute_offset / PNG_LOW_YIELD_REGION_BYTES) *
        PNG_LOW_YIELD_REGION_BYTES;

    if (g_png_low_yield_region.region_base != region_base) {
        png_low_yield_region_reset(absolute_offset);
    }
}

static size_t png_low_yield_adjusted_max_want(
    uint64_t absolute_offset,
    size_t max_want,
    int *out_capped
)
{
    size_t capped_max = max_want;

    if (out_capped != NULL) {
        *out_capped = 0;
    }

    png_low_yield_region_ensure(absolute_offset);

    if (g_png_low_yield_region.recovered == 0U) {
        if (g_png_low_yield_region.failed_no_iend >= 16U &&
            capped_max > PNG_LOW_YIELD_STAGE3_MAX) {
            capped_max = PNG_LOW_YIELD_STAGE3_MAX;
        } else if (g_png_low_yield_region.failed_no_iend >= 8U &&
                   capped_max > PNG_LOW_YIELD_STAGE2_MAX) {
            capped_max = PNG_LOW_YIELD_STAGE2_MAX;
        } else if (g_png_low_yield_region.failed_no_iend >= 4U &&
                   capped_max > PNG_LOW_YIELD_STAGE1_MAX) {
            capped_max = PNG_LOW_YIELD_STAGE1_MAX;
        }
    }

    if (out_capped != NULL && capped_max < max_want) {
        *out_capped = 1;
    }

    return capped_max;
}

static int should_skip_small_png(
    const PngAnalysis *analysis
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

static void log_filtered_png_local(
    size_t absolute_offset,
    const PngAnalysis *analysis
)
{
    if (analysis == NULL) {
        return;
    }
    filtered_image_log_append_current(
        "raw-carver",
        "png",
        "small_image_filtered",
        (uint64_t)absolute_offset,
        0U,
        (uint64_t)analysis->file_size,
        (uint64_t)analysis->width,
        (uint64_t)analysis->height,
        NULL
    );
}

static int write_png_file(
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
        "png",
        buffer + start_offset,
        file_size
    );
}

static int png_analysis_is_complete(
    const PngAnalysis *analysis
)
{
    return analysis != NULL &&
           analysis->valid_signature &&
           analysis->valid_ihdr &&
           analysis->saw_idat &&
           analysis->saw_iend &&
           analysis->file_size >= PNG_MIN_FILE_SIZE;
}

static int png_analysis_needs_more_data(
    const PngAnalysis *analysis
)
{
    return analysis != NULL &&
           analysis->valid_signature &&
           analysis->valid_ihdr &&
           !analysis->saw_iend &&
           (analysis->failure_reason == PNG_FAILURE_TRUNCATED_CHUNK ||
            analysis->failure_reason == PNG_FAILURE_TRUNCATED_HEADER);
}

static void advance_reader_past_png_span(
    Reader *reader,
    size_t absolute_offset,
    size_t file_size,
    size_t bytes_already_buffered,
    size_t *confirmed_span_out
)
{
    uint64_t seek_offset;

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = file_size;
    }
    if (reader == NULL || file_size <= bytes_already_buffered) {
        return;
    }

    seek_offset = (uint64_t)absolute_offset + (uint64_t)file_size;
    if (!reader_seek_absolute(reader, seek_offset)) {
        return;
    }
    (void)reader_read_next(reader);
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0U;
    }
}

static int finalize_png_recovery(
    Reader *reader,
    const uint8_t *buffer,
    size_t start_offset,
    size_t buffer_length,
    size_t absolute_offset,
    const PngAnalysis *analysis,
    size_t *confirmed_span_out
)
{
    size_t bytes_already_buffered;

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0U;
    }
    if (buffer == NULL || analysis == NULL || !png_analysis_is_complete(analysis)) {
        return 0;
    }

    bytes_already_buffered =
        (start_offset < buffer_length) ? (buffer_length - start_offset) : 0U;

    if (should_skip_small_png(analysis)) {
        g_png_stats.skipped_small_image++;
        log_filtered_png_local(absolute_offset, analysis);
        advance_reader_past_png_span(
            reader,
            absolute_offset,
            analysis->file_size,
            bytes_already_buffered,
            confirmed_span_out
        );
        return 1;
    }

    if (!write_png_file(
            buffer,
            start_offset,
            analysis->file_size,
            absolute_offset)) {
        return 0;
    }

    g_png_stats.recovered_files++;
    advance_reader_past_png_span(
        reader,
        absolute_offset,
        analysis->file_size,
        bytes_already_buffered,
        confirmed_span_out
    );
    return 1;
}

static PngAnalysis analyze_png_candidate(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset
)
{
    static const uint8_t png_signature[PNG_SIGNATURE_SIZE] =
        {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    PngAnalysis result = {0};
    size_t cursor;
    int first_chunk = 1;
    int saw_plte = 0;
    int after_idat_non_idat = 0;

    if (buffer == NULL || start_offset + PNG_MIN_FILE_SIZE > buffer_length) {
        png_analysis_note_failure(
            &result,
            PNG_FAILURE_TRUNCATED_HEADER,
            start_offset,
            NULL,
            0U
        );
        return result;
    }

    if (memcmp(buffer + start_offset, png_signature, PNG_SIGNATURE_SIZE) != 0) {
        png_analysis_note_failure(
            &result,
            PNG_FAILURE_BAD_SIGNATURE,
            start_offset,
            NULL,
            0U
        );
        return result;
    }

    result.valid_signature = 1;
    cursor = start_offset + PNG_SIGNATURE_SIZE;

    while (cursor + PNG_CHUNK_HEADER_SIZE + PNG_CHUNK_CRC_SIZE <= buffer_length) {
        uint32_t chunk_length = read_u32_be_local(buffer + cursor);
        const uint8_t *chunk_type = buffer + cursor + 4;
        size_t chunk_total_size =
            PNG_CHUNK_HEADER_SIZE + (size_t)chunk_length + PNG_CHUNK_CRC_SIZE;

        if (chunk_total_size < PNG_CHUNK_HEADER_SIZE + PNG_CHUNK_CRC_SIZE) {
            png_analysis_note_failure(
                &result,
                PNG_FAILURE_CHUNK_OVERFLOW,
                cursor - start_offset,
                chunk_type,
                chunk_length
            );
            return result;
        }
        if (cursor + chunk_total_size > buffer_length) {
            png_analysis_note_failure(
                &result,
                PNG_FAILURE_TRUNCATED_CHUNK,
                cursor - start_offset,
                chunk_type,
                chunk_length
            );
            return result;
        }
        if (!png_chunk_type_is_ascii_letters(chunk_type)) {
            png_analysis_note_failure(
                &result,
                PNG_FAILURE_NON_ASCII_CHUNK,
                cursor - start_offset,
                chunk_type,
                chunk_length
            );
            return result;
        }

        if (first_chunk) {
            if (memcmp(chunk_type, "IHDR", 4) != 0 || chunk_length != 13U) {
                png_analysis_note_failure(
                    &result,
                    PNG_FAILURE_BAD_FIRST_CHUNK,
                    cursor - start_offset,
                    chunk_type,
                    chunk_length
                );
                return result;
            }

            if (!png_ihdr_fields_valid(
                    buffer + cursor + 8U,
                    &result.width,
                    &result.height)) {
                png_analysis_note_failure(
                    &result,
                    PNG_FAILURE_BAD_IHDR,
                    cursor - start_offset,
                    chunk_type,
                    chunk_length
                );
                return result;
            }
            result.valid_ihdr = 1;
            first_chunk = 0;
        } else if (memcmp(chunk_type, "IHDR", 4) == 0) {
            png_analysis_note_failure(
                &result,
                PNG_FAILURE_DUPLICATE_IHDR,
                cursor - start_offset,
                chunk_type,
                chunk_length
            );
            return result;
        } else if (memcmp(chunk_type, "PLTE", 4) == 0) {
            if (saw_plte || result.saw_idat) {
                png_analysis_note_failure(
                    &result,
                    PNG_FAILURE_BAD_PLTE_POSITION,
                    cursor - start_offset,
                    chunk_type,
                    chunk_length
                );
                return result;
            }
            saw_plte = 1;
        } else if (memcmp(chunk_type, "IDAT", 4) == 0) {
            if (after_idat_non_idat) {
                png_analysis_note_failure(
                    &result,
                    PNG_FAILURE_IDAT_AFTER_TRAILING,
                    cursor - start_offset,
                    chunk_type,
                    chunk_length
                );
                return result;
            }
            result.saw_idat = 1;
        } else if (memcmp(chunk_type, "IEND", 4) == 0) {
            if (chunk_length != 0U) {
                png_analysis_note_failure(
                    &result,
                    PNG_FAILURE_IEND_WITH_LENGTH,
                    cursor - start_offset,
                    chunk_type,
                    chunk_length
                );
                return result;
            }
            if (!result.saw_idat) {
                png_analysis_note_failure(
                    &result,
                    PNG_FAILURE_IEND_BEFORE_IDAT,
                    cursor - start_offset,
                    chunk_type,
                    chunk_length
                );
                return result;
            }
            result.saw_iend = 1;
            result.file_size = cursor + chunk_total_size - start_offset;
            return result;
        } else if (result.saw_idat) {
            if (png_chunk_is_critical(chunk_type)) {
                png_analysis_note_failure(
                    &result,
                    PNG_FAILURE_CRITICAL_AFTER_IDAT,
                    cursor - start_offset,
                    chunk_type,
                    chunk_length
                );
                return result;
            }
            after_idat_non_idat = 1;
        }

        cursor += chunk_total_size;
    }

    png_analysis_note_failure(
        &result,
        PNG_FAILURE_TRUNCATED_HEADER,
        cursor - start_offset,
        NULL,
        0U
    );

    return result;
}

int carver_png_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    PngAnalysis analysis;
    double analysis_started_at = png_now_seconds();
    int ok;

    carver_png_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0;
    }
    if (buffer == NULL || start_offset >= buffer_length) {
        carver_audit_set_inline(&g_png_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    g_png_stats.candidates_total++;

    analysis = analyze_png_candidate(buffer, buffer_length, start_offset);
    g_png_stats.seconds_total_analysis += png_now_seconds() - analysis_started_at;
    if (!png_analysis_is_complete(&analysis)) {
        append_png_breakpoint_report(
            absolute_offset,
            "buffer",
            buffer_length > start_offset ? (buffer_length - start_offset) : 0U,
            buffer_length > start_offset ? (buffer_length - start_offset) : 0U,
            &analysis
        );
        carver_audit_set_inline(
            &g_png_last_audit,
            "rejected",
            png_failure_reason_name(analysis.failure_reason),
            0U);
        return 0;
    }

    ok = finalize_png_recovery(
        NULL,
        buffer,
        start_offset,
        buffer_length,
        absolute_offset,
        &analysis,
        confirmed_span_out
    );
    carver_audit_set_inline(
        &g_png_last_audit,
        ok ? "recovered" : "rejected",
        ok ? "accepted" : "write_failed",
        ok ? analysis.file_size : 0U);
    return ok;
}

int carver_png_from_reader(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    PngAnalysis analysis;
    RawCandidateStream stream;
    size_t current_bytes;
    size_t max_want;
    size_t want;
    size_t next_want;
    size_t advanced = 0U;
    size_t total_bytes;
    int ok = 0;
    double analysis_started_at = png_now_seconds();
    double extended_started_at = 0.0;

    carver_png_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0U;
    }
    if (reader == NULL ||
        reader->buffer == NULL ||
        reader->fd < 0 ||
        start_offset >= reader->bytes_in_buffer) {
        carver_audit_set_inline(&g_png_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    g_png_stats.candidates_total++;

    analysis = analyze_png_candidate(
        reader->buffer,
        reader->bytes_in_buffer,
        start_offset
    );
    g_png_stats.seconds_total_analysis += png_now_seconds() - analysis_started_at;
    if (png_analysis_is_complete(&analysis)) {
        ok = finalize_png_recovery(
            reader,
            reader->buffer,
            start_offset,
            reader->bytes_in_buffer,
            absolute_offset,
            &analysis,
            confirmed_span_out
        );
        carver_audit_set_inline(
            &g_png_last_audit,
            ok ? "recovered" : "rejected",
            ok ? "accepted" : "write_failed",
            ok ? analysis.file_size : 0U);
        return ok;
    }

    if (!png_analysis_needs_more_data(&analysis)) {
        append_png_breakpoint_report(
            absolute_offset,
            "direct",
            reader->bytes_in_buffer > start_offset
                ? (reader->bytes_in_buffer - start_offset)
                : 0U,
            reader->bytes_in_buffer > start_offset
                ? (reader->bytes_in_buffer - start_offset)
                : 0U,
            &analysis
        );
        carver_audit_set_inline(
            &g_png_last_audit,
            "rejected",
            png_failure_reason_name(analysis.failure_reason),
            0U);
        return 0;
    }

    g_png_stats.extended_window_attempts++;
    extended_started_at = png_now_seconds();

    if (!raw_candidate_stream_init(
            &stream,
            reader,
            start_offset,
            absolute_offset,
            PNG_EXTENDED_FORWARD_SCAN_MAX)) {
        carver_audit_set_inline(&g_png_last_audit, "rejected", "stream_init_failed", 0U);
        return 0;
    }

    current_bytes = raw_candidate_stream_initial_buffer_bytes(&stream);
    want = PNG_EXTENDED_FORWARD_SCAN_INITIAL;
    if (want < current_bytes) {
        want = current_bytes;
    }
    max_want = PNG_EXTENDED_FORWARD_SCAN_MAX;
    if (max_want < want) {
        max_want = want;
    }
    {
        int region_capped = 0;

        max_want = png_low_yield_adjusted_max_want(
            (uint64_t)absolute_offset,
            max_want,
            &region_capped
        );
        if (region_capped) {
            g_png_stats.extended_window_region_capped++;
        }
    }
    if (want > max_want) {
        want = max_want;
    }
    if (raw_candidate_stream_remaining(&stream) + current_bytes < want) {
        want = raw_candidate_stream_remaining(&stream) + current_bytes;
    }
    if (raw_candidate_stream_remaining(&stream) + current_bytes < max_want) {
        max_want = raw_candidate_stream_remaining(&stream) + current_bytes;
    }
    if (want <= current_bytes) {
        raw_candidate_stream_free(&stream);
        carver_audit_set_inline(&g_png_last_audit, "rejected", "no_extended_bytes_available", 0U);
        return 0;
    }

    png_low_yield_region_ensure((uint64_t)absolute_offset);
    g_png_low_yield_region.attempts++;
    total_bytes = current_bytes;

    while (total_bytes < max_want) {
        const uint8_t *window;

        advanced = raw_candidate_stream_grow_to(&stream, want);
        total_bytes = raw_candidate_stream_size(&stream);
        window = raw_candidate_stream_data(&stream);
        analysis = analyze_png_candidate(window, total_bytes, 0U);
        if (png_analysis_is_complete(&analysis)) {
            ok = finalize_png_recovery(
                reader,
                window,
                0U,
                total_bytes,
                absolute_offset,
                &analysis,
                confirmed_span_out
            );
            if (ok) {
                g_png_stats.extended_window_recovered++;
                g_png_low_yield_region.recovered++;
            } else {
                g_png_stats.extended_window_failed_write++;
            }
            break;
        }
        if (!png_analysis_needs_more_data(&analysis)) {
            if (analysis.file_size > 0U &&
                analysis.file_size < PNG_MIN_FILE_SIZE) {
                g_png_stats.extended_window_failed_small_image++;
            } else {
                g_png_stats.extended_window_failed_other++;
            }
            append_png_breakpoint_report(
                absolute_offset,
                "extended",
                total_bytes,
                max_want,
                &analysis
            );
            break;
        }
        if (advanced == 0U || total_bytes >= max_want) {
            g_png_stats.extended_window_failed_no_iend++;
            g_png_low_yield_region.failed_no_iend++;
            append_png_breakpoint_report(
                absolute_offset,
                "extended",
                total_bytes,
                max_want,
                &analysis
            );
            break;
        }

        next_want = want;
        while (next_want <= want && next_want < max_want) {
            size_t doubled = next_want * 2U;
            if (doubled <= next_want) {
                next_want = max_want;
                break;
            }
            next_want = doubled;
        }
        if (next_want > max_want) {
            next_want = max_want;
        }
        if (next_want <= want) {
            g_png_stats.extended_window_failed_no_iend++;
            append_png_breakpoint_report(
                absolute_offset,
                "extended",
                total_bytes,
                max_want,
                &analysis
            );
            break;
        }

        {
            if (next_want > raw_candidate_stream_remaining(&stream) + total_bytes) {
                next_want = raw_candidate_stream_remaining(&stream) + total_bytes;
            }
        }
        want = next_want;
    }

    g_png_stats.seconds_extended_window += png_now_seconds() - extended_started_at;
    raw_candidate_stream_free(&stream);
    carver_audit_set_inline(
        &g_png_last_audit,
        ok ? "recovered" : "rejected",
        ok ? "extended_window" : png_failure_reason_name(analysis.failure_reason),
        ok && confirmed_span_out != NULL ? *confirmed_span_out : 0U);
    return ok;
}

void carver_png_get_stats(CarverPngStats *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    *out_stats = g_png_stats;
}

void carver_png_reset_stats(void)
{
    memset(&g_png_stats, 0, sizeof(g_png_stats));
    memset(&g_png_low_yield_region, 0, sizeof(g_png_low_yield_region));
    g_png_breakpoint_report_saturated = 0;
}
