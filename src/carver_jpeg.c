/*
 * carver_jpeg.c
 * Analyzes JPEG candidates, assigns a confidence score, and recovers
 * likely JPEG files from the current buffer.
 */

#include "carver_jpeg.h"
#include "carver_output.h"
#include "config.h"
#include "filtered_image_log.h"
#include "image_filter.h"
#include "jpeg_mpf_parser.h"
#include "log.h"
#include "app.h"
#include "fs_backend.h"
#include "jpeg_stream_probe.h"
#include "jpeg_wrapper_classifier.h"
#include "mftprobe_engine_types.h"
#include "raw_candidate_stream.h"
#include "recovery_runner.h"
#include "reader.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <setjmp.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#ifndef CARVER_HAVE_LIBJPEG
#define CARVER_HAVE_LIBJPEG 1
#endif

#if CARVER_HAVE_LIBJPEG
#include <jpeglib.h>

#define JPEG_SCORE_RECOVER_THRESHOLD 6
#define JPEG_SCORE_SUSPECT_THRESHOLD 2
#define JPEG_SCORE_STREAM_THRESHOLD 5
#define JPEG_MIN_REASONABLE_SIZE 1024U
#define JPEG_DOMINANT_SPAN_MIN_SIZE (2U * 1024U * 1024U)
#define JPEG_DOMINANT_MAX_LONG_SIDE 20000U
#define JPEG_DOMINANT_MAX_PIXELS_PER_BYTE 512U
#define JPEG_MAX_SCAN_SIZE (128U * 1024U * 1024U)
#define JPEG_MARKER_SCAN_WINDOW (64U * 1024U)
#define JPEG_LARGE_EXIF_SCAN_WINDOW_MAX (1024U * 1024U)
#define JPEG_EXTENDED_FORWARD_SCAN (64U * 1024U * 1024U)
#define JPEG_JFIF_CLUSTER_MIN_SIZE (200U * 1024U)
#define JPEG_JFIF_CLUSTER_MAX_SIZE (1024U * 1024U)
#define JPEG_JFIF_CLUSTER_WINDOW_BYTES (16U * 1024U * 1024U)
#define JPEG_JFIF_CLUSTER_TRIGGER_COUNT 4U
#define JPEG_BREAKPOINT_REPORT_NAME APP_STATE_DIR_NAME "/jpeg_breakpoints.tsv"
#define JPEG_BREAKPOINT_REPORT_MAX_BYTES (64U * 1024U * 1024U)
#define JPEG_NESTED_REVISIT_DECODE_MAX_BYTES (32U * 1024U * 1024U)

typedef struct {
    int score;
    int has_strong_header;
    int has_jfif;
    int has_exif;
    int has_large_leading_exif;
    int has_eoi;
    int has_valid_marker_layout;
    int inside_known_container;
    int has_mft_match;
    size_t eoi_offset;
    size_t estimated_size;
    size_t leading_exif_span;
    uint16_t width;
    uint16_t height;
} JpegAnalysis;

typedef struct {
    int active;
    int reported;
    uint64_t first_offset;
    uint64_t last_offset;
    size_t count;
} JpegJfifClusterState;

typedef struct {
    struct jpeg_error_mgr pub;
    jmp_buf jump_buffer;
} JpegDecodeErrorManager;

static CarverJpegStats g_jpeg_stats = {0};
static CarverJpegLastExtendedFailure g_jpeg_last_extended_failure = {0};
static CarverJpegLastDominantClaim g_jpeg_last_dominant_claim = {0};
static CarverAuditReport g_jpeg_last_audit;
static JpegJfifClusterState g_jpeg_jfif_cluster_state = {0};
static int g_jpeg_breakpoint_report_saturated = 0;

void carver_jpeg_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_jpeg_last_audit);
}

void carver_jpeg_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_jpeg_last_audit;
}

static int jpeg_breakpoint_report_enabled(void)
{
    const char *breakpoint_logs = getenv("CARV_ENABLE_IMAGE_BREAKPOINT_LOGS");
    const char *debug_logs = getenv("CARV_DEBUG_LOGS");

    return (breakpoint_logs != NULL && breakpoint_logs[0] != '\0' && breakpoint_logs[0] != '0') ||
           (debug_logs != NULL && debug_logs[0] != '\0' && debug_logs[0] != '0');
}

static int probe_current_jpeg_prefix(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    JpegStreamProbeStatus *status_out,
    JpegStreamProbeResult *result_out
);
static int jpeg_stream_result_has_plausible_prefix(
    const JpegStreamProbeResult *result
);
static void merge_stream_result_into_analysis(
    JpegAnalysis *analysis,
    const JpegStreamProbeResult *result
);
static int maybe_promote_wrapper_span(
    JpegAnalysis *analysis,
    const unsigned char *buffer,
    size_t buffer_length,
    size_t start_offset,
    JpegWrapperInfo *wrapper_info_out,
    JpegMpfInfo *mpf_info_out
);

static void clear_last_dominant_claim(void)
{
    memset(&g_jpeg_last_dominant_claim, 0, sizeof(g_jpeg_last_dominant_claim));
}

static void carver_jpeg_decode_error_exit(j_common_ptr cinfo)
{
    JpegDecodeErrorManager *error_mgr = (JpegDecodeErrorManager *)cinfo->err;

    longjmp(error_mgr->jump_buffer, 1);
}

static void carver_jpeg_decode_output_message(j_common_ptr cinfo)
{
    (void)cinfo;
}

const char *carver_jpeg_breakpoint_kind_name(int kind)
{
    switch ((JpegStreamBreakpointKind)kind) {
        case JPEG_STREAM_BREAKPOINT_NONE:
            return "none";
        case JPEG_STREAM_BREAKPOINT_PREFIX_EARLY_EOI:
            return "prefix_early_eoi";
        case JPEG_STREAM_BREAKPOINT_PREFIX_SOF_WITHOUT_SUPPORT:
            return "prefix_sof_without_support";
        case JPEG_STREAM_BREAKPOINT_PREFIX_SOS_WITHOUT_SUPPORT:
            return "prefix_sos_without_support";
        case JPEG_STREAM_BREAKPOINT_PREFIX_INVALID_SEGMENT:
            return "prefix_invalid_segment";
        case JPEG_STREAM_BREAKPOINT_ENTROPY_MARKER:
            return "entropy_marker";
        default:
            return "unknown";
    }
}

static int marker_supports_prefix_layout(uint8_t marker)
{
    return (marker >= 0xE0U && marker <= 0xEFU) ||
           marker == 0xC4U ||
           marker == 0xCCU ||
           marker == 0xDBU ||
           marker == 0xDDU ||
           marker == 0xFEU;
}

static void append_jpeg_breakpoint_report(
    size_t absolute_offset,
    size_t total_bytes,
    JpegStreamProbeStatus status,
    const JpegStreamProbeResult *result,
    const JpegAnalysis *analysis,
    int gate_complete,
    int gate_recoverable_complete
)
{
    char report_path[1024];
    struct stat st;
    FILE *report;
    int have_existing_file = 0;

    if (!jpeg_breakpoint_report_enabled()) {
        (void)absolute_offset;
        (void)total_bytes;
        (void)status;
        (void)result;
        (void)analysis;
        (void)gate_complete;
        (void)gate_recoverable_complete;
        return;
    }

    if (g_jpeg_breakpoint_report_saturated ||
        result == NULL ||
        !fs_backend_build_output_path(
            report_path,
            sizeof(report_path),
            JPEG_BREAKPOINT_REPORT_NAME) ||
        !recovery_runner_ensure_parent_dirs(report_path)) {
        return;
    }

    if (stat(report_path, &st) == 0) {
        have_existing_file = 1;
        if ((uint64_t)st.st_size >= JPEG_BREAKPOINT_REPORT_MAX_BYTES) {
            g_jpeg_breakpoint_report_saturated = 1;
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
            "abs_offset\tprobe_status\tbreakpoint_kind\tbreakpoint_marker\tfirst_marker_after_soi\tscore\tgate_complete\tgate_recoverable_complete\tgate_has_eoi\ttotal_bytes\testimated_size\terror_offset\teoi_offset\tentropy_data_bytes\twidth\theight\tsaw_exif\tsaw_jfif\tsaw_sof\tsaw_sos\tsaw_eoi\tsaw_prefix_support\tsaw_prefix_app\tsaw_prefix_table\tsaw_restart\tsaw_entropy_marker_anomaly\n"
        );
    }

    fprintf(
        report,
        "%zu\t%d\t%s\t0x%02X\t0x%02X\t%d\t%d\t%d\t%d\t%zu\t%zu\t%zu\t%zu\t%zu\t%u\t%u\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
        absolute_offset,
        (int)status,
        carver_jpeg_breakpoint_kind_name(result->breakpoint_kind),
        (unsigned int)result->breakpoint_marker,
        (unsigned int)result->first_marker_after_soi,
        analysis != NULL ? analysis->score : 0,
        gate_complete,
        gate_recoverable_complete,
        analysis != NULL ? analysis->has_eoi : 0,
        total_bytes,
        analysis != NULL ? analysis->estimated_size : 0U,
        result->error_offset,
        result->eoi_offset,
        result->entropy_data_bytes,
        (unsigned int)result->width,
        (unsigned int)result->height,
        result->saw_exif,
        result->saw_jfif,
        result->saw_sof,
        result->saw_sos,
        result->saw_eoi,
        result->saw_prefix_support_segment,
        result->saw_prefix_app_segment,
        result->saw_prefix_table_segment,
        result->saw_restart_marker,
        result->saw_entropy_marker_anomaly
    );

    fclose(report);

    if (stat(report_path, &st) == 0 &&
        (uint64_t)st.st_size >= JPEG_BREAKPOINT_REPORT_MAX_BYTES) {
        g_jpeg_breakpoint_report_saturated = 1;
    }
}

static void note_extended_failure(
    size_t absolute_offset,
    size_t total_bytes,
    JpegStreamProbeStatus status,
    const JpegStreamProbeResult *result,
    const JpegAnalysis *analysis,
    int gate_complete,
    int gate_recoverable_complete
)
{
    memset(&g_jpeg_last_extended_failure, 0, sizeof(g_jpeg_last_extended_failure));
    g_jpeg_last_extended_failure.active = 1;
    g_jpeg_last_extended_failure.probe_status = (int)status;
    g_jpeg_last_extended_failure.gate_complete = gate_complete;
    g_jpeg_last_extended_failure.gate_recoverable_complete = gate_recoverable_complete;
    g_jpeg_last_extended_failure.absolute_offset = (uint64_t)absolute_offset;
    g_jpeg_last_extended_failure.total_bytes = (uint64_t)total_bytes;
    if (analysis != NULL) {
        g_jpeg_last_extended_failure.analysis_score = analysis->score;
        g_jpeg_last_extended_failure.gate_has_eoi = analysis->has_eoi;
        g_jpeg_last_extended_failure.estimated_size = (uint64_t)analysis->estimated_size;
    }
    if (result == NULL) {
        return;
    }

    g_jpeg_last_extended_failure.error_offset = (uint64_t)result->error_offset;
    g_jpeg_last_extended_failure.eoi_offset = (uint64_t)result->eoi_offset;
    g_jpeg_last_extended_failure.entropy_data_bytes = (uint64_t)result->entropy_data_bytes;
    g_jpeg_last_extended_failure.width = result->width;
    g_jpeg_last_extended_failure.height = result->height;
    g_jpeg_last_extended_failure.breakpoint_kind = result->breakpoint_kind;
    g_jpeg_last_extended_failure.breakpoint_marker = result->breakpoint_marker;
    g_jpeg_last_extended_failure.first_marker_after_soi = result->first_marker_after_soi;
    g_jpeg_last_extended_failure.saw_exif = result->saw_exif;
    g_jpeg_last_extended_failure.saw_jfif = result->saw_jfif;
    g_jpeg_last_extended_failure.saw_sof = result->saw_sof;
    g_jpeg_last_extended_failure.saw_sos = result->saw_sos;
    g_jpeg_last_extended_failure.saw_eoi = result->saw_eoi;
    g_jpeg_last_extended_failure.saw_prefix_support_segment =
        result->saw_prefix_support_segment;
    g_jpeg_last_extended_failure.saw_prefix_app_segment =
        result->saw_prefix_app_segment;
    g_jpeg_last_extended_failure.saw_prefix_table_segment =
        result->saw_prefix_table_segment;
    g_jpeg_last_extended_failure.saw_restart_marker = result->saw_restart_marker;
    g_jpeg_last_extended_failure.saw_entropy_marker_anomaly =
        result->saw_entropy_marker_anomaly;
    append_jpeg_breakpoint_report(
        absolute_offset,
        total_bytes,
        status,
        result,
        analysis,
        gate_complete,
        gate_recoverable_complete
    );
}

static double jpeg_now_seconds(void)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0) {
        return 0.0;
    }

    return (double)tv.tv_sec + ((double)tv.tv_usec / 1000000.0);
}

static int has_jpeg_header(const uint8_t *buffer, size_t buffer_length, size_t offset)
{
    if (buffer == NULL || offset + 3 > buffer_length) {
        return 0;
    }

    return buffer[offset] == 0xFF &&
           buffer[offset + 1] == 0xD8 &&
           buffer[offset + 2] == 0xFF;
}

static uint16_t read_u16_be(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static int marker_is_start_of_frame(uint8_t marker)
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

static int marker_has_length(uint8_t marker)
{
    if (marker == 0xD8 ||
        marker == 0xD9 ||
        marker == 0x01 ||
        (marker >= 0xD0 && marker <= 0xD7)) {
        return 0;
    }

    return 1;
}

static int has_valid_marker_layout(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
)
{
    size_t cursor;
    size_t scan_end;
    int saw_sof = 0;
    int saw_support_segment = 0;

    if (buffer == NULL || offset + 4 > buffer_length) {
        return 0;
    }

    scan_end = offset + JPEG_MARKER_SCAN_WINDOW;
    if (scan_end > buffer_length) {
        scan_end = buffer_length;
    }

    cursor = offset + 2;

    while (cursor + 1 < scan_end) {
        uint8_t marker;
        uint16_t segment_length;

        while (cursor < scan_end && buffer[cursor] != 0xFF) {
            cursor++;
        }

        if (cursor + 1 >= scan_end) {
            break;
        }

        while (cursor < scan_end && buffer[cursor] == 0xFF) {
            cursor++;
        }

        if (cursor >= scan_end) {
            break;
        }

        marker = buffer[cursor++];

        if (marker == 0x00) {
            continue;
        }

        if (marker == 0xD9) {
            return 0;
        }

        if (marker == 0xDA) {
            if (!saw_sof || !saw_support_segment || cursor + 2 > scan_end) {
                return 0;
            }

            segment_length = read_u16_be(buffer + cursor);
            if (segment_length < 2 || cursor + segment_length > scan_end) {
                return 0;
            }

            return 1;
        }

        if (!marker_has_length(marker)) {
            continue;
        }

        if (cursor + 2 > scan_end) {
            return 0;
        }

        segment_length = read_u16_be(buffer + cursor);
        if (segment_length < 2 || cursor + segment_length > scan_end) {
            return 0;
        }

        if (marker_is_start_of_frame(marker)) {
            if (!saw_support_segment) {
                return 0;
            }
            saw_sof = 1;
        }

        if (marker_supports_prefix_layout(marker)) {
            saw_support_segment = 1;
        }

        cursor += segment_length;
    }

    return 0;
}

static int has_jfif_marker(const uint8_t *buffer, size_t buffer_length, size_t offset)
{
    size_t i;
    size_t max_scan;

    if (buffer == NULL || offset >= buffer_length) {
        return 0;
    }

    max_scan = offset + 32;
    if (max_scan > buffer_length) {
        max_scan = buffer_length;
    }

    for (i = offset; i + 5 <= max_scan; i++) {
        if (memcmp(buffer + i, "JFIF\0", 5) == 0) {
            return 1;
        }
    }

    return 0;
}

static int has_exif_marker(const uint8_t *buffer, size_t buffer_length, size_t offset)
{
    size_t i;
    size_t max_scan;

    if (buffer == NULL || offset >= buffer_length) {
        return 0;
    }

    max_scan = offset + 40;
    if (max_scan > buffer_length) {
        max_scan = buffer_length;
    }

    for (i = offset; i + 6 <= max_scan; i++) {
        if (memcmp(buffer + i, "Exif\0\0", 6) == 0) {
            return 1;
        }
    }

    return 0;
}

static size_t leading_exif_span(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
)
{
    size_t cursor;
    uint8_t marker;
    uint16_t segment_length;

    if (buffer == NULL || offset + 12U > buffer_length) {
        return 0U;
    }
    if (!has_jpeg_header(buffer, buffer_length, offset)) {
        return 0U;
    }

    cursor = offset + 2U;
    while (cursor < buffer_length && buffer[cursor] == 0xFFU) {
        cursor++;
    }
    if (cursor >= buffer_length) {
        return 0U;
    }

    marker = buffer[cursor++];
    if (marker != 0xE1U) {
        return 0U;
    }
    if (cursor + 2U > buffer_length) {
        return 0U;
    }

    segment_length = read_u16_be(buffer + cursor);
    if (segment_length < 8U) {
        return 0U;
    }
    if (cursor + 8U > buffer_length) {
        return 0U;
    }
    if (memcmp(buffer + cursor + 2U, "Exif\0\0", 6U) != 0) {
        return 0U;
    }

    return 2U + (size_t)segment_length;
}

static size_t jpeg_marker_scan_window_for_prefix(
    size_t base_window,
    size_t leading_exif_bytes
)
{
    size_t wanted = base_window;

    if (leading_exif_bytes >= 8U * 1024U) {
        size_t padded = leading_exif_bytes + (64U * 1024U);
        if (padded > wanted) {
            wanted = padded;
        }
    }
    if (wanted > JPEG_LARGE_EXIF_SCAN_WINDOW_MAX) {
        wanted = JPEG_LARGE_EXIF_SCAN_WINDOW_MAX;
    }
    return wanted;
}

static int find_jpeg_dimensions(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset,
    size_t max_scan_window,
    uint16_t *width_out,
    uint16_t *height_out
)
{
    size_t cursor;
    size_t scan_end;

    if (width_out != NULL) {
        *width_out = 0;
    }
    if (height_out != NULL) {
        *height_out = 0;
    }
    if (buffer == NULL || offset + 4 > buffer_length) {
        return 0;
    }

    scan_end = offset + max_scan_window;
    if (scan_end > buffer_length) {
        scan_end = buffer_length;
    }

    cursor = offset + 2;
    while (cursor + 1 < scan_end) {
        uint8_t marker;
        uint16_t segment_length;

        while (cursor < scan_end && buffer[cursor] != 0xFF) {
            cursor++;
        }

        if (cursor + 1 >= scan_end) {
            break;
        }

        while (cursor < scan_end && buffer[cursor] == 0xFF) {
            cursor++;
        }

        if (cursor >= scan_end) {
            break;
        }

        marker = buffer[cursor++];
        if (marker == 0x00) {
            continue;
        }
        if (marker == 0xD9) {
            break;
        }
        if (!marker_has_length(marker)) {
            continue;
        }

        if (cursor + 2 > scan_end) {
            return 0;
        }

        segment_length = read_u16_be(buffer + cursor);
        if (segment_length < 2 || cursor + segment_length > scan_end) {
            return 0;
        }

        if (marker_is_start_of_frame(marker)) {
            uint16_t width;
            uint16_t height;

            if (segment_length < 8U) {
                return 0;
            }

            height = read_u16_be(buffer + cursor + 3);
            width = read_u16_be(buffer + cursor + 5);
            if (width == 0 || height == 0) {
                return 0;
            }

            if (width_out != NULL) {
                *width_out = width;
            }
            if (height_out != NULL) {
                *height_out = height;
            }
            return 1;
        }

        cursor += segment_length;
    }

    return 0;
}

static int find_jpeg_dimensions_quick(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset,
    size_t leading_exif_bytes,
    uint16_t *width_out,
    uint16_t *height_out
)
{
    return find_jpeg_dimensions(
        buffer,
        buffer_length,
        offset,
        jpeg_marker_scan_window_for_prefix(4096U, leading_exif_bytes),
        width_out,
        height_out
    );
}

static int find_jpeg_eoi(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset,
    size_t *eoi_offset
)
{
    size_t scan_end;
    size_t i;
    int seen_sos = 0;

    if (buffer == NULL || eoi_offset == NULL || offset >= buffer_length) {
        return 0;
    }

    scan_end = buffer_length;
    if (offset + JPEG_MAX_SCAN_SIZE < scan_end) {
        scan_end = offset + JPEG_MAX_SCAN_SIZE;
    }

    for (i = offset + 2U; i + 1U < scan_end; i++) {
        uint8_t marker;
        size_t marker_start = i;

        if (buffer[i] != 0xFFU) {
            continue;
        }

        while (i + 1U < scan_end && buffer[i + 1U] == 0xFFU) {
            i++;
        }
        if (i + 1U >= scan_end) {
            break;
        }

        marker = buffer[i + 1U];
        if (!seen_sos) {
            if (marker == 0xDAU) {
                seen_sos = 1;
            }
            continue;
        }

        if (marker == 0x00U || marker == 0xFFU) {
            continue;
        }
        if (marker >= 0xD0U && marker <= 0xD7U) {
            continue;
        }
        if (marker == 0xD9U) {
            *eoi_offset = marker_start;
            return 1;
        }

        return 0;
    }

    return 0;
}

static int is_inside_known_container(size_t absolute_offset)
{
    (void)absolute_offset;
    return 0;
}

static int should_skip_small_jpeg(const JpegAnalysis *analysis)
{
    if (analysis == NULL) {
        return 0;
    }

    return image_filter_should_skip_image(
        analysis->width,
        analysis->height,
        analysis->estimated_size
    );
}

static void log_filtered_jpeg_local(
    size_t absolute_offset,
    const JpegAnalysis *analysis
)
{
    if (analysis == NULL) {
        return;
    }
    filtered_image_log_append_current(
        "raw-carver",
        "jpg",
        "small_image_filtered",
        (uint64_t)absolute_offset,
        0U,
        (uint64_t)analysis->estimated_size,
        (uint64_t)analysis->width,
        (uint64_t)analysis->height,
        NULL
    );
}

static JpegAnalysis analyze_jpeg_candidate(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    const JpegStreamProbeResult *stream_result
)
{
    JpegAnalysis result = {0};
    size_t eoi_offset = 0;
    size_t estimated_size = 0;
    size_t leading_exif_bytes = 0;
    size_t marker_scan_window = JPEG_MARKER_SCAN_WINDOW;
    FsScanHint mft_hint = {0};
    int has_quick_dimensions = 0;
    int marker_layout_ok;
    int has_strong_mft_match = 0;
    double analysis_start = jpeg_now_seconds();
    double marker_start;
    double dims_start;
    double eoi_start;

    g_jpeg_stats.candidates_total++;

    if (!has_jpeg_header(buffer, buffer_length, start_offset)) {
        g_jpeg_stats.rejected_no_header++;
        result.score = -100;
        g_jpeg_stats.seconds_total_analysis += jpeg_now_seconds() - analysis_start;
        return result;
    }

    result.has_strong_header = 1;
    result.score += 3;

    leading_exif_bytes = leading_exif_span(buffer, buffer_length, start_offset);
    result.leading_exif_span = leading_exif_bytes;
    if (leading_exif_bytes >= 16U * 1024U) {
        result.has_large_leading_exif = 1;
        result.score += 2;
        if (leading_exif_bytes >= 32U * 1024U) {
            result.score += 1;
        }
    }
    marker_scan_window = jpeg_marker_scan_window_for_prefix(
        JPEG_MARKER_SCAN_WINDOW,
        leading_exif_bytes
    );

    g_jpeg_stats.marker_layout_checks++;
    marker_start = jpeg_now_seconds();
    marker_layout_ok = has_valid_marker_layout(
        buffer,
        buffer_length > start_offset + marker_scan_window
            ? start_offset + marker_scan_window
            : buffer_length,
        start_offset
    );
    g_jpeg_stats.seconds_marker_layout += jpeg_now_seconds() - marker_start;
    if (marker_layout_ok) {
        g_jpeg_stats.marker_layout_successes++;
        result.has_valid_marker_layout = 1;
        result.score += 2;
    } else {
        result.score -= 4;
    }

    if (has_jfif_marker(buffer, buffer_length, start_offset)) {
        result.has_jfif = 1;
        result.score += 3;
    }

    if (has_exif_marker(buffer, buffer_length, start_offset)) {
        result.has_exif = 1;
        result.score += 3;
    }

    dims_start = jpeg_now_seconds();
    has_quick_dimensions = find_jpeg_dimensions_quick(
        buffer,
        buffer_length,
        start_offset,
        leading_exif_bytes,
        &result.width,
        &result.height
    );
    g_jpeg_stats.seconds_dimensions += jpeg_now_seconds() - dims_start;
    if (has_quick_dimensions) {
        g_jpeg_stats.early_dimensions_ok++;
    }

    if (fs_backend_lookup_scan_hint((long long)absolute_offset, &mft_hint)) {
        if (mft_hint.exact_data_match || mft_hint.inside_resident_record) {
            result.has_mft_match = 1;
            has_strong_mft_match = 1;

            if (mft_hint.exact_data_match) {
                result.score += 2;
            }
            if (mft_hint.inside_resident_record) {
                result.score += 1;
            }
        }
    }

    merge_stream_result_into_analysis(&result, stream_result);

    if (!result.has_jfif &&
        !result.has_exif &&
        !has_strong_mft_match &&
        !has_quick_dimensions) {
        g_jpeg_stats.rejected_weak_early++;
        result.score -= 4;
        g_jpeg_stats.seconds_total_analysis += jpeg_now_seconds() - analysis_start;
        return result;
    }

    if (!has_quick_dimensions) {
        dims_start = jpeg_now_seconds();
        if (find_jpeg_dimensions(
            buffer,
            buffer_length,
            start_offset,
            marker_scan_window,
            &result.width,
            &result.height
        )) {
            g_jpeg_stats.full_dimensions_ok++;
        }
        g_jpeg_stats.seconds_dimensions += jpeg_now_seconds() - dims_start;
    }

    if (result.width != 0 &&
        result.height != 0 &&
        should_skip_small_jpeg(&result)) {
        g_jpeg_stats.rejected_small_image++;
        log_filtered_jpeg_local(absolute_offset, &result);
        result.score -= 10;
        g_jpeg_stats.seconds_total_analysis += jpeg_now_seconds() - analysis_start;
        return result;
    }

    if (!result.has_valid_marker_layout &&
        !result.has_jfif &&
        !result.has_exif &&
        !has_strong_mft_match &&
        result.width == 0 &&
        result.height == 0) {
        g_jpeg_stats.rejected_weak_early++;
        result.score -= 3;
        g_jpeg_stats.seconds_total_analysis += jpeg_now_seconds() - analysis_start;
        return result;
    }

    if (!result.has_valid_marker_layout &&
        !result.has_jfif &&
        !result.has_exif &&
        !has_strong_mft_match &&
        (result.width == 0 || result.height == 0)) {
        g_jpeg_stats.rejected_weak_early++;
        result.score -= 2;
        g_jpeg_stats.seconds_total_analysis += jpeg_now_seconds() - analysis_start;
        return result;
    }

    eoi_start = jpeg_now_seconds();
    if (!result.has_eoi && stream_result == NULL) {
        if (find_jpeg_eoi(buffer, buffer_length, start_offset, &eoi_offset)) {
            g_jpeg_stats.eoi_found++;
            result.has_eoi = 1;
            result.eoi_offset = eoi_offset;
            estimated_size = (eoi_offset + 2) - start_offset;
            result.estimated_size = estimated_size;
            result.score += 3;

            if (estimated_size < JPEG_MIN_REASONABLE_SIZE) {
                result.score -= 3;
            } else if (estimated_size >= 1024 && estimated_size <= (50 * 1024 * 1024)) {
                result.score += 2;
            } else if (estimated_size > (200 * 1024 * 1024)) {
                result.score -= 2;
            }
        } else {
            result.score -= 3;
        }
    }
    g_jpeg_stats.seconds_eoi += jpeg_now_seconds() - eoi_start;

    (void)maybe_promote_wrapper_span(
        &result,
        buffer,
        buffer_length,
        start_offset,
        NULL,
        NULL
    );

    if (is_inside_known_container(absolute_offset)) {
        result.inside_known_container = 1;
        result.score -= 5;
    }

    g_jpeg_stats.seconds_total_analysis += jpeg_now_seconds() - analysis_start;
    return result;
}

static int write_jpeg_file(
    const uint8_t *buffer,
    size_t start_offset,
    size_t file_size,
    size_t absolute_offset,
    const JpegAnalysis *analysis
)
{
    if (analysis != NULL &&
        analysis->has_jfif &&
        !analysis->has_exif &&
        !analysis->has_large_leading_exif &&
        !analysis->inside_known_container &&
        !analysis->has_mft_match &&
        analysis->estimated_size >= JPEG_JFIF_CLUSTER_MIN_SIZE &&
        analysis->estimated_size <= JPEG_JFIF_CLUSTER_MAX_SIZE &&
        analysis->width >= 2000U &&
        analysis->height >= 2000U) {
        uint64_t abs64 = (uint64_t)absolute_offset;

        if (!g_jpeg_jfif_cluster_state.active ||
            abs64 > g_jpeg_jfif_cluster_state.last_offset + JPEG_JFIF_CLUSTER_WINDOW_BYTES) {
            memset(&g_jpeg_jfif_cluster_state, 0, sizeof(g_jpeg_jfif_cluster_state));
            g_jpeg_jfif_cluster_state.active = 1;
            g_jpeg_jfif_cluster_state.first_offset = abs64;
            g_jpeg_jfif_cluster_state.last_offset = abs64;
            g_jpeg_jfif_cluster_state.count = 1U;
        } else {
            g_jpeg_jfif_cluster_state.last_offset = abs64;
            g_jpeg_jfif_cluster_state.count++;
        }

        if (g_jpeg_jfif_cluster_state.count >= JPEG_JFIF_CLUSTER_TRIGGER_COUNT) {
            if (!g_jpeg_jfif_cluster_state.reported) {
                log_info(
                    "Dense JFIF-only JPEG cluster observed: start=%llu count=%zu window=%.1f MiB",
                    (unsigned long long)g_jpeg_jfif_cluster_state.first_offset,
                    g_jpeg_jfif_cluster_state.count,
                    (double)(g_jpeg_jfif_cluster_state.last_offset -
                             g_jpeg_jfif_cluster_state.first_offset) /
                        (1024.0 * 1024.0)
                );
                g_jpeg_jfif_cluster_state.reported = 1;
            }
        }
    }

    return carver_output_write_buffer(
        (long long)absolute_offset,
        APP_DEFAULT_UNIDENT_DIR,
        "recov",
        "jpg",
        buffer + start_offset,
        file_size
    );
}

static void advance_reader_past_recovered_span(
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

static int finalize_jpeg_recovery_internal(
    Reader *reader,
    const uint8_t *buffer,
    size_t start_offset,
    size_t bytes_already_buffered,
    size_t absolute_offset,
    const JpegAnalysis *analysis,
    size_t *confirmed_span_out
)
{
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0U;
    }
    if (buffer == NULL || analysis == NULL || !analysis->has_eoi ||
        analysis->estimated_size < JPEG_MIN_REASONABLE_SIZE) {
        return 0;
    }

    if (should_skip_small_jpeg(analysis)) {
        g_jpeg_stats.rejected_small_image++;
        log_filtered_jpeg_local(absolute_offset, analysis);
        advance_reader_past_recovered_span(
            reader,
            absolute_offset,
            analysis->estimated_size,
            bytes_already_buffered,
            confirmed_span_out
        );
        return 1;
    }

    if (!write_jpeg_file(
            buffer,
            start_offset,
            analysis->estimated_size,
            absolute_offset,
            analysis)) {
        return 0;
    }

    g_jpeg_stats.recovered_files++;
    advance_reader_past_recovered_span(
        reader,
        absolute_offset,
        analysis->estimated_size,
        bytes_already_buffered,
        confirmed_span_out
    );
    return 1;
}

static int finalize_jpeg_recovery(
    Reader *reader,
    const uint8_t *buffer,
    size_t start_offset,
    size_t buffer_length,
    size_t absolute_offset,
    const JpegAnalysis *analysis,
    size_t *confirmed_span_out
)
{
    size_t bytes_already_buffered =
        (start_offset < buffer_length) ? (buffer_length - start_offset) : 0U;

    return finalize_jpeg_recovery_internal(
        reader,
        buffer,
        start_offset,
        bytes_already_buffered,
        absolute_offset,
        analysis,
        confirmed_span_out
    );
}

static int should_try_extended_jpeg_window(const JpegAnalysis *analysis)
{
    if (analysis == NULL) {
        return 0;
    }
    if (analysis->has_eoi || analysis->inside_known_container) {
        return 0;
    }
    if (!analysis->has_strong_header) {
        return 0;
    }
    if (analysis->score < JPEG_SCORE_STREAM_THRESHOLD) {
        return analysis->has_large_leading_exif ? 1 : 0;
    }
    if (!analysis->has_valid_marker_layout &&
        !analysis->has_jfif &&
        !analysis->has_exif &&
        !analysis->has_mft_match) {
        return analysis->has_large_leading_exif ? 1 : 0;
    }
    return 1;
}

static int jpeg_large_candidate_dimensions_reasonable(
    uint32_t width,
    uint32_t height,
    uint64_t file_size
)
{
    uint64_t long_side;
    uint64_t pixels;

    if (width == 0U || height == 0U || file_size == 0U) {
        return 0;
    }
    if (image_filter_is_below_min_dimensions(width, height)) {
        return 0;
    }

    long_side = width >= height ? width : height;
    if (long_side > JPEG_DOMINANT_MAX_LONG_SIDE) {
        return 0;
    }

    pixels = (uint64_t)width * (uint64_t)height;
    if (height != 0U && pixels / (uint64_t)height != (uint64_t)width) {
        return 0;
    }
    if (pixels > file_size * JPEG_DOMINANT_MAX_PIXELS_PER_BYTE) {
        return 0;
    }

    return 1;
}

static int jpeg_revisit_dimensions_reasonable(
    uint32_t width,
    uint32_t height
)
{
    uint64_t long_side;
    uint64_t pixels;

    if (width == 0U || height == 0U) {
        return 0;
    }
    if (image_filter_is_below_min_dimensions(width, height)) {
        return 0;
    }

    long_side = width >= height ? width : height;
    if (long_side > JPEG_DOMINANT_MAX_LONG_SIDE) {
        return 0;
    }

    pixels = (uint64_t)width * (uint64_t)height;
    if (height != 0U && pixels / (uint64_t)height != (uint64_t)width) {
        return 0;
    }

    return 1;
}

static void note_dominant_claim_revisits(
    size_t absolute_offset,
    size_t dominant_span,
    const uint8_t *buffer,
    size_t buffer_length
)
{
    size_t scan_limit;
    size_t rel;
    uint64_t last_added = 0U;

    clear_last_dominant_claim();
    if (buffer == NULL || buffer_length == 0U || dominant_span == 0U) {
        return;
    }

    g_jpeg_last_dominant_claim.active = 1;
    g_jpeg_last_dominant_claim.absolute_offset = (uint64_t)absolute_offset;
    g_jpeg_last_dominant_claim.claimed_span = (uint64_t)dominant_span;

    scan_limit = dominant_span;
    if (scan_limit > buffer_length) {
        scan_limit = buffer_length;
    }
    if (scan_limit <= 4U) {
        return;
    }

    for (rel = 1U; rel + 3U < scan_limit; rel++) {
        uint16_t width = 0U;
        uint16_t height = 0U;
        uint64_t revisit_abs;

        if (!has_jpeg_header(buffer, scan_limit, rel)) {
            continue;
        }
        if (!has_valid_marker_layout(buffer, scan_limit, rel)) {
            continue;
        }
        if (!find_jpeg_dimensions(
                buffer,
                scan_limit,
                rel,
                JPEG_MARKER_SCAN_WINDOW,
                &width,
                &height)) {
            continue;
        }
        if (!jpeg_revisit_dimensions_reasonable(width, height)) {
            continue;
        }

        revisit_abs = (uint64_t)absolute_offset + (uint64_t)rel;
        if (g_jpeg_last_dominant_claim.revisit_count > 0U &&
            revisit_abs <= last_added + 4096U) {
            continue;
        }
        if (g_jpeg_last_dominant_claim.revisit_count >=
            CARVER_JPEG_MAX_DOMINANT_REVISITS) {
            g_jpeg_last_dominant_claim.revisit_overflow = 1;
            break;
        }

        g_jpeg_last_dominant_claim
            .revisit_offsets[g_jpeg_last_dominant_claim.revisit_count++] =
            revisit_abs;
        last_added = revisit_abs;
    }
}

static int note_nested_large_exif_revisits(
    size_t absolute_offset,
    size_t claimed_span,
    const uint8_t *buffer,
    size_t buffer_length
)
{
    size_t scan_limit;
    size_t rel;
    uint64_t last_added = 0U;

    clear_last_dominant_claim();
    if (buffer == NULL || buffer_length <= 4U || claimed_span == 0U) {
        return 0;
    }

    scan_limit = claimed_span;
    if (scan_limit > buffer_length) {
        scan_limit = buffer_length;
    }
    if (scan_limit <= 4U) {
        return 0;
    }

    g_jpeg_last_dominant_claim.active = 1;
    g_jpeg_last_dominant_claim.absolute_offset = (uint64_t)absolute_offset;
    g_jpeg_last_dominant_claim.claimed_span = (uint64_t)claimed_span;

    for (rel = 1U; rel + 4U <= scan_limit; rel++) {
        size_t exif_span = 0U;
        uint64_t revisit_abs;
        JpegStreamProbeResult stream_result = {0};

        if (buffer[rel] != 0xFFU ||
            buffer[rel + 1U] != 0xD8U ||
            buffer[rel + 2U] != 0xFFU ||
            buffer[rel + 3U] != 0xE1U) {
            continue;
        }
        if (!carver_jpeg_has_large_leading_exif(
                buffer,
                scan_limit,
                rel,
                &exif_span)) {
            continue;
        }
        if (!probe_current_jpeg_prefix(
                buffer,
                scan_limit,
                rel,
                NULL,
                &stream_result)) {
            continue;
        }
        if (!jpeg_stream_result_has_plausible_prefix(&stream_result)) {
            continue;
        }

        revisit_abs = (uint64_t)absolute_offset + (uint64_t)rel;
        if (g_jpeg_last_dominant_claim.revisit_count > 0U &&
            revisit_abs <= last_added + 4096U) {
            continue;
        }
        if (g_jpeg_last_dominant_claim.revisit_count >=
            CARVER_JPEG_MAX_DOMINANT_REVISITS) {
            g_jpeg_last_dominant_claim.revisit_overflow = 1;
            break;
        }

        g_jpeg_last_dominant_claim
            .revisit_offsets[g_jpeg_last_dominant_claim.revisit_count++] =
            revisit_abs;
        last_added = revisit_abs;

        if (exif_span > 4U) {
            rel += exif_span - 4U;
        }
    }

    return g_jpeg_last_dominant_claim.revisit_count > 0U;
}

static int jpeg_candidate_fully_decodes(
    const uint8_t *data,
    size_t size
)
{
    struct jpeg_decompress_struct cinfo;
    JpegDecodeErrorManager error_mgr;
    JSAMPARRAY scanline = NULL;
    volatile unsigned decoded_rows = 0U;
    volatile unsigned output_height = 0U;

    if (data == NULL ||
        size < JPEG_MIN_REASONABLE_SIZE ||
        size > JPEG_NESTED_REVISIT_DECODE_MAX_BYTES) {
        return 0;
    }

    memset(&cinfo, 0, sizeof(cinfo));
    cinfo.err = jpeg_std_error(&error_mgr.pub);
    error_mgr.pub.error_exit = carver_jpeg_decode_error_exit;
    error_mgr.pub.output_message = carver_jpeg_decode_output_message;

    if (setjmp(error_mgr.jump_buffer) != 0) {
        decoded_rows = cinfo.output_scanline;
        output_height = cinfo.output_height;
        jpeg_destroy_decompress(&cinfo);
        return output_height > 0U && decoded_rows == output_height;
    }

    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, (unsigned char *)data, size);
    (void)jpeg_read_header(&cinfo, TRUE);
    (void)jpeg_start_decompress(&cinfo);
    output_height = cinfo.output_height;

    scanline = (*cinfo.mem->alloc_sarray)(
        (j_common_ptr)&cinfo,
        JPOOL_IMAGE,
        cinfo.output_width * cinfo.output_components,
        1
    );

    while (cinfo.output_scanline < cinfo.output_height) {
        if (jpeg_read_scanlines(&cinfo, scanline, 1) != 1U) {
            break;
        }
        decoded_rows = cinfo.output_scanline;
    }

    (void)jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
    return output_height > 0U && decoded_rows == output_height;
}

static int probe_current_jpeg_prefix(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    JpegStreamProbeStatus *status_out,
    JpegStreamProbeResult *result_out
)
{
    JpegStreamProbe probe;
    size_t length;
    JpegStreamProbeStatus status;
    const JpegStreamProbeResult *result;

    if (status_out != NULL) {
        *status_out = JPEG_STREAM_PROBE_INVALID;
    }
    if (result_out != NULL) {
        memset(result_out, 0, sizeof(*result_out));
    }
    if (buffer == NULL || start_offset >= buffer_length) {
        return 0;
    }

    length = buffer_length - start_offset;
    if (length == 0U) {
        return 0;
    }

    jpeg_stream_probe_init(&probe);
    if (!jpeg_stream_probe_append(&probe, buffer + start_offset, length)) {
        jpeg_stream_probe_free(&probe);
        return 0;
    }

    status = jpeg_stream_probe_status(&probe);
    result = jpeg_stream_probe_result(&probe);
    if (status_out != NULL) {
        *status_out = status;
    }
    if (result_out != NULL && result != NULL) {
        *result_out = *result;
    }

    jpeg_stream_probe_free(&probe);
    return 1;
}

static int jpeg_stream_result_has_plausible_prefix(
    const JpegStreamProbeResult *result
)
{
    if (result == NULL) {
        return 0;
    }

    if (!result->saw_soi || !result->saw_sof || !result->saw_sos) {
        return 0;
    }
    if (!result->saw_prefix_support_segment) {
        return 0;
    }
    if (result->width == 0U || result->height == 0U) {
        return 0;
    }
    if (image_filter_is_below_min_dimensions(result->width, result->height)) {
        return 0;
    }

    return 1;
}

static int jpeg_stream_result_is_recoverable_complete(
    const JpegStreamProbeResult *result
)
{
    size_t file_size;

    if (!jpeg_stream_result_has_plausible_prefix(result) ||
        result == NULL ||
        !result->saw_eoi) {
        return 0;
    }
    if (result->saw_entropy_marker_anomaly) {
        return 0;
    }

    file_size = result->eoi_offset + 2U;
    if (file_size < JPEG_MIN_REASONABLE_SIZE) {
        return 0;
    }
    if (image_filter_is_below_min_file_size(file_size)) {
        return 0;
    }

    return 1;
}

static int jpeg_analysis_should_claim_dominant_span(
    const JpegAnalysis *analysis,
    JpegStreamProbeStatus status,
    const JpegStreamProbeResult *result
)
{
    if (analysis == NULL || result == NULL) {
        return 0;
    }
    if (status != JPEG_STREAM_PROBE_COMPLETE) {
        return 0;
    }
    if (!jpeg_stream_result_is_recoverable_complete(result)) {
        return 0;
    }
    if (analysis->estimated_size < JPEG_DOMINANT_SPAN_MIN_SIZE) {
        return 0;
    }
    if (!jpeg_large_candidate_dimensions_reasonable(
            result->width,
            result->height,
            (uint64_t)(result->eoi_offset + 2U))) {
        return 0;
    }

    return 1;
}

static size_t jpeg_estimate_lead_span(
    const JpegAnalysis *analysis,
    const JpegStreamProbeResult *result,
    size_t total_bytes
)
{
    uint32_t width = 0U;
    uint32_t height = 0U;
    uint64_t pixels;
    uint64_t span;

    if (analysis != NULL) {
        width = analysis->width;
        height = analysis->height;
    }
    if (result != NULL && result->width != 0U && result->height != 0U) {
        width = result->width;
        height = result->height;
    }
    if (!jpeg_revisit_dimensions_reasonable(width, height)) {
        return 0U;
    }

    pixels = (uint64_t)width * (uint64_t)height;
    if (height != 0U && pixels / (uint64_t)height != (uint64_t)width) {
        return 0U;
    }

    span = pixels / 2U;
    if (analysis != NULL && analysis->has_exif) {
        span += 512U * 1024U;
    }
    if (span < (4U * 1024U * 1024U)) {
        span = 4U * 1024U * 1024U;
    }
    if (span > (16U * 1024U * 1024U)) {
        span = 16U * 1024U * 1024U;
    }

    if (analysis != NULL &&
        analysis->estimated_size >= JPEG_MIN_REASONABLE_SIZE &&
        analysis->estimated_size < span) {
        span = analysis->estimated_size;
    }
    if (result != NULL &&
        result->saw_eoi &&
        result->eoi_offset + 2U > span &&
        result->eoi_offset + 2U <= JPEG_MAX_SCAN_SIZE) {
        span = result->eoi_offset + 2U;
    }
    (void)total_bytes;

    return (size_t)span;
}

static int jpeg_analysis_should_claim_lead_span(
    const JpegAnalysis *analysis,
    JpegStreamProbeStatus status,
    const JpegStreamProbeResult *result
)
{
    uint32_t width = 0U;
    uint32_t height = 0U;

    if (analysis == NULL) {
        return 0;
    }
    if (analysis->inside_known_container) {
        return 0;
    }
    if (!analysis->has_valid_marker_layout) {
        if (!analysis->has_large_leading_exif) {
            return 0;
        }
    }
    if (!analysis->has_exif &&
        !analysis->has_jfif &&
        !analysis->has_mft_match) {
        return 0;
    }
    if (analysis->score < JPEG_SCORE_STREAM_THRESHOLD) {
        if (!analysis->has_large_leading_exif) {
            return 0;
        }
    }

    width = analysis->width;
    height = analysis->height;
    if (result != NULL && result->width != 0U && result->height != 0U) {
        width = result->width;
        height = result->height;
    }
    if (!jpeg_revisit_dimensions_reasonable(width, height)) {
        if (!analysis->has_large_leading_exif) {
            return 0;
        }
    }
    if (status == JPEG_STREAM_PROBE_INVALID) {
        return 0;
    }
    if (result != NULL &&
        !jpeg_stream_result_has_plausible_prefix(result) &&
        (result->width == 0U || result->height == 0U)) {
        if (!analysis->has_large_leading_exif) {
            return 0;
        }
    }

    return 1;
}

static void merge_stream_result_into_analysis(
    JpegAnalysis *analysis,
    const JpegStreamProbeResult *result
)
{
    size_t file_size;

    if (analysis == NULL || !jpeg_stream_result_has_plausible_prefix(result)) {
        return;
    }

    analysis->has_strong_header = 1;
    analysis->has_valid_marker_layout = 1;
    if (result->saw_jfif) {
        analysis->has_jfif = 1;
    }
    if (result->saw_exif) {
        analysis->has_exif = 1;
    }
    if (analysis->width == 0U) {
        analysis->width = result->width;
    }
    if (analysis->height == 0U) {
        analysis->height = result->height;
    }
    if (analysis->score < JPEG_SCORE_STREAM_THRESHOLD) {
        analysis->score = JPEG_SCORE_STREAM_THRESHOLD;
    }

    if (!result->saw_eoi) {
        return;
    }
    if (!jpeg_stream_result_is_recoverable_complete(result)) {
        return;
    }

    file_size = result->eoi_offset + 2U;
    analysis->has_eoi = 1;
    analysis->eoi_offset = result->eoi_offset;
    analysis->estimated_size = file_size;
    if (analysis->score < JPEG_SCORE_RECOVER_THRESHOLD) {
        analysis->score = JPEG_SCORE_RECOVER_THRESHOLD;
    }
}

static int maybe_promote_wrapper_span(
    JpegAnalysis *analysis,
    const unsigned char *buffer,
    size_t buffer_length,
    size_t start_offset,
    JpegWrapperInfo *wrapper_info_out,
    JpegMpfInfo *mpf_info_out
)
{
    JpegWrapperInfo wrapper_info;
    JpegMpfInfo mpf_info;
    int promoted = 0;
    size_t wrapper_length;

    jpeg_wrapper_info_init(&wrapper_info);
    jpeg_mpf_info_init(&mpf_info);
    if (wrapper_info_out != NULL) {
        *wrapper_info_out = wrapper_info;
    }
    if (mpf_info_out != NULL) {
        *mpf_info_out = mpf_info;
    }

    if (analysis == NULL ||
        buffer == NULL ||
        start_offset >= buffer_length ||
        !analysis->has_eoi ||
        analysis->estimated_size < JPEG_MIN_REASONABLE_SIZE) {
        return 0;
    }

    wrapper_length = buffer_length - start_offset;
    if (wrapper_length == 0U || wrapper_length > JPEG_MAX_SCAN_SIZE) {
        return 0;
    }

    (void)jpeg_wrapper_classify(buffer + start_offset, wrapper_length, &wrapper_info);
    (void)jpeg_mpf_parse(buffer + start_offset, wrapper_length, &mpf_info);

    if (wrapper_info_out != NULL) {
        *wrapper_info_out = wrapper_info;
    }
    if (mpf_info_out != NULL) {
        *mpf_info_out = mpf_info;
    }

    if (mpf_info.valid &&
        mpf_info.wrapper_end_offset > analysis->estimated_size &&
        mpf_info.wrapper_end_offset <= wrapper_length) {
        analysis->has_eoi = 1;
        analysis->eoi_offset = start_offset + mpf_info.wrapper_end_offset - 2U;
        analysis->estimated_size = mpf_info.wrapper_end_offset;
        if (analysis->score < JPEG_SCORE_RECOVER_THRESHOLD) {
            analysis->score = JPEG_SCORE_RECOVER_THRESHOLD;
        }
        promoted = 1;
    }

    return promoted;
}

static int carver_jpeg_try_extended_window(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    JpegAnalysis analysis;
    JpegWrapperInfo wrapper_info;
    JpegMpfInfo mpf_info;
    JpegStreamProbe probe;
    RawCandidateStream stream;
    const unsigned char *window = NULL;
    const JpegStreamProbeResult *probe_result = NULL;
    size_t current_bytes;
    size_t total_bytes = 0U;
    size_t chunk_size;
    size_t got;
    size_t grown_to_wrapper = 0U;
    size_t dominant_span = 0U;
    size_t lead_span = 0U;
    int gate_complete = 0;
    int gate_recoverable_complete = 0;
    int ok = 0;
    double started_at = jpeg_now_seconds();

    if (reader == NULL ||
        reader->buffer == NULL ||
        reader->fd < 0 ||
        start_offset >= reader->bytes_in_buffer) {
        return 0;
    }

    g_jpeg_stats.extended_window_attempts++;
    jpeg_stream_probe_init(&probe);
    if (!raw_candidate_stream_init(
            &stream,
            reader,
            start_offset,
            absolute_offset,
            JPEG_MAX_SCAN_SIZE)) {
        jpeg_stream_probe_free(&probe);
        return 0;
    }

    current_bytes = raw_candidate_stream_initial_buffer_bytes(&stream);
    if (!jpeg_stream_probe_append(
            &probe,
            raw_candidate_stream_data(&stream),
            current_bytes)) {
        raw_candidate_stream_free(&stream);
        jpeg_stream_probe_free(&probe);
        return 0;
    }
    total_bytes = current_bytes;

    chunk_size = recovery_runner_default_read_size();
    while (jpeg_stream_probe_status(&probe) == JPEG_STREAM_PROBE_NEED_MORE &&
           raw_candidate_stream_remaining(&stream) > 0U) {
        const unsigned char *stream_bytes;
        size_t before = total_bytes;

        got = raw_candidate_stream_read_some(&stream, chunk_size);
        if (got == 0U) {
            break;
        }
        stream_bytes = raw_candidate_stream_data(&stream);
        total_bytes = raw_candidate_stream_size(&stream);
        if (stream_bytes == NULL || total_bytes < before + got) {
            raw_candidate_stream_free(&stream);
            jpeg_stream_probe_free(&probe);
            return 0;
        }
        if (!jpeg_stream_probe_append(&probe, stream_bytes + before, got)) {
            raw_candidate_stream_free(&stream);
            jpeg_stream_probe_free(&probe);
            return 0;
        }
    }

    window = jpeg_stream_probe_data(&probe, &total_bytes);
    probe_result = jpeg_stream_probe_result(&probe);
    analysis = analyze_jpeg_candidate(
        window,
        total_bytes,
        0U,
        absolute_offset,
        probe_result
    );
    jpeg_wrapper_info_init(&wrapper_info);
    jpeg_mpf_info_init(&mpf_info);
    if (window != NULL && total_bytes > 0U) {
        (void)maybe_promote_wrapper_span(
            &analysis,
            window,
            total_bytes,
            0U,
            &wrapper_info,
            &mpf_info
        );
    }
    if (mpf_info.valid &&
        mpf_info.wrapper_end_offset > total_bytes &&
        mpf_info.wrapper_end_offset <= JPEG_MAX_SCAN_SIZE) {
        grown_to_wrapper = raw_candidate_stream_grow_to(
            &stream,
            mpf_info.wrapper_end_offset
        );
        if (grown_to_wrapper > 0U) {
            window = raw_candidate_stream_data(&stream);
            total_bytes = raw_candidate_stream_size(&stream);
            analysis = analyze_jpeg_candidate(
                window,
                total_bytes,
                0U,
                absolute_offset,
                probe_result
            );
            jpeg_wrapper_info_init(&wrapper_info);
            jpeg_mpf_info_init(&mpf_info);
            if (window != NULL && total_bytes > 0U) {
                (void)maybe_promote_wrapper_span(
                    &analysis,
                    window,
                    total_bytes,
                    0U,
                    &wrapper_info,
                    &mpf_info
                );
            }
        }
    }
    gate_complete = (jpeg_stream_probe_status(&probe) == JPEG_STREAM_PROBE_COMPLETE);
    gate_recoverable_complete =
        jpeg_stream_result_is_recoverable_complete(probe_result);
    if (jpeg_analysis_should_claim_dominant_span(
            &analysis,
            jpeg_stream_probe_status(&probe),
            probe_result)) {
        dominant_span = analysis.estimated_size;
    } else if (jpeg_analysis_should_claim_lead_span(
                   &analysis,
                   jpeg_stream_probe_status(&probe),
                   probe_result)) {
        lead_span = jpeg_estimate_lead_span(&analysis, probe_result, total_bytes);
    }

    if (gate_complete &&
        gate_recoverable_complete &&
        analysis.score >= JPEG_SCORE_RECOVER_THRESHOLD &&
        analysis.has_eoi &&
        analysis.estimated_size >= JPEG_MIN_REASONABLE_SIZE) {
        if (analysis.has_large_leading_exif &&
            wrapper_info.wrapper_class != JPEG_WRAPPER_CLASS_UNKNOWN &&
            wrapper_info.wrapper_class != JPEG_WRAPPER_CLASS_LARGE_EXIF &&
            wrapper_info.wrapper_class != JPEG_WRAPPER_CLASS_SIMPLE) {
            log_info(
                "JPEG wrapper classified: abs=%zu class=%s soi=%u sos=%u eoi=%u mpf=%d first_eoi=%zu second_soi=%zu last_eoi=%zu",
                absolute_offset,
                jpeg_wrapper_class_name(wrapper_info.wrapper_class),
                wrapper_info.soi_count,
                wrapper_info.sos_count,
                wrapper_info.eoi_count,
                wrapper_info.has_mpf_app2,
                wrapper_info.first_eoi_offset,
                wrapper_info.second_soi_offset == SIZE_MAX ? 0U : wrapper_info.second_soi_offset,
                wrapper_info.last_eoi_offset
            );
            if (mpf_info.valid) {
                log_info(
                    "JPEG MPF wrapper: abs=%zu images=%u wrapper_end=%zu primary_end=%zu",
                    absolute_offset,
                    mpf_info.image_count,
                    mpf_info.wrapper_end_offset,
                    wrapper_info.first_eoi_offset + 2U
                );
            }
        }
        ok = finalize_jpeg_recovery_internal(
            reader,
            window,
            0U,
            total_bytes,
            absolute_offset,
            &analysis,
            confirmed_span_out
        );
        if (ok) {
            g_jpeg_stats.extended_window_recovered++;
            g_jpeg_stats.extended_window_probe_recovered++;
        } else {
            g_jpeg_stats.extended_window_failed_write++;
            note_extended_failure(
                absolute_offset,
                total_bytes,
                jpeg_stream_probe_status(&probe),
                probe_result,
                &analysis,
                gate_complete,
                gate_recoverable_complete
            );
        }
    } else if (dominant_span > 0U || lead_span > 0U) {
        size_t claimed_span = dominant_span > 0U ? dominant_span : lead_span;

        if (confirmed_span_out != NULL) {
            *confirmed_span_out = claimed_span;
        }
        note_dominant_claim_revisits(
            absolute_offset,
            claimed_span,
            window,
            total_bytes
        );
        g_jpeg_stats.extended_window_claimed_dominant_span++;
        log_verbose(
            "JPEG lead claim: abs=%zu span=%.1f MiB score=%d dims=%ux%u exif=%d jfif=%d status=%d",
            absolute_offset,
            (double)claimed_span / (1024.0 * 1024.0),
            analysis.score,
            (unsigned int)(probe_result != NULL && probe_result->width != 0U
                ? probe_result->width : analysis.width),
            (unsigned int)(probe_result != NULL && probe_result->height != 0U
                ? probe_result->height : analysis.height),
            analysis.has_exif,
            analysis.has_jfif,
            (int)jpeg_stream_probe_status(&probe)
        );
        ok = 1;
    } else if (jpeg_stream_probe_status(&probe) == JPEG_STREAM_PROBE_INVALID) {
        g_jpeg_stats.extended_window_failed_other++;
        note_extended_failure(
            absolute_offset,
            total_bytes,
            jpeg_stream_probe_status(&probe),
            probe_result,
            &analysis,
            gate_complete,
            gate_recoverable_complete
        );
    } else if (!analysis.has_eoi) {
        g_jpeg_stats.extended_window_failed_no_eoi++;
        note_extended_failure(
            absolute_offset,
            total_bytes,
            jpeg_stream_probe_status(&probe),
            probe_result,
            &analysis,
            gate_complete,
            gate_recoverable_complete
        );
    } else if (analysis.estimated_size < JPEG_MIN_REASONABLE_SIZE) {
        g_jpeg_stats.extended_window_failed_small_image++;
        note_extended_failure(
            absolute_offset,
            total_bytes,
            jpeg_stream_probe_status(&probe),
            probe_result,
            &analysis,
            gate_complete,
            gate_recoverable_complete
        );
    } else {
        g_jpeg_stats.extended_window_failed_other++;
        note_extended_failure(
            absolute_offset,
            total_bytes,
            jpeg_stream_probe_status(&probe),
            probe_result,
            &analysis,
            gate_complete,
            gate_recoverable_complete
        );
    }

    g_jpeg_stats.seconds_extended_window += jpeg_now_seconds() - started_at;
    raw_candidate_stream_free(&stream);
    jpeg_stream_probe_free(&probe);
    return ok;
}

static int mft_view_runs_are_stream_contiguous(const FsViewEntry *view)
{
    size_t i;
    uint64_t expected_offset;
    uint64_t available = 0;

    if (view == NULL ||
        view->run_count == 0 ||
        view->run_truncated ||
        view->abs_offset < 0 ||
        view->data_size == 0) {
        return 0;
    }

    expected_offset = (uint64_t)view->abs_offset;
    for (i = 0; i < view->run_count; i++) {
        if (view->runs[i].abs_offset != expected_offset ||
            view->runs[i].byte_length == 0) {
            return 0;
        }

        available += view->runs[i].byte_length;
        expected_offset += view->runs[i].byte_length;
    }

    return available >= view->data_size;
}

static int build_recovery_target_from_view(
    const FsViewEntry *view,
    size_t absolute_offset,
    const char *output_path,
    RecoveryTarget *out_target
)
{
    size_t run_index;

    if (view == NULL ||
        output_path == NULL ||
        output_path[0] == '\0' ||
        out_target == NULL ||
        view->run_count == 0U ||
        view->data_size == 0U) {
        return 0;
    }

    memset(out_target, 0, sizeof(*out_target));
    out_target->validator_id = RECOVERY_VALIDATOR_JPEG;
    out_target->abs_offset = (uint64_t)absolute_offset;
    out_target->size = view->data_size;
    out_target->expected_size = view->data_size;
    out_target->remaining = view->data_size;
    out_target->record = 0;
    out_target->family = 0U;
    out_target->run_truncated = view->run_truncated != 0;
    out_target->blob_start[0] = 0xFFU;
    out_target->blob_start[1] = 0xD8U;
    out_target->blob_start[2] = 0xFFU;
    out_target->blob_start_length = 3U;
    snprintf(out_target->extension, sizeof(out_target->extension), "%s", "jpg");
    snprintf(
        out_target->source_path,
        sizeof(out_target->source_path),
        "%s",
        (view->path[0] != '\0') ? view->path : view->name
    );
    snprintf(out_target->output_path, sizeof(out_target->output_path), "%s", output_path);

    for (run_index = 0; run_index < view->run_count; run_index++) {
        if (view->runs[run_index].byte_length == 0U) {
            return 0;
        }
        out_target->runs[out_target->run_count].abs_offset = view->runs[run_index].abs_offset;
        out_target->runs[out_target->run_count].byte_length = view->runs[run_index].byte_length;
        out_target->run_count++;
    }

    return out_target->run_count > 0U;
}

int carver_jpeg_from_mft_stream(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    const FsViewEntry *view
)
{
    char output_path[1024];
    RecoveryTarget target;
    CarverOutput output = {0};
    uint64_t remaining;
    int first_chunk = 1;

    if (reader == NULL ||
        view == NULL ||
        view->abs_offset != (long long)absolute_offset ||
        start_offset >= reader->bytes_in_buffer ||
        view->run_count == 0U ||
        view->data_size == 0U) {
        return 0;
    }

    if (!mft_view_runs_are_stream_contiguous(view)) {
        unsigned char *repair_buffer = NULL;
        size_t repair_buffer_size = recovery_runner_default_read_size();
        int ok;

        if (reader->fd < 0 ||
            !fs_backend_build_recovered_output_path(
                output_path,
                sizeof(output_path),
                (long long)absolute_offset,
                APP_DEFAULT_UNIDENT_DIR,
                "recov",
                "jpg") ||
            !build_recovery_target_from_view(
                view,
                absolute_offset,
                output_path,
                &target)) {
            return 0;
        }

        repair_buffer = (unsigned char *)malloc(repair_buffer_size);
        if (repair_buffer == NULL) {
            return 0;
        }

        ok = recovery_runner_recover_target_best_effort_fd(
                reader->fd,
                &target,
                repair_buffer,
                repair_buffer_size,
                app_stop_requested);
        free(repair_buffer);
        if (!ok) {
            return 0;
        }

        (void)fs_backend_apply_output_owner_to_path(output_path);
        (void)fs_backend_apply_created_time_to_path(output_path, (long long)absolute_offset);
        fs_backend_note_recovered_output(output_path, (long long)absolute_offset);
        return 1;
    }

    if (!carver_output_open(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "jpg")) {
        log_error("Failed to prepare JPEG output");
        return 0;
    }

    remaining = view->data_size;
    while (remaining > 0) {
        size_t write_offset;
        size_t available;

        if (first_chunk) {
            write_offset = start_offset;
            first_chunk = 0;
        } else {
            if (reader_read_next(reader) == 0) {
                carver_output_abort(&output);
                return 0;
            }
            write_offset = reader->overlap_bytes;
        }

        if (write_offset >= reader->bytes_in_buffer) {
            carver_output_abort(&output);
            return 0;
        }

        available = reader->bytes_in_buffer - write_offset;
        if ((uint64_t)available > remaining) {
            available = (size_t)remaining;
        }

        if (fwrite(reader->buffer + write_offset, 1, available, output.file) != available) {
            carver_output_abort(&output);
            return 0;
        }

        remaining -= available;
    }

    return carver_output_finish(&output);
}

int carver_jpeg_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    JpegAnalysis analysis;
    JpegStreamProbeResult stream_result = {0};
    int have_stream_result = 0;
    int ok;

    carver_jpeg_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0;
    }
    clear_last_dominant_claim();

    if (buffer == NULL || start_offset >= buffer_length) {
        carver_audit_set_inline(&g_jpeg_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    have_stream_result = probe_current_jpeg_prefix(
        buffer,
        buffer_length,
        start_offset,
        NULL,
        &stream_result
    );

    analysis = analyze_jpeg_candidate(
        buffer,
        buffer_length,
        start_offset,
        absolute_offset,
        have_stream_result ? &stream_result : NULL
    );

   /* if (analysis.score >= JPEG_SCORE_SUSPECT_THRESHOLD) {
        log_info(
            "JPEG candidate at offset %zu: score=%d header=%d layout=%d jfif=%d exif=%d eoi=%d inside_container=%d mft_match=%d size=%zu",
            absolute_offset,
            analysis.score,
            analysis.has_strong_header,
            analysis.has_valid_marker_layout,
            analysis.has_jfif,
            analysis.has_exif,
            analysis.has_eoi,
            analysis.inside_known_container,
            analysis.has_mft_match,
            analysis.estimated_size
        );
    }*/

    if (analysis.score < JPEG_SCORE_RECOVER_THRESHOLD) {
        g_jpeg_stats.rejected_low_score++;
        carver_audit_set_inline(&g_jpeg_last_audit, "rejected", "low_score", 0U);
        return 0;
    }

    if (!analysis.has_eoi ||
        analysis.estimated_size < JPEG_MIN_REASONABLE_SIZE) {
        g_jpeg_stats.rejected_missing_eoi++;
        carver_audit_set_inline(&g_jpeg_last_audit, "rejected", "missing_eoi_or_too_small", 0U);
        return 0;
    }

    ok = finalize_jpeg_recovery(
        NULL,
        buffer,
        start_offset,
        buffer_length,
        absolute_offset,
        &analysis,
        confirmed_span_out
    );
    carver_audit_set_inline(
        &g_jpeg_last_audit,
        ok ? "recovered" : "rejected",
        ok ? "accepted" : "write_failed",
        ok ? analysis.estimated_size : 0U);
    return ok;
}

int carver_jpeg_from_reader(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    JpegAnalysis analysis;
    JpegStreamProbeResult stream_result = {0};
    int stream_prefix_plausible = 0;
    int have_stream_result = 0;
    int nested_large_exif_revisits = 0;
    int ok;

    carver_jpeg_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0U;
    }
    clear_last_dominant_claim();
    if (reader == NULL ||
        reader->buffer == NULL ||
        start_offset >= reader->bytes_in_buffer) {
        carver_audit_set_inline(&g_jpeg_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    have_stream_result = probe_current_jpeg_prefix(
        reader->buffer,
        reader->bytes_in_buffer,
        start_offset,
        NULL,
        &stream_result
    );
    analysis = analyze_jpeg_candidate(
        reader->buffer,
        reader->bytes_in_buffer,
        start_offset,
        absolute_offset,
        have_stream_result ? &stream_result : NULL
    );

    if (analysis.has_large_leading_exif &&
        analysis.has_eoi &&
        analysis.estimated_size >= JPEG_MIN_REASONABLE_SIZE &&
        analysis.estimated_size <= reader->bytes_in_buffer - start_offset) {
        nested_large_exif_revisits = note_nested_large_exif_revisits(
            absolute_offset,
            analysis.estimated_size,
            reader->buffer + start_offset,
            reader->bytes_in_buffer - start_offset);
    }

    if (nested_large_exif_revisits &&
        g_jpeg_last_dominant_claim.revisit_count > 0U &&
        g_jpeg_last_dominant_claim.revisit_offsets[0] > (uint64_t)absolute_offset &&
        (g_jpeg_last_dominant_claim.revisit_offsets[0] - (uint64_t)absolute_offset) <
            (uint64_t)analysis.leading_exif_span) {
        if (confirmed_span_out != NULL) {
            *confirmed_span_out = analysis.estimated_size;
        }
        carver_audit_set_inline(
            &g_jpeg_last_audit,
            "skipped",
            "nested_exif_revisit_claim",
            analysis.estimated_size);
        log_info(
            "JPEG nested Exif-inside-Exif handoff: abs=%zu span=%.1f MiB revisit=%u%s",
            absolute_offset,
            (double)analysis.estimated_size / (1024.0 * 1024.0),
            g_jpeg_last_dominant_claim.revisit_count,
            g_jpeg_last_dominant_claim.revisit_overflow ? "+" : ""
        );
        return 1;
    }

    if (nested_large_exif_revisits &&
        !jpeg_candidate_fully_decodes(
            reader->buffer + start_offset,
            analysis.estimated_size)) {
        if (confirmed_span_out != NULL) {
            *confirmed_span_out = analysis.estimated_size;
        }
        carver_audit_set_inline(
            &g_jpeg_last_audit,
            "skipped",
            "nested_exif_handoff",
            analysis.estimated_size);
        log_info(
            "JPEG nested Exif handoff: abs=%zu span=%.1f MiB revisit=%u%s",
            absolute_offset,
            (double)analysis.estimated_size / (1024.0 * 1024.0),
            g_jpeg_last_dominant_claim.revisit_count,
            g_jpeg_last_dominant_claim.revisit_overflow ? "+" : ""
        );
        return 1;
    }

    if (have_stream_result &&
        analysis.has_large_leading_exif &&
        analysis.has_eoi &&
        analysis.estimated_size >= JPEG_MIN_REASONABLE_SIZE &&
        !jpeg_stream_result_is_recoverable_complete(&stream_result) &&
        nested_large_exif_revisits) {
        if (confirmed_span_out != NULL) {
            *confirmed_span_out = analysis.estimated_size;
        }
        carver_audit_set_inline(
            &g_jpeg_last_audit,
            "skipped",
            "nested_exif_revisit_claim",
            analysis.estimated_size);
        log_info(
            "JPEG nested Exif revisit claim: abs=%zu span=%.1f MiB revisit=%u%s",
            absolute_offset,
            (double)analysis.estimated_size / (1024.0 * 1024.0),
            g_jpeg_last_dominant_claim.revisit_count,
            g_jpeg_last_dominant_claim.revisit_overflow ? "+" : ""
        );
        return 1;
    }

    if (analysis.score >= JPEG_SCORE_RECOVER_THRESHOLD &&
        analysis.has_eoi &&
        analysis.estimated_size >= JPEG_MIN_REASONABLE_SIZE) {
        ok = finalize_jpeg_recovery(
            reader,
            reader->buffer,
            start_offset,
            reader->bytes_in_buffer,
            absolute_offset,
            &analysis,
            confirmed_span_out
        );
        carver_audit_set_inline(
            &g_jpeg_last_audit,
            ok ? "recovered" : "rejected",
            ok ? "accepted" : "write_failed",
            ok ? analysis.estimated_size : 0U);
        return ok;
    }

    if (analysis.score < JPEG_SCORE_RECOVER_THRESHOLD ||
        !analysis.has_eoi ||
        analysis.estimated_size < JPEG_MIN_REASONABLE_SIZE) {
        if (have_stream_result) {
            stream_prefix_plausible =
                jpeg_stream_result_has_plausible_prefix(&stream_result);
        }
        if (stream_prefix_plausible) {
            g_jpeg_stats.extended_window_probe_plausible++;
        }
    }

    if (analysis.score < JPEG_SCORE_RECOVER_THRESHOLD) {
        if (analysis.has_large_leading_exif) {
            log_info(
                "JPEG large Exif lead: abs=%zu exif_span=%zu score=%d layout=%d dims=%ux%u eoi=%d",
                absolute_offset,
                analysis.leading_exif_span,
                analysis.score,
                analysis.has_valid_marker_layout,
                (unsigned int)analysis.width,
                (unsigned int)analysis.height,
                analysis.has_eoi
            );
        }
        if ((should_try_extended_jpeg_window(&analysis) || stream_prefix_plausible) &&
            carver_jpeg_try_extended_window(
                reader,
                start_offset,
                absolute_offset,
                confirmed_span_out)) {
            carver_audit_set_inline(
                &g_jpeg_last_audit,
                "recovered",
                "extended_window",
                confirmed_span_out != NULL ? *confirmed_span_out : 0U);
            return 1;
        }
        g_jpeg_stats.rejected_low_score++;
        carver_audit_set_inline(&g_jpeg_last_audit, "rejected", "low_score", 0U);
        return 0;
    }

    if (!analysis.has_eoi ||
        analysis.estimated_size < JPEG_MIN_REASONABLE_SIZE) {
        if (analysis.has_large_leading_exif) {
            log_info(
                "JPEG large Exif lead: abs=%zu exif_span=%zu score=%d layout=%d dims=%ux%u eoi=%d",
                absolute_offset,
                analysis.leading_exif_span,
                analysis.score,
                analysis.has_valid_marker_layout,
                (unsigned int)analysis.width,
                (unsigned int)analysis.height,
                analysis.has_eoi
            );
        }
        if ((should_try_extended_jpeg_window(&analysis) || stream_prefix_plausible) &&
            carver_jpeg_try_extended_window(
                reader,
                start_offset,
                absolute_offset,
                confirmed_span_out)) {
            carver_audit_set_inline(
                &g_jpeg_last_audit,
                "recovered",
                "extended_window",
                confirmed_span_out != NULL ? *confirmed_span_out : 0U);
            return 1;
        }
        g_jpeg_stats.rejected_missing_eoi++;
        carver_audit_set_inline(&g_jpeg_last_audit, "rejected", "missing_eoi_or_too_small", 0U);
        return 0;
    }

    ok = finalize_jpeg_recovery(
        reader,
        reader->buffer,
        start_offset,
        reader->bytes_in_buffer,
        absolute_offset,
        &analysis,
        confirmed_span_out
    );
    carver_audit_set_inline(
        &g_jpeg_last_audit,
        ok ? "recovered" : "rejected",
        ok ? "accepted" : "write_failed",
        ok ? analysis.estimated_size : 0U);
    return ok;
}

void carver_jpeg_reset_stats(void)
{
    memset(&g_jpeg_stats, 0, sizeof(g_jpeg_stats));
    memset(&g_jpeg_last_extended_failure, 0, sizeof(g_jpeg_last_extended_failure));
    g_jpeg_breakpoint_report_saturated = 0;
}

void carver_jpeg_get_stats(CarverJpegStats *out_stats)
{
    if (out_stats == NULL) {
        return;
    }

    *out_stats = g_jpeg_stats;
}

int carver_jpeg_has_large_leading_exif(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t *exif_span_out
)
{
    size_t span;

    if (exif_span_out != NULL) {
        *exif_span_out = 0U;
    }
    if (buffer == NULL || start_offset >= buffer_length) {
        return 0;
    }

    span = leading_exif_span(buffer, buffer_length, start_offset);
    if (exif_span_out != NULL) {
        *exif_span_out = span;
    }
    return span >= 16U * 1024U;
}

void carver_jpeg_get_last_extended_failure(CarverJpegLastExtendedFailure *out_failure)
{
    if (out_failure == NULL) {
        return;
    }

    *out_failure = g_jpeg_last_extended_failure;
}

void carver_jpeg_get_last_dominant_claim(CarverJpegLastDominantClaim *out_claim)
{
    if (out_claim == NULL) {
        return;
    }

    *out_claim = g_jpeg_last_dominant_claim;
}
#else
static void log_libjpeg_unavailable_once(void)
{
    static int warned = 0;

    if (!warned) {
        warned = 1;
        log_info(
            "Built without libjpeg; JPEG recovery is disabled in this binary. Install libjpeg-dev and rebuild to enable it."
        );
    }
}

int carver_jpeg_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    (void)buffer;
    (void)buffer_length;
    (void)start_offset;
    (void)absolute_offset;
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0U;
    }
    log_libjpeg_unavailable_once();
    return 0;
}

int carver_jpeg_from_reader(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    (void)reader;
    (void)start_offset;
    (void)absolute_offset;
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0U;
    }
    log_libjpeg_unavailable_once();
    return 0;
}

int carver_jpeg_from_mft_stream(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    const FsViewEntry *view
)
{
    (void)reader;
    (void)start_offset;
    (void)absolute_offset;
    (void)view;
    log_libjpeg_unavailable_once();
    return 0;
}

int carver_jpeg_has_large_leading_exif(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t *exif_span_out
)
{
    (void)buffer;
    (void)buffer_length;
    (void)start_offset;
    if (exif_span_out != NULL) {
        *exif_span_out = 0U;
    }
    return 0;
}

void carver_jpeg_reset_stats(void)
{
}

void carver_jpeg_get_stats(CarverJpegStats *out_stats)
{
    if (out_stats == NULL) {
        return;
    }

    memset(out_stats, 0, sizeof(*out_stats));
}

void carver_jpeg_get_last_extended_failure(CarverJpegLastExtendedFailure *out_failure)
{
    if (out_failure == NULL) {
        return;
    }

    memset(out_failure, 0, sizeof(*out_failure));
}

void carver_jpeg_get_last_dominant_claim(CarverJpegLastDominantClaim *out_claim)
{
    if (out_claim == NULL) {
        return;
    }

    memset(out_claim, 0, sizeof(*out_claim));
}

const char *carver_jpeg_breakpoint_kind_name(int kind)
{
    (void)kind;
    return "libjpeg_unavailable";
}
#endif
