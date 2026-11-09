/*
 * carver_jpeg.h
 * Analyzes JPEG candidates and recovers likely JPEG files from a buffer.
 */

#ifndef CARVER_JPEG_H
#define CARVER_JPEG_H

#include <stddef.h>
#include <stdint.h>

#include "carver_audit.h"
#include "fs_backend.h"
#include "reader.h"

typedef struct {
    uint64_t candidates_total;
    uint64_t rejected_no_header;
    uint64_t rejected_weak_early;
    uint64_t rejected_small_image;
    uint64_t rejected_low_score;
    uint64_t rejected_missing_eoi;
    uint64_t recovered_files;
    uint64_t skipped_by_mft_context;
    uint64_t early_dimensions_ok;
    uint64_t full_dimensions_ok;
    uint64_t eoi_found;
    uint64_t marker_layout_checks;
    uint64_t marker_layout_successes;
    uint64_t extended_window_attempts;
    uint64_t extended_window_recovered;
    uint64_t extended_window_claimed_dominant_span;
    uint64_t extended_window_probe_plausible;
    uint64_t extended_window_probe_recovered;
    uint64_t extended_window_failed_no_eoi;
    uint64_t extended_window_failed_small_image;
    uint64_t extended_window_failed_write;
    uint64_t extended_window_failed_other;
    double seconds_total_analysis;
    double seconds_marker_layout;
    double seconds_dimensions;
    double seconds_eoi;
    double seconds_extended_window;
} CarverJpegStats;

typedef struct {
    int active;
    int probe_status;
    int analysis_score;
    int gate_complete;
    int gate_recoverable_complete;
    int gate_has_eoi;
    uint64_t absolute_offset;
    uint64_t total_bytes;
    uint64_t estimated_size;
    uint64_t error_offset;
    uint64_t eoi_offset;
    uint64_t entropy_data_bytes;
    uint32_t width;
    uint32_t height;
    int breakpoint_kind;
    int breakpoint_marker;
    int first_marker_after_soi;
    int saw_exif;
    int saw_jfif;
    int saw_sof;
    int saw_sos;
    int saw_eoi;
    int saw_prefix_support_segment;
    int saw_prefix_app_segment;
    int saw_prefix_table_segment;
    int saw_restart_marker;
    int saw_entropy_marker_anomaly;
} CarverJpegLastExtendedFailure;

#define CARVER_JPEG_MAX_DOMINANT_REVISITS 64U

typedef struct {
    int active;
    uint64_t absolute_offset;
    uint64_t claimed_span;
    uint32_t revisit_count;
    int revisit_overflow;
    uint64_t revisit_offsets[CARVER_JPEG_MAX_DOMINANT_REVISITS];
} CarverJpegLastDominantClaim;

int carver_jpeg_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
);

int carver_jpeg_from_reader(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
);

int carver_jpeg_from_mft_stream(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    const FsViewEntry *view
);

int carver_jpeg_has_large_leading_exif(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t *exif_span_out
);

void carver_jpeg_reset_stats(void);
void carver_jpeg_get_stats(CarverJpegStats *out_stats);
void carver_jpeg_get_last_extended_failure(CarverJpegLastExtendedFailure *out_failure);
void carver_jpeg_get_last_dominant_claim(CarverJpegLastDominantClaim *out_claim);
void carver_jpeg_reset_last_audit(void);
void carver_jpeg_get_last_audit(CarverAuditReport *out);
const char *carver_jpeg_breakpoint_kind_name(int kind);

#endif
