#ifndef CARVER_PNG_H
#define CARVER_PNG_H

#include <stddef.h>
#include <stdint.h>

#include "carver_audit.h"
#include "reader.h"

typedef struct {
    uint64_t candidates_total;
    uint64_t recovered_files;
    uint64_t skipped_small_image;
    uint64_t skipped_by_mft_context;
    uint64_t extended_window_attempts;
    uint64_t extended_window_recovered;
    uint64_t extended_window_failed_no_iend;
    uint64_t extended_window_failed_small_image;
    uint64_t extended_window_failed_write;
    uint64_t extended_window_failed_other;
    uint64_t extended_window_region_capped;
    double seconds_total_analysis;
    double seconds_extended_window;
} CarverPngStats;

int carver_png_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
);

int carver_png_from_reader(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
);

void carver_png_get_stats(CarverPngStats *out_stats);
void carver_png_reset_stats(void);
void carver_png_reset_last_audit(void);
void carver_png_get_last_audit(CarverAuditReport *out);

#endif
