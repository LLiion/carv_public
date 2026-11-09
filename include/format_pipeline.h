/*
 * format_pipeline.h
 * Shared format pipeline API used by both MFT-users and raw-all scan paths.
 */

#ifndef FORMAT_PIPELINE_H
#define FORMAT_PIPELINE_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"
#include "fs_backend.h"
#include "mftprobe_engine_types.h"
#include "reader.h"
#include "signature_types.h"

typedef enum {
    FORMAT_PIPELINE_CATEGORY_NONE = 0U,
    FORMAT_PIPELINE_CATEGORY_IMAGE = 1U << 0,
    FORMAT_PIPELINE_CATEGORY_VIDEO = 1U << 1,
    FORMAT_PIPELINE_CATEGORY_DOCUMENT = 1U << 2
} FormatPipelineCategoryMask;

typedef enum {
    FORMAT_PIPELINE_DISPATCH_NO_HANDLER = 0,
    FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED = 1,
    FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE = 2,
    FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME = 3
} FormatPipelineDispatchResult;

typedef struct {
    uint64_t metadata_exact_mft_attempts;
    uint64_t metadata_exact_mft_recovered;
    uint64_t metadata_exact_mft_run_truncated;
    uint64_t metadata_exact_jpeg_attempts;
    uint64_t metadata_exact_jpeg_recovered;
} FormatPipelineLiveStats;

typedef struct {
    uint32_t enabled_categories;
    uint64_t enabled_format_mask;
    uint64_t enabled_extension_mask;
    int active_order_present;
    int metadata_candidate_context_available;
    MetadataIndexCandidateContext metadata_candidate_context;
} FormatPipelineDispatchContext;

uint32_t format_pipeline_enabled_categories(const AppConfig *config);

int format_pipeline_category_enabled(
    const AppConfig *config,
    uint32_t required_mask
);

int format_pipeline_allows_metadata_stream_recovery(
    const AppConfig *config,
    const RecoveryOrder *active_order
);

int format_pipeline_recover_metadata_target(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    size_t start_offset,
    size_t absolute_offset,
    const FsViewEntry *view
);

/* Compatibility shims while callers finish the rename. */
int format_pipeline_allows_mft_stream_recovery(
    const AppConfig *config,
    const RecoveryOrder *active_order
);
int format_pipeline_recover_mft_target(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    size_t start_offset,
    size_t absolute_offset,
    const FsViewEntry *view
);

void format_pipeline_prepare_dispatch_context(
    FormatPipelineDispatchContext *context,
    const AppConfig *config,
    const RecoveryOrder *active_order
);

int format_pipeline_dispatch_context_allows_jpeg(
    const FormatPipelineDispatchContext *context
);

int format_pipeline_dispatch_context_allows_png(
    const FormatPipelineDispatchContext *context
);

int format_pipeline_dispatch_context_allows_pdf(
    const FormatPipelineDispatchContext *context
);

FormatPipelineDispatchResult format_pipeline_dispatch_raw_match_with_context(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const MagicTable *magic_table,
    const MagicEntry *match,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

FormatPipelineDispatchResult format_pipeline_dispatch_raw_match(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const MagicEntry *match,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

void format_pipeline_reset_live_stats(void);
void format_pipeline_get_live_stats(FormatPipelineLiveStats *out);

#endif
