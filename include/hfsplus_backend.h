#ifndef HFSPLUS_BACKEND_H
#define HFSPLUS_BACKEND_H

#include "mft_spool.h"
#include "mft_types.h"
#include "metadata_index.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>

typedef struct {
    uint64_t source_size;
    uint64_t container_offset;
    uint64_t volume_offset;
    uint64_t volume_size;
    uint64_t catalog_logical_size;
    uint64_t volume_uuid;
    uint32_t block_size;
    uint32_t total_blocks;
    uint32_t catalog_total_blocks;
    uint32_t attributes;
    uint32_t journal_info_block;
    uint32_t modify_date_hfs;
    uint32_t write_count;
    int has_wrapper;
    int is_hfsx;
} HfsPlusBackendGeometry;

void hfsplus_backend_reset(void);
void hfsplus_backend_set_output_dir(const char *output_dir);
void hfsplus_backend_set_compact_metadata_preferred(int enabled);
void hfsplus_backend_set_active_formats(const char *formats_csv);
void hfsplus_backend_set_assemble_all_catalog_files(int enabled);
int hfsplus_backend_configure_from_source(const char *input_path);
int hfsplus_backend_has_geometry(void);
const char *hfsplus_backend_source_hint(void);
const HfsPlusBackendGeometry *hfsplus_backend_current_geometry(void);
int hfsplus_backend_supports_root_folder_preview(void);
int hfsplus_backend_list_root_folders(const char *input_path, FILE *out_stream);
int hfsplus_backend_list_child_folders(
    const char *input_path,
    const char *parent_path,
    FILE *out_stream
);
int hfsplus_backend_run_selected_tree(
    const char *input_path,
    const char *root_scope_csv,
    int quick_resume,
    size_t *out_recovered_count
);
int hfsplus_backend_run_metadata_jpeg_test(
    const char *input_path,
    const char *out_dir,
    size_t max_files,
    size_t *out_recovered_count
);
int hfsplus_backend_write_selected_tree_ddrescue_domain(
    const char *input_path,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
);
size_t hfsplus_backend_entry_count(void);
int hfsplus_backend_prepare_index(void);
int hfsplus_backend_finalize_index(void);
int hfsplus_backend_should_attempt_metadata_acquisition(int phase);
int hfsplus_backend_run_metadata_acquisition(int phase);
int hfsplus_backend_load_recovered_output_state(void);
const char *hfsplus_backend_lookup_path_by_offset(long long abs_offset);
time_t hfsplus_backend_lookup_created_time_by_offset(long long abs_offset);
int hfsplus_backend_lookup_scan_hint(long long abs_offset, MftScanHint *out);
const char *hfsplus_backend_lookup_container_label_by_offset(long long abs_offset);
int hfsplus_backend_get_view_entry_by_offset(long long abs_offset, MftViewEntry *out);
size_t hfsplus_backend_collect_view_entries_in_range(
    long long range_start,
    long long range_end,
    MftViewEntry **out_entries
);
int hfsplus_backend_build_recovered_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
void hfsplus_backend_note_recovered_output(const char *path, long long abs_offset);
int hfsplus_backend_get_recovered_output_info(
    long long abs_offset,
    char *out_path,
    size_t out_path_size,
    int *out_reconciled
);
void hfsplus_backend_get_live_stats(MftSpoolLiveStats *out);
size_t hfsplus_backend_recovered_output_count(void);
size_t hfsplus_backend_named_output_count(void);
size_t hfsplus_backend_unreconciled_output_count(void);
int hfsplus_backend_is_offset_fully_recovered(long long abs_offset);
int hfsplus_backend_finalize_recovered_outputs(void);
void hfsplus_backend_set_finalize_opportunistic_budget_seconds(
    double seconds,
    const char *profile_label
);
void hfsplus_backend_refresh_recovery_state(size_t *entry_count_snapshot);
void hfsplus_backend_reconcile_recovered_outputs_live(void);
void hfsplus_backend_set_background_conservative(int enabled);
int hfsplus_backend_background_is_conservative(void);
void hfsplus_backend_note_foreground_activity(void);
void hfsplus_backend_observe_sequential_bytes(
    uint64_t range_start,
    const unsigned char *bytes,
    size_t byte_count
);
void hfsplus_backend_finish_sequential_measurement(int completed_full_scan);
int hfsplus_backend_range_has_trusted_metadata_owner(
    uint64_t range_start,
    uint64_t range_end
);
int hfsplus_backend_get_candidate_context(
    uint64_t physical_offset,
    MetadataIndexCandidateContext *context_out
);

#endif
