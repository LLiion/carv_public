#ifndef MFT_ENGINE_H
#define MFT_ENGINE_H

#include "mft_types.h"
#include "mft.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

typedef struct MftprobePartialNtfsSource MftprobePartialNtfsSource;

typedef enum {
    MFT_ENGINE_STATUS_NONE = 0,
    MFT_ENGINE_STATUS_OK,
    MFT_ENGINE_STATUS_FAILED,
    MFT_ENGINE_STATUS_INTERRUPTED
} MftEngineStatus;

typedef struct {
    const char *categories_csv;
    const char *formats_csv;
    const char *dev_format;
    const char *compare_scope_csv;
    const char *record_list_path;
    const char *root_scope_csv;
    int root_scope_defaulted;
    const char *date_filter_value;
    const char *deleted_filter_value;
    int folder_levels;
    uint64_t start_offset;
    int start_offset_explicit;
    int generic_file_targets;
} MftEngineUsersOptions;

typedef struct {
    const char *output_dir;
    const char *service_id;
    const char *active_formats_csv;
    MftContextualOutputMode contextual_output_mode;
    int reset_existing_store;
    int recover_img;
    int recover_vid;
    int recover_doc;
    int has_deleted_filter;
    int deleted_value;
    int include_recycle_bin_with_live_filter;
    int has_date_filter;
    int date_start_yyyymmdd;
    int date_end_yyyymmdd;
    int force_ntfs_target;
} MftEngineConfig;

void mft_engine_configure(const MftEngineConfig *config);
void mft_engine_prepare_background_child(void);
int mft_engine_configure_from_source(const char *input_path);
int mft_engine_source_is_definitely_non_ntfs(void);
const char *mft_engine_source_filesystem_hint(void);
size_t mft_engine_record_size(void);
void mft_engine_set_partial_record_salvage(int enabled);
void mft_engine_set_salvage_first_sector_confirmed_bytes(size_t bytes);
void mft_engine_set_catalog_first_mode(int enabled);
void mft_engine_set_name_trace_enabled(int enabled);
void mft_engine_set_finalize_opportunistic_budget_seconds(
    double seconds,
    const char *profile_label
);
void mft_engine_emit_i30_name_trace_sample(size_t limit);
void mft_engine_reset_record_salvage_stats(void);
void mft_engine_get_record_salvage_stats(MftRecordSalvageStats *out_stats);
int mft_engine_preview_recovered_output_match(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    MftRecoveredMatchKind *out_kind
);
int mft_engine_collect_recovered_output_match_signals(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    MftRecoveredMatchSignals *out_signals
);
void mft_engine_get_name_uniqueness_stats(MftNameUniquenessStats *out_stats);
int mft_engine_get_name_candidate_index_stats(MftNameCandidateIndexStats *out_stats);
int mft_engine_write_name_candidate_index(MftNameCandidateIndexStats *out_stats);
int mft_engine_write_name_match_preview(MftNameMatchPreviewStats *out_stats);

size_t mft_engine_observe_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset,
    int allow_unaligned
);
int mft_engine_refresh_record_at(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t absolute_offset,
    size_t buffer_offset
);
int mft_engine_record_offset_is_naming_ready(uint64_t absolute_offset);
size_t mft_engine_collect_partial_metadata_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
);
size_t mft_engine_collect_parent_chain_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
);
size_t mft_engine_collect_name_detail_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
);
size_t mft_engine_collect_i30_scan_targets(
    MftI30ScanTarget *out_targets,
    size_t out_capacity,
    uint64_t max_total_bytes
);
size_t mft_engine_absorb_i30_index_buffer(
    const MftI30ScanTarget *target,
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_engine_absorb_usn_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_engine_absorb_lnk_dlt_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_engine_absorb_windows_search_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_engine_absorb_vss_evidence_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_engine_refresh_i30_names_from_source(
    const char *source_path,
    uint64_t max_total_bytes,
    size_t max_target_count,
    uint64_t *out_bytes_scanned
);
size_t mft_engine_i30_name_count(void);

int mft_engine_load_resume_artifacts(void);
int mft_engine_load_finalize_resume_artifacts(void);
int mft_engine_load_name_resume_artifacts(void);
int mft_engine_load_recovered_output_state(void);
int mft_engine_load_full_mft_resume_artifacts(void);
int mft_engine_saved_mft_map_available(void);
int mft_engine_saved_spool_artifacts_available(void);
int mft_engine_saved_metadata_available(void);
void mft_engine_reconcile_recovered_outputs_live(void);
int mft_engine_prepare_index(void);
int mft_engine_finalize_index(void);
int mft_engine_finalize_recovered_outputs(void);
int mft_engine_finalize_recovered_outputs_with_mft_map(void);
void mft_engine_set_state_writes_suppressed(int suppressed);
void mft_engine_close(void);

size_t mft_engine_entry_count(void);
size_t mft_engine_recovered_output_count(void);
size_t mft_engine_named_output_count(void);
size_t mft_engine_unreconciled_output_count(void);
int mft_engine_is_offset_fully_recovered(long long abs_offset);
int mft_engine_get_recovered_output_info(
    long long abs_offset,
    char *out_path,
    size_t out_path_size,
    int *out_reconciled
);

int mft_engine_build_output_path(char *out, size_t out_size, const char *relative_path);
int mft_engine_build_recovered_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
int mft_engine_build_deferred_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
int mft_engine_apply_output_owner_to_path(const char *path);
int mft_engine_apply_created_time_to_path(const char *path, long long abs_offset);
int mft_engine_apply_created_time_value_to_path(const char *path, time_t created_time);
void mft_engine_note_recovered_output(const char *path, long long abs_offset);

const char *mft_engine_lookup_path_by_offset(long long abs_offset);
time_t mft_engine_lookup_created_time_by_offset(long long abs_offset);
int mft_engine_lookup_scan_hint(long long abs_offset, MftScanHint *out);
const char *mft_engine_lookup_container_label_by_offset(long long abs_offset);
int mft_engine_classify_recovered_output_hint(
    long long abs_offset,
    const char *recovered_extension,
    MftRecoveredNamingHint *out_hint
);
void mft_engine_refresh_recovery_state(size_t *entry_count_snapshot);
size_t mft_engine_collect_view_entries_in_range(
    long long range_start,
    long long range_end,
    MftViewEntry **out_entries
);
int mft_engine_get_view_entry_by_offset(long long abs_offset, MftViewEntry *out);
size_t mft_engine_write_missed_users_report(const char *path);
void mft_engine_background_tick(int final_pass);
void mft_engine_set_background_conservative(int enabled);
int mft_engine_background_is_conservative(void);
void mft_engine_reset_process_stats(void);
void mft_engine_get_process_stats(MftProcessStats *out_stats);

int mft_engine_artifacts_available(const char *out_dir);
int mft_engine_is_internal_output_artifact_name(const char *name);
int mft_engine_split_run_output_dir(
    const char *run_output_dir,
    char *base_out,
    size_t base_out_size,
    char *run_id,
    size_t run_id_size
);

int mft_engine_run_users_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    uint64_t limit,
    int quick_resume,
    int auto_recover_missed,
    int only_recover_missed,
    const MftEngineUsersOptions *options
);
int mft_engine_run_filtered_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    const char *filter_csv,
    uint64_t limit,
    const MftEngineUsersOptions *options
);
int mft_engine_run_metadata_jpeg_test(
    const char *image_path,
    const char *out_dir,
    size_t max_files,
    size_t *out_recovered_count
);
int mft_engine_run_compare_mount_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    const char *mount_path,
    const char *filter_csv,
    uint64_t limit,
    const MftEngineUsersOptions *options
);
int mft_engine_list_root_folders(const char *image_path, FILE *out_stream);
int mft_engine_list_child_folders(
    const char *image_path,
    const char *parent_path,
    FILE *out_stream
);
int mft_engine_list_root_folders_partial(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    FILE *out_stream
);
int mft_engine_list_child_folders_partial(
    const char *image_path,
    const char *parent_path,
    const MftprobePartialNtfsSource *source,
    FILE *out_stream
);
int mft_engine_write_selected_tree_ddrescue_domain(
    const char *image_path,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
);
int mft_engine_write_selected_tree_ddrescue_domain_partial(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
);
int mft_engine_write_selected_tree_ddrescue_domain_partial_with_options(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    const MftEngineUsersOptions *options,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes,
    uint64_t *out_file_count
);
int mft_engine_run_selected_partial_recovery(
    const char *image_path,
    const char *out_dir,
    const MftprobePartialNtfsSource *source,
    const MftEngineUsersOptions *options,
    size_t *out_recovered_count,
    size_t *out_waiting_for_coverage,
    size_t *out_already_present,
    size_t *out_failed,
    size_t *out_folders_with_complete_files
);
MftEngineStatus mft_engine_users_last_status(void);
size_t mft_engine_users_last_recovered_count(void);

#endif
