#ifndef FS_BACKEND_H
#define FS_BACKEND_H

/*
 * Generic filesystem backend facade.
 *
 * The implementation still delegates to filesystem-specific engines, but the
 * public app-facing surface should expose backend-neutral types so new
 * filesystems do not need to inherit NTFS/MFT naming just to participate in
 * shared scan/output/reconcile flows.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "reader.h"
#include "metadata_index.h"

#define FS_BACKEND_HAVE_SALVAGE_API 1
#define FS_BACKEND_HAVE_METADATA_ACQUIRE_API 1
#define FS_BACKEND_HAVE_MATCH_PREVIEW_API 1
#define FS_BACKEND_HAVE_NAME_CANDIDATE_INDEX_API 1
#define FS_VIEW_MAX_RUNS 64U
#define FS_VIEW_FLAG_TREE_SYSTEM 0x00000800U

typedef struct {
    uint64_t abs_offset;
    uint64_t byte_length;
} FsViewRun;

typedef struct {
    long long abs_offset;
    uint64_t data_size;
    uint64_t allocated_size;
    size_t run_count;
    int run_truncated;
    FsViewRun runs[FS_VIEW_MAX_RUNS];
    int flags;
    int has_data;
    int is_resident;
    char path[1024];
    char name[256];
} FsViewEntry;

typedef struct {
    int exact_data_match;
    int inside_nonresident_run;
    int inside_resident_record;
    int record_number;
} FsScanHint;

typedef struct {
    uint64_t parsed_metadata_units;
    uint64_t indexed_metadata_units;
    uint64_t built_entries;
    uint64_t stored_entries;
    double seconds_parse;
    double seconds_index;
    double seconds_build;
    double seconds_store;
} FsBackendProcessStats;

typedef struct {
    size_t candidate_records;
    size_t whole_records;
    size_t partial_records;
    size_t broken_records;
} FsBackendRecordSalvageStats;

typedef struct {
    int has_entry;
    int created_time_available;
    int exact_start_match;
    int size_available;
    int exact_size_match;
    int size_close_match;
    int header_time_available;
    int header_time_close_match;
    int has_name;
    int contextual_complete;
    int flat_name_exact_family;
    int flat_name_preserve_extension;
} FsRecoveredNamingHint;

typedef struct {
    int direct_anchor_match;
    int candidate_found;
    int exact_size_match;
    int size_close_match;
    int header_time_close_match;
    int contextual_complete;
    int contextual_partial;
    int merged_candidate;
    int mft_only_candidate;
    int i30_only_candidate;
} FsRecoveredMatchSignals;

typedef struct {
    size_t total_candidates;
    size_t merged_candidates;
    size_t mft_only_candidates;
    size_t i30_only_candidates;
    size_t direct_data_anchors;
    size_t complete_paths;
    size_t partial_paths;
    size_t named_candidates;
    size_t nameless_candidates;
    size_t mft_record_seq_present;
    size_t mft_record_seq_missing;
    size_t unique_missing_parents;
    uint64_t top_missing_parent_record;
    size_t top_missing_parent_blocked_candidates;
} FsNameCandidateIndexStats;

typedef struct {
    size_t total_outputs;
    size_t matched_outputs;
    size_t unmatched_outputs;
    size_t context_complete_matches;
    size_t context_partial_matches;
    size_t parent_group_matches;
    size_t flat_name_matches;
    size_t hint_context_complete_matches;
    size_t hint_context_partial_matches;
    size_t hint_parent_group_matches;
    size_t hint_flat_name_matches;
} FsNameMatchPreviewStats;

typedef struct {
    size_t outputs_needing_name;
    size_t outputs_with_size;
    size_t outputs_with_header_time;
    size_t direct_anchor_outputs;
    size_t outputs_with_any_exact_size_candidate;
    size_t unique_exact_size_outputs;
    size_t ambiguous_exact_size_outputs;
    size_t outputs_with_any_exact_size_time_candidate;
    size_t unique_exact_size_time_outputs;
    size_t ambiguous_exact_size_time_outputs;
} FsNameUniquenessStats;

typedef enum {
    FS_RECOVERED_MATCH_NONE = 0,
    FS_RECOVERED_MATCH_CONTEXT_COMPLETE = 1,
    FS_RECOVERED_MATCH_CONTEXT_PARTIAL = 2,
    FS_RECOVERED_MATCH_PARENT_GROUP = 3,
    FS_RECOVERED_MATCH_FLAT_NAME = 4,
    FS_RECOVERED_MATCH_HINT_CONTEXT_COMPLETE = 5,
    FS_RECOVERED_MATCH_HINT_CONTEXT_PARTIAL = 6,
    FS_RECOVERED_MATCH_HINT_PARENT_GROUP = 7,
    FS_RECOVERED_MATCH_HINT_FLAT_NAME = 8
} FsRecoveredMatchKind;

typedef struct {
    uint64_t abs_offset;
    uint64_t byte_length;
    uint32_t index_block_size;
    long long family_base_offset;
    int directory_record_number;
    uint16_t directory_record_seq;
} FsDirectoryIndexTarget;

typedef enum {
    FS_BACKEND_BACKGROUND_PHASE_IDLE = 0,
    FS_BACKEND_BACKGROUND_PHASE_TREE = 1,
    FS_BACKEND_BACKGROUND_PHASE_INDEX = 2,
    FS_BACKEND_BACKGROUND_PHASE_NAMING = 3,
    FS_BACKEND_BACKGROUND_PHASE_REPAIR = 4
} FsBackendBackgroundPhase;

typedef struct {
    uint64_t renamed_outputs;
    uint64_t repaired_outputs;
    uint64_t recovered_outputs_current;
    uint64_t named_outputs_current;
    uint64_t unident_outputs_current;
    uint64_t repair_pending_outputs;
    uint64_t repair_queue_events;
    size_t record_index_count;
    size_t range_index_count;
    unsigned long long scan_stalled_seconds;
    unsigned int background_phase;
    unsigned int background_conservative;
} FsBackendLiveStats;

typedef enum {
    FS_BACKEND_ARTIFACT_PHASE_SCAN_RESUME = 0,
    FS_BACKEND_ARTIFACT_PHASE_FINALIZE_RESUME = 1,
    FS_BACKEND_ARTIFACT_PHASE_NAME_RESUME = 2
} FsBackendArtifactPhase;

typedef enum {
    FS_BACKEND_METADATA_ACQUIRE_STARTUP = 0,
    FS_BACKEND_METADATA_ACQUIRE_PRE_DEFERRED = 1,
    FS_BACKEND_METADATA_ACQUIRE_POST_DEFERRED = 2
} FsBackendMetadataAcquirePhase;

typedef struct {
    int metadata_snapshot_ready;
    int recovered_output_log_ready;
    int finalize_status_present;
    int finalize_state_ready;
    int ready_for_phase;
    size_t pending_outputs;
    size_t finalize_next_output_index;
    size_t recovered_outputs;
    size_t named_outputs;
} FsBackendArtifactState;

typedef enum {
    FS_BACKEND_KIND_NONE = 0,
    FS_BACKEND_KIND_NTFS = 1,
    FS_BACKEND_KIND_HFSPLUS = 2,
    FS_BACKEND_KIND_EXFAT = 3
} FsBackendKind;

typedef enum {
    FS_CONTEXTUAL_OUTPUT_SELECTED_TREE = 0,
    FS_CONTEXTUAL_OUTPUT_FULL_TREE = 1
} FsContextualOutputMode;

typedef enum {
    FS_BACKEND_METADATA_STATUS_NONE = 0,
    FS_BACKEND_METADATA_STATUS_OK,
    FS_BACKEND_METADATA_STATUS_FAILED,
    FS_BACKEND_METADATA_STATUS_INTERRUPTED
} FsBackendMetadataStatus;

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
} FsBackendMetadataOptions;

typedef struct {
    const char *output_dir;
    const char *service_id;
    const char *active_formats_csv;
    FsContextualOutputMode contextual_output_mode;
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
    int force_hfsplus_target;
    int prefer_compact_metadata;
    /* Raw header hunting remains format-selected.  This flag only controls
     * whether a complete HFS+ Catalog data fork may be assembled from bytes
     * already passing through the sequential scanner regardless of suffix. */
    int hfsplus_assemble_all_catalog_files;
} FsBackendConfig;

void fs_backend_configure(const FsBackendConfig *config);
FsBackendKind fs_backend_current_kind(void);

int fs_backend_configure_from_source(const char *input_path);
int fs_backend_source_is_definitely_non_ntfs(void);
const char *fs_backend_source_filesystem_hint(void);
const char *fs_backend_current_id(void);
const char *fs_backend_current_name(void);
const char *fs_backend_current_output_dir(void);
uint64_t fs_backend_current_volume_serial(void);
int fs_backend_is_internal_output_artifact_name(const char *name);
int fs_backend_supports_live_metadata_observation(void);
int fs_backend_has_metadata_context_for_raw_scan(void);
int fs_backend_translate_photorec_file_number(
    unsigned long long file_number,
    long long *out_abs_offset
);
int fs_backend_source_path_is_direct_metadata_file(const char *path);
int fs_backend_supports_selected_tree_recovery(void);
int fs_backend_supports_root_folder_preview(void);
int fs_backend_supports_compare_mount(void);
int fs_backend_has_native_geometry(void);
size_t fs_backend_record_size(void);
int fs_backend_write_resident_record_payload(
    FILE *out,
    const unsigned char *record,
    size_t record_length,
    uint64_t record_abs_offset,
    uint64_t expected_data_size
);
size_t fs_backend_observe_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset,
    int allow_unaligned
);
size_t fs_backend_absorb_usn_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t fs_backend_absorb_lnk_dlt_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t fs_backend_absorb_windows_search_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t fs_backend_absorb_vss_evidence_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);

int fs_backend_load_resume_artifacts(void);
int fs_backend_load_finalize_resume_artifacts(void);
int fs_backend_load_name_resume_artifacts(void);
int fs_backend_load_recovered_output_state(void);
int fs_backend_saved_metadata_available(void);
int fs_backend_load_artifacts_for_phase(FsBackendArtifactPhase phase);
int fs_backend_saved_metadata_available_for_phase(FsBackendArtifactPhase phase);
void fs_backend_get_artifact_state(
    FsBackendArtifactPhase phase,
    FsBackendArtifactState *out_state
);
void fs_backend_set_partial_record_salvage(int enabled);
void fs_backend_set_salvage_first_sector_confirmed_bytes(size_t bytes);
void fs_backend_set_catalog_first_mode(int enabled);
void fs_backend_set_name_trace_enabled(int enabled);
void fs_backend_set_finalize_opportunistic_budget_seconds(
    double seconds,
    const char *profile_label
);
void fs_backend_reset_record_salvage_stats(void);
void fs_backend_get_record_salvage_stats(FsBackendRecordSalvageStats *out_stats);
void fs_backend_reset_seen_offsets(void);
int fs_backend_prepare_index(void);
int fs_backend_finalize_index(void);
int fs_backend_finalize_recovered_outputs(void);
int fs_backend_finalize_recovered_outputs_with_live_catalog(void);
void fs_backend_observe_sequential_bytes(
    uint64_t range_start,
    const unsigned char *bytes,
    size_t byte_count
);
void fs_backend_finish_sequential_measurement(int completed_full_scan);
int fs_backend_range_has_trusted_metadata_owner(
    uint64_t range_start,
    uint64_t range_end
);
int fs_backend_get_candidate_context(
    uint64_t physical_offset,
    MetadataIndexCandidateContext *context_out
);
void fs_backend_set_state_writes_suppressed(int suppressed);
void fs_backend_close(void);

size_t fs_backend_entry_count(void);
size_t fs_backend_recovered_output_count(void);
size_t fs_backend_named_output_count(void);
size_t fs_backend_unreconciled_output_count(void);
int fs_backend_is_offset_fully_recovered(long long abs_offset);
int fs_backend_get_recovered_output_info(
    long long abs_offset,
    char *out_path,
    size_t out_path_size,
    int *out_reconciled
);

int fs_backend_build_output_path(char *out, size_t out_size, const char *relative_path);
int fs_backend_build_recovered_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
int fs_backend_build_deferred_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
int fs_backend_output_path_write_guard_allows(const char *path);
FILE *fs_backend_fopen_output_write_guarded(const char *path, const char *mode);
int fs_backend_apply_output_owner_to_path(const char *path);
int fs_backend_apply_created_time_to_path(const char *path, long long abs_offset);
int fs_backend_apply_created_time_value_to_path(const char *path, time_t created_time);
void fs_backend_note_recovered_output(const char *path, long long abs_offset);
void fs_backend_reconcile_recovered_outputs_live(void);
int fs_backend_refresh_record_at(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t absolute_offset,
    size_t buffer_offset
);
int fs_backend_record_offset_is_naming_ready(uint64_t absolute_offset);
size_t fs_backend_collect_partial_metadata_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
);
size_t fs_backend_collect_parent_chain_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
);
size_t fs_backend_collect_name_detail_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
);
size_t fs_backend_collect_directory_index_targets(
    FsDirectoryIndexTarget *out_targets,
    size_t out_capacity,
    uint64_t max_total_bytes
);
size_t fs_backend_absorb_directory_index_buffer(
    const FsDirectoryIndexTarget *target,
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t fs_backend_refresh_directory_index_from_source(
    const char *source_path,
    uint64_t max_total_bytes,
    size_t max_target_count,
    uint64_t *out_bytes_scanned
);
size_t fs_backend_directory_index_name_count(void);
int fs_backend_classify_recovered_output_hint(
    long long abs_offset,
    const char *recovered_extension,
    FsRecoveredNamingHint *out_hint
);
int fs_backend_preview_recovered_output_match(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    FsRecoveredMatchKind *out_kind
);
int fs_backend_collect_recovered_output_match_signals(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    FsRecoveredMatchSignals *out_signals
);
void fs_backend_get_name_uniqueness_stats(FsNameUniquenessStats *out_stats);
int fs_backend_get_name_candidate_index_stats(FsNameCandidateIndexStats *out_stats);
int fs_backend_write_name_candidate_index(FsNameCandidateIndexStats *out_stats);
int fs_backend_write_name_match_preview(FsNameMatchPreviewStats *out_stats);
void fs_backend_emit_directory_index_hint_sample(size_t limit);

const char *fs_backend_lookup_path_by_offset(long long abs_offset);
time_t fs_backend_lookup_created_time_by_offset(long long abs_offset);
int fs_backend_lookup_scan_hint(long long abs_offset, FsScanHint *out);
const char *fs_backend_lookup_container_label_by_offset(long long abs_offset);
void fs_backend_refresh_recovery_state(size_t *entry_count_snapshot);
size_t fs_backend_collect_view_entries_in_range(
    long long range_start,
    long long range_end,
    FsViewEntry **out_entries
);
int fs_backend_get_view_entry_by_offset(long long abs_offset, FsViewEntry *out);
size_t fs_backend_write_missed_report(const char *path);
void fs_backend_reset_process_stats(void);
void fs_backend_get_process_stats(FsBackendProcessStats *out_stats);

long long fs_backend_primary_scan_start_offset(void);
uint64_t fs_backend_primary_total_bytes(void);
long long fs_backend_expected_mirror_offset(void);
uint64_t fs_backend_estimated_mirror_bytes(void);
long long fs_backend_partition_start_offset(void);
uint32_t fs_backend_cluster_size(void);
int fs_backend_has_primary_catalog_root(void);
int fs_backend_run_primary_metadata_bootstrap(Reader *reader);
int fs_backend_should_attempt_primary_metadata_acquisition(
    FsBackendMetadataAcquirePhase phase
);
int fs_backend_run_primary_metadata_acquisition(
    Reader *reader,
    FsBackendMetadataAcquirePhase phase
);
int fs_backend_bootstrap_should_disable_live_observation(void);
size_t fs_backend_primary_run_count(void);
int fs_backend_get_primary_run(
    size_t run_index,
    uint64_t *out_abs_offset,
    uint64_t *out_length
);
int fs_backend_split_run_output_dir(
    const char *run_output_dir,
    char *base_out,
    size_t base_out_size,
    char *run_id,
    size_t run_id_size
);
int fs_backend_run_selected_tree_with_options(
    const char *input_path,
    const char *out_dir,
    const char *run_name,
    uint64_t limit,
    int quick_resume,
    int auto_recover_missed,
    int only_recover_missed,
    const FsBackendMetadataOptions *options
);
int fs_backend_write_selected_tree_ddrescue_domain(
    const char *input_path,
    const char *domain_map_path,
    const FsBackendMetadataOptions *options,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
);
int fs_backend_run_filtered_recovery_with_options(
    const char *input_path,
    const char *out_dir,
    const char *run_name,
    const char *filter_csv,
    uint64_t limit,
    const FsBackendMetadataOptions *options
);
int fs_backend_run_metadata_jpeg_test(
    const char *input_path,
    const char *out_dir,
    size_t max_files,
    size_t *out_recovered_count
);
int fs_backend_run_compare_mount_with_options(
    const char *input_path,
    const char *out_dir,
    const char *run_name,
    const char *mount_path,
    const char *filter_csv,
    uint64_t limit,
    const FsBackendMetadataOptions *options
);
int fs_backend_list_root_folders(const char *input_path, FILE *out_stream);
int fs_backend_list_child_folders(
    const char *input_path,
    const char *parent_path,
    FILE *out_stream
);
FsBackendMetadataStatus fs_backend_last_metadata_status(void);
size_t fs_backend_last_metadata_recovered_count(void);

int fs_backend_start_background_worker(const FsBackendConfig *config);
void fs_backend_stop_background_worker(void);
int fs_backend_background_worker_running(void);
int fs_backend_background_worker_expected_running(void);
int fs_backend_background_stop_requested(void);
void fs_backend_set_background_conservative(int enabled);
int fs_backend_background_is_conservative(void);
void fs_backend_set_output_context_skip_enabled(int enabled);
void fs_backend_set_metadata_stall_watch_suspended(int suspended);
void fs_backend_get_live_queue_stats(FsBackendLiveStats *out);
void fs_backend_note_foreground_activity(void);

#endif
