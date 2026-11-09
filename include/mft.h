#ifndef MFT_H
#define MFT_H

#include "mft_types.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct {
    uint64_t parsed_records;
    uint64_t spooled_records;
    uint64_t built_entries;
    uint64_t stored_entries;
    double seconds_parse;
    double seconds_spool;
    double seconds_build;
    double seconds_store;
} MftProcessStats;

typedef struct {
    size_t candidate_records;
    size_t whole_records;
    size_t partial_records;
    size_t broken_records;
} MftRecordSalvageStats;

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
} MftRecoveredNamingHint;

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
} MftRecoveredMatchSignals;

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
} MftNameCandidateIndexStats;

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
} MftNameMatchPreviewStats;

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
} MftNameUniquenessStats;

typedef enum {
    MFT_RECOVERED_MATCH_NONE = 0,
    MFT_RECOVERED_MATCH_CONTEXT_COMPLETE = 1,
    MFT_RECOVERED_MATCH_CONTEXT_PARTIAL = 2,
    MFT_RECOVERED_MATCH_PARENT_GROUP = 3,
    MFT_RECOVERED_MATCH_FLAT_NAME = 4,
    MFT_RECOVERED_MATCH_HINT_CONTEXT_COMPLETE = 5,
    MFT_RECOVERED_MATCH_HINT_CONTEXT_PARTIAL = 6,
    MFT_RECOVERED_MATCH_HINT_PARENT_GROUP = 7,
    MFT_RECOVERED_MATCH_HINT_FLAT_NAME = 8,
    MFT_RECOVERED_MATCH_FOLDER_ONLY = 9
} MftRecoveredMatchKind;

typedef struct {
    uint64_t abs_offset;
    uint64_t byte_length;
    uint32_t index_block_size;
    long long family_base_offset;
    int directory_record_number;
    uint16_t directory_record_seq;
} MftI30ScanTarget;

void mft_set_recovery_categories(
    int recover_img,
    int recover_vid,
    int recover_doc
);
void mft_set_requested_formats_csv(const char *formats_csv);
void mft_set_contextual_output_mode(MftContextualOutputMode mode);
void mft_set_reset_existing_store(int enabled);
void mft_set_deleted_filter(int enabled, int deleted_value);
void mft_set_deleted_filter_recycle_policy(int include_with_live_filter);
void mft_set_date_filter(int enabled, int start_yyyymmdd, int end_yyyymmdd);
void mft_set_output_dir(const char *output_dir);
void mft_set_resume_source_path_hint(const char *source_path);
int mft_apply_resume_source_rebase(void);
void mft_set_partial_record_salvage(int enabled);
void mft_set_salvage_first_sector_confirmed_bytes(size_t bytes);
void mft_set_catalog_first_mode(int enabled);
void mft_set_force_ntfs_target(int enabled);
void mft_set_name_trace_enabled(int enabled);
void mft_set_finalize_opportunistic_budget_seconds(
    double seconds,
    const char *profile_label
);
void mft_reset_record_salvage_stats(void);
void mft_get_record_salvage_stats(MftRecordSalvageStats *out_stats);
void mft_reset_seen_offsets(void);
const char *mft_get_output_dir(void);
const char *mft_visible_windows_component_name(const char *component);
int mft_build_output_path(char *out, size_t out_size, const char *relative_path);
int mft_build_unident_dir(char *out, size_t out_size);
int mft_build_unident_typed_dir(
    char *out,
    size_t out_size,
    const char *extension
);
int mft_build_unident_typed_bucket_dir(
    char *out,
    size_t out_size,
    const char *extension
);
int mft_build_deferred_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
int mft_configure_from_source(const char *input_path);
int mft_has_ntfs_geometry(void);
int mft_source_is_definitely_non_ntfs(void);
const char *mft_source_filesystem_hint(void);
uint64_t mft_get_ntfs_volume_serial(void);
size_t mft_get_record_size(void);
long long mft_get_partition_start(void);
uint32_t mft_get_cluster_size(void);
int mft_is_record_candidate_offset(size_t absolute_offset);
size_t mft_next_candidate_offset(size_t absolute_offset);
int mft_is_record_candidate_offset(size_t absolute_offset);
size_t mft_next_candidate_offset(size_t absolute_offset);
long long mft_get_scan_end_offset(void);
long long mft_get_primary_scan_start_offset(void);
long long mft_get_expected_mft_mirror_offset(void);
uint64_t mft_get_primary_mft_total_bytes(void);
uint64_t mft_get_estimated_mft_mirror_bytes(void);
size_t mft_get_primary_mft_run_count(void);
int mft_get_primary_mft_run(
    size_t index,
    uint64_t *out_abs_offset,
    uint64_t *out_byte_length
);
int mft_has_primary_users_root(void);
void mft_refresh_recovery_mode(void);
void mft_process_record_at(
    const unsigned char *buffer,
    size_t buffer_length,
    size_t absolute_offset,
    size_t buffer_offset,
    int allow_unaligned
);
int mft_refresh_record_at(
    const unsigned char *buffer,
    size_t buffer_length,
    size_t absolute_offset,
    size_t buffer_offset
);
int mft_record_offset_is_naming_ready(uint64_t absolute_offset);
size_t mft_collect_partial_metadata_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
);
size_t mft_collect_parent_chain_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
);
size_t mft_collect_name_detail_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
);
size_t mft_collect_i30_scan_targets(
    MftI30ScanTarget *out_targets,
    size_t out_capacity,
    uint64_t max_total_bytes
);
size_t mft_absorb_i30_index_buffer(
    const MftI30ScanTarget *target,
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_absorb_usn_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_absorb_lnk_dlt_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_absorb_windows_search_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_absorb_vss_evidence_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
size_t mft_refresh_i30_names_from_source(
    const char *source_path,
    uint64_t max_total_bytes,
    size_t max_target_count,
    uint64_t *out_bytes_scanned
);
size_t mft_i30_name_count(void);

const char *mft_lookup_path_by_offset(long long abs_offset);
int mft_lookup_record_by_offset(long long abs_offset);
time_t mft_lookup_created_time_by_offset(long long abs_offset);
int mft_lookup_scan_hint(long long abs_offset, MftScanHint *out);
const char *mft_lookup_container_label_by_offset(long long abs_offset);
int mft_classify_recovered_output_hint(
    long long abs_offset,
    const char *recovered_extension,
    MftRecoveredNamingHint *out_hint
);
int mft_preview_recovered_output_match(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    MftRecoveredMatchKind *out_kind
);
int mft_collect_recovered_output_match_signals(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    MftRecoveredMatchSignals *out_signals
);
void mft_get_name_uniqueness_stats(MftNameUniquenessStats *out_stats);
int mft_get_name_candidate_index_stats(MftNameCandidateIndexStats *out_stats);
int mft_write_name_candidate_index(MftNameCandidateIndexStats *out_stats);
int mft_write_name_match_preview(MftNameMatchPreviewStats *out_stats);
void mft_emit_i30_name_trace_sample(size_t limit);
int mft_should_recover_offset(long long abs_offset);
int mft_is_offset_recovered(long long abs_offset);
int mft_is_offset_fully_recovered(long long abs_offset);
int mft_get_recovered_output_info(
    long long abs_offset,
    char *out_path,
    size_t out_path_size,
    int *out_reconciled
);
size_t mft_recovered_output_count(void);
size_t mft_named_output_count(void);
size_t mft_unreconciled_output_count(void);
size_t mft_write_missed_users_report(const char *path);
int mft_missed_report_path_should_recover(const char *path, const char *name);
size_t mft_entry_count(void);
int mft_get_view_entry(size_t index, MftViewEntry *out);
int mft_get_view_entry_by_offset(long long abs_offset, MftViewEntry *out);
size_t mft_collect_view_entries_in_range(
    long long range_start,
    long long range_end,
    MftViewEntry **out_entries
);
int mft_build_recovered_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
int mft_normalize_directory_conflicts_for_path(
    char *out,
    size_t out_size,
    const char *input_path,
    int leaf_is_directory
);
int mft_apply_created_time_value_to_path(const char *path, time_t created_time);
int mft_apply_created_time_to_path(const char *path, long long abs_offset);
int mft_apply_output_owner_to_path(const char *path);
void mft_note_recovered_output(const char *path, long long abs_offset);
void mft_reconcile_recovered_outputs_live(void);
int mft_load_recovered_outputs_resume_artifacts(void);
int mft_load_saved_i30_name_artifacts(void);
int mft_load_targeted_resume_artifacts(void);
int mft_load_resume_artifacts(void);
void mft_release_in_memory_catalog(void);
int mft_prepare_index(void);
int mft_finalize_index(void);
int mft_finalize_recovered_outputs_name_only(void);
void mft_set_state_writes_suppressed(int suppressed);
void mft_close(void);
void mft_reset_process_stats(void);
void mft_get_process_stats(MftProcessStats *out_stats);

#endif
