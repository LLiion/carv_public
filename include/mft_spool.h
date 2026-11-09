#ifndef MFT_SPOOL_H
#define MFT_SPOOL_H

#include "mft_types.h"
#include "mft_probe_parser.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *output_dir;
    const char *service_id;
    MftContextualOutputMode contextual_output_mode;
    int reset_existing_store;
} MftSpoolConfig;

typedef enum {
    MFT_SPOOL_BACKGROUND_PHASE_IDLE = 0,
    MFT_SPOOL_BACKGROUND_PHASE_TREE = 1,
    MFT_SPOOL_BACKGROUND_PHASE_INDEX = 2,
    MFT_SPOOL_BACKGROUND_PHASE_NAMING = 3,
    MFT_SPOOL_BACKGROUND_PHASE_REPAIR = 4
} MftSpoolBackgroundPhase;

typedef struct {
    uint64_t renamed_outputs;
    uint64_t repaired_outputs;
    uint64_t recovered_outputs_current;
    uint64_t named_outputs_current;
    uint64_t unident_outputs_current;
    uint64_t repair_pending_outputs;
    uint64_t repair_queue_events;
    uint64_t opportunistic_naming_sweeps;
    uint64_t opportunistic_naming_renamed;
    uint64_t opportunistic_naming_zero_delta;
    uint64_t opportunistic_naming_last_delta;
    uint64_t recovered_first_checked_last;
    uint64_t recovered_first_moved_last;
    uint64_t recovered_first_complete_moves_last;
    uint64_t recovered_first_partial_moves_last;
    uint64_t recovered_first_parent_group_moves_last;
    uint64_t recovered_first_flat_name_moves_last;
    uint64_t recovered_first_no_path_last;
    uint64_t recovered_first_missing_source_last;
    uint64_t recovered_first_no_extension_last;
    uint64_t recovered_first_no_range_anchor_last;
    uint64_t recovered_first_no_exact_range_start_last;
    uint64_t recovered_first_no_context_path_last;
    uint64_t recovered_first_no_payload_last;
    uint64_t recovered_first_no_commit_candidate_last;
    uint64_t recovered_first_same_path_last;
    uint64_t recovered_first_rename_failures_last;
    size_t record_index_count;
    size_t range_index_count;
    unsigned long long scan_stalled_seconds;
    unsigned int background_phase;
    unsigned int background_conservative;
} MftSpoolLiveStats;

void mft_spool_configure(const MftSpoolConfig *config);
void mft_spool_prepare_background_child(void);
void mft_spool_set_geometry(
    int has_ntfs_geometry,
    long long partition_start,
    uint32_t cluster_size,
    uint32_t record_size
);

int mft_spool_prepare(void);
int mft_spool_artifacts_available(void);
int mft_spool_load_resume_artifacts(void);
void mft_spool_close(void);

int mft_spool_append_probe(const MftProbeEntry *entry);
int mft_spool_append_recovered_output(const char *path, long long abs_offset);

int mft_spool_build_indices(void);
int mft_spool_indices_available(void);
int mft_spool_probe_index_current(void);
size_t mft_spool_record_index_count(void);
size_t mft_spool_range_index_count(void);
void mft_spool_get_live_stats(MftSpoolLiveStats *out);
void mft_spool_background_tick(int final_pass);
void mft_spool_set_background_conservative(int enabled);
int mft_spool_background_is_conservative(void);
void mft_spool_set_stall_watch_suspended(int suspended);
void mft_spool_note_foreground_activity(void);
int mft_spool_materialize_output_directories(void);
int mft_spool_reconcile_outputs(void);
int mft_spool_reconcile_outputs_naming_only(void);
void mft_spool_publish_backend_counts(
    uint64_t recovered_total,
    uint64_t named_total,
    uint64_t unident_total
);
void mft_spool_publish_backend_progress(
    uint64_t recovered_total,
    uint64_t named_total,
    uint64_t unident_total,
    uint64_t renamed_total,
    uint64_t repaired_total
);

#endif
