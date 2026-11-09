#ifndef RECOVERED_CONTENT_INDEX_H
#define RECOVERED_CONTENT_INDEX_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int (*stop_requested)(void *context);
    int (*path_write_allowed)(const char *path, void *context);
    int (*finalize_path)(const char *path, void *context);
    void *context;
    double time_budget_seconds;
    /* Optional deterministic slice cap. Zero leaves scheduling time-based. */
    uint64_t work_item_budget;
} RecoveredContentIndexOptions;

typedef struct {
    uint64_t generation;
    uint64_t files_seen;
    uint64_t files_bytes;
    uint64_t client_artifacts_ignored;
    uint64_t files_seen_before_slice;
    uint64_t files_added_this_slice;
    uint64_t ledger_bytes_consumed;
    uint64_t directories_completed;
    uint64_t pending_directories;
    uint64_t candidate_files;
    uint64_t cross_class_candidate_files;
    uint64_t photo_candidate_files;
    uint64_t files_hashed_now;
    uint64_t hashes_reused;
    uint64_t hash_failures;
    uint64_t bytes_hashed_now;
    uint64_t duplicate_groups;
    uint64_t duplicate_occurrences;
    uint64_t redundant_copies;
    uint64_t redundant_bytes;
    uint64_t catalog_duplicate_groups;
    uint64_t catalog_duplicate_files;
    uint64_t catalog_duplicate_bytes;
    double seconds_total;
    int checkpoint_resumed;
    int budget_exhausted;
    int completed;
} RecoveredContentIndexStats;

/* Scans run_dir/recovered only. It never opens the recovery source. */
int recovered_content_index_update(
    const char *run_dir,
    const RecoveredContentIndexOptions *options,
    RecoveredContentIndexStats *stats_out
);

#endif
