#ifndef METADATA_OUTCOME_H
#define METADATA_OUTCOME_H

#include "metadata_index.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef FILE *(*MetadataOutcomeOpenFileFn)(const char *path, const char *mode);

typedef struct {
    uint64_t physical_offset;
    const char *format;
    const char *output_kind;
} MetadataOutcomeRecord;

typedef struct {
    uint64_t outputs;
    uint64_t lookup_failures;
    uint64_t no_owner;
    uint64_t ambiguous_owner;
    uint64_t non_data_owner;
    uint64_t incomplete_owner;
    uint64_t trusted_exact_start;
    uint64_t trusted_interior;
    uint64_t named_outputs;
    uint64_t unresolved_outputs;
    uint64_t embedded_outputs;
    uint64_t artifact_bytes;
} MetadataOutcomeStats;

typedef struct {
    uint64_t lookups;
    uint64_t lookup_failures;
    uint64_t no_owner;
    uint64_t ambiguous_owner;
    uint64_t non_data_owner;
    uint64_t incomplete_owner;
    uint64_t trusted_exact_start;
    uint64_t trusted_interior;
    uint64_t shared_with_dispatch;
    uint64_t high_water_offset;
    int high_water_valid;
} MetadataCandidateStats;

/* Returns 1 once for each new monotonically increasing physical offset. */
int metadata_candidate_stats_note_offset(
    MetadataCandidateStats *stats,
    uint64_t physical_offset
);

int metadata_candidate_stats_is_consistent(const MetadataCandidateStats *stats);

/*
 * Atomically rewrites recovered_output_metadata.tsv and its status file from
 * the caller's canonical recovered-output list. Repeating the call is
 * idempotent: one input record always produces one artifact row.
 */
int metadata_outcome_write_artifacts(
    const MetadataIndexReader *reader,
    const char *metadata_dir,
    const char *backend_id,
    const MetadataOutcomeRecord *records,
    size_t record_count,
    MetadataOutcomeOpenFileFn open_file,
    MetadataOutcomeStats *stats_out
);

#endif
