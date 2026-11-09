#ifndef METADATA_INDEX_H
#define METADATA_INDEX_H

/*
 * Compact, backend-neutral filesystem metadata search view.
 *
 * The on-disk representation is private to metadata_index.c.  Callers pass
 * host-endian values through this API; every persisted integer is encoded
 * explicitly as little endian.
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define METADATA_INDEX_FORMAT_VERSION 2U
#define METADATA_INDEX_NO_ROW UINT32_MAX
#define METADATA_INDEX_SPARSE_OFFSET UINT64_MAX
#define METADATA_INDEX_TIME_UNKNOWN UINT64_MAX
#define METADATA_INDEX_REFERENCE_UNKNOWN UINT64_MAX

#define METADATA_INDEX_OBJECT_FLAG_DIRECTORY 0x00000001U
#define METADATA_INDEX_OBJECT_FLAG_ROOT 0x00000002U
#define METADATA_INDEX_OBJECT_FLAG_LIVE 0x00000004U
#define METADATA_INDEX_OBJECT_FLAG_PATH_COMPLETE 0x00000008U
#define METADATA_INDEX_OBJECT_FLAG_RESOURCE_FORK_UNKNOWN 0x00000010U
/* Backend-neutral storage for HFS+ hard-link fidelity.  A placeholder names
 * another object's data fork through source_reference; backing objects own
 * the actual bytes.  INTERNAL_METADATA must never become client output. */
#define METADATA_INDEX_OBJECT_FLAG_HARDLINK_PLACEHOLDER 0x00000020U
#define METADATA_INDEX_OBJECT_FLAG_HARDLINK_BACKING 0x00000040U
#define METADATA_INDEX_OBJECT_FLAG_INTERNAL_METADATA 0x00000080U

#define METADATA_INDEX_FORK_DATA 1U
#define METADATA_INDEX_FORK_RESOURCE 2U
#define METADATA_INDEX_FORK_FLAG_COMPLETE 0x0001U
#define METADATA_INDEX_FORK_FLAG_TRUNCATED 0x0002U

#define METADATA_INDEX_PROVENANCE_LIVE_NTFS_MFT 1U
#define METADATA_INDEX_PROVENANCE_NTFS_I30 2U
#define METADATA_INDEX_PROVENANCE_NTFS_SALVAGE 3U
#define METADATA_INDEX_PROVENANCE_LIVE_HFSPLUS_CATALOG 4U
#define METADATA_INDEX_PROVENANCE_HFSPLUS_SALVAGE 5U
#define METADATA_INDEX_PROVENANCE_INFERRED_RAW 6U

typedef enum {
    METADATA_INDEX_BACKEND_NONE = 0,
    METADATA_INDEX_BACKEND_NTFS = 1,
    METADATA_INDEX_BACKEND_HFSPLUS = 2,
    METADATA_INDEX_BACKEND_EXFAT = 3
} MetadataIndexBackend;

typedef struct {
    uint32_t backend_kind;
    uint32_t block_size;
    uint64_t source_size;
    uint64_t container_offset;
    uint64_t volume_offset;
    uint64_t volume_size;
    uint64_t identity_primary;
    uint64_t identity_secondary;
    uint8_t uuid[16];
} MetadataIndexVolumeIdentity;

typedef struct {
    uint64_t object_key;
    uint32_t best_link_row;
    uint32_t first_fork_row;
    uint32_t fork_count;
    uint32_t flags;
    uint64_t source_reference;
    uint64_t create_time;
    uint64_t modify_time;
} MetadataIndexObject;

typedef struct {
    uint64_t link_key;
    uint64_t object_key;
    uint64_t parent_object_key;
    uint64_t string_offset;
    uint32_t string_length;
    uint8_t namespace_kind;
    uint8_t flags;
    uint8_t provenance;
    uint8_t confidence;
} MetadataIndexLink;

typedef struct {
    uint64_t object_key;
    uint64_t logical_size;
    uint64_t allocated_size;
    uint64_t first_extent_row;
    uint32_t extent_count;
    uint16_t fork_kind;
    uint16_t flags;
} MetadataIndexFork;

typedef struct {
    uint64_t physical_start;
    uint64_t logical_start;
    uint64_t byte_length;
} MetadataIndexExtent;

typedef struct {
    uint64_t object_key;
    uint64_t physical_row;
    uint32_t fork_row;
    uint32_t extent_ordinal;
    uint64_t physical_start;
    uint64_t physical_end;
    uint64_t logical_position;
} MetadataIndexPhysicalMatch;

typedef struct {
    MetadataIndexPhysicalMatch best_match;
    MetadataIndexFork fork;
    uint64_t owner_count;
    int has_owner;
    int unique_owner;
    int complete_data_fork;
    int exact_file_start;
} MetadataIndexCandidateContext;

typedef struct {
    uint64_t object_count;
    uint64_t link_count;
    uint64_t fork_count;
    uint64_t extent_count;
    uint64_t physical_count;
    uint64_t string_bytes;
} MetadataIndexStats;

/*
 * Identifies the row-addressed part of an index.  Assembly checkpoints may
 * be reused across generations only when this value matches exactly; links,
 * strings and reconstructed paths are deliberately not part of it.
 */
typedef struct {
    uint64_t fork_count;
    uint64_t extent_count;
    uint64_t physical_count;
    uint32_t forks_crc32;
    uint32_t extents_crc32;
    uint32_t physical_crc32;
} MetadataIndexLayoutFingerprint;

typedef struct MetadataIndexWriter MetadataIndexWriter;
typedef struct MetadataIndexReader MetadataIndexReader;
typedef struct MetadataIndexSequentialMeter MetadataIndexSequentialMeter;

typedef int (*MetadataIndexSequentialDeliveryFn)(
    const MetadataIndexPhysicalMatch *match,
    uint64_t physical_start,
    uint64_t physical_end,
    void *context
);

typedef struct {
    uint64_t ranges_observed;
    uint64_t source_bytes_observed;
    uint64_t source_gap_bytes;
    uint64_t duplicate_or_backward_ranges;
    uint64_t extent_intersections;
    uint64_t extent_delivery_bytes;
    uint64_t extents_total;
    uint64_t extents_touched;
    uint64_t extents_complete;
    uint64_t forks_total;
    uint64_t forks_touched;
    uint64_t forks_complete;
    uint64_t forks_empty_complete;
    uint64_t forks_incomplete_runlist;
} MetadataIndexSequentialStats;

typedef struct {
    int (*stop_requested)(void *context);
    int (*path_write_allowed)(const char *path, void *context);
    int (*finalize_path)(const char *path, void *context);
    void *context;
} MetadataIndexWriterOptions;

/* index_dir is the directory containing manifest.bin and generation dirs. */
int metadata_index_writer_create(
    const char *index_dir,
    const MetadataIndexVolumeIdentity *identity,
    MetadataIndexWriter **writer_out
);
int metadata_index_writer_create_with_options(
    const char *index_dir,
    const MetadataIndexVolumeIdentity *identity,
    const MetadataIndexWriterOptions *options,
    MetadataIndexWriter **writer_out
);

/* Strings are raw, length-delimited UTF-8 and need not be NUL terminated. */
int metadata_index_writer_append_string(
    MetadataIndexWriter *writer,
    const void *utf8,
    uint32_t length,
    uint64_t *offset_out
);
int metadata_index_writer_append_object(
    MetadataIndexWriter *writer,
    const MetadataIndexObject *row
);
int metadata_index_writer_append_link(
    MetadataIndexWriter *writer,
    const MetadataIndexLink *row
);
int metadata_index_writer_append_fork(
    MetadataIndexWriter *writer,
    const MetadataIndexFork *row
);
int metadata_index_writer_append_extent(
    MetadataIndexWriter *writer,
    const MetadataIndexExtent *row
);

/*
 * Builds children.idx and physical.idx, validates all row references, then
 * publishes the completed generation by atomically replacing manifest.bin.
 * On success or failure the writer is consumed.
 */
int metadata_index_writer_commit(MetadataIndexWriter *writer);
void metadata_index_writer_abort(MetadataIndexWriter *writer);

int metadata_index_reader_open(
    const char *index_dir,
    MetadataIndexReader **reader_out
);
/* Opens a retained immutable generation without changing the manifest. */
int metadata_index_reader_open_generation(
    const char *index_dir,
    uint64_t generation,
    MetadataIndexReader **reader_out
);
/* Fails with ESTALE unless every identity/geometry field matches exactly. */
int metadata_index_reader_open_expected(
    const char *index_dir,
    const MetadataIndexVolumeIdentity *expected_identity,
    MetadataIndexReader **reader_out
);
void metadata_index_reader_close(MetadataIndexReader *reader);

const MetadataIndexVolumeIdentity *metadata_index_reader_volume(
    const MetadataIndexReader *reader
);
uint64_t metadata_index_reader_generation(const MetadataIndexReader *reader);
void metadata_index_reader_get_stats(
    const MetadataIndexReader *reader,
    MetadataIndexStats *stats_out
);
int metadata_index_reader_get_layout_fingerprint(
    const MetadataIndexReader *reader,
    MetadataIndexLayoutFingerprint *fingerprint_out
);
int metadata_index_reader_get_object(
    const MetadataIndexReader *reader,
    uint64_t object_key,
    MetadataIndexObject *object_out
);
int metadata_index_reader_get_object_by_row(
    const MetadataIndexReader *reader,
    uint64_t object_row,
    MetadataIndexObject *object_out
);
int metadata_index_reader_get_fork_by_row(
    const MetadataIndexReader *reader,
    uint32_t fork_row,
    MetadataIndexFork *fork_out
);
int metadata_index_reader_get_fork_first_physical(
    const MetadataIndexReader *reader,
    uint32_t fork_row,
    uint64_t *physical_start_out
);

/*
 * Finds every allocated extent containing physical_offset.  best_out is the
 * most specific deterministic match (shortest extent, then lowest row).
 * match_count_out receives the full overlap count, including best_out.
 * Returns 1 when matched, 0 when unmatched, and -1 on invalid input.
 */
int metadata_index_reader_lookup_physical(
    const MetadataIndexReader *reader,
    uint64_t physical_offset,
    MetadataIndexPhysicalMatch *best_out,
    size_t *match_count_out
);

/*
 * Builds one reusable ownership decision for a raw-format candidate. A
 * physical overlap is contextual evidence; only a unique, complete data fork
 * is marked trusted. Returns 1 with an owner, 0 without one, or -1 on error.
 */
int metadata_index_reader_get_candidate_context(
    const MetadataIndexReader *reader,
    uint64_t physical_offset,
    MetadataIndexCandidateContext *context_out
);

/* Exact overlap check intended for exporter/backend equivalence tests. */
int metadata_index_reader_offset_has_object(
    const MetadataIndexReader *reader,
    uint64_t physical_offset,
    uint64_t object_key
);

/* Reconstructs the selected best-link path. Returns 0 or -1 (errno set). */
int metadata_index_reader_reconstruct_path(
    const MetadataIndexReader *reader,
    uint64_t object_key,
    char *path_out,
    size_t path_capacity
);

/*
 * Measurement-only monotonic extent fan-out. It records how source byte
 * ranges would intersect metadata extents and predicts complete forks, but it
 * never opens or writes a recovery output.
 */
int metadata_index_sequential_meter_create(
    const MetadataIndexReader *reader,
    MetadataIndexSequentialMeter **meter_out
);
int metadata_index_sequential_meter_observe(
    MetadataIndexSequentialMeter *meter,
    uint64_t range_start,
    uint64_t range_end
);
int metadata_index_sequential_meter_observe_with_delivery(
    MetadataIndexSequentialMeter *meter,
    uint64_t range_start,
    uint64_t range_end,
    MetadataIndexSequentialDeliveryFn delivery,
    void *delivery_context
);
void metadata_index_sequential_meter_get_stats(
    const MetadataIndexSequentialMeter *meter,
    MetadataIndexSequentialStats *stats_out
);
void metadata_index_sequential_meter_destroy(MetadataIndexSequentialMeter *meter);

#ifdef __cplusplus
}
#endif

#endif
