#ifndef NTFS_HYPERSAFE_H
#define NTFS_HYPERSAFE_H

#include <stddef.h>
#include <stdint.h>

#include "mft_runlist.h"

#define NTFS_HYPERSAFE_STATUS_TEXT_MAX 48U
#define NTFS_HYPERSAFE_DETAIL_TEXT_MAX 256U
#define NTFS_HYPERSAFE_PATH_TEXT_MAX 4096U
#define NTFS_HYPERSAFE_DEVICE_ID_TEXT_MAX 512U

typedef enum NtfsHypersafeIdentityDecision {
    NTFS_HYPERSAFE_IDENTITY_MISMATCH = 0,
    NTFS_HYPERSAFE_IDENTITY_MATCH = 1,
    NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE = 2
} NtfsHypersafeIdentityDecision;

typedef struct NtfsHypersafeVolume {
    uint64_t volume_offset;
    uint64_t volume_size;
    uint64_t cluster_size;
    uint64_t volume_serial;
    uint64_t mft_abs_offset;
    uint64_t mft_mirror_abs_offset;
    uint64_t mft_data_size;
    uint32_t mft_record_size;
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    int is_basic_data;
} NtfsHypersafeVolume;

typedef struct NtfsHypersafeResult {
    uint64_t source_size;
    uint32_t source_logical_sector_size;
    NtfsHypersafeVolume volume;
    MftDataRun mft_runs[MFT_ENTRY_MAX_RUNS];
    size_t mft_run_count;
    int mft_run_truncated;
    uint64_t mft_requested_bytes;
    uint64_t mft_finished_bytes;
    char status[NTFS_HYPERSAFE_STATUS_TEXT_MAX];
    char detail[NTFS_HYPERSAFE_DETAIL_TEXT_MAX];
    char source_path[NTFS_HYPERSAFE_PATH_TEXT_MAX];
    char image_path[NTFS_HYPERSAFE_PATH_TEXT_MAX];
    char map_path[NTFS_HYPERSAFE_PATH_TEXT_MAX];
    char linux_wwn_id[NTFS_HYPERSAFE_DEVICE_ID_TEXT_MAX];
    char linux_ata_id[NTFS_HYPERSAFE_DEVICE_ID_TEXT_MAX];
    char linux_usb_id[NTFS_HYPERSAFE_DEVICE_ID_TEXT_MAX];
} NtfsHypersafeResult;

typedef int (*NtfsHypersafeAcquireRangeFn)(
    void *context,
    uint64_t start,
    uint64_t length,
    const char *stage,
    const char *detail
);

uint64_t ntfs_hypersafe_source_size(const char *path);
uint32_t ntfs_hypersafe_source_logical_sector_size(const char *path);

int ntfs_hypersafe_bootstrap(
    const char *source_path,
    const char *image_path,
    const char *map_path,
    const char *status_path,
    NtfsHypersafeAcquireRangeFn acquire_range,
    void *acquire_context,
    NtfsHypersafeResult *out_result
);

int ntfs_hypersafe_load_status(
    const char *status_path,
    NtfsHypersafeResult *out_result
);

/* Save the minimal identity contract used before a complete image exists.
 * The rescued head sample in the shared ddrescue map supplies the actual
 * identity proof until an NTFS volume serial has been discovered. */
int ntfs_hypersafe_write_identity_status(
    const char *source_path,
    const char *image_path,
    const char *map_path,
    const char *status_path
);

/* Compare strong Linux block-device identifiers saved at first contact.
 * WWN and ATA IDs are authoritative; a USB bridge ID is diagnostic only.
 * UNAVAILABLE means that no strong saved/current pair could be compared. */
NtfsHypersafeIdentityDecision ntfs_hypersafe_compare_linux_source_identity(
    const char *source_path,
    const NtfsHypersafeResult *expected
);

/* Backfill Linux identifiers after an older state file has been verified by
 * content, so later reconnects no longer depend on one readable sector. */
int ntfs_hypersafe_refresh_linux_identity_status(
    const char *status_path,
    const char *source_path
);

/* Trust an explicitly selected source once when resuming legacy state that
 * predates Linux device identifiers. Existing WWN/ATA conditions are never
 * overwritten; they are compared normally instead. */
NtfsHypersafeIdentityDecision
ntfs_hypersafe_bind_explicit_linux_source_identity(
    const char *status_path,
    const char *source_path,
    const char *image_path,
    const char *map_path
);

/* Verify a freshly acquired NTFS boot sector against a saved preview before
 * an existing image/map pair is allowed to grow. */
int ntfs_hypersafe_image_matches_status(
    const char *image_path,
    const char *map_path,
    const NtfsHypersafeResult *expected
);

NtfsHypersafeIdentityDecision ntfs_hypersafe_image_identity_decision(
    const char *image_path,
    const char *map_path,
    const NtfsHypersafeResult *expected
);

/* Compare one already rescued, non-trivial head sample with a separately
 * acquired probe.  This protects resume even if interruption happened before
 * the NTFS boot sector and serial could be saved. */
int ntfs_hypersafe_image_sample_matches(
    const char *saved_image_path,
    const char *saved_map_path,
    const char *probe_image_path,
    const char *probe_map_path,
    uint64_t start,
    size_t length
);

NtfsHypersafeIdentityDecision ntfs_hypersafe_image_sample_identity_decision(
    const char *saved_image_path,
    const char *saved_map_path,
    const char *probe_image_path,
    const char *probe_map_path,
    uint64_t start,
    size_t length
);

#endif
