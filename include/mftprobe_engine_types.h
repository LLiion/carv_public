#ifndef MFTPROBE_ENGINE_TYPES_H
#define MFTPROBE_ENGINE_TYPES_H

#include "mft_runlist.h"
#include "ddrescue_map.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define RECORD_SIZE 1024U
#define NAME_MAX_LEN 256U
#define PATH_MAX_LEN 2048U
#define RECOVERY_TARGET_MAX_RUNS MFT_ENTRY_MAX_RUNS
#define RECOVERY_FORMAT_MAX 128U
#define FORMAT_NAME_MAX 64U
#define FORMAT_EXTENSION_MAX 16U
#define FORMAT_EXTENSION_ALIAS_MAX 32U
#define FORMAT_BLOB_START_MAX 32U
#define MAX_NTFS_VOLUMES 32U
#define MFT_VOLUME_INDEX_NONE UINT32_MAX

#define RECOVERY_CATEGORY_IMAGE (1U << 0)
#define RECOVERY_CATEGORY_VIDEO (1U << 1)
#define RECOVERY_CATEGORY_DOCUMENT (1U << 2)
#define RECOVERY_CATEGORY_AUDIO (1U << 3)
#define RECOVERY_CATEGORY_ARCHIVE (1U << 4)
#define RECOVERY_CATEGORY_OTHER (1U << 5)
#define RECOVERY_CATEGORY_RAW (1U << 6)
#define RECOVERY_CATEGORY_LIBRARY (1U << 7)
#define RECOVERY_CATEGORY_ALL \
    (RECOVERY_CATEGORY_IMAGE | \
     RECOVERY_CATEGORY_VIDEO | \
     RECOVERY_CATEGORY_DOCUMENT | \
     RECOVERY_CATEGORY_AUDIO | \
     RECOVERY_CATEGORY_ARCHIVE | \
     RECOVERY_CATEGORY_OTHER | \
     RECOVERY_CATEGORY_RAW | \
     RECOVERY_CATEGORY_LIBRARY)

typedef struct MftEntry {
    uint64_t offset;
    int record;
    int raw_record;
    uint64_t base_record_ref;
    uint16_t base_record_seq;
    uint64_t parent;
    uint32_t family;
    uint16_t flags;
    char name[NAME_MAX_LEN];
    uint8_t name_namespace;
    char created[32];
    uint64_t created_filetime;
    int has_data;
    int resident;
    int64_t data_offset;
    uint64_t data_size;
    uint64_t data_low_vcn;
    uint64_t first_lcn;
    uint64_t run_clusters;
    uint64_t run_count;
    uint64_t run_total_clusters;
    uint64_t max_lcn_end;
    size_t stored_run_count;
    int run_truncated;
    MftDataRun runs[MFT_ENTRY_MAX_RUNS];
    uint32_t volume_index;
    uint64_t volume_offset;
    uint64_t volume_size;
    uint64_t volume_cluster_size;
    uint64_t volume_serial;
} MftEntry;

typedef struct RecordIndex RecordIndex;

typedef struct MftTable {
    MftEntry *items;
    size_t count;
    size_t capacity;
    RecordIndex *record_index;
    size_t record_index_count;
    int record_index_dirty;
    pthread_mutex_t mutex;
} MftTable;

struct RecordIndex {
    int record;
    uint32_t volume_index;
    uint32_t family;
    size_t index;
};

typedef struct PathListIndexSlot {
    uint64_t hash;
    size_t index;
    int used;
} PathListIndexSlot;

typedef struct PathList {
    char **items;
    size_t count;
    size_t capacity;
    PathListIndexSlot *index_slots;
    size_t index_capacity;
    size_t index_count;
} PathList;

typedef enum RecoveryValidatorId {
    RECOVERY_VALIDATOR_NONE = 0,
    RECOVERY_VALIDATOR_JPEG = 1,
    RECOVERY_VALIDATOR_RIFF = 2,
    RECOVERY_VALIDATOR_PDF = 3,
    RECOVERY_VALIDATOR_SQLITE = 4
} RecoveryValidatorId;

typedef struct RecoveryValidatorState {
    unsigned char tail[64];
    size_t tail_len;
} RecoveryValidatorState;

typedef struct RecoveryRun {
    uint64_t abs_offset;
    uint64_t byte_length;
} RecoveryRun;

typedef struct RecoveryFormat {
    uint32_t format_id;
    const char *name;
    const char *default_extension;
    const char *const *extensions;
    size_t extension_count;
    RecoveryValidatorId validator_id;
    uint32_t category_mask;
    unsigned char blob_start[FORMAT_BLOB_START_MAX];
    size_t blob_start_length;
} RecoveryFormat;

typedef struct RecoveryOrder {
    const RecoveryFormat *formats;
    size_t count;
} RecoveryOrder;

typedef enum RecoveryTargetState {
    TARGET_PENDING = 0,
    TARGET_ACTIVE,
    TARGET_QUEUED,
    TARGET_DONE,
    TARGET_MISSED,
    TARGET_SKIPPED,
    TARGET_DEFERRED
} RecoveryTargetState;

typedef struct RecoveryTarget {
    uint32_t format_id;
    RecoveryValidatorId validator_id;
    char extension[16];
    uint64_t abs_offset;
    uint64_t size;
    uint64_t expected_size;
    uint64_t remaining;
    uint64_t next_offset;
    RecoveryRun runs[RECOVERY_TARGET_MAX_RUNS];
    size_t run_count;
    size_t run_index;
    int run_truncated;
    int record;
    uint32_t family;
    time_t created_unix;
    RecoveryTargetState state;
    char source_path[PATH_MAX_LEN];
    char output_path[PATH_MAX_LEN];
    unsigned char blob_start[FORMAT_BLOB_START_MAX];
    size_t blob_start_length;
    RecoveryValidatorState validator_state;
    FILE *file;
    char last_error[128];
} RecoveryTarget;

typedef struct RecoveryTargetIndexSlot {
    uint32_t format_id;
    int record;
    uint32_t family;
    uint64_t abs_offset;
    size_t index;
    int used;
} RecoveryTargetIndexSlot;

typedef struct RecoveryOutputIndexSlot {
    uint32_t format_id;
    uint64_t abs_offset;
    uint64_t path_hash;
    size_t index;
    int used;
} RecoveryOutputIndexSlot;

typedef struct RecoveryPlan {
    RecoveryTarget *items;
    size_t count;
    size_t capacity;
    size_t scheduler_index;
    int scheduler_dirty;
    RecoveryTargetIndexSlot *target_index_slots;
    size_t target_index_capacity;
    size_t target_index_count;
    int target_index_dirty;
    RecoveryOutputIndexSlot *output_index_slots;
    size_t output_index_capacity;
    size_t output_index_count;
    int output_index_dirty;
    uint64_t miss_before_offset;
    int have_miss_before_offset;
    uint64_t stream_end_offset;
    int have_stream_end_offset;
    size_t recovered;
    size_t missed;
    size_t skipped;
    size_t deferred;
    size_t refresh_count;
    size_t last_refresh_entries;
    double refresh_total_seconds;
    double refresh_max_seconds;
    pthread_mutex_t mutex;
} RecoveryPlan;

typedef struct RecoveryWriteJob {
    uint32_t format_id;
    RecoveryValidatorId validator_id;
    char extension[16];
    uint64_t abs_offset;
    uint64_t size;
    uint64_t expected_size;
    uint64_t chunk_offset;
    size_t data_len;
    RecoveryRun runs[RECOVERY_TARGET_MAX_RUNS];
    size_t run_count;
    int run_truncated;
    int record;
    uint32_t family;
    time_t created_unix;
    int first_chunk;
    int last_chunk;
    char source_path[PATH_MAX_LEN];
    char output_path[PATH_MAX_LEN];
    unsigned char blob_start[FORMAT_BLOB_START_MAX];
    size_t blob_start_length;
    unsigned char *data;
} RecoveryWriteJob;

typedef struct RecoveryWriteQueue {
    RecoveryWriteJob *items;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    size_t max_count;
    int done;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} RecoveryWriteQueue;

typedef struct NtfsGeometry {
    int valid;
    uint64_t volume_offset;
    uint64_t volume_size;
    uint64_t cluster_size;
    uint64_t volume_serial;
    uint64_t mft_lcn;
    uint64_t mft_mirror_lcn;
    uint64_t mft_abs_offset;
    uint64_t mft_mirror_abs_offset;
    uint32_t mft_record_size;
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    int is_basic_data;
} NtfsGeometry;

typedef struct Config {
    const char *image_path;
    const char *out_dir;
    uint64_t limit;
    uint64_t source_size;
    uint64_t start_offset;
    int resume_requested;
    int resume_active;
    int auto_recover_missed;
    int only_recover_missed;
    const RecoveryOrder *recovery_order;
    RecoveryOrder selected_recovery_order;
    RecoveryFormat selected_recovery_formats[RECOVERY_FORMAT_MAX];
    RecoveryOrder loaded_recovery_order;
    RecoveryFormat loaded_recovery_formats[RECOVERY_FORMAT_MAX];
    char loaded_format_names[RECOVERY_FORMAT_MAX][FORMAT_NAME_MAX];
    char loaded_format_extensions[RECOVERY_FORMAT_MAX][FORMAT_EXTENSION_MAX];
    char loaded_format_aliases[RECOVERY_FORMAT_MAX][FORMAT_EXTENSION_ALIAS_MAX][FORMAT_EXTENSION_MAX];
    const char *loaded_format_extension_lists[RECOVERY_FORMAT_MAX][FORMAT_EXTENSION_ALIAS_MAX];
    NtfsGeometry ntfs;
    NtfsGeometry ntfs_volumes[MAX_NTFS_VOLUMES];
    size_t ntfs_volume_count;
    uint64_t observation_run_id;
    char source_id[128];
    char state_path[PATH_MAX_LEN];
    size_t root_scope_count;
    char root_scopes[64][NAME_MAX_LEN];
    uint8_t root_scope_is_and_expression[64];
    int root_scope_defaulted;
    int has_deleted_filter;
    int deleted_value;
    int has_date_filter;
    int date_start_yyyymmdd;
    int date_end_yyyymmdd;
    int generic_file_targets;
    /* Non-NULL only for the isolated Hypersafe partial-image preview path. */
    const DdrescueMap *coverage_map;
} Config;

#endif
