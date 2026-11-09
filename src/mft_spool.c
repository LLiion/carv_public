#define _POSIX_C_SOURCE 200809L

#include "mft_spool.h"

#include "app.h"
#include "config.h"
#include "fs_backend.h"
#include "log.h"
#include "mft_background.h"
#include "mft.h"
#include "mftprobe_format_api.h"
#include "recovery_runner.h"
#include "scan_state.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <strings.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#define MFT_SPOOL_OUTPUT_MOUNT_GRACE_SECONDS 5U

#if defined(__GNUC__) && !defined(__clang__)
#define GCC_ICE_WORKAROUND_O0 __attribute__((optimize("O0")))
#else
#define GCC_ICE_WORKAROUND_O0
#endif

#if defined(__GNUC__) || defined(__clang__)
#define MFT_SPOOL_PACKED __attribute__((packed))
#define MFT_SPOOL_MAYBE_UNUSED __attribute__((unused))
#else
#define MFT_SPOOL_PACKED
#define MFT_SPOOL_MAYBE_UNUSED
#endif

#define MFT_SPOOL_FILE_MAGIC "C26SPL1"
#define MFT_SPOOL_INDEX_MAGIC "C26IDX1"
#define MFT_SPOOL_STATE_MAGIC "C26SPS1"
#define MFT_SPOOL_FILE_VERSION 1U
#define MFT_SPOOL_INDEX_VERSION 1U
#define MFT_SPOOL_STATE_VERSION 1U
#define MFT_SPOOL_SEGMENT_PROBE 1U
#define MFT_SPOOL_SEGMENT_RECOVERED 2U
#define MFT_SPOOL_INDEX_RECORD 1U
#define MFT_SPOOL_INDEX_RANGE 2U
#define MFT_SPOOL_STATE_FLAG_HAS_NTFS_GEOMETRY 0x00000001U
#define MFT_SPOOL_SEGMENT_LIMIT_BYTES (128U * 1024U * 1024U)
#define MFT_SPOOL_MAX_RECOVERED_PATH 1023U
#define MFT_SPOOL_PROBE_FLUSH_INTERVAL 64U
#define MFT_SPOOL_RECOVERED_FLUSH_INTERVAL 8U
#define MFT_SPOOL_MAX_INFER_GAP_RECORDS 65536ULL
#define MFT_SPOOL_BACKGROUND_BUILD_INTERVAL_SECONDS 5
#define MFT_SPOOL_BACKGROUND_RECONCILE_INTERVAL_SECONDS 1
#define MFT_SPOOL_BACKGROUND_PROBE_REBUILD_DELTA_BYTES (8ULL * 1024ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_RECOVERED_RECONCILE_DELTA_BYTES (64ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_RECONCILE_BATCH_EVENTS 2048U
#define MFT_SPOOL_BACKGROUND_REPAIR_BATCH_EVENTS 128U
#define MFT_SPOOL_BACKGROUND_NAMING_PRESSURE_MIN_UNIDENT 256U
#define MFT_SPOOL_BACKGROUND_PRESSURE_BUILD_INTERVAL_SECONDS 2
#define MFT_SPOOL_BACKGROUND_PRESSURE_PROBE_REBUILD_DELTA_BYTES (2ULL * 1024ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_PRESSURE_RECONCILE_DELTA_BYTES (16ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_PRESSURE_RECONCILE_BATCH_EVENTS 8192U
#define MFT_SPOOL_BACKGROUND_PRESSURE_REPAIR_INTERVAL_SECONDS 3
#define MFT_SPOOL_BACKGROUND_PRESSURE_REPAIR_DELTA_BYTES (256ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_SECONDS 2
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_MIN_UNIDENT 8U
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_BUILD_INTERVAL_SECONDS 1
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_RECONCILE_INTERVAL_SECONDS 1
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_REPAIR_INTERVAL_SECONDS 1
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_PROBE_REBUILD_DELTA_BYTES (1ULL * 1024ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_RECONCILE_DELTA_BYTES (4ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_REPAIR_DELTA_BYTES (64ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_RECONCILE_BATCH_EVENTS 16384U
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_REPAIR_BATCH_EVENTS 512U
#define MFT_SPOOL_BACKGROUND_SLOW_SCAN_SWEEP_INTERVAL_SECONDS 20
#define MFT_SPOOL_FINAL_RECONCILE_MAX_PASSES 8U
#define MFT_SPOOL_BACKGROUND_STATS_REFRESH_INTERVAL_SECONDS 5
#define MFT_SPOOL_BACKGROUND_STALL_SECONDS 5
#define MFT_SPOOL_BACKGROUND_IDLE_SWEEP_INTERVAL_SECONDS 5
#define MFT_SPOOL_BACKGROUND_IDLE_SWEEP_MIN_UNIDENT 64U
#define MFT_SPOOL_BACKGROUND_CONSERVATIVE_BUILD_INTERVAL_SECONDS 15
#define MFT_SPOOL_BACKGROUND_CONSERVATIVE_RECONCILE_INTERVAL_SECONDS 5
#define MFT_SPOOL_BACKGROUND_CONSERVATIVE_REPAIR_INTERVAL_SECONDS 5
#define MFT_SPOOL_BACKGROUND_CONSERVATIVE_PROBE_REBUILD_DELTA_BYTES (32ULL * 1024ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_CONSERVATIVE_RECONCILE_DELTA_BYTES (1ULL * 1024ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_CONSERVATIVE_REPAIR_DELTA_BYTES (1ULL * 1024ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_CONSERVATIVE_RECONCILE_BATCH_EVENTS 256U
#define MFT_SPOOL_BACKGROUND_CONSERVATIVE_REPAIR_BATCH_EVENTS 32U
#define MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_MIN_UNIDENT 64U
#define MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_INTERVAL_SECONDS 30
#define MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_IDLE_INTERVAL_SECONDS 120
#define MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_PROBE_DELTA_BYTES (8ULL * 1024ULL * 1024ULL)
#define MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_RECOVERED_DELTA_BYTES (256ULL * 1024ULL)

typedef struct MFT_SPOOL_PACKED {
    char magic[8];
    uint16_t version;
    uint16_t kind;
    uint32_t header_size;
    uint32_t segment_number;
    uint32_t reserved0;
    uint64_t created_unix;
    uint64_t record_count;
    uint64_t payload_bytes;
    uint64_t next_sequence;
    uint32_t header_crc32;
} MftSpoolFileHeader;

typedef struct MFT_SPOOL_PACKED {
    uint32_t magic;
    uint16_t version;
    uint16_t kind;
    uint32_t total_size;
    uint32_t payload_size;
    uint32_t payload_crc32;
    uint64_t sequence;
    uint32_t header_crc32;
} MftSpoolRecordHeader;

typedef struct MFT_SPOOL_PACKED {
    uint64_t family_id;
    uint64_t record_offset;
    int32_t record;
    int32_t raw_record;
    uint64_t parent;
    uint16_t parent_seq;
    uint16_t flags;
    uint32_t record_used_size;
    uint32_t record_allocated_size;
    uint64_t created_filetime;
    int64_t data_abs_offset;
    int64_t data_end_abs_offset;
    uint64_t data_size;
    uint64_t run_byte_length;
    uint64_t first_lcn;
    uint64_t run_clusters;
    uint8_t has_data;
    uint8_t resident;
    uint8_t reserved0[6];
    char name[MFT_PROBE_NAME_MAX];
} MftSpoolProbePayloadV1;

typedef struct MFT_SPOOL_PACKED {
    MftSpoolProbePayloadV1 base;
    uint64_t run_count;
    uint64_t run_total_clusters;
    uint64_t max_lcn_end;
    uint32_t stored_run_count;
    uint32_t run_truncated;
} MftSpoolProbePayloadFixed;

typedef struct MFT_SPOOL_PACKED {
    uint64_t lcn;
    uint64_t clusters;
    int64_t abs_offset;
    uint64_t byte_length;
} MftSpoolProbeRunPayload;

typedef struct {
    MftSpoolProbePayloadFixed fixed;
    MftSpoolProbeRunPayload runs[MFT_ENTRY_MAX_RUNS];
} MftSpoolProbePayload;

typedef struct MFT_SPOOL_PACKED {
    int64_t abs_offset;
    uint16_t path_length;
    uint16_t reserved0;
    uint32_t reserved1;
} MftSpoolRecoveredPayloadHeader;

typedef struct MFT_SPOOL_PACKED {
    char magic[8];
    uint16_t version;
    uint16_t kind;
    uint32_t header_size;
    uint32_t row_size;
    uint64_t row_count;
    uint32_t header_crc32;
} MftSpoolIndexHeader;

typedef struct MFT_SPOOL_PACKED {
    char magic[8];
    uint16_t version;
    uint16_t reserved0;
    uint32_t header_size;
    uint32_t flags;
    uint32_t cluster_size;
    uint32_t record_size;
    int64_t partition_start;
    uint32_t header_crc32;
} MftSpoolStateHeader;

typedef struct MFT_SPOOL_PACKED {
    uint64_t family_id;
    int32_t record;
    uint32_t segment_number;
    uint64_t spool_record_offset;
} MftSpoolRecordIndexRow;

typedef struct MFT_SPOOL_PACKED {
    int64_t data_abs_offset;
    int64_t data_end_abs_offset;
    uint64_t family_id;
    int32_t record;
    uint32_t segment_number;
    uint64_t spool_record_offset;
    uint16_t flags;
    uint8_t resident;
    uint8_t reserved0;
} MftSpoolRangeIndexRow;

typedef struct {
    FILE *file;
    uint16_t kind;
    uint32_t segment_number;
    uint64_t record_count;
    uint64_t payload_bytes;
    uint64_t next_sequence;
    uint64_t current_size;
    uint64_t pending_flush_rows;
    char path[1024];
    int prepared;
} MftSpoolWriter;

typedef struct {
    uint32_t segment_number;
    int is_open;
    char path[1024];
} MftSpoolSegmentFile;

typedef struct {
    uint32_t segment_number;
    char path[1024];
    FILE *file;
} MftSpoolSegmentReader;

typedef struct {
    long long abs_offset;
    uint64_t ordinal;
    char *path;
} MftSpoolRecoveredEvent;

typedef struct {
    uint64_t checked;
    uint64_t moved;
    uint64_t complete_path_moves;
    uint64_t partial_path_moves;
    uint64_t parent_group_moves;
    uint64_t flat_name_moves;
    uint64_t skipped_no_path;
    uint64_t skipped_missing_source;
    uint64_t skipped_no_extension;
    uint64_t skipped_no_range_anchor;
    uint64_t skipped_no_exact_range_start;
    uint64_t skipped_no_context_path;
    uint64_t skipped_no_payload;
    uint64_t skipped_no_commit_candidate;
    uint64_t skipped_same_path;
    uint64_t rename_failures;
} MftSpoolRecoveredFirstStats;

typedef struct {
    uint32_t segment_number;
    uint64_t next_offset;
} MftSpoolSegmentCursor;

typedef struct {
    uint64_t record_count;
    uint64_t payload_bytes;
    uint64_t next_sequence;
    uint64_t valid_size;
    int has_last_probe;
    MftSpoolProbePayload last_probe;
} MftSpoolValidateResult;

static int compare_segment_files(const void *left, const void *right);
static void free_recovered_events(MftSpoolRecoveredEvent *events, size_t event_count);
static int regular_file_exists(const char *path);
static void hydrate_probe_payload_geometry(MftSpoolProbePayload *payload);
static size_t reconcile_loaded_events(
    const MftSpoolRecordIndexRow *record_rows,
    size_t record_count,
    const MftSpoolRangeIndexRow *range_rows,
    const long long *range_prefix_max,
    size_t range_count,
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    MftSpoolRecoveredEvent *events,
    size_t event_count,
    MftSpoolRecoveredFirstStats *out_stats
);
static int build_unique_output_path_from_flat_name_local(
    char *out_path,
    size_t out_size,
    const char *directory,
    const char *name,
    const char *current_path
);
static int build_unique_output_path_from_flat_name_with_extension_local(
    char *out_path,
    size_t out_size,
    const char *directory,
    const char *name,
    const char *extension,
    const char *current_path
);
static int build_unique_context_path(
    char *out,
    size_t out_size,
    const char *relative_path,
    const char *current_path
);
static int build_recovered_path(
    char *out,
    size_t out_size,
    const char *relative_path
);
static int build_unique_partial_context_path_local(
    char *out_path,
    size_t out_size,
    const char *relative_path,
    const char *current_path
);
static int build_relative_path_for_record(
    const MftSpoolRecordIndexRow *record_rows,
    size_t record_count,
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    uint64_t family_id,
    int record,
    char *out,
    size_t out_size,
    int *out_complete,
    time_t *out_created_time
);

static char g_output_dir[1024] = "";
static char g_spool_dir[1024] = "";
static char g_index_dir[1024] = "";
static MftContextualOutputMode g_contextual_output_mode =
    MFT_CONTEXTUAL_OUTPUT_USERS_ONLY;
static int g_reset_existing_store = 0;
static int g_prepare_seen = 0;
static int g_spool_state_dirty = 1;

static int g_has_ntfs_geometry = 0;
static long long g_partition_start = 0;
static uint32_t g_cluster_size = 0;
static uint32_t g_record_size = MFT_PROBE_RECORD_SIZE;

static MftSpoolWriter g_probe_writer = {0};
static MftSpoolWriter g_recovered_writer = {0};

static uint64_t g_probe_family_count = 0;
static uint64_t g_probe_prev_offset = 0;
static int g_probe_prev_record = 0;
static int g_probe_have_prev = 0;

static size_t g_record_index_count = 0;
static size_t g_range_index_count = 0;
static uint64_t g_background_last_probe_bytes = 0;
static uint64_t g_background_last_recovered_bytes = 0;
static uint64_t g_background_last_index_probe_bytes = 0;
static uint64_t g_background_last_reconcile_recovered_bytes = 0;
static uint64_t g_background_last_repair_recovered_bytes = 0;
static time_t g_background_last_index_build = 0;
static time_t g_background_last_reconcile = 0;
static time_t g_background_last_repair = 0;
static MftSpoolSegmentCursor *g_probe_cursors = NULL;
static size_t g_probe_cursor_count = 0;
static int g_probe_cursors_initialized = 0;
static MftSpoolSegmentCursor *g_recovered_cursors = NULL;
static size_t g_recovered_cursor_count = 0;
static int g_recovered_cursors_initialized = 0;
static MftSpoolSegmentCursor *g_repair_cursors = NULL;
static size_t g_repair_cursor_count = 0;
static int g_repair_cursors_initialized = 0;
static int g_background_need_full_reconcile = 1;
static uint64_t g_live_renamed_outputs = 0;
static uint64_t g_live_repaired_outputs = 0;
static uint64_t g_live_recovered_outputs_current = 0;
static uint64_t g_live_named_outputs_current = 0;
static uint64_t g_live_unident_outputs_current = 0;
static uint64_t g_live_repair_pending_outputs = 0;
static uint64_t g_live_repair_queue_events = 0;
static unsigned long long g_live_scan_stalled_seconds = 0;
static uint64_t g_background_last_scan_offset = 0;
static time_t g_background_last_scan_change = 0;
static time_t g_background_last_foreground_activity = 0;
static unsigned long long g_background_last_stall_log_seconds = 0;
static int g_background_stall_watch_armed = 0;
static time_t g_background_last_idle_sweep = 0;
static time_t g_background_last_slow_scan_sweep = 0;
static time_t g_background_last_opportunistic_naming = 0;
static time_t g_background_last_live_stats_refresh = 0;
static uint64_t g_background_last_stats_recovered_bytes = 0;
static uint64_t g_background_last_stats_renamed_outputs = 0;
static uint64_t g_background_last_stats_repaired_outputs = 0;
static uint64_t g_background_last_opportunistic_probe_bytes = 0;
static uint64_t g_background_last_opportunistic_recovered_bytes = 0;
static uint64_t g_background_opportunistic_sweeps = 0;
static uint64_t g_background_opportunistic_renamed_outputs = 0;
static uint64_t g_background_opportunistic_zero_delta_sweeps = 0;
static uint64_t g_background_last_opportunistic_renamed_delta = 0;
static MftSpoolRecoveredFirstStats g_background_last_recovered_first_stats;
static int g_logged_no_range_reconcile_notice = 0;
static int g_suspend_stall_watch = 0;
static int g_background_conservative_mode = 0;
static MftSpoolBackgroundPhase g_live_background_phase =
    MFT_SPOOL_BACKGROUND_PHASE_IDLE;

typedef struct {
    uint64_t scan_offset;
    uint64_t recovered_bytes;
    uint64_t renamed_outputs;
    uint64_t repaired_outputs;
    uint64_t recovered_outputs_current;
    uint64_t named_outputs_current;
    uint64_t unident_outputs_current;
    uint64_t repair_pending_outputs;
    uint64_t repair_queue_events;
    size_t record_index_count;
    size_t range_index_count;
} MftSpoolProgressSnapshot;

static MftSpoolProgressSnapshot g_background_last_progress = {0};

#define MFT_SPOOL_FOREGROUND_ACTIVITY_GRACE_SECONDS 8

static uint32_t g_crc32_table[256];
static int g_crc32_ready = 0;

static int write_live_stats_file(void);

static void set_background_phase(MftSpoolBackgroundPhase phase, time_t now)
{
    if (g_live_background_phase == phase) {
        return;
    }

    if (now == (time_t)-1) {
        now = time(NULL);
    }

    g_live_background_phase = phase;
    g_live_scan_stalled_seconds = 0ULL;
    if (now != (time_t)-1) {
        g_background_last_scan_change = now;
    }
    (void)write_live_stats_file();
}

#define MFT_SPOOL_PROBE_PAYLOAD_V1_SIZE ((size_t)sizeof(MftSpoolProbePayloadV1))
#define MFT_SPOOL_PROBE_PAYLOAD_FIXED_SIZE ((size_t)sizeof(MftSpoolProbePayloadFixed))
#define MFT_SPOOL_PROBE_RUN_PAYLOAD_SIZE ((size_t)sizeof(MftSpoolProbeRunPayload))
#define MFT_SPOOL_PROBE_PAYLOAD_MAX_SIZE \
    (MFT_SPOOL_PROBE_PAYLOAD_FIXED_SIZE + MFT_ENTRY_MAX_RUNS * MFT_SPOOL_PROBE_RUN_PAYLOAD_SIZE)
#define MFT_SPOOL_RECOVERED_PAYLOAD_MAX_SIZE \
    (sizeof(MftSpoolRecoveredPayloadHeader) + MFT_SPOOL_MAX_RECOVERED_PATH + 32U)
#define MFT_SPOOL_MAX_RECORD_PAYLOAD_SIZE \
    ((MFT_SPOOL_PROBE_PAYLOAD_MAX_SIZE > MFT_SPOOL_RECOVERED_PAYLOAD_MAX_SIZE) ? \
        MFT_SPOOL_PROBE_PAYLOAD_MAX_SIZE : MFT_SPOOL_RECOVERED_PAYLOAD_MAX_SIZE)

_Static_assert(sizeof(MftSpoolFileHeader) == 60U, "unexpected spool header size");
_Static_assert(sizeof(MftSpoolRecordHeader) == 32U, "unexpected spool record header size");
_Static_assert(sizeof(MftSpoolProbePayloadV1) == 364U, "unexpected probe v1 payload size");
_Static_assert(sizeof(MftSpoolProbePayloadFixed) == 396U, "unexpected probe fixed payload size");
_Static_assert(sizeof(MftSpoolProbeRunPayload) == 32U, "unexpected probe run payload size");
_Static_assert(sizeof(MftSpoolRecoveredPayloadHeader) == 16U, "unexpected recovered payload header size");
_Static_assert(sizeof(MftSpoolStateHeader) == 40U, "unexpected spool state header size");

static int text_present(const char *text)
{
    return text != NULL && text[0] != '\0';
}

static int spool_output_mount_root_from_path_local(
    const char *path,
    char *out_root,
    size_t out_root_size
)
{
    if (out_root != NULL && out_root_size > 0U) {
        out_root[0] = '\0';
    }
    if (!text_present(path) || out_root == NULL || out_root_size == 0U) {
        return 0;
    }

    if (strncmp(path, "/media/", 7U) == 0) {
        const char *rest = path + 7U;
        const char *user_slash = strchr(rest, '/');
        const char *leaf_start;
        const char *leaf_slash;
        size_t root_len;

        if (user_slash == NULL || user_slash == rest || user_slash[1] == '\0') {
            return 0;
        }
        leaf_start = user_slash + 1;
        leaf_slash = strchr(leaf_start, '/');
        root_len = leaf_slash != NULL ? (size_t)(leaf_slash - path) : strlen(path);
        if (root_len == 0U || root_len >= out_root_size) {
            return 0;
        }
        memcpy(out_root, path, root_len);
        out_root[root_len] = '\0';
        return 1;
    }

    if (strncmp(path, "/Volumes/", 9U) == 0) {
        const char *leaf_start = path + 9U;
        const char *leaf_slash;
        size_t root_len;

        if (*leaf_start == '\0') {
            return 0;
        }
        leaf_slash = strchr(leaf_start, '/');
        root_len = leaf_slash != NULL ? (size_t)(leaf_slash - path) : strlen(path);
        if (root_len == 0U || root_len >= out_root_size) {
            return 0;
        }
        memcpy(out_root, path, root_len);
        out_root[root_len] = '\0';
        return 1;
    }

    return 0;
}

static int spool_parent_path_local(
    const char *path,
    char *out_parent,
    size_t out_parent_size
)
{
    const char *last_slash;
    size_t parent_len;

    if (out_parent != NULL && out_parent_size > 0U) {
        out_parent[0] = '\0';
    }
    if (!text_present(path) || out_parent == NULL || out_parent_size == 0U) {
        return 0;
    }

    last_slash = strrchr(path, '/');
    if (last_slash == NULL) {
        return 0;
    }
    if (last_slash == path) {
        return snprintf(out_parent, out_parent_size, "/") < (int)out_parent_size;
    }
    parent_len = (size_t)(last_slash - path);
    if (parent_len == 0U || parent_len >= out_parent_size) {
        return 0;
    }
    memcpy(out_parent, path, parent_len);
    out_parent[parent_len] = '\0';
    return 1;
}

static int spool_output_mount_root_is_live_local(const char *mount_root)
{
    char parent[PATH_MAX];
    struct stat mount_st;
    struct stat parent_st;

    if (!text_present(mount_root) ||
        stat(mount_root, &mount_st) != 0 ||
        !S_ISDIR(mount_st.st_mode) ||
        !spool_parent_path_local(mount_root, parent, sizeof(parent)) ||
        stat(parent, &parent_st) != 0) {
        return 0;
    }

    return mount_st.st_dev != parent_st.st_dev;
}

static int spool_output_path_write_guard_allows(
    const char *path,
    const char *operation
)
{
    char mount_root[PATH_MAX];
    unsigned int waited_seconds;
    static int warned = 0;

    if (!spool_output_mount_root_from_path_local(path, mount_root, sizeof(mount_root))) {
        return 1;
    }
    if (spool_output_mount_root_is_live_local(mount_root)) {
        return 1;
    }
    for (waited_seconds = 0U;
         waited_seconds < MFT_SPOOL_OUTPUT_MOUNT_GRACE_SECONDS;
         waited_seconds++) {
        sleep(1);
        if (spool_output_mount_root_is_live_local(mount_root)) {
            return 1;
        }
    }

    if (!warned) {
        warned = 1;
        log_error(
            "Refusing to %s under %s because %s is not a live mounted output volume; reconnect the output disk or resume using its new mount path before writing.",
            text_present(operation) ? operation : "write NTFS spool",
            path,
            mount_root
        );
    }
    return 0;
}

static void crc32_init(void)
{
    uint32_t polynomial = 0xEDB88320U;
    uint32_t i;

    if (g_crc32_ready) {
        return;
    }

    for (i = 0; i < 256U; i++) {
        uint32_t value = i;
        int bit;

        for (bit = 0; bit < 8; bit++) {
            if ((value & 1U) != 0U) {
                value = (value >> 1) ^ polynomial;
            } else {
                value >>= 1;
            }
        }
        g_crc32_table[i] = value;
    }

    g_crc32_ready = 1;
}

static uint32_t crc32_compute(const void *buffer, size_t length)
{
    const unsigned char *bytes = (const unsigned char *)buffer;
    uint32_t crc = 0xFFFFFFFFU;
    size_t i;

    crc32_init();

    for (i = 0; i < length; i++) {
        crc = (crc >> 8) ^ g_crc32_table[(crc ^ bytes[i]) & 0xFFU];
    }

    return crc ^ 0xFFFFFFFFU;
}

static int ensure_directory_recursive(const char *path)
{
    char temp[1024];
    size_t i;

    if (!text_present(path)) {
        return 0;
    }
    if (!spool_output_path_write_guard_allows(path, "create NTFS spool directory")) {
        return 0;
    }

    if (snprintf(temp, sizeof(temp), "%s", path) >= (int)sizeof(temp)) {
        return 0;
    }

    for (i = 1; temp[i] != '\0'; i++) {
        if (temp[i] != '/') {
            continue;
        }
        temp[i] = '\0';
        if (!spool_output_path_write_guard_allows(temp, "create NTFS spool directory")) {
            return 0;
        }
        if (temp[0] != '\0' && mkdir(temp, 0777) != 0 && errno != EEXIST) {
            return 0;
        }
        temp[i] = '/';
    }

    if (!spool_output_path_write_guard_allows(temp, "create NTFS spool directory")) {
        return 0;
    }
    if (mkdir(temp, 0777) != 0 && errno != EEXIST) {
        return 0;
    }

    return 1;
}

static int path_join(char *out, size_t out_size, const char *dir, const char *name)
{
    if (out == NULL || out_size == 0 || dir == NULL || name == NULL) {
        return 0;
    }

    return snprintf(out, out_size, "%s/%s", dir, name) < (int)out_size;
}

static void normalize_probe_payload_fallback(MftSpoolProbePayload *payload)
{
    if (payload == NULL) {
        return;
    }

    if (payload->fixed.stored_run_count == 0U &&
        payload->fixed.base.first_lcn > 0 &&
        payload->fixed.base.run_clusters > 0) {
        payload->fixed.run_count = payload->fixed.run_count == 0U ? 1U : payload->fixed.run_count;
        payload->fixed.run_total_clusters =
            payload->fixed.run_total_clusters == 0U
                ? payload->fixed.base.run_clusters
                : payload->fixed.run_total_clusters;
        payload->fixed.max_lcn_end =
            payload->fixed.max_lcn_end == 0U
                ? payload->fixed.base.first_lcn + payload->fixed.base.run_clusters
                : payload->fixed.max_lcn_end;
        payload->fixed.stored_run_count = 1U;
        payload->runs[0].lcn = payload->fixed.base.first_lcn;
        payload->runs[0].clusters = payload->fixed.base.run_clusters;
        payload->runs[0].abs_offset = payload->fixed.base.data_abs_offset;
        payload->runs[0].byte_length =
            payload->fixed.base.run_byte_length > 0
                ? payload->fixed.base.run_byte_length
                : (payload->fixed.base.data_end_abs_offset > payload->fixed.base.data_abs_offset
                    ? (uint64_t)(payload->fixed.base.data_end_abs_offset -
                                 payload->fixed.base.data_abs_offset)
                    : 0U);
    }

    hydrate_probe_payload_geometry(payload);
}

static int decode_probe_payload(
    const void *payload_bytes,
    size_t payload_size,
    MftSpoolProbePayload *out_payload
)
{
    const unsigned char *bytes = (const unsigned char *)payload_bytes;
    size_t run_bytes;
    size_t stored_run_count;

    if (payload_bytes == NULL || out_payload == NULL) {
        return 0;
    }

    memset(out_payload, 0, sizeof(*out_payload));

    if (payload_size == MFT_SPOOL_PROBE_PAYLOAD_V1_SIZE) {
        memcpy(&out_payload->fixed.base, bytes, MFT_SPOOL_PROBE_PAYLOAD_V1_SIZE);
        normalize_probe_payload_fallback(out_payload);
        return 1;
    }

    if (payload_size < MFT_SPOOL_PROBE_PAYLOAD_FIXED_SIZE ||
        payload_size > MFT_SPOOL_PROBE_PAYLOAD_MAX_SIZE) {
        return 0;
    }

    memcpy(&out_payload->fixed, bytes, MFT_SPOOL_PROBE_PAYLOAD_FIXED_SIZE);
    stored_run_count = out_payload->fixed.stored_run_count;
    if (stored_run_count > MFT_ENTRY_MAX_RUNS) {
        return 0;
    }

    run_bytes = stored_run_count * MFT_SPOOL_PROBE_RUN_PAYLOAD_SIZE;
    if (payload_size != MFT_SPOOL_PROBE_PAYLOAD_FIXED_SIZE + run_bytes) {
        return 0;
    }

    if (stored_run_count > 0U) {
        memcpy(
            out_payload->runs,
            bytes + MFT_SPOOL_PROBE_PAYLOAD_FIXED_SIZE,
            run_bytes
        );
    }

    normalize_probe_payload_fallback(out_payload);
    return 1;
}

static int build_state_child_path(char *out, size_t out_size, const char *child)
{
    char state_dir[1024];

    if (!path_join(state_dir, sizeof(state_dir), g_output_dir, APP_STATE_DIR_NAME)) {
        return 0;
    }
    return path_join(out, out_size, state_dir, child);
}

static int build_spool_state_path(char *out, size_t out_size)
{
    return build_state_child_path(out, out_size, "spool_state.bin");
}

static int compute_abs_offset_from_lcn(uint64_t lcn, int64_t *out_abs_offset)
{
    uint64_t byte_start;
    uint64_t base_offset;

    if (out_abs_offset == NULL ||
        !g_has_ntfs_geometry ||
        g_cluster_size == 0 ||
        g_partition_start < 0 ||
        lcn > UINT64_MAX / (uint64_t)g_cluster_size) {
        return 0;
    }

    byte_start = lcn * (uint64_t)g_cluster_size;
    base_offset = (uint64_t)g_partition_start;
    if (byte_start > (uint64_t)INT64_MAX - base_offset) {
        return 0;
    }

    *out_abs_offset = (int64_t)(base_offset + byte_start);
    return 1;
}

static int compute_byte_length_from_clusters(uint64_t clusters, uint64_t *out_byte_length)
{
    if (out_byte_length == NULL ||
        g_cluster_size == 0 ||
        clusters > UINT64_MAX / (uint64_t)g_cluster_size) {
        return 0;
    }

    *out_byte_length = clusters * (uint64_t)g_cluster_size;
    return 1;
}

static void hydrate_probe_payload_geometry(MftSpoolProbePayload *payload)
{
    size_t run_index;
    int64_t first_abs_offset = -1;
    int64_t max_end_offset = -1;
    int can_hydrate_geometry =
        g_has_ntfs_geometry &&
        g_cluster_size > 0 &&
        g_partition_start >= 0;

    if (payload == NULL) {
        return;
    }

    for (run_index = 0; run_index < payload->fixed.stored_run_count; run_index++) {
        if (can_hydrate_geometry) {
            int64_t abs_offset = payload->runs[run_index].abs_offset;
            (void)compute_abs_offset_from_lcn(
                payload->runs[run_index].lcn,
                &abs_offset
            );
            payload->runs[run_index].abs_offset = abs_offset;
        } else if (payload->runs[run_index].abs_offset < 0) {
            int64_t abs_offset = payload->runs[run_index].abs_offset;
            (void)compute_abs_offset_from_lcn(
                payload->runs[run_index].lcn,
                &abs_offset
            );
            payload->runs[run_index].abs_offset = abs_offset;
        }
        if (can_hydrate_geometry || payload->runs[run_index].byte_length == 0U) {
            uint64_t byte_length = payload->runs[run_index].byte_length;
            if (compute_byte_length_from_clusters(
                    payload->runs[run_index].clusters,
                    &byte_length)) {
                payload->runs[run_index].byte_length = byte_length;
            }
        }
        if (payload->runs[run_index].abs_offset >= 0 &&
            payload->runs[run_index].byte_length > 0U) {
            int64_t run_end = payload->runs[run_index].abs_offset +
                              (int64_t)payload->runs[run_index].byte_length;
            if (first_abs_offset < 0 || payload->runs[run_index].abs_offset < first_abs_offset) {
                first_abs_offset = payload->runs[run_index].abs_offset;
            }
            if (run_end > max_end_offset) {
                max_end_offset = run_end;
            }
        }
    }

    if ((can_hydrate_geometry || payload->fixed.base.data_abs_offset < 0) &&
        first_abs_offset >= 0) {
        payload->fixed.base.data_abs_offset = first_abs_offset;
    }
    if (payload->fixed.base.run_byte_length == 0U &&
        payload->fixed.base.run_clusters > 0) {
        uint64_t run_byte_length = 0;

        if (compute_byte_length_from_clusters(
                payload->fixed.base.run_clusters,
                &run_byte_length)) {
            payload->fixed.base.run_byte_length = run_byte_length;
        }
    }
    if ((can_hydrate_geometry ||
         payload->fixed.base.data_end_abs_offset <= payload->fixed.base.data_abs_offset) &&
        max_end_offset > payload->fixed.base.data_abs_offset) {
        payload->fixed.base.data_end_abs_offset = max_end_offset;
    }
}

static int build_unique_parent_group_path_local(
    char *out_path,
    size_t out_size,
    uint64_t parent_record,
    const char *parent_relative_path,
    const char *name,
    const char *extension,
    const char *current_path
)
{
    char relative_dir[1024];
    char directory[1024];

    if (out_path == NULL ||
        out_size == 0U ||
        !text_present(name) ||
        parent_record == 0U ||
        parent_record == 5U) {
        return 0;
    }

    if (text_present(parent_relative_path)) {
        while (*parent_relative_path == '/') {
            parent_relative_path++;
        }
        if (snprintf(
                relative_dir,
                sizeof(relative_dir),
                "%s/%s",
                APP_PARTIAL_TREE_DIR_NAME,
                parent_relative_path) >= (int)sizeof(relative_dir)) {
            return 0;
        }
    } else {
        if (snprintf(
                relative_dir,
                sizeof(relative_dir),
                "%s/mapp_%llu",
                APP_PARTIAL_TREE_DIR_NAME,
                (unsigned long long)parent_record) >= (int)sizeof(relative_dir)) {
            return 0;
        }
    }

    if (!build_recovered_path(directory, sizeof(directory), relative_dir) ||
        !ensure_directory_recursive(directory)) {
        return 0;
    }

    if (text_present(extension)) {
        return build_unique_output_path_from_flat_name_with_extension_local(
            out_path,
            out_size,
            directory,
            name,
            extension,
            current_path
        );
    }

    return build_unique_output_path_from_flat_name_local(
        out_path,
        out_size,
        directory,
        name,
        current_path
    );
}

static int build_parent_relative_path_for_record_local(
    const MftSpoolRecordIndexRow *record_rows,
    size_t record_count,
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    uint64_t family_id,
    uint64_t parent_record,
    char *out_relative,
    size_t out_relative_size
)
{
    int ignored_complete = 0;

    if (out_relative == NULL || out_relative_size == 0U) {
        return 0;
    }
    out_relative[0] = '\0';

    if (parent_record == 0U ||
        parent_record == 5U ||
        parent_record > (uint64_t)INT_MAX) {
        return 0;
    }

    return build_relative_path_for_record(
        record_rows,
        record_count,
        readers,
        reader_count,
        family_id,
        (int)parent_record,
        out_relative,
        out_relative_size,
        &ignored_complete,
        NULL
    );
}

static int build_unique_partial_context_path_local(
    char *out_path,
    size_t out_size,
    const char *relative_path,
    const char *current_path
)
{
    char partial_relative[1024];

    if (out_path == NULL ||
        out_size == 0U ||
        !text_present(relative_path)) {
        return 0;
    }

    while (*relative_path == '/') {
        relative_path++;
    }

    if (snprintf(
            partial_relative,
            sizeof(partial_relative),
            "%s/%s",
            APP_PARTIAL_TREE_DIR_NAME,
            relative_path) >= (int)sizeof(partial_relative)) {
        return 0;
    }

    return build_unique_context_path(
        out_path,
        out_size,
        partial_relative,
        current_path
    );
}

static int write_spool_state_file(void)
{
    char path[1024];
    FILE *file = NULL;
    MftSpoolStateHeader header;
    int ok = 0;

    if (!text_present(g_output_dir)) {
        return 0;
    }
    if (!build_spool_state_path(path, sizeof(path))) {
        return 0;
    }
    if (!ensure_directory_recursive(g_spool_dir) ||
        !ensure_directory_recursive(g_index_dir)) {
        return 0;
    }

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, MFT_SPOOL_STATE_MAGIC, 8U);
    header.version = MFT_SPOOL_STATE_VERSION;
    header.header_size = (uint32_t)sizeof(header);
    header.flags = g_has_ntfs_geometry ? MFT_SPOOL_STATE_FLAG_HAS_NTFS_GEOMETRY : 0U;
    header.cluster_size = g_cluster_size;
    header.record_size = g_record_size;
    header.partition_start = g_partition_start;
    header.header_crc32 = crc32_compute(
        &header,
        sizeof(header) - sizeof(header.header_crc32)
    );

    file = fopen(path, "wb");
    if (file == NULL) {
        return 0;
    }
    if (fwrite(&header, sizeof(header), 1, file) == 1 && fflush(file) == 0) {
        ok = 1;
    }
    fclose(file);
    return ok;
}

static int load_spool_state_file(void)
{
    char path[1024];
    FILE *file = NULL;
    MftSpoolStateHeader header;
    uint32_t expected_crc;

    if (!text_present(g_output_dir) ||
        !build_spool_state_path(path, sizeof(path)) ||
        !regular_file_exists(path)) {
        return 0;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    if (fread(&header, sizeof(header), 1, file) != 1) {
        fclose(file);
        return 0;
    }
    fclose(file);

    expected_crc = crc32_compute(&header, sizeof(header) - sizeof(header.header_crc32));
    if (memcmp(header.magic, MFT_SPOOL_STATE_MAGIC, 8U) != 0 ||
        header.version != MFT_SPOOL_STATE_VERSION ||
        header.header_size != sizeof(header) ||
        header.header_crc32 != expected_crc) {
        return 0;
    }

    g_has_ntfs_geometry = (header.flags & MFT_SPOOL_STATE_FLAG_HAS_NTFS_GEOMETRY) != 0U;
    g_partition_start = header.partition_start;
    g_cluster_size = header.cluster_size;
    g_record_size = header.record_size > 0 ? header.record_size : MFT_PROBE_RECORD_SIZE;
    return 1;
}

static int build_segment_path(
    char *out,
    size_t out_size,
    uint16_t kind,
    uint32_t segment_number,
    int sealed
)
{
    const char *prefix = (kind == MFT_SPOOL_SEGMENT_PROBE) ? "mft_probe" : "recovered";
    const char *extension = sealed ? "seg" : "open";
    char name[128];

    if (snprintf(
            name,
            sizeof(name),
            "%s_%06u.%s",
            prefix,
            segment_number,
            extension) >= (int)sizeof(name)) {
        return 0;
    }

    return path_join(out, out_size, g_spool_dir, name);
}

static int build_index_path(char *out, size_t out_size, const char *name)
{
    return path_join(out, out_size, g_index_dir, name);
}

static int build_recovered_outputs_log_path(char *out, size_t out_size)
{
    char state_dir[1024];

    if (!path_join(state_dir, sizeof(state_dir), g_output_dir, APP_STATE_DIR_NAME)) {
        return 0;
    }
    return path_join(out, out_size, state_dir, "recovered_outputs.tsv");
}

static int build_live_stats_path_local(char *out, size_t out_size)
{
    return build_state_child_path(out, out_size, "spool_live_stats.txt");
}

static int parse_stats_value_local(
    const char *line,
    const char *key,
    unsigned long long *out_value
)
{
    size_t key_length;
    char *end_ptr = NULL;

    if (line == NULL || key == NULL || out_value == NULL) {
        return 0;
    }

    key_length = strlen(key);
    if (strncmp(line, key, key_length) != 0 || line[key_length] != '=') {
        return 0;
    }

    *out_value = strtoull(line + key_length + 1U, &end_ptr, 10);
    return end_ptr != NULL;
}

static int write_live_stats_file(void)
{
    char path[1024];
    char temp_path[1060];
    FILE *file;

    if (!text_present(g_output_dir) ||
        !build_live_stats_path_local(path, sizeof(path)) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >= (int)sizeof(temp_path)) {
        return 0;
    }
    if (!spool_output_path_write_guard_allows(temp_path, "write NTFS spool live stats")) {
        return 0;
    }

    file = fopen(temp_path, "w");
    if (file == NULL) {
        return 0;
    }

    fprintf(file, "version=1\n");
    fprintf(file, "renamed_outputs=%llu\n", (unsigned long long)g_live_renamed_outputs);
    fprintf(file, "repaired_outputs=%llu\n", (unsigned long long)g_live_repaired_outputs);
    fprintf(file, "recovered_outputs_current=%llu\n", (unsigned long long)g_live_recovered_outputs_current);
    fprintf(file, "named_outputs_current=%llu\n", (unsigned long long)g_live_named_outputs_current);
    fprintf(file, "files_outside_unident=%llu\n", (unsigned long long)g_live_named_outputs_current);
    fprintf(file, "unident_outputs_current=%llu\n", (unsigned long long)g_live_unident_outputs_current);
    fprintf(file, "files_still_in_unident=%llu\n", (unsigned long long)g_live_unident_outputs_current);
    fprintf(file, "repair_pending_outputs=%llu\n", (unsigned long long)g_live_repair_pending_outputs);
    fprintf(file, "repair_pending_files=%llu\n", (unsigned long long)g_live_repair_pending_outputs);
    fprintf(file, "rename_operations=%llu\n", (unsigned long long)g_live_renamed_outputs);
    fprintf(file, "repair_queue_events=%llu\n", (unsigned long long)g_live_repair_queue_events);
    fprintf(file, "opportunistic_naming_sweeps=%llu\n", (unsigned long long)g_background_opportunistic_sweeps);
    fprintf(file, "opportunistic_naming_renamed=%llu\n", (unsigned long long)g_background_opportunistic_renamed_outputs);
    fprintf(file, "opportunistic_naming_zero_delta=%llu\n", (unsigned long long)g_background_opportunistic_zero_delta_sweeps);
    fprintf(file, "opportunistic_naming_last_delta=%llu\n", (unsigned long long)g_background_last_opportunistic_renamed_delta);
    fprintf(file, "recovered_first_checked_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.checked);
    fprintf(file, "recovered_first_moved_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.moved);
    fprintf(file, "recovered_first_complete_moves_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.complete_path_moves);
    fprintf(file, "recovered_first_partial_moves_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.partial_path_moves);
    fprintf(file, "recovered_first_parent_group_moves_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.parent_group_moves);
    fprintf(file, "recovered_first_flat_name_moves_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.flat_name_moves);
    fprintf(file, "recovered_first_no_path_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.skipped_no_path);
    fprintf(file, "recovered_first_missing_source_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.skipped_missing_source);
    fprintf(file, "recovered_first_no_extension_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.skipped_no_extension);
    fprintf(file, "recovered_first_no_range_anchor_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.skipped_no_range_anchor);
    fprintf(file, "recovered_first_no_exact_range_start_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.skipped_no_exact_range_start);
    fprintf(file, "recovered_first_no_context_path_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.skipped_no_context_path);
    fprintf(file, "recovered_first_no_payload_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.skipped_no_payload);
    fprintf(file, "recovered_first_no_commit_candidate_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.skipped_no_commit_candidate);
    fprintf(file, "recovered_first_same_path_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.skipped_same_path);
    fprintf(file, "recovered_first_rename_failures_last=%llu\n", (unsigned long long)g_background_last_recovered_first_stats.rename_failures);
    fprintf(file, "record_index_count=%zu\n", g_record_index_count);
    fprintf(file, "range_index_count=%zu\n", g_range_index_count);
    fprintf(file, "scan_stalled_seconds=%llu\n", g_live_scan_stalled_seconds);
    fprintf(file, "background_phase=%u\n", (unsigned int)g_live_background_phase);
    fprintf(file, "background_conservative=%d\n", g_background_conservative_mode ? 1 : 0);

    if (fclose(file) != 0) {
        (void)unlink(temp_path);
        return 0;
    }

    if (rename(temp_path, path) != 0) {
        (void)unlink(temp_path);
        return 0;
    }

    return 1;
}

static int load_live_stats_file(MftSpoolLiveStats *out)
{
    char path[1024];
    FILE *file;
    char line[256];
    MftSpoolLiveStats stats = {0};

    if (out == NULL ||
        !build_live_stats_path_local(path, sizeof(path))) {
        return 0;
    }

    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned long long value = 0ULL;

        if (parse_stats_value_local(line, "renamed_outputs", &value)) {
            stats.renamed_outputs = (uint64_t)value;
        } else if (parse_stats_value_local(line, "repaired_outputs", &value)) {
            stats.repaired_outputs = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_outputs_current", &value)) {
            stats.recovered_outputs_current = (uint64_t)value;
        } else if (parse_stats_value_local(line, "named_outputs_current", &value)) {
            stats.named_outputs_current = (uint64_t)value;
        } else if (parse_stats_value_local(line, "files_outside_unident", &value)) {
            stats.named_outputs_current = (uint64_t)value;
        } else if (parse_stats_value_local(line, "unident_outputs_current", &value)) {
            stats.unident_outputs_current = (uint64_t)value;
        } else if (parse_stats_value_local(line, "files_still_in_unident", &value)) {
            stats.unident_outputs_current = (uint64_t)value;
        } else if (parse_stats_value_local(line, "repair_pending_outputs", &value)) {
            stats.repair_pending_outputs = (uint64_t)value;
        } else if (parse_stats_value_local(line, "repair_pending_files", &value)) {
            stats.repair_pending_outputs = (uint64_t)value;
        } else if (parse_stats_value_local(line, "rename_operations", &value)) {
            stats.renamed_outputs = (uint64_t)value;
        } else if (parse_stats_value_local(line, "repair_queue_events", &value)) {
            stats.repair_queue_events = (uint64_t)value;
        } else if (parse_stats_value_local(line, "opportunistic_naming_sweeps", &value)) {
            stats.opportunistic_naming_sweeps = (uint64_t)value;
        } else if (parse_stats_value_local(line, "opportunistic_naming_renamed", &value)) {
            stats.opportunistic_naming_renamed = (uint64_t)value;
        } else if (parse_stats_value_local(line, "opportunistic_naming_zero_delta", &value)) {
            stats.opportunistic_naming_zero_delta = (uint64_t)value;
        } else if (parse_stats_value_local(line, "opportunistic_naming_last_delta", &value)) {
            stats.opportunistic_naming_last_delta = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_checked_last", &value)) {
            stats.recovered_first_checked_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_moved_last", &value)) {
            stats.recovered_first_moved_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_complete_moves_last", &value)) {
            stats.recovered_first_complete_moves_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_partial_moves_last", &value)) {
            stats.recovered_first_partial_moves_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_parent_group_moves_last", &value)) {
            stats.recovered_first_parent_group_moves_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_flat_name_moves_last", &value)) {
            stats.recovered_first_flat_name_moves_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_no_path_last", &value)) {
            stats.recovered_first_no_path_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_missing_source_last", &value)) {
            stats.recovered_first_missing_source_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_no_extension_last", &value)) {
            stats.recovered_first_no_extension_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_no_range_anchor_last", &value)) {
            stats.recovered_first_no_range_anchor_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_no_exact_range_start_last", &value)) {
            stats.recovered_first_no_exact_range_start_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_no_context_path_last", &value)) {
            stats.recovered_first_no_context_path_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_no_payload_last", &value)) {
            stats.recovered_first_no_payload_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_no_commit_candidate_last", &value)) {
            stats.recovered_first_no_commit_candidate_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_same_path_last", &value)) {
            stats.recovered_first_same_path_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "recovered_first_rename_failures_last", &value)) {
            stats.recovered_first_rename_failures_last = (uint64_t)value;
        } else if (parse_stats_value_local(line, "record_index_count", &value)) {
            stats.record_index_count = (size_t)value;
        } else if (parse_stats_value_local(line, "range_index_count", &value)) {
            stats.range_index_count = (size_t)value;
        } else if (parse_stats_value_local(line, "scan_stalled_seconds", &value)) {
            stats.scan_stalled_seconds = value;
        } else if (parse_stats_value_local(line, "background_phase", &value)) {
            stats.background_phase = (unsigned int)value;
        } else if (parse_stats_value_local(line, "background_conservative", &value)) {
            stats.background_conservative = (unsigned int)value;
        }
    }

    fclose(file);
    *out = stats;
    return 1;
}

static void reset_background_state(void)
{
    g_background_last_probe_bytes = 0;
    g_background_last_recovered_bytes = 0;
    g_background_last_index_probe_bytes = 0;
    g_background_last_reconcile_recovered_bytes = 0;
    g_background_last_repair_recovered_bytes = 0;
    g_background_last_index_build = 0;
    g_background_last_reconcile = 0;
    g_background_last_repair = 0;
    g_background_last_scan_offset = 0;
    g_background_last_scan_change = 0;
    g_background_last_idle_sweep = 0;
    g_background_last_slow_scan_sweep = 0;
    g_background_last_opportunistic_naming = 0;
    g_background_last_live_stats_refresh = 0;
    g_background_last_stats_recovered_bytes = 0;
    g_background_last_stats_renamed_outputs = 0;
    g_background_last_stats_repaired_outputs = 0;
    g_background_last_opportunistic_probe_bytes = 0;
    g_background_last_opportunistic_recovered_bytes = 0;
    g_background_opportunistic_sweeps = 0;
    g_background_opportunistic_renamed_outputs = 0;
    g_background_opportunistic_zero_delta_sweeps = 0;
    g_background_last_opportunistic_renamed_delta = 0;
    memset(&g_background_last_recovered_first_stats, 0, sizeof(g_background_last_recovered_first_stats));
    memset(&g_background_last_progress, 0, sizeof(g_background_last_progress));
    free(g_probe_cursors);
    g_probe_cursors = NULL;
    g_probe_cursor_count = 0;
    g_probe_cursors_initialized = 0;
    free(g_recovered_cursors);
    g_recovered_cursors = NULL;
    g_recovered_cursor_count = 0;
    g_recovered_cursors_initialized = 0;
    free(g_repair_cursors);
    g_repair_cursors = NULL;
    g_repair_cursor_count = 0;
    g_repair_cursors_initialized = 0;
    g_background_need_full_reconcile = 1;
    g_live_renamed_outputs = 0;
    g_live_repaired_outputs = 0;
    g_live_recovered_outputs_current = 0;
    g_live_named_outputs_current = 0;
    g_live_unident_outputs_current = 0;
    g_live_repair_pending_outputs = 0;
    g_live_repair_queue_events = 0;
    g_live_scan_stalled_seconds = 0;
    g_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;
    g_logged_no_range_reconcile_notice = 0;
}

static int regular_file_exists(const char *path)
{
    struct stat st;

    return text_present(path) &&
           stat(path, &st) == 0 &&
           S_ISREG(st.st_mode);
}

static void reset_cursor_set(
    MftSpoolSegmentCursor **cursors,
    size_t *cursor_count,
    int *initialized
)
{
    if (cursors != NULL) {
        free(*cursors);
        *cursors = NULL;
    }
    if (cursor_count != NULL) {
        *cursor_count = 0;
    }
    if (initialized != NULL) {
        *initialized = 0;
    }
}

static void discard_geometry_dependent_indices(void)
{
    char path[1024];

    if (text_present(g_index_dir)) {
        if (build_index_path(path, sizeof(path), "record.idx")) {
            (void)unlink(path);
        }
        if (build_index_path(path, sizeof(path), "range.idx")) {
            (void)unlink(path);
        }
    }

    g_record_index_count = 0;
    g_range_index_count = 0;
    g_background_last_index_probe_bytes = 0;
    g_background_last_probe_bytes = 0;
    reset_cursor_set(
        &g_probe_cursors,
        &g_probe_cursor_count,
        &g_probe_cursors_initialized);
    reset_cursor_set(
        &g_recovered_cursors,
        &g_recovered_cursor_count,
        &g_recovered_cursors_initialized);
    reset_cursor_set(
        &g_repair_cursors,
        &g_repair_cursor_count,
        &g_repair_cursors_initialized);
    g_background_need_full_reconcile = 1;
}

static uint32_t spool_record_magic(uint16_t kind)
{
    return kind == MFT_SPOOL_SEGMENT_PROBE ? 0x3142504DU : 0x3152434DU;
}

static int record_kind_matches_header(uint16_t segment_kind, uint16_t record_kind)
{
    return segment_kind == record_kind &&
           (segment_kind == MFT_SPOOL_SEGMENT_PROBE ||
            segment_kind == MFT_SPOOL_SEGMENT_RECOVERED);
}

static int write_file_header(FILE *file, const MftSpoolWriter *writer)
{
    MftSpoolFileHeader header;

    if (file == NULL || writer == NULL) {
        return 0;
    }

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, MFT_SPOOL_FILE_MAGIC, 8U);
    header.version = MFT_SPOOL_FILE_VERSION;
    header.kind = writer->kind;
    header.header_size = (uint32_t)sizeof(header);
    header.segment_number = writer->segment_number;
    header.created_unix = (uint64_t)time(NULL);
    header.record_count = writer->record_count;
    header.payload_bytes = writer->payload_bytes;
    header.next_sequence = writer->next_sequence;
    header.header_crc32 = crc32_compute(&header, sizeof(header) - sizeof(header.header_crc32));

    if (fseeko(file, 0, SEEK_SET) != 0) {
        return 0;
    }
    if (fwrite(&header, sizeof(header), 1, file) != 1) {
        return 0;
    }
    return fflush(file) == 0;
}

static int validate_file_header(FILE *file, uint16_t expected_kind, MftSpoolFileHeader *out_header)
{
    MftSpoolFileHeader header;
    uint32_t expected_crc;

    if (file == NULL) {
        return 0;
    }

    if (fseeko(file, 0, SEEK_SET) != 0) {
        return 0;
    }
    if (fread(&header, sizeof(header), 1, file) != 1) {
        return 0;
    }
    if (memcmp(header.magic, MFT_SPOOL_FILE_MAGIC, 8U) != 0 ||
        header.version != MFT_SPOOL_FILE_VERSION ||
        header.kind != expected_kind ||
        header.header_size != sizeof(header)) {
        return 0;
    }

    expected_crc = crc32_compute(&header, sizeof(header) - sizeof(header.header_crc32));
    if (header.header_crc32 != expected_crc) {
        return 0;
    }

    if (out_header != NULL) {
        *out_header = header;
    }
    return 1;
}

static int validate_record_header(
    const MftSpoolRecordHeader *header,
    uint16_t expected_kind
)
{
    uint32_t expected_crc;

    if (header == NULL) {
        return 0;
    }

    if (header->magic != spool_record_magic(expected_kind) ||
        header->version != MFT_SPOOL_FILE_VERSION ||
        !record_kind_matches_header(expected_kind, header->kind) ||
        header->total_size < sizeof(*header) ||
        header->payload_size != header->total_size - sizeof(*header)) {
        return 0;
    }

    expected_crc = crc32_compute(
        header,
        sizeof(*header) - sizeof(header->header_crc32)
    );
    return header->header_crc32 == expected_crc;
}

static int find_next_spool_boundary(
    FILE *file,
    uint64_t start_offset,
    uint16_t expected_kind,
    uint64_t *out_offset
)
{
    enum {
        RESYNC_READ_SIZE = 65536,
        RESYNC_CARRY_SIZE = 7
    };
    unsigned char buffer[RESYNC_READ_SIZE + RESYNC_CARRY_SIZE];
    unsigned char record_magic_bytes[sizeof(uint32_t)];
    uint32_t record_magic = spool_record_magic(expected_kind);
    uint64_t read_offset = start_offset;
    size_t carry = 0U;

    if (file == NULL || out_offset == NULL) {
        return 0;
    }

    memcpy(record_magic_bytes, &record_magic, sizeof(record_magic_bytes));

    while (!app_stop_requested()) {
        size_t bytes_read;
        size_t total;
        size_t i;
        uint64_t buffer_base;

        if (fseeko(file, (off_t)read_offset, SEEK_SET) != 0) {
            return 0;
        }

        bytes_read = fread(buffer + carry, 1, RESYNC_READ_SIZE, file);
        if (bytes_read == 0U) {
            clearerr(file);
            return 0;
        }

        total = carry + bytes_read;
        buffer_base = read_offset - (uint64_t)carry;
        for (i = 0U; i < total; i++) {
            uint64_t candidate = buffer_base + (uint64_t)i;

            if (candidate < start_offset) {
                continue;
            }
            if (i + 8U <= total &&
                memcmp(buffer + i, MFT_SPOOL_FILE_MAGIC, 8U) == 0) {
                *out_offset = candidate;
                return 1;
            }
            if (i + sizeof(record_magic_bytes) <= total &&
                memcmp(buffer + i, record_magic_bytes, sizeof(record_magic_bytes)) == 0) {
                *out_offset = candidate;
                return 1;
            }
        }

        if (bytes_read < RESYNC_READ_SIZE) {
            clearerr(file);
            return 0;
        }

        carry = total < RESYNC_CARRY_SIZE ? total : RESYNC_CARRY_SIZE;
        if (carry > 0U) {
            memmove(buffer, buffer + total - carry, carry);
        }
        read_offset += (uint64_t)bytes_read;
    }

    return 0;
}

static int read_next_spool_record_header(
    FILE *file,
    uint16_t expected_kind,
    uint64_t *io_offset,
    MftSpoolRecordHeader *out_header,
    int *out_eof
)
{
    uint64_t offset;

    if (file == NULL || io_offset == NULL || out_header == NULL || out_eof == NULL) {
        return 0;
    }

    offset = *io_offset;
    *out_eof = 0;

    while (!app_stop_requested()) {
        MftSpoolRecordHeader record_header;
        uint64_t resync_offset;

        if (fseeko(file, (off_t)offset, SEEK_SET) != 0) {
            return 0;
        }

        if (fread(&record_header, sizeof(record_header), 1, file) != 1) {
            clearerr(file);
            *io_offset = offset;
            *out_eof = 1;
            return 1;
        }

        if (validate_record_header(&record_header, expected_kind)) {
            *io_offset = offset;
            *out_header = record_header;
            return 1;
        }

        /*
         * Older builds reopened open spool segments in append mode.  The
         * header refresh that was meant for byte 0 was then appended into
         * the middle of the segment, after which readers stopped early.  A
         * nested file header is safe to skip because real records are still
         * individually CRC-checked before use.
         */
        if (memcmp(&record_header, MFT_SPOOL_FILE_MAGIC, 8U) == 0) {
            offset += (uint64_t)sizeof(MftSpoolFileHeader);
            continue;
        }

        if (!find_next_spool_boundary(file, offset + 1U, expected_kind, &resync_offset)) {
            *io_offset = offset;
            *out_eof = 1;
            return 1;
        }

        offset = resync_offset;
    }

    *io_offset = offset;
    *out_eof = 1;
    return 1;
}

static int validate_segment_file(
    const char *path,
    uint16_t expected_kind,
    int allow_truncate,
    MftSpoolValidateResult *out_result
)
{
    FILE *file = NULL;
    MftSpoolValidateResult result;
    MftSpoolFileHeader file_header;
    uint64_t offset = sizeof(MftSpoolFileHeader);
    unsigned char payload_buffer[MFT_SPOOL_MAX_RECORD_PAYLOAD_SIZE];
    int ok = 0;

    memset(&result, 0, sizeof(result));

    file = fopen(path, allow_truncate ? "rb+" : "rb");
    if (file == NULL) {
        return 0;
    }

    if (!validate_file_header(file, expected_kind, &file_header)) {
        fclose(file);
        return 0;
    }

    result.next_sequence = file_header.next_sequence;

    while (1) {
        MftSpoolRecordHeader record_header;
        uint32_t payload_crc;
        uint64_t record_offset;
        uint64_t resync_offset;
        int eof = 0;

        if (!read_next_spool_record_header(
                file,
                expected_kind,
                &offset,
                &record_header,
                &eof)) {
            break;
        }
        if (eof) {
            break;
        }

        record_offset = offset;
        if (record_header.payload_size > sizeof(payload_buffer)) {
            if (!find_next_spool_boundary(
                    file,
                    record_offset + 1U,
                    expected_kind,
                    &resync_offset)) {
                break;
            }
            offset = resync_offset;
            continue;
        }

        if (fread(payload_buffer, record_header.payload_size, 1, file) != 1) {
            clearerr(file);
            if (!find_next_spool_boundary(
                    file,
                    record_offset + 1U,
                    expected_kind,
                    &resync_offset)) {
                break;
            }
            offset = resync_offset;
            continue;
        }

        payload_crc = crc32_compute(payload_buffer, record_header.payload_size);
        if (payload_crc != record_header.payload_crc32) {
            if (!find_next_spool_boundary(
                    file,
                    record_offset + 1U,
                    expected_kind,
                    &resync_offset)) {
                break;
            }
            offset = resync_offset;
            continue;
        }

        if (expected_kind == MFT_SPOOL_SEGMENT_PROBE &&
            decode_probe_payload(
                payload_buffer,
                record_header.payload_size,
                &result.last_probe)) {
            result.has_last_probe = 1;
        }

        result.record_count++;
        result.payload_bytes += record_header.payload_size;
        result.next_sequence = record_header.sequence + 1U;
        offset = record_offset + (uint64_t)record_header.total_size;
        result.valid_size = offset;
    }

    if (result.valid_size == 0) {
        result.valid_size = sizeof(MftSpoolFileHeader);
    }

    if (allow_truncate) {
        int fd = fileno(file);

        if (fd >= 0 && ftruncate(fd, (off_t)result.valid_size) != 0) {
            fclose(file);
            return 0;
        }

        file_header.record_count = result.record_count;
        file_header.payload_bytes = result.payload_bytes;
        file_header.next_sequence = result.next_sequence;
        file_header.header_crc32 = crc32_compute(
            &file_header,
            sizeof(file_header) - sizeof(file_header.header_crc32)
        );
        if (fseeko(file, 0, SEEK_SET) != 0 ||
            fwrite(&file_header, sizeof(file_header), 1, file) != 1 ||
            fflush(file) != 0) {
            fclose(file);
            return 0;
        }
    }

    if (out_result != NULL) {
        *out_result = result;
    }

    ok = 1;
    fclose(file);
    return ok;
}

static int parse_segment_name(
    const char *name,
    uint16_t expected_kind,
    uint32_t *out_segment_number,
    int *out_is_open
)
{
    const char *prefix = expected_kind == MFT_SPOOL_SEGMENT_PROBE
        ? "mft_probe_"
        : "recovered_";
    const char *extension = strrchr(name, '.');
    char digits[7];
    size_t prefix_len;
    unsigned long value;
    char *endptr = NULL;

    if (name == NULL || extension == NULL) {
        return 0;
    }

    prefix_len = strlen(prefix);
    if (strncmp(name, prefix, prefix_len) != 0 ||
        (strcmp(extension, ".seg") != 0 && strcmp(extension, ".open") != 0) ||
        (size_t)(extension - name) != prefix_len + 6U) {
        return 0;
    }

    memcpy(digits, name + prefix_len, 6U);
    digits[6] = '\0';
    value = strtoul(digits, &endptr, 10);
    if (endptr == NULL || *endptr != '\0' || value > UINT32_MAX) {
        return 0;
    }

    if (out_segment_number != NULL) {
        *out_segment_number = (uint32_t)value;
    }
    if (out_is_open != NULL) {
        *out_is_open = strcmp(extension, ".open") == 0;
    }
    return 1;
}

static int collect_segment_files(
    uint16_t expected_kind,
    MftSpoolSegmentFile **out_files,
    size_t *out_count
)
{
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    MftSpoolSegmentFile *files = NULL;
    size_t count = 0;
    size_t capacity = 0;

    if (out_files == NULL || out_count == NULL) {
        return 0;
    }

    *out_files = NULL;
    *out_count = 0;

    dir = opendir(g_spool_dir);
    if (dir == NULL) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        MftSpoolSegmentFile segment = {0};

        if (!parse_segment_name(
                entry->d_name,
                expected_kind,
                &segment.segment_number,
                &segment.is_open)) {
            continue;
        }

        if (!path_join(segment.path, sizeof(segment.path), g_spool_dir, entry->d_name)) {
            continue;
        }

        if (count == capacity) {
            size_t new_capacity = capacity == 0 ? 8U : capacity * 2U;
            MftSpoolSegmentFile *new_files = (MftSpoolSegmentFile *)realloc(
                files,
                new_capacity * sizeof(*new_files)
            );

            if (new_files == NULL) {
                free(files);
                closedir(dir);
                return 0;
            }

            files = new_files;
            capacity = new_capacity;
        }

        files[count++] = segment;
    }

    closedir(dir);
    *out_files = files;
    *out_count = count;
    return 1;
}

static MftSpoolSegmentCursor *find_segment_cursor(
    MftSpoolSegmentCursor *cursors,
    size_t cursor_count,
    uint32_t segment_number
)
{
    size_t i;

    for (i = 0; i < cursor_count; i++) {
        if (cursors[i].segment_number == segment_number) {
            return &cursors[i];
        }
    }

    return NULL;
}

static MftSpoolSegmentCursor *ensure_segment_cursor(
    MftSpoolSegmentCursor **io_cursors,
    size_t *io_cursor_count,
    uint32_t segment_number
)
{
    MftSpoolSegmentCursor *cursor;
    MftSpoolSegmentCursor *new_cursors;
    size_t new_count;

    if (io_cursors == NULL || io_cursor_count == NULL) {
        return NULL;
    }

    cursor = find_segment_cursor(*io_cursors, *io_cursor_count, segment_number);
    if (cursor != NULL) {
        return cursor;
    }

    new_count = *io_cursor_count + 1U;
    new_cursors = (MftSpoolSegmentCursor *)realloc(
        *io_cursors,
        new_count * sizeof(*new_cursors)
    );
    if (new_cursors == NULL) {
        return NULL;
    }

    *io_cursors = new_cursors;
    cursor = &new_cursors[*io_cursor_count];
    memset(cursor, 0, sizeof(*cursor));
    cursor->segment_number = segment_number;
    cursor->next_offset = sizeof(MftSpoolFileHeader);
    *io_cursor_count = new_count;
    return cursor;
}

static int initialize_segment_cursors_to_segment_end(
    uint16_t expected_kind,
    MftSpoolSegmentCursor **io_cursors,
    size_t *io_cursor_count
)
{
    MftSpoolSegmentFile *files = NULL;
    size_t file_count = 0;
    size_t i;

    if (io_cursors == NULL || io_cursor_count == NULL) {
        return 0;
    }

    if (!collect_segment_files(expected_kind, &files, &file_count)) {
        return 0;
    }
    if (file_count > 1U) {
        qsort(files, file_count, sizeof(*files), compare_segment_files);
    }

    free(*io_cursors);
    *io_cursors = NULL;
    *io_cursor_count = 0;

    for (i = 0; i < file_count; i++) {
        MftSpoolValidateResult validation;
        MftSpoolSegmentCursor *cursor;

        memset(&validation, 0, sizeof(validation));
        if (!validate_segment_file(files[i].path, expected_kind, 0, &validation)) {
            continue;
        }

        cursor = ensure_segment_cursor(io_cursors, io_cursor_count, files[i].segment_number);
        if (cursor == NULL) {
            free(files);
            return 0;
        }
        cursor->next_offset = validation.valid_size;
    }

    free(files);
    return 1;
}

static int collect_segment_bytes(uint16_t expected_kind, uint64_t *out_bytes)
{
    MftSpoolSegmentFile *files = NULL;
    size_t file_count = 0;
    uint64_t total_bytes = 0;
    size_t i;

    if (out_bytes == NULL) {
        return 0;
    }
    *out_bytes = 0;

    if (!collect_segment_files(expected_kind, &files, &file_count)) {
        return 0;
    }

    for (i = 0; i < file_count; i++) {
        struct stat st;

        if (stat(files[i].path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        total_bytes += (uint64_t)st.st_size;
    }

    free(files);
    *out_bytes = total_bytes;
    return 1;
}

static int collect_segment_latest_mtime(uint16_t expected_kind, time_t *out_latest_mtime)
{
    MftSpoolSegmentFile *files = NULL;
    size_t file_count = 0;
    time_t latest_mtime = (time_t)0;
    size_t i;

    if (out_latest_mtime == NULL) {
        return 0;
    }
    *out_latest_mtime = (time_t)0;

    if (!collect_segment_files(expected_kind, &files, &file_count)) {
        return 0;
    }

    for (i = 0; i < file_count; i++) {
        struct stat st;

        if (stat(files[i].path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        if (st.st_mtime > latest_mtime) {
            latest_mtime = st.st_mtime;
        }
    }

    free(files);
    *out_latest_mtime = latest_mtime;
    return 1;
}

static int compare_segment_files(const void *left, const void *right)
{
    const MftSpoolSegmentFile *a = (const MftSpoolSegmentFile *)left;
    const MftSpoolSegmentFile *b = (const MftSpoolSegmentFile *)right;

    if (a->segment_number < b->segment_number) {
        return -1;
    }
    if (a->segment_number > b->segment_number) {
        return 1;
    }
    if (a->is_open < b->is_open) {
        return -1;
    }
    if (a->is_open > b->is_open) {
        return 1;
    }
    return strcmp(a->path, b->path);
}

static void seed_probe_family_state(const MftSpoolValidateResult *result)
{
    if (result == NULL || !result->has_last_probe) {
        return;
    }

    g_probe_family_count = result->last_probe.fixed.base.family_id;
    g_probe_prev_offset = result->last_probe.fixed.base.record_offset;
    g_probe_prev_record = result->last_probe.fixed.base.record;
    g_probe_have_prev = 1;
}

static int writer_flush(MftSpoolWriter *writer)
{
    if (writer == NULL || writer->file == NULL) {
        return 0;
    }

    if (!write_file_header(writer->file, writer)) {
        return 0;
    }
    if (fseeko(writer->file, 0, SEEK_END) != 0) {
        return 0;
    }
    writer->pending_flush_rows = 0;
    return 1;
}

static int writer_seal(MftSpoolWriter *writer)
{
    char sealed_path[1024];

    if (writer == NULL || writer->file == NULL) {
        return 1;
    }

    if (!writer_flush(writer)) {
        return 0;
    }
    fclose(writer->file);
    writer->file = NULL;

    if (!build_segment_path(
            sealed_path,
            sizeof(sealed_path),
            writer->kind,
            writer->segment_number,
            1)) {
        return 0;
    }

    (void)unlink(sealed_path);
    if (rename(writer->path, sealed_path) != 0) {
        return 0;
    }

    snprintf(writer->path, sizeof(writer->path), "%s", sealed_path);
    writer->prepared = 0;
    return 1;
}

static int writer_open_new_segment(MftSpoolWriter *writer, uint32_t segment_number)
{
    if (writer == NULL) {
        return 0;
    }

    if (!build_segment_path(
            writer->path,
            sizeof(writer->path),
            writer->kind,
            segment_number,
            0)) {
        return 0;
    }

    if (!spool_output_path_write_guard_allows(writer->path, "write NTFS spool segment")) {
        return 0;
    }
    writer->file = fopen(writer->path, "wb+");
    if (writer->file == NULL) {
        return 0;
    }

    writer->segment_number = segment_number;
    writer->record_count = 0;
    writer->payload_bytes = 0;
    writer->current_size = sizeof(MftSpoolFileHeader);
    writer->next_sequence = 1;
    writer->pending_flush_rows = 0;
    writer->prepared = 1;

    if (!writer_flush(writer)) {
        fclose(writer->file);
        writer->file = NULL;
        writer->prepared = 0;
        return 0;
    }

    return fseeko(writer->file, 0, SEEK_END) == 0;
}

static int writer_prepare(MftSpoolWriter *writer)
{
    MftSpoolSegmentFile *files = NULL;
    size_t file_count = 0;
    size_t i;
    uint32_t highest_segment = 0;
    MftSpoolSegmentFile *open_segment = NULL;
    MftSpoolValidateResult last_result = {0};
    int have_last_result = 0;

    if (writer == NULL) {
        return 0;
    }
    if (writer->prepared && writer->file != NULL) {
        return 1;
    }
    if (!ensure_directory_recursive(g_spool_dir) ||
        !ensure_directory_recursive(g_index_dir)) {
        return 0;
    }

    if (!collect_segment_files(writer->kind, &files, &file_count)) {
        return 0;
    }

    if (file_count > 1U) {
        qsort(files, file_count, sizeof(*files), compare_segment_files);
    }

    for (i = 0; i < file_count; i++) {
        MftSpoolValidateResult validate_result = {0};

        if (files[i].segment_number > highest_segment) {
            highest_segment = files[i].segment_number;
        }
        if (files[i].is_open) {
            open_segment = &files[i];
            if (!validate_segment_file(
                    files[i].path,
                    writer->kind,
                    1,
                    &validate_result)) {
                free(files);
                return 0;
            }
            last_result = validate_result;
            have_last_result = 1;
        } else if (i + 1U == file_count) {
            if (validate_segment_file(
                    files[i].path,
                    writer->kind,
                    0,
                    &validate_result)) {
                last_result = validate_result;
                have_last_result = 1;
            }
        }
    }

    if (writer->kind == MFT_SPOOL_SEGMENT_PROBE && have_last_result) {
        seed_probe_family_state(&last_result);
    }

    if (open_segment != NULL) {
        if (!spool_output_path_write_guard_allows(
                open_segment->path,
                "update NTFS spool segment")) {
            free(files);
            return 0;
        }
        writer->file = fopen(open_segment->path, "rb+");
        if (writer->file == NULL) {
            free(files);
            return 0;
        }
        writer->segment_number = open_segment->segment_number;
        writer->record_count = last_result.record_count;
        writer->payload_bytes = last_result.payload_bytes;
        writer->next_sequence = last_result.next_sequence == 0 ? 1 : last_result.next_sequence;
        writer->current_size = last_result.valid_size;
        writer->pending_flush_rows = 0;
        writer->prepared = 1;
        snprintf(writer->path, sizeof(writer->path), "%s", open_segment->path);
        if (fseeko(writer->file, (off_t)writer->current_size, SEEK_SET) != 0) {
            fclose(writer->file);
            writer->file = NULL;
            writer->prepared = 0;
            free(files);
            return 0;
        }
        free(files);
        return 1;
    }

    free(files);
    return writer_open_new_segment(writer, highest_segment == 0 ? 1U : highest_segment + 1U);
}

static int writer_rotate_if_needed(MftSpoolWriter *writer, size_t next_record_size)
{
    if (writer == NULL) {
        return 0;
    }
    if (!writer_prepare(writer)) {
        return 0;
    }
    if (writer->current_size + (uint64_t)next_record_size <= MFT_SPOOL_SEGMENT_LIMIT_BYTES ||
        writer->record_count == 0) {
        return 1;
    }
    if (!writer_seal(writer)) {
        return 0;
    }
    return writer_open_new_segment(writer, writer->segment_number + 1U);
}

static uint64_t assign_family_id(const MftProbeEntry *entry)
{
    if (entry == NULL || entry->record < 0) {
        return 0;
    }

    if (entry->family != 0U) {
        g_probe_family_count = entry->family;
        g_probe_prev_offset = entry->offset;
        g_probe_prev_record = entry->record;
        g_probe_have_prev = 1;
        return entry->family;
    }

    if (g_probe_have_prev &&
        entry->offset > g_probe_prev_offset &&
        g_record_size > 0 &&
        (entry->offset - g_probe_prev_offset) % (uint64_t)g_record_size == 0) {
        uint64_t gap_records =
            (entry->offset - g_probe_prev_offset) / (uint64_t)g_record_size;
        uint64_t expected_record =
            (uint64_t)(uint32_t)g_probe_prev_record + gap_records;

        if (!(gap_records <= MFT_SPOOL_MAX_INFER_GAP_RECORDS &&
              expected_record <= (uint64_t)INT32_MAX)) {
            g_probe_family_count++;
        }
    } else {
        g_probe_family_count++;
    }

    if (g_probe_family_count == 0) {
        g_probe_family_count = 1;
    }

    g_probe_prev_offset = entry->offset;
    g_probe_prev_record = entry->record;
    g_probe_have_prev = 1;
    return g_probe_family_count;
}

static int writer_append_record(
    MftSpoolWriter *writer,
    const void *payload,
    size_t payload_size
)
{
    MftSpoolRecordHeader record_header;
    size_t total_size = sizeof(record_header) + payload_size;

    if (writer == NULL || payload == NULL || payload_size == 0) {
        return 0;
    }
    if (!writer_rotate_if_needed(writer, total_size)) {
        return 0;
    }

    memset(&record_header, 0, sizeof(record_header));
    record_header.magic = spool_record_magic(writer->kind);
    record_header.version = MFT_SPOOL_FILE_VERSION;
    record_header.kind = writer->kind;
    record_header.total_size = (uint32_t)total_size;
    record_header.payload_size = (uint32_t)payload_size;
    record_header.payload_crc32 = crc32_compute(payload, payload_size);
    record_header.sequence = writer->next_sequence++;
    record_header.header_crc32 = crc32_compute(
        &record_header,
        sizeof(record_header) - sizeof(record_header.header_crc32)
    );

    if (fwrite(&record_header, sizeof(record_header), 1, writer->file) != 1 ||
        fwrite(payload, payload_size, 1, writer->file) != 1) {
        return 0;
    }

    writer->record_count++;
    writer->payload_bytes += payload_size;
    writer->current_size += total_size;
    writer->pending_flush_rows++;

    if (writer->kind == MFT_SPOOL_SEGMENT_RECOVERED &&
        fflush(writer->file) != 0) {
        return 0;
    }

    if ((writer->kind == MFT_SPOOL_SEGMENT_PROBE &&
         writer->pending_flush_rows >= MFT_SPOOL_PROBE_FLUSH_INTERVAL) ||
        (writer->kind == MFT_SPOOL_SEGMENT_RECOVERED &&
         writer->pending_flush_rows >= MFT_SPOOL_RECOVERED_FLUSH_INTERVAL)) {
        return writer_flush(writer);
    }

    return 1;
}

static int write_index_header(
    FILE *file,
    uint16_t kind,
    uint32_t row_size,
    uint64_t row_count
)
{
    MftSpoolIndexHeader header;

    memset(&header, 0, sizeof(header));
    memcpy(header.magic, MFT_SPOOL_INDEX_MAGIC, 8U);
    header.version = MFT_SPOOL_INDEX_VERSION;
    header.kind = kind;
    header.header_size = (uint32_t)sizeof(header);
    header.row_size = row_size;
    header.row_count = row_count;
    header.header_crc32 = crc32_compute(&header, sizeof(header) - sizeof(header.header_crc32));

    return fwrite(&header, sizeof(header), 1, file) == 1;
}

static int compare_record_index_rows(const void *left, const void *right)
{
    const MftSpoolRecordIndexRow *a = (const MftSpoolRecordIndexRow *)left;
    const MftSpoolRecordIndexRow *b = (const MftSpoolRecordIndexRow *)right;

    if (a->family_id < b->family_id) {
        return -1;
    }
    if (a->family_id > b->family_id) {
        return 1;
    }
    if (a->record < b->record) {
        return -1;
    }
    if (a->record > b->record) {
        return 1;
    }
    if (a->segment_number < b->segment_number) {
        return -1;
    }
    if (a->segment_number > b->segment_number) {
        return 1;
    }
    if (a->spool_record_offset < b->spool_record_offset) {
        return -1;
    }
    if (a->spool_record_offset > b->spool_record_offset) {
        return 1;
    }
    return 0;
}

static int compare_range_index_rows(const void *left, const void *right)
{
    const MftSpoolRangeIndexRow *a = (const MftSpoolRangeIndexRow *)left;
    const MftSpoolRangeIndexRow *b = (const MftSpoolRangeIndexRow *)right;

    if (a->data_abs_offset < b->data_abs_offset) {
        return -1;
    }
    if (a->data_abs_offset > b->data_abs_offset) {
        return 1;
    }
    if (a->data_end_abs_offset < b->data_end_abs_offset) {
        return -1;
    }
    if (a->data_end_abs_offset > b->data_end_abs_offset) {
        return 1;
    }
    if (a->family_id < b->family_id) {
        return -1;
    }
    if (a->family_id > b->family_id) {
        return 1;
    }
    if (a->record < b->record) {
        return -1;
    }
    if (a->record > b->record) {
        return 1;
    }
    if (a->segment_number < b->segment_number) {
        return -1;
    }
    if (a->segment_number > b->segment_number) {
        return 1;
    }
    if (a->spool_record_offset < b->spool_record_offset) {
        return -1;
    }
    if (a->spool_record_offset > b->spool_record_offset) {
        return 1;
    }
    return 0;
}

static MftSpoolRecordIndexRow *merge_record_index_rows(
    const MftSpoolRecordIndexRow *left,
    size_t left_count,
    const MftSpoolRecordIndexRow *right,
    size_t right_count
)
{
    MftSpoolRecordIndexRow *merged;
    size_t left_pos = 0U;
    size_t right_pos = 0U;
    size_t out_pos = 0U;
    size_t total_count;

    if (left_count > SIZE_MAX - right_count) {
        return NULL;
    }
    total_count = left_count + right_count;
    if (total_count == 0U) {
        return NULL;
    }

    merged = (MftSpoolRecordIndexRow *)malloc(total_count * sizeof(*merged));
    if (merged == NULL) {
        return NULL;
    }

    while (left_pos < left_count && right_pos < right_count) {
        if (compare_record_index_rows(&left[left_pos], &right[right_pos]) <= 0) {
            merged[out_pos++] = left[left_pos++];
        } else {
            merged[out_pos++] = right[right_pos++];
        }
    }
    while (left_pos < left_count) {
        merged[out_pos++] = left[left_pos++];
    }
    while (right_pos < right_count) {
        merged[out_pos++] = right[right_pos++];
    }

    return merged;
}

static MftSpoolRangeIndexRow *merge_range_index_rows(
    const MftSpoolRangeIndexRow *left,
    size_t left_count,
    const MftSpoolRangeIndexRow *right,
    size_t right_count
)
{
    MftSpoolRangeIndexRow *merged;
    size_t left_pos = 0U;
    size_t right_pos = 0U;
    size_t out_pos = 0U;
    size_t total_count;

    if (left_count > SIZE_MAX - right_count) {
        return NULL;
    }
    total_count = left_count + right_count;
    if (total_count == 0U) {
        return NULL;
    }

    merged = (MftSpoolRangeIndexRow *)malloc(total_count * sizeof(*merged));
    if (merged == NULL) {
        return NULL;
    }

    while (left_pos < left_count && right_pos < right_count) {
        if (compare_range_index_rows(&left[left_pos], &right[right_pos]) <= 0) {
            merged[out_pos++] = left[left_pos++];
        } else {
            merged[out_pos++] = right[right_pos++];
        }
    }
    while (left_pos < left_count) {
        merged[out_pos++] = left[left_pos++];
    }
    while (right_pos < right_count) {
        merged[out_pos++] = right[right_pos++];
    }

    return merged;
}

static time_t filetime_to_unix(uint64_t filetime)
{
    int64_t unix_seconds;

    if (filetime == 0) {
        return (time_t)0;
    }
    unix_seconds = (int64_t)(filetime / 10000000ULL) - 11644473600LL;
    if (unix_seconds <= 0) {
        return (time_t)0;
    }
    return (time_t)unix_seconds;
}

static void lower_extension_from_name(const char *name, char *out, size_t out_size)
{
    const char *slash;
    const char *dot;
    size_t i;

    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (!text_present(name)) {
        return;
    }

    slash = strrchr(name, '/');
    dot = strrchr(name, '.');
    if (dot == NULL || dot[1] == '\0' || (slash != NULL && dot < slash)) {
        return;
    }

    dot++;
    for (i = 0; dot[i] != '\0' && i + 1U < out_size; i++) {
        unsigned char ch = (unsigned char)dot[i];
        out[i] = (char)((ch >= 'A' && ch <= 'Z') ? (ch - 'A' + 'a') : ch);
    }
    out[i] = '\0';
}

static int extensions_are_same_recovery_family(const char *lhs, const char *rhs)
{
    if (!text_present(lhs) || !text_present(rhs)) {
        return 0;
    }
    if (strcmp(lhs, rhs) == 0) {
        return 1;
    }
    if ((strcmp(lhs, "jpg") == 0 && strcmp(rhs, "jpeg") == 0) ||
        (strcmp(lhs, "jpeg") == 0 && strcmp(rhs, "jpg") == 0)) {
        return 1;
    }
    if ((strcmp(lhs, "tif") == 0 && strcmp(rhs, "tiff") == 0) ||
        (strcmp(lhs, "tiff") == 0 && strcmp(rhs, "tif") == 0)) {
        return 1;
    }
    if ((strcmp(lhs, "mpg") == 0 && strcmp(rhs, "mpeg") == 0) ||
        (strcmp(lhs, "mpeg") == 0 && strcmp(rhs, "mpg") == 0)) {
        return 1;
    }
    return 0;
}

static int contextual_path_is_usable_for_recovered_extension(
    const char *contextual_path,
    const char *recovered_extension
)
{
    char contextual_extension[32];
    const char *basename;

    if (!text_present(contextual_path) || !text_present(recovered_extension)) {
        return 0;
    }

    basename = strrchr(contextual_path, '/');
    basename = (basename != NULL) ? (basename + 1) : contextual_path;
    if (basename[0] == '\0' ||
        strcmp(basename, "hiberfil.sys") == 0 ||
        strcmp(basename, "pagefile.sys") == 0 ||
        strcmp(basename, "swapfile.sys") == 0 ||
        strcmp(basename, "memory.dmp") == 0 ||
        strcmp(basename, "dumpstack.log") == 0 ||
        strcmp(basename, "dumpstack.log.tmp") == 0) {
        return 0;
    }

    lower_extension_from_name(contextual_path, contextual_extension, sizeof(contextual_extension));
    return extensions_are_same_recovery_family(contextual_extension, recovered_extension);
}

static int name_is_ntfs_metadata(const char *name, int record)
{
    if (record >= 0 && record < 16) {
        return 1;
    }
    if (!text_present(name) || name[0] != '$') {
        return 0;
    }
    return strcmp(name, "$MFT") == 0 ||
           strcmp(name, "$MFTMirr") == 0 ||
           strcmp(name, "$LogFile") == 0 ||
           strcmp(name, "$Volume") == 0 ||
           strcmp(name, "$AttrDef") == 0 ||
           strcmp(name, "$Bitmap") == 0 ||
           strcmp(name, "$Boot") == 0 ||
           strcmp(name, "$BadClus") == 0 ||
           strcmp(name, "$Secure") == 0 ||
           strcmp(name, "$UpCase") == 0 ||
           strcmp(name, "$Extend") == 0;
}

static int is_users_component(const char *name)
{
    return text_present(name) &&
           (strcmp(name, "Users") == 0 || strcmp(name, "users") == 0);
}

static void sanitize_component(const char *in, char *out, size_t out_size)
{
    size_t i;
    size_t j = 0;
    const char *src;

    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (in == NULL) {
        return;
    }
    src = mft_visible_windows_component_name(in);

    for (i = 0; src[i] != '\0' && j + 1U < out_size; i++) {
        unsigned char ch = (unsigned char)src[i];
        if (ch < 32 || ch == '/' || ch == '\\' || ch == ':' || ch == '$') {
            out[j++] = '_';
        } else {
            out[j++] = (char)ch;
        }
    }
    out[j] = '\0';
}

static int append_component(char *path, size_t path_size, const char *component)
{
    char clean[256];
    size_t used;

    sanitize_component(component, clean, sizeof(clean));
    if (!text_present(clean) || strcmp(clean, ".") == 0) {
        return 1;
    }

    used = strlen(path);
    if (used > 0) {
        if (used + 1U >= path_size) {
            return 0;
        }
        path[used++] = '/';
        path[used] = '\0';
    }

    if (used + strlen(clean) + 1U > path_size) {
        return 0;
    }

    memcpy(path + used, clean, strlen(clean) + 1U);
    return 1;
}

static int build_recovered_path(char *out, size_t out_size, const char *relative_path)
{
    if (out == NULL || out_size == 0) {
        return 0;
    }

    if (!text_present(relative_path)) {
        return snprintf(out, out_size, "%s/%s", g_output_dir, APP_RECOVERED_DIR_NAME) <
            (int)out_size;
    }

    while (*relative_path == '/') {
        relative_path++;
    }
    return snprintf(
        out,
        out_size,
        "%s/" APP_RECOVERED_DIR_NAME "/%s",
        g_output_dir,
        relative_path
    ) < (int)out_size;
}

static int basename_is_system_container_ci_local(const char *basename)
{
    return text_present(basename) &&
           (strcasecmp(basename, "hiberfil.sys") == 0 ||
            strcasecmp(basename, "pagefile.sys") == 0 ||
            strcasecmp(basename, "swapfile.sys") == 0 ||
            strcasecmp(basename, "memory.dmp") == 0 ||
            strcasecmp(basename, "dumpstack.log") == 0 ||
            strcasecmp(basename, "dumpstack.log.tmp") == 0);
}

static int build_unique_output_path_from_flat_name_local(
    char *out_path,
    size_t out_size,
    const char *directory,
    const char *name,
    const char *current_path
)
{
    char base[1024];
    char candidate[1024];
    char visible_name[1024];
    const char *dot;
    int index = 1;

    if (out_path == NULL || directory == NULL || name == NULL || name[0] == '\0') {
        return 0;
    }

    sanitize_component(name, visible_name, sizeof(visible_name));
    if (!text_present(visible_name)) {
        return 0;
    }

    if (snprintf(base, sizeof(base), "%s/%s", directory, visible_name) >= (int)sizeof(base)) {
        return 0;
    }

    if ((current_path != NULL && strcmp(base, current_path) == 0) ||
        access(base, F_OK) != 0) {
        snprintf(out_path, out_size, "%s", base);
        return 1;
    }

    dot = strrchr(base, '.');
    if (dot == NULL) {
        while (1) {
            if (snprintf(candidate, sizeof(candidate), "%s_%d", base, index) >=
                (int)sizeof(candidate)) {
                return 0;
            }

            if ((current_path != NULL && strcmp(candidate, current_path) == 0) ||
                access(candidate, F_OK) != 0) {
                snprintf(out_path, out_size, "%s", candidate);
                return 1;
            }

            index++;
        }
    }

    while (1) {
        size_t prefix_len = (size_t)(dot - base);

        if (snprintf(
                candidate,
                sizeof(candidate),
                "%.*s_%d%s",
                (int)prefix_len,
                base,
                index,
                dot) >= (int)sizeof(candidate)) {
            return 0;
        }

        if ((current_path != NULL && strcmp(candidate, current_path) == 0) ||
            access(candidate, F_OK) != 0) {
            snprintf(out_path, out_size, "%s", candidate);
            return 1;
        }

        index++;
    }
}

static int build_unique_output_path_from_flat_name_with_extension_local(
    char *out_path,
    size_t out_size,
    const char *directory,
    const char *name,
    const char *extension,
    const char *current_path
)
{
    char visible_name[1024];
    char stem[1024];
    char base[1024];
    char candidate[1024];
    char *dot;
    int index = 1;
    size_t stem_len;

    if (out_path == NULL ||
        directory == NULL ||
        name == NULL ||
        name[0] == '\0' ||
        extension == NULL ||
        extension[0] == '\0') {
        return 0;
    }

    sanitize_component(name, visible_name, sizeof(visible_name));
    if (!text_present(visible_name)) {
        return 0;
    }

    snprintf(stem, sizeof(stem), "%s", visible_name);
    dot = strrchr(stem, '.');
    if (dot != NULL) {
        *dot = '\0';
    }
    stem_len = strlen(stem);
    if (stem_len == 0U) {
        return 0;
    }

    if (snprintf(base, sizeof(base), "%s/%s.%s", directory, stem, extension) >= (int)sizeof(base)) {
        return 0;
    }

    if ((current_path != NULL && strcmp(base, current_path) == 0) ||
        access(base, F_OK) != 0) {
        snprintf(out_path, out_size, "%s", base);
        return 1;
    }

    while (1) {
        if (snprintf(candidate, sizeof(candidate), "%s/%s_%d.%s", directory, stem, index, extension) >=
            (int)sizeof(candidate)) {
            return 0;
        }

        if ((current_path != NULL && strcmp(candidate, current_path) == 0) ||
            access(candidate, F_OK) != 0) {
            snprintf(out_path, out_size, "%s", candidate);
            return 1;
        }

        index++;
    }
}

static int MFT_SPOOL_MAYBE_UNUSED build_unique_path(
    char *out,
    size_t out_size,
    const char *dir,
    const char *prefix,
    long long abs_offset,
    const char *extension
)
{
    unsigned int collision = 0;

    if (out == NULL || dir == NULL || prefix == NULL || extension == NULL) {
        return 0;
    }
    if (!ensure_directory_recursive(dir)) {
        return 0;
    }

    for (;;) {
        int written;

        if (collision == 0U) {
            written = snprintf(
                out,
                out_size,
                "%s/%s_%016llx.%s",
                dir,
                prefix,
                (unsigned long long)abs_offset,
                extension
            );
        } else {
            written = snprintf(
                out,
                out_size,
                "%s/%s_%016llx_%u.%s",
                dir,
                prefix,
                (unsigned long long)abs_offset,
                collision,
                extension
            );
        }
        if (written < 0 || written >= (int)out_size) {
            return 0;
        }
        if (access(out, F_OK) != 0) {
            return 1;
        }
        collision++;
        if (collision > 9999U) {
            return 0;
        }
    }
}

static int build_unique_context_path(
    char *out,
    size_t out_size,
    const char *relative_path,
    const char *current_path
)
{
    char base[1024];
    char dir[1024];
    char stem[1024];
    char ext[128];
    char *slash;
    char *dot;
    unsigned int collision = 0;

    if (!build_recovered_path(base, sizeof(base), relative_path)) {
        return 0;
    }
    snprintf(dir, sizeof(dir), "%s", base);
    slash = strrchr(dir, '/');
    if (slash == NULL) {
        return 0;
    }
    *slash = '\0';
    if (!ensure_directory_recursive(dir)) {
        return 0;
    }

    snprintf(stem, sizeof(stem), "%s", base);
    dot = strrchr(stem, '.');
    slash = strrchr(stem, '/');
    ext[0] = '\0';
    if (dot != NULL && (slash == NULL || dot > slash)) {
        snprintf(ext, sizeof(ext), "%s", dot);
        *dot = '\0';
    }

    for (;;) {
        int written;

        if (collision == 0U) {
            written = snprintf(out, out_size, "%s%s", stem, ext);
        } else {
            written = snprintf(out, out_size, "%s_%u%s", stem, collision, ext);
        }
        if (written < 0 || written >= (int)out_size) {
            return 0;
        }
        if (current_path != NULL && strcmp(out, current_path) == 0) {
            return 1;
        }
        if (access(out, F_OK) != 0) {
            return 1;
        }
        collision++;
        if (collision > 9999U) {
            return 0;
        }
    }
}

static int compare_recovered_events(const void *left, const void *right)
{
    const MftSpoolRecoveredEvent *a = (const MftSpoolRecoveredEvent *)left;
    const MftSpoolRecoveredEvent *b = (const MftSpoolRecoveredEvent *)right;

    if (a->abs_offset < b->abs_offset) {
        return -1;
    }
    if (a->abs_offset > b->abs_offset) {
        return 1;
    }
    if (a->ordinal < b->ordinal) {
        return -1;
    }
    if (a->ordinal > b->ordinal) {
        return 1;
    }
    return 0;
}

static int append_probe_payload_rows(
    MftSpoolRecordIndexRow **io_record_rows,
    size_t *io_record_count,
    size_t *io_record_capacity,
    MftSpoolRangeIndexRow **io_range_rows,
    size_t *io_range_count,
    size_t *io_range_capacity,
    const MftSpoolProbePayload *payload,
    uint32_t segment_number,
    uint64_t spool_record_offset
)
{
    MftSpoolRecordIndexRow record_row;

    if (io_record_rows == NULL || io_record_count == NULL || io_record_capacity == NULL ||
        io_range_rows == NULL || io_range_count == NULL || io_range_capacity == NULL ||
        payload == NULL) {
        return 0;
    }

    if (*io_record_count == *io_record_capacity) {
        size_t new_capacity = *io_record_capacity == 0 ? 4096U : *io_record_capacity * 2U;
        MftSpoolRecordIndexRow *new_rows = (MftSpoolRecordIndexRow *)realloc(
            *io_record_rows,
            new_capacity * sizeof(*new_rows)
        );

        if (new_rows == NULL) {
            return 0;
        }

        *io_record_rows = new_rows;
        *io_record_capacity = new_capacity;
    }

    memset(&record_row, 0, sizeof(record_row));
    record_row.family_id = payload->fixed.base.family_id;
    record_row.record = payload->fixed.base.record;
    record_row.segment_number = segment_number;
    record_row.spool_record_offset = spool_record_offset;
    (*io_record_rows)[(*io_record_count)++] = record_row;

    if (payload->fixed.stored_run_count > 0U) {
        size_t run_index;

        for (run_index = 0; run_index < payload->fixed.stored_run_count; run_index++) {
            MftSpoolRangeIndexRow range_row;

            if (payload->runs[run_index].abs_offset < 0 ||
                payload->runs[run_index].byte_length == 0U) {
                continue;
            }

            if (*io_range_count == *io_range_capacity) {
                size_t new_capacity = *io_range_capacity == 0 ? 4096U : *io_range_capacity * 2U;
                MftSpoolRangeIndexRow *new_rows = (MftSpoolRangeIndexRow *)realloc(
                    *io_range_rows,
                    new_capacity * sizeof(*new_rows)
                );

                if (new_rows == NULL) {
                    return 0;
                }

                *io_range_rows = new_rows;
                *io_range_capacity = new_capacity;
            }

            memset(&range_row, 0, sizeof(range_row));
            range_row.data_abs_offset = payload->runs[run_index].abs_offset;
            range_row.data_end_abs_offset =
                payload->runs[run_index].abs_offset +
                (int64_t)payload->runs[run_index].byte_length;
            range_row.family_id = payload->fixed.base.family_id;
            range_row.record = payload->fixed.base.record;
            range_row.segment_number = segment_number;
            range_row.spool_record_offset = spool_record_offset;
            range_row.flags = payload->fixed.base.flags;
            range_row.resident = payload->fixed.base.resident;
            (*io_range_rows)[(*io_range_count)++] = range_row;
        }
    } else if (payload->fixed.base.data_abs_offset >= 0 &&
               payload->fixed.base.data_end_abs_offset > payload->fixed.base.data_abs_offset) {
        MftSpoolRangeIndexRow range_row;

        if (*io_range_count == *io_range_capacity) {
            size_t new_capacity = *io_range_capacity == 0 ? 4096U : *io_range_capacity * 2U;
            MftSpoolRangeIndexRow *new_rows = (MftSpoolRangeIndexRow *)realloc(
                *io_range_rows,
                new_capacity * sizeof(*new_rows)
            );

            if (new_rows == NULL) {
                return 0;
            }

            *io_range_rows = new_rows;
            *io_range_capacity = new_capacity;
        }

        memset(&range_row, 0, sizeof(range_row));
        range_row.data_abs_offset = payload->fixed.base.data_abs_offset;
        range_row.data_end_abs_offset = payload->fixed.base.data_end_abs_offset;
        range_row.family_id = payload->fixed.base.family_id;
        range_row.record = payload->fixed.base.record;
        range_row.segment_number = segment_number;
        range_row.spool_record_offset = spool_record_offset;
        range_row.flags = payload->fixed.base.flags;
        range_row.resident = payload->fixed.base.resident;
        (*io_range_rows)[(*io_range_count)++] = range_row;
    }

    return 1;
}

static int load_probe_rows_from_segments(
    MftSpoolRecordIndexRow **out_record_rows,
    size_t *out_record_count,
    MftSpoolRangeIndexRow **out_range_rows,
    size_t *out_range_count
)
{
    MftSpoolSegmentFile *files = NULL;
    size_t file_count = 0;
    MftSpoolRecordIndexRow *record_rows = NULL;
    MftSpoolRangeIndexRow *range_rows = NULL;
    size_t record_count = 0;
    size_t range_count = 0;
    size_t record_capacity = 0;
    size_t range_capacity = 0;
    size_t i;

    if (out_record_rows == NULL || out_record_count == NULL ||
        out_range_rows == NULL || out_range_count == NULL) {
        return 0;
    }

    *out_record_rows = NULL;
    *out_record_count = 0;
    *out_range_rows = NULL;
    *out_range_count = 0;

    if (!collect_segment_files(MFT_SPOOL_SEGMENT_PROBE, &files, &file_count)) {
        return 0;
    }

    if (file_count > 1U) {
        qsort(files, file_count, sizeof(*files), compare_segment_files);
    }

    for (i = 0; i < file_count; i++) {
        FILE *file = fopen(files[i].path, "rb");
        MftSpoolFileHeader file_header;
        uint64_t offset = sizeof(MftSpoolFileHeader);

        if (file == NULL) {
            continue;
        }
        if (!validate_file_header(file, MFT_SPOOL_SEGMENT_PROBE, &file_header)) {
            fclose(file);
            continue;
        }

        while (!app_stop_requested()) {
            MftSpoolRecordHeader record_header;
            unsigned char payload_buffer[MFT_SPOOL_PROBE_PAYLOAD_MAX_SIZE];
            MftSpoolProbePayload payload;
            uint32_t payload_crc;
            uint64_t record_offset;
            uint64_t resync_offset;
            int eof = 0;

            if (!read_next_spool_record_header(
                    file,
                    MFT_SPOOL_SEGMENT_PROBE,
                    &offset,
                    &record_header,
                    &eof) ||
                eof) {
                break;
            }

            record_offset = offset;
            if (record_header.payload_size > sizeof(payload_buffer) ||
                fread(payload_buffer, record_header.payload_size, 1, file) != 1) {
                clearerr(file);
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_PROBE,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }

            payload_crc = crc32_compute(payload_buffer, record_header.payload_size);
            if (payload_crc != record_header.payload_crc32 ||
                !decode_probe_payload(payload_buffer, record_header.payload_size, &payload)) {
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_PROBE,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }

            if (!append_probe_payload_rows(
                    &record_rows,
                    &record_count,
                    &record_capacity,
                    &range_rows,
                    &range_count,
                    &range_capacity,
                    &payload,
                    files[i].segment_number,
                    record_offset)) {
                fclose(file);
                free(files);
                free(record_rows);
                free(range_rows);
                return 0;
            }

            offset = record_offset + (uint64_t)record_header.total_size;
        }

        fclose(file);
    }

    free(files);
    *out_record_rows = record_rows;
    *out_record_count = record_count;
    *out_range_rows = range_rows;
    *out_range_count = range_count;
    return 1;
}

static int load_probe_delta_rows_from_segments(
    MftSpoolRecordIndexRow **out_record_rows,
    size_t *out_record_count,
    MftSpoolRangeIndexRow **out_range_rows,
    size_t *out_range_count
)
{
    MftSpoolSegmentFile *files = NULL;
    size_t file_count = 0;
    MftSpoolRecordIndexRow *record_rows = NULL;
    MftSpoolRangeIndexRow *range_rows = NULL;
    size_t record_count = 0;
    size_t range_count = 0;
    size_t record_capacity = 0;
    size_t range_capacity = 0;
    size_t i;

    if (out_record_rows == NULL || out_record_count == NULL ||
        out_range_rows == NULL || out_range_count == NULL) {
        return 0;
    }

    *out_record_rows = NULL;
    *out_record_count = 0;
    *out_range_rows = NULL;
    *out_range_count = 0;

    if (!collect_segment_files(MFT_SPOOL_SEGMENT_PROBE, &files, &file_count)) {
        return 0;
    }
    if (file_count > 1U) {
        qsort(files, file_count, sizeof(*files), compare_segment_files);
    }

    for (i = 0; i < file_count; i++) {
        FILE *file = fopen(files[i].path, "rb");
        MftSpoolFileHeader file_header;
        MftSpoolSegmentCursor *cursor;
        uint64_t offset;

        if (file == NULL) {
            continue;
        }
        if (!validate_file_header(file, MFT_SPOOL_SEGMENT_PROBE, &file_header)) {
            fclose(file);
            continue;
        }

        cursor = ensure_segment_cursor(&g_probe_cursors, &g_probe_cursor_count, files[i].segment_number);
        if (cursor == NULL) {
            fclose(file);
            free(files);
            free(record_rows);
            free(range_rows);
            return 0;
        }

        offset = cursor->next_offset;
        if (offset < sizeof(MftSpoolFileHeader)) {
            offset = sizeof(MftSpoolFileHeader);
        }

        while (!app_stop_requested()) {
            MftSpoolRecordHeader record_header;
            unsigned char payload_buffer[MFT_SPOOL_PROBE_PAYLOAD_MAX_SIZE];
            MftSpoolProbePayload payload;
            uint32_t payload_crc;
            uint64_t record_offset;
            uint64_t resync_offset;
            int eof = 0;

            if (!read_next_spool_record_header(
                    file,
                    MFT_SPOOL_SEGMENT_PROBE,
                    &offset,
                    &record_header,
                    &eof) ||
                eof) {
                break;
            }

            record_offset = offset;
            if (record_header.payload_size > sizeof(payload_buffer) ||
                fread(payload_buffer, record_header.payload_size, 1, file) != 1) {
                clearerr(file);
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_PROBE,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }

            payload_crc = crc32_compute(payload_buffer, record_header.payload_size);
            if (payload_crc != record_header.payload_crc32 ||
                !decode_probe_payload(payload_buffer, record_header.payload_size, &payload)) {
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_PROBE,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }

            if (!append_probe_payload_rows(
                    &record_rows,
                    &record_count,
                    &record_capacity,
                    &range_rows,
                    &range_count,
                    &range_capacity,
                    &payload,
                    files[i].segment_number,
                    record_offset)) {
                fclose(file);
                free(files);
                free(record_rows);
                free(range_rows);
                return 0;
            }

            offset = record_offset + (uint64_t)record_header.total_size;
        }

        cursor->next_offset = offset;
        fclose(file);
    }

    free(files);
    *out_record_rows = record_rows;
    *out_record_count = record_count;
    *out_range_rows = range_rows;
    *out_range_count = range_count;
    return 1;
}

static int load_index_rows(
    const char *path,
    uint16_t expected_kind,
    size_t row_size,
    void **out_rows,
    size_t *out_count
)
{
    FILE *file = NULL;
    MftSpoolIndexHeader header;
    uint32_t expected_crc;
    void *rows = NULL;
    size_t row_count;

    if (out_rows == NULL || out_count == NULL) {
        return 0;
    }

    *out_rows = NULL;
    *out_count = 0;

    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }

    if (fread(&header, sizeof(header), 1, file) != 1 ||
        memcmp(header.magic, MFT_SPOOL_INDEX_MAGIC, 8U) != 0 ||
        header.version != MFT_SPOOL_INDEX_VERSION ||
        header.kind != expected_kind ||
        header.header_size != sizeof(header) ||
        header.row_size != row_size) {
        fclose(file);
        return 0;
    }

    expected_crc = crc32_compute(&header, sizeof(header) - sizeof(header.header_crc32));
    if (header.header_crc32 != expected_crc) {
        fclose(file);
        return 0;
    }

    if (header.row_count > ((uint64_t)SIZE_MAX / row_size)) {
        fclose(file);
        return 0;
    }

    row_count = (size_t)header.row_count;
    if (row_count > 0) {
        rows = malloc(row_count * row_size);
        if (rows == NULL) {
            fclose(file);
            return 0;
        }
        if (fread(rows, row_size, row_count, file) != row_count) {
            free(rows);
            fclose(file);
            return 0;
        }
    }

    fclose(file);
    *out_rows = rows;
    *out_count = row_count;
    return 1;
}

static int write_index_rows(
    const char *path,
    uint16_t kind,
    size_t row_size,
    const void *rows,
    size_t row_count
)
{
    FILE *file;
    int ok = 0;

    if (!spool_output_path_write_guard_allows(path, "write NTFS spool index")) {
        return 0;
    }
    file = fopen(path, "wb");
    if (file == NULL) {
        return 0;
    }

    if (write_index_header(
            file,
            kind,
            (uint32_t)row_size,
            (uint64_t)row_count) &&
        (row_count == 0U ||
         fwrite(rows, row_size, row_count, file) == row_count) &&
        fflush(file) == 0) {
        ok = 1;
    }

    fclose(file);
    return ok;
}

static int collect_probe_segment_readers(
    MftSpoolSegmentReader **out_readers,
    size_t *out_reader_count
)
{
    MftSpoolSegmentFile *files = NULL;
    size_t file_count = 0;
    MftSpoolSegmentReader *readers = NULL;
    size_t i;

    if (out_readers == NULL || out_reader_count == NULL) {
        return 0;
    }

    *out_readers = NULL;
    *out_reader_count = 0;

    if (!collect_segment_files(MFT_SPOOL_SEGMENT_PROBE, &files, &file_count)) {
        return 0;
    }
    if (file_count > 1U) {
        qsort(files, file_count, sizeof(*files), compare_segment_files);
    }

    if (file_count > 0U) {
        readers = (MftSpoolSegmentReader *)calloc(file_count, sizeof(*readers));
        if (readers == NULL) {
            free(files);
            return 0;
        }
        for (i = 0; i < file_count; i++) {
            readers[i].segment_number = files[i].segment_number;
            snprintf(readers[i].path, sizeof(readers[i].path), "%s", files[i].path);
        }
    }

    free(files);
    *out_readers = readers;
    *out_reader_count = file_count;
    return 1;
}

static void close_probe_segment_readers(MftSpoolSegmentReader *readers, size_t reader_count)
{
    size_t i;

    if (readers == NULL) {
        return;
    }

    for (i = 0; i < reader_count; i++) {
        if (readers[i].file != NULL) {
            fclose(readers[i].file);
        }
    }
    free(readers);
}

static FILE *open_probe_segment_reader(
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    uint32_t segment_number
)
{
    size_t i;

    if (readers == NULL) {
        return NULL;
    }

    for (i = 0; i < reader_count; i++) {
        if (readers[i].segment_number != segment_number) {
            continue;
        }
        if (readers[i].file == NULL) {
            readers[i].file = fopen(readers[i].path, "rb");
        }
        return readers[i].file;
    }

    return NULL;
}

static int load_probe_payload_from_row(
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    uint32_t segment_number,
    uint64_t spool_record_offset,
    MftSpoolProbePayload *out_payload
)
{
    FILE *file;
    MftSpoolRecordHeader record_header;
    unsigned char payload_buffer[MFT_SPOOL_PROBE_PAYLOAD_MAX_SIZE];
    MftSpoolProbePayload payload;
    uint32_t payload_crc;

    if (out_payload == NULL) {
        return 0;
    }

    file = open_probe_segment_reader(readers, reader_count, segment_number);
    if (file == NULL) {
        return 0;
    }

    if (fseeko(file, (off_t)spool_record_offset, SEEK_SET) != 0 ||
        fread(&record_header, sizeof(record_header), 1, file) != 1 ||
        !validate_record_header(&record_header, MFT_SPOOL_SEGMENT_PROBE) ||
        record_header.payload_size > sizeof(payload_buffer) ||
        fread(payload_buffer, record_header.payload_size, 1, file) != 1) {
        return 0;
    }

    payload_crc = crc32_compute(payload_buffer, record_header.payload_size);
    if (payload_crc != record_header.payload_crc32 ||
        !decode_probe_payload(payload_buffer, record_header.payload_size, &payload)) {
        return 0;
    }

    *out_payload = payload;
    return 1;
}

static int find_record_row(
    const MftSpoolRecordIndexRow *rows,
    size_t row_count,
    uint64_t family_id,
    int record,
    MftSpoolRecordIndexRow *out_row
)
{
    size_t left = 0;
    size_t right = row_count;

    while (left < right) {
        size_t mid = left + (right - left) / 2U;
        const MftSpoolRecordIndexRow *row = &rows[mid];

        if (row->family_id < family_id ||
            (row->family_id == family_id && row->record < record)) {
            left = mid + 1U;
        } else {
            right = mid;
        }
    }

    if (left >= row_count ||
        rows[left].family_id != family_id ||
        rows[left].record != record) {
        return 0;
    }

    if (out_row != NULL) {
        *out_row = rows[left];
    }
    return 1;
}

static size_t upper_bound_range_start(
    const MftSpoolRangeIndexRow *rows,
    size_t row_count,
    long long abs_offset
)
{
    size_t left = 0;
    size_t right = row_count;

    while (left < right) {
        size_t mid = left + (right - left) / 2U;

        if (rows[mid].data_abs_offset <= abs_offset) {
            left = mid + 1U;
        } else {
            right = mid;
        }
    }

    return left;
}

static long long *build_range_prefix_max(
    const MftSpoolRangeIndexRow *rows,
    size_t row_count
)
{
    long long *prefix = NULL;
    size_t i;

    if (row_count == 0) {
        return NULL;
    }

    prefix = (long long *)malloc(row_count * sizeof(*prefix));
    if (prefix == NULL) {
        return NULL;
    }

    prefix[0] = rows[0].data_end_abs_offset;
    for (i = 1; i < row_count; i++) {
        prefix[i] = prefix[i - 1];
        if (rows[i].data_end_abs_offset > prefix[i]) {
            prefix[i] = rows[i].data_end_abs_offset;
        }
    }

    return prefix;
}

static int lookup_range_row_for_offset(
    const MftSpoolRangeIndexRow *rows,
    const long long *prefix_max_end,
    size_t row_count,
    long long abs_offset,
    MftSpoolRangeIndexRow *out_row
)
{
    size_t lower;
    size_t upper;
    size_t i;

    if (rows == NULL || row_count == 0 || abs_offset < 0) {
        return 0;
    }

    lower = upper_bound_range_start(rows, row_count, abs_offset);
    upper = lower;

    while (lower > 0U && rows[lower - 1U].data_abs_offset == abs_offset) {
        lower--;
    }

    for (i = lower; i < upper; i++) {
        if (rows[i].data_end_abs_offset > abs_offset) {
            if (out_row != NULL) {
                *out_row = rows[i];
            }
            return 1;
        }
    }

    if (lower == 0U) {
        return 0;
    }

    i = lower - 1U;
    for (;;) {
        if (rows[i].data_end_abs_offset > abs_offset) {
            long long best_start = rows[i].data_abs_offset;
            MftSpoolRangeIndexRow best_row = rows[i];

            while (i > 0U && rows[i - 1U].data_abs_offset == best_start) {
                i--;
                if (rows[i].data_end_abs_offset > abs_offset) {
                    best_row = rows[i];
                }
            }

            if (out_row != NULL) {
                *out_row = best_row;
            }
            return 1;
        }

        if (i == 0U || prefix_max_end[i - 1U] <= abs_offset) {
            break;
        }
        i--;
    }

    return 0;
}

static int range_row_starts_at_offset(
    const MftSpoolRangeIndexRow *row,
    long long abs_offset
)
{
    return row != NULL &&
           abs_offset >= 0 &&
           row->data_abs_offset == abs_offset &&
           row->data_end_abs_offset > abs_offset;
}

static int build_relative_path_for_record(
    const MftSpoolRecordIndexRow *record_rows,
    size_t record_count,
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    uint64_t family_id,
    int record,
    char *out,
    size_t out_size,
    int *out_complete,
    time_t *out_created_time
)
{
    char components[64][256];
    size_t component_count = 0;
    int complete = 0;
    int saw_users = 0;
    int current_record = record;
    int depth;

    if (out == NULL || out_size == 0 || record < 0) {
        return 0;
    }

    out[0] = '\0';
    if (out_complete != NULL) {
        *out_complete = 0;
    }
    if (out_created_time != NULL) {
        *out_created_time = (time_t)0;
    }

    for (depth = 0; depth < 64; depth++) {
        MftSpoolRecordIndexRow row;
        MftSpoolProbePayload payload;

        if (!find_record_row(record_rows, record_count, family_id, current_record, &row) ||
            !load_probe_payload_from_row(
                readers,
                reader_count,
                row.segment_number,
                row.spool_record_offset,
                &payload)) {
            break;
        }

        if (name_is_ntfs_metadata(payload.fixed.base.name, payload.fixed.base.record)) {
            return 0;
        }
        if (is_users_component(payload.fixed.base.name)) {
            saw_users = 1;
        }
        if (out_created_time != NULL && depth == 0) {
            *out_created_time = filetime_to_unix(payload.fixed.base.created_filetime);
        }
        sanitize_component(
            payload.fixed.base.name,
            components[component_count],
            sizeof(components[0])
        );
        if (!text_present(components[component_count])) {
            return 0;
        }
        component_count++;

        if (payload.fixed.base.parent == 5U) {
            complete = 1;
            break;
        }
        if (payload.fixed.base.parent > (uint64_t)INT_MAX) {
            break;
        }
        current_record = (int)payload.fixed.base.parent;
    }

    if (component_count == 0U) {
        return 0;
    }

    for (depth = (int)component_count - 1; depth >= 0; depth--) {
        if (!append_component(out, out_size, components[depth])) {
            return 0;
        }
    }

    if (g_contextual_output_mode == MFT_CONTEXTUAL_OUTPUT_USERS_ONLY && !saw_users) {
        return 0;
    }

    if (out_complete != NULL) {
        *out_complete = complete;
    }
    return 1;
}

static int load_latest_recovered_events(
    MftSpoolRecoveredEvent **out_events,
    size_t *out_event_count
)
{
    MftSpoolSegmentFile *files = NULL;
    size_t file_count = 0;
    MftSpoolRecoveredEvent *events = NULL;
    size_t event_count = 0;
    size_t event_capacity = 0;
    uint64_t ordinal = 0;
    size_t i;

    if (out_events == NULL || out_event_count == NULL) {
        return 0;
    }

    *out_events = NULL;
    *out_event_count = 0;

    if (!collect_segment_files(MFT_SPOOL_SEGMENT_RECOVERED, &files, &file_count)) {
        return 0;
    }
    if (file_count > 1U) {
        qsort(files, file_count, sizeof(*files), compare_segment_files);
    }

    for (i = 0; i < file_count; i++) {
        FILE *file = fopen(files[i].path, "rb");
        MftSpoolFileHeader file_header;
        uint64_t offset = sizeof(MftSpoolFileHeader);

        if (file == NULL) {
            continue;
        }
        if (!validate_file_header(file, MFT_SPOOL_SEGMENT_RECOVERED, &file_header)) {
            fclose(file);
            continue;
        }

        while (1) {
            MftSpoolRecordHeader record_header;
            MftSpoolRecoveredPayloadHeader payload_header;
            unsigned char *path_buffer = NULL;
            uint32_t payload_crc;
            uint64_t record_offset;
            uint64_t resync_offset;
            int eof = 0;

            if (!read_next_spool_record_header(
                    file,
                    MFT_SPOOL_SEGMENT_RECOVERED,
                    &offset,
                    &record_header,
                    &eof) ||
                eof) {
                break;
            }
            record_offset = offset;
            if (record_header.payload_size < sizeof(payload_header) ||
                fread(&payload_header, sizeof(payload_header), 1, file) != 1 ||
                payload_header.path_length > MFT_SPOOL_MAX_RECOVERED_PATH ||
                sizeof(payload_header) + payload_header.path_length != record_header.payload_size) {
                clearerr(file);
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_RECOVERED,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }

            path_buffer = (unsigned char *)malloc((size_t)payload_header.path_length + 1U);
            if (path_buffer == NULL) {
                fclose(file);
                free(files);
                return 0;
            }
            if (fread(path_buffer, payload_header.path_length, 1, file) != 1) {
                free(path_buffer);
                clearerr(file);
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_RECOVERED,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }
            path_buffer[payload_header.path_length] = '\0';

            {
                unsigned char payload_buffer[sizeof(payload_header) + MFT_SPOOL_MAX_RECOVERED_PATH];

                memcpy(payload_buffer, &payload_header, sizeof(payload_header));
                memcpy(payload_buffer + sizeof(payload_header), path_buffer, payload_header.path_length);
                payload_crc = crc32_compute(
                    payload_buffer,
                    sizeof(payload_header) + payload_header.path_length
                );
            }
            if (payload_crc != record_header.payload_crc32) {
                free(path_buffer);
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_RECOVERED,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }

            if (event_count == event_capacity) {
                size_t new_capacity = event_capacity == 0U ? 256U : event_capacity * 2U;
                MftSpoolRecoveredEvent *new_events = (MftSpoolRecoveredEvent *)realloc(
                    events,
                    new_capacity * sizeof(*new_events)
                );

                if (new_events == NULL) {
                    free(path_buffer);
                    fclose(file);
                    free(files);
                    return 0;
                }

                events = new_events;
                event_capacity = new_capacity;
            }

            events[event_count].abs_offset = payload_header.abs_offset;
            events[event_count].ordinal = ordinal++;
            events[event_count].path = (char *)path_buffer;
            event_count++;
            offset = record_offset + (uint64_t)record_header.total_size;
        }

        fclose(file);
    }

    free(files);

    if (event_count == 0U) {
        *out_events = NULL;
        *out_event_count = 0;
        return 1;
    }

    qsort(events, event_count, sizeof(*events), compare_recovered_events);

    {
        size_t write_index = 0;
        for (i = 0; i < event_count; i++) {
            if (write_index > 0U &&
                events[write_index - 1U].abs_offset == events[i].abs_offset) {
                free(events[write_index - 1U].path);
                events[write_index - 1U] = events[i];
            } else {
                if (write_index != i) {
                    events[write_index] = events[i];
                }
                write_index++;
            }
        }
        event_count = write_index;
    }

    *out_events = events;
    *out_event_count = event_count;
    return 1;
}

static int load_recovered_events_from_log(
    MftSpoolRecoveredEvent **out_events,
    size_t *out_event_count
)
{
    char log_path[1024];
    FILE *file = NULL;
    MftSpoolRecoveredEvent *events = NULL;
    size_t event_count = 0;
    size_t event_capacity = 0;
    uint64_t ordinal = 0;
    char line[4096];
    int ok = 0;

    if (out_events == NULL || out_event_count == NULL) {
        return 0;
    }

    *out_events = NULL;
    *out_event_count = 0;

    if (!build_recovered_outputs_log_path(log_path, sizeof(log_path))) {
        return 0;
    }

    file = fopen(log_path, "r");
    if (file == NULL) {
        return 1;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *tab;
        char *path;
        char *tab2;
        long long abs_offset;
        int reconciled = 0;

        if (strncmp(line, "offset\tpath", 11) == 0) {
            continue;
        }

        tab = strchr(line, '\t');
        if (tab == NULL) {
            continue;
        }
        *tab = '\0';
        path = tab + 1;
        tab2 = strchr(path, '\t');
        if (tab2 != NULL) {
            *tab2 = '\0';
            reconciled = atoi(tab2 + 1);
        }
        path[strcspn(path, "\r\n")] = '\0';
        if (!text_present(path) ||
            sscanf(line, "%lld", &abs_offset) != 1 ||
            abs_offset < 0 ||
            reconciled) {
            continue;
        }

        if (event_count == event_capacity) {
            size_t new_capacity = event_capacity == 0U ? 256U : event_capacity * 2U;
            MftSpoolRecoveredEvent *new_events = (MftSpoolRecoveredEvent *)realloc(
                events,
                new_capacity * sizeof(*new_events)
            );

            if (new_events == NULL) {
                goto cleanup;
            }

            events = new_events;
            event_capacity = new_capacity;
        }

        events[event_count].abs_offset = abs_offset;
        events[event_count].ordinal = ordinal++;
        events[event_count].path = strdup(path);
        if (events[event_count].path == NULL) {
            goto cleanup;
        }
        event_count++;
    }

    if (event_count > 1U) {
        size_t i;
        size_t write_index = 0;

        qsort(events, event_count, sizeof(*events), compare_recovered_events);
        for (i = 0; i < event_count; i++) {
            if (write_index > 0U &&
                events[write_index - 1U].abs_offset == events[i].abs_offset) {
                free(events[write_index - 1U].path);
                events[write_index - 1U] = events[i];
            } else {
                if (write_index != i) {
                    events[write_index] = events[i];
                }
                write_index++;
            }
        }
        event_count = write_index;
    }

    *out_events = events;
    *out_event_count = event_count;
    events = NULL;
    ok = 1;

cleanup:
    if (file != NULL) {
        fclose(file);
    }
    if (events != NULL) {
        free_recovered_events(events, event_count);
    }
    return ok;
}

static int merge_recovered_event_lists(
    MftSpoolRecoveredEvent **io_base_events,
    size_t *io_base_count,
    MftSpoolRecoveredEvent *extra_events,
    size_t extra_count
)
{
    MftSpoolRecoveredEvent *merged;
    size_t base_count;
    size_t total_count;
    size_t i;
    size_t write_index = 0U;

    if (io_base_events == NULL || io_base_count == NULL) {
        free_recovered_events(extra_events, extra_count);
        return 0;
    }
    if (extra_count == 0U) {
        free(extra_events);
        return 1;
    }

    base_count = *io_base_count;
    if (base_count > SIZE_MAX - extra_count) {
        free_recovered_events(extra_events, extra_count);
        return 0;
    }
    total_count = base_count + extra_count;
    merged = (MftSpoolRecoveredEvent *)realloc(
        *io_base_events,
        total_count * sizeof(*merged)
    );
    if (merged == NULL) {
        free_recovered_events(extra_events, extra_count);
        return 0;
    }
    *io_base_events = merged;
    for (i = 0U; i < extra_count; i++) {
        extra_events[i].ordinal += (uint64_t)base_count + 1U;
        (*io_base_events)[base_count + i] = extra_events[i];
    }
    free(extra_events);

    if (total_count > 1U) {
        qsort(*io_base_events, total_count, sizeof(**io_base_events), compare_recovered_events);
    }

    for (i = 0U; i < total_count; i++) {
        if (write_index > 0U &&
            (*io_base_events)[write_index - 1U].abs_offset ==
                (*io_base_events)[i].abs_offset) {
            int kept_exists =
                text_present((*io_base_events)[write_index - 1U].path) &&
                access((*io_base_events)[write_index - 1U].path, F_OK) == 0;
            int incoming_exists =
                text_present((*io_base_events)[i].path) &&
                access((*io_base_events)[i].path, F_OK) == 0;

            if (kept_exists && !incoming_exists) {
                free((*io_base_events)[i].path);
                continue;
            }

            /*
             * Prefer a path that still exists.  If both candidates are equally
             * usable, keep the later ordinal: recovered_outputs.tsv often knows
             * the current path after prior moves, while old spool segment rows
             * may point at where the file used to be.
             */
            free((*io_base_events)[write_index - 1U].path);
            (*io_base_events)[write_index - 1U] = (*io_base_events)[i];
        } else {
            if (write_index != i) {
                (*io_base_events)[write_index] = (*io_base_events)[i];
            }
            write_index++;
        }
    }
    *io_base_count = write_index;
    return 1;
}

static int load_recovered_events_for_background_sweep(
    MftSpoolRecoveredEvent **out_events,
    size_t *out_event_count
)
{
    MftSpoolRecoveredEvent *events = NULL;
    MftSpoolRecoveredEvent *log_events = NULL;
    size_t event_count = 0U;
    size_t log_event_count = 0U;

    if (out_events == NULL || out_event_count == NULL) {
        return 0;
    }
    *out_events = NULL;
    *out_event_count = 0U;

    if (!load_latest_recovered_events(&events, &event_count)) {
        return 0;
    }
    if (!load_recovered_events_from_log(&log_events, &log_event_count)) {
        free_recovered_events(events, event_count);
        return 0;
    }
    if (!merge_recovered_event_lists(
            &events,
            &event_count,
            log_events,
            log_event_count)) {
        free_recovered_events(events, event_count);
        return 0;
    }

    *out_events = events;
    *out_event_count = event_count;
    return 1;
}

static int load_recovered_delta_events_with_cursors(
    MftSpoolSegmentCursor **cursor_set,
    size_t *cursor_count,
    size_t max_events,
    MftSpoolRecoveredEvent **out_events,
    size_t *out_event_count
)
{
    MftSpoolSegmentFile *files = NULL;
    size_t file_count = 0;
    MftSpoolRecoveredEvent *events = NULL;
    size_t event_count = 0;
    size_t event_capacity = 0;
    uint64_t ordinal = 0;
    size_t i;

    if (cursor_set == NULL || cursor_count == NULL ||
        out_events == NULL || out_event_count == NULL) {
        return 0;
    }

    *out_events = NULL;
    *out_event_count = 0;

    if (!collect_segment_files(MFT_SPOOL_SEGMENT_RECOVERED, &files, &file_count)) {
        return 0;
    }
    if (file_count > 1U) {
        qsort(files, file_count, sizeof(*files), compare_segment_files);
    }

    for (i = 0; i < file_count; i++) {
        FILE *file = fopen(files[i].path, "rb");
        MftSpoolFileHeader file_header;
        MftSpoolSegmentCursor *cursor;
        uint64_t offset;

        if (file == NULL) {
            continue;
        }
        if (!validate_file_header(file, MFT_SPOOL_SEGMENT_RECOVERED, &file_header)) {
            fclose(file);
            continue;
        }

        cursor = ensure_segment_cursor(
            cursor_set,
            cursor_count,
            files[i].segment_number);
        if (cursor == NULL) {
            fclose(file);
            free(files);
            free_recovered_events(events, event_count);
            return 0;
        }

        offset = cursor->next_offset;
        if (offset < sizeof(MftSpoolFileHeader)) {
            offset = sizeof(MftSpoolFileHeader);
        }

        while (1) {
            MftSpoolRecordHeader record_header;
            MftSpoolRecoveredPayloadHeader payload_header;
            unsigned char *path_buffer = NULL;
            uint32_t payload_crc;
            uint64_t record_offset;
            uint64_t resync_offset;
            int eof = 0;

            if (!read_next_spool_record_header(
                    file,
                    MFT_SPOOL_SEGMENT_RECOVERED,
                    &offset,
                    &record_header,
                    &eof) ||
                eof) {
                break;
            }
            record_offset = offset;
            if (record_header.payload_size < sizeof(payload_header) ||
                fread(&payload_header, sizeof(payload_header), 1, file) != 1 ||
                payload_header.path_length > MFT_SPOOL_MAX_RECOVERED_PATH ||
                sizeof(payload_header) + payload_header.path_length != record_header.payload_size) {
                clearerr(file);
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_RECOVERED,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }

            path_buffer = (unsigned char *)malloc((size_t)payload_header.path_length + 1U);
            if (path_buffer == NULL) {
                fclose(file);
                free(files);
                free_recovered_events(events, event_count);
                return 0;
            }
            if (fread(path_buffer, payload_header.path_length, 1, file) != 1) {
                free(path_buffer);
                clearerr(file);
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_RECOVERED,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }
            path_buffer[payload_header.path_length] = '\0';

            {
                unsigned char payload_buffer[sizeof(payload_header) + MFT_SPOOL_MAX_RECOVERED_PATH];

                memcpy(payload_buffer, &payload_header, sizeof(payload_header));
                memcpy(payload_buffer + sizeof(payload_header), path_buffer, payload_header.path_length);
                payload_crc = crc32_compute(
                    payload_buffer,
                    sizeof(payload_header) + payload_header.path_length
                );
            }
            if (payload_crc != record_header.payload_crc32) {
                free(path_buffer);
                if (find_next_spool_boundary(
                        file,
                        record_offset + 1U,
                        MFT_SPOOL_SEGMENT_RECOVERED,
                        &resync_offset)) {
                    offset = resync_offset;
                    continue;
                }
                break;
            }

            if (event_count == event_capacity) {
                size_t new_capacity = event_capacity == 0U ? 128U : event_capacity * 2U;
                MftSpoolRecoveredEvent *new_events = (MftSpoolRecoveredEvent *)realloc(
                    events,
                    new_capacity * sizeof(*new_events)
                );

                if (new_events == NULL) {
                    free(path_buffer);
                    fclose(file);
                    free(files);
                    free_recovered_events(events, event_count);
                    return 0;
                }

                events = new_events;
                event_capacity = new_capacity;
            }

            events[event_count].abs_offset = payload_header.abs_offset;
            events[event_count].ordinal = ordinal++;
            events[event_count].path = (char *)path_buffer;
            event_count++;
            offset = record_offset + (uint64_t)record_header.total_size;
            if (max_events > 0U && event_count >= max_events) {
                break;
            }
        }

        cursor->next_offset = offset;
        fclose(file);
        if (max_events > 0U && event_count >= max_events) {
            break;
        }
    }

    free(files);

    if (event_count == 0U) {
        *out_events = NULL;
        *out_event_count = 0;
        return 1;
    }

    qsort(events, event_count, sizeof(*events), compare_recovered_events);
    {
        size_t write_index = 0;
        for (i = 0; i < event_count; i++) {
            if (write_index > 0U &&
                events[write_index - 1U].abs_offset == events[i].abs_offset) {
                free(events[write_index - 1U].path);
                events[write_index - 1U] = events[i];
            } else {
                if (write_index != i) {
                    events[write_index] = events[i];
                }
                write_index++;
            }
        }
        event_count = write_index;
    }

    *out_events = events;
    *out_event_count = event_count;
    return 1;
}

static int load_recovered_delta_events(
    size_t max_events,
    MftSpoolRecoveredEvent **out_events,
    size_t *out_event_count
)
{
    return load_recovered_delta_events_with_cursors(
        &g_recovered_cursors,
        &g_recovered_cursor_count,
        max_events,
        out_events,
        out_event_count);
}

static int load_repair_delta_events(
    size_t max_events,
    MftSpoolRecoveredEvent **out_events,
    size_t *out_event_count
)
{
    return load_recovered_delta_events_with_cursors(
        &g_repair_cursors,
        &g_repair_cursor_count,
        max_events,
        out_events,
        out_event_count);
}

static void free_recovered_events(MftSpoolRecoveredEvent *events, size_t event_count)
{
    size_t i;

    if (events == NULL) {
        return;
    }

    for (i = 0; i < event_count; i++) {
        free(events[i].path);
    }
    free(events);
}

static int stat_regular_file_size_local(const char *path, uint64_t *out_size)
{
    struct stat st;

    if (!text_present(path) || stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return 0;
    }
    if (out_size != NULL) {
        *out_size = (uint64_t)st.st_size;
    }
    return 1;
}

static uint64_t size_gap_local(uint64_t lhs, uint64_t rhs)
{
    return lhs > rhs ? (lhs - rhs) : (rhs - lhs);
}

static int extension_is_jpeg_local(const char *extension)
{
    return text_present(extension) &&
           (strcmp(extension, "jpg") == 0 || strcmp(extension, "jpeg") == 0);
}

static int path_is_in_unident_local(const char *path)
{
    return text_present(path) &&
           (strstr(path, "/" APP_UNIDENT_RELATIVE_DIR "/") != NULL ||
            strstr(path, "/" APP_LEGACY_UNIDENT_RELATIVE_DIR "/") != NULL);
}

static int path_is_in_partial_tree_local(const char *path)
{
    return text_present(path) &&
           (strstr(path, "/" APP_PARTIAL_TREE_RELATIVE_DIR "/") != NULL ||
            strstr(path, "/" APP_LEGACY_PARTIAL_TREE_RELATIVE_DIR "/") != NULL);
}

static int build_scan_state_path_local(char *out, size_t out_size)
{
    return build_state_child_path(out, out_size, "scan_state.txt");
}

static int build_recovered_root_path_local(char *out, size_t out_size)
{
    if (!text_present(g_output_dir) || out == NULL || out_size == 0U) {
        return 0;
    }

    return snprintf(
        out,
        out_size,
        "%s/%s",
        g_output_dir,
        APP_RECOVERED_DIR_NAME) < (int)out_size;
}

static int collect_recovered_tree_stats_recursive(
    const char *path,
    int in_unident,
    uint64_t *io_total,
    uint64_t *io_unident,
    uint64_t *io_repair_pending
)
{
    DIR *dir = NULL;
    struct dirent *entry = NULL;

    if (!text_present(path) ||
        io_total == NULL ||
        io_unident == NULL ||
        io_repair_pending == NULL) {
        return 0;
    }

    dir = opendir(path);
    if (dir == NULL) {
        return errno == ENOENT;
    }

    while ((entry = readdir(dir)) != NULL) {
        char child[2048];
        struct stat st;
        int child_in_unident = in_unident;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >= (int)sizeof(child)) {
            continue;
        }
        if (lstat(child, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!in_unident &&
                (strcmp(entry->d_name, APP_UNIDENT_DIR_NAME) == 0 ||
                 strcmp(entry->d_name, APP_LEGACY_UNIDENT_DIR_NAME) == 0)) {
                child_in_unident = 1;
            }
            if (!collect_recovered_tree_stats_recursive(
                    child,
                    child_in_unident,
                    io_total,
                    io_unident,
                    io_repair_pending)) {
                closedir(dir);
                return 0;
            }
            continue;
        }

        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        if (strcmp(entry->d_name, ".DS_Store") == 0) {
            continue;
        }

        (*io_total)++;
        if (in_unident) {
            char ext[32];

            (*io_unident)++;
            lower_extension_from_name(entry->d_name, ext, sizeof(ext));
            if (extension_is_jpeg_local(ext)) {
                (*io_repair_pending)++;
            }
        }
    }

    closedir(dir);
    return 1;
}

static int collect_recovered_tree_stats(
    uint64_t *out_total,
    uint64_t *out_named,
    uint64_t *out_unident,
    uint64_t *out_repair_pending
)
{
    char recovered_root[1024];
    uint64_t total = 0U;
    uint64_t unident = 0U;
    uint64_t repair_pending = 0U;

    if (out_total == NULL ||
        out_named == NULL ||
        out_unident == NULL ||
        out_repair_pending == NULL ||
        !build_recovered_root_path_local(recovered_root, sizeof(recovered_root))) {
        return 0;
    }

    if (!collect_recovered_tree_stats_recursive(
            recovered_root,
            0,
            &total,
            &unident,
            &repair_pending)) {
        return 0;
    }

    *out_total = total;
    *out_named = (total >= unident) ? (total - unident) : 0U;
    *out_unident = unident;
    *out_repair_pending = repair_pending;
    return 1;
}

static int load_source_path_from_scan_state(char *out, size_t out_size)
{
    char state_path[1024];
    ScanState state = {0};

    if (out == NULL || out_size == 0U ||
        !build_scan_state_path_local(state_path, sizeof(state_path)) ||
        !scan_state_load(state_path, &state) ||
        !text_present(state.source_path)) {
        return 0;
    }

    return snprintf(out, out_size, "%s", state.source_path) < (int)out_size;
}

static void refresh_scan_stall_state(time_t now, uint64_t recovered_bytes)
{
    char state_path[1024];
    ScanState state = {0};
    MftSpoolProgressSnapshot current = {0};

    g_live_scan_stalled_seconds = 0ULL;

    if (!build_scan_state_path_local(state_path, sizeof(state_path)) ||
        !scan_state_load(state_path, &state) ||
        state.completed || state.scan_completed) {
        g_background_last_scan_offset = 0;
        g_background_last_scan_change = 0;
        g_background_last_foreground_activity = 0;
        g_background_last_stall_log_seconds = 0ULL;
        g_background_stall_watch_armed = 0;
        memset(&g_background_last_progress, 0, sizeof(g_background_last_progress));
        return;
    }

    current.scan_offset = state.scan_offset;
    current.recovered_bytes = recovered_bytes;
    current.renamed_outputs = g_live_renamed_outputs;
    current.repaired_outputs = g_live_repaired_outputs;
    current.recovered_outputs_current = g_live_recovered_outputs_current;
    current.named_outputs_current = g_live_named_outputs_current;
    current.unident_outputs_current = g_live_unident_outputs_current;
    current.repair_pending_outputs = g_live_repair_pending_outputs;
    current.repair_queue_events = g_live_repair_queue_events;
    current.record_index_count = g_record_index_count;
    current.range_index_count = g_range_index_count;

    if (g_background_last_scan_change == 0) {
        g_background_last_scan_offset = state.scan_offset;
        g_background_last_scan_change = now;
        g_background_last_foreground_activity = now;
        g_background_last_stall_log_seconds = 0ULL;
        g_background_stall_watch_armed = 0;
        g_background_last_progress = current;
        return;
    }

    if (current.scan_offset != g_background_last_progress.scan_offset ||
        current.recovered_bytes != g_background_last_progress.recovered_bytes ||
        current.renamed_outputs != g_background_last_progress.renamed_outputs ||
        current.repaired_outputs != g_background_last_progress.repaired_outputs ||
        current.recovered_outputs_current !=
            g_background_last_progress.recovered_outputs_current ||
        current.named_outputs_current !=
            g_background_last_progress.named_outputs_current ||
        current.unident_outputs_current !=
            g_background_last_progress.unident_outputs_current ||
        current.repair_pending_outputs !=
            g_background_last_progress.repair_pending_outputs ||
        current.repair_queue_events !=
            g_background_last_progress.repair_queue_events ||
        current.record_index_count !=
            g_background_last_progress.record_index_count ||
        current.range_index_count !=
            g_background_last_progress.range_index_count) {
        g_background_stall_watch_armed = 1;
        g_background_last_scan_offset = state.scan_offset;
        g_background_last_scan_change = now;
        g_background_last_stall_log_seconds = 0ULL;
        g_background_last_progress = current;
        return;
    }

    if (!g_background_stall_watch_armed) {
        return;
    }

    if (g_live_background_phase != MFT_SPOOL_BACKGROUND_PHASE_IDLE) {
        g_background_last_scan_change = now;
        g_live_scan_stalled_seconds = 0ULL;
        return;
    }

    if (g_background_last_foreground_activity != 0 &&
        now >= g_background_last_foreground_activity &&
        now - g_background_last_foreground_activity <=
            MFT_SPOOL_FOREGROUND_ACTIVITY_GRACE_SECONDS) {
        g_live_scan_stalled_seconds = 0ULL;
        return;
    }

    if (now > g_background_last_scan_change) {
        g_live_scan_stalled_seconds =
            (unsigned long long)(now - g_background_last_scan_change);
    }
}

static int refresh_live_queue_stats(time_t now, uint64_t recovered_bytes, int force)
{
    uint64_t total = 0U;
    uint64_t named = 0U;
    uint64_t unident = 0U;
    uint64_t repair_pending = 0U;

    if (!force &&
        g_background_last_live_stats_refresh > 0 &&
        now - g_background_last_live_stats_refresh <
            MFT_SPOOL_BACKGROUND_STATS_REFRESH_INTERVAL_SECONDS) {
        return 1;
    }

    if (!force &&
        recovered_bytes == g_background_last_stats_recovered_bytes &&
        g_live_renamed_outputs == g_background_last_stats_renamed_outputs &&
        g_live_repaired_outputs == g_background_last_stats_repaired_outputs) {
        g_background_last_live_stats_refresh = now;
        return 1;
    }

    set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_TREE, now);
    if (!collect_recovered_tree_stats(&total, &named, &unident, &repair_pending)) {
        set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_IDLE, now);
        return 0;
    }
    set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_IDLE, now);

    g_live_recovered_outputs_current = total;
    g_live_named_outputs_current = named;
    g_live_unident_outputs_current = unident;
    g_live_repair_pending_outputs = repair_pending;
    g_background_last_live_stats_refresh = now;
    g_background_last_stats_recovered_bytes = recovered_bytes;
    g_background_last_stats_renamed_outputs = g_live_renamed_outputs;
    g_background_last_stats_repaired_outputs = g_live_repaired_outputs;
    return write_live_stats_file();
}

static int resolve_contextual_repair_paths(
    const MftSpoolRecordIndexRow *record_rows,
    size_t record_count,
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    const MftSpoolRangeIndexRow *range_row,
    const MftSpoolRecoveredEvent *event,
    const char *extension,
    char *target_path,
    size_t target_path_size,
    char *current_path,
    size_t current_path_size,
    time_t *out_created_time
)
{
    char relative_path[1024];
    int complete = 0;
    time_t created_time = (time_t)0;

    if (record_rows == NULL || readers == NULL || range_row == NULL ||
        event == NULL || !text_present(extension) ||
        target_path == NULL || target_path_size == 0U ||
        current_path == NULL || current_path_size == 0U) {
        return 0;
    }
    if (!range_row_starts_at_offset(range_row, event->abs_offset)) {
        return 0;
    }

    if (!build_relative_path_for_record(
            record_rows,
            record_count,
            readers,
            reader_count,
            range_row->family_id,
            range_row->record,
            relative_path,
            sizeof(relative_path),
            &complete,
            &created_time) ||
        !complete ||
        !contextual_path_is_usable_for_recovered_extension(relative_path, extension) ||
        !build_unique_context_path(
            target_path,
            target_path_size,
            relative_path,
            event->path)) {
        return 0;
    }

    if (stat_regular_file_size_local(target_path, NULL)) {
        if (snprintf(current_path, current_path_size, "%s", target_path) >= (int)current_path_size) {
            return 0;
        }
    } else if (text_present(event->path)) {
        if (snprintf(current_path, current_path_size, "%s", event->path) >= (int)current_path_size) {
            return 0;
        }
    } else {
        if (snprintf(current_path, current_path_size, "%s", target_path) >= (int)current_path_size) {
            return 0;
        }
    }

    if (out_created_time != NULL) {
        *out_created_time = created_time;
    }
    (void)complete;
    return 1;
}

static int build_jpeg_repair_target_from_payload(
    const MftSpoolProbePayload *payload,
    const char *extension,
    long long abs_offset,
    const char *output_path,
    RecoveryTarget *out_target
)
{
    size_t run_index;

    if (payload == NULL || !extension_is_jpeg_local(extension) ||
        payload->fixed.stored_run_count == 0U ||
        payload->fixed.base.data_size == 0U ||
        !text_present(output_path) ||
        out_target == NULL) {
        return 0;
    }

    memset(out_target, 0, sizeof(*out_target));
    out_target->validator_id = RECOVERY_VALIDATOR_JPEG;
    out_target->abs_offset = abs_offset >= 0
        ? (uint64_t)abs_offset
        : (payload->fixed.base.data_abs_offset >= 0
            ? (uint64_t)payload->fixed.base.data_abs_offset
            : 0U);
    out_target->size = payload->fixed.base.data_size;
    out_target->expected_size = payload->fixed.base.data_size;
    out_target->remaining = payload->fixed.base.data_size;
    out_target->record = payload->fixed.base.record;
    out_target->family =
        payload->fixed.base.family_id <= UINT32_MAX
            ? (uint32_t)payload->fixed.base.family_id
            : 0U;
    out_target->run_truncated = payload->fixed.run_truncated != 0U;
    out_target->blob_start[0] = 0xFFU;
    out_target->blob_start[1] = 0xD8U;
    out_target->blob_start[2] = 0xFFU;
    out_target->blob_start_length = 3U;
    snprintf(out_target->extension, sizeof(out_target->extension), "%s", extension);
    snprintf(out_target->output_path, sizeof(out_target->output_path), "%s", output_path);

    for (run_index = 0; run_index < payload->fixed.stored_run_count; run_index++) {
        if (payload->runs[run_index].abs_offset < 0 ||
            payload->runs[run_index].byte_length == 0U) {
            return 0;
        }
        out_target->runs[out_target->run_count].abs_offset =
            (uint64_t)payload->runs[run_index].abs_offset;
        out_target->runs[out_target->run_count].byte_length =
            payload->runs[run_index].byte_length;
        out_target->run_count++;
    }

    return out_target->run_count > 0U;
}

static int repair_single_jpeg_event(
    const MftSpoolRecordIndexRow *record_rows,
    size_t record_count,
    const MftSpoolRangeIndexRow *range_rows,
    const long long *range_prefix_max,
    size_t range_count,
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    const MftSpoolRecoveredEvent *event,
    int image_fd,
    unsigned char *buffer,
    size_t buffer_size,
    int (*stop_requested)(void)
)
{
    MftSpoolRangeIndexRow range_row;
    MftSpoolRecordIndexRow record_row;
    MftSpoolProbePayload payload;
    char extension[32];
    char target_path[1024];
    char current_path[1024];
    char temp_path[1152];
    RecoveryTarget target;
    time_t created_time = (time_t)0;
    uint64_t current_size = 0U;
    uint64_t repaired_size = 0U;
    uint64_t expected_size = 0U;
    uint64_t current_gap;
    uint64_t repaired_gap;
    int have_current = 0;
    int prefer_repaired;

    if (record_rows == NULL || range_rows == NULL || range_prefix_max == NULL ||
        readers == NULL || event == NULL || image_fd < 0 ||
        buffer == NULL || buffer_size == 0U) {
        return 0;
    }

    lower_extension_from_name(event->path, extension, sizeof(extension));
    if (!extension_is_jpeg_local(extension) ||
        !lookup_range_row_for_offset(
            range_rows,
            range_prefix_max,
            range_count,
            event->abs_offset,
            &range_row) ||
        !range_row_starts_at_offset(&range_row, event->abs_offset) ||
        !find_record_row(
            record_rows,
            record_count,
            range_row.family_id,
            range_row.record,
            &record_row) ||
        !load_probe_payload_from_row(
            readers,
            reader_count,
            record_row.segment_number,
            record_row.spool_record_offset,
            &payload) ||
        payload.fixed.stored_run_count == 0U ||
        (!payload.fixed.run_truncated && payload.fixed.stored_run_count < 2U) ||
        !resolve_contextual_repair_paths(
            record_rows,
            record_count,
            readers,
            reader_count,
            &range_row,
            event,
            extension,
            target_path,
            sizeof(target_path),
            current_path,
            sizeof(current_path),
            &created_time) ||
        !build_jpeg_repair_target_from_payload(
            &payload,
            extension,
            event->abs_offset,
            target_path,
            &target)) {
        return 0;
    }

    expected_size = payload.fixed.base.data_size;
    have_current = stat_regular_file_size_local(current_path, &current_size);
    if (have_current &&
        current_size == expected_size &&
        !path_is_in_unident_local(current_path)) {
        return 0;
    }

    if (snprintf(temp_path, sizeof(temp_path), "%s.repairing", target_path) >= (int)sizeof(temp_path)) {
        return 1;
    }
    (void)unlink(temp_path);
    snprintf(target.output_path, sizeof(target.output_path), "%s", temp_path);

    if (!recovery_runner_recover_target_best_effort_fd(
            image_fd,
            &target,
            buffer,
            buffer_size,
            stop_requested)) {
        (void)unlink(temp_path);
        return 1;
    }

    if (!stat_regular_file_size_local(temp_path, &repaired_size)) {
        (void)unlink(temp_path);
        return 1;
    }

    current_gap = have_current ? size_gap_local(current_size, expected_size) : UINT64_MAX;
    repaired_gap = size_gap_local(repaired_size, expected_size);
    prefer_repaired = !have_current ||
        repaired_gap < current_gap ||
        (repaired_gap == current_gap && strcmp(target_path, event->path) != 0);
    if (!prefer_repaired) {
        (void)unlink(temp_path);
        return 1;
    }

    if (rename(temp_path, target_path) != 0) {
        (void)unlink(temp_path);
        return 1;
    }

    if (created_time > 0) {
        (void)mft_apply_created_time_value_to_path(target_path, created_time);
    } else {
        (void)mft_apply_created_time_to_path(target_path, event->abs_offset);
    }
    (void)mft_apply_output_owner_to_path(target_path);
    if (text_present(current_path) &&
        strcmp(current_path, target_path) != 0) {
        (void)remove(current_path);
    }
    if (strcmp(event->path, target_path) != 0) {
        mft_note_recovered_output(target_path, event->abs_offset);
    }
    return 2;
}

static size_t repair_loaded_events(
    const MftSpoolRecordIndexRow *record_rows,
    size_t record_count,
    const MftSpoolRangeIndexRow *range_rows,
    const long long *range_prefix_max,
    size_t range_count,
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    MftSpoolRecoveredEvent *events,
    size_t event_count,
    size_t repair_limit,
    int (*stop_requested)(void),
    int log_missing_source
)
{
    char source_path[1024];
    unsigned char *buffer = NULL;
    size_t repaired = 0U;
    int image_fd = -1;
    size_t buffer_size;
    size_t i;

    if (record_rows == NULL || range_rows == NULL || range_prefix_max == NULL ||
        readers == NULL || events == NULL || event_count == 0U) {
        return 0U;
    }
    if (!load_source_path_from_scan_state(source_path, sizeof(source_path))) {
        if (log_missing_source) {
            log_verbose("JPEG fragment repair skipped: no saved source path was found");
        }
        return 0U;
    }

    image_fd = open(source_path, O_RDONLY);
    if (image_fd < 0) {
        if (log_missing_source) {
            log_verbose("JPEG fragment repair skipped: could not open source %s", source_path);
        }
        return 0U;
    }

    buffer_size = recovery_runner_default_read_size();
    buffer = (unsigned char *)malloc(buffer_size);
    if (buffer == NULL) {
        close(image_fd);
        return 0U;
    }

    for (i = 0; i < event_count; i++) {
        int result;

        if (stop_requested != NULL && stop_requested()) {
            break;
        }

        result = repair_single_jpeg_event(
            record_rows,
            record_count,
            range_rows,
            range_prefix_max,
            range_count,
            readers,
            reader_count,
            &events[i],
            image_fd,
            buffer,
            buffer_size,
            stop_requested
        );
        if (result == 2) {
            repaired++;
        }
        if (result > 0 && repair_limit > 0U) {
            break;
        }
    }

    free(buffer);
    close(image_fd);
    return repaired;
}

static size_t reconcile_loaded_events(
    const MftSpoolRecordIndexRow *record_rows,
    size_t record_count,
    const MftSpoolRangeIndexRow *range_rows,
    const long long *range_prefix_max,
    size_t range_count,
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    MftSpoolRecoveredEvent *events,
    size_t event_count,
    MftSpoolRecoveredFirstStats *out_stats
)
{
    MftSpoolRecoveredFirstStats stats = {0};
    size_t moved = 0;
    size_t i;

    if (out_stats != NULL) {
        *out_stats = stats;
    }

    if (record_rows == NULL || range_rows == NULL || range_prefix_max == NULL ||
        readers == NULL || events == NULL) {
        return 0;
    }

    for (i = 0; i < event_count; i++) {
        MftSpoolRangeIndexRow range_row;
        MftSpoolRecordIndexRow record_row;
        MftSpoolProbePayload payload;
        char ext[32];
        char relative_path[1024];
        char parent_relative_path[1024];
        char new_path[1024];
        char payload_extension[32];
        char current_dir[1024];
        char *slash;
        int built_relative = 0;
        int complete = 0;
        time_t created_time = (time_t)0;
        int loaded_payload = 0;
        int contextual_ok = 0;
        int partial_context_ok = 0;
        int parent_group_ok = 0;
        int exact_flat_ok = 0;
        int exact_range_match = 0;

        stats.checked++;

        if (!text_present(events[i].path)) {
            stats.skipped_no_path++;
            continue;
        }
        if (access(events[i].path, F_OK) != 0) {
            stats.skipped_missing_source++;
            continue;
        }

        lower_extension_from_name(events[i].path, ext, sizeof(ext));
        if (!text_present(ext)) {
            stats.skipped_no_extension++;
            continue;
        }

        if (!lookup_range_row_for_offset(
                range_rows,
                range_prefix_max,
                range_count,
                events[i].abs_offset,
                &range_row)) {
            stats.skipped_no_range_anchor++;
            continue;
        }
        exact_range_match = range_row_starts_at_offset(&range_row, events[i].abs_offset);

        built_relative =
            exact_range_match &&
            build_relative_path_for_record(
                record_rows,
                record_count,
                readers,
                reader_count,
                range_row.family_id,
                range_row.record,
                relative_path,
                sizeof(relative_path),
                &complete,
                &created_time) &&
            contextual_path_is_usable_for_recovered_extension(relative_path, ext);

        contextual_ok =
            built_relative &&
            complete &&
            build_unique_context_path(
                new_path,
                sizeof(new_path),
                relative_path,
                events[i].path);

        partial_context_ok =
            built_relative &&
            !complete &&
            strchr(relative_path, '/') != NULL &&
            (path_is_in_unident_local(events[i].path) ||
             path_is_in_partial_tree_local(events[i].path)) &&
            build_unique_partial_context_path_local(
                new_path,
                sizeof(new_path),
                relative_path,
                events[i].path);

        if (!contextual_ok &&
            (path_is_in_unident_local(events[i].path) ||
             path_is_in_partial_tree_local(events[i].path)) &&
            find_record_row(
                record_rows,
                record_count,
                range_row.family_id,
                range_row.record,
                &record_row) &&
            load_probe_payload_from_row(
                readers,
                reader_count,
                record_row.segment_number,
                record_row.spool_record_offset,
                &payload)) {
            loaded_payload = 1;
        }

        if (!contextual_ok && loaded_payload) {
            lower_extension_from_name(payload.fixed.base.name, payload_extension, sizeof(payload_extension));
            snprintf(current_dir, sizeof(current_dir), "%s", events[i].path);
            slash = strrchr(current_dir, '/');
            if (slash != NULL && slash != current_dir) {
                *slash = '\0';
            } else {
                current_dir[0] = '\0';
            }

            if (text_present(current_dir) &&
                text_present(payload.fixed.base.name) &&
                !name_is_ntfs_metadata(payload.fixed.base.name, payload.fixed.base.record) &&
                !basename_is_system_container_ci_local(payload.fixed.base.name)) {
                created_time = filetime_to_unix(payload.fixed.base.created_filetime);

                if (payload.fixed.base.parent > 0U &&
                    payload.fixed.base.parent != 5U &&
                    payload.fixed.base.parent != (uint64_t)payload.fixed.base.record &&
                    (exact_range_match ||
                     (range_row.data_abs_offset >= 0 &&
                      events[i].abs_offset >= range_row.data_abs_offset &&
                      events[i].abs_offset - range_row.data_abs_offset <= 65536LL))) {
                    int parent_named_ok = build_parent_relative_path_for_record_local(
                        record_rows,
                        record_count,
                        readers,
                        reader_count,
                        range_row.family_id,
                        payload.fixed.base.parent,
                        parent_relative_path,
                        sizeof(parent_relative_path)
                    );
                    if (extensions_are_same_recovery_family(payload_extension, ext)) {
                        parent_group_ok = build_unique_parent_group_path_local(
                            new_path,
                            sizeof(new_path),
                            payload.fixed.base.parent,
                            parent_named_ok ? parent_relative_path : NULL,
                            payload.fixed.base.name,
                            NULL,
                            events[i].path
                        );
                    } else {
                        parent_group_ok = build_unique_parent_group_path_local(
                            new_path,
                            sizeof(new_path),
                            payload.fixed.base.parent,
                            parent_named_ok ? parent_relative_path : NULL,
                            payload.fixed.base.name,
                            ext,
                            events[i].path
                        );
                    }
                }

                if (!parent_group_ok &&
                    extensions_are_same_recovery_family(payload_extension, ext)) {
                    exact_flat_ok = build_unique_output_path_from_flat_name_local(
                        new_path,
                        sizeof(new_path),
                        current_dir,
                        payload.fixed.base.name,
                        events[i].path);
                } else if (!parent_group_ok) {
                    exact_flat_ok = build_unique_output_path_from_flat_name_with_extension_local(
                        new_path,
                        sizeof(new_path),
                        current_dir,
                        payload.fixed.base.name,
                        ext,
                        events[i].path);
                }
            }
        }

        if (!contextual_ok && !partial_context_ok &&
            !parent_group_ok && !exact_flat_ok) {
            if (!exact_range_match) {
                stats.skipped_no_exact_range_start++;
            } else if (!built_relative) {
                stats.skipped_no_context_path++;
            } else if (!loaded_payload) {
                stats.skipped_no_payload++;
            } else {
                stats.skipped_no_commit_candidate++;
            }
            continue;
        }

        if (strcmp(new_path, events[i].path) == 0) {
            stats.skipped_same_path++;
            continue;
        }

        if (rename(events[i].path, new_path) != 0) {
            stats.rename_failures++;
            continue;
        }

        if (created_time > 0) {
            (void)mft_apply_created_time_value_to_path(new_path, created_time);
        } else {
            (void)mft_apply_created_time_to_path(new_path, events[i].abs_offset);
        }
        (void)mft_apply_output_owner_to_path(new_path);
        (void)mft_spool_append_recovered_output(new_path, events[i].abs_offset);
        if (contextual_ok) {
            stats.complete_path_moves++;
        } else if (partial_context_ok) {
            stats.partial_path_moves++;
        } else if (parent_group_ok) {
            stats.parent_group_moves++;
        } else if (exact_flat_ok) {
            stats.flat_name_moves++;
        }
        moved++;
    }

    stats.moved = (uint64_t)moved;
    if (out_stats != NULL) {
        *out_stats = stats;
    }
    return moved;
}

static size_t materialize_loaded_output_directories(
    const MftSpoolRecordIndexRow *record_rows,
    size_t record_count,
    const MftSpoolRangeIndexRow *range_rows,
    const long long *range_prefix_max,
    size_t range_count,
    MftSpoolSegmentReader *readers,
    size_t reader_count,
    MftSpoolRecoveredEvent *events,
    size_t event_count
)
{
    size_t prepared = 0U;
    size_t i;

    if (record_rows == NULL || range_rows == NULL || range_prefix_max == NULL ||
        readers == NULL || events == NULL) {
        return 0U;
    }

    for (i = 0; i < event_count; i++) {
        MftSpoolRangeIndexRow range_row;
        char ext[32];
        char relative_path[1024];
        char full_path[1024];
        char conflict_safe[1024];
        char dir_path[1024];
        char *slash;
        int complete = 0;

        if (!text_present(events[i].path)) {
            continue;
        }

        lower_extension_from_name(events[i].path, ext, sizeof(ext));
        if (!text_present(ext)) {
            continue;
        }

        if (!lookup_range_row_for_offset(
                range_rows,
                range_prefix_max,
                range_count,
                events[i].abs_offset,
                &range_row) ||
            !range_row_starts_at_offset(&range_row, events[i].abs_offset) ||
            !build_relative_path_for_record(
                record_rows,
                record_count,
                readers,
                reader_count,
                range_row.family_id,
                range_row.record,
                relative_path,
                sizeof(relative_path),
                &complete,
                NULL) ||
            !complete ||
            !contextual_path_is_usable_for_recovered_extension(relative_path, ext) ||
            !build_recovered_path(full_path, sizeof(full_path), relative_path) ||
            !mft_normalize_directory_conflicts_for_path(
                conflict_safe,
                sizeof(conflict_safe),
                full_path,
                0)) {
            continue;
        }

        snprintf(dir_path, sizeof(dir_path), "%s", conflict_safe);
        slash = strrchr(dir_path, '/');
        if (slash == NULL || slash == dir_path) {
            continue;
        }
        *slash = '\0';

        if (!ensure_directory_recursive(dir_path)) {
            continue;
        }
        (void)mft_apply_output_owner_to_path(dir_path);
        prepared++;
    }

    return prepared;
}

void mft_spool_configure(const MftSpoolConfig *config)
{
    if (config == NULL) {
        return;
    }

    snprintf(g_output_dir, sizeof(g_output_dir), "%s", text_present(config->output_dir)
        ? config->output_dir
        : APP_DEFAULT_OUTPUT_DIR);
    g_reset_existing_store = config->reset_existing_store;
    g_contextual_output_mode = config->contextual_output_mode;
    g_prepare_seen = 0;
    g_spool_state_dirty = 1;
    g_has_ntfs_geometry = 0;
    g_partition_start = 0;
    g_cluster_size = 0;
    g_record_size = MFT_PROBE_RECORD_SIZE;
    reset_background_state();
    g_probe_writer.kind = MFT_SPOOL_SEGMENT_PROBE;
    g_recovered_writer.kind = MFT_SPOOL_SEGMENT_RECOVERED;

    (void)build_state_child_path(g_spool_dir, sizeof(g_spool_dir), APP_SPOOL_DIR_NAME);
    (void)build_state_child_path(g_index_dir, sizeof(g_index_dir), APP_INDEX_DIR_NAME);
}

void mft_spool_prepare_background_child(void)
{
    if (g_probe_writer.file != NULL) {
        fclose(g_probe_writer.file);
        g_probe_writer.file = NULL;
        g_probe_writer.prepared = 0;
        g_probe_writer.kind = MFT_SPOOL_SEGMENT_PROBE;
    }
    if (g_recovered_writer.file != NULL) {
        fclose(g_recovered_writer.file);
        g_recovered_writer.file = NULL;
        g_recovered_writer.prepared = 0;
        g_recovered_writer.kind = MFT_SPOOL_SEGMENT_RECOVERED;
    }
}

void mft_spool_set_geometry(
    int has_ntfs_geometry,
    long long partition_start,
    uint32_t cluster_size,
    uint32_t record_size
)
{
    int changed = 0;

    if (g_has_ntfs_geometry != has_ntfs_geometry ||
        g_partition_start != partition_start ||
        g_cluster_size != cluster_size ||
        (record_size > 0 && g_record_size != record_size)) {
        changed = 1;
    }

    g_has_ntfs_geometry = has_ntfs_geometry;
    g_partition_start = partition_start;
    g_cluster_size = cluster_size;
    if (record_size > 0) {
        g_record_size = record_size;
    }
    if (changed) {
        g_spool_state_dirty = 1;
        discard_geometry_dependent_indices();
    }
    if (text_present(g_output_dir) && g_spool_state_dirty) {
        if (write_spool_state_file()) {
            g_spool_state_dirty = 0;
        }
    }
}

int mft_spool_prepare(void)
{
    if (!g_prepare_seen && g_reset_existing_store) {
        char path[1024];

        if (build_index_path(path, sizeof(path), "record.idx")) {
            (void)unlink(path);
        }
        if (build_index_path(path, sizeof(path), "range.idx")) {
            (void)unlink(path);
        }
    }
    g_prepare_seen = 1;

    if (!text_present(g_output_dir)) {
        return 0;
    }

    if (g_spool_state_dirty && !write_spool_state_file()) {
        log_error("Failed to persist spool state metadata");
        return 0;
    }
    g_spool_state_dirty = 0;

    if (!writer_prepare(&g_probe_writer)) {
        log_error("Failed to prepare MFT probe spool");
        return 0;
    }
    if (!writer_prepare(&g_recovered_writer)) {
        log_error("Failed to prepare recovered-output spool");
        return 0;
    }
    return 1;
}

int mft_spool_artifacts_available(void)
{
    MftSpoolSegmentFile *probe_files = NULL;
    size_t probe_count = 0;
    char record_index_path[1024];

    if (!text_present(g_output_dir)) {
        return 0;
    }

    if (collect_segment_files(MFT_SPOOL_SEGMENT_PROBE, &probe_files, &probe_count)) {
        free(probe_files);
        if (probe_count > 0U) {
            return 1;
        }
    }

    if (build_index_path(record_index_path, sizeof(record_index_path), "record.idx") &&
        regular_file_exists(record_index_path)) {
        return 1;
    }

    return 0;
}

int mft_spool_load_resume_artifacts(void)
{
    MftSpoolLiveStats live_stats = {0};

    (void)load_spool_state_file();
    if (load_live_stats_file(&live_stats)) {
        g_live_renamed_outputs = live_stats.renamed_outputs;
        g_live_repaired_outputs = live_stats.repaired_outputs;
        g_live_recovered_outputs_current =
            live_stats.recovered_outputs_current;
        g_live_named_outputs_current = live_stats.named_outputs_current;
        g_live_unident_outputs_current = live_stats.unident_outputs_current;
        g_live_repair_pending_outputs = live_stats.repair_pending_outputs;
        g_live_repair_queue_events = live_stats.repair_queue_events;
        g_record_index_count = live_stats.record_index_count;
        g_range_index_count = live_stats.range_index_count;
    }
    return mft_spool_artifacts_available();
}

void mft_spool_close(void)
{
    if (g_probe_writer.file != NULL) {
        (void)writer_seal(&g_probe_writer);
        memset(&g_probe_writer, 0, sizeof(g_probe_writer));
        g_probe_writer.kind = MFT_SPOOL_SEGMENT_PROBE;
    }
    if (g_recovered_writer.file != NULL) {
        (void)writer_seal(&g_recovered_writer);
        memset(&g_recovered_writer, 0, sizeof(g_recovered_writer));
        g_recovered_writer.kind = MFT_SPOOL_SEGMENT_RECOVERED;
    }
}

int mft_spool_append_probe(const MftProbeEntry *entry)
{
    MftSpoolProbePayload payload;
    uint64_t family_id;
    size_t stored_run_count;
    size_t run_index;
    size_t payload_size;

    if (entry == NULL || entry->record < 0 || !text_present(entry->name)) {
        return 0;
    }
    g_probe_writer.kind = MFT_SPOOL_SEGMENT_PROBE;
    if (!mft_spool_prepare()) {
        return 0;
    }

    memset(&payload, 0, sizeof(payload));
    family_id = assign_family_id(entry);
    payload.fixed.base.family_id = family_id;
    payload.fixed.base.record_offset = entry->offset;
    payload.fixed.base.record = entry->record;
    payload.fixed.base.raw_record = entry->raw_record;
    payload.fixed.base.parent = entry->parent;
    payload.fixed.base.parent_seq = entry->parent_seq;
    payload.fixed.base.flags = entry->flags;
    payload.fixed.base.record_used_size = entry->record_used_size;
    payload.fixed.base.record_allocated_size = entry->record_allocated_size;
    payload.fixed.base.created_filetime = entry->created_filetime;
    payload.fixed.base.data_abs_offset = -1;
    payload.fixed.base.data_end_abs_offset = -1;
    payload.fixed.base.data_size = entry->data_size;
    payload.fixed.base.first_lcn = entry->first_lcn;
    payload.fixed.base.run_clusters = entry->run_clusters;
    payload.fixed.base.has_data = entry->has_data ? 1U : 0U;
    payload.fixed.base.resident = entry->resident ? 1U : 0U;
    snprintf(payload.fixed.base.name, sizeof(payload.fixed.base.name), "%s", entry->name);
    payload.fixed.run_count = entry->run_count;
    payload.fixed.run_total_clusters = entry->run_total_clusters;
    payload.fixed.max_lcn_end = entry->max_lcn_end;
    stored_run_count = entry->stored_run_count;
    if (stored_run_count > MFT_ENTRY_MAX_RUNS) {
        stored_run_count = MFT_ENTRY_MAX_RUNS;
        payload.fixed.run_truncated = 1U;
    }
    payload.fixed.stored_run_count = (uint32_t)stored_run_count;
    if (entry->run_truncated) {
        payload.fixed.run_truncated = 1U;
    }

    if (g_has_ntfs_geometry &&
        entry->has_data &&
        !entry->resident &&
        entry->first_lcn > 0 &&
        entry->run_clusters > 0 &&
        g_cluster_size > 0) {
        uint64_t span_bytes = entry->data_size;
        uint64_t run_byte_length = entry->run_clusters * (uint64_t)g_cluster_size;

        payload.fixed.base.data_abs_offset =
            (int64_t)(g_partition_start + (long long)(entry->first_lcn * (uint64_t)g_cluster_size));
        payload.fixed.base.run_byte_length = run_byte_length;
        if (run_byte_length > span_bytes) {
            span_bytes = run_byte_length;
        }
        payload.fixed.base.data_end_abs_offset =
            payload.fixed.base.data_abs_offset + (int64_t)span_bytes;
    }

    for (run_index = 0; run_index < stored_run_count; run_index++) {
        payload.runs[run_index].lcn = entry->runs[run_index].lcn;
        payload.runs[run_index].clusters = entry->runs[run_index].clusters;
        payload.runs[run_index].abs_offset = -1;
        payload.runs[run_index].byte_length = 0;
        if (g_has_ntfs_geometry && g_cluster_size > 0 && entry->runs[run_index].clusters > 0) {
            payload.runs[run_index].abs_offset =
                (int64_t)(g_partition_start +
                          (long long)(entry->runs[run_index].lcn * (uint64_t)g_cluster_size));
            payload.runs[run_index].byte_length =
                entry->runs[run_index].clusters * (uint64_t)g_cluster_size;
        }
    }

    payload_size =
        MFT_SPOOL_PROBE_PAYLOAD_FIXED_SIZE +
        stored_run_count * MFT_SPOOL_PROBE_RUN_PAYLOAD_SIZE;
    return writer_append_record(&g_probe_writer, &payload, payload_size);
}

int mft_spool_append_recovered_output(const char *path, long long abs_offset)
{
    MftSpoolRecoveredPayloadHeader header;
    unsigned char payload[sizeof(header) + MFT_SPOOL_MAX_RECOVERED_PATH + 1U];
    size_t path_length;

    if (!text_present(path) || abs_offset < 0) {
        return 0;
    }
    g_recovered_writer.kind = MFT_SPOOL_SEGMENT_RECOVERED;
    if (!mft_spool_prepare()) {
        return 0;
    }

    path_length = strlen(path);
    if (path_length > MFT_SPOOL_MAX_RECOVERED_PATH) {
        path_length = MFT_SPOOL_MAX_RECOVERED_PATH;
    }

    memset(&header, 0, sizeof(header));
    header.abs_offset = abs_offset;
    header.path_length = (uint16_t)path_length;
    memcpy(payload, &header, sizeof(header));
    memcpy(payload + sizeof(header), path, path_length);

    return writer_append_record(
        &g_recovered_writer,
        payload,
        sizeof(header) + path_length
    );
}

static int build_indices_internal(int flush_writers)
{
    MftSpoolRecordIndexRow *record_rows = NULL;
    MftSpoolRangeIndexRow *range_rows = NULL;
    size_t record_count = 0;
    size_t range_count = 0;
    char record_index_path[1024];
    char range_index_path[1024];
    FILE *record_file = NULL;
    FILE *range_file = NULL;
    int ok = 0;

    if (flush_writers) {
        if (!mft_spool_prepare()) {
            return 0;
        }

        if (!writer_flush(&g_probe_writer) || !writer_flush(&g_recovered_writer)) {
            return 0;
        }
    }

    if (!load_probe_rows_from_segments(
            &record_rows,
            &record_count,
            &range_rows,
            &range_count)) {
        return 0;
    }
    if (app_stop_requested()) {
        goto cleanup;
    }

    if (record_count > 1U) {
        qsort(record_rows, record_count, sizeof(*record_rows), compare_record_index_rows);
    }
    if (range_count > 1U) {
        qsort(range_rows, range_count, sizeof(*range_rows), compare_range_index_rows);
    }
    if (app_stop_requested()) {
        goto cleanup;
    }

    if (!build_index_path(record_index_path, sizeof(record_index_path), "record.idx") ||
        !build_index_path(range_index_path, sizeof(range_index_path), "range.idx")) {
        goto cleanup;
    }

    if (!spool_output_path_write_guard_allows(
            record_index_path,
            "write NTFS spool record index")) {
        goto cleanup;
    }
    record_file = fopen(record_index_path, "wb");
    if (record_file == NULL) {
        goto cleanup;
    }
    if (!write_index_header(
            record_file,
            MFT_SPOOL_INDEX_RECORD,
            (uint32_t)sizeof(*record_rows),
            (uint64_t)record_count) ||
        (record_count > 0 &&
         fwrite(record_rows, sizeof(*record_rows), record_count, record_file) != record_count) ||
        fflush(record_file) != 0) {
        goto cleanup;
    }

    if (!spool_output_path_write_guard_allows(
            range_index_path,
            "write NTFS spool range index")) {
        goto cleanup;
    }
    range_file = fopen(range_index_path, "wb");
    if (range_file == NULL) {
        goto cleanup;
    }
    if (!write_index_header(
            range_file,
            MFT_SPOOL_INDEX_RANGE,
            (uint32_t)sizeof(*range_rows),
            (uint64_t)range_count) ||
        (range_count > 0 &&
         fwrite(range_rows, sizeof(*range_rows), range_count, range_file) != range_count) ||
        fflush(range_file) != 0) {
        goto cleanup;
    }

    g_record_index_count = record_count;
    g_range_index_count = range_count;
    if (initialize_segment_cursors_to_segment_end(
            MFT_SPOOL_SEGMENT_PROBE,
            &g_probe_cursors,
            &g_probe_cursor_count)) {
        g_probe_cursors_initialized = 1;
    }
    g_background_need_full_reconcile = 1;
    (void)write_live_stats_file();
    log_verbose(
        "Spool indices rebuilt: record.idx=%zu range.idx=%zu",
        record_count,
        range_count
    );
    ok = 1;

cleanup:
    if (record_file != NULL) {
        fclose(record_file);
    }
    if (range_file != NULL) {
        fclose(range_file);
    }
    free(record_rows);
    free(range_rows);
    return ok;
}

int mft_spool_build_indices(void)
{
    mft_spool_close();
    return build_indices_internal(0);
}

int mft_spool_indices_available(void)
{
    struct stat st;
    char record_index_path[1024];
    char range_index_path[1024];

    if (!build_index_path(record_index_path, sizeof(record_index_path), "record.idx") ||
        !build_index_path(range_index_path, sizeof(range_index_path), "range.idx")) {
        return 0;
    }

    return stat(record_index_path, &st) == 0 &&
           S_ISREG(st.st_mode) &&
           stat(range_index_path, &st) == 0 &&
           S_ISREG(st.st_mode);
}

int mft_spool_probe_index_current(void)
{
    char record_index_path[1024];
    char range_index_path[1024];
    struct stat record_st;
    struct stat range_st;
    time_t latest_probe_mtime = (time_t)0;

    if (!mft_spool_indices_available()) {
        return 0;
    }
    if (!build_index_path(record_index_path, sizeof(record_index_path), "record.idx") ||
        !build_index_path(range_index_path, sizeof(range_index_path), "range.idx")) {
        return 0;
    }
    if (stat(record_index_path, &record_st) != 0 ||
        !S_ISREG(record_st.st_mode) ||
        stat(range_index_path, &range_st) != 0 ||
        !S_ISREG(range_st.st_mode)) {
        return 0;
    }
    if (!collect_segment_latest_mtime(MFT_SPOOL_SEGMENT_PROBE, &latest_probe_mtime)) {
        return 0;
    }

    return record_st.st_mtime >= latest_probe_mtime &&
           range_st.st_mtime >= latest_probe_mtime;
}

size_t mft_spool_record_index_count(void)
{
    return g_record_index_count;
}

size_t mft_spool_range_index_count(void)
{
    return g_range_index_count;
}

void mft_spool_get_live_stats(MftSpoolLiveStats *out)
{
    MftSpoolLiveStats file_stats;

    if (out == NULL) {
        return;
    }

    if (load_live_stats_file(&file_stats)) {
        *out = file_stats;
        return;
    }

    out->renamed_outputs = g_live_renamed_outputs;
    out->repaired_outputs = g_live_repaired_outputs;
    out->recovered_outputs_current = g_live_recovered_outputs_current;
    out->named_outputs_current = g_live_named_outputs_current;
    out->unident_outputs_current = g_live_unident_outputs_current;
    out->repair_pending_outputs = g_live_repair_pending_outputs;
    out->repair_queue_events = g_live_repair_queue_events;
    out->opportunistic_naming_sweeps = g_background_opportunistic_sweeps;
    out->opportunistic_naming_renamed =
        g_background_opportunistic_renamed_outputs;
    out->opportunistic_naming_zero_delta =
        g_background_opportunistic_zero_delta_sweeps;
    out->opportunistic_naming_last_delta =
        g_background_last_opportunistic_renamed_delta;
    out->recovered_first_checked_last =
        g_background_last_recovered_first_stats.checked;
    out->recovered_first_moved_last =
        g_background_last_recovered_first_stats.moved;
    out->recovered_first_complete_moves_last =
        g_background_last_recovered_first_stats.complete_path_moves;
    out->recovered_first_partial_moves_last =
        g_background_last_recovered_first_stats.partial_path_moves;
    out->recovered_first_parent_group_moves_last =
        g_background_last_recovered_first_stats.parent_group_moves;
    out->recovered_first_flat_name_moves_last =
        g_background_last_recovered_first_stats.flat_name_moves;
    out->recovered_first_no_path_last =
        g_background_last_recovered_first_stats.skipped_no_path;
    out->recovered_first_missing_source_last =
        g_background_last_recovered_first_stats.skipped_missing_source;
    out->recovered_first_no_extension_last =
        g_background_last_recovered_first_stats.skipped_no_extension;
    out->recovered_first_no_range_anchor_last =
        g_background_last_recovered_first_stats.skipped_no_range_anchor;
    out->recovered_first_no_exact_range_start_last =
        g_background_last_recovered_first_stats.skipped_no_exact_range_start;
    out->recovered_first_no_context_path_last =
        g_background_last_recovered_first_stats.skipped_no_context_path;
    out->recovered_first_no_payload_last =
        g_background_last_recovered_first_stats.skipped_no_payload;
    out->recovered_first_no_commit_candidate_last =
        g_background_last_recovered_first_stats.skipped_no_commit_candidate;
    out->recovered_first_same_path_last =
        g_background_last_recovered_first_stats.skipped_same_path;
    out->recovered_first_rename_failures_last =
        g_background_last_recovered_first_stats.rename_failures;
    out->record_index_count = g_record_index_count;
    out->range_index_count = g_range_index_count;
    out->scan_stalled_seconds = g_live_scan_stalled_seconds;
    out->background_phase = (unsigned int)g_live_background_phase;
}

void mft_spool_publish_backend_counts(
    uint64_t recovered_total,
    uint64_t named_total,
    uint64_t unident_total
)
{
    mft_spool_publish_backend_progress(
        recovered_total,
        named_total,
        unident_total,
        g_live_renamed_outputs,
        g_live_repaired_outputs
    );
}

void mft_spool_publish_backend_progress(
    uint64_t recovered_total,
    uint64_t named_total,
    uint64_t unident_total,
    uint64_t renamed_total,
    uint64_t repaired_total
)
{
    g_live_recovered_outputs_current = recovered_total;
    g_live_named_outputs_current = named_total;
    g_live_unident_outputs_current = unident_total;
    g_live_renamed_outputs = renamed_total;
    g_live_repaired_outputs = repaired_total;
    (void)write_live_stats_file();
}

static int build_indices_incremental(void)
{
    MftSpoolRecordIndexRow *existing_record_rows = NULL;
    MftSpoolRangeIndexRow *existing_range_rows = NULL;
    MftSpoolRecordIndexRow *delta_record_rows = NULL;
    MftSpoolRangeIndexRow *delta_range_rows = NULL;
    size_t existing_record_count = 0;
    size_t existing_range_count = 0;
    size_t delta_record_count = 0;
    size_t delta_range_count = 0;
    size_t merged_record_count;
    size_t merged_range_count;
    char record_index_path[1024];
    char range_index_path[1024];
    int ok = 0;

    if (!g_probe_cursors_initialized &&
        !initialize_segment_cursors_to_segment_end(
            MFT_SPOOL_SEGMENT_PROBE,
            &g_probe_cursors,
            &g_probe_cursor_count)) {
        return 0;
    }
    g_probe_cursors_initialized = 1;

    if (!load_probe_delta_rows_from_segments(
            &delta_record_rows,
            &delta_record_count,
            &delta_range_rows,
            &delta_range_count)) {
        return 0;
    }

    if (delta_record_count == 0U && delta_range_count == 0U) {
        ok = 1;
        goto cleanup;
    }

    if (!build_index_path(record_index_path, sizeof(record_index_path), "record.idx") ||
        !build_index_path(range_index_path, sizeof(range_index_path), "range.idx") ||
        !load_index_rows(
            record_index_path,
            MFT_SPOOL_INDEX_RECORD,
            sizeof(MftSpoolRecordIndexRow),
            (void **)&existing_record_rows,
            &existing_record_count) ||
        !load_index_rows(
            range_index_path,
            MFT_SPOOL_INDEX_RANGE,
            sizeof(MftSpoolRangeIndexRow),
            (void **)&existing_range_rows,
            &existing_range_count)) {
        goto cleanup;
    }

    if (existing_record_count > SIZE_MAX - delta_record_count ||
        existing_range_count > SIZE_MAX - delta_range_count) {
        goto cleanup;
    }
    merged_record_count = existing_record_count + delta_record_count;
    merged_range_count = existing_range_count + delta_range_count;

    if (delta_record_count > 0U) {
        MftSpoolRecordIndexRow *merged_rows;

        if (delta_record_count > 1U) {
            qsort(
                delta_record_rows,
                delta_record_count,
                sizeof(*delta_record_rows),
                compare_record_index_rows);
        }
        merged_rows = merge_record_index_rows(
            existing_record_rows,
            existing_record_count,
            delta_record_rows,
            delta_record_count);
        if (merged_rows == NULL) {
            goto cleanup;
        }
        free(existing_record_rows);
        existing_record_rows = merged_rows;
    }

    if (delta_range_count > 0U) {
        MftSpoolRangeIndexRow *merged_rows;

        if (delta_range_count > 1U) {
            qsort(
                delta_range_rows,
                delta_range_count,
                sizeof(*delta_range_rows),
                compare_range_index_rows);
        }
        merged_rows = merge_range_index_rows(
            existing_range_rows,
            existing_range_count,
            delta_range_rows,
            delta_range_count);
        if (merged_rows == NULL) {
            goto cleanup;
        }
        free(existing_range_rows);
        existing_range_rows = merged_rows;
    }

    if (!write_index_rows(
            record_index_path,
            MFT_SPOOL_INDEX_RECORD,
            sizeof(*existing_record_rows),
            existing_record_rows,
            merged_record_count) ||
        !write_index_rows(
            range_index_path,
            MFT_SPOOL_INDEX_RANGE,
            sizeof(*existing_range_rows),
            existing_range_rows,
            merged_range_count)) {
        goto cleanup;
    }

    g_record_index_count = merged_record_count;
    g_range_index_count = merged_range_count;
    (void)write_live_stats_file();
    ok = 1;

cleanup:
    free(existing_record_rows);
    free(existing_range_rows);
    free(delta_record_rows);
    free(delta_range_rows);
    return ok;
}

void GCC_ICE_WORKAROUND_O0 mft_spool_background_tick(int final_pass)
{
    uint64_t probe_bytes = 0;
    uint64_t recovered_bytes = 0;
    uint64_t probe_rebuild_delta_bytes =
        MFT_SPOOL_BACKGROUND_PROBE_REBUILD_DELTA_BYTES;
    uint64_t reconcile_delta_bytes =
        MFT_SPOOL_BACKGROUND_RECOVERED_RECONCILE_DELTA_BYTES;
    uint64_t repair_delta_bytes =
        MFT_SPOOL_BACKGROUND_RECOVERED_RECONCILE_DELTA_BYTES;
    time_t now = time(NULL);
    time_t build_interval_seconds =
        MFT_SPOOL_BACKGROUND_BUILD_INTERVAL_SECONDS;
    time_t reconcile_interval_seconds =
        MFT_SPOOL_BACKGROUND_RECONCILE_INTERVAL_SECONDS;
    time_t repair_interval_seconds =
        MFT_SPOOL_BACKGROUND_RECONCILE_INTERVAL_SECONDS;
    int queue_stats_ok = 0;
    int idle_sweep_requested = 0;
    int slow_scan_opportunity = 0;
    int slow_scan_full_sweep_requested = 0;
    int should_build = 0;
    int should_reconcile = 0;
    int should_repair = 0;
    size_t reconcile_batch_events =
        MFT_SPOOL_BACKGROUND_RECONCILE_BATCH_EVENTS;
    size_t repair_batch_events =
        MFT_SPOOL_BACKGROUND_REPAIR_BATCH_EVENTS;
    int conservative_mode = g_background_conservative_mode;

    if (!mft_spool_artifacts_available()) {
        return;
    }
    if (!collect_segment_bytes(MFT_SPOOL_SEGMENT_PROBE, &probe_bytes) ||
        !collect_segment_bytes(MFT_SPOOL_SEGMENT_RECOVERED, &recovered_bytes)) {
        return;
    }

    queue_stats_ok = refresh_live_queue_stats(now, recovered_bytes, 0);
    refresh_scan_stall_state(now, recovered_bytes);
    if (g_suspend_stall_watch) {
        g_live_scan_stalled_seconds = 0ULL;
    }
    if (!conservative_mode &&
        !g_suspend_stall_watch &&
        !final_pass &&
        queue_stats_ok &&
        g_live_scan_stalled_seconds >= MFT_SPOOL_BACKGROUND_STALL_SECONDS &&
        g_live_unident_outputs_current >= MFT_SPOOL_BACKGROUND_IDLE_SWEEP_MIN_UNIDENT &&
        (g_background_last_idle_sweep == 0 ||
         now - g_background_last_idle_sweep >=
             MFT_SPOOL_BACKGROUND_IDLE_SWEEP_INTERVAL_SECONDS)) {
        idle_sweep_requested = 1;
        g_background_need_full_reconcile = 1;
    }

    if (!conservative_mode &&
        !final_pass &&
        queue_stats_ok &&
        g_live_unident_outputs_current >=
            MFT_SPOOL_BACKGROUND_NAMING_PRESSURE_MIN_UNIDENT) {
        probe_rebuild_delta_bytes =
            MFT_SPOOL_BACKGROUND_PRESSURE_PROBE_REBUILD_DELTA_BYTES;
        reconcile_delta_bytes =
            MFT_SPOOL_BACKGROUND_PRESSURE_RECONCILE_DELTA_BYTES;
        repair_delta_bytes =
            MFT_SPOOL_BACKGROUND_PRESSURE_REPAIR_DELTA_BYTES;
        build_interval_seconds =
            MFT_SPOOL_BACKGROUND_PRESSURE_BUILD_INTERVAL_SECONDS;
        repair_interval_seconds =
            MFT_SPOOL_BACKGROUND_PRESSURE_REPAIR_INTERVAL_SECONDS;
        reconcile_batch_events =
            MFT_SPOOL_BACKGROUND_PRESSURE_RECONCILE_BATCH_EVENTS;
    }

    if (!conservative_mode &&
        !final_pass &&
        queue_stats_ok &&
        !g_suspend_stall_watch &&
        g_live_scan_stalled_seconds >= MFT_SPOOL_BACKGROUND_SLOW_SCAN_SECONDS &&
        (g_live_unident_outputs_current >=
             MFT_SPOOL_BACKGROUND_SLOW_SCAN_MIN_UNIDENT ||
         g_live_repair_pending_outputs > 0U ||
         g_live_repair_queue_events > 0U)) {
        slow_scan_opportunity = 1;
        probe_rebuild_delta_bytes =
            MFT_SPOOL_BACKGROUND_SLOW_SCAN_PROBE_REBUILD_DELTA_BYTES;
        reconcile_delta_bytes =
            MFT_SPOOL_BACKGROUND_SLOW_SCAN_RECONCILE_DELTA_BYTES;
        repair_delta_bytes =
            MFT_SPOOL_BACKGROUND_SLOW_SCAN_REPAIR_DELTA_BYTES;
        build_interval_seconds =
            MFT_SPOOL_BACKGROUND_SLOW_SCAN_BUILD_INTERVAL_SECONDS;
        reconcile_interval_seconds =
            MFT_SPOOL_BACKGROUND_SLOW_SCAN_RECONCILE_INTERVAL_SECONDS;
        repair_interval_seconds =
            MFT_SPOOL_BACKGROUND_SLOW_SCAN_REPAIR_INTERVAL_SECONDS;
        reconcile_batch_events =
            MFT_SPOOL_BACKGROUND_SLOW_SCAN_RECONCILE_BATCH_EVENTS;
        repair_batch_events =
            MFT_SPOOL_BACKGROUND_SLOW_SCAN_REPAIR_BATCH_EVENTS;

        if (mft_spool_indices_available() &&
            g_live_unident_outputs_current >=
                MFT_SPOOL_BACKGROUND_SLOW_SCAN_MIN_UNIDENT &&
            (g_background_last_slow_scan_sweep == 0 ||
             now - g_background_last_slow_scan_sweep >=
                 MFT_SPOOL_BACKGROUND_SLOW_SCAN_SWEEP_INTERVAL_SECONDS)) {
            slow_scan_full_sweep_requested = 1;
            g_background_need_full_reconcile = 1;
        }
    }

    if (final_pass) {
        should_build = 1;
        should_reconcile = 1;
        should_repair = 1;
    } else {
        if (conservative_mode) {
            probe_rebuild_delta_bytes =
                MFT_SPOOL_BACKGROUND_CONSERVATIVE_PROBE_REBUILD_DELTA_BYTES;
            reconcile_delta_bytes =
                MFT_SPOOL_BACKGROUND_CONSERVATIVE_RECONCILE_DELTA_BYTES;
            repair_delta_bytes =
                MFT_SPOOL_BACKGROUND_CONSERVATIVE_REPAIR_DELTA_BYTES;
            build_interval_seconds =
                MFT_SPOOL_BACKGROUND_CONSERVATIVE_BUILD_INTERVAL_SECONDS;
            reconcile_interval_seconds =
                MFT_SPOOL_BACKGROUND_CONSERVATIVE_RECONCILE_INTERVAL_SECONDS;
            repair_interval_seconds =
                MFT_SPOOL_BACKGROUND_CONSERVATIVE_REPAIR_INTERVAL_SECONDS;
            reconcile_batch_events =
                MFT_SPOOL_BACKGROUND_CONSERVATIVE_RECONCILE_BATCH_EVENTS;
            repair_batch_events =
                MFT_SPOOL_BACKGROUND_CONSERVATIVE_REPAIR_BATCH_EVENTS;
        }

        if (!mft_spool_indices_available()) {
            should_build = probe_bytes > 0U;
        } else if (probe_bytes > g_background_last_index_probe_bytes &&
                   (probe_bytes - g_background_last_index_probe_bytes >=
                        probe_rebuild_delta_bytes ||
                    (g_background_last_index_build > 0 &&
                     now - g_background_last_index_build >=
                         build_interval_seconds))) {
            should_build = 1;
        }

        if (recovered_bytes > 0U &&
            g_background_last_reconcile_recovered_bytes == 0U &&
            g_live_unident_outputs_current > 0U) {
            should_reconcile = 1;
        } else if (recovered_bytes > g_background_last_reconcile_recovered_bytes &&
            (recovered_bytes - g_background_last_reconcile_recovered_bytes >=
                 reconcile_delta_bytes ||
             (g_background_last_reconcile > 0 &&
              now - g_background_last_reconcile >=
                  reconcile_interval_seconds))) {
            should_reconcile = 1;
        }

        if (recovered_bytes > g_background_last_repair_recovered_bytes &&
            (recovered_bytes - g_background_last_repair_recovered_bytes >=
                 repair_delta_bytes ||
             (g_background_last_repair > 0 &&
              now - g_background_last_repair >=
                  repair_interval_seconds))) {
            should_repair = 1;
        }

        if (idle_sweep_requested) {
            should_reconcile = 1;
            should_repair = 1;
        }
        if (slow_scan_opportunity) {
            if (g_live_unident_outputs_current > 0U) {
                should_reconcile = 1;
            }
            if (g_live_repair_pending_outputs > 0U ||
                g_live_repair_queue_events > 0U) {
                should_repair = 1;
            }
        }
        if (slow_scan_full_sweep_requested) {
            should_reconcile = 1;
            should_repair = 1;
        }

        if (conservative_mode) {
            /*
             * Conservative raw-all background mode stays recovered-first:
             * keep building live indices as filtered probe data arrives and
             * allow small naming batches once carved outputs exist, but leave
             * repair sweeps and full finalize-only passes for later.
             */
            should_repair = 0;
            if (g_live_unident_outputs_current == 0U) {
                should_reconcile = 0;
            }
        }
    }

    g_background_last_probe_bytes = probe_bytes;
    g_background_last_recovered_bytes = recovered_bytes;

    if (should_build) {
        int build_ok;

        set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_INDEX, now);
        if (!mft_spool_indices_available()) {
            build_ok = build_indices_internal(0);
        } else {
            build_ok = build_indices_incremental();
        }
        set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_IDLE, now);

        if (build_ok) {
            g_background_last_index_probe_bytes = probe_bytes;
            g_background_last_index_build = now;
            if (!conservative_mode || final_pass) {
                should_reconcile = 1;
                should_repair = 1;
            } else if (g_live_unident_outputs_current > 0U) {
                should_reconcile = 1;
            }
        }
    }

    if ((should_reconcile || should_repair) && mft_spool_indices_available()) {
        int reconcile_ok = 0;
        int repair_ok = 0;

        if (!g_recovered_cursors_initialized &&
            !initialize_segment_cursors_to_segment_end(
                MFT_SPOOL_SEGMENT_RECOVERED,
                &g_recovered_cursors,
                &g_recovered_cursor_count)) {
            return;
        }
        g_recovered_cursors_initialized = 1;
        if (!g_repair_cursors_initialized &&
            !initialize_segment_cursors_to_segment_end(
                MFT_SPOOL_SEGMENT_RECOVERED,
                &g_repair_cursors,
                &g_repair_cursor_count)) {
            return;
        }
        g_repair_cursors_initialized = 1;
        g_live_repair_queue_events = 0U;

        if (final_pass ||
            (g_background_need_full_reconcile && !conservative_mode)) {
            reconcile_ok = mft_spool_reconcile_outputs();
            if (reconcile_ok) {
                (void)initialize_segment_cursors_to_segment_end(
                    MFT_SPOOL_SEGMENT_RECOVERED,
                    &g_recovered_cursors,
                    &g_recovered_cursor_count);
                g_recovered_cursors_initialized = 1;
                (void)initialize_segment_cursors_to_segment_end(
                    MFT_SPOOL_SEGMENT_RECOVERED,
                    &g_repair_cursors,
                    &g_repair_cursor_count);
                g_repair_cursors_initialized = 1;
                g_background_need_full_reconcile = 0;
                repair_ok = 1;
                if (idle_sweep_requested) {
                    g_background_last_idle_sweep = now;
                }
                if (slow_scan_full_sweep_requested) {
                    g_background_last_slow_scan_sweep = now;
                }
            }
        } else {
            MftSpoolRecordIndexRow *record_rows = NULL;
            MftSpoolRangeIndexRow *range_rows = NULL;
            long long *range_prefix_max = NULL;
            MftSpoolSegmentReader *readers = NULL;
            MftSpoolRecoveredEvent *events = NULL;
            MftSpoolRecoveredEvent *repair_events = NULL;
            size_t record_count = 0;
            size_t range_count = 0;
            size_t reader_count = 0;
            size_t event_count = 0;
            size_t repair_event_count = 0;
            char record_index_path[1024];
            char range_index_path[1024];
            size_t moved = 0;
            size_t repaired = 0;

            if ((!should_reconcile ||
                 load_recovered_delta_events(
                     reconcile_batch_events,
                     &events,
                     &event_count)) &&
                (!should_repair ||
                 load_repair_delta_events(
                     repair_batch_events,
                     &repair_events,
                     &repair_event_count))) {
                if ((!should_reconcile || event_count == 0U) &&
                    (!should_repair || repair_event_count == 0U)) {
                    if (should_reconcile) {
                        reconcile_ok = 1;
                    }
                    if (should_repair) {
                        g_live_repair_queue_events = 0U;
                        repair_ok = 1;
                    }
                } else if (build_index_path(record_index_path, sizeof(record_index_path), "record.idx") &&
                           build_index_path(range_index_path, sizeof(range_index_path), "range.idx") &&
                           load_index_rows(
                               record_index_path,
                               MFT_SPOOL_INDEX_RECORD,
                               sizeof(MftSpoolRecordIndexRow),
                               (void **)&record_rows,
                               &record_count) &&
                           load_index_rows(
                               range_index_path,
                               MFT_SPOOL_INDEX_RANGE,
                               sizeof(MftSpoolRangeIndexRow),
                               (void **)&range_rows,
                               &range_count) &&
                           collect_probe_segment_readers(&readers, &reader_count)) {
                    if (range_count == 0U) {
                        g_live_repair_queue_events = 0U;
                        reconcile_ok = 1;
                        repair_ok = 1;
                    } else {
                        range_prefix_max = build_range_prefix_max(range_rows, range_count);
                        if (range_prefix_max != NULL) {
                            if (should_reconcile && event_count > 0U) {
                                set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_NAMING, now);
                                moved = reconcile_loaded_events(
                                    record_rows,
                                    record_count,
                                    range_rows,
                                    range_prefix_max,
                                    range_count,
                                    readers,
                                    reader_count,
                                    events,
                                    event_count,
                                    &g_background_last_recovered_first_stats);
                                set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_IDLE, now);
                            }
                            if (should_repair && repair_event_count > 0U) {
                                g_live_repair_queue_events =
                                    (uint64_t)repair_event_count;
                                set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_REPAIR, now);
                                repaired = repair_loaded_events(
                                    record_rows,
                                    record_count,
                                    range_rows,
                                    range_prefix_max,
                                    range_count,
                                    readers,
                                    reader_count,
                                    repair_events,
                                    repair_event_count,
                                    0U,
                                    mft_background_stop_requested,
                                    0
                                );
                                set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_IDLE, now);
                            } else if (should_repair) {
                                g_live_repair_queue_events = 0U;
                            }
                            if (should_reconcile) {
                                reconcile_ok = 1;
                            }
                            if (should_repair) {
                                repair_ok = 1;
                            }
                        }
                    }
                } else if (should_repair) {
                    g_live_repair_queue_events = 0U;
                }
            }

            free(record_rows);
            free(range_rows);
            free(range_prefix_max);
            close_probe_segment_readers(readers, reader_count);
            free_recovered_events(events, event_count);
            free_recovered_events(repair_events, repair_event_count);

            if (moved > 0U) {
                g_live_renamed_outputs += (uint64_t)moved;
            }
            if (repaired > 0U) {
                g_live_repaired_outputs += (uint64_t)repaired;
            }
            if (moved > 0U || repaired > 0U) {
                (void)refresh_live_queue_stats(now, recovered_bytes, 1);
            }
        }

        if (reconcile_ok) {
            g_background_last_reconcile_recovered_bytes = recovered_bytes;
            g_background_last_reconcile = now;
        }
        if (repair_ok) {
            g_background_last_repair_recovered_bytes = recovered_bytes;
            g_background_last_repair = now;
        }
    }

    if (conservative_mode &&
        !final_pass &&
        queue_stats_ok &&
        mft_spool_indices_available() &&
        g_live_unident_outputs_current >=
            MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_MIN_UNIDENT) {
        int has_new_probe_delta =
            g_background_last_opportunistic_probe_bytes == 0U ||
            probe_bytes >=
                g_background_last_opportunistic_probe_bytes +
                    MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_PROBE_DELTA_BYTES;
        int has_new_recovered_delta =
            recovered_bytes >=
                g_background_last_opportunistic_recovered_bytes +
                    MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_RECOVERED_DELTA_BYTES;
        int scan_waiting =
            !g_suspend_stall_watch &&
            g_live_scan_stalled_seconds >=
                MFT_SPOOL_BACKGROUND_SLOW_SCAN_SECONDS;
        time_t interval_seconds =
            (g_background_last_opportunistic_renamed_delta > 0U ||
             has_new_probe_delta ||
             has_new_recovered_delta ||
             scan_waiting)
                ? MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_INTERVAL_SECONDS
                : MFT_SPOOL_BACKGROUND_OPPORTUNISTIC_NAMING_IDLE_INTERVAL_SECONDS;
        int time_ok =
            g_background_last_opportunistic_naming == 0 ||
            now - g_background_last_opportunistic_naming >= interval_seconds;
        int useful_delta =
            has_new_probe_delta ||
            has_new_recovered_delta ||
            scan_waiting;

        if (time_ok &&
            useful_delta &&
            !mft_background_stop_requested()) {
            uint64_t renamed_before = g_live_renamed_outputs;
            uint64_t renamed_after;
            uint64_t delta;

            set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_NAMING, now);
            (void)mft_spool_reconcile_outputs_naming_only();
            set_background_phase(MFT_SPOOL_BACKGROUND_PHASE_IDLE, now);

            renamed_after = g_live_renamed_outputs;
            delta =
                renamed_after >= renamed_before
                    ? renamed_after - renamed_before
                    : 0U;

            g_background_opportunistic_sweeps++;
            g_background_last_opportunistic_naming = now;
            g_background_last_opportunistic_probe_bytes = probe_bytes;
            g_background_last_opportunistic_recovered_bytes = recovered_bytes;
            g_background_last_opportunistic_renamed_delta = delta;
            if (delta > 0U) {
                g_background_opportunistic_renamed_outputs += delta;
                (void)refresh_live_queue_stats(now, recovered_bytes, 1);
            } else {
                g_background_opportunistic_zero_delta_sweeps++;
            }
        }
    }

    if (!queue_stats_ok) {
        (void)refresh_live_queue_stats(now, recovered_bytes, 1);
    } else {
        (void)write_live_stats_file();
    }
}

void mft_spool_set_stall_watch_suspended(int suspended)
{
    g_suspend_stall_watch = suspended ? 1 : 0;
    if (g_suspend_stall_watch) {
        g_live_scan_stalled_seconds = 0ULL;
        g_background_last_stall_log_seconds = 0ULL;
        g_background_stall_watch_armed = 0;
    }
}

void mft_spool_set_background_conservative(int enabled)
{
    int next = enabled ? 1 : 0;

    if (g_background_conservative_mode == next) {
        return;
    }

    g_background_conservative_mode = next;
    if (g_background_conservative_mode) {
        g_background_need_full_reconcile = 0;
    }
    (void)write_live_stats_file();
}

int mft_spool_background_is_conservative(void)
{
    return g_background_conservative_mode;
}

void mft_spool_note_foreground_activity(void)
{
    time_t now = time(NULL);

    if (now == (time_t)-1) {
        return;
    }

    g_background_last_foreground_activity = now;
    if (!g_suspend_stall_watch) {
        g_live_scan_stalled_seconds = 0ULL;
    }
}

static int mft_spool_reconcile_outputs_internal(int allow_repair)
{
    size_t total_moved = 0;
    size_t total_repaired = 0;
    size_t passes = 0;
    char record_index_path[1024];
    char range_index_path[1024];
    int ok = 0;

    if (!build_index_path(record_index_path, sizeof(record_index_path), "record.idx") ||
        !build_index_path(range_index_path, sizeof(range_index_path), "range.idx")) {
        return 0;
    }

    for (passes = 0; passes < MFT_SPOOL_FINAL_RECONCILE_MAX_PASSES; passes++) {
        MftSpoolRecordIndexRow *record_rows = NULL;
        MftSpoolRangeIndexRow *range_rows = NULL;
        long long *range_prefix_max = NULL;
        MftSpoolSegmentReader *readers = NULL;
        MftSpoolRecoveredEvent *events = NULL;
        size_t record_count = 0;
        size_t range_count = 0;
        size_t reader_count = 0;
        size_t event_count = 0;
        size_t moved = 0;
        size_t repaired = 0;

        if (!load_index_rows(
                record_index_path,
                MFT_SPOOL_INDEX_RECORD,
                sizeof(MftSpoolRecordIndexRow),
                (void **)&record_rows,
                &record_count) ||
            !load_index_rows(
                range_index_path,
                MFT_SPOOL_INDEX_RANGE,
                sizeof(MftSpoolRangeIndexRow),
                (void **)&range_rows,
                &range_count) ||
            !collect_probe_segment_readers(&readers, &reader_count)) {
            goto cleanup;
        }

        if (!load_recovered_events_for_background_sweep(&events, &event_count)) {
            free(record_rows);
            free(range_rows);
            close_probe_segment_readers(readers, reader_count);
            goto cleanup;
        }

        if (range_count == 0U || event_count == 0U) {
            if (event_count > 0U && range_count == 0U) {
                if (!g_logged_no_range_reconcile_notice) {
                    log_info(
                        "Full naming pass found %zu recovered files but no usable range index rows yet; no additional spool-based matches were possible",
                        event_count
                    );
                    g_logged_no_range_reconcile_notice = 1;
                }
            }
            free(record_rows);
            free(range_rows);
            close_probe_segment_readers(readers, reader_count);
            free_recovered_events(events, event_count);
            ok = 1;
            break;
        }

        range_prefix_max = build_range_prefix_max(range_rows, range_count);
        if (range_prefix_max == NULL) {
            free(record_rows);
            free(range_rows);
            close_probe_segment_readers(readers, reader_count);
            free_recovered_events(events, event_count);
            goto cleanup;
        }

        log_set_working_activity("reconciling spool-named files");
        moved = reconcile_loaded_events(
            record_rows,
            record_count,
            range_rows,
            range_prefix_max,
            range_count,
            readers,
            reader_count,
            events,
            event_count,
            &g_background_last_recovered_first_stats);
        if (allow_repair) {
            repaired = repair_loaded_events(
                record_rows,
                record_count,
                range_rows,
                range_prefix_max,
                range_count,
                readers,
                reader_count,
                events,
                event_count,
                0U,
                NULL,
                1
            );
        }

        free(record_rows);
        free(range_rows);
        free(range_prefix_max);
        close_probe_segment_readers(readers, reader_count);
        free_recovered_events(events, event_count);

        total_moved += moved;
        total_repaired += repaired;
        ok = 1;

        if (moved == 0U && (!allow_repair || repaired == 0U)) {
            break;
        }
    }

cleanup:
    if (ok) {
        size_t total_passes = passes + 1U;
        if (total_moved > 0U) {
            g_live_renamed_outputs += (uint64_t)total_moved;
            log_info(
                "Spool reconcile applied %zu rename operation%s%s",
                total_moved,
                total_moved == 1U ? "" : "s",
                total_passes > 1U ? " across multiple passes" : ""
            );
        }
        if (total_repaired > 0U) {
            g_live_repaired_outputs += (uint64_t)total_repaired;
            log_info(
                "Spool JPEG repair rebuilt %zu fragmented files%s",
                total_repaired,
                total_passes > 1U ? " across multiple passes" : ""
            );
        }
        (void)refresh_live_queue_stats(time(NULL), g_background_last_recovered_bytes, 1);
    }
    return ok;
}

int mft_spool_reconcile_outputs(void)
{
    return mft_spool_reconcile_outputs_internal(1);
}

int mft_spool_reconcile_outputs_naming_only(void)
{
    return mft_spool_reconcile_outputs_internal(0);
}

int mft_spool_materialize_output_directories(void)
{
    char record_index_path[1024];
    char range_index_path[1024];
    MftSpoolRecordIndexRow *record_rows = NULL;
    MftSpoolRangeIndexRow *range_rows = NULL;
    long long *range_prefix_max = NULL;
    MftSpoolSegmentReader *readers = NULL;
    MftSpoolRecoveredEvent *events = NULL;
    size_t record_count = 0U;
    size_t range_count = 0U;
    size_t reader_count = 0U;
    size_t event_count = 0U;
    size_t prepared = 0U;
    int ok = 0;

    if (!build_index_path(record_index_path, sizeof(record_index_path), "record.idx") ||
        !build_index_path(range_index_path, sizeof(range_index_path), "range.idx") ||
        !load_index_rows(
            record_index_path,
            MFT_SPOOL_INDEX_RECORD,
            sizeof(MftSpoolRecordIndexRow),
            (void **)&record_rows,
            &record_count) ||
        !load_index_rows(
            range_index_path,
            MFT_SPOOL_INDEX_RANGE,
            sizeof(MftSpoolRangeIndexRow),
            (void **)&range_rows,
            &range_count) ||
        !collect_probe_segment_readers(&readers, &reader_count) ||
        !load_recovered_events_from_log(&events, &event_count)) {
        goto cleanup;
    }

    if (range_count == 0U || event_count == 0U) {
        ok = 1;
        goto cleanup;
    }

    range_prefix_max = build_range_prefix_max(range_rows, range_count);
    if (range_prefix_max == NULL) {
        goto cleanup;
    }

    log_set_working_activity("preparing output folders from spool catalog");
    prepared = materialize_loaded_output_directories(
        record_rows,
        record_count,
        range_rows,
        range_prefix_max,
        range_count,
        readers,
        reader_count,
        events,
        event_count);
    if (prepared > 0U) {
        log_info(
            "Spool-first directory pass prepared %zu output folder path%s from saved naming context",
            prepared,
            prepared == 1U ? "" : "s"
        );
    }
    ok = 1;

cleanup:
    free(record_rows);
    free(range_rows);
    free(range_prefix_max);
    close_probe_segment_readers(readers, reader_count);
    free_recovered_events(events, event_count);
    return ok;
}
