/*
 * mftprobe_engine.c
 * Multi-threaded MFT-first recovery engine.
 *
 * This layer coordinates the heavier MFT-driven workflows: scanning,
 * worker queues, targeted recovery, compare-mode output, and resume-aware
 * orchestration around the lower-level MFT catalogue code.
 */

#define _POSIX_C_SOURCE 200809L

#include "mftprobe_engine.h"
#include "mftprobe_engine_types.h"
#include "mft_runlist.h"
#include "mft_probe_parser.h"
#include "mftprobe_format_api.h"
#include "recovery_runner.h"
#include "mftprobe_users_tree.h"
#include "mft_engine.h"
#include "mft.h"
#include "config.h"
#include "fs_backend.h"
#include "log.h"
#include "platform.h"
#include "reader.h"

#include <errno.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <fcntl.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#endif

#ifdef __linux__
#include <fcntl.h>
#include <sys/ioctl.h>
#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)
#endif
#endif

#if defined(__GNUC__) || defined(__clang__)
#define MFTPROBE_MAYBE_UNUSED __attribute__((unused))
#else
#define MFTPROBE_MAYBE_UNUSED
#endif

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#if defined(__GNUC__) || defined(__clang__)
#define ATOMIC_LOAD_U64(ptr) __atomic_load_n((ptr), __ATOMIC_RELAXED)
#define ATOMIC_STORE_U64(ptr, value) __atomic_store_n((ptr), (value), __ATOMIC_RELAXED)
#define ATOMIC_ADD_U64(ptr, value) __atomic_add_fetch((ptr), (value), __ATOMIC_RELAXED)
#define ATOMIC_LOAD_SIZE(ptr) __atomic_load_n((ptr), __ATOMIC_RELAXED)
#define ATOMIC_STORE_SIZE(ptr, value) __atomic_store_n((ptr), (value), __ATOMIC_RELAXED)
#define ATOMIC_ADD_SIZE(ptr, value) __atomic_add_fetch((ptr), (value), __ATOMIC_RELAXED)
#else
#define ATOMIC_LOAD_U64(ptr) (*(ptr))
#define ATOMIC_STORE_U64(ptr, value) (*(ptr) = (value))
#define ATOMIC_ADD_U64(ptr, value) ((*(ptr)) += (value))
#define ATOMIC_LOAD_SIZE(ptr) (*(ptr))
#define ATOMIC_STORE_SIZE(ptr, value) (*(ptr) = (value))
#define ATOMIC_ADD_SIZE(ptr, value) ((*(ptr)) += (value))
#endif

#define READ_SIZE (4U * 1024U * 1024U)
#define READ_ERROR_MIN_SIZE 4096U
#define READ_RECOVERY_SIZE (1024U * 1024U)
#define READ_ERROR_FIRST_SKIP_SIZE (1024ULL * 1024ULL)
#define READ_ERROR_SECOND_SKIP_SIZE (4ULL * 1024ULL * 1024ULL)
#define READ_ERROR_MAX_SKIP_SIZE (16ULL * 1024ULL * 1024ULL)
#define READ_RECOVERY_ZONE_BYTES (16ULL * 1024ULL * 1024ULL)
#define OVERLAP (RECORD_SIZE - 1U)
#define TREE_INITIAL_REFRESH_RECORDS 5000U
#define TREE_REFRESH_RECORDS 50000U
#define TREE_LIVE_REFRESH_MIN_SECONDS 300.0
#define ENTRY_QUEUE_CAPACITY 8192U
#define MFT_EVENT_QUEUE_CAPACITY 8192U
#define READ_BLOCK_QUEUE_CAPACITY 8U
#define RECOVERY_WRITE_QUEUE_CAPACITY 8U
#define BIN_WRITER_FLUSH_EVENTS 65536U
#define RECORD_STATS_CAPACITY 1048576U
#define BIN_ROW_SIZE_V1 104U
#define BIN_ROW_SIZE 144U
#define BIN_ROW_SIZE_V3 152U
#define BIN_MAGIC_V1 "C26MFT1"
#define BIN_MAGIC_V2 "C26MFT2"
#define BIN_MAGIC_V3 "C26MFT3"
#define LEGACY_MAP_HEADER_SIZE 44U
#define LEGACY_MAP_RECORD_FIXED_SIZE 120U
#define LEGACY_MAP_MAGIC "C26MFT1"
#define LEGACY_RECORD_MAGIC "MFR1"
#define LEGACY_BINARY_FLAG_HAS_DATA 0x00000004U
#define LEGACY_BINARY_FLAG_IS_RESIDENT 0x00000008U
#define FORMAT_PROFILE_DB_PATH "data/database.db"
#define MAX_INFER_GAP_RECORDS 65536ULL
#define ASSUMED_CLUSTER_SIZE 4096ULL
#define RECOVERY_SIGNAL_RECORDS 1048576U
#define RESUME_BACKOFF_BYTES (64ULL * 1024ULL * 1024ULL)
#define STATE_UPDATE_BYTES (64ULL * 1024ULL * 1024ULL)
#define DIRECT_READ_ALIGNMENT 512ULL
#define OBSERVATION_MAGIC "C26OBS2"
#define OBSERVATION_VERSION 1U
#define OBSERVATION_RUN_NAME_MAX 64U
#define OBSERVATION_SOURCE_PATH_MAX 256U
#define MFTPROBE_BOOT_FRONT_SCAN_BYTES (16ULL * 1024ULL * 1024ULL)
#define MFTPROBE_BOOT_TAIL_SCAN_BYTES (64ULL * 1024ULL * 1024ULL)
#define MFTPROBE_BOOT_SCAN_STEP_BYTES 512ULL

#define ATTR_FILE_NAME 0x30U
#define ATTR_DATA 0x80U
#define ATTR_END 0xFFFFFFFFU
#define NTFS_FILE_ATTRIBUTE_DIRECTORY 0x10000000U
#define MBR_PARTITION_TABLE_OFFSET 446U
#define MBR_PARTITION_ENTRY_SIZE 16U
#define MBR_PARTITION_COUNT 4U
#define GPT_HEADER_LBA 1ULL
#define GPT_SIGNATURE "EFI PART"
#define GPT_PARTITION_ENTRY_MIN_SIZE 128U
#define GPT_PARTITION_ENTRY_MAX_SIZE 4096U
#define GPT_PARTITION_SCAN_MAX 512U
#define SECTOR_SIZE_FALLBACK 512ULL
#define MFT_SCAN_CHUNK_BYTES (4U * 1024U * 1024U)
#define COMPARE_SCOPE_MAX_ITEMS 16U
#define COMPARE_SCOPE_ITEM_MAX 128U
#define STOP_REQUESTED_MESSAGE "\n[INFO] Ctrl-C mottaget; stanger av snyggt. Tryck Ctrl-C igen for direkt avslut.\n"
#define STOP_FORCED_MESSAGE "\n[INFO] Andra stoppsignalen mottagen; avslutar direkt.\n"

static volatile sig_atomic_t g_stop_requested = 0;
static volatile sig_atomic_t g_stop_signal_count = 0;
static struct sigaction g_previous_sigint_action;
static struct sigaction g_previous_sigterm_action;
static int g_signal_handlers_installed = 0;
static MftprobeEngineStatus g_last_engine_status = MFTPROBE_ENGINE_STATUS_NONE;
static size_t g_last_engine_recovered_count = 0;
static int g_binary_map_format = 1; /* 1=legacy, 2=mftprobe rows */

typedef struct RecoverPathList RecoverPathList;

static void recover_path_build_key(
    const char *rel_path,
    char *out,
    size_t out_size
);
static int targeted_parse_exact_date(const char *value, int *out_date);
static int config_entry_effective_date_matches_local(
    const Config *config,
    const RecoveryFormat *format,
    const MftEntry *entry
);
static int config_entry_matches_users_runtime_filters_local(
    const Config *config,
    const RecoveryFormat *format,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry
);
static int recover_path_list_lookup_output(
    const RecoverPathList *list,
    const char *match_key,
    uint64_t size,
    char *out_rel_path,
    size_t out_rel_path_size
);

typedef struct {
    uint64_t offset;
    unsigned char bytes[RECORD_SIZE];
} MftCandidate;

typedef struct {
    MftEntry entry;
    int relevant;
    int snapshot_relevant;
} MftEvent;

typedef struct {
    uint64_t offset;
    unsigned char prefix[4];
    uint8_t prefix_len;
} MagicCandidate;

typedef struct {
    MagicCandidate *items;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    size_t max_count;
    size_t dropped;
    int done;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} MagicCandidateQueue;


typedef struct {
    uint64_t offset;
    size_t length;
    unsigned char *data;
} ReadBlock;

typedef struct {
    ReadBlock *items;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    size_t max_count;
    int done;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} ReadBlockQueue;

typedef struct {
    MftCandidate *items;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    size_t max_count;
    int done;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} MftCandidateQueue;

typedef struct {
    MftEvent *items;
    size_t capacity;
    size_t head;
    size_t tail;
    size_t count;
    size_t max_count;
    int done;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} MftEventQueue;

typedef struct {
    int record;
    int used;
} RecordSeenSlot;

typedef struct {
    uint64_t offset;
    int used;
} OffsetSeenSlot;

typedef struct {
    OffsetSeenSlot *slots;
    size_t capacity;
    size_t count;
    uint64_t max_offset;
} OffsetSet;

typedef struct {
    uint32_t volume_index;
    uint32_t family;
    int record;
    int used;
} RootScopePrunedSlot;

typedef struct {
    RootScopePrunedSlot *slots;
    size_t capacity;
    size_t count;
} RootScopePrunedSet;

static int root_scope_prune_entry_for_live_scan(
    const Config *config,
    const MftEntry *entry,
    RootScopePrunedSet *pruned_set
);


typedef struct {
    uint32_t volume_index;
    uint32_t family;
    int record;
} LiveRecordKey;

typedef struct {
    uint64_t start;
    uint64_t end;
} NtfsDomainRange;

#define NTFS_DDRESCUE_DOMAIN_COALESCE_GAP_BYTES (1024ULL * 1024ULL)

typedef struct {
    LiveRecordKey key;
    size_t index;
    int used;
} LiveRecordSlot;

typedef struct {
    LiveRecordKey key;
    size_t table_index;
    size_t next;
    int active;
} PendingSelected;

typedef struct {
    LiveRecordKey key;
    size_t head;
    int used;
} PendingWaitSlot;

typedef struct {
    MftTable *table;
    LiveRecordSlot *record_slots;
    size_t record_capacity;
    size_t record_count;
    PendingSelected *pending_items;
    size_t pending_count;
    size_t pending_capacity;
    PendingWaitSlot *pending_wait_slots;
    size_t pending_wait_capacity;
    size_t pending_wait_count;
} LiveIndexState;


static int compare_recovery_targets_by_offset(const void *left, const void *right);
static int compare_recovery_targets_by_schedule(const void *left, const void *right);
static void recovery_plan_advance_scheduler_locked(RecoveryPlan *plan);
static int path_has_size(const char *path, uint64_t size);
static int read_error_is_fatal_device_error(int error_code);
static int streq_ci(const char *a, const char *b);
static int collect_primary_mft_entries(
    FILE *file,
    int image_fd,
    const Config *config,
    MftTable *table,
    uint64_t *out_scanned_bytes
);
static int collect_primary_mft_entries_resolving_folder_terms(
    FILE *file,
    int image_fd,
    Config *config,
    MftTable *table,
    uint64_t *out_scanned_bytes,
    int *out_folder_search_failed
);
static void recovery_plan_log_summary(RecoveryPlan *plan);
static int recovery_plan_direct_recover(
    RecoveryPlan *plan,
    const Config *config,
    int only_missed_like
);
static int recovery_plan_replay_missed_jpeg_targets(
    RecoveryPlan *plan,
    const Config *config
);
static int recovery_plan_replay_missed_png_targets(
    RecoveryPlan *plan,
    const Config *config
);
static int recovery_plan_replay_missed_mov_targets(
    RecoveryPlan *plan,
    const Config *config
);
static int write_users_selected_tree(const Config *config, MftTable *table);
static void prune_empty_deleted_dirs(const char *out_dir);
static int ensure_state_dir_for_out_dir(
    const char *out_dir,
    char *state_dir,
    size_t state_dir_size
);
static int write_binary_map_snapshot(const Config *config, MftTable *table);
static int write_missed_targets_report(const Config *config, RecoveryPlan *plan);

typedef struct PrimaryMftScanContext {
    const NtfsGeometry *geometry;
    RecoveryRun runs[RECOVERY_TARGET_MAX_RUNS];
    size_t run_count;
    int run_truncated;
    uint64_t mft_file_bytes;
    uint64_t scan_limit;
} PrimaryMftScanContext;

static int recovery_target_is_partial(const RecoveryTarget *target)
{
    return mftprobe_format_target_is_partial(target);
}

static int append_partial_suffix(char *path, size_t path_size)
{
    char temp[PATH_MAX_LEN];

    if (path == NULL || path[0] == '\0' || path_size == 0) {
        return 0;
    }

    if (snprintf(temp, sizeof(temp), "%s.partial", path) >= (int)sizeof(temp)) {
        return 0;
    }
    if (snprintf(path, path_size, "%s", temp) >= (int)path_size) {
        return 0;
    }

    return 1;
}

typedef struct {
    MftTable *table;
    const Config *config;
    RecoveryPlan *recovery_plan;
    int done;
    int refresh_requested;
    size_t last_written_count;
    double last_written_at;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} UsersWorker;

typedef struct {
    ReadBlockQueue *read_queue;
    MftCandidateQueue *mft_queue;
    MagicCandidateQueue *magic_queue;
    RecoveryPlan *recovery_plan;
    RecoveryWriteQueue *recovery_write_queue;
    uint64_t blocks_processed;
    uint64_t bytes_processed;
    int ok;
} PrefixWorker;

typedef struct {
    const Config *config;
    MftCandidateQueue *queue;
    MftEventQueue *bin_queue;
    MftEventQueue *live_queue;
    uint64_t raw_records;
    uint64_t accepted_records;
    uint64_t duplicate_offsets;
    uint64_t duplicate_record_ids;
    uint64_t hard_rejected_records;
    uint64_t soft_duplicate_record_ids_kept;
    uint64_t first_record_offset;
    uint64_t last_record_offset;
    uint64_t users_root_count;
    uint64_t users_root_first_seen_offset;
    uint64_t mft_run_count;
    uint64_t mft_run_total_bytes;
    uint64_t mft_run_max_lcn_end;
    uint64_t mft_expected_end_offset;
    uint64_t expected_end_miss_count;
    uint32_t family_count;
    int have_record;
    int have_users_root;
    uint64_t initial_prev_offset;
    int initial_prev_record;
    int initial_have_prev;
    OffsetSet resume_offsets;
    RootScopePrunedSet root_scope_pruned;
    int ok;
} SieveWorker;

typedef struct {
    const Config *config;
    MftEventQueue *queue;
    uint64_t rows_written;
    int ok;
} BinWriterWorker;

typedef struct {
    const Config *config;
    MftTable *table;
    MftEventQueue *queue;
    UsersWorker *users_worker;
    RecoveryPlan *recovery_plan;
    uint64_t selected_candidates_seen;
    uint64_t path_ready_candidates;
    uint64_t targets_attempted;
    uint64_t targets_appended;
    uint64_t pending_waits_created;
    uint64_t pending_remaining;
    int ok;
} LiveIndexWorker;

typedef struct {
    RecoveryWriteQueue *queue;
    RecoveryPlan *recovery_plan;
    uint64_t jobs_completed;
    uint64_t bytes_written;
    int ok;
} RecoveryWriterWorker;

typedef struct {
    const Config *config;
    ReadBlockQueue *read_queue;
    MftCandidateQueue *mft_queue;
    MftEventQueue *bin_queue;
    MftEventQueue *live_queue;
    RecoveryWriteQueue *write_queue;
    MftTable *table;
    RecoveryPlan *recovery_plan;
    UsersWorker *users_worker;
    PrefixWorker *prefix_worker;
    SieveWorker *sieve_worker;
    BinWriterWorker *bin_writer_worker;
    LiveIndexWorker *live_index_worker;
    RecoveryWriterWorker *recovery_writer_worker;
} ThreadActivityStateContext;

typedef struct {
    ThreadActivityStateContext *context;
    int done;
    int ok;
    pthread_mutex_t mutex;
} ThreadActivityWriterWorker;

static int snapshot_entries(MftTable *table, MftEntry **out_items, size_t *out_count);
static uint64_t mftprobe_detect_source_size(const char *path);
static uint64_t mftprobe_detect_logical_block_size(const char *path);
#ifdef __APPLE__
static int detect_ntfs_geometries_macos_diskutil_fallback(
    const char *path,
    NtfsGeometry *volumes,
    size_t *volume_count
);
#endif
static int write_scan_state(const Config *config, uint64_t scan_offset, int completed);
static int mftprobe_preflight_open(const char *path);
static int mftprobe_resolve_input_source_path(
    const char *input_path,
    char *resolved_path,
    size_t resolved_path_size,
    const char **effective_path
);
static int write_thread_activity_state(const ThreadActivityStateContext *context);
static void observation_write_run_start(const Config *config);
static void observation_write_geometry(const Config *config);
static void observation_write_final(
    const Config *config,
    const SieveWorker *sieve,
    RecoveryPlan *plan,
    MftTable *table,
    int completed
);

static size_t live_index_count_pending_active(const LiveIndexState *state)
{
    size_t count = 0;
    size_t i;

    if (state == NULL || state->pending_items == NULL) {
        return 0U;
    }

    for (i = 0; i < state->pending_count; i++) {
        if (state->pending_items[i].active) {
            count++;
        }
    }

    return count;
}

static int scan_state_mode_is_users(const char *scan_mode)
{
    return scan_mode != NULL &&
           scan_mode[0] != '\0' &&
           (strcmp(scan_mode, "users") == 0 ||
            strcmp(scan_mode, "folders") == 0);
}

static void request_stop(int signum)
{
    ssize_t ignored = 0;

    (void)signum;
    if (g_stop_signal_count == 0) {
        ignored = write(
            STDERR_FILENO,
            STOP_REQUESTED_MESSAGE,
            sizeof(STOP_REQUESTED_MESSAGE) - 1U
        );
        (void)ignored;
    }
    g_stop_requested = 1;
    if (g_stop_signal_count < 1000) {
        g_stop_signal_count++;
    }
    if (g_stop_signal_count >= 2) {
        ignored = write(
            STDERR_FILENO,
            STOP_FORCED_MESSAGE,
            sizeof(STOP_FORCED_MESSAGE) - 1U
        );
        (void)ignored;
        _exit(130);
    }
}

static int mftprobe_resolve_input_source_path(
    const char *input_path,
    char *resolved_path,
    size_t resolved_path_size,
    const char **effective_path
)
{
    struct stat st;

    if (effective_path != NULL) {
        *effective_path = input_path;
    }
    if (resolved_path != NULL && resolved_path_size > 0U) {
        resolved_path[0] = '\0';
    }

    if (input_path == NULL || input_path[0] == '\0') {
        return 0;
    }

    if (stat(input_path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return 1;
    }
    if (resolved_path == NULL || resolved_path_size == 0U) {
        log_error("Mounted source resolution needs a buffer");
        return 0;
    }
    if (!reader_resolve_mounted_source_device(
            input_path,
            resolved_path,
            resolved_path_size)) {
        log_error(
            "Source path is a mounted directory but no backing device could be resolved: %s (%s)",
            input_path,
            reader_last_error()
        );
        return 0;
    }

    if (effective_path != NULL) {
        *effective_path = resolved_path;
    }
    log_info("Resolved mounted source %s to device %s", input_path, resolved_path);
    return 1;
}

static void install_signal_handlers(void)
{
    struct sigaction action;

    g_stop_requested = 0;
    g_stop_signal_count = 0;
    memset(&action, 0, sizeof(action));
    action.sa_handler = request_stop;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    if (sigaction(SIGINT, &action, &g_previous_sigint_action) == 0 &&
        sigaction(SIGTERM, &action, &g_previous_sigterm_action) == 0) {
        g_signal_handlers_installed = 1;
    }
}

static void restore_signal_handlers(void)
{
    if (!g_signal_handlers_installed) {
        return;
    }

    sigaction(SIGINT, &g_previous_sigint_action, NULL);
    sigaction(SIGTERM, &g_previous_sigterm_action, NULL);
    g_signal_handlers_installed = 0;
}

static int stop_requested(void)
{
    return g_stop_requested != 0;
}

static double monotonic_seconds(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + ((double)now.tv_nsec / 1000000000.0);
}

static void cond_wait_briefly(pthread_cond_t *cond, pthread_mutex_t *mutex)
{
    struct timespec deadline;

    clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_nsec += 100000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    (void)pthread_cond_timedwait(cond, mutex, &deadline);
}

static void block_stop_signals_in_worker(void)
{
    sigset_t blocked;

    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGTERM);
    (void)pthread_sigmask(SIG_BLOCK, &blocked, NULL);
}

static uint16_t rd16(const unsigned char *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const unsigned char *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const unsigned char *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static int read_exact_at(FILE *file, uint64_t offset, unsigned char *buffer, size_t size)
{
    if (file == NULL || buffer == NULL) {
        return 0;
    }

    if (fseeko(file, (off_t)offset, SEEK_SET) != 0) {
        return 0;
    }
    return fread(buffer, 1, size, file) == size;
}

static size_t read_chunk_at_fd(int fd, uint64_t offset, unsigned char *buffer, size_t size)
{
    for (;;) {
        ssize_t got;

        if (fd < 0 || buffer == NULL || size == 0U) {
            return 0U;
        }

        errno = 0;
        got = pread(fd, buffer, size, (off_t)offset);
        if (got > 0) {
            return (size_t)got;
        }
        if (got == 0) {
            return 0U;
        }
        if (errno != EINTR) {
            return 0U;
        }
    }
}

static int ntfs_geometry_from_boot_sector(
    const unsigned char *sector,
    uint64_t volume_offset,
    uint64_t volume_size,
    int is_basic_data,
    NtfsGeometry *geometry
)
{
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint64_t cluster_size;
    uint64_t mft_lcn;
    uint64_t mft_mirror_lcn;
    int8_t record_size_raw;
    uint32_t mft_record_size = RECORD_SIZE;

    if (sector == NULL || geometry == NULL ||
        memcmp(sector + 3, "NTFS    ", 8) != 0) {
        return 0;
    }

    bytes_per_sector = rd16(sector + 11);
    sectors_per_cluster = sector[13];
    cluster_size = (uint64_t)bytes_per_sector * (uint64_t)sectors_per_cluster;
    mft_lcn = rd64(sector + 48);
    mft_mirror_lcn = rd64(sector + 56);
    record_size_raw = (int8_t)sector[64];

    if (bytes_per_sector == 0 ||
        sectors_per_cluster == 0 ||
        cluster_size == 0 ||
        cluster_size > (16ULL * 1024ULL * 1024ULL)) {
        return 0;
    }

    if (record_size_raw < 0) {
        mft_record_size = (uint32_t)1U << (uint8_t)(-record_size_raw);
    } else if (record_size_raw > 0) {
        mft_record_size = (uint32_t)record_size_raw * (uint32_t)cluster_size;
    }
    if (mft_record_size == 0) {
        mft_record_size = RECORD_SIZE;
    }

    memset(geometry, 0, sizeof(*geometry));
    geometry->valid = 1;
    geometry->volume_offset = volume_offset;
    geometry->volume_size = volume_size;
    geometry->cluster_size = cluster_size;
    geometry->volume_serial = rd64(sector + 72);
    geometry->mft_lcn = mft_lcn;
    geometry->mft_mirror_lcn = mft_mirror_lcn;
    geometry->mft_abs_offset = volume_offset + mft_lcn * cluster_size;
    geometry->mft_mirror_abs_offset = volume_offset + mft_mirror_lcn * cluster_size;
    geometry->mft_record_size = mft_record_size;
    geometry->bytes_per_sector = bytes_per_sector;
    geometry->sectors_per_cluster = sectors_per_cluster;
    geometry->is_basic_data = is_basic_data;
    return 1;
}

static int try_ntfs_geometry_at(
    FILE *file,
    uint64_t offset,
    uint64_t volume_size,
    int is_basic_data,
    NtfsGeometry *geometry
)
{
    unsigned char sector[512];

    return read_exact_at(file, offset, sector, sizeof(sector)) &&
           ntfs_geometry_from_boot_sector(
               sector,
               offset,
               volume_size,
               is_basic_data,
               geometry);
}

static int guid_is_microsoft_basic_data(const unsigned char *guid)
{
    static const unsigned char basic_data_guid[16] = {
        0xA2, 0xA0, 0xD0, 0xEB,
        0xE5, 0xB9,
        0x33, 0x44,
        0x87, 0xC0,
        0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
    };

    return guid != NULL &&
           memcmp(guid, basic_data_guid, sizeof(basic_data_guid)) == 0;
}

static int ntfs_volume_exists(
    const NtfsGeometry *volumes,
    size_t count,
    uint64_t volume_offset
)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (volumes[i].valid && volumes[i].volume_offset == volume_offset) {
            return 1;
        }
    }

    return 0;
}

static int add_ntfs_volume(
    NtfsGeometry *volumes,
    size_t *count,
    const NtfsGeometry *geometry
)
{
    if (volumes == NULL || count == NULL || geometry == NULL || !geometry->valid) {
        return 0;
    }
    if (*count >= MAX_NTFS_VOLUMES ||
        ntfs_volume_exists(volumes, *count, geometry->volume_offset)) {
        return 0;
    }

    volumes[*count] = *geometry;
    (*count)++;
    return 1;
}

typedef struct {
    int found;
    unsigned int score;
    NtfsGeometry geometry;
    uint64_t boot_offset;
    int as_backup;
    int primary_signature;
    int mirror_signature;
} MftprobeNtfsBootCandidate;

typedef struct {
    MftprobeNtfsBootCandidate best;
    size_t plausible_count;
    size_t signature_count;
} MftprobeNtfsBootSearch;

static const char *mftprobe_record_signature_label(int signature)
{
    switch (signature) {
        case 2:
            return "FILE";
        case 1:
            return "BAAD";
        default:
            return "none";
    }
}

static int mftprobe_record_signature_at(
    FILE *file,
    uint64_t source_size,
    uint64_t offset
)
{
    unsigned char signature[4];

    if (file == NULL ||
        (source_size > 0ULL &&
         (offset > source_size || sizeof(signature) > source_size - offset)) ||
        !read_exact_at(file, offset, signature, sizeof(signature))) {
        return 0;
    }
    if (memcmp(signature, "FILE", 4) == 0) {
        return 2;
    }
    if (memcmp(signature, "BAAD", 4) == 0) {
        return 1;
    }
    return 0;
}

static int ntfs_boot_sector_volume_bytes(
    const unsigned char *sector,
    uint64_t *out_volume_bytes
)
{
    uint16_t bytes_per_sector;
    uint64_t total_sectors;

    if (out_volume_bytes != NULL) {
        *out_volume_bytes = 0ULL;
    }
    if (sector == NULL ||
        out_volume_bytes == NULL ||
        memcmp(sector + 3, "NTFS    ", 8) != 0) {
        return 0;
    }

    bytes_per_sector = rd16(sector + 11);
    total_sectors = rd64(sector + 40);
    if (bytes_per_sector == 0 ||
        total_sectors == 0 ||
        total_sectors > UINT64_MAX / (uint64_t)bytes_per_sector) {
        return 0;
    }

    *out_volume_bytes = total_sectors * (uint64_t)bytes_per_sector;
    return *out_volume_bytes != 0ULL;
}

static unsigned int mftprobe_ntfs_boot_candidate_score(
    int as_backup,
    int primary_signature,
    int mirror_signature
)
{
    unsigned int score = as_backup ? 20U : 40U;

    if (primary_signature == 2) {
        score += 10000U;
    } else if (primary_signature == 1) {
        score += 6000U;
    }
    if (mirror_signature == 2) {
        score += 5000U;
    } else if (mirror_signature == 1) {
        score += 3000U;
    }
    if (primary_signature != 0 && mirror_signature != 0) {
        score += 3000U;
    }
    return score;
}

static int mftprobe_ntfs_boot_candidate_is_better(
    const MftprobeNtfsBootCandidate *candidate,
    const MftprobeNtfsBootCandidate *best
)
{
    if (candidate == NULL || best == NULL) {
        return 0;
    }
    if (!best->found) {
        return 1;
    }
    if (candidate->score != best->score) {
        return candidate->score > best->score;
    }
    if (candidate->primary_signature != best->primary_signature) {
        return candidate->primary_signature > best->primary_signature;
    }
    if (candidate->mirror_signature != best->mirror_signature) {
        return candidate->mirror_signature > best->mirror_signature;
    }
    if (candidate->as_backup != best->as_backup) {
        return candidate->as_backup < best->as_backup;
    }
    return candidate->geometry.volume_offset < best->geometry.volume_offset;
}

static int mftprobe_consider_ntfs_boot_candidate_at(
    FILE *file,
    uint64_t source_size,
    uint64_t boot_offset,
    int as_backup,
    MftprobeNtfsBootSearch *search
)
{
    unsigned char sector[512];
    uint64_t volume_size = 0;
    uint64_t volume_offset;
    NtfsGeometry geometry;
    MftprobeNtfsBootCandidate candidate;

    if (file == NULL ||
        search == NULL ||
        source_size < sizeof(sector) ||
        boot_offset > source_size ||
        sizeof(sector) > source_size - boot_offset ||
        !read_exact_at(file, boot_offset, sector, sizeof(sector)) ||
        !ntfs_boot_sector_volume_bytes(sector, &volume_size)) {
        return 0;
    }

    if (as_backup) {
        if (volume_size < sizeof(sector) ||
            boot_offset < volume_size - sizeof(sector)) {
            return 0;
        }
        volume_offset = boot_offset - (volume_size - sizeof(sector));
    } else {
        volume_offset = boot_offset;
    }
    if (source_size > 0ULL &&
        (volume_offset >= source_size ||
         volume_size > source_size - volume_offset)) {
        return 0;
    }
    if (!ntfs_geometry_from_boot_sector(
            sector,
            volume_offset,
            volume_size,
            0,
            &geometry)) {
        return 0;
    }

    memset(&candidate, 0, sizeof(candidate));
    candidate.found = 1;
    candidate.geometry = geometry;
    candidate.boot_offset = boot_offset;
    candidate.as_backup = as_backup ? 1 : 0;
    candidate.primary_signature =
        mftprobe_record_signature_at(file, source_size, geometry.mft_abs_offset);
    candidate.mirror_signature =
        mftprobe_record_signature_at(file, source_size, geometry.mft_mirror_abs_offset);
    candidate.score = mftprobe_ntfs_boot_candidate_score(
        candidate.as_backup,
        candidate.primary_signature,
        candidate.mirror_signature
    );

    search->plausible_count++;
    if (candidate.primary_signature != 0 || candidate.mirror_signature != 0) {
        search->signature_count++;
    }
    if (mftprobe_ntfs_boot_candidate_is_better(&candidate, &search->best)) {
        search->best = candidate;
    }
    return 1;
}

static void mftprobe_scan_ntfs_boot_sector_range(
    FILE *file,
    uint64_t source_size,
    uint64_t start_offset,
    uint64_t end_offset,
    uint64_t step_bytes,
    int as_backup,
    MftprobeNtfsBootSearch *search
)
{
    uint64_t offset;

    if (file == NULL ||
        search == NULL ||
        start_offset >= end_offset ||
        step_bytes == 0ULL) {
        return;
    }
    if (step_bytes <= 512ULL) {
        start_offset -= start_offset % 512ULL;
    }

    for (offset = start_offset;
         offset + 512ULL <= end_offset && !stop_requested();
         offset += step_bytes) {
        (void)mftprobe_consider_ntfs_boot_candidate_at(
            file,
            source_size,
            offset,
            as_backup,
            search
        );
    }
}

static int recover_ntfs_geometries_from_orphan_boot_sectors(
    FILE *file,
    uint64_t source_size,
    NtfsGeometry *volumes,
    size_t *volume_count
)
{
    MftprobeNtfsBootSearch search;
    uint64_t front_end;
    uint64_t tail_start;

    if (file == NULL ||
        volumes == NULL ||
        volume_count == NULL ||
        source_size < 512ULL) {
        return 0;
    }

    memset(&search, 0, sizeof(search));

    (void)mftprobe_consider_ntfs_boot_candidate_at(
        file,
        source_size,
        source_size - 512ULL,
        1,
        &search
    );

    front_end = source_size < MFTPROBE_BOOT_FRONT_SCAN_BYTES
        ? source_size
        : MFTPROBE_BOOT_FRONT_SCAN_BYTES;
    mftprobe_scan_ntfs_boot_sector_range(
        file,
        source_size,
        0ULL,
        front_end,
        MFTPROBE_BOOT_SCAN_STEP_BYTES,
        0,
        &search
    );

    tail_start = source_size > MFTPROBE_BOOT_TAIL_SCAN_BYTES
        ? source_size - MFTPROBE_BOOT_TAIL_SCAN_BYTES
        : 0ULL;
    mftprobe_scan_ntfs_boot_sector_range(
        file,
        source_size,
        tail_start,
        source_size,
        MFTPROBE_BOOT_SCAN_STEP_BYTES,
        1,
        &search
    );

    if (!search.best.found) {
        return 0;
    }

    if (!add_ntfs_volume(volumes, volume_count, &search.best.geometry)) {
        return 0;
    }

    log_info(
        "Recovered NTFS geometry for MFT preview: %s boot=%llu volume_start=%llu mft=%llu(%s) mirror=%llu(%s)",
        search.best.as_backup ? "backup" : "orphan",
        (unsigned long long)search.best.boot_offset,
        (unsigned long long)search.best.geometry.volume_offset,
        (unsigned long long)search.best.geometry.mft_abs_offset,
        mftprobe_record_signature_label(search.best.primary_signature),
        (unsigned long long)search.best.geometry.mft_mirror_abs_offset,
        mftprobe_record_signature_label(search.best.mirror_signature)
    );
    return 1;
}

static size_t choose_preferred_ntfs_volume(const NtfsGeometry *volumes, size_t count)
{
    size_t best = 0;
    size_t i;

    for (i = 1; i < count; i++) {
        int best_basic = volumes[best].is_basic_data;
        int this_basic = volumes[i].is_basic_data;

        if ((this_basic && !best_basic) ||
            (this_basic == best_basic &&
             volumes[i].volume_size > volumes[best].volume_size)) {
            best = i;
        }
    }

    return best;
}

static int detect_ntfs_geometries(
    const char *path,
    uint64_t source_size,
    NtfsGeometry *volumes,
    size_t *volume_count
)
{
    FILE *file;
    unsigned char sector[512];
    uint64_t logical_block_size;
    uint64_t sector_stride;
    size_t i;
    int maybe_gpt = 0;
    NtfsGeometry geometry;

    if (volumes == NULL || volume_count == NULL) {
        return 0;
    }

    *volume_count = 0;
    memset(volumes, 0, MAX_NTFS_VOLUMES * sizeof(*volumes));
    logical_block_size = mftprobe_detect_logical_block_size(path);
    sector_stride = logical_block_size >= SECTOR_SIZE_FALLBACK
        ? logical_block_size
        : SECTOR_SIZE_FALLBACK;
    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }

    if (try_ntfs_geometry_at(file, 0, source_size, 0, &geometry)) {
        (void)add_ntfs_volume(volumes, volume_count, &geometry);
    }

    if (!read_exact_at(file, 0, sector, sizeof(sector)) ||
        sector[510] != 0x55 || sector[511] != 0xAA) {
        fclose(file);
        return *volume_count > 0;
    }

    for (i = 0; i < MBR_PARTITION_COUNT; i++) {
        const unsigned char *entry =
            sector + MBR_PARTITION_TABLE_OFFSET + i * MBR_PARTITION_ENTRY_SIZE;
        uint8_t type = entry[4];
        uint32_t start_lba = rd32(entry + 8);
        uint32_t sector_count = rd32(entry + 12);

        if (type == 0xEEU) {
            maybe_gpt = 1;
        }
        if (type == 0 || start_lba == 0 || sector_count == 0) {
            continue;
        }
        if (try_ntfs_geometry_at(
                file,
                (uint64_t)start_lba * sector_stride,
                (uint64_t)sector_count * sector_stride,
                0,
                &geometry)) {
            (void)add_ntfs_volume(volumes, volume_count, &geometry);
        }
    }

    if (maybe_gpt) {
        unsigned char gpt_header[512];
        uint64_t entries_lba;
        uint32_t entry_count;
        uint32_t entry_size;
        uint32_t capped_count;

        if (read_exact_at(file, GPT_HEADER_LBA * sector_stride, gpt_header, sizeof(gpt_header)) &&
            memcmp(gpt_header, GPT_SIGNATURE, 8) == 0) {
            entries_lba = rd64(gpt_header + 72);
            entry_count = rd32(gpt_header + 80);
            entry_size = rd32(gpt_header + 84);

            if (entries_lba != 0 &&
                entry_count != 0 &&
                entry_size >= GPT_PARTITION_ENTRY_MIN_SIZE &&
                entry_size <= GPT_PARTITION_ENTRY_MAX_SIZE) {
                capped_count = entry_count > GPT_PARTITION_SCAN_MAX ?
                    GPT_PARTITION_SCAN_MAX : entry_count;

                for (i = 0; i < capped_count; i++) {
                    unsigned char entry[GPT_PARTITION_ENTRY_MAX_SIZE];
                    uint64_t entry_offset =
                        entries_lba * sector_stride + (uint64_t)i * entry_size;
                    uint64_t first_lba;
                    size_t j;
                    int empty = 1;

                    if (!read_exact_at(file, entry_offset, entry, entry_size)) {
                        break;
                    }
                    for (j = 0; j < 16U; j++) {
                        if (entry[j] != 0) {
                            empty = 0;
                            break;
                        }
                    }
                    if (empty) {
                        continue;
                    }

                    first_lba = rd64(entry + 32);
                    if (first_lba == 0) {
                        continue;
                    }
                    {
                        uint64_t last_lba = rd64(entry + 40);
                        uint64_t volume_size;

                        if (last_lba < first_lba) {
                            continue;
                        }
                        volume_size = (last_lba - first_lba + 1ULL) *
                                      sector_stride;
                        if (!try_ntfs_geometry_at(
                                file,
                                first_lba * sector_stride,
                                volume_size,
                                guid_is_microsoft_basic_data(entry),
                                &geometry)) {
                            continue;
                        }
                        (void)add_ntfs_volume(volumes, volume_count, &geometry);
                    }
                }
            }
        }
    }

    if (*volume_count == 0) {
        (void)recover_ntfs_geometries_from_orphan_boot_sectors(
            file,
            source_size,
            volumes,
            volume_count
        );
    }

    fclose(file);

#ifdef __APPLE__
    if (*volume_count == 0 &&
        detect_ntfs_geometries_macos_diskutil_fallback(path, volumes, volume_count)) {
        return 1;
    }
#endif

    return *volume_count > 0;
}

static uint64_t mftprobe_detect_logical_block_size(const char *path)
{
    struct stat st;

    if (path == NULL || stat(path, &st) != 0) {
        return 0;
    }

#ifdef __APPLE__
    if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
        int fd = open(path, O_RDONLY);
        uint32_t block_size = 0;

        if (fd < 0) {
            return 0;
        }
        if (ioctl(fd, DKIOCGETBLOCKSIZE, &block_size) != 0) {
            close(fd);
            return 0;
        }
        close(fd);
        return block_size > 0 ? (uint64_t)block_size : 0;
    }
#endif

    return 0;
}

#ifdef __APPLE__
static int derive_macos_whole_disk_name(const char *path, char *out, size_t out_size)
{
    const char *suffix = NULL;
    size_t digits = 0;

    if (path == NULL || out == NULL || out_size == 0) {
        return 0;
    }

    if (strncmp(path, "/dev/rdisk", 10) == 0) {
        suffix = path + 10;
    } else if (strncmp(path, "/dev/disk", 9) == 0) {
        suffix = path + 9;
    } else {
        return 0;
    }

    while (isdigit((unsigned char)suffix[digits])) {
        digits++;
    }
    if (digits == 0 || suffix[digits] != '\0') {
        return 0;
    }

    return snprintf(out, out_size, "disk%.*s", (int)digits, suffix) < (int)out_size;
}

static int parse_diskutil_bytes_line(const char *line, const char *prefix, uint64_t *value_out)
{
    unsigned long long value = 0;

    if (line == NULL || prefix == NULL || value_out == NULL) {
        return 0;
    }
    if (strncmp(line, prefix, strlen(prefix)) != 0) {
        return 0;
    }
    if (sscanf(line + strlen(prefix), "%llu Bytes", &value) != 1) {
        return 0;
    }

    *value_out = (uint64_t)value;
    return 1;
}

static int parse_diskutil_size_parenthetical(const char *line, uint64_t *value_out)
{
    const char *paren;
    unsigned long long value = 0;

    if (line == NULL || value_out == NULL) {
        return 0;
    }

    paren = strchr(line, '(');
    if (paren == NULL) {
        return 0;
    }
    if (sscanf(paren, "(%llu Bytes)", &value) != 1) {
        return 0;
    }

    *value_out = (uint64_t)value;
    return 1;
}

static void copy_trimmed_diskutil_value(
    const char *line,
    const char *prefix,
    char *out,
    size_t out_size
)
{
    const char *start;
    const char *end;
    size_t len;

    if (line == NULL || prefix == NULL || out == NULL || out_size == 0) {
        return;
    }
    if (strncmp(line, prefix, strlen(prefix)) != 0) {
        return;
    }

    start = line + strlen(prefix);
    while (*start == ' ' || *start == '\t') {
        start++;
    }
    end = start + strlen(start);
    while (end > start &&
           (end[-1] == '\n' || end[-1] == '\r' ||
            end[-1] == ' ' || end[-1] == '\t')) {
        end--;
    }

    len = (size_t)(end - start);
    if (len >= out_size) {
        len = out_size - 1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
}

static int detect_macos_source_filesystem_hint(
    const char *path,
    char *slice_out,
    size_t slice_out_size,
    char *personality_out,
    size_t personality_out_size,
    char *partition_type_out,
    size_t partition_type_out_size
)
{
    char whole_disk[64];
    int slice_number;

    if (slice_out == NULL || slice_out_size == 0 ||
        personality_out == NULL || personality_out_size == 0 ||
        partition_type_out == NULL || partition_type_out_size == 0) {
        return 0;
    }

    slice_out[0] = '\0';
    personality_out[0] = '\0';
    partition_type_out[0] = '\0';

    if (path == NULL) {
        return 0;
    }

    if (!derive_macos_whole_disk_name(path, whole_disk, sizeof(whole_disk))) {
        char info_command[256];
        char info_line[512];
        FILE *info_pipe;
        int saw_output = 0;

        if (snprintf(info_command, sizeof(info_command), "diskutil info '%s' 2>/dev/null", path) >= (int)sizeof(info_command)) {
            return 0;
        }
        info_pipe = popen(info_command, "r");
        if (info_pipe == NULL) {
            return 0;
        }
        while (fgets(info_line, sizeof(info_line), info_pipe) != NULL) {
            saw_output = 1;
            copy_trimmed_diskutil_value(
                info_line,
                "   File System Personality:",
                personality_out,
                personality_out_size
            );
            copy_trimmed_diskutil_value(
                info_line,
                "   Partition Type:",
                partition_type_out,
                partition_type_out_size
            );
        }
        pclose(info_pipe);
        if (!saw_output) {
            return 0;
        }
        snprintf(slice_out, slice_out_size, "%s", path);
        return personality_out[0] != '\0' || partition_type_out[0] != '\0';
    }

    for (slice_number = 1; slice_number <= 32; slice_number++) {
        char slice_id[64];
        char info_command[128];
        char info_line[512];
        FILE *info_pipe;
        int saw_output = 0;

        snprintf(slice_id, sizeof(slice_id), "%ss%d", whole_disk, slice_number);
        if (snprintf(info_command, sizeof(info_command), "diskutil info /dev/%s 2>/dev/null", slice_id) >= (int)sizeof(info_command)) {
            continue;
        }

        info_pipe = popen(info_command, "r");
        if (info_pipe == NULL) {
            continue;
        }

        while (fgets(info_line, sizeof(info_line), info_pipe) != NULL) {
            saw_output = 1;
            copy_trimmed_diskutil_value(
                info_line,
                "   File System Personality:",
                personality_out,
                personality_out_size
            );
            copy_trimmed_diskutil_value(
                info_line,
                "   Partition Type:",
                partition_type_out,
                partition_type_out_size
            );
        }
        pclose(info_pipe);

        if (!saw_output) {
            continue;
        }

        snprintf(slice_out, slice_out_size, "/dev/%s", slice_id);
        if (personality_out[0] != '\0' || partition_type_out[0] != '\0') {
            return 1;
        }
    }

    return 0;
}

static int macos_hint_is_definitely_non_ntfs(const char *personality)
{
    if (personality == NULL || personality[0] == '\0') {
        return 0;
    }

    return strcasecmp(personality, "ntfs") != 0 &&
           strcasecmp(personality, "windows_ntfs") != 0;
}

static int detect_ntfs_geometries_macos_diskutil_fallback(
    const char *path,
    NtfsGeometry *volumes,
    size_t *volume_count
)
{
    char whole_disk[64];
    int found = 0;
    int slice_number;
    int consecutive_missing = 0;

    if (path == NULL || volumes == NULL || volume_count == NULL) {
        return 0;
    }
    if (!derive_macos_whole_disk_name(path, whole_disk, sizeof(whole_disk))) {
        return 0;
    }

    /*
     * On some macOS raw whole-disk devices, direct GPT/MBR probing succeeds for
     * size detection but not for reliable NTFS boot-sector reads. When that
     * happens, ask diskutil for the slice metadata and then read the boot sector
     * from the slice device itself while preserving the absolute partition offset
     * for later runlist calculations against the whole disk.
     */
    for (slice_number = 1; slice_number <= 32; slice_number++) {
        char slice_id[64];
        char raw_slice_path[96];
        char slice_path[96];
        char info_command[128];
        char info_line[512];
        FILE *info_pipe;
        unsigned char boot_sector[512];
        int slice_fd = -1;
        uint64_t partition_offset = 0;
        uint64_t volume_size = 0;
        int have_offset = 0;
        int have_size = 0;
        int is_ntfs = 0;
        int is_basic_data = 0;
        int saw_output = 0;
        NtfsGeometry geometry;

        snprintf(slice_id, sizeof(slice_id), "%ss%d", whole_disk, slice_number);
        if (snprintf(info_command, sizeof(info_command), "diskutil info /dev/%s 2>/dev/null", slice_id) >= (int)sizeof(info_command)) {
            continue;
        }

        info_pipe = popen(info_command, "r");
        if (info_pipe == NULL) {
            continue;
        }

        while (fgets(info_line, sizeof(info_line), info_pipe) != NULL) {
            saw_output = 1;
            if (strncmp(info_line, "   File System Personality:", 27) == 0 &&
                strstr(info_line, "NTFS") != NULL) {
                is_ntfs = 1;
            } else if (strncmp(info_line, "   Partition Type:", 18) == 0 &&
                       strstr(info_line, "Microsoft Basic Data") != NULL) {
                is_basic_data = 1;
            } else if (parse_diskutil_bytes_line(
                           info_line,
                           "   Partition Offset: ",
                           &partition_offset)) {
                have_offset = 1;
            } else if (strncmp(
                           info_line,
                           "   Disk Size:",
                           strlen("   Disk Size:")) == 0 &&
                       parse_diskutil_size_parenthetical(info_line, &volume_size)) {
                have_size = 1;
            }
        }
        pclose(info_pipe);

        if (!saw_output) {
            consecutive_missing++;
            if (consecutive_missing >= 4 && slice_number > 4) {
                break;
            }
            continue;
        }
        consecutive_missing = 0;

        if ((!is_ntfs && !is_basic_data) || !have_offset || !have_size) {
            continue;
        }

        if (snprintf(raw_slice_path, sizeof(raw_slice_path), "/dev/r%s", slice_id) >= (int)sizeof(raw_slice_path) ||
            snprintf(slice_path, sizeof(slice_path), "/dev/%s", slice_id) >= (int)sizeof(slice_path)) {
            continue;
        }

        slice_fd = open(raw_slice_path, O_RDONLY);
        if (slice_fd < 0) {
            slice_fd = open(slice_path, O_RDONLY);
        }
        if (slice_fd < 0) {
            continue;
        }
        if (pread(slice_fd, boot_sector, sizeof(boot_sector), 0) == (ssize_t)sizeof(boot_sector) &&
            ntfs_geometry_from_boot_sector(
                boot_sector,
                partition_offset,
                volume_size,
                is_basic_data,
                &geometry)) {
            if (add_ntfs_volume(volumes, volume_count, &geometry)) {
                found = 1;
            }
        }
        close(slice_fd);
    }
    return found;
}
#endif

static void wr16(unsigned char *p, uint16_t value)
{
    p[0] = (unsigned char)(value & 0xFFU);
    p[1] = (unsigned char)((value >> 8) & 0xFFU);
}

static void wr32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)(value & 0xFFU);
    p[1] = (unsigned char)((value >> 8) & 0xFFU);
    p[2] = (unsigned char)((value >> 16) & 0xFFU);
    p[3] = (unsigned char)((value >> 24) & 0xFFU);
}

static void wr64(unsigned char *p, uint64_t value)
{
    wr32(p, (uint32_t)(value & 0xFFFFFFFFULL));
    wr32(p + 4, (uint32_t)(value >> 32));
}

static void wr_i64(unsigned char *p, int64_t value)
{
    wr64(p, (uint64_t)value);
}

static int write_bytes(FILE *file, const void *data, size_t size)
{
    return size == 0 || (file != NULL && data != NULL && fwrite(data, 1, size, file) == size);
}

static int observation_write_fixed_string(FILE *file, const char *text, size_t width)
{
    char zero[OBSERVATION_SOURCE_PATH_MAX] = {0};
    size_t len;

    if (file == NULL || width > sizeof(zero)) {
        return 0;
    }

    if (text == NULL) {
        return write_bytes(file, zero, width);
    }

    len = strlen(text);
    if (len > width) {
        len = width;
    }

    return write_bytes(file, text, len) &&
           (len == width || write_bytes(file, zero, width - len));
}

static FILE *open_observations_append(void)
{
    /*
     * The old MFT observation binary log was used for performance experiments
     * and is now retired. Keep the surrounding helpers in place for now so we
     * can remove them in a calmer cleanup pass without re-opening the feature.
     */
    return NULL;
}

static int observation_write_header(FILE *file, uint16_t type, uint32_t length)
{
    unsigned char header[16];

    memset(header, 0, sizeof(header));
    memcpy(header, OBSERVATION_MAGIC, 7);
    wr16(header + 8, type);
    wr16(header + 10, OBSERVATION_VERSION);
    wr32(header + 12, length);
    return write_bytes(file, header, sizeof(header));
}

static int write_u32_value(FILE *file, uint32_t value)
{
    unsigned char data[4];

    wr32(data, value);
    return write_bytes(file, data, sizeof(data));
}

static int write_u64_value(FILE *file, uint64_t value)
{
    unsigned char data[8];

    wr64(data, value);
    return write_bytes(file, data, sizeof(data));
}

static int write_i64_value(FILE *file, int64_t value)
{
    unsigned char data[8];

    wr_i64(data, value);
    return write_bytes(file, data, sizeof(data));
}

static int ensure_dir(const char *path)
{
    if (!fs_backend_output_path_write_guard_allows(path)) {
        return 0;
    }
    return mkdir(path, 0775) == 0 || errno == EEXIST;
}

static int ensure_parent_dirs(const char *path)
{
    char temp[PATH_MAX_LEN];
    char *cursor;

    if (path == NULL || strlen(path) >= sizeof(temp)) {
        return 0;
    }
    if (!fs_backend_output_path_write_guard_allows(path)) {
        return 0;
    }

    snprintf(temp, sizeof(temp), "%s", path);
    cursor = temp;

    while ((cursor = strchr(cursor + 1, '/')) != NULL) {
        *cursor = '\0';
        if (!ensure_dir(temp)) {
            return 0;
        }
        *cursor = '/';
    }

    return 1;
}

static void copy_text_truncated_local(char *dst, size_t dst_size, const char *src)
{
    size_t length;

    if (dst == NULL || dst_size == 0) {
        return;
    }

    dst[0] = '\0';
    if (src == NULL) {
        return;
    }

    length = strlen(src);
    if (length >= dst_size) {
        length = dst_size - 1U;
    }

    memcpy(dst, src, length);
    dst[length] = '\0';
}

static int path_exists_local(const char *path)
{
    struct stat st;

    return path != NULL && stat(path, &st) == 0;
}

static int parse_decimal_digits_local(const char *text, size_t count, int *out)
{
    size_t i;
    int value = 0;

    if (text == NULL || out == NULL) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        unsigned char ch = (unsigned char)text[i];

        if (!isdigit(ch)) {
            return 0;
        }
        value = value * 10 + (int)(ch - '0');
    }
    *out = value;
    return 1;
}

static int parse_camera_timestamp_from_filename_local(
    const char *path,
    int *year,
    int *month,
    int *day,
    int *hour,
    int *minute,
    int *second
)
{
    const char *name;

    if (path == NULL ||
        year == NULL || month == NULL || day == NULL ||
        hour == NULL || minute == NULL || second == NULL) {
        return 0;
    }

    name = strrchr(path, '/');
    name = name != NULL ? name + 1 : path;
    if (strlen(name) < 15U || name[8] != '_' ||
        !parse_decimal_digits_local(name, 4U, year) ||
        !parse_decimal_digits_local(name + 4U, 2U, month) ||
        !parse_decimal_digits_local(name + 6U, 2U, day) ||
        !parse_decimal_digits_local(name + 9U, 2U, hour) ||
        !parse_decimal_digits_local(name + 11U, 2U, minute) ||
        !parse_decimal_digits_local(name + 13U, 2U, second)) {
        return 0;
    }

    return 1;
}

static int targeted_filename_to_yyyymmdd_local(const char *path)
{
    int year, month, day, hour, minute, second;

    if (!parse_camera_timestamp_from_filename_local(
            path,
            &year,
            &month,
            &day,
            &hour,
            &minute,
            &second)) {
        return 0;
    }

    (void)hour;
    (void)minute;
    (void)second;
    return year * 10000 + month * 100 + day;
}

static int parse_exif_ascii_timestamp_local(
    const unsigned char *buffer,
    size_t len,
    int *year,
    int *month,
    int *day,
    int *hour,
    int *minute,
    int *second
)
{
    size_t i;

    if (buffer == NULL ||
        year == NULL || month == NULL || day == NULL ||
        hour == NULL || minute == NULL || second == NULL ||
        len < 19U) {
        return 0;
    }

    for (i = 0; i + 19U <= len; i++) {
        if (buffer[i + 4U] != ':' ||
            buffer[i + 7U] != ':' ||
            buffer[i + 10U] != ' ' ||
            buffer[i + 13U] != ':' ||
            buffer[i + 16U] != ':') {
            continue;
        }
        if (!parse_decimal_digits_local((const char *)(buffer + i), 4U, year) ||
            !parse_decimal_digits_local((const char *)(buffer + i + 5U), 2U, month) ||
            !parse_decimal_digits_local((const char *)(buffer + i + 8U), 2U, day) ||
            !parse_decimal_digits_local((const char *)(buffer + i + 11U), 2U, hour) ||
            !parse_decimal_digits_local((const char *)(buffer + i + 14U), 2U, minute) ||
            !parse_decimal_digits_local((const char *)(buffer + i + 17U), 2U, second)) {
            continue;
        }
        return 1;
    }

    return 0;
}

static int read_deleted_jpeg_exif_timestamp_local(
    const char *path,
    int *year,
    int *month,
    int *day,
    int *hour,
    int *minute,
    int *second
)
{
    static const size_t read_limit = 256U * 1024U;
    static const unsigned char exif_magic[] = { 'E', 'x', 'i', 'f', 0x00U, 0x00U };
    FILE *file = NULL;
    unsigned char *buffer = NULL;
    size_t got = 0U;
    int ok = 0;
    size_t i;

    if (path == NULL ||
        year == NULL || month == NULL || day == NULL ||
        hour == NULL || minute == NULL || second == NULL) {
        return 0;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }

    buffer = (unsigned char *)malloc(read_limit);
    if (buffer == NULL) {
        fclose(file);
        return 0;
    }

    got = fread(buffer, 1, read_limit, file);
    fclose(file);
    file = NULL;

    for (i = 0; i + sizeof(exif_magic) <= got; i++) {
        if (memcmp(buffer + i, exif_magic, sizeof(exif_magic)) == 0) {
            ok = parse_exif_ascii_timestamp_local(
                buffer + i + sizeof(exif_magic),
                got - (i + sizeof(exif_magic)),
                year,
                month,
                day,
                hour,
                minute,
                second
            );
            if (ok) {
                break;
            }
        }
    }

    if (!ok) {
        ok = parse_exif_ascii_timestamp_local(
            buffer,
            got,
            year,
            month,
            day,
            hour,
            minute,
            second
        );
    }

    free(buffer);
    return ok;
}

static int64_t days_from_civil_local(int year, int month, int day)
{
    year -= month <= 2;
    {
        const int era = (year >= 0 ? year : year - 399) / 400;
        const unsigned yoe = (unsigned)(year - era * 400);
        const unsigned doy = (153U * (unsigned)(month + (month > 2 ? -3 : 9)) + 2U) / 5U +
                             (unsigned)day - 1U;
        const unsigned doe = yoe * 365U + yoe / 4U - yoe / 100U + doy;

        return (int64_t)era * 146097LL + (int64_t)doe - 719468LL;
    }
}

static int64_t timestamp_to_unix_like_local(
    int year,
    int month,
    int day,
    int hour,
    int minute,
    int second
)
{
    return days_from_civil_local(year, month, day) * 86400LL +
           (int64_t)hour * 3600LL +
           (int64_t)minute * 60LL +
           (int64_t)second;
}

static const char *find_recovered_deleted_marker_local(
    const char *path,
    size_t *out_marker_length
)
{
    static const char deleted_marker[] =
        "/" APP_RECOVERED_DIR_NAME "/" APP_DELETED_DIR_NAME "/";
    static const char legacy_deleted_marker[] =
        "/" APP_RECOVERED_DIR_NAME "/deleted/";
    const char *found;

    if (out_marker_length != NULL) {
        *out_marker_length = 0U;
    }
    if (path == NULL) {
        return NULL;
    }

    found = strstr(path, deleted_marker);
    if (found != NULL) {
        if (out_marker_length != NULL) {
            *out_marker_length = strlen(deleted_marker);
        }
        return found;
    }

    found = strstr(path, legacy_deleted_marker);
    if (found != NULL && out_marker_length != NULL) {
        *out_marker_length = strlen(legacy_deleted_marker);
    }
    return found;
}

static int path_is_under_recovered_deleted_local(const char *path)
{
    return find_recovered_deleted_marker_local(path, NULL) != NULL;
}

static int build_deleted_tagged_output_path_local(
    const char *current_path,
    const char *tag_name,
    char *out,
    size_t out_size
)
{
    const char *found;
    size_t marker_length = 0U;
    size_t prefix_len;

    if (current_path == NULL || tag_name == NULL || tag_name[0] == '\0' ||
        out == NULL || out_size == 0U) {
        return 0;
    }

    found = find_recovered_deleted_marker_local(current_path, &marker_length);
    if (found == NULL) {
        return 0;
    }

    prefix_len = (size_t)(found - current_path) + marker_length;
    if (prefix_len + strlen(tag_name) + 1U + strlen(found + marker_length) + 1U > out_size) {
        return 0;
    }

    memcpy(out, current_path, prefix_len);
    out[prefix_len] = '\0';
    strncat(out, tag_name, out_size - strlen(out) - 1U);
    strncat(out, "/", out_size - strlen(out) - 1U);
    strncat(out, found + marker_length, out_size - strlen(out) - 1U);
    return 1;
}

static int ensure_unique_tagged_path_local(char *path, size_t path_size, const char *suffix_tag)
{
    char candidate[PATH_MAX_LEN];
    const char *base;
    const char *dot;
    size_t dir_len;
    size_t stem_len;
    int i;

    if (path == NULL || path[0] == '\0' || path_size == 0U ||
        suffix_tag == NULL || suffix_tag[0] == '\0' ||
        !path_exists_local(path)) {
        return 1;
    }

    base = strrchr(path, '/');
    base = base != NULL ? base + 1 : path;
    dot = strrchr(base, '.');
    dir_len = (size_t)(base - path);
    stem_len = dot != NULL ? (size_t)(dot - base) : strlen(base);

    for (i = 1; i < 10000; i++) {
        int written;

        written = snprintf(
            candidate,
            sizeof(candidate),
            "%.*s%.*s_%s_%d%s",
            (int)dir_len,
            path,
            (int)stem_len,
            base,
            suffix_tag,
            i,
            dot != NULL ? dot : ""
        );
        if (written <= 0 || (size_t)written >= sizeof(candidate)) {
            return 0;
        }
        if (!path_exists_local(candidate)) {
            copy_text_truncated_local(path, path_size, candidate);
            return 1;
        }
    }

    return 0;
}

static int deleted_jpeg_header_looks_plausible_local(
    const unsigned char *buffer,
    size_t len
)
{
    size_t pos;
    int saw_sof = 0;
    int saw_sos = 0;

    if (buffer == NULL || len < 4U || buffer[0] != 0xFFU || buffer[1] != 0xD8U) {
        return 0;
    }

    pos = 2U;
    while (pos + 3U < len) {
        uint8_t marker;
        uint16_t seg_len;

        while (pos < len && buffer[pos] != 0xFFU) {
            pos++;
        }
        while (pos < len && buffer[pos] == 0xFFU) {
            pos++;
        }
        if (pos >= len) {
            break;
        }

        marker = buffer[pos++];
        if (marker == 0xD9U || marker == 0xDAU) {
            if (marker == 0xDAU) {
                saw_sos = 1;
            }
            break;
        }
        if (marker == 0x01U || (marker >= 0xD0U && marker <= 0xD7U)) {
            return 0;
        }
        if (pos + 1U >= len) {
            break;
        }

        seg_len = (uint16_t)(((uint16_t)buffer[pos] << 8) | (uint16_t)buffer[pos + 1U]);
        if (seg_len < 2U || pos + seg_len > len) {
            break;
        }

        if ((marker >= 0xC0U && marker <= 0xC3U) ||
            (marker >= 0xC5U && marker <= 0xC7U) ||
            (marker >= 0xC9U && marker <= 0xCBU) ||
            (marker >= 0xCDU && marker <= 0xCFU)) {
            uint16_t height;
            uint16_t width;

            if (seg_len < 7U) {
                return 0;
            }
            height = (uint16_t)(((uint16_t)buffer[pos + 3U] << 8) | (uint16_t)buffer[pos + 4U]);
            width = (uint16_t)(((uint16_t)buffer[pos + 5U] << 8) | (uint16_t)buffer[pos + 6U]);
            if (height == 0U || width == 0U ||
                height > 20000U || width > 20000U) {
                return 0;
            }
            saw_sof = 1;
        }

        pos += seg_len;

        if (pos > 262144U && !saw_sos) {
            return 0;
        }
    }

    return saw_sof && saw_sos;
}

static time_t filetime_to_unix_time_local(uint64_t filetime)
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

static int deleted_jpeg_should_be_marked_damaged_local(const RecoveryTarget *target)
{
    unsigned char header[512U * 1024U];
    FILE *fp;
    size_t read_bytes;

    if (target == NULL ||
        target->output_path[0] == '\0' ||
        !(streq_ci(target->extension, "jpg") || streq_ci(target->extension, "jpeg")) ||
        !path_is_under_recovered_deleted_local(target->output_path)) {
        return 0;
    }

    fp = fopen(target->output_path, "rb");
    if (fp == NULL) {
        return 0;
    }
    read_bytes = fread(header, 1U, sizeof(header), fp);
    fclose(fp);

    if (read_bytes < 4U) {
        return 1;
    }

    return !deleted_jpeg_header_looks_plausible_local(header, read_bytes);
}

static MFTPROBE_MAYBE_UNUSED int deleted_jpeg_should_be_marked_unsure_local(const RecoveryTarget *target)
{
    int name_year, name_month, name_day, name_hour, name_minute, name_second;
    int exif_year, exif_month, exif_day, exif_hour, exif_minute, exif_second;
    int64_t filename_stamp;
    int64_t exif_stamp;
    int64_t delta;

    if (target == NULL ||
        target->output_path[0] == '\0' ||
        !(streq_ci(target->extension, "jpg") || streq_ci(target->extension, "jpeg")) ||
        !path_is_under_recovered_deleted_local(target->output_path)) {
        return 0;
    }

    if (!parse_camera_timestamp_from_filename_local(
            target->output_path,
            &name_year,
            &name_month,
            &name_day,
            &name_hour,
            &name_minute,
            &name_second)) {
        return 0;
    }
    if (!read_deleted_jpeg_exif_timestamp_local(
            target->output_path,
            &exif_year,
            &exif_month,
            &exif_day,
            &exif_hour,
            &exif_minute,
            &exif_second)) {
        return 0;
    }

    filename_stamp = timestamp_to_unix_like_local(
        name_year, name_month, name_day, name_hour, name_minute, name_second);
    exif_stamp = timestamp_to_unix_like_local(
        exif_year, exif_month, exif_day, exif_hour, exif_minute, exif_second);
    delta = filename_stamp - exif_stamp;
    if (delta < 0) {
        delta = -delta;
    }

    return name_year != exif_year || delta > 30LL * 86400LL;
}

static int maybe_relocate_deleted_jpeg_to_unsure_local(RecoveryTarget *target)
{
    char tagged_path[PATH_MAX_LEN];

    if (!deleted_jpeg_should_be_marked_damaged_local(target)) {
        return 0;
    }
    if (!build_deleted_tagged_output_path_local(
            target->output_path,
            "_unsure",
            tagged_path,
            sizeof(tagged_path))) {
        return 0;
    }
    if (!ensure_unique_tagged_path_local(tagged_path, sizeof(tagged_path), "unsure")) {
        return 0;
    }
    if (!ensure_parent_dirs(tagged_path)) {
        return 0;
    }
    if (rename(target->output_path, tagged_path) != 0) {
        return 0;
    }

    copy_text_truncated_local(target->output_path, sizeof(target->output_path), tagged_path);
    return 1;
}

static void join_path(char *out, size_t out_size, const char *dir, const char *name)
{
    size_t dir_len;
    size_t name_len;
    size_t copy_len;
    size_t pos = 0;

    if (out == NULL || out_size == 0) {
        return;
    }

    out[0] = '\0';
    if (dir == NULL) {
        dir = "";
    }
    if (name == NULL) {
        name = "";
    }

    dir_len = strlen(dir);
    name_len = strlen(name);

    copy_len = dir_len;
    if (copy_len >= out_size) {
        copy_len = out_size - 1U;
    }
    if (copy_len > 0) {
        memcpy(out, dir, copy_len);
        pos = copy_len;
    }

    if (pos + 1U < out_size) {
        out[pos++] = '/';
    }

    copy_len = name_len;
    if (copy_len > out_size - pos - 1U) {
        copy_len = out_size - pos - 1U;
    }
    if (copy_len > 0) {
        memcpy(out + pos, name, copy_len);
        pos += copy_len;
    }

    out[pos] = '\0';
}

static void sanitize_id(char *text)
{
    size_t i;

    if (text == NULL) {
        return;
    }

    for (i = 0; text[i] != '\0'; i++) {
        unsigned char ch = (unsigned char)text[i];

        if (!(isalnum(ch) || ch == '_' || ch == '-' || ch == '.')) {
            text[i] = '_';
        }
    }
}

static void unlink_out_file(const char *dir, const char *name)
{
    char path[PATH_MAX_LEN];

    join_path(path, sizeof(path), dir, name);
    unlink(path);
}

static void recovery_output_path_from_mft_path(
    char *out,
    size_t out_size,
    const char *out_dir,
    const char *mft_path
)
{
    size_t out_len;
    const char *src;
    char segment[256];
    size_t seg_len = 0;

    if (out == NULL || out_size == 0) {
        return;
    }

    out[0] = '\0';
    if (out_dir == NULL || out_dir[0] == '\0') {
        out_dir = APP_DEFAULT_OUTPUT_DIR;
    }

    snprintf(out, out_size, "%s/" APP_RECOVERED_DIR_NAME, out_dir);
    out_len = strlen(out);
    if (out_len + 1 < out_size && out_len > 0 && out[out_len - 1U] != '/') {
        out[out_len++] = '/';
        out[out_len] = '\0';
    }

    #define APPEND_VISIBLE_SEGMENT(seg_text) do { \
        size_t _i; \
        for (_i = 0; (seg_text)[_i] != '\0' && out_len + 1U < out_size; _i++) { \
            char _ch = (seg_text)[_i]; \
            if (_ch == '$') { \
                _ch = '_'; \
            } \
            out[out_len++] = _ch; \
        } \
        out[out_len] = '\0'; \
    } while (0)

    src = mft_path;
    if (src != NULL && *src == '\\') {
        src++;
    }

    while (src != NULL && *src != '\0') {
        char ch = (*src == '\\') ? '/' : *src;

        if (ch == '/') {
            const char *visible = segment;
            size_t visible_len;

            if (seg_len > 0) {
                segment[seg_len] = '\0';
                visible = mft_visible_windows_component_name(segment);
                visible_len = strlen(visible);
                if (out_len + visible_len + 2U >= out_size) {
                    out[0] = '\0';
                    return;
                }
                APPEND_VISIBLE_SEGMENT(visible);
                seg_len = 0;
            }
            if (out_len > 0 && out[out_len - 1U] != '/') {
                out[out_len++] = '/';
                out[out_len] = '\0';
            }
        } else if (seg_len + 1U < sizeof(segment)) {
            segment[seg_len++] = ch;
        }
        src++;
    }

    if (seg_len > 0) {
        const char *visible = segment;
        size_t visible_len;

        segment[seg_len] = '\0';
        visible = mft_visible_windows_component_name(segment);
        visible_len = strlen(visible);
        if (out_len + visible_len + 1U >= out_size) {
            out[0] = '\0';
            return;
        }
        APPEND_VISIBLE_SEGMENT(visible);
    }

    #undef APPEND_VISIBLE_SEGMENT
}

static void remove_legacy_text_outputs(const char *out_dir)
{
    unlink_out_file(out_dir, "mft_map.tsv");
    unlink_out_file(out_dir, "mapptrad.txt");
    unlink_out_file(out_dir, "stats.txt");
    unlink_out_file(out_dir, "users_jpeg_files.tsv");
}

static int ascii_tolower(int c)
{
    return (c >= 'A' && c <= 'Z') ? c - 'A' + 'a' : c;
}

static int streq_ci(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        if (ascii_tolower((unsigned char)*a) != ascii_tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int ntfs_geometry_contains_offset(const NtfsGeometry *geometry, uint64_t offset)
{
    if (geometry == NULL || !geometry->valid) {
        return 0;
    }
    if (offset < geometry->volume_offset) {
        return 0;
    }
    if (geometry->volume_size == 0) {
        return 1;
    }
    return offset < geometry->volume_offset + geometry->volume_size;
}

static const NtfsGeometry *find_ntfs_geometry_for_record(
    const Config *config,
    uint64_t record_offset
)
{
    const NtfsGeometry *best = NULL;
    size_t i;

    if (config == NULL) {
        return NULL;
    }

    for (i = 0; i < config->ntfs_volume_count; i++) {
        const NtfsGeometry *candidate = &config->ntfs_volumes[i];

        if (!ntfs_geometry_contains_offset(candidate, record_offset)) {
            continue;
        }
        if (best == NULL ||
            (candidate->volume_size > 0 &&
             (best->volume_size == 0 || candidate->volume_size < best->volume_size))) {
            best = candidate;
        }
    }

    return best;
}

static void assign_entry_volume(const Config *config, MftEntry *entry)
{
    const NtfsGeometry *geometry;
    size_t i;

    if (entry == NULL) {
        return;
    }

    if (entry->volume_index != MFT_VOLUME_INDEX_NONE &&
        entry->volume_cluster_size > 0) {
        return;
    }

    geometry = find_ntfs_geometry_for_record(config, entry->offset);
    if (geometry == NULL) {
        entry->volume_index = MFT_VOLUME_INDEX_NONE;
        entry->volume_offset = 0;
        entry->volume_size = 0;
        entry->volume_cluster_size = 0;
        entry->volume_serial = 0;
        return;
    }

    entry->volume_index = MFT_VOLUME_INDEX_NONE;
    if (config != NULL) {
        for (i = 0; i < config->ntfs_volume_count; i++) {
            if (&config->ntfs_volumes[i] == geometry) {
                entry->volume_index = (uint32_t)i;
                break;
            }
        }
    }
    entry->volume_offset = geometry->volume_offset;
    entry->volume_size = geometry->volume_size;
    entry->volume_cluster_size = geometry->cluster_size;
    entry->volume_serial = geometry->volume_serial;
}

static int entry_has_assigned_volume(const MftEntry *entry)
{
    return entry != NULL &&
           entry->volume_index != MFT_VOLUME_INDEX_NONE &&
           entry->volume_cluster_size > 0;
}

static uint64_t mft_data_offset_for_entry(const Config *config, const MftEntry *entry)
{
    const NtfsGeometry *geometry;

    if (entry == NULL) {
        return 0;
    }
    if (entry->resident) {
        if (entry->data_offset < 0) {
            return 0;
        }
        return entry->offset + (uint64_t)entry->data_offset;
    }
    if (entry->first_lcn == 0) {
        return 0;
    }

    if (entry_has_assigned_volume(entry)) {
        return entry->volume_offset + entry->first_lcn * entry->volume_cluster_size;
    }

    geometry = find_ntfs_geometry_for_record(config, entry->offset);
    if (geometry == NULL || geometry->cluster_size == 0) {
        return 0;
    }

    return geometry->volume_offset + entry->first_lcn * geometry->cluster_size;
}

static uint64_t mft_run_available_bytes(const Config *config, const MftEntry *entry)
{
    const NtfsGeometry *geometry;
    uint64_t cluster_size;
    uint64_t clusters = 0;
    size_t i;

    if (entry == NULL) {
        return 0;
    }
    if (entry->resident) {
        return entry->data_size;
    }

    if (entry_has_assigned_volume(entry)) {
        cluster_size = entry->volume_cluster_size;
    } else {
        geometry = find_ntfs_geometry_for_record(config, entry->offset);
        if (geometry == NULL || geometry->cluster_size == 0) {
            return 0;
        }
        cluster_size = geometry->cluster_size;
    }

    if (entry->stored_run_count > 0) {
        for (i = 0; i < entry->stored_run_count; i++) {
            clusters += entry->runs[i].clusters;
        }
    } else {
        clusters = entry->run_clusters;
    }

    return clusters * cluster_size;
}

static int recovery_runs_from_entry(
    const Config *config,
    const MftEntry *entry,
    RecoveryRun *runs,
    size_t *run_count,
    int *run_truncated
)
{
    const NtfsGeometry *geometry;
    uint64_t volume_offset;
    uint64_t cluster_size;
    size_t source_run_count;
    size_t i;

    if (run_count != NULL) {
        *run_count = 0;
    }
    if (run_truncated != NULL) {
        *run_truncated = 0;
    }
    if (config == NULL || entry == NULL || runs == NULL || run_count == NULL) {
        return 0;
    }
    if (entry->resident) {
        if (entry->data_offset < 0 || entry->data_size == 0U) {
            return 0;
        }
        runs[0].abs_offset = entry->offset + (uint64_t)entry->data_offset;
        runs[0].byte_length = entry->data_size;
        *run_count = 1;
        return 1;
    }

    if (entry_has_assigned_volume(entry)) {
        volume_offset = entry->volume_offset;
        cluster_size = entry->volume_cluster_size;
    } else {
        geometry = find_ntfs_geometry_for_record(config, entry->offset);
        if (geometry == NULL || geometry->cluster_size == 0) {
            return 0;
        }
        volume_offset = geometry->volume_offset;
        cluster_size = geometry->cluster_size;
    }

    source_run_count = entry->stored_run_count;
    if (source_run_count == 0 && entry->first_lcn > 0 && entry->run_clusters > 0) {
        runs[0].abs_offset = volume_offset + entry->first_lcn * cluster_size;
        runs[0].byte_length = entry->run_clusters * cluster_size;
        *run_count = 1;
        if (run_truncated != NULL) {
            *run_truncated = entry->run_count > 1;
        }
        return 1;
    }

    if (source_run_count > RECOVERY_TARGET_MAX_RUNS) {
        source_run_count = RECOVERY_TARGET_MAX_RUNS;
        if (run_truncated != NULL) {
            *run_truncated = 1;
        }
    }

    for (i = 0; i < source_run_count; i++) {
        if (entry->runs[i].clusters == 0) {
            continue;
        }
        runs[*run_count].abs_offset = volume_offset + entry->runs[i].lcn * cluster_size;
        runs[*run_count].byte_length = entry->runs[i].clusters * cluster_size;
        (*run_count)++;
    }
    if (run_truncated != NULL && entry->run_truncated) {
        *run_truncated = 1;
    }

    return *run_count > 0;
}

static int recovery_runs_within_source(
    const Config *config,
    const RecoveryRun *runs,
    size_t run_count
)
{
    size_t i;

    if (config == NULL || runs == NULL || config->source_size == 0) {
        return 1;
    }
    for (i = 0; i < run_count; i++) {
        if (runs[i].byte_length == 0 ||
            runs[i].abs_offset >= config->source_size ||
            runs[i].byte_length > config->source_size - runs[i].abs_offset) {
            return 0;
        }
    }
    return 1;
}

static int entry_is_generic_file_candidate(
    const Config *config,
    const MftEntry *entry
)
{
    if (config == NULL || !config->generic_file_targets || entry == NULL) {
        return 0;
    }
    if (!entry->has_data ||
        entry->data_size == 0U ||
        entry->name[0] == '\0' ||
        entry->name[0] == '$' ||
        (entry->flags & 0x0002U) != 0U) {
        return 0;
    }
    return mftprobe_format_select_for_entry(config, entry) == NULL;
}

static int entry_needed_for_live_index(const Config *config, const MftEntry *entry)
{
    if (entry == NULL || entry->name[0] == '\0') {
        return 0;
    }

    return (entry->flags & 0x0002U) ||
           mftprobe_format_select_for_entry(config, entry) != NULL ||
           entry_is_generic_file_candidate(config, entry);
}

static int entry_needed_for_binary_snapshot_with_root_scope(
    const Config *config,
    const MftEntry *entry,
    RootScopePrunedSet *pruned_set
)
{
    if (entry == NULL || entry->name[0] == '\0') {
        return 0;
    }

    if (config == NULL || config->root_scope_count == 0) {
        return 1;
    }

    return !root_scope_prune_entry_for_live_scan(config, entry, pruned_set);
}

static RecordIndex *build_record_index(const MftEntry *items, size_t count);

static void table_mark_record_index_dirty(MftTable *table)
{
    if (table == NULL) {
        return;
    }

    table->record_index_dirty = 1;
}

static int table_ensure_record_index(MftTable *table)
{
    RecordIndex *rebuilt = NULL;

    if (table == NULL) {
        return 0;
    }

    if (table->count == 0U || table->items == NULL) {
        free(table->record_index);
        table->record_index = NULL;
        table->record_index_count = 0U;
        table->record_index_dirty = 0;
        return 1;
    }

    if (!table->record_index_dirty &&
        table->record_index != NULL &&
        table->record_index_count == table->count) {
        return 1;
    }

    rebuilt = build_record_index(table->items, table->count);
    if (table->count > 0U && rebuilt == NULL) {
        return 0;
    }

    free(table->record_index);
    table->record_index = rebuilt;
    table->record_index_count = rebuilt != NULL ? table->count : 0U;
    table->record_index_dirty = 0;
    return 1;
}

static int table_append(MftTable *table, const MftEntry *entry)
{
    MftEntry *new_items;

    if (table->count == table->capacity) {
        size_t new_capacity = table->capacity == 0 ? 4096U : table->capacity * 2U;
        new_items = (MftEntry *)realloc(table->items, new_capacity * sizeof(*new_items));
        if (new_items == NULL) {
            return 0;
        }
        table->items = new_items;
        table->capacity = new_capacity;
    }

    table->items[table->count++] = *entry;
    table_mark_record_index_dirty(table);
    return 1;
}

static void table_reset(MftTable *table)
{
    if (table == NULL) {
        return;
    }

    free(table->items);
    free(table->record_index);
    table->items = NULL;
    table->record_index = NULL;
    table->count = 0;
    table->capacity = 0;
    table->record_index_count = 0U;
    table->record_index_dirty = 0;
}

static int queue_init(MftCandidateQueue *queue, size_t capacity)
{
    memset(queue, 0, sizeof(*queue));
    queue->items = (MftCandidate *)malloc(capacity * sizeof(*queue->items));
    if (queue->items == NULL) {
        return 0;
    }
    queue->capacity = capacity;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    return 1;
}

static void queue_destroy(MftCandidateQueue *queue)
{
    free(queue->items);
    pthread_cond_destroy(&queue->not_full);
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->mutex);
}

static int queue_push(MftCandidateQueue *queue, const MftCandidate *candidate)
{
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == queue->capacity && !queue->done && !stop_requested()) {
        cond_wait_briefly(&queue->not_full, &queue->mutex);
    }
    if (queue->done || stop_requested()) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    queue->items[queue->tail] = *candidate;
    queue->tail = (queue->tail + 1U) % queue->capacity;
    queue->count++;
    if (queue->count > queue->max_count) {
        queue->max_count = queue->count;
    }
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

static int queue_pop(MftCandidateQueue *queue, MftCandidate *candidate)
{
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0 && !queue->done && !stop_requested()) {
        cond_wait_briefly(&queue->not_empty, &queue->mutex);
    }
    if (queue->count == 0 && (queue->done || stop_requested())) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    *candidate = queue->items[queue->head];
    queue->head = (queue->head + 1U) % queue->capacity;
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

static void queue_finish(MftCandidateQueue *queue)
{
    pthread_mutex_lock(&queue->mutex);
    queue->done = 1;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
}

static int event_queue_init(MftEventQueue *queue, size_t capacity)
{
    memset(queue, 0, sizeof(*queue));
    queue->items = (MftEvent *)malloc(capacity * sizeof(*queue->items));
    if (queue->items == NULL) {
        return 0;
    }
    queue->capacity = capacity;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    return 1;
}

static void event_queue_destroy(MftEventQueue *queue)
{
    free(queue->items);
    pthread_cond_destroy(&queue->not_full);
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->mutex);
}

static int event_queue_push(MftEventQueue *queue, const MftEvent *event)
{
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == queue->capacity && !queue->done && !stop_requested()) {
        cond_wait_briefly(&queue->not_full, &queue->mutex);
    }
    if (queue->done || stop_requested()) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    queue->items[queue->tail] = *event;
    queue->tail = (queue->tail + 1U) % queue->capacity;
    queue->count++;
    if (queue->count > queue->max_count) {
        queue->max_count = queue->count;
    }
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

static int event_queue_pop(MftEventQueue *queue, MftEvent *event)
{
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0 && !queue->done && !stop_requested()) {
        cond_wait_briefly(&queue->not_empty, &queue->mutex);
    }
    if (queue->count == 0 && (queue->done || stop_requested())) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    *event = queue->items[queue->head];
    queue->head = (queue->head + 1U) % queue->capacity;
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

static void event_queue_finish(MftEventQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    pthread_mutex_lock(&queue->mutex);
    queue->done = 1;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
}

static int read_block_queue_init(ReadBlockQueue *queue, size_t capacity)
{
    memset(queue, 0, sizeof(*queue));
    queue->items = (ReadBlock *)calloc(capacity, sizeof(*queue->items));
    if (queue->items == NULL) {
        return 0;
    }
    queue->capacity = capacity;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    return 1;
}

static void read_block_queue_destroy(ReadBlockQueue *queue)
{
    size_t i;

    if (queue == NULL) {
        return;
    }
    for (i = 0; i < queue->capacity; i++) {
        free(queue->items[i].data);
        queue->items[i].data = NULL;
    }
    free(queue->items);
    pthread_cond_destroy(&queue->not_full);
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->mutex);
}

static int read_block_queue_push(ReadBlockQueue *queue, ReadBlock *block)
{
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == queue->capacity && !queue->done && !stop_requested()) {
        cond_wait_briefly(&queue->not_full, &queue->mutex);
    }
    if (queue->done || stop_requested()) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    queue->items[queue->tail] = *block;
    block->data = NULL;
    block->length = 0;
    queue->tail = (queue->tail + 1U) % queue->capacity;
    queue->count++;
    if (queue->count > queue->max_count) {
        queue->max_count = queue->count;
    }
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

static int read_block_queue_pop(ReadBlockQueue *queue, ReadBlock *block)
{
    pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0 && !queue->done && !stop_requested()) {
        cond_wait_briefly(&queue->not_empty, &queue->mutex);
    }
    if (queue->count == 0 && (queue->done || stop_requested())) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    *block = queue->items[queue->head];
    memset(&queue->items[queue->head], 0, sizeof(queue->items[queue->head]));
    queue->head = (queue->head + 1U) % queue->capacity;
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

static void read_block_queue_finish(ReadBlockQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    pthread_mutex_lock(&queue->mutex);
    queue->done = 1;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
}

static void recovery_write_job_clear(RecoveryWriteJob *job)
{
    if (job == NULL) {
        return;
    }
    free(job->data);
    memset(job, 0, sizeof(*job));
}

static int recovery_write_queue_init(RecoveryWriteQueue *queue, size_t capacity)
{
    memset(queue, 0, sizeof(*queue));
    queue->items = (RecoveryWriteJob *)calloc(capacity, sizeof(*queue->items));
    if (queue->items == NULL) {
        return 0;
    }
    queue->capacity = capacity;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
    return 1;
}

static void recovery_write_queue_destroy(RecoveryWriteQueue *queue)
{
    size_t i;

    if (queue == NULL) {
        return;
    }
    for (i = 0; i < queue->capacity; i++) {
        recovery_write_job_clear(&queue->items[i]);
    }
    free(queue->items);
    pthread_cond_destroy(&queue->not_full);
    pthread_cond_destroy(&queue->not_empty);
    pthread_mutex_destroy(&queue->mutex);
}

static int recovery_write_queue_push(RecoveryWriteQueue *queue, RecoveryWriteJob *job)
{
    if (queue == NULL || job == NULL) {
        return 0;
    }

    pthread_mutex_lock(&queue->mutex);
    while (queue->count == queue->capacity && !queue->done && !stop_requested()) {
        cond_wait_briefly(&queue->not_full, &queue->mutex);
    }
    if (queue->done || stop_requested()) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    queue->items[queue->tail] = *job;
    memset(job, 0, sizeof(*job));
    queue->tail = (queue->tail + 1U) % queue->capacity;
    queue->count++;
    if (queue->count > queue->max_count) {
        queue->max_count = queue->count;
    }
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

static int recovery_write_queue_pop(RecoveryWriteQueue *queue, RecoveryWriteJob *job)
{
    if (queue == NULL || job == NULL) {
        return 0;
    }

    pthread_mutex_lock(&queue->mutex);
    while (queue->count == 0 && !queue->done && !stop_requested()) {
        cond_wait_briefly(&queue->not_empty, &queue->mutex);
    }
    if (queue->count == 0 && (queue->done || stop_requested())) {
        pthread_mutex_unlock(&queue->mutex);
        return 0;
    }

    *job = queue->items[queue->head];
    memset(&queue->items[queue->head], 0, sizeof(queue->items[queue->head]));
    queue->head = (queue->head + 1U) % queue->capacity;
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    return 1;
}

static void recovery_write_queue_finish(RecoveryWriteQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    pthread_mutex_lock(&queue->mutex);
    queue->done = 1;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
}

static void read_block_queue_snapshot(
    ReadBlockQueue *queue,
    size_t *out_count,
    size_t *out_capacity
)
{
    if (out_count != NULL) {
        *out_count = 0;
    }
    if (out_capacity != NULL) {
        *out_capacity = 0;
    }
    if (queue == NULL) {
        return;
    }

    pthread_mutex_lock(&queue->mutex);
    if (out_count != NULL) {
        *out_count = queue->count;
    }
    if (out_capacity != NULL) {
        *out_capacity = queue->capacity;
    }
    pthread_mutex_unlock(&queue->mutex);
}

static void candidate_queue_snapshot(
    MftCandidateQueue *queue,
    size_t *out_count,
    size_t *out_capacity
)
{
    if (out_count != NULL) {
        *out_count = 0;
    }
    if (out_capacity != NULL) {
        *out_capacity = 0;
    }
    if (queue == NULL) {
        return;
    }

    pthread_mutex_lock(&queue->mutex);
    if (out_count != NULL) {
        *out_count = queue->count;
    }
    if (out_capacity != NULL) {
        *out_capacity = queue->capacity;
    }
    pthread_mutex_unlock(&queue->mutex);
}

static void event_queue_snapshot(
    MftEventQueue *queue,
    size_t *out_count,
    size_t *out_capacity
)
{
    if (out_count != NULL) {
        *out_count = 0;
    }
    if (out_capacity != NULL) {
        *out_capacity = 0;
    }
    if (queue == NULL) {
        return;
    }

    pthread_mutex_lock(&queue->mutex);
    if (out_count != NULL) {
        *out_count = queue->count;
    }
    if (out_capacity != NULL) {
        *out_capacity = queue->capacity;
    }
    pthread_mutex_unlock(&queue->mutex);
}

static void recovery_write_queue_snapshot(
    RecoveryWriteQueue *queue,
    size_t *out_count,
    size_t *out_capacity
)
{
    if (out_count != NULL) {
        *out_count = 0;
    }
    if (out_capacity != NULL) {
        *out_capacity = 0;
    }
    if (queue == NULL) {
        return;
    }

    pthread_mutex_lock(&queue->mutex);
    if (out_count != NULL) {
        *out_count = queue->count;
    }
    if (out_capacity != NULL) {
        *out_capacity = queue->capacity;
    }
    pthread_mutex_unlock(&queue->mutex);
}

static void users_worker_snapshot(
    UsersWorker *worker,
    size_t *out_last_written_count,
    int *out_refresh_requested
)
{
    if (out_last_written_count != NULL) {
        *out_last_written_count = 0;
    }
    if (out_refresh_requested != NULL) {
        *out_refresh_requested = 0;
    }
    if (worker == NULL) {
        return;
    }

    pthread_mutex_lock(&worker->mutex);
    if (out_last_written_count != NULL) {
        *out_last_written_count = worker->last_written_count;
    }
    if (out_refresh_requested != NULL) {
        *out_refresh_requested = worker->refresh_requested;
    }
    pthread_mutex_unlock(&worker->mutex);
}

static int write_thread_activity_state(const ThreadActivityStateContext *context)
{
    char path[PATH_MAX_LEN];
    char temp_path[PATH_MAX_LEN];
    FILE *file;
    size_t read_queue_count = 0;
    size_t read_queue_capacity = 0;
    size_t mft_queue_count = 0;
    size_t mft_queue_capacity = 0;
    size_t bin_queue_count = 0;
    size_t bin_queue_capacity = 0;
    size_t live_queue_count = 0;
    size_t live_queue_capacity = 0;
    size_t write_queue_count = 0;
    size_t write_queue_capacity = 0;
    size_t table_count = 0;
    size_t recovery_plan_count = 0;
    size_t recovery_plan_recovered = 0;
    size_t users_last_written = 0;
    int users_refresh_requested = 0;

    if (context == NULL || context->config == NULL || context->config->out_dir == NULL) {
        return 0;
    }

    read_block_queue_snapshot(context->read_queue, &read_queue_count, &read_queue_capacity);
    candidate_queue_snapshot(context->mft_queue, &mft_queue_count, &mft_queue_capacity);
    event_queue_snapshot(context->bin_queue, &bin_queue_count, &bin_queue_capacity);
    event_queue_snapshot(context->live_queue, &live_queue_count, &live_queue_capacity);
    recovery_write_queue_snapshot(context->write_queue, &write_queue_count, &write_queue_capacity);
    users_worker_snapshot(
        context->users_worker,
        &users_last_written,
        &users_refresh_requested
    );

    if (context->table != NULL) {
        pthread_mutex_lock(&context->table->mutex);
        table_count = context->table->count;
        pthread_mutex_unlock(&context->table->mutex);
    }
    if (context->recovery_plan != NULL) {
        pthread_mutex_lock(&context->recovery_plan->mutex);
        recovery_plan_count = context->recovery_plan->count;
        recovery_plan_recovered = context->recovery_plan->recovered;
        pthread_mutex_unlock(&context->recovery_plan->mutex);
    }

    join_path(
        path,
        sizeof(path),
        context->config->out_dir,
        APP_STATE_DIR_NAME "/thread_activity.txt");
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >= (int)sizeof(temp_path)) {
        return 0;
    }
    if (!ensure_parent_dirs(path)) {
        return 0;
    }

    file = fopen(temp_path, "w");
    if (file == NULL) {
        return 0;
    }

    fprintf(file, "version=1\n");
    fprintf(file, "mode=folders\n");
    fprintf(file, "updated_unix=%llu\n", (unsigned long long)time(NULL));

    fprintf(file, "read_queue.count=%zu\n", read_queue_count);
    fprintf(file, "read_queue.capacity=%zu\n", read_queue_capacity);
    fprintf(file, "mft_queue.count=%zu\n", mft_queue_count);
    fprintf(file, "mft_queue.capacity=%zu\n", mft_queue_capacity);
    fprintf(file, "bin_queue.count=%zu\n", bin_queue_count);
    fprintf(file, "bin_queue.capacity=%zu\n", bin_queue_capacity);
    fprintf(file, "live_queue.count=%zu\n", live_queue_count);
    fprintf(file, "live_queue.capacity=%zu\n", live_queue_capacity);
    fprintf(file, "write_queue.count=%zu\n", write_queue_count);
    fprintf(file, "write_queue.capacity=%zu\n", write_queue_capacity);
    fprintf(file, "table.count=%zu\n", table_count);
    fprintf(file, "recovery_plan.count=%zu\n", recovery_plan_count);
    fprintf(file, "recovery_plan.recovered=%zu\n", recovery_plan_recovered);

    fprintf(
        file,
        "prefix.blocks_processed=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->prefix_worker->blocks_processed)
    );
    fprintf(
        file,
        "prefix.bytes_processed=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->prefix_worker->bytes_processed)
    );
    fprintf(
        file,
        "sieve.raw_records=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->sieve_worker->raw_records)
    );
    fprintf(
        file,
        "sieve.accepted_records=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->sieve_worker->accepted_records)
    );
    fprintf(
        file,
        "bin.rows_written=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->bin_writer_worker->rows_written)
    );
    fprintf(
        file,
        "live.selected_candidates_seen=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->live_index_worker->selected_candidates_seen)
    );
    fprintf(
        file,
        "live.path_ready_candidates=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->live_index_worker->path_ready_candidates)
    );
    fprintf(
        file,
        "live.targets_attempted=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->live_index_worker->targets_attempted)
    );
    fprintf(
        file,
        "live.targets_appended=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->live_index_worker->targets_appended)
    );
    fprintf(
        file,
        "live.pending_waits_created=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->live_index_worker->pending_waits_created)
    );
    fprintf(
        file,
        "live.pending_remaining=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->live_index_worker->pending_remaining)
    );
    fprintf(
        file,
        "recovery.jobs_completed=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->recovery_writer_worker->jobs_completed)
    );
    fprintf(
        file,
        "recovery.bytes_written=%llu\n",
        (unsigned long long)ATOMIC_LOAD_U64(&context->recovery_writer_worker->bytes_written)
    );
    fprintf(file, "users.last_written_count=%zu\n", users_last_written);
    fprintf(file, "users.refresh_requested=%d\n", users_refresh_requested);

    if (fclose(file) != 0) {
        unlink(temp_path);
        return 0;
    }
    if (rename(temp_path, path) != 0) {
        unlink(temp_path);
        return 0;
    }
    return 1;
}

static void *thread_activity_writer_worker_main(void *arg)
{
    ThreadActivityWriterWorker *worker = (ThreadActivityWriterWorker *)arg;
    const struct timespec nap = {0, 500000000L};

    block_stop_signals_in_worker();
    worker->ok = 1;

    for (;;) {
        int should_stop = 0;

        pthread_mutex_lock(&worker->mutex);
        should_stop = worker->done;
        pthread_mutex_unlock(&worker->mutex);
        if (should_stop) {
            break;
        }

        if (!write_thread_activity_state(worker->context)) {
            worker->ok = 0;
        }
        nanosleep(&nap, NULL);
    }

    (void)write_thread_activity_state(worker->context);
    return NULL;
}

static uint64_t hash_u64(uint64_t value)
{
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value;
}

static size_t next_power_of_two_size(size_t value)
{
    size_t power = 1;

    while (power < value && power <= (SIZE_MAX / 2U)) {
        power *= 2U;
    }
    return power;
}

static size_t hash_index_capacity_for_count(size_t count)
{
    if (count < 512U) {
        return 1024U;
    }
    if (count > (SIZE_MAX / 2U)) {
        return 0;
    }
    return next_power_of_two_size(count * 2U);
}

static uint64_t hash_string(const char *text)
{
    uint64_t hash = 1469598103934665603ULL;

    if (text == NULL) {
        return hash_u64(0);
    }
    while (*text != '\0') {
        hash ^= (unsigned char)*text;
        hash *= 1099511628211ULL;
        text++;
    }
    return hash_u64(hash);
}

static uint64_t recovery_target_key_hash(
    uint32_t format_id,
    int record,
    uint32_t family,
    uint64_t abs_offset
)
{
    uint64_t value = hash_u64(abs_offset);

    value ^= hash_u64(((uint64_t)format_id << 32) ^ (uint64_t)family);
    value ^= hash_u64((uint64_t)(uint32_t)record);
    return hash_u64(value);
}

static int recovery_target_index_slot_matches(
    const RecoveryTargetIndexSlot *slot,
    uint32_t format_id,
    int record,
    uint32_t family,
    uint64_t abs_offset
)
{
    return slot != NULL &&
           slot->used &&
           slot->format_id == format_id &&
           slot->record == record &&
           slot->family == family &&
           slot->abs_offset == abs_offset;
}

static int recovery_target_index_insert_slot(
    RecoveryTargetIndexSlot *slots,
    size_t capacity,
    const RecoveryTarget *target,
    size_t index,
    int *added
)
{
    uint64_t hash;
    size_t pos;

    if (added != NULL) {
        *added = 0;
    }
    if (slots == NULL || capacity == 0 || target == NULL) {
        return 0;
    }

    hash = recovery_target_key_hash(
        target->format_id,
        target->record,
        target->family,
        target->abs_offset
    );
    pos = (size_t)hash & (capacity - 1U);

    while (slots[pos].used) {
        if (recovery_target_index_slot_matches(
                &slots[pos],
                target->format_id,
                target->record,
                target->family,
                target->abs_offset)) {
            slots[pos].index = index;
            return 1;
        }
        pos = (pos + 1U) & (capacity - 1U);
    }

    slots[pos].used = 1;
    slots[pos].format_id = target->format_id;
    slots[pos].record = target->record;
    slots[pos].family = target->family;
    slots[pos].abs_offset = target->abs_offset;
    slots[pos].index = index;
    if (added != NULL) {
        *added = 1;
    }
    return 1;
}

static int recovery_plan_rebuild_target_index_locked(RecoveryPlan *plan)
{
    RecoveryTargetIndexSlot *slots;
    size_t capacity;
    size_t i;
    size_t inserted = 0;

    if (plan == NULL) {
        return 0;
    }
    if (plan->count == 0) {
        free(plan->target_index_slots);
        plan->target_index_slots = NULL;
        plan->target_index_capacity = 0;
        plan->target_index_count = 0;
        plan->target_index_dirty = 0;
        return 1;
    }

    capacity = hash_index_capacity_for_count(plan->count);
    if (capacity == 0) {
        return 0;
    }
    slots = (RecoveryTargetIndexSlot *)calloc(capacity, sizeof(*slots));
    if (slots == NULL) {
        return 0;
    }

    for (i = 0; i < plan->count; i++) {
        int added = 0;

        if (!recovery_target_index_insert_slot(
                slots,
                capacity,
                &plan->items[i],
                i,
                &added)) {
            free(slots);
            return 0;
        }
        inserted += added ? 1U : 0U;
    }

    free(plan->target_index_slots);
    plan->target_index_slots = slots;
    plan->target_index_capacity = capacity;
    plan->target_index_count = inserted;
    plan->target_index_dirty = 0;
    return 1;
}

static int recovery_plan_ensure_target_index_locked(RecoveryPlan *plan)
{
    if (plan == NULL) {
        return 0;
    }
    if (plan->count == 0) {
        plan->target_index_dirty = 0;
        return 1;
    }
    if (plan->target_index_dirty ||
        plan->target_index_slots == NULL ||
        plan->target_index_capacity == 0 ||
        plan->target_index_count >= plan->target_index_capacity / 2U ||
        plan->target_index_count > plan->count) {
        return recovery_plan_rebuild_target_index_locked(plan);
    }
    return 1;
}

static int recovery_output_index_slot_matches(
    const RecoveryOutputIndexSlot *slot,
    uint32_t format_id,
    uint64_t abs_offset,
    uint64_t path_hash
)
{
    return slot != NULL &&
           slot->used &&
           slot->format_id == format_id &&
           slot->abs_offset == abs_offset &&
           slot->path_hash == path_hash;
}

static int recovery_output_index_insert_slot(
    RecoveryOutputIndexSlot *slots,
    size_t capacity,
    const RecoveryTarget *items,
    size_t item_count,
    const RecoveryTarget *target,
    size_t index,
    int *added
)
{
    uint64_t path_hash;
    uint64_t hash;
    size_t pos;

    if (added != NULL) {
        *added = 0;
    }
    if (slots == NULL || capacity == 0 || items == NULL || target == NULL ||
        target->output_path[0] == '\0') {
        return 0;
    }

    path_hash = hash_string(target->output_path);
    hash = hash_u64(path_hash ^ target->abs_offset ^ ((uint64_t)target->format_id << 32));
    pos = (size_t)hash & (capacity - 1U);

    while (slots[pos].used) {
        if (recovery_output_index_slot_matches(
                &slots[pos],
                target->format_id,
                target->abs_offset,
                path_hash)) {
            size_t existing = slots[pos].index;

            if (existing < item_count &&
                strcmp(items[existing].output_path, target->output_path) == 0) {
                slots[pos].index = index;
                return 1;
            }
        }
        pos = (pos + 1U) & (capacity - 1U);
    }

    slots[pos].used = 1;
    slots[pos].format_id = target->format_id;
    slots[pos].abs_offset = target->abs_offset;
    slots[pos].path_hash = path_hash;
    slots[pos].index = index;
    if (added != NULL) {
        *added = 1;
    }
    return 1;
}

static int recovery_plan_rebuild_output_index_locked(RecoveryPlan *plan)
{
    RecoveryOutputIndexSlot *slots;
    size_t capacity;
    size_t i;
    size_t inserted = 0;

    if (plan == NULL) {
        return 0;
    }
    if (plan->count == 0) {
        free(plan->output_index_slots);
        plan->output_index_slots = NULL;
        plan->output_index_capacity = 0;
        plan->output_index_count = 0;
        plan->output_index_dirty = 0;
        return 1;
    }

    capacity = hash_index_capacity_for_count(plan->count);
    if (capacity == 0) {
        return 0;
    }
    slots = (RecoveryOutputIndexSlot *)calloc(capacity, sizeof(*slots));
    if (slots == NULL) {
        return 0;
    }

    for (i = 0; i < plan->count; i++) {
        int added = 0;

        if (plan->items[i].output_path[0] == '\0') {
            continue;
        }
        if (!recovery_output_index_insert_slot(
                slots,
                capacity,
                plan->items,
                plan->count,
                &plan->items[i],
                i,
                &added)) {
            free(slots);
            return 0;
        }
        inserted += added ? 1U : 0U;
    }

    free(plan->output_index_slots);
    plan->output_index_slots = slots;
    plan->output_index_capacity = capacity;
    plan->output_index_count = inserted;
    plan->output_index_dirty = 0;
    return 1;
}

static int recovery_plan_ensure_output_index_locked(RecoveryPlan *plan)
{
    if (plan == NULL) {
        return 0;
    }
    if (plan->count == 0) {
        plan->output_index_dirty = 0;
        return 1;
    }
    if (plan->output_index_dirty ||
        plan->output_index_slots == NULL ||
        plan->output_index_capacity == 0 ||
        plan->output_index_count >= plan->output_index_capacity / 2U ||
        plan->output_index_count > plan->count) {
        return recovery_plan_rebuild_output_index_locked(plan);
    }
    return 1;
}

static void recovery_plan_mark_indexes_dirty_locked(RecoveryPlan *plan)
{
    if (plan == NULL) {
        return;
    }
    plan->target_index_dirty = 1;
    plan->output_index_dirty = 1;
}

static void recovery_plan_note_target_appended_locked(RecoveryPlan *plan, size_t index)
{
    if (plan == NULL || index >= plan->count) {
        return;
    }

    plan->scheduler_dirty = plan->count > 1 ? 1 : 0;

    if (!plan->target_index_dirty) {
        if (plan->target_index_slots == NULL ||
            plan->target_index_capacity == 0 ||
            plan->target_index_count + 1U >= plan->target_index_capacity / 2U) {
            if (!recovery_plan_rebuild_target_index_locked(plan)) {
                plan->target_index_dirty = 1;
            }
        } else {
            int added = 0;

            if (recovery_target_index_insert_slot(
                    plan->target_index_slots,
                    plan->target_index_capacity,
                    &plan->items[index],
                    index,
                    &added)) {
                plan->target_index_count += added ? 1U : 0U;
            } else {
                plan->target_index_dirty = 1;
            }
        }
    }

    if (!plan->output_index_dirty && plan->items[index].output_path[0] != '\0') {
        if (plan->output_index_slots == NULL ||
            plan->output_index_capacity == 0 ||
            plan->output_index_count + 1U >= plan->output_index_capacity / 2U) {
            if (!recovery_plan_rebuild_output_index_locked(plan)) {
                plan->output_index_dirty = 1;
            }
        } else {
            int added = 0;

            if (recovery_output_index_insert_slot(
                    plan->output_index_slots,
                    plan->output_index_capacity,
                    plan->items,
                    plan->count,
                    &plan->items[index],
                    index,
                    &added)) {
                plan->output_index_count += added ? 1U : 0U;
            } else {
                plan->output_index_dirty = 1;
            }
        }
    }
}

static int offset_seen_before(OffsetSeenSlot *slots, size_t capacity, uint64_t offset)
{
    size_t pos = (size_t)hash_u64(offset) & (capacity - 1U);
    size_t start = pos;

    while (slots[pos].used) {
        if (slots[pos].offset == offset) {
            return 1;
        }
        pos = (pos + 1U) & (capacity - 1U);
        if (pos == start) {
            return 0;
        }
    }

    slots[pos].used = 1;
    slots[pos].offset = offset;
    return 0;
}

static int offset_set_init(OffsetSet *set, size_t expected_entries)
{
    size_t capacity;

    if (set == NULL) {
        return 0;
    }

    memset(set, 0, sizeof(*set));
    capacity = next_power_of_two_size(expected_entries < 1024U ? 1024U : expected_entries * 4U);
    set->slots = (OffsetSeenSlot *)calloc(capacity, sizeof(*set->slots));
    if (set->slots == NULL) {
        return 0;
    }
    set->capacity = capacity;
    return 1;
}

static void offset_set_destroy(OffsetSet *set)
{
    if (set == NULL) {
        return;
    }

    free(set->slots);
    memset(set, 0, sizeof(*set));
}

static int offset_set_add(OffsetSet *set, uint64_t offset)
{
    int seen;

    if (set == NULL || set->slots == NULL || set->capacity == 0) {
        return 1;
    }

    seen = offset_seen_before(set->slots, set->capacity, offset);
    if (!seen) {
        set->count++;
        if (offset > set->max_offset) {
            set->max_offset = offset;
        }
    }
    return !seen;
}

static int offset_set_contains(OffsetSet *set, uint64_t offset)
{
    size_t pos;
    size_t start;

    if (set == NULL || set->slots == NULL || set->capacity == 0) {
        return 0;
    }

    pos = (size_t)hash_u64(offset) & (set->capacity - 1U);
    start = pos;

    while (set->slots[pos].used) {
        if (set->slots[pos].offset == offset) {
            return 1;
        }
        pos = (pos + 1U) & (set->capacity - 1U);
        if (pos == start) {
            return 0;
        }
    }

    return 0;
}

static int record_seen_before(RecordSeenSlot *slots, size_t capacity, int record)
{
    size_t pos = (size_t)hash_u64((uint64_t)(uint32_t)record) & (capacity - 1U);
    size_t start = pos;

    while (slots[pos].used) {
        if (slots[pos].record == record) {
            return 1;
        }
        pos = (pos + 1U) & (capacity - 1U);
        if (pos == start) {
            return 0;
        }
    }

    slots[pos].used = 1;
    slots[pos].record = record;
    return 0;
}

static LiveRecordKey live_record_key_for_entry(const MftEntry *entry)
{
    LiveRecordKey key;

    memset(&key, 0, sizeof(key));
    if (entry != NULL) {
        key.volume_index = entry->volume_index;
        key.family = entry->family;
        key.record = entry->record;
    }
    return key;
}

static int live_record_key_equal(LiveRecordKey a, LiveRecordKey b)
{
    return a.volume_index == b.volume_index &&
           a.family == b.family &&
           a.record == b.record;
}

static uint64_t live_record_key_hash(LiveRecordKey key)
{
    uint64_t value = (uint64_t)key.volume_index;

    value ^= ((uint64_t)key.family << 32);
    value ^= (uint64_t)(uint32_t)key.record * 0x9e3779b97f4a7c15ULL;
    return hash_u64(value);
}

static void root_scope_pruned_set_destroy(RootScopePrunedSet *set)
{
    if (set == NULL) {
        return;
    }

    free(set->slots);
    memset(set, 0, sizeof(*set));
}

static int root_scope_pruned_set_rehash(RootScopePrunedSet *set, size_t new_capacity)
{
    RootScopePrunedSlot *old_slots;
    size_t old_capacity;
    RootScopePrunedSlot *new_slots;
    size_t i;

    if (set == NULL) {
        return 0;
    }

    old_slots = set->slots;
    old_capacity = set->capacity;
    new_capacity = next_power_of_two_size(new_capacity < 1024U ? 1024U : new_capacity);
    new_slots = (RootScopePrunedSlot *)calloc(new_capacity, sizeof(*new_slots));
    if (new_slots == NULL) {
        return 0;
    }

    set->slots = new_slots;
    set->capacity = new_capacity;
    set->count = 0;

    for (i = 0; i < old_capacity; i++) {
        if (old_slots[i].used) {
            LiveRecordKey key;
            size_t pos;

            key.volume_index = old_slots[i].volume_index;
            key.family = old_slots[i].family;
            key.record = old_slots[i].record;
            pos = (size_t)live_record_key_hash(key) & (set->capacity - 1U);
            while (set->slots[pos].used) {
                pos = (pos + 1U) & (set->capacity - 1U);
            }
            set->slots[pos] = old_slots[i];
            set->count++;
        }
    }

    free(old_slots);
    return 1;
}

static int root_scope_pruned_set_contains(
    const RootScopePrunedSet *set,
    LiveRecordKey key
)
{
    size_t pos;
    size_t start;

    if (set == NULL || set->slots == NULL || set->capacity == 0 || key.record < 0) {
        return 0;
    }

    pos = (size_t)live_record_key_hash(key) & (set->capacity - 1U);
    start = pos;
    while (set->slots[pos].used) {
        if (set->slots[pos].volume_index == key.volume_index &&
            set->slots[pos].family == key.family &&
            set->slots[pos].record == key.record) {
            return 1;
        }
        pos = (pos + 1U) & (set->capacity - 1U);
        if (pos == start) {
            return 0;
        }
    }

    return 0;
}

static int root_scope_pruned_set_add(
    RootScopePrunedSet *set,
    LiveRecordKey key
)
{
    size_t pos;

    if (set == NULL || key.record < 0) {
        return 0;
    }

    if (set->capacity == 0 ||
        (set->count + 1U) * 2U >= set->capacity) {
        size_t target_capacity = set->capacity == 0 ? 1024U : set->capacity * 2U;

        if (!root_scope_pruned_set_rehash(set, target_capacity)) {
            return 0;
        }
    }

    pos = (size_t)live_record_key_hash(key) & (set->capacity - 1U);
    while (set->slots[pos].used) {
        if (set->slots[pos].volume_index == key.volume_index &&
            set->slots[pos].family == key.family &&
            set->slots[pos].record == key.record) {
            return 1;
        }
        pos = (pos + 1U) & (set->capacity - 1U);
    }

    set->slots[pos].used = 1;
    set->slots[pos].volume_index = key.volume_index;
    set->slots[pos].family = key.family;
    set->slots[pos].record = key.record;
    set->count++;
    return 1;
}

static int live_index_record_rehash(LiveIndexState *state, size_t new_capacity)
{
    LiveRecordSlot *old_slots = state->record_slots;
    size_t old_capacity = state->record_capacity;
    LiveRecordSlot *new_slots;
    size_t i;

    new_capacity = next_power_of_two_size(new_capacity < 1024U ? 1024U : new_capacity);
    new_slots = (LiveRecordSlot *)calloc(new_capacity, sizeof(*new_slots));
    if (new_slots == NULL) {
        return 0;
    }

    state->record_slots = new_slots;
    state->record_capacity = new_capacity;
    state->record_count = 0;

    for (i = 0; i < old_capacity; i++) {
        if (old_slots[i].used) {
            size_t pos = (size_t)live_record_key_hash(old_slots[i].key) &
                         (state->record_capacity - 1U);

            while (state->record_slots[pos].used) {
                pos = (pos + 1U) & (state->record_capacity - 1U);
            }
            state->record_slots[pos] = old_slots[i];
            state->record_count++;
        }
    }

    free(old_slots);
    return 1;
}

static int live_index_init(LiveIndexState *state, MftTable *table)
{
    memset(state, 0, sizeof(*state));
    state->table = table;
    return live_index_record_rehash(state, 8192U);
}

static void live_index_destroy(LiveIndexState *state)
{
    if (state == NULL) {
        return;
    }
    free(state->record_slots);
    free(state->pending_items);
    free(state->pending_wait_slots);
    memset(state, 0, sizeof(*state));
}

static int live_index_insert_record(LiveIndexState *state, const MftEntry *entry, size_t index)
{
    LiveRecordKey key = live_record_key_for_entry(entry);
    size_t pos;

    if (state == NULL || entry == NULL || entry->record < 0) {
        return 1;
    }
    if (state->record_capacity == 0 ||
        (state->record_count + 1U) * 2U >= state->record_capacity) {
        if (!live_index_record_rehash(
                state,
                state->record_capacity == 0 ? 8192U : state->record_capacity * 2U)) {
            return 0;
        }
    }

    pos = (size_t)live_record_key_hash(key) & (state->record_capacity - 1U);
    while (state->record_slots[pos].used) {
        if (live_record_key_equal(state->record_slots[pos].key, key)) {
            return 1;
        }
        pos = (pos + 1U) & (state->record_capacity - 1U);
    }

    state->record_slots[pos].used = 1;
    state->record_slots[pos].key = key;
    state->record_slots[pos].index = index;
    state->record_count++;
    return 1;
}

static const MftEntry *live_index_find_entry(LiveIndexState *state, LiveRecordKey key)
{
    size_t pos;
    size_t start;

    if (state == NULL || state->record_slots == NULL || state->record_capacity == 0) {
        return NULL;
    }

    pos = (size_t)live_record_key_hash(key) & (state->record_capacity - 1U);
    start = pos;

    while (state->record_slots[pos].used) {
        if (live_record_key_equal(state->record_slots[pos].key, key)) {
            return &state->table->items[state->record_slots[pos].index];
        }
        pos = (pos + 1U) & (state->record_capacity - 1U);
        if (pos == start) {
            break;
        }
    }

    return NULL;
}

static int live_index_pending_wait_rehash(LiveIndexState *state, size_t new_capacity)
{
    PendingWaitSlot *new_slots;
    size_t i;

    new_capacity = next_power_of_two_size(new_capacity < 1024U ? 1024U : new_capacity);
    new_slots = (PendingWaitSlot *)calloc(new_capacity, sizeof(*new_slots));
    if (new_slots == NULL) {
        return 0;
    }
    for (i = 0; i < new_capacity; i++) {
        new_slots[i].head = SIZE_MAX;
    }

    free(state->pending_wait_slots);
    state->pending_wait_slots = new_slots;
    state->pending_wait_capacity = new_capacity;
    state->pending_wait_count = 0;

    for (i = 0; i < state->pending_count; i++) {
        PendingSelected *pending = &state->pending_items[i];
        size_t pos;

        if (!pending->active) {
            continue;
        }
        pos = (size_t)live_record_key_hash(pending->key) &
              (state->pending_wait_capacity - 1U);
        while (state->pending_wait_slots[pos].used &&
               !live_record_key_equal(state->pending_wait_slots[pos].key, pending->key)) {
            pos = (pos + 1U) & (state->pending_wait_capacity - 1U);
        }
        if (!state->pending_wait_slots[pos].used) {
            state->pending_wait_slots[pos].used = 1;
            state->pending_wait_slots[pos].key = pending->key;
            state->pending_wait_slots[pos].head = SIZE_MAX;
            state->pending_wait_count++;
        }
        pending->next = state->pending_wait_slots[pos].head;
        state->pending_wait_slots[pos].head = i;
    }

    return 1;
}

static int live_index_pending_insert(LiveIndexState *state, size_t table_index, LiveRecordKey wait_key)
{
    PendingSelected *new_items;
    size_t pending_index;
    size_t pos;

    if (state->pending_count == state->pending_capacity) {
        size_t new_capacity = state->pending_capacity == 0 ? 1024U : state->pending_capacity * 2U;

        new_items = (PendingSelected *)realloc(
            state->pending_items,
            new_capacity * sizeof(*new_items));
        if (new_items == NULL) {
            return 0;
        }
        state->pending_items = new_items;
        state->pending_capacity = new_capacity;
    }
    if (state->pending_wait_capacity == 0 ||
        (state->pending_wait_count + 1U) * 2U >= state->pending_wait_capacity) {
        if (!live_index_pending_wait_rehash(
                state,
                state->pending_wait_capacity == 0 ? 8192U : state->pending_wait_capacity * 2U)) {
            return 0;
        }
    }

    pending_index = state->pending_count++;
    state->pending_items[pending_index].key = wait_key;
    state->pending_items[pending_index].table_index = table_index;
    state->pending_items[pending_index].next = SIZE_MAX;
    state->pending_items[pending_index].active = 1;

    pos = (size_t)live_record_key_hash(wait_key) & (state->pending_wait_capacity - 1U);
    while (state->pending_wait_slots[pos].used &&
           !live_record_key_equal(state->pending_wait_slots[pos].key, wait_key)) {
        pos = (pos + 1U) & (state->pending_wait_capacity - 1U);
    }
    if (!state->pending_wait_slots[pos].used) {
        state->pending_wait_slots[pos].used = 1;
        state->pending_wait_slots[pos].key = wait_key;
        state->pending_wait_slots[pos].head = SIZE_MAX;
        state->pending_wait_count++;
    }
    state->pending_items[pending_index].next = state->pending_wait_slots[pos].head;
    state->pending_wait_slots[pos].head = pending_index;
    return 1;
}

static size_t live_index_take_pending_for_key(LiveIndexState *state, LiveRecordKey key)
{
    size_t pos;
    size_t start;
    size_t head;

    if (state == NULL || state->pending_wait_slots == NULL ||
        state->pending_wait_capacity == 0) {
        return SIZE_MAX;
    }

    pos = (size_t)live_record_key_hash(key) & (state->pending_wait_capacity - 1U);
    start = pos;

    while (state->pending_wait_slots[pos].used) {
        if (live_record_key_equal(state->pending_wait_slots[pos].key, key)) {
            head = state->pending_wait_slots[pos].head;
            state->pending_wait_slots[pos].head = SIZE_MAX;
            return head;
        }
        pos = (pos + 1U) & (state->pending_wait_capacity - 1U);
        if (pos == start) {
            break;
        }
    }

    return SIZE_MAX;
}

static int compare_record_index(const void *left, const void *right)
{
    const RecordIndex *a = (const RecordIndex *)left;
    const RecordIndex *b = (const RecordIndex *)right;

    if (a->volume_index < b->volume_index) {
        return -1;
    }
    if (a->volume_index > b->volume_index) {
        return 1;
    }
    if (a->family < b->family) {
        return -1;
    }
    if (a->family > b->family) {
        return 1;
    }
    if (a->record < b->record) {
        return -1;
    }
    if (a->record > b->record) {
        return 1;
    }
    if (a->index < b->index) {
        return -1;
    }
    if (a->index > b->index) {
        return 1;
    }
    return 0;
}

static int compare_paths(const void *left, const void *right)
{
    const char *a = *(const char *const *)left;
    const char *b = *(const char *const *)right;

    return strcmp(a, b);
}

static int path_list_rehash(PathList *list, size_t expected_count)
{
    PathListIndexSlot *slots;
    size_t capacity;
    size_t i;

    if (list == NULL) {
        return 0;
    }
    if (expected_count == 0) {
        free(list->index_slots);
        list->index_slots = NULL;
        list->index_capacity = 0;
        list->index_count = 0;
        return 1;
    }

    capacity = hash_index_capacity_for_count(expected_count);
    if (capacity == 0) {
        return 0;
    }
    slots = (PathListIndexSlot *)calloc(capacity, sizeof(*slots));
    if (slots == NULL) {
        return 0;
    }

    for (i = 0; i < list->count; i++) {
        uint64_t hash = hash_string(list->items[i]);
        size_t pos = (size_t)hash & (capacity - 1U);

        while (slots[pos].used) {
            pos = (pos + 1U) & (capacity - 1U);
        }
        slots[pos].used = 1;
        slots[pos].hash = hash;
        slots[pos].index = i;
    }

    free(list->index_slots);
    list->index_slots = slots;
    list->index_capacity = capacity;
    list->index_count = list->count;
    return 1;
}

static int append_path(PathList *list, const char *path)
{
    char **new_items;
    uint64_t hash;
    size_t pos;
    int have_index;

    if (path == NULL || path[0] == '\0') {
        return 1;
    }
    if (list == NULL) {
        return 0;
    }

    if (list->index_slots == NULL ||
        list->index_capacity == 0 ||
        list->index_count + 1U >= list->index_capacity / 2U) {
        if (!path_list_rehash(list, list->count + 1U)) {
            return 0;
        }
    }

    hash = hash_string(path);
    have_index = list->index_slots != NULL && list->index_capacity > 0;
    if (have_index) {
        pos = (size_t)hash & (list->index_capacity - 1U);
        while (list->index_slots[pos].used) {
            size_t index = list->index_slots[pos].index;

            if (list->index_slots[pos].hash == hash &&
                index < list->count &&
                strcmp(list->items[index], path) == 0) {
                return 1;
            }
            pos = (pos + 1U) & (list->index_capacity - 1U);
        }
    } else {
        pos = 0;
    }

    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 4096U : list->capacity * 2U;
        new_items = (char **)realloc(list->items, new_capacity * sizeof(*new_items));
        if (new_items == NULL) {
            return 0;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count] = strdup(path);
    if (list->items[list->count] == NULL) {
        return 0;
    }
    if (have_index) {
        list->index_slots[pos].used = 1;
        list->index_slots[pos].hash = hash;
        list->index_slots[pos].index = list->count;
        list->index_count++;
    }
    list->count++;
    return 1;
}

static void MFTPROBE_MAYBE_UNUSED free_paths(PathList *list)
{
    size_t i;

    for (i = 0; i < list->count; i++) {
        free(list->items[i]);
    }
    free(list->items);
    free(list->index_slots);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
    list->index_slots = NULL;
    list->index_capacity = 0;
    list->index_count = 0;
}

static size_t path_depth(const char *path)
{
    size_t depth = 0;
    const char *p;

    if (path == NULL) {
        return 0;
    }

    for (p = path; *p != '\0'; p++) {
        if (*p == '\\') {
            depth++;
        }
    }
    return depth > 0 ? depth - 1U : 0;
}

static const char *path_basename(const char *path)
{
    const char *slash;

    if (path == NULL) {
        return "";
    }
    slash = strrchr(path, '\\');
    return slash != NULL ? slash + 1 : path;
}

static void MFTPROBE_MAYBE_UNUSED write_ascii_tree(FILE *tree, PathList *paths)
{
    size_t i;

    qsort(paths->items, paths->count, sizeof(*paths->items), compare_paths);

    for (i = 0; i < paths->count; i++) {
        size_t depth;
        size_t j;

        if (i > 0 && strcmp(paths->items[i], paths->items[i - 1U]) == 0) {
            continue;
        }

        depth = path_depth(paths->items[i]);
        for (j = 0; j < depth; j++) {
            fprintf(tree, "|   ");
        }
        fprintf(tree, "|-- %s\n", path_basename(paths->items[i]));
    }
}

static int is_users_root_entry(const MftEntry *entry)
{
    return entry != NULL &&
           (entry->flags & 0x0002U) &&
           entry->parent == 5 &&
           (streq_ci(entry->name, "Users") ||
            (strlen(entry->name) > 6U &&
             ascii_tolower((unsigned char)entry->name[0]) == 'u' &&
             ascii_tolower((unsigned char)entry->name[1]) == 's' &&
             ascii_tolower((unsigned char)entry->name[2]) == 'e' &&
             ascii_tolower((unsigned char)entry->name[3]) == 'r' &&
             ascii_tolower((unsigned char)entry->name[4]) == 's' &&
             entry->name[5] == '_'));
}

static void config_trim_ascii(char *text)
{
    char *start;
    char *end;

    if (text == NULL || text[0] == '\0') {
        return;
    }

    start = text;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }
    if (start != text) {
        memmove(text, start, strlen(start) + 1U);
    }

    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
}

static void config_root_scope_normalize_token_impl(
    char *text,
    int preserve_explicit_and
)
{
    size_t i;

    if (text == NULL) {
        return;
    }

    config_trim_ascii(text);
    while (text[0] == '/' || text[0] == '\\') {
        memmove(text, text + 1, strlen(text));
    }
    for (i = 0; text[i] != '\0'; i++) {
        if (preserve_explicit_and && strncmp(text + i, " AND ", 5U) == 0) {
            i += 4U;
            continue;
        }
        if (text[i] == '\\') {
            text[i] = '/';
        }
        text[i] = (char)ascii_tolower((unsigned char)text[i]);
    }
    while (i > 0 && (text[i - 1U] == '/' || text[i - 1U] == '\\')) {
        text[--i] = '\0';
    }
}

static void config_root_scope_normalize_token(char *text)
{
    config_root_scope_normalize_token_impl(text, 0);
}

static int config_root_scope_has_item(const Config *config, const char *item)
{
    size_t i;

    if (config == NULL || item == NULL || item[0] == '\0') {
        return 0;
    }

    for (i = 0; i < config->root_scope_count; i++) {
        if (strcmp(config->root_scopes[i], item) == 0) {
            return 1;
        }
    }

    return 0;
}

static int config_root_scope_has_item_with_kind(
    const Config *config,
    const char *item,
    int is_and_expression
)
{
    size_t i;

    if (config == NULL || item == NULL || item[0] == '\0') {
        return 0;
    }

    for (i = 0; i < config->root_scope_count; i++) {
        if (strcmp(config->root_scopes[i], item) == 0 &&
            !!config->root_scope_is_and_expression[i] == !!is_and_expression) {
            return 1;
        }
    }

    return 0;
}

static int root_scope_token_has_explicit_and(const char *text)
{
    const char *separator;

    if (text == NULL || text[0] == '\0') {
        return 0;
    }
    separator = strstr(text, " AND ");
    return separator != NULL && separator != text && separator[5] != '\0';
}

static int config_root_scope_matches_name(const Config *config, const char *name)
{
    char normalized[NAME_MAX_LEN];

    if (config == NULL || name == NULL || name[0] == '\0') {
        return 0;
    }

    snprintf(normalized, sizeof(normalized), "%s", name);
    config_root_scope_normalize_token(normalized);
    return config_root_scope_has_item(config, normalized);
}

static int config_root_scope_index_for_name(const Config *config, const char *name)
{
    char normalized[NAME_MAX_LEN];
    size_t i;

    if (config == NULL || name == NULL || name[0] == '\0') {
        return -1;
    }

    snprintf(normalized, sizeof(normalized), "%s", name);
    config_root_scope_normalize_token(normalized);
    for (i = 0; i < config->root_scope_count; i++) {
        if (strcmp(config->root_scopes[i], normalized) == 0) {
            return (int)i;
        }
    }

    return -1;
}

static int root_scope_item_has_path_separator(const char *item)
{
    return item != NULL && strchr(item, '/') != NULL;
}

static int root_scope_item_matches_root_name_or_path_start(
    const char *item,
    const char *normalized_root_name
)
{
    size_t root_len;

    if (item == NULL ||
        item[0] == '\0' ||
        normalized_root_name == NULL ||
        normalized_root_name[0] == '\0') {
        return 0;
    }

    if (strcmp(item, normalized_root_name) == 0) {
        return 1;
    }

    root_len = strlen(normalized_root_name);
    return strncmp(item, normalized_root_name, root_len) == 0 &&
           item[root_len] == '/';
}

static int config_root_scope_has_path_scope(const Config *config)
{
    size_t i;

    if (config == NULL) {
        return 0;
    }

    for (i = 0; i < config->root_scope_count; i++) {
        if (root_scope_item_has_path_separator(config->root_scopes[i])) {
            return 1;
        }
    }
    return 0;
}

static int config_root_scope_matches_root_name_or_path_start(
    const Config *config,
    const char *name
)
{
    char normalized[NAME_MAX_LEN];
    size_t i;

    if (config == NULL || name == NULL || name[0] == '\0') {
        return 0;
    }

    snprintf(normalized, sizeof(normalized), "%s", name);
    config_root_scope_normalize_token(normalized);
    if (normalized[0] == '\0') {
        return 0;
    }

    for (i = 0; i < config->root_scope_count; i++) {
        if (root_scope_item_matches_root_name_or_path_start(
                config->root_scopes[i],
                normalized)) {
            return 1;
        }
    }
    return 0;
}

static int config_root_scope_add_csv(
    Config *config,
    const char *csv,
    char *error_text,
    size_t error_text_size
)
{
    static const char encoded_scope_prefix[] = "@scope-v1:";
    size_t scope_offset = 0U;
    int allow_and_expressions;

    if (error_text != NULL && error_text_size > 0U) {
        error_text[0] = '\0';
    }
    if (config == NULL || csv == NULL || csv[0] == '\0') {
        return 1;
    }
    allow_and_expressions =
        strncmp(csv, encoded_scope_prefix, sizeof(encoded_scope_prefix) - 1U) != 0;
    while (1) {
        char normalized[NAME_MAX_LEN];
        int is_and_expression;
        int token_status = config_scope_next_item(
            csv,
            &scope_offset,
            normalized,
            sizeof(normalized)
        );

        if (token_status == 0) {
            break;
        }
        if (token_status < 0) {
            snprintf(error_text, error_text_size, "Root scope item is invalid or too long");
            return 0;
        }
        is_and_expression =
            allow_and_expressions && root_scope_token_has_explicit_and(normalized);
        config_root_scope_normalize_token_impl(normalized, is_and_expression);
        if (normalized[0] != '\0' &&
            !config_root_scope_has_item_with_kind(
                config,
                normalized,
                is_and_expression)) {
            if (config->root_scope_count >=
                (sizeof(config->root_scopes) / sizeof(config->root_scopes[0]))) {
                snprintf(
                    error_text,
                    error_text_size,
                    "Too many --fold items (max %u)",
                    (unsigned int)(
                        sizeof(config->root_scopes) / sizeof(config->root_scopes[0])
                    )
                );
                return 0;
            }
            snprintf(
                config->root_scopes[config->root_scope_count],
                sizeof(config->root_scopes[config->root_scope_count]),
                "%s",
                normalized
            );
            config->root_scope_is_and_expression[config->root_scope_count] =
                is_and_expression ? 1U : 0U;
            config->root_scope_count++;
        }
    }

    return 1;
}

static void config_root_scope_format_csv(
    const Config *config,
    char *out,
    size_t out_size
)
{
    size_t i;

    if (out == NULL || out_size == 0U) {
        return;
    }
    out[0] = '\0';

    if (config == NULL) {
        return;
    }

    for (i = 0; i < config->root_scope_count; i++) {
        if (!config_scope_append_item_v1(
                out,
                out_size,
                config->root_scopes[i])) {
            out[0] = '\0';
            return;
        }
    }
}

static uint64_t config_root_scope_and_expression_mask(const Config *config)
{
    uint64_t mask = 0ULL;
    size_t i;

    if (config == NULL) {
        return 0ULL;
    }
    for (i = 0U; i < config->root_scope_count && i < 64U; ++i) {
        if (config->root_scope_is_and_expression[i]) {
            mask |= 1ULL << i;
        }
    }
    return mask;
}

#define ROOT_SCOPE_RESOLUTION_CSV_MAX \
    (64U * ((NAME_MAX_LEN * 3U) + 1U) + 64U)

static int write_root_scope_resolution_state(
    const Config *requested_config,
    const Config *resolved_config
)
{
    char path[PATH_MAX_LEN];
    char temp_path[PATH_MAX_LEN + 32U];
    char query_csv[ROOT_SCOPE_RESOLUTION_CSV_MAX];
    char resolved_csv[ROOT_SCOPE_RESOLUTION_CSV_MAX];
    FILE *file;
    int ok = 0;

    if (requested_config == NULL || resolved_config == NULL ||
        requested_config->out_dir == NULL || requested_config->out_dir[0] == '\0' ||
        requested_config->root_scope_count == 0U ||
        resolved_config->root_scope_count == 0U) {
        return 0;
    }
    config_root_scope_format_csv(requested_config, query_csv, sizeof(query_csv));
    config_root_scope_format_csv(resolved_config, resolved_csv, sizeof(resolved_csv));
    if (query_csv[0] == '\0' || resolved_csv[0] == '\0') {
        return 0;
    }
    join_path(
        path,
        sizeof(path),
        requested_config->out_dir,
        APP_STATE_DIR_NAME "/folder_scope_resolution.txt"
    );
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >=
            (int)sizeof(temp_path) ||
        !ensure_parent_dirs(path)) {
        return 0;
    }
    file = fopen(temp_path, "wb");
    if (file == NULL) {
        return 0;
    }
    fprintf(file, "format_version=1\n");
    fprintf(file, "volume_serial=%016llx\n",
        (unsigned long long)requested_config->ntfs.volume_serial);
    fprintf(file, "source_size=%llu\n",
        (unsigned long long)requested_config->source_size);
    fprintf(file, "query_and_mask=%016llx\n",
        (unsigned long long)config_root_scope_and_expression_mask(requested_config));
    fprintf(file, "query=%s\n", query_csv);
    fprintf(file, "resolved=%s\n", resolved_csv);
    if (fflush(file) == 0 && fsync(fileno(file)) == 0) {
        int close_ok = fclose(file) == 0;

        file = NULL;
        if (close_ok) {
            ok = rename(temp_path, path) == 0;
        }
    } else {
        (void)fclose(file);
        file = NULL;
    }
    if (!ok) {
        (void)unlink(temp_path);
    }
    return ok;
}

static int load_root_scope_resolution_state(Config *config)
{
    char path[PATH_MAX_LEN];
    char expected_query[ROOT_SCOPE_RESOLUTION_CSV_MAX];
    char saved_query[ROOT_SCOPE_RESOLUTION_CSV_MAX] = "";
    char saved_resolved[ROOT_SCOPE_RESOLUTION_CSV_MAX] = "";
    char *line = NULL;
    size_t line_capacity = 0U;
    unsigned long long saved_serial = 0ULL;
    unsigned long long saved_source_size = 0ULL;
    unsigned long long saved_and_mask = 0ULL;
    Config loaded_config;
    char error_text[256] = "";
    FILE *file;
    int format_version = 0;

    if (config == NULL || config->out_dir == NULL ||
        config->root_scope_count == 0U) {
        return 0;
    }
    config_root_scope_format_csv(config, expected_query, sizeof(expected_query));
    if (expected_query[0] == '\0') {
        return 0;
    }
    join_path(
        path,
        sizeof(path),
        config->out_dir,
        APP_STATE_DIR_NAME "/folder_scope_resolution.txt"
    );
    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    while (getline(&line, &line_capacity, file) >= 0) {
        char *newline = strpbrk(line, "\r\n");

        if (newline != NULL) {
            *newline = '\0';
        }
        if (sscanf(line, "format_version=%d", &format_version) == 1 ||
            sscanf(line, "volume_serial=%llx", &saved_serial) == 1 ||
            sscanf(line, "source_size=%llu", &saved_source_size) == 1 ||
            sscanf(line, "query_and_mask=%llx", &saved_and_mask) == 1) {
            continue;
        }
        if (strncmp(line, "query=", 6U) == 0) {
            snprintf(saved_query, sizeof(saved_query), "%s", line + 6U);
        } else if (strncmp(line, "resolved=", 9U) == 0) {
            snprintf(saved_resolved, sizeof(saved_resolved), "%s", line + 9U);
        }
    }
    free(line);
    fclose(file);

    if (format_version != 1 || strcmp(saved_query, expected_query) != 0 ||
        saved_resolved[0] == '\0' ||
        saved_serial != config->ntfs.volume_serial ||
        saved_source_size != config->source_size ||
        saved_and_mask != config_root_scope_and_expression_mask(config)) {
        return 0;
    }

    loaded_config = *config;
    loaded_config.root_scope_count = 0U;
    if (!config_root_scope_add_csv(
            &loaded_config,
            saved_resolved,
            error_text,
            sizeof(error_text)) ||
        loaded_config.root_scope_count == 0U) {
        return 0;
    }
    config->root_scope_count = loaded_config.root_scope_count;
    memcpy(config->root_scopes, loaded_config.root_scopes, sizeof(config->root_scopes));
    memcpy(
        config->root_scope_is_and_expression,
        loaded_config.root_scope_is_and_expression,
        sizeof(config->root_scope_is_and_expression)
    );
    log_info(
        "Reusing %zu resolved --fold folder path%s from saved state",
        config->root_scope_count,
        config->root_scope_count == 1U ? "" : "s"
    );
    return 1;
}

static int csv_token_matches_exact_item(
    const char *csv,
    const char *item
)
{
    size_t scope_offset = 0U;

    if (csv == NULL || item == NULL || item[0] == '\0') {
        return 0;
    }
    while (1) {
        char token[NAME_MAX_LEN];
        int token_status = config_scope_next_item(
            csv,
            &scope_offset,
            token,
            sizeof(token)
        );

        if (token_status <= 0) {
            break;
        }
        config_trim_ascii(token);
        if (strcmp(token, item) == 0) {
            return 1;
        }
    }

    return 0;
}

static size_t config_root_scope_prune_missing_csv_in_place(
    Config *config,
    const char *missing_csv,
    char *kept_csv,
    size_t kept_csv_size
)
{
    size_t read_index;
    size_t write_index = 0U;
    size_t removed = 0U;

    if (kept_csv != NULL && kept_csv_size > 0U) {
        kept_csv[0] = '\0';
    }
    if (config == NULL ||
        config->root_scope_count == 0U ||
        missing_csv == NULL ||
        missing_csv[0] == '\0') {
        if (kept_csv != NULL && kept_csv_size > 0U) {
            config_root_scope_format_csv(config, kept_csv, kept_csv_size);
        }
        return 0U;
    }

    for (read_index = 0; read_index < config->root_scope_count; read_index++) {
        if (csv_token_matches_exact_item(missing_csv, config->root_scopes[read_index])) {
            removed++;
            continue;
        }
        if (write_index != read_index) {
            snprintf(
                config->root_scopes[write_index],
                sizeof(config->root_scopes[write_index]),
                "%s",
                config->root_scopes[read_index]
            );
            config->root_scope_is_and_expression[write_index] =
                config->root_scope_is_and_expression[read_index];
        }
        write_index++;
    }

    if (write_index < config->root_scope_count) {
        memset(
            &config->root_scope_is_and_expression[write_index],
            0,
            config->root_scope_count - write_index
        );
    }

    config->root_scope_count = write_index;
    if (kept_csv != NULL && kept_csv_size > 0U) {
        config_root_scope_format_csv(config, kept_csv, kept_csv_size);
    }
    return removed;
}

static int root_scope_prune_entry_for_live_scan(
    const Config *config,
    const MftEntry *entry,
    RootScopePrunedSet *pruned_set
)
{
    LiveRecordKey parent_key;
    LiveRecordKey entry_key;
    int is_directory;

    if (config == NULL ||
        entry == NULL ||
        config->root_scope_count == 0 ||
        entry->name[0] == '\0') {
        return 0;
    }

    is_directory = (entry->flags & 0x0002U) != 0U;
    entry_key = live_record_key_for_entry(entry);

    if (entry->parent == 5U) {
        if (is_directory &&
            config_root_scope_matches_root_name_or_path_start(config, entry->name)) {
            return 0;
        }
        if (is_directory && pruned_set != NULL) {
            if (!root_scope_pruned_set_add(pruned_set, entry_key)) {
                return 0;
            }
        }
        return 1;
    }

    if (entry->parent > (uint64_t)INT32_MAX) {
        return 0;
    }

    parent_key.volume_index = entry->volume_index;
    parent_key.family = entry->family;
    parent_key.record = (int)entry->parent;
    if (pruned_set != NULL && root_scope_pruned_set_contains(pruned_set, parent_key)) {
        if (is_directory) {
            if (!root_scope_pruned_set_add(pruned_set, entry_key)) {
                return 0;
            }
        }
        return 1;
    }

    return 0;
}

static int entry_needed_for_live_index_with_root_scope(
    const Config *config,
    const MftEntry *entry,
    RootScopePrunedSet *pruned_set
)
{
    if (root_scope_prune_entry_for_live_scan(config, entry, pruned_set)) {
        return 0;
    }

    return entry_needed_for_live_index(config, entry);
}

static const MftEntry *find_entry_by_record_relaxed(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    uint32_t volume_index,
    uint32_t family,
    int record
);

enum {
    ROOT_SCOPE_PATH_RELATION_NONE = 0,
    ROOT_SCOPE_PATH_RELATION_ANCESTOR = 1,
    ROOT_SCOPE_PATH_RELATION_MATCH = 2
};

static int append_normalized_scope_path_part(
    char *out,
    size_t out_size,
    const char *name
)
{
    char normalized[NAME_MAX_LEN];

    if (out == NULL || out_size == 0U || name == NULL || name[0] == '\0') {
        return 0;
    }

    snprintf(normalized, sizeof(normalized), "%s", name);
    config_root_scope_normalize_token(normalized);
    if (normalized[0] == '\0') {
        return 0;
    }

    if (out[0] != '\0') {
        strncat(out, "/", out_size - strlen(out) - 1U);
    }
    strncat(out, normalized, out_size - strlen(out) - 1U);
    return out[0] != '\0';
}

static int build_normalized_mft_entry_scope_path(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    char *out,
    size_t out_size
)
{
    const MftEntry *chain[256];
    const MftEntry *cur = entry;
    size_t chain_count = 0;
    size_t i;
    int reached_root = 0;

    if (out == NULL || out_size == 0U) {
        return 0;
    }
    out[0] = '\0';

    if (items == NULL || index == NULL || entry == NULL || entry->name[0] == '\0') {
        return 0;
    }

    while (cur != NULL && chain_count < (sizeof(chain) / sizeof(chain[0]))) {
        chain[chain_count++] = cur;
        if (cur->parent == 5U) {
            reached_root = 1;
            break;
        }
        if (cur->record == 5 ||
            cur->parent == (uint64_t)cur->record ||
            cur->parent > (uint64_t)INT32_MAX) {
            break;
        }
        cur = find_entry_by_record_relaxed(
            items,
            index,
            count,
            cur->volume_index,
            cur->family,
            (int)cur->parent
        );
    }

    if (!reached_root) {
        return 0;
    }

    for (i = chain_count; i > 0; i--) {
        const MftEntry *part = chain[i - 1U];

        if (part->record == 5) {
            continue;
        }
        if (!append_normalized_scope_path_part(out, out_size, part->name)) {
            return 0;
        }
    }

    return out[0] != '\0';
}

static int root_scope_directory_matches_exact_item(
    const char *scope,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry
)
{
    char normalized_name[NAME_MAX_LEN];
    char normalized_path[PATH_MAX_LEN];

    if (scope == NULL || scope[0] == '\0' || entry == NULL ||
        (entry->flags & 0x0002U) == 0U || entry->name[0] == '\0') {
        return 0;
    }

    if (!root_scope_item_has_path_separator(scope)) {
        if (entry->parent != 5U) {
            return 0;
        }
        snprintf(normalized_name, sizeof(normalized_name), "%s", entry->name);
        config_root_scope_normalize_token(normalized_name);
        return strcmp(normalized_name, scope) == 0;
    }

    return build_normalized_mft_entry_scope_path(
        items,
        index,
        count,
        entry,
        normalized_path,
        sizeof(normalized_path)
    ) && strcmp(normalized_path, scope) == 0;
}

static int config_root_scopes_are_all_exact_in_table(
    const Config *config,
    MftTable *table
)
{
    size_t scope_index;

    if (config == NULL || table == NULL || config->root_scope_count == 0U) {
        return 1;
    }
    if (table->count == 0U || !table_ensure_record_index(table)) {
        return 0;
    }

    for (scope_index = 0U; scope_index < config->root_scope_count; ++scope_index) {
        size_t entry_index;
        int found = 0;

        if (config->root_scope_is_and_expression[scope_index]) {
            return 0;
        }

        for (entry_index = 0U; entry_index < table->count; ++entry_index) {
            if (root_scope_directory_matches_exact_item(
                    config->root_scopes[scope_index],
                    table->items,
                    table->record_index,
                    table->count,
                    &table->items[entry_index])) {
                found = 1;
                break;
            }
        }
        if (!found) {
            return 0;
        }
    }
    return 1;
}

static int config_root_scope_add_resolved_path(
    Config *config,
    const char *normalized_path
)
{
    size_t capacity;

    if (config == NULL || normalized_path == NULL || normalized_path[0] == '\0') {
        return 0;
    }
    if (config_root_scope_has_item(config, normalized_path)) {
        return 1;
    }
    capacity = sizeof(config->root_scopes) / sizeof(config->root_scopes[0]);
    if (strlen(normalized_path) >= sizeof(config->root_scopes[0])) {
        log_error(
            "Folder search matched a path that is too long for --fold: %s",
            normalized_path
        );
        return 0;
    }
    if (config->root_scope_count >= capacity) {
        log_error(
            "Folder search matched more than %zu folders; use a more specific --fold term",
            capacity
        );
        return 0;
    }
    snprintf(
        config->root_scopes[config->root_scope_count],
        sizeof(config->root_scopes[config->root_scope_count]),
        "%s",
        normalized_path
    );
    config->root_scope_is_and_expression[config->root_scope_count] = 0U;
    config->root_scope_count++;
    return 1;
}

static int normalized_scope_path_matches_and_expression(
    const char *normalized_path,
    const char *normalized_expression
)
{
    static const char separator[] = " AND ";
    const char *cursor;
    size_t clause_count = 0U;

    if (normalized_path == NULL || normalized_path[0] == '\0' ||
        normalized_expression == NULL || normalized_expression[0] == '\0') {
        return 0;
    }

    cursor = normalized_expression;
    while (cursor[0] != '\0') {
        const char *next = strstr(cursor, separator);
        size_t clause_length = next != NULL
            ? (size_t)(next - cursor)
            : strlen(cursor);
        char clause[NAME_MAX_LEN];

        while (clause_length > 0U && isspace((unsigned char)cursor[0])) {
            cursor++;
            clause_length--;
        }
        while (clause_length > 0U &&
               isspace((unsigned char)cursor[clause_length - 1U])) {
            clause_length--;
        }
        if (clause_length == 0U || clause_length >= sizeof(clause)) {
            return 0;
        }
        memcpy(clause, cursor, clause_length);
        clause[clause_length] = '\0';
        if (strstr(normalized_path, clause) == NULL) {
            return 0;
        }
        clause_count++;
        if (next == NULL) {
            break;
        }
        cursor = next + sizeof(separator) - 1U;
    }

    return clause_count >= 2U;
}

/*
 * Keep today's exact --fold semantics whenever an exact directory exists.
 * Only a term with no exact hit becomes a case-insensitive substring search;
 * an explicitly marked AND expression always searches the full folder path.
 * The search is resolved once into concrete paths, so all later ownership,
 * domain and recovery code continues to use the proven exact-path machinery.
 */
static int config_resolve_partial_root_scopes_from_table(
    Config *config,
    MftTable *table
)
{
    Config resolved_config;
    char requested[64][NAME_MAX_LEN];
    uint8_t requested_is_and_expression[64];
    size_t requested_count;
    size_t scope_index;

    if (config == NULL || table == NULL || config->root_scope_count == 0U) {
        return 1;
    }
    if (!table_ensure_record_index(table)) {
        log_error("Folder search could not build the MFT parent index");
        return 0;
    }
    if (config_root_scopes_are_all_exact_in_table(config, table)) {
        return 1;
    }

    requested_count = config->root_scope_count;
    memcpy(requested, config->root_scopes, sizeof(requested));
    memcpy(
        requested_is_and_expression,
        config->root_scope_is_and_expression,
        sizeof(requested_is_and_expression)
    );
    resolved_config = *config;
    resolved_config.root_scope_count = 0U;
    memset(
        resolved_config.root_scope_is_and_expression,
        0,
        sizeof(resolved_config.root_scope_is_and_expression)
    );

    for (scope_index = 0U; scope_index < requested_count; ++scope_index) {
        const char *term = requested[scope_index];
        size_t entry_index;
        size_t term_match_count = 0U;
        int exact_found = 0;
        int is_and_expression = requested_is_and_expression[scope_index] != 0U;

        if (!is_and_expression) {
            for (entry_index = 0U; entry_index < table->count; ++entry_index) {
                if (root_scope_directory_matches_exact_item(
                        term,
                        table->items,
                        table->record_index,
                        table->count,
                        &table->items[entry_index])) {
                    exact_found = 1;
                    break;
                }
            }
        }
        if (exact_found) {
            if (!config_root_scope_add_resolved_path(&resolved_config, term)) {
                return 0;
            }
            continue;
        }

        if (resolved_config.root_scope_defaulted) {
            log_error("Default folder was not found exactly in the primary $MFT: %s", term);
            return 0;
        }

        for (entry_index = 0U; entry_index < table->count; ++entry_index) {
            const MftEntry *entry = &table->items[entry_index];
            char normalized_name[NAME_MAX_LEN];
            char normalized_path[PATH_MAX_LEN];
            int matches;

            if ((entry->flags & 0x0002U) == 0U || entry->name[0] == '\0') {
                continue;
            }
            if (is_and_expression) {
                if (!build_normalized_mft_entry_scope_path(
                        table->items,
                        table->record_index,
                        table->count,
                        entry,
                        normalized_path,
                        sizeof(normalized_path))) {
                    continue;
                }
                matches = normalized_scope_path_matches_and_expression(
                    normalized_path,
                    term
                );
            } else {
                snprintf(normalized_name, sizeof(normalized_name), "%s", entry->name);
                config_root_scope_normalize_token(normalized_name);
                if (root_scope_item_has_path_separator(term)) {
                    if (!build_normalized_mft_entry_scope_path(
                            table->items,
                            table->record_index,
                            table->count,
                            entry,
                            normalized_path,
                            sizeof(normalized_path))) {
                        continue;
                    }
                    matches = strstr(normalized_path, term) != NULL;
                } else {
                    matches = strstr(normalized_name, term) != NULL;
                }
                if (matches && !root_scope_item_has_path_separator(term) &&
                    !build_normalized_mft_entry_scope_path(
                        table->items,
                        table->record_index,
                        table->count,
                        entry,
                        normalized_path,
                        sizeof(normalized_path))) {
                    continue;
                }
            }
            if (!matches) {
                continue;
            }
            term_match_count++;
            if (!config_root_scope_add_resolved_path(&resolved_config, normalized_path)) {
                return 0;
            }
            if (term_match_count <= 12U) {
                log_info("Folder search match for '%s': /%s", term, normalized_path);
            }
        }

        if (term_match_count == 0U) {
            log_error("Folder search term did not match any MFT directory: %s", term);
            return 0;
        }
        log_info(
            "Folder search term '%s' resolved to %zu exact folder path%s%s",
            term,
            term_match_count,
            term_match_count == 1U ? "" : "s",
            term_match_count > 12U ? " (first 12 shown)" : ""
        );
    }

    if (resolved_config.root_scope_count == 0U) {
        return 0;
    }
    config->root_scope_count = resolved_config.root_scope_count;
    memcpy(config->root_scopes, resolved_config.root_scopes, sizeof(config->root_scopes));
    memcpy(
        config->root_scope_is_and_expression,
        resolved_config.root_scope_is_and_expression,
        sizeof(config->root_scope_is_and_expression)
    );
    return 1;
}

static int normalized_scope_path_relation(
    const Config *config,
    const char *normalized_path,
    int is_directory,
    int *scope_index_out
)
{
    size_t path_len;
    size_t i;
    int ancestor_index = -1;

    if (scope_index_out != NULL) {
        *scope_index_out = -1;
    }
    if (config == NULL || normalized_path == NULL || normalized_path[0] == '\0') {
        return ROOT_SCOPE_PATH_RELATION_NONE;
    }

    path_len = strlen(normalized_path);
    for (i = 0; i < config->root_scope_count; i++) {
        const char *scope = config->root_scopes[i];
        size_t scope_len;

        if (scope == NULL || scope[0] == '\0') {
            continue;
        }
        scope_len = strlen(scope);
        if (strcmp(normalized_path, scope) == 0 ||
            (strncmp(normalized_path, scope, scope_len) == 0 &&
             normalized_path[scope_len] == '/')) {
            if (scope_index_out != NULL) {
                *scope_index_out = (int)i;
            }
            return ROOT_SCOPE_PATH_RELATION_MATCH;
        }
        if (is_directory &&
            ancestor_index < 0 &&
            strncmp(scope, normalized_path, path_len) == 0 &&
            scope[path_len] == '/') {
            ancestor_index = (int)i;
        }
    }

    if (ancestor_index >= 0) {
        if (scope_index_out != NULL) {
            *scope_index_out = ancestor_index;
        }
        return ROOT_SCOPE_PATH_RELATION_ANCESTOR;
    }
    return ROOT_SCOPE_PATH_RELATION_NONE;
}

static int mft_entry_root_scope_path_relation(
    const Config *config,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    int *scope_index_out
)
{
    char normalized_path[PATH_MAX_LEN];
    int is_directory;

    if (scope_index_out != NULL) {
        *scope_index_out = -1;
    }
    if (config == NULL ||
        config->root_scope_count == 0 ||
        entry == NULL ||
        entry->name[0] == '\0') {
        return ROOT_SCOPE_PATH_RELATION_NONE;
    }

    if (!build_normalized_mft_entry_scope_path(
            items,
            index,
            count,
            entry,
            normalized_path,
            sizeof(normalized_path))) {
        return ROOT_SCOPE_PATH_RELATION_NONE;
    }

    is_directory = (entry->flags & 0x0002U) != 0U;
    return normalized_scope_path_relation(
        config,
        normalized_path,
        is_directory,
        scope_index_out
    );
}

enum {
    ROOT_SCOPE_CACHE_STATE_UNKNOWN = 0,
    ROOT_SCOPE_CACHE_STATE_DROP = 1,
    ROOT_SCOPE_CACHE_STATE_KEEP_DIR = 2,
    ROOT_SCOPE_CACHE_STATE_KEEP_LEAF = 3,
    ROOT_SCOPE_CACHE_STATE_VISITING = 4,
    ROOT_SCOPE_CACHE_STATE_KEEP_PREFIX_DIR = 5
};

static uint8_t classify_loaded_entry_for_selected_root_scope(
    const Config *config,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    size_t item_index,
    uint8_t *states
)
{
    const MftEntry *entry;
    const MftEntry *parent;
    uint8_t cached_state;
    uint8_t parent_state;
    int is_directory;

    if (config == NULL ||
        items == NULL ||
        index == NULL ||
        states == NULL ||
        item_index >= count) {
        return ROOT_SCOPE_CACHE_STATE_DROP;
    }

    cached_state = states[item_index];
    if (cached_state == ROOT_SCOPE_CACHE_STATE_DROP ||
        cached_state == ROOT_SCOPE_CACHE_STATE_KEEP_DIR ||
        cached_state == ROOT_SCOPE_CACHE_STATE_KEEP_LEAF) {
        return cached_state;
    }
    if (cached_state == ROOT_SCOPE_CACHE_STATE_VISITING) {
        return ROOT_SCOPE_CACHE_STATE_DROP;
    }

    entry = &items[item_index];
    is_directory = (entry->flags & 0x0002U) != 0U;
    states[item_index] = ROOT_SCOPE_CACHE_STATE_VISITING;

    if (entry->name[0] == '\0') {
        states[item_index] = ROOT_SCOPE_CACHE_STATE_DROP;
        return ROOT_SCOPE_CACHE_STATE_DROP;
    }

    if (config_root_scope_has_path_scope(config)) {
        int relation = mft_entry_root_scope_path_relation(
            config,
            items,
            index,
            count,
            entry,
            NULL
        );

        if (relation == ROOT_SCOPE_PATH_RELATION_MATCH) {
            states[item_index] = is_directory
                ? ROOT_SCOPE_CACHE_STATE_KEEP_DIR
                : ROOT_SCOPE_CACHE_STATE_KEEP_LEAF;
            return states[item_index];
        }
        if (relation == ROOT_SCOPE_PATH_RELATION_ANCESTOR && is_directory) {
            states[item_index] = ROOT_SCOPE_CACHE_STATE_KEEP_PREFIX_DIR;
            return states[item_index];
        }
        states[item_index] = ROOT_SCOPE_CACHE_STATE_DROP;
        return ROOT_SCOPE_CACHE_STATE_DROP;
    }

    if (entry->parent == 5U) {
        states[item_index] =
            (is_directory && config_root_scope_matches_name(config, entry->name))
                ? ROOT_SCOPE_CACHE_STATE_KEEP_DIR
                : ROOT_SCOPE_CACHE_STATE_DROP;
        return states[item_index];
    }

    if (entry->record == 5 ||
        entry->parent == (uint64_t)entry->record ||
        entry->parent > (uint64_t)INT32_MAX) {
        states[item_index] = ROOT_SCOPE_CACHE_STATE_DROP;
        return ROOT_SCOPE_CACHE_STATE_DROP;
    }

    parent = find_entry_by_record_relaxed(
        items,
        index,
        count,
        entry->volume_index,
        entry->family,
        (int)entry->parent
    );
    if (parent == NULL) {
        states[item_index] = ROOT_SCOPE_CACHE_STATE_DROP;
        return ROOT_SCOPE_CACHE_STATE_DROP;
    }

    parent_state = classify_loaded_entry_for_selected_root_scope(
        config,
        items,
        index,
        count,
        (size_t)(parent - items),
        states
    );
    if (parent_state != ROOT_SCOPE_CACHE_STATE_KEEP_DIR) {
        states[item_index] = ROOT_SCOPE_CACHE_STATE_DROP;
        return ROOT_SCOPE_CACHE_STATE_DROP;
    }

    if (is_directory) {
        states[item_index] = ROOT_SCOPE_CACHE_STATE_KEEP_DIR;
    } else if (mftprobe_format_select_for_entry(config, entry) != NULL ||
               entry_is_generic_file_candidate(config, entry)) {
        states[item_index] = ROOT_SCOPE_CACHE_STATE_KEEP_LEAF;
    } else {
        states[item_index] = ROOT_SCOPE_CACHE_STATE_DROP;
    }

    return states[item_index];
}

static void format_compact_entry_count_local(
    size_t value,
    char *out,
    size_t out_size
)
{
    double scaled = (double)value;

    if (out == NULL || out_size == 0) {
        return;
    }

    if (value >= 1000000U) {
        snprintf(out, out_size, "%.1fM", scaled / 1000000.0);
        return;
    }

    if (value >= 1000U) {
        snprintf(out, out_size, "%.1fK", scaled / 1000.0);
        return;
    }

    snprintf(out, out_size, "%zu", value);
}

static void publish_users_loop_activity_progress(
    const char *base_activity,
    size_t current,
    size_t total,
    double *last_published_at
)
{
    char current_text[32];
    char total_text[32];
    char activity[96];
    double now;

    if (base_activity == NULL || base_activity[0] == '\0' || total == 0U) {
        return;
    }

    now = monotonic_seconds();
    if (last_published_at != NULL &&
        current != 0U &&
        current < total &&
        (now - *last_published_at) < 0.25) {
        return;
    }

    format_compact_entry_count_local(current, current_text, sizeof(current_text));
    format_compact_entry_count_local(total, total_text, sizeof(total_text));
    snprintf(
        activity,
        sizeof(activity),
        "%s %s/%s",
        base_activity,
        current_text,
        total_text
    );
    log_set_working_activity(activity);
    if (last_published_at != NULL) {
        *last_published_at = now;
    }
}

static int prune_loaded_table_to_selected_root_scope(
    const Config *config,
    MftTable *table
)
{
    double started_at;
    double phase_started_at;
    double index_seconds = 0.0;
    double classify_seconds = 0.0;
    double last_progress_published_at = 0.0;
    size_t original_count;
    size_t kept = 0;
    size_t i;
    RecordIndex *index = NULL;
    uint8_t *states = NULL;
    MftEntry *items;

    if (config == NULL ||
        table == NULL ||
        config->root_scope_count == 0 ||
        table->count == 0 ||
        table->items == NULL) {
        return 1;
    }

    started_at = monotonic_seconds();
    items = table->items;
    original_count = table->count;
    log_set_working_activity("pruning cached folders scope");

    phase_started_at = monotonic_seconds();
    log_set_working_activity("pruning cached folders scope index");
    if (!table_ensure_record_index(table)) {
        if (stop_requested()) {
            return 0;
        }
        log_info(
            "Folders --fold exact prune skipped: could not build record index for %zu cached entries",
            original_count
        );
        return 1;
    }
    index = table->record_index;
    index_seconds = monotonic_seconds() - phase_started_at;

    states = (uint8_t *)calloc(original_count, sizeof(*states));
    if (states == NULL) {
        log_info(
            "Folders --fold exact prune skipped: could not allocate state for %zu cached entries",
            original_count
        );
        return 1;
    }

    publish_users_loop_activity_progress(
        "pruning cached folders scope",
        0U,
        original_count,
        &last_progress_published_at
    );
    phase_started_at = monotonic_seconds();
    for (i = 0; i < original_count; i++) {
        if ((i & 0x3FFFU) == 0 && stop_requested()) {
            free(states);
            return 0;
        }
        if ((i & 0x3FFFU) == 0) {
            publish_users_loop_activity_progress(
                "pruning cached folders scope",
                i,
                original_count,
                &last_progress_published_at
            );
        }
        (void)classify_loaded_entry_for_selected_root_scope(
            config,
            items,
            index,
            original_count,
            i,
            states
        );
    }
    publish_users_loop_activity_progress(
        "pruning cached folders scope",
        original_count,
        original_count,
        &last_progress_published_at
    );
    for (i = 0; i < original_count; i++) {
        if (states[i] == ROOT_SCOPE_CACHE_STATE_KEEP_DIR ||
            states[i] == ROOT_SCOPE_CACHE_STATE_KEEP_PREFIX_DIR ||
            states[i] == ROOT_SCOPE_CACHE_STATE_KEEP_LEAF) {
            if (kept != i) {
                items[kept] = items[i];
            }
            kept++;
        }
    }
    table->count = kept;
    table_mark_record_index_dirty(table);
    classify_seconds = monotonic_seconds() - phase_started_at;

    log_info(
        "Folders --fold exact prune: cached entries=%zu kept=%zu dropped=%zu t_index=%.2fs t_filter=%.2fs total=%.2fs",
        original_count,
        kept,
        original_count > kept ? (original_count - kept) : 0U,
        index_seconds,
        classify_seconds,
        monotonic_seconds() - started_at
    );

    free(states);
    return 1;
}

enum {
    ROOT_SCOPE_OWNER_UNKNOWN = -3,
    ROOT_SCOPE_OWNER_NONE = -2,
    ROOT_SCOPE_OWNER_VISITING = -1
};

static int selected_root_scope_index_for_entry(
    const Config *config,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    size_t item_index,
    int *owner_cache
)
{
    const MftEntry *entry;
    const MftEntry *parent;
    int cached_owner;
    int selected_root_index;

    if (config == NULL ||
        items == NULL ||
        index == NULL ||
        owner_cache == NULL ||
        item_index >= count) {
        return ROOT_SCOPE_OWNER_NONE;
    }

    cached_owner = owner_cache[item_index];
    if (cached_owner != ROOT_SCOPE_OWNER_UNKNOWN) {
        if (cached_owner == ROOT_SCOPE_OWNER_VISITING) {
            return ROOT_SCOPE_OWNER_NONE;
        }
        return cached_owner;
    }

    entry = &items[item_index];
    owner_cache[item_index] = ROOT_SCOPE_OWNER_VISITING;

    if (entry->name[0] == '\0') {
        owner_cache[item_index] = ROOT_SCOPE_OWNER_NONE;
        return ROOT_SCOPE_OWNER_NONE;
    }

    if (config_root_scope_has_path_scope(config)) {
        int scope_index = -1;
        int relation = mft_entry_root_scope_path_relation(
            config,
            items,
            index,
            count,
            entry,
            &scope_index
        );

        owner_cache[item_index] =
            relation == ROOT_SCOPE_PATH_RELATION_MATCH
                ? scope_index
                : ROOT_SCOPE_OWNER_NONE;
        return owner_cache[item_index];
    }

    if ((entry->flags & 0x0002U) != 0U && entry->parent == 5U) {
        selected_root_index = config_root_scope_index_for_name(config, entry->name);
        owner_cache[item_index] = selected_root_index >= 0
            ? selected_root_index
            : ROOT_SCOPE_OWNER_NONE;
        return owner_cache[item_index];
    }

    if (entry->record == 5 ||
        entry->parent == (uint64_t)entry->record ||
        entry->parent > (uint64_t)INT32_MAX) {
        owner_cache[item_index] = ROOT_SCOPE_OWNER_NONE;
        return ROOT_SCOPE_OWNER_NONE;
    }

    parent = find_entry_by_record_relaxed(
        items,
        index,
        count,
        entry->volume_index,
        entry->family,
        (int)entry->parent
    );
    if (parent == NULL) {
        owner_cache[item_index] = ROOT_SCOPE_OWNER_NONE;
        return ROOT_SCOPE_OWNER_NONE;
    }

    owner_cache[item_index] = selected_root_scope_index_for_entry(
        config,
        items,
        index,
        count,
        (size_t)(parent - items),
        owner_cache
    );
    return owner_cache[item_index];
}

static int selected_root_scope_cache_has_descendants_for_all(
    const Config *config,
    MftTable *table,
    char *missing_names,
    size_t missing_names_size,
    size_t *missing_count_out
)
{
    const MftEntry *items = NULL;
    size_t count = 0;
    RecordIndex *index = NULL;
    int *owner_cache = NULL;
    size_t *root_entries = NULL;
    size_t *total_entries = NULL;
    size_t i;
    size_t missing_count = 0;
    int ok = 1;

    if (missing_count_out != NULL) {
        *missing_count_out = 0;
    }
    if (missing_names != NULL && missing_names_size > 0U) {
        missing_names[0] = '\0';
    }
    if (config == NULL || table == NULL || config->root_scope_count == 0) {
        return 1;
    }

    pthread_mutex_lock(&table->mutex);
    if (!table_ensure_record_index(table)) {
        pthread_mutex_unlock(&table->mutex);
        return stop_requested() ? 0 : 1;
    }
    items = table->items;
    count = table->count;
    index = table->record_index;
    pthread_mutex_unlock(&table->mutex);

    if (count == 0 || items == NULL) {
        if (missing_names != NULL && missing_names_size > 0U) {
            size_t j;

            for (j = 0; j < config->root_scope_count; j++) {
                if (missing_names[0] != '\0') {
                    strncat(
                        missing_names,
                        ",",
                        missing_names_size - strlen(missing_names) - 1U
                    );
                }
                strncat(
                    missing_names,
                    config->root_scopes[j],
                    missing_names_size - strlen(missing_names) - 1U
                );
            }
        }
        if (missing_count_out != NULL) {
            *missing_count_out = config->root_scope_count;
        }
        return 0;
    }

    owner_cache = (int *)malloc(count * sizeof(*owner_cache));
    root_entries = (size_t *)calloc(config->root_scope_count, sizeof(*root_entries));
    total_entries = (size_t *)calloc(config->root_scope_count, sizeof(*total_entries));
    if (owner_cache == NULL || root_entries == NULL || total_entries == NULL) {
        free(total_entries);
        free(root_entries);
        free(owner_cache);
        return 1;
    }
    for (i = 0; i < count; i++) {
        owner_cache[i] = ROOT_SCOPE_OWNER_UNKNOWN;
    }

    for (i = 0; i < count; i++) {
        int owner = selected_root_scope_index_for_entry(
            config,
            items,
            index,
            count,
            i,
            owner_cache
        );

        if ((i & 0x3FFFU) == 0 && stop_requested()) {
            ok = 0;
            break;
        }
        if (owner < 0) {
            continue;
        }
        total_entries[owner]++;
        if ((items[i].flags & 0x0002U) != 0U &&
            items[i].parent == 5U &&
            config_root_scope_matches_name(config, items[i].name)) {
            root_entries[owner]++;
        }
    }

    if (ok) {
        for (i = 0; i < config->root_scope_count; i++) {
            if (total_entries[i] <= root_entries[i]) {
                missing_count++;
                if (missing_names != NULL && missing_names_size > 0U) {
                    if (missing_names[0] != '\0') {
                        strncat(
                            missing_names,
                            ",",
                            missing_names_size - strlen(missing_names) - 1U
                        );
                    }
                    strncat(
                        missing_names,
                        config->root_scopes[i],
                        missing_names_size - strlen(missing_names) - 1U
                    );
                }
            }
        }
    }

    if (missing_count_out != NULL) {
        *missing_count_out = ok ? missing_count : 0U;
    }
    free(total_entries);
    free(root_entries);
    free(owner_cache);
    return ok ? (missing_count == 0) : 0;
}

static int users_root_scope_primary_preview(
    Config *config,
    int *out_all_missing
)
{
    FILE *file = NULL;
    int image_fd = -1;
    MftTable table = {0};
    int table_mutex_initialized = 0;
    uint64_t scanned_bytes = 0;
    char missing_root_scopes[512];
    char kept_root_scopes[512];
    char selected_root_scopes[512];
    size_t missing_root_scope_count = 0;
    size_t removed_root_scope_count = 0;
    uint8_t *present_roots = NULL;
    size_t i;
    int all_missing = 0;
    int folder_search_failed = 0;
    int ok = 1;

    if (out_all_missing != NULL) {
        *out_all_missing = 0;
    }
    if (config == NULL || config->root_scope_count == 0U) {
        return 1;
    }
    if (pthread_mutex_init(&table.mutex, NULL) != 0) {
        log_info("Folders root preview skipped: could not initialize preview table state");
        return 1;
    }
    table_mutex_initialized = 1;

    missing_root_scopes[0] = '\0';
    kept_root_scopes[0] = '\0';
    selected_root_scopes[0] = '\0';
    config_root_scope_format_csv(config, selected_root_scopes, sizeof(selected_root_scopes));

    file = fopen(config->image_path, "rb");
    if (file == NULL) {
        log_info("Folders root preview skipped: could not reopen source: %s", config->image_path);
        return 1;
    }

    image_fd = open(config->image_path, O_RDONLY);
    if (image_fd < 0) {
        fclose(file);
        log_info("Folders root preview skipped: could not reopen source fd: %s", config->image_path);
        return 1;
    }

    if (!collect_primary_mft_entries_resolving_folder_terms(
            file,
            image_fd,
            config,
            &table,
            &scanned_bytes,
            &folder_search_failed)) {
        ok = stop_requested() || folder_search_failed ? 0 : 1;
        if (folder_search_failed) {
            all_missing = 1;
            if (out_all_missing != NULL) {
                *out_all_missing = 1;
            }
        } else if (!stop_requested()) {
            log_info("Folders root preview could not complete from primary $MFT; continuing with full scan");
        }
        goto cleanup;
    }
    present_roots = (uint8_t *)calloc(config->root_scope_count, sizeof(*present_roots));
    if (present_roots == NULL) {
        log_info("Folders root preview could not allocate root-presence state; continuing with full scan");
        goto cleanup;
    }

    if (config_root_scope_has_path_scope(config) && !table_ensure_record_index(&table)) {
        log_info("Folders root preview could not build path index; continuing with full scan");
        goto cleanup;
    }

    for (i = 0; i < table.count; i++) {
        const MftEntry *entry = &table.items[i];
        int root_index;

        if (config_root_scope_has_path_scope(config)) {
            int relation = mft_entry_root_scope_path_relation(
                config,
                table.items,
                table.record_index,
                table.count,
                entry,
                &root_index
            );

            if (relation == ROOT_SCOPE_PATH_RELATION_MATCH && root_index >= 0) {
                present_roots[root_index] = 1U;
            }
            continue;
        }

        if ((entry->flags & 0x0002U) == 0U ||
            entry->parent != 5U ||
            entry->name[0] == '\0') {
            continue;
        }

        root_index = config_root_scope_index_for_name(config, entry->name);
        if (root_index >= 0) {
            present_roots[root_index] = 1U;
        }
    }

    for (i = 0; i < config->root_scope_count; i++) {
        if (present_roots[i]) {
            continue;
        }
        missing_root_scope_count++;
        if (!config_scope_append_item_v1(
            missing_root_scopes,
            sizeof(missing_root_scopes),
            config->root_scopes[i])) {
            log_info("Folders preview missing-scope list was too long; continuing with full scan");
            goto cleanup;
        }
    }

    if (missing_root_scope_count == 0U) {
        log_info(
            "Folders preview: selected folders found in primary $MFT (%s); scanned=%.1f MiB",
            selected_root_scopes[0] != '\0' ? selected_root_scopes : "Users",
            (double)scanned_bytes / (1024.0 * 1024.0)
        );
        goto cleanup;
    }

    if (missing_root_scope_count >= config->root_scope_count) {
        all_missing = 1;
        if (out_all_missing != NULL) {
            *out_all_missing = 1;
        }
        if (config->root_scope_defaulted) {
            log_error(
                "Folder path default folder was not found in primary $MFT (%s); choose another folder, use --fold / for full root, or use --mode all",
                missing_root_scopes[0] != '\0' ? missing_root_scopes : selected_root_scopes
            );
        } else {
            log_error(
                "Folder path preview: none of the selected folders were found in primary $MFT (%s); choose another folder, use --fold / for full root, or use --mode all",
                missing_root_scopes[0] != '\0' ? missing_root_scopes : selected_root_scopes
            );
        }
        goto cleanup;
    }

    removed_root_scope_count = config_root_scope_prune_missing_csv_in_place(
        config,
        missing_root_scopes,
        kept_root_scopes,
        sizeof(kept_root_scopes)
    );
    if (removed_root_scope_count > 0U) {
        log_info(
            "Folders preview: selected folders missing in primary $MFT (%s); continuing with present folders: %s",
            missing_root_scopes[0] != '\0' ? missing_root_scopes : "unknown",
            kept_root_scopes[0] != '\0' ? kept_root_scopes : "(none)"
        );
    }

cleanup:
    free(present_roots);
    table_reset(&table);
    if (table_mutex_initialized) {
        pthread_mutex_destroy(&table.mutex);
    }
    if (image_fd >= 0) {
        close(image_fd);
    }
    if (file != NULL) {
        fclose(file);
    }
    return ok && !all_missing;
}

static void MFTPROBE_MAYBE_UNUSED append_parent_dirs(PathList *dirs, const char *file_path)
{
    char prefix[PATH_MAX_LEN];
    size_t len;
    size_t i;

    if (file_path == NULL || file_path[0] != '\\') {
        return;
    }

    len = strlen(file_path);
    for (i = 1; i < len; i++) {
        if (file_path[i] == '\\') {
            if (i >= sizeof(prefix)) {
                return;
            }
            memcpy(prefix, file_path, i);
            prefix[i] = '\0';
            append_path(dirs, prefix);
        }
    }
}

static RecordIndex *build_record_index(const MftEntry *items, size_t count)
{
    RecordIndex *index;
    size_t i;

    if (count == 0) {
        return NULL;
    }

    index = (RecordIndex *)malloc(count * sizeof(*index));
    if (index == NULL) {
        return NULL;
    }

    for (i = 0; i < count; i++) {
        if ((i & 0x3FFFU) == 0 && stop_requested()) {
            free(index);
            return NULL;
        }
        index[i].record = items[i].record;
        index[i].volume_index = items[i].volume_index;
        index[i].family = items[i].family;
        index[i].index = i;
    }
    if (stop_requested()) {
        free(index);
        return NULL;
    }
    qsort(index, count, sizeof(*index), compare_record_index);
    return index;
}

static const MftEntry *find_entry_by_record(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    uint32_t volume_index,
    uint32_t family,
    int record
)
{
    size_t lo = 0;
    size_t hi = count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2U;

        if (index[mid].volume_index < volume_index ||
            (index[mid].volume_index == volume_index && index[mid].family < family) ||
            (index[mid].volume_index == volume_index &&
             index[mid].family == family &&
             index[mid].record < record)) {
            lo = mid + 1U;
        } else {
            hi = mid;
        }
    }

    if (lo < count &&
        index[lo].volume_index == volume_index &&
        index[lo].family == family &&
        index[lo].record == record) {
        return &items[index[lo].index];
    }
    return NULL;
}

static const MftEntry *find_entry_by_record_relaxed(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    uint32_t volume_index,
    uint32_t family,
    int record
)
{
    const MftEntry *exact;
    size_t i;

    exact = find_entry_by_record(items, index, count, volume_index, family, record);
    if (exact != NULL) {
        return exact;
    }

    if (items == NULL || index == NULL) {
        return NULL;
    }

    for (i = 0; i < count; i++) {
        if (index[i].volume_index == volume_index &&
            index[i].record == record) {
            return &items[index[i].index];
        }
    }

    return NULL;
}

static int build_path_if_under_selected_root_scope(
    const Config *config,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    const char *prefix_root,
    char *out,
    size_t out_size
)
{
    const MftEntry *chain[256];
    const MftEntry *cur = entry;
    size_t chain_count = 0;
    size_t i;
    int found_root = 0;

    if (config == NULL ||
        out == NULL ||
        out_size == 0U ||
        config->root_scope_count == 0) {
        return 0;
    }
    out[0] = '\0';

    if (mft_entry_root_scope_path_relation(
            config,
            items,
            index,
            count,
            entry,
            NULL) != ROOT_SCOPE_PATH_RELATION_MATCH) {
        return 0;
    }

    while (cur != NULL && chain_count < (sizeof(chain) / sizeof(chain[0]))) {
        chain[chain_count++] = cur;
        if (cur->parent == 5U) {
            found_root = 1;
            break;
        }
        if (cur->record == 5 ||
            cur->parent == (uint64_t)cur->record ||
            cur->parent > (uint64_t)INT32_MAX) {
            break;
        }
        cur = find_entry_by_record_relaxed(
            items,
            index,
            count,
            cur->volume_index,
            cur->family,
            (int)cur->parent
        );
    }

    if (!found_root) {
        return 0;
    }

    if (prefix_root != NULL && prefix_root[0] != '\0') {
        snprintf(out, out_size, "\\%s", prefix_root);
    } else {
        snprintf(out, out_size, "\\");
    }

    for (i = chain_count; i > 0; i--) {
        const MftEntry *part = chain[i - 1U];
        int is_leaf = (i - 1U) == 0U;
        int is_anchor = (i == chain_count);

        if (part->record == 5 || part->name[0] == '\0') {
            continue;
        }
        if (!is_leaf && !is_anchor && (part->flags & 0x0002U) == 0U) {
            return 0;
        }
        if (strlen(out) > 1U) {
            strncat(out, "\\", out_size - strlen(out) - 1U);
        }
        strncat(out, part->name, out_size - strlen(out) - 1U);
    }

    return out[0] != '\0' && strcmp(out, "\\") != 0;
}

static int build_path_if_under_users_root(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    char *out,
    size_t out_size
);

static int users_name_is_recycle_root(const char *name)
{
    return name != NULL &&
           (strcasecmp(name, "$Recycle.Bin") == 0 ||
            strcasecmp(name, "Recycler") == 0 ||
            strcasecmp(name, "Recycled") == 0);
}

enum {
    ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT = 1 << 0,
    ENTRY_DELETED_SOURCE_FLAG_RECYCLE = 1 << 1
};

static unsigned entry_deleted_source_flags_in_table(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry
)
{
    const MftEntry *current = entry;
    size_t depth = 0;
    unsigned flags = 0U;

    if (entry == NULL) {
        return 0U;
    }
    if ((entry->flags & 0x0001U) == 0U) {
        flags |= ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT;
    }

    while (current != NULL && depth++ < 256U) {
        if (users_name_is_recycle_root(current->name)) {
            flags |= ENTRY_DELETED_SOURCE_FLAG_RECYCLE;
            break;
        }
        if (current->record == 5 ||
            current->parent == (uint64_t)current->record ||
            current->parent > (uint64_t)INT32_MAX) {
            break;
        }
        current = find_entry_by_record_relaxed(
            items,
            index,
            count,
            current->volume_index,
            current->family,
            (int)current->parent);
    }

    return flags;
}

static int entry_is_deleted_like_in_table(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry
)
{
    return entry_deleted_source_flags_in_table(items, index, count, entry) != 0U;
}

static int build_path_for_deleted_recovery(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    char *out,
    size_t out_size
)
{
    const MftEntry *chain[256];
    const MftEntry *cur = entry;
    unsigned deleted_source_flags = 0U;
    size_t chain_count = 0;
    size_t anchor_index = SIZE_MAX;
    size_t i;

    if (out == NULL || out_size == 0) {
        return 0;
    }
    out[0] = '\0';
    if (entry == NULL || entry->name[0] == '\0') {
        return 0;
    }

    deleted_source_flags = entry_deleted_source_flags_in_table(items, index, count, entry);

    while (cur != NULL && chain_count < 256U) {
        chain[chain_count] = cur;
        if (users_name_is_recycle_root(cur->name) || is_users_root_entry(cur)) {
            anchor_index = chain_count;
            chain_count++;
            break;
        }
        chain_count++;
        if (cur->record == 5 || cur->parent == (uint64_t)cur->record ||
            cur->parent > (uint64_t)INT32_MAX) {
            break;
        }
        cur = find_entry_by_record_relaxed(
            items,
            index,
            count,
            cur->volume_index,
            cur->family,
            (int)cur->parent);
    }

    if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_RECYCLE) != 0U) {
        snprintf(out, out_size, "\\deleted\\Recycle.Bin");
    } else {
        snprintf(out, out_size, "\\deleted");
    }
    if (anchor_index != SIZE_MAX) {
        for (i = anchor_index + 1U; i > 0; i--) {
            const MftEntry *part = chain[i - 1U];
            int is_leaf = (i - 1U) == 0U;
            int is_anchor = (i - 1U) == anchor_index;

            if (part->record == 5 || part->name[0] == '\0') {
                continue;
            }
            if (is_anchor && users_name_is_recycle_root(part->name)) {
                continue;
            }
            if (!is_leaf &&
                !is_anchor &&
                (part->flags & 0x0002U) == 0U) {
                continue;
            }
            strncat(out, "\\", out_size - strlen(out) - 1U);
            strncat(out, part->name, out_size - strlen(out) - 1U);
        }
        return out[0] != '\0' && strcmp(out, "\\deleted") != 0;
    }

    if (strlen(out) + 1U < out_size) {
        strncat(out, "\\", out_size - strlen(out) - 1U);
        strncat(out, entry->name, out_size - strlen(out) - 1U);
    }
    return out[0] != '\0' && strcmp(out, "\\deleted") != 0;
}

static int build_path_from_ntfs_root(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    char *out,
    size_t out_size
)
{
    const MftEntry *chain[256];
    const MftEntry *cur = entry;
    size_t chain_count = 0;
    size_t i;
    int found_root = 0;

    if (out_size == 0) {
        return 0;
    }
    out[0] = '\0';

    while (cur != NULL && chain_count < 256U) {
        chain[chain_count++] = cur;
        if (cur->record == 5 || cur->parent == 5U) {
            found_root = 1;
            break;
        }
        if (cur->parent == (uint64_t)cur->record ||
            cur->parent > (uint64_t)INT32_MAX) {
            break;
        }
        cur = find_entry_by_record_relaxed(
            items,
            index,
            count,
            cur->volume_index,
            cur->family,
            (int)cur->parent);
    }

    if (!found_root) {
        return 0;
    }

    for (i = 1; i + 1U < chain_count; i++) {
        if ((chain[i]->flags & 0x0002U) == 0U) {
            return 0;
        }
    }

    snprintf(out, out_size, "\\");
    for (i = chain_count; i > 0; i--) {
        const MftEntry *part = chain[i - 1U];

        if (part->record == 5 || part->name[0] == '\0') {
            continue;
        }
        if (strlen(out) > 1U) {
            strncat(out, "\\", out_size - strlen(out) - 1U);
        }
        strncat(out, part->name, out_size - strlen(out) - 1U);
    }
    return out[0] != '\0' && strcmp(out, "\\") != 0;
}

static int build_path_for_selected_recovery(
    const Config *config,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    char *out,
    size_t out_size
)
{
    int is_deleted_like;

    if (config == NULL) {
        return 0;
    }
    if (config->generic_file_targets && config->root_scope_count == 0) {
        return build_path_from_ntfs_root(items, index, count, entry, out, out_size);
    }
    if (config->root_scope_count > 0) {
        if (!config->has_deleted_filter) {
            return build_path_if_under_selected_root_scope(
                config,
                items,
                index,
                count,
                entry,
                NULL,
                out,
                out_size
            );
        }

        is_deleted_like = entry_is_deleted_like_in_table(items, index, count, entry);
        if (config->deleted_value == 2) {
            if (is_deleted_like) {
                return build_path_if_under_selected_root_scope(
                    config,
                    items,
                    index,
                    count,
                    entry,
                    "deleted",
                    out,
                    out_size
                );
            }
            return build_path_if_under_selected_root_scope(
                config,
                items,
                index,
                count,
                entry,
                NULL,
                out,
                out_size
            );
        }
        if (is_deleted_like != config->deleted_value) {
            return 0;
        }
        return build_path_if_under_selected_root_scope(
            config,
            items,
            index,
            count,
            entry,
            config->deleted_value == 1 ? "deleted" : NULL,
            out,
            out_size
        );
    }

    if (!config->has_deleted_filter) {
        return build_path_if_under_users_root(items, index, count, entry, out, out_size);
    }

    is_deleted_like = entry_is_deleted_like_in_table(items, index, count, entry);
    if (config->deleted_value == 2) {
        if (is_deleted_like) {
            return build_path_for_deleted_recovery(items, index, count, entry, out, out_size);
        }
        return build_path_if_under_users_root(items, index, count, entry, out, out_size);
    }
    if (is_deleted_like != config->deleted_value) {
        return 0;
    }
    if (config->deleted_value == 1) {
        return build_path_for_deleted_recovery(items, index, count, entry, out, out_size);
    }

    return build_path_if_under_users_root(items, index, count, entry, out, out_size);
}

static int build_path_if_under_users_root(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    char *out,
    size_t out_size
)
{
    const MftEntry *chain[256];
    const MftEntry *cur = entry;
    size_t chain_count = 0;
    size_t i;
    int found_users_root = 0;

    if (out_size == 0) {
        return 0;
    }
    out[0] = '\0';

    while (cur != NULL && chain_count < 256U) {
        chain[chain_count++] = cur;
        if (is_users_root_entry(cur)) {
            found_users_root = 1;
            break;
        }
        if (cur->record == 5 || cur->parent == (uint64_t)cur->record ||
            cur->parent > (uint64_t)INT32_MAX) {
            break;
        }
        cur = find_entry_by_record_relaxed(
            items,
            index,
            count,
            cur->volume_index,
            cur->family,
            (int)cur->parent);
    }

    if (!found_users_root) {
        return 0;
    }

    for (i = 1; i + 1U < chain_count; i++) {
        if ((chain[i]->flags & 0x0002U) == 0U) {
            return 0;
        }
    }

    snprintf(out, out_size, "\\");
    for (i = chain_count; i > 0; i--) {
        const MftEntry *part = chain[i - 1U];

        if (part->record == 5 || part->name[0] == '\0') {
            continue;
        }
        if (strlen(out) > 1) {
            strncat(out, "\\", out_size - strlen(out) - 1U);
        }
        strncat(out, part->name, out_size - strlen(out) - 1U);
    }
    return out[0] != '\0' && strcmp(out, "\\") != 0;
}

static int targeted_build_users_relative_compare_path(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    char *out,
    size_t out_size
)
{
    char full_path[PATH_MAX_LEN];
    const char *src;
    size_t out_pos = 0;

    if (out == NULL || out_size == 0) {
        return 0;
    }
    out[0] = '\0';

    if (!build_path_if_under_users_root(
            items,
            index,
            count,
            entry,
            full_path,
            sizeof(full_path))) {
        return 0;
    }

    src = full_path;
    if (*src == '\\' || *src == '/') {
        src++;
    }
    if ((src[0] == 'U' || src[0] == 'u') &&
        (src[1] == 'S' || src[1] == 's') &&
        (src[2] == 'E' || src[2] == 'e') &&
        (src[3] == 'R' || src[3] == 'r') &&
        (src[4] == 'S' || src[4] == 's') &&
        (src[5] == '\\' || src[5] == '/')) {
        src += 6;
    }

    while (*src != '\0' && out_pos + 1U < out_size) {
        out[out_pos++] = (*src == '\\') ? '/' : *src;
        src++;
    }
    out[out_pos] = '\0';
    return out[0] != '\0';
}

static int targeted_find_recover_path_match(
    const RecoverPathList *paths,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    char *out_rel_path,
    size_t out_rel_path_size
)
{
    char users_rel_path[PATH_MAX_LEN];
    char key[PATH_MAX_LEN];
    const char *suffix;

    if (out_rel_path != NULL && out_rel_path_size > 0) {
        out_rel_path[0] = '\0';
    }
    if (paths == NULL || entry == NULL || out_rel_path == NULL || out_rel_path_size == 0) {
        return 0;
    }

    if (!targeted_build_users_relative_compare_path(
            items,
            index,
            count,
            entry,
            users_rel_path,
            sizeof(users_rel_path))) {
        return 0;
    }

    recover_path_build_key(users_rel_path, key, sizeof(key));
    if (key[0] == '\0') {
        return 0;
    }
    if (recover_path_list_lookup_output(
            paths,
            key,
            entry->data_size,
            out_rel_path,
            out_rel_path_size)) {
        return 1;
    }

    suffix = strchr(key, '/');
    while (suffix != NULL && suffix[1] != '\0') {
        suffix++;
        if (recover_path_list_lookup_output(
                paths,
                suffix,
                entry->data_size,
                out_rel_path,
                out_rel_path_size)) {
            return 1;
        }
        suffix = strchr(suffix, '/');
    }

    return 0;
}

static int recovery_plan_init(RecoveryPlan *plan)
{
    if (plan == NULL) {
        return 0;
    }

    memset(plan, 0, sizeof(*plan));
    return pthread_mutex_init(&plan->mutex, NULL) == 0;
}

static int recovery_target_is_terminal(RecoveryTargetState state)
{
    return state == TARGET_DONE ||
           state == TARGET_MISSED ||
           state == TARGET_SKIPPED;
}

static int recovery_target_is_scheduler_complete(RecoveryTargetState state)
{
    return recovery_target_is_terminal(state) ||
           state == TARGET_QUEUED ||
           state == TARGET_DEFERRED;
}

static uint64_t recovery_target_schedule_offset(const RecoveryTarget *target)
{
    if (target == NULL || recovery_target_is_scheduler_complete(target->state)) {
        return UINT64_MAX;
    }
    if (target->state == TARGET_ACTIVE) {
        return target->next_offset;
    }
    return target->abs_offset;
}

static void recovery_plan_resort_scheduler_locked(RecoveryPlan *plan)
{
    if (plan == NULL) {
        return;
    }
    if (plan->count > 1) {
        qsort(plan->items, plan->count, sizeof(*plan->items), compare_recovery_targets_by_schedule);
        recovery_plan_mark_indexes_dirty_locked(plan);
    }
    plan->scheduler_dirty = 0;
    plan->scheduler_index = 0;
    recovery_plan_advance_scheduler_locked(plan);
}

static void recovery_plan_ensure_scheduler_sorted_locked(RecoveryPlan *plan)
{
    if (plan == NULL) {
        return;
    }
    if (plan->scheduler_dirty) {
        recovery_plan_resort_scheduler_locked(plan);
    } else {
        recovery_plan_advance_scheduler_locked(plan);
    }
}

static void recovery_target_close_and_remove(RecoveryTarget *target)
{
    if (target == NULL) {
        return;
    }
    if (target->file != NULL) {
        fclose(target->file);
        target->file = NULL;
    }
    if (target->output_path[0] != '\0') {
        (void)remove(target->output_path);
    }
}

static int recovery_target_output_already_present(const RecoveryTarget *target)
{
    return target != NULL &&
           target->output_path[0] != '\0' &&
           target->size > 0 &&
           path_has_size(target->output_path, target->size);
}

static void recovery_plan_advance_scheduler_locked(RecoveryPlan *plan)
{
    if (plan == NULL) {
        return;
    }
    while (plan->scheduler_index < plan->count &&
           recovery_target_is_scheduler_complete(plan->items[plan->scheduler_index].state)) {
        plan->scheduler_index++;
    }
}

static void recovery_plan_note_terminal_transition_locked(
    RecoveryPlan *plan,
    RecoveryTargetState before,
    RecoveryTargetState after
)
{
    if (plan == NULL || before == after || recovery_target_is_terminal(before)) {
        return;
    }
    if (after == TARGET_DONE) {
        plan->recovered++;
    } else if (after == TARGET_SKIPPED) {
        plan->skipped++;
    } else if (after == TARGET_MISSED) {
        plan->missed++;
    } else if (after == TARGET_DEFERRED) {
        plan->deferred++;
    }
}

static void recovery_plan_mark_passed_locked(RecoveryPlan *plan, uint64_t miss_before)
{
    if (plan == NULL) {
        return;
    }

    recovery_plan_ensure_scheduler_sorted_locked(plan);
    while (plan->scheduler_index < plan->count) {
        RecoveryTarget *target = &plan->items[plan->scheduler_index];

        if (recovery_target_is_scheduler_complete(target->state)) {
            plan->scheduler_index++;
            continue;
        }
        if (target->state == TARGET_PENDING) {
            if (target->abs_offset >= miss_before) {
                break;
            }
            if (recovery_target_output_already_present(target)) {
                target->state = TARGET_DONE;
                plan->scheduler_index++;
                continue;
            }
            target->state = TARGET_DEFERRED;
            snprintf(
                target->last_error,
                sizeof(target->last_error),
                "target discovered after stream passed byte %llu; deferred for post-scan recovery",
                (unsigned long long)target->abs_offset
            );
            plan->deferred++;
            plan->scheduler_index++;
            continue;
        }
        if (target->state == TARGET_ACTIVE) {
            if (target->next_offset >= miss_before) {
                break;
            }
            if (recovery_target_output_already_present(target)) {
                target->state = TARGET_DONE;
                plan->scheduler_index++;
                continue;
            }
            recovery_target_close_and_remove(target);
            target->state = TARGET_DEFERRED;
            snprintf(
                target->last_error,
                sizeof(target->last_error),
                "stream skipped active target byte %llu; deferred for post-scan recovery",
                (unsigned long long)target->next_offset
            );
            plan->deferred++;
            plan->scheduler_index++;
            continue;
        }
        break;
    }
}

static void recovery_plan_close_open_files(RecoveryPlan *plan)
{
    size_t i;

    if (plan == NULL) {
        return;
    }

    for (i = 0; i < plan->count; i++) {
        if (plan->items[i].file != NULL) {
            fclose(plan->items[i].file);
            plan->items[i].file = NULL;
            if (plan->items[i].state == TARGET_ACTIVE) {
                plan->items[i].state = TARGET_MISSED;
                plan->missed++;
                (void)remove(plan->items[i].output_path);
            }
        }
    }
}

static void recovery_plan_destroy(RecoveryPlan *plan)
{
    if (plan == NULL) {
        return;
    }

    pthread_mutex_lock(&plan->mutex);
    recovery_plan_close_open_files(plan);
    free(plan->items);
    free(plan->target_index_slots);
    free(plan->output_index_slots);
    plan->items = NULL;
    plan->count = 0;
    plan->capacity = 0;
    plan->target_index_slots = NULL;
    plan->target_index_capacity = 0;
    plan->target_index_count = 0;
    plan->output_index_slots = NULL;
    plan->output_index_capacity = 0;
    plan->output_index_count = 0;
    pthread_mutex_unlock(&plan->mutex);
    pthread_mutex_destroy(&plan->mutex);
}

static RecoveryTarget *recovery_plan_find_target(
    RecoveryPlan *plan,
    uint32_t format_id,
    int record,
    uint32_t family,
    uint64_t abs_offset
)
{
    size_t i;

    if (plan == NULL) {
        return NULL;
    }

    if (recovery_plan_ensure_target_index_locked(plan) &&
        plan->target_index_slots != NULL &&
        plan->target_index_capacity > 0) {
        uint64_t hash = recovery_target_key_hash(format_id, record, family, abs_offset);
        size_t pos = (size_t)hash & (plan->target_index_capacity - 1U);
        size_t start = pos;

        while (plan->target_index_slots[pos].used) {
            if (recovery_target_index_slot_matches(
                    &plan->target_index_slots[pos],
                    format_id,
                    record,
                    family,
                    abs_offset)) {
                size_t index = plan->target_index_slots[pos].index;

                if (index < plan->count &&
                    plan->items[index].format_id == format_id &&
                    plan->items[index].record == record &&
                    plan->items[index].family == family &&
                    plan->items[index].abs_offset == abs_offset) {
                    return &plan->items[index];
                }
            }
            pos = (pos + 1U) & (plan->target_index_capacity - 1U);
            if (pos == start) {
                break;
            }
        }

        return NULL;
    }

    for (i = 0; i < plan->count; i++) {
        if (plan->items[i].format_id == format_id &&
            plan->items[i].record == record &&
            plan->items[i].family == family &&
            plan->items[i].abs_offset == abs_offset) {
            return &plan->items[i];
        }
    }

    return NULL;
}

static RecoveryTarget *recovery_plan_find_target_by_output(
    RecoveryPlan *plan,
    uint32_t format_id,
    uint64_t abs_offset,
    const char *output_path
)
{
    size_t i;

    if (plan == NULL || output_path == NULL || output_path[0] == '\0') {
        return NULL;
    }

    if (recovery_plan_ensure_output_index_locked(plan) &&
        plan->output_index_slots != NULL &&
        plan->output_index_capacity > 0) {
        uint64_t path_hash = hash_string(output_path);
        uint64_t hash = hash_u64(path_hash ^ abs_offset ^ ((uint64_t)format_id << 32));
        size_t pos = (size_t)hash & (plan->output_index_capacity - 1U);
        size_t start = pos;

        while (plan->output_index_slots[pos].used) {
            if (recovery_output_index_slot_matches(
                    &plan->output_index_slots[pos],
                    format_id,
                    abs_offset,
                    path_hash)) {
                size_t index = plan->output_index_slots[pos].index;

                if (index < plan->count &&
                    plan->items[index].format_id == format_id &&
                    plan->items[index].abs_offset == abs_offset &&
                    strcmp(plan->items[index].output_path, output_path) == 0) {
                    return &plan->items[index];
                }
            }
            pos = (pos + 1U) & (plan->output_index_capacity - 1U);
            if (pos == start) {
                break;
            }
        }

        return NULL;
    }

    for (i = 0; i < plan->count; i++) {
        if (plan->items[i].format_id == format_id &&
            plan->items[i].abs_offset == abs_offset &&
            strcmp(plan->items[i].output_path, output_path) == 0) {
            return &plan->items[i];
        }
    }

    return NULL;
}

static int recovery_plan_add_target(
    RecoveryPlan *plan,
    const Config *config,
    const RecoveryFormat *format,
    const MftEntry *entry,
    const char *mft_path
)
{
    RecoveryTarget *new_items;
    RecoveryTarget prepared;
    uint64_t abs_offset;
    uint64_t available_bytes;
    uint64_t target_size;
    RecoveryRun runs[RECOVERY_TARGET_MAX_RUNS];
    size_t run_count = 0;
    int run_truncated = 0;
    int partial_target = 0;
    int output_ok;

    if (plan == NULL || config == NULL || entry == NULL || mft_path == NULL ||
        entry->data_size == 0) {
        return 1;
    }

    abs_offset = mft_data_offset_for_entry(config, entry);
    available_bytes = mft_run_available_bytes(config, entry);

    if (abs_offset == 0) {
        return 1;
    }
    if (!recovery_runs_from_entry(config, entry, runs, &run_count, &run_truncated)) {
        return 1;
    }
    if (!recovery_runs_within_source(config, runs, run_count)) {
        return 1;
    }

    target_size = entry->data_size;
    if (run_truncated || available_bytes < entry->data_size) {
        if (format == NULL ||
            !mftprobe_format_allows_partial_target(format, available_bytes)) {
            return 1;
        }
        target_size = available_bytes;
        partial_target = 1;
    }

    if (recovery_plan_find_target(
        plan,
        format != NULL ? format->format_id : 0U,
        entry->record,
        entry->family,
        abs_offset
    ) != NULL) {
        return 1;
    }

    if (plan->count == plan->capacity) {
        size_t new_capacity = plan->capacity == 0 ? 128U : plan->capacity * 2U;
        new_items = (RecoveryTarget *)realloc(
            plan->items,
            new_capacity * sizeof(*new_items)
        );
        if (new_items == NULL) {
            return 0;
        }
        plan->items = new_items;
        plan->capacity = new_capacity;
    }

    memset(&prepared, 0, sizeof(prepared));
    prepared.format_id = format != NULL ? format->format_id : 0U;
    prepared.validator_id =
        format != NULL ? format->validator_id : RECOVERY_VALIDATOR_NONE;
    if (format != NULL) {
        snprintf(prepared.extension, sizeof(prepared.extension), "%s", format->default_extension);
        memcpy(prepared.blob_start, format->blob_start, sizeof(prepared.blob_start));
        prepared.blob_start_length = format->blob_start_length;
    }
    prepared.abs_offset = abs_offset;
    prepared.size = target_size;
    prepared.expected_size = entry->data_size;
    prepared.remaining = target_size;
    prepared.next_offset = abs_offset;
    memcpy(prepared.runs, runs, run_count * sizeof(*runs));
    prepared.run_count = run_count;
    prepared.run_index = 0;
    prepared.run_truncated = run_truncated;
    prepared.record = entry->record;
    prepared.family = entry->family;
    prepared.created_unix = filetime_to_unix_time_local(entry->created_filetime);
    prepared.state = TARGET_PENDING;
    snprintf(prepared.source_path, sizeof(prepared.source_path), "%s", mft_path);
    recovery_output_path_from_mft_path(
        prepared.output_path,
        sizeof(prepared.output_path),
        config->out_dir,
        mft_path
    );
    if (partial_target && !append_partial_suffix(prepared.output_path, sizeof(prepared.output_path))) {
        return 0;
    }
    output_ok = prepared.output_path[0] != '\0';
    if (!output_ok) {
        return 0;
    }
    if (recovery_plan_find_target_by_output(
            plan,
            prepared.format_id,
            prepared.abs_offset,
            prepared.output_path) != NULL) {
        return 1;
    }
    if (plan->have_miss_before_offset && prepared.abs_offset < plan->miss_before_offset) {
        prepared.state = TARGET_DEFERRED;
        snprintf(
            prepared.last_error,
            sizeof(prepared.last_error),
            "target discovered after stream passed byte %llu; deferred for post-scan recovery",
            (unsigned long long)prepared.abs_offset
        );
        plan->deferred++;
    }
    plan->items[plan->count++] = prepared;
    recovery_plan_note_target_appended_locked(plan, plan->count - 1U);

    return 1;
}

static int live_index_build_path_for_selected_recovery(
    const Config *config,
    LiveIndexState *state,
    const MftEntry *entry,
    char *out,
    size_t out_size,
    LiveRecordKey *missing_key
)
{
    const MftEntry *chain[256];
    const MftEntry *cur = entry;
    size_t chain_count = 0;
    size_t i;
    int found_users_root = 0;

    if (missing_key != NULL) {
        memset(missing_key, 0, sizeof(*missing_key));
        missing_key->record = -1;
    }
    if (out_size == 0) {
        return 0;
    }
    out[0] = '\0';

    if (config != NULL && config->root_scope_count > 0) {
        char normalized_path[PATH_MAX_LEN];
        int found_root = 0;

        while (cur != NULL && chain_count < 256U) {
            chain[chain_count++] = cur;
            if (cur->parent == 5U) {
                found_root = 1;
                break;
            }
            if (cur->record == 5 || cur->parent == (uint64_t)cur->record ||
                cur->parent > (uint64_t)INT32_MAX) {
                break;
            }
            {
                LiveRecordKey parent_key;

                parent_key.volume_index = cur->volume_index;
                parent_key.family = cur->family;
                parent_key.record = (int)cur->parent;
                cur = live_index_find_entry(state, parent_key);
                if (cur == NULL) {
                    if (missing_key != NULL) {
                        *missing_key = parent_key;
                    }
                    return 0;
                }
            }
        }

        if (!found_root) {
            return 0;
        }

        normalized_path[0] = '\0';
        for (i = chain_count; i > 0; i--) {
            const MftEntry *part = chain[i - 1U];

            if (part->record == 5) {
                continue;
            }
            if (!append_normalized_scope_path_part(
                    normalized_path,
                    sizeof(normalized_path),
                    part->name)) {
                return 0;
            }
        }
        if (normalized_scope_path_relation(
                config,
                normalized_path,
                0,
                NULL) != ROOT_SCOPE_PATH_RELATION_MATCH) {
            return 0;
        }

        snprintf(out, out_size, "\\");
        for (i = chain_count; i > 0; i--) {
            const MftEntry *part = chain[i - 1U];
            int is_leaf = (i - 1U) == 0U;

            if (part->record == 5 || part->name[0] == '\0') {
                continue;
            }
            if (!is_leaf && (part->flags & 0x0002U) == 0U) {
                return 0;
            }
            if (strlen(out) > 1U) {
                strncat(out, "\\", out_size - strlen(out) - 1U);
            }
            strncat(out, part->name, out_size - strlen(out) - 1U);
        }
        return out[0] != '\0' && strcmp(out, "\\") != 0;
    }

    if (config != NULL && config->generic_file_targets) {
        int found_root = 0;

        while (cur != NULL && chain_count < 256U) {
            chain[chain_count++] = cur;
            if (cur->record == 5 || cur->parent == 5U) {
                found_root = 1;
                break;
            }
            if (cur->parent == (uint64_t)cur->record ||
                cur->parent > (uint64_t)INT32_MAX) {
                break;
            }
            {
                LiveRecordKey parent_key;

                parent_key.volume_index = cur->volume_index;
                parent_key.family = cur->family;
                parent_key.record = (int)cur->parent;
                cur = live_index_find_entry(state, parent_key);
                if (cur == NULL) {
                    if (missing_key != NULL) {
                        *missing_key = parent_key;
                    }
                    return 0;
                }
            }
        }

        if (!found_root) {
            return 0;
        }
        for (i = 1; i + 1U < chain_count; i++) {
            if ((chain[i]->flags & 0x0002U) == 0U) {
                return 0;
            }
        }

        snprintf(out, out_size, "\\");
        for (i = chain_count; i > 0; i--) {
            const MftEntry *part = chain[i - 1U];

            if (part->record == 5 || part->name[0] == '\0') {
                continue;
            }
            if (strlen(out) > 1U) {
                strncat(out, "\\", out_size - strlen(out) - 1U);
            }
            strncat(out, part->name, out_size - strlen(out) - 1U);
        }
        return out[0] != '\0' && strcmp(out, "\\") != 0;
    }

    while (cur != NULL && chain_count < 256U) {
        chain[chain_count++] = cur;
        if (is_users_root_entry(cur)) {
            found_users_root = 1;
            break;
        }
        if (cur->record == 5 || cur->parent == (uint64_t)cur->record ||
            cur->parent > (uint64_t)INT32_MAX) {
            break;
        }
        {
            LiveRecordKey parent_key;

            parent_key.volume_index = cur->volume_index;
            parent_key.family = cur->family;
            parent_key.record = (int)cur->parent;
            cur = live_index_find_entry(state, parent_key);
            if (cur == NULL) {
                if (missing_key != NULL) {
                    *missing_key = parent_key;
                }
                return 0;
            }
        }
    }

    if (!found_users_root) {
        return 0;
    }

    for (i = 1; i + 1U < chain_count; i++) {
        if ((chain[i]->flags & 0x0002U) == 0U) {
            return 0;
        }
    }

    snprintf(out, out_size, "\\");
    for (i = chain_count; i > 0; i--) {
        const MftEntry *part = chain[i - 1U];

        if (part->record == 5 || part->name[0] == '\0') {
            continue;
        }
        if (strlen(out) > 1) {
            strncat(out, "\\", out_size - strlen(out) - 1U);
        }
        strncat(out, part->name, out_size - strlen(out) - 1U);
    }
    return out[0] != '\0' && strcmp(out, "\\") != 0;
}

static int live_index_try_selected_file(
    LiveIndexWorker *worker,
    LiveIndexState *state,
    size_t table_index,
    LiveRecordKey *missing_key
)
{
    MftEntry entry;
    char full_path[PATH_MAX_LEN];
    const RecoveryFormat *format;
    int path_ok;
    size_t count_before_add = 0U;

    if (missing_key != NULL) {
        memset(missing_key, 0, sizeof(*missing_key));
        missing_key->record = -1;
    }

    pthread_mutex_lock(&worker->table->mutex);
    if (table_index >= worker->table->count) {
        pthread_mutex_unlock(&worker->table->mutex);
        return 1;
    }
    entry = worker->table->items[table_index];
    format = mftprobe_format_select_for_entry(worker->config, &entry);
    if (format == NULL &&
        !entry_is_generic_file_candidate(worker->config, &entry)) {
        pthread_mutex_unlock(&worker->table->mutex);
        return 1;
    }

    if (worker->config->has_deleted_filter) {
        pthread_mutex_unlock(&worker->table->mutex);
        return 1;
    }
    if (!config_entry_effective_date_matches_local(worker->config, format, &entry)) {
        pthread_mutex_unlock(&worker->table->mutex);
        return 1;
    }
    path_ok = live_index_build_path_for_selected_recovery(
        worker->config,
        state,
        &worker->table->items[table_index],
        full_path,
        sizeof(full_path),
        missing_key);
    pthread_mutex_unlock(&worker->table->mutex);

    if (!path_ok) {
        return 1;
    }
    ATOMIC_ADD_U64(&worker->path_ready_candidates, 1U);

    pthread_mutex_lock(&worker->recovery_plan->mutex);
    count_before_add = worker->recovery_plan->count;
    if (!recovery_plan_add_target(
            worker->recovery_plan,
            worker->config,
            format,
            &entry,
            full_path)) {
        pthread_mutex_unlock(&worker->recovery_plan->mutex);
        return 0;
    }
    ATOMIC_ADD_U64(&worker->targets_attempted, 1U);
    if (worker->recovery_plan->count > count_before_add) {
        ATOMIC_ADD_U64(&worker->targets_appended, 1U);
    }
    pthread_mutex_unlock(&worker->recovery_plan->mutex);
    return 1;
}

static int live_index_retry_pending_for_key(
    LiveIndexWorker *worker,
    LiveIndexState *state,
    LiveRecordKey key
)
{
    size_t pending_index = live_index_take_pending_for_key(state, key);

    while (pending_index != SIZE_MAX) {
        PendingSelected *pending = &state->pending_items[pending_index];
        size_t next = pending->next;
        LiveRecordKey missing_key;

        pending->active = 0;
        pending->next = SIZE_MAX;
        if (!live_index_try_selected_file(worker, state, pending->table_index, &missing_key)) {
            return 0;
        }
        if (missing_key.record >= 0) {
            if (!live_index_pending_insert(state, pending->table_index, missing_key)) {
                return 0;
            }
            worker->pending_waits_created++;
        }

        pending_index = next;
    }

    return 1;
}

static int recovery_plan_refresh_from_table(
    RecoveryPlan *plan,
    const Config *config,
    MftTable *table
)
{
    double started_at;
    double elapsed;
    double phase_started_at;
    double snapshot_seconds = 0.0;
    double index_seconds = 0.0;
    double select_seconds = 0.0;
    double last_progress_published_at = 0.0;
    const MftEntry *items = NULL;
    RecordIndex *index = NULL;
    size_t count = 0;
    size_t i;
    size_t format_candidates = 0;
    size_t deleted_like_candidates = 0;
    size_t recycle_only_candidates = 0;
    size_t deleted_bit_only_candidates = 0;
    size_t deleted_and_recycle_candidates = 0;
    size_t source_recycle_only_candidates = 0;
    size_t source_deleted_bit_only_candidates = 0;
    size_t source_deleted_and_recycle_candidates = 0;
    size_t path_candidates = 0;
    size_t path_ok_recycle_only = 0;
    size_t path_ok_deleted_bit_only = 0;
    size_t path_ok_deleted_and_recycle = 0;
    size_t attempted_targets = 0;
    size_t appended_targets = 0;
    size_t appended_recycle_only = 0;
    size_t appended_deleted_bit_only = 0;
    size_t appended_deleted_and_recycle = 0;
    int ok = 1;
    int profile_deleted = 0;

    if (plan == NULL || config == NULL || table == NULL) {
        return 0;
    }

    started_at = monotonic_seconds();
    profile_deleted = config->has_deleted_filter &&
                      (config->deleted_value == 1 || config->deleted_value == 2);

    if (stop_requested()) {
        return 0;
    }
    log_set_working_activity("building folders targets");
    phase_started_at = monotonic_seconds();
    /*
     * This refresh path is only called when the table is quiescent
     * (before worker threads start, after they have joined, or in
     * cache-only/direct-recover flows). Avoid cloning the whole MFT
     * table here; the extra copy becomes very expensive on large maps.
     */
    pthread_mutex_lock(&table->mutex);
    items = table->items;
    count = table->count;
    pthread_mutex_unlock(&table->mutex);
    snapshot_seconds = monotonic_seconds() - phase_started_at;

    if (stop_requested()) {
        return 0;
    }

    phase_started_at = monotonic_seconds();
    log_set_working_activity("building folders targets index");
    pthread_mutex_lock(&table->mutex);
    if (!table_ensure_record_index(table)) {
        pthread_mutex_unlock(&table->mutex);
        return stop_requested() ? 0 : 0;
    }
    items = table->items;
    count = table->count;
    index = table->record_index;
    pthread_mutex_unlock(&table->mutex);
    index_seconds = monotonic_seconds() - phase_started_at;

    if (stop_requested()) {
        return 0;
    }

    log_verbose("Refreshing recovery plan from MFT map: entries=%zu", count);
    publish_users_loop_activity_progress(
        "building folders targets",
        0U,
        count,
        &last_progress_published_at
    );
    phase_started_at = monotonic_seconds();
    pthread_mutex_lock(&plan->mutex);
    for (i = 0; i < count; i++) {
        char full_path[PATH_MAX_LEN];
        const RecoveryFormat *format;
        unsigned deleted_source_flags = 0U;
        size_t count_before_add = 0U;

        if ((i & 0x3FFFU) == 0 && stop_requested()) {
            ok = 0;
            break;
        }
        if ((i & 0x3FFFU) == 0) {
            publish_users_loop_activity_progress(
                "building folders targets",
                i,
                count,
                &last_progress_published_at
            );
        }
        if (profile_deleted) {
            deleted_source_flags = entry_deleted_source_flags_in_table(
                items,
                index,
                count,
                &items[i]
            );
            if (deleted_source_flags != 0U) {
                if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_RECYCLE) != 0U &&
                    (deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT) != 0U) {
                    source_deleted_and_recycle_candidates++;
                } else if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_RECYCLE) != 0U) {
                    source_recycle_only_candidates++;
                } else if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT) != 0U) {
                    source_deleted_bit_only_candidates++;
                }
            }
        }
        format = mftprobe_format_select_for_entry(config, &items[i]);
        if (format == NULL &&
            !entry_is_generic_file_candidate(config, &items[i])) {
            continue;
        }
        if (format != NULL) {
            format_candidates++;
        }
        if (!config_entry_matches_users_runtime_filters_local(
                config,
                format,
                items,
                index,
                count,
                &items[i])) {
            continue;
        }
        if (profile_deleted) {
            if (deleted_source_flags != 0U) {
                deleted_like_candidates++;
                if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_RECYCLE) != 0U &&
                    (deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT) != 0U) {
                    deleted_and_recycle_candidates++;
                } else if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_RECYCLE) != 0U) {
                    recycle_only_candidates++;
                } else if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT) != 0U) {
                    deleted_bit_only_candidates++;
                }
            }
        }
        if (!build_path_for_selected_recovery(
                config,
                items,
                index,
                count,
                &items[i],
                full_path,
                sizeof(full_path))) {
            continue;
        }
        path_candidates++;
        if (profile_deleted && deleted_source_flags != 0U) {
            if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_RECYCLE) != 0U &&
                (deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT) != 0U) {
                path_ok_deleted_and_recycle++;
            } else if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_RECYCLE) != 0U) {
                path_ok_recycle_only++;
            } else if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT) != 0U) {
                path_ok_deleted_bit_only++;
            }
        }
        count_before_add = plan->count;
        if (!recovery_plan_add_target(plan, config, format, &items[i], full_path)) {
            ok = 0;
            break;
        }
        attempted_targets++;
        if (plan->count > count_before_add) {
            appended_targets++;
            if (profile_deleted && deleted_source_flags != 0U) {
                if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_RECYCLE) != 0U &&
                    (deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT) != 0U) {
                    appended_deleted_and_recycle++;
                } else if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_RECYCLE) != 0U) {
                    appended_recycle_only++;
                } else if ((deleted_source_flags & ENTRY_DELETED_SOURCE_FLAG_DELETED_BIT) != 0U) {
                    appended_deleted_bit_only++;
                }
            }
        }
    }
    if (ok) {
        publish_users_loop_activity_progress(
            "building folders targets",
            count,
            count,
            &last_progress_published_at
        );
    }
    if (ok && !stop_requested() && plan->count > 1) {
        log_verbose("Sorting recovery schedule: targets=%zu", plan->count);
    }
    recovery_plan_resort_scheduler_locked(plan);
    pthread_mutex_unlock(&plan->mutex);
    select_seconds = monotonic_seconds() - phase_started_at;

    elapsed = monotonic_seconds() - started_at;
    pthread_mutex_lock(&plan->mutex);
    plan->refresh_count++;
    plan->last_refresh_entries = count;
    plan->refresh_total_seconds += elapsed;
    if (elapsed > plan->refresh_max_seconds) {
        plan->refresh_max_seconds = elapsed;
    }
    pthread_mutex_unlock(&plan->mutex);

    if (profile_deleted) {
        log_info(
            "Users deleted profiling: entries=%zu format=%zu deleted_like=%zu path_ok=%zu target_attempts=%zu appended=%zu t_snapshot=%.2fs t_index=%.2fs t_select=%.2fs total=%.2fs",
            count,
            format_candidates,
            deleted_like_candidates,
            path_candidates,
            attempted_targets,
            appended_targets,
            snapshot_seconds,
            index_seconds,
            select_seconds,
            elapsed
        );
        log_info(
            "Users deleted split: recycle_only=%zu deleted_bit_only=%zu both=%zu path_ok_recycle=%zu path_ok_deleted=%zu path_ok_both=%zu appended_recycle=%zu appended_deleted=%zu appended_both=%zu",
            recycle_only_candidates,
            deleted_bit_only_candidates,
            deleted_and_recycle_candidates,
            path_ok_recycle_only,
            path_ok_deleted_bit_only,
            path_ok_deleted_and_recycle,
            appended_recycle_only,
            appended_deleted_bit_only,
            appended_deleted_and_recycle
        );
        log_info(
            "Users deleted source coverage: recycle_only_any=%zu deleted_bit_only_any=%zu both_any=%zu recycle_only_selected=%zu deleted_bit_only_selected=%zu both_selected=%zu",
            source_recycle_only_candidates,
            source_deleted_bit_only_candidates,
            source_deleted_and_recycle_candidates,
            recycle_only_candidates,
            deleted_bit_only_candidates,
            deleted_and_recycle_candidates
        );
    } else {
        log_info(
            "Folders target build: entries=%zu format=%zu path_ok=%zu target_attempts=%zu appended=%zu t_snapshot=%.2fs t_index=%.2fs t_select=%.2fs total=%.2fs",
            count,
            format_candidates,
            path_candidates,
            attempted_targets,
            appended_targets,
            snapshot_seconds,
            index_seconds,
            select_seconds,
            elapsed
        );
    }

    return ok;
}

static int recovery_plan_refresh_users_with_primary_mft_fallback(
    RecoveryPlan *plan,
    const Config *config,
    MftTable *table,
    int *used_primary_mft_fallback,
    int skip_initial_refresh
)
{
    FILE *file = NULL;
    uint64_t scanned_bytes = 0;
    size_t target_count = 0;
    int need_primary_mft_supplement = 0;
    int need_selected_root_scope_supplement = 0;
    char missing_root_scopes[512];
    size_t missing_root_scope_count = 0;

    if (used_primary_mft_fallback != NULL) {
        *used_primary_mft_fallback = 0;
    }
    missing_root_scopes[0] = '\0';
    if (plan == NULL || config == NULL || table == NULL) {
        return 0;
    }
    if (!skip_initial_refresh &&
        !recovery_plan_refresh_from_table(plan, config, table)) {
        return 0;
    }

    pthread_mutex_lock(&plan->mutex);
    target_count = plan->count;
    pthread_mutex_unlock(&plan->mutex);

    if (config->has_deleted_filter && config->deleted_value == 2) {
        need_primary_mft_supplement = 1;
    }
    if (config->root_scope_count > 0 &&
        !selected_root_scope_cache_has_descendants_for_all(
            config,
            table,
            missing_root_scopes,
            sizeof(missing_root_scopes),
            &missing_root_scope_count)) {
        if (stop_requested()) {
            return 0;
        }
        if (missing_root_scope_count > 0) {
            need_selected_root_scope_supplement = 1;
        }
    }

    if ((target_count > 0 &&
         !need_primary_mft_supplement &&
         !need_selected_root_scope_supplement) ||
        stop_requested() ||
        !config->ntfs.valid) {
        return 1;
    }

    if (need_selected_root_scope_supplement) {
        log_info(
            "Folders fallback: cached --fold coverage is incomplete for selected folders (%s); rescanning primary $MFT directly",
            missing_root_scopes[0] != '\0' ? missing_root_scopes : "unknown"
        );
    } else if (need_primary_mft_supplement) {
        log_info(
            "Users del2 primary $MFT supplement: rescanning primary $MFT for live Users coverage in addition to deleted-like hits"
        );
    } else {
        log_info(
            "Folders fallback: sequential scan produced no targets; rescanning primary $MFT directly across detected NTFS volumes"
        );
    }

    file = fopen(config->image_path, "rb");
    if (file == NULL) {
        log_error("Folders fallback failed to reopen source: %s", config->image_path);
        return 1;
    }

    recovery_plan_destroy(plan);
    if (!recovery_plan_init(plan)) {
        fclose(file);
        return 0;
    }
    table_reset(table);
    if (!collect_primary_mft_entries(file, fileno(file), config, table, &scanned_bytes)) {
        log_error("Folders fallback failed while reading primary $MFT");
        fclose(file);
        return 1;
    }
    fclose(file);

    if (need_selected_root_scope_supplement) {
        log_info(
            "Folders --fold primary $MFT supplement loaded: entries=%zu scanned=%.1f MiB",
            table->count,
            (double)scanned_bytes / (1024.0 * 1024.0)
        );
    } else if (need_primary_mft_supplement) {
        log_info(
            "Users del2 primary $MFT supplement loaded: entries=%zu scanned=%.1f MiB",
            table->count,
            (double)scanned_bytes / (1024.0 * 1024.0)
        );
    } else {
        log_info(
            "Folders fallback loaded primary $MFT data: entries=%zu scanned=%.1f MiB",
            table->count,
            (double)scanned_bytes / (1024.0 * 1024.0)
        );
    }

    if (used_primary_mft_fallback != NULL) {
        *used_primary_mft_fallback = 1;
    }

    return recovery_plan_refresh_from_table(plan, config, table);
}

static int users_live_index_can_skip_postscan_refresh(
    const Config *config,
    const LiveIndexWorker *worker,
    RecoveryPlan *plan,
    char *summary,
    size_t summary_size
)
{
    size_t target_count = 0;
    if (summary != NULL && summary_size > 0U) {
        summary[0] = '\0';
    }

    if (config == NULL || worker == NULL || plan == NULL) {
        return 0;
    }
    if (config->has_deleted_filter || config->resume_active) {
        return 0;
    }
    if (!worker->ok || worker->selected_candidates_seen == 0U || worker->pending_remaining != 0U) {
        return 0;
    }
    pthread_mutex_lock(&plan->mutex);
    target_count = plan->count;
    pthread_mutex_unlock(&plan->mutex);
    if (target_count == 0U) {
        return 0;
    }

    if (summary != NULL && summary_size > 0U) {
        snprintf(
            summary,
            summary_size,
            "selected=%llu path_ready=%llu attempted=%llu appended=%llu pending=0 targets=%zu",
            (unsigned long long)worker->selected_candidates_seen,
            (unsigned long long)worker->path_ready_candidates,
            (unsigned long long)worker->targets_attempted,
            (unsigned long long)worker->targets_appended,
            target_count
        );
    }
    return 1;
}

static int try_users_deleted_primary_mft_fast_path(
    const Config *config,
    MftTable *table,
    RecoveryPlan *plan,
    int *out_handled
)
{
    FILE *file = NULL;
    uint64_t scanned_bytes = 0;
    size_t target_count = 0;
    int ok = 0;

    if (out_handled != NULL) {
        *out_handled = 0;
    }
    if (config == NULL || table == NULL || plan == NULL) {
        return 0;
    }
    if (!(config->has_deleted_filter && config->deleted_value == 1) ||
        config->resume_requested ||
        config->resume_active ||
        config->only_recover_missed ||
        !config->ntfs.valid) {
        return 1;
    }

    log_info(
        "Users deleted fast path: scanning primary $MFT across %zu NTFS volumes before full-disk fallback",
        config->ntfs_volume_count > 0 ? config->ntfs_volume_count : (size_t)1
    );

    file = fopen(config->image_path, "rb");
    if (file == NULL) {
        log_info("Users deleted fast path could not reopen source; falling back to full-disk scan");
        return 1;
    }

    table_reset(table);
    if (!collect_primary_mft_entries(file, fileno(file), config, table, &scanned_bytes)) {
        fclose(file);
        table_reset(table);
        log_info("Users deleted fast path could not read primary $MFT cleanly; falling back to full-disk scan");
        return 1;
    }
    fclose(file);
    if (!write_binary_map_snapshot(config, table)) {
        log_verbose("Users deleted fast path could not persist MFT snapshot state");
    }

    if (!recovery_plan_refresh_from_table(plan, config, table)) {
        return 0;
    }

    pthread_mutex_lock(&plan->mutex);
    target_count = plan->count;
    pthread_mutex_unlock(&plan->mutex);

    log_info(
        "Users deleted fast path primary $MFT: entries=%zu scanned=%.1f MiB targets=%zu",
        table->count,
        (double)scanned_bytes / (1024.0 * 1024.0),
        target_count
    );

    if (target_count == 0) {
        log_info(
            "Users deleted fast path found no targets in primary $MFT; falling back to full-disk scan"
        );
        return 1;
    }

    log_info(
        "Users deleted fast path found %zu targets; skipping the slower whole-disk MFT observation pass",
        target_count
    );

    write_users_selected_tree(config, table);
    ok = recovery_plan_direct_recover(plan, config, 1);
    if (ok && !stop_requested() &&
        !recovery_plan_replay_missed_jpeg_targets(plan, config)) {
        ok = 0;
    }
    if (ok && !stop_requested() &&
        !recovery_plan_replay_missed_png_targets(plan, config)) {
        ok = 0;
    }
    if (ok && !stop_requested() &&
        !recovery_plan_replay_missed_mov_targets(plan, config)) {
        ok = 0;
    }
    if (!write_missed_targets_report(config, plan)) {
        log_verbose("Users deleted fast path could not persist missed-target report");
    }
    prune_empty_deleted_dirs(config->out_dir);
    recovery_plan_log_summary(plan);
    if (ok && !stop_requested() &&
        !write_scan_state(config, config->source_size, 1)) {
        log_verbose("Users deleted fast path could not update scan state");
    }

    if (out_handled != NULL) {
        *out_handled = 1;
    }
    return ok;
}

static int recovery_target_open(RecoveryTarget *target)
{
    if (target == NULL || target->file != NULL) {
        return 0;
    }

    if (!ensure_parent_dirs(target->output_path)) {
        return 0;
    }

    target->file = fopen(target->output_path, "wb");
    if (target->file == NULL) {
        return 0;
    }

    target->state = TARGET_ACTIVE;
    return 1;
}

static int recovery_target_write_from_buffer(
    RecoveryTarget *target,
    const unsigned char *buffer,
    uint64_t buffer_base,
    size_t buffer_len
)
{
    uint64_t buffer_end;
    uint64_t write_abs;
    size_t buffer_offset;
    size_t available;

    if (target == NULL || buffer == NULL || target->remaining == 0) {
        return 1;
    }

    buffer_end = buffer_base + (uint64_t)buffer_len;
    if (target->next_offset < buffer_base || target->next_offset >= buffer_end) {
        return 1;
    }

    write_abs = target->next_offset;
    buffer_offset = (size_t)(write_abs - buffer_base);
    available = buffer_len - buffer_offset;
    if ((uint64_t)available > target->remaining) {
        available = (size_t)target->remaining;
    }

    if (target->state == TARGET_PENDING) {
        size_t skip_bytes = 0;

        mftprobe_format_validator_reset(target);
        if (!mftprobe_format_validator_start(target, buffer + buffer_offset, available, &skip_bytes)) {
            target->state = TARGET_SKIPPED;
            return 0;
        }
        if (skip_bytes > 0) {
            if (skip_bytes >= available || (uint64_t)skip_bytes >= target->remaining) {
                target->state = TARGET_SKIPPED;
                snprintf(target->last_error, sizeof(target->last_error), "JPEG SOI adjustment consumed target");
                return 0;
            }
            buffer_offset += skip_bytes;
            available -= skip_bytes;
            target->remaining -= skip_bytes;
            target->next_offset += skip_bytes;
        }
    }

    if (target->file == NULL && !recovery_target_open(target)) {
        target->state = TARGET_SKIPPED;
        return 0;
    }

    mftprobe_format_validator_update(target, buffer + buffer_offset, available);

    if (fwrite(buffer + buffer_offset, 1, available, target->file) != available) {
        target->state = TARGET_MISSED;
        return 0;
    }

    target->remaining -= available;
    target->next_offset += available;
    while (target->remaining > 0 && target->run_index < target->run_count) {
        uint64_t run_end =
            target->runs[target->run_index].abs_offset +
            target->runs[target->run_index].byte_length;

        if (target->next_offset < run_end) {
            break;
        }
        target->run_index++;
        if (target->run_index < target->run_count) {
            target->next_offset = target->runs[target->run_index].abs_offset;
        }
    }

    if (target->remaining == 0) {
        if (!mftprobe_format_validator_finish(target)) {
            fclose(target->file);
            target->file = NULL;
            target->state = TARGET_SKIPPED;
            (void)remove(target->output_path);
            return 0;
        }
        if (fclose(target->file) != 0) {
            target->file = NULL;
            target->state = TARGET_MISSED;
            return 0;
        }
        target->file = NULL;
        target->state = TARGET_DONE;
    }

    return 1;
}

static int recovery_plan_make_write_job_locked(
    RecoveryPlan *plan,
    const unsigned char *buffer,
    uint64_t buffer_base,
    uint64_t buffer_end,
    RecoveryWriteJob *job
)
{
    if (plan == NULL || buffer == NULL || job == NULL) {
        return 0;
    }

    recovery_plan_mark_passed_locked(plan, buffer_base);
    while (plan->scheduler_index < plan->count) {
        RecoveryTarget *target = &plan->items[plan->scheduler_index];
        uint64_t chunk_offset;
        size_t buffer_offset;
        size_t data_len;

        if (recovery_target_is_scheduler_complete(target->state)) {
            plan->scheduler_index++;
            continue;
        }

        if (target->state == TARGET_PENDING) {
            if (target->abs_offset >= buffer_end) {
                return 0;
            }
        } else if (target->state == TARGET_ACTIVE) {
            if (target->next_offset >= buffer_end) {
                return 0;
            }
        }

        if (target->next_offset < buffer_base) {
            recovery_target_close_and_remove(target);
            if (target->state != TARGET_DEFERRED) {
                plan->deferred++;
            }
            target->state = TARGET_DEFERRED;
            snprintf(
                target->last_error,
                sizeof(target->last_error),
                "stream passed target byte %llu; deferred for post-scan recovery",
                (unsigned long long)target->next_offset
            );
            plan->scheduler_index++;
            continue;
        }

        if (target->next_offset >= buffer_base && target->next_offset < buffer_end) {
            memset(job, 0, sizeof(*job));
            chunk_offset = target->next_offset;
            buffer_offset = (size_t)(chunk_offset - buffer_base);
            data_len = (size_t)(buffer_end - chunk_offset);
            if (target->run_index < target->run_count) {
                uint64_t run_end =
                    target->runs[target->run_index].abs_offset +
                    target->runs[target->run_index].byte_length;

                if (run_end > chunk_offset && (uint64_t)data_len > run_end - chunk_offset) {
                    data_len = (size_t)(run_end - chunk_offset);
                }
            }
            if ((uint64_t)data_len > target->remaining) {
                data_len = (size_t)target->remaining;
            }
            if (data_len == 0) {
                target->state = TARGET_QUEUED;
                plan->scheduler_index++;
                continue;
            }

            job->data = (unsigned char *)malloc(data_len);
            if (job->data == NULL) {
                return -1;
            }
            memcpy(job->data, buffer + buffer_offset, data_len);
            job->format_id = target->format_id;
            job->validator_id = target->validator_id;
            snprintf(job->extension, sizeof(job->extension), "%s", target->extension);
            job->abs_offset = target->abs_offset;
            job->size = target->size;
            job->expected_size = target->expected_size;
            job->chunk_offset = chunk_offset;
            job->data_len = data_len;
            memcpy(job->blob_start, target->blob_start, sizeof(job->blob_start));
            job->blob_start_length = target->blob_start_length;
            memcpy(job->runs, target->runs, target->run_count * sizeof(*target->runs));
            job->run_count = target->run_count;
            job->run_truncated = target->run_truncated;
            job->record = target->record;
            job->family = target->family;
            job->created_unix = target->created_unix;
            job->first_chunk = target->state == TARGET_PENDING && chunk_offset == target->abs_offset;
            snprintf(job->source_path, sizeof(job->source_path), "%s", target->source_path);
            snprintf(job->output_path, sizeof(job->output_path), "%s", target->output_path);

            target->state = TARGET_ACTIVE;
            target->remaining -= data_len;
            target->next_offset += data_len;
            while (target->remaining > 0 && target->run_index < target->run_count) {
                uint64_t run_end =
                    target->runs[target->run_index].abs_offset +
                    target->runs[target->run_index].byte_length;

                if (target->next_offset < run_end) {
                    break;
                }
                target->run_index++;
                if (target->run_index < target->run_count) {
                    target->next_offset = target->runs[target->run_index].abs_offset;
                }
            }
            if (target->remaining == 0) {
                target->state = TARGET_QUEUED;
                job->last_chunk = 1;
                plan->scheduler_index++;
                recovery_plan_advance_scheduler_locked(plan);
            } else if (target->next_offset >= buffer_end) {
                recovery_plan_resort_scheduler_locked(plan);
            }
            return 1;
        }

        return 0;
    }

    return 0;
}

static RecoveryTarget *recovery_plan_find_target_for_commit_locked(
    RecoveryPlan *plan,
    const RecoveryWriteJob *job
)
{
    if (plan == NULL || job == NULL) {
        return NULL;
    }
    return recovery_plan_find_target(
        plan,
        job->format_id,
        job->record,
        job->family,
        job->abs_offset
    );
}

static int recovery_plan_commit_writer_result_locked(
    RecoveryPlan *plan,
    const RecoveryWriteJob *job,
    RecoveryTargetState after,
    const char *last_error
)
{
    RecoveryTarget *target;
    RecoveryTargetState before;

    target = recovery_plan_find_target_for_commit_locked(plan, job);
    if (target == NULL || recovery_target_is_terminal(target->state)) {
        return 0;
    }

    before = target->state;
    target->state = after;
    if (last_error != NULL) {
        snprintf(target->last_error, sizeof(target->last_error), "%s", last_error);
    }

    recovery_plan_note_terminal_transition_locked(plan, before, target->state);
    recovery_plan_advance_scheduler_locked(plan);
    return 1;
}

static void recovery_plan_mark_unqueued_write_job(
    RecoveryPlan *plan,
    const RecoveryWriteJob *job,
    const char *reason
)
{
    if (plan == NULL || job == NULL) {
        return;
    }

    pthread_mutex_lock(&plan->mutex);
    recovery_plan_commit_writer_result_locked(
        plan,
        job,
        TARGET_MISSED,
        reason != NULL ? reason : "recovery write job was not queued"
    );
    pthread_mutex_unlock(&plan->mutex);
}

static int recovery_plan_process_buffer(
    RecoveryPlan *plan,
    RecoveryWriteQueue *write_queue,
    const unsigned char *buffer,
    uint64_t buffer_base,
    size_t buffer_len
)
{
    uint64_t buffer_end;
    int ok = 1;

    if (plan == NULL || write_queue == NULL || buffer == NULL || buffer_len == 0) {
        return 1;
    }

    buffer_end = buffer_base + (uint64_t)buffer_len;

    for (;;) {
        RecoveryWriteJob job;
        int have_job;

        memset(&job, 0, sizeof(job));
        pthread_mutex_lock(&plan->mutex);
        have_job = recovery_plan_make_write_job_locked(
            plan,
            buffer,
            buffer_base,
            buffer_end,
            &job
        );
        if (have_job <= 0) {
            uint64_t miss_before = buffer_base;

            if (buffer_end > OVERLAP) {
                miss_before = buffer_end - OVERLAP;
                if (miss_before < buffer_base) {
                    miss_before = buffer_base;
                }
            }
            if (!plan->have_miss_before_offset ||
                miss_before > plan->miss_before_offset) {
                plan->miss_before_offset = miss_before;
                plan->have_miss_before_offset = 1;
            }
            if (!plan->have_stream_end_offset ||
                buffer_end > plan->stream_end_offset) {
                plan->stream_end_offset = buffer_end;
                plan->have_stream_end_offset = 1;
            }
            recovery_plan_mark_passed_locked(plan, plan->miss_before_offset);
            pthread_mutex_unlock(&plan->mutex);
            if (have_job < 0) {
                recovery_write_queue_finish(write_queue);
                ok = 0;
            }
            break;
        }
        pthread_mutex_unlock(&plan->mutex);

        if (!recovery_write_queue_push(write_queue, &job)) {
            ok = stop_requested() ? 1 : 0;
            recovery_plan_mark_unqueued_write_job(
                plan,
                &job,
                stop_requested()
                    ? "stop requested before recovery write job was queued"
                    : "recovery write queue stopped before job was queued"
            );
            recovery_write_job_clear(&job);
            break;
        }
    }
    return ok;
}

static void recovery_plan_finish_stream(RecoveryPlan *plan)
{
    if (plan == NULL) {
        return;
    }

    pthread_mutex_lock(&plan->mutex);
    if (plan->have_stream_end_offset) {
        if (!plan->have_miss_before_offset ||
            plan->stream_end_offset > plan->miss_before_offset) {
            plan->miss_before_offset = plan->stream_end_offset;
            plan->have_miss_before_offset = 1;
        }
        recovery_plan_mark_passed_locked(plan, plan->miss_before_offset);
    }
    pthread_mutex_unlock(&plan->mutex);
}

static int recovery_write_job_same_target(const RecoveryWriteJob *job, const RecoveryTarget *target)
{
    return job != NULL && target != NULL &&
           job->format_id == target->format_id &&
           job->record == target->record &&
           job->family == target->family &&
           job->abs_offset == target->abs_offset;
}

static void recovery_target_start_from_job(RecoveryTarget *target, const RecoveryWriteJob *job)
{
    if (target == NULL || job == NULL) {
        return;
    }
    memset(target, 0, sizeof(*target));
    target->format_id = job->format_id;
    target->validator_id = job->validator_id;
    snprintf(target->extension, sizeof(target->extension), "%s", job->extension);
    memcpy(target->blob_start, job->blob_start, sizeof(target->blob_start));
    target->blob_start_length = job->blob_start_length;
    target->abs_offset = job->abs_offset;
    target->size = job->size;
    target->expected_size = job->expected_size;
    target->remaining = job->size;
    target->next_offset = job->abs_offset;
    if (job->run_count > 0 && job->run_count <= RECOVERY_TARGET_MAX_RUNS) {
        memcpy(target->runs, job->runs, job->run_count * sizeof(*job->runs));
        target->run_count = job->run_count;
        target->run_truncated = job->run_truncated;
    } else {
        target->runs[0].abs_offset = job->abs_offset;
        target->runs[0].byte_length = job->size;
        target->run_count = 1;
    }
    target->run_index = 0;
    target->record = job->record;
    target->family = job->family;
    target->created_unix = job->created_unix;
    target->state = TARGET_PENDING;
    snprintf(target->source_path, sizeof(target->source_path), "%s", job->source_path);
    snprintf(target->output_path, sizeof(target->output_path), "%s", job->output_path);
}

static void recovery_writer_commit_terminal(
    RecoveryPlan *plan,
    const RecoveryWriteJob *job,
    const RecoveryTarget *target
)
{
    pthread_mutex_lock(&plan->mutex);
    recovery_plan_commit_writer_result_locked(
        plan,
        job,
        target->state,
        target->last_error
    );
    pthread_mutex_unlock(&plan->mutex);

    if (target->state == TARGET_DONE) {
        if (target->created_unix > 0) {
            (void)mft_engine_apply_created_time_value_to_path(
                target->output_path,
                target->created_unix
            );
        }
        if (recovery_target_is_partial(target)) {
            log_verbose("Recovered partial format %u from MFT stream: %s (%llu/%llu bytes)",
                        target->format_id,
                        target->output_path,
                        (unsigned long long)target->size,
                        (unsigned long long)target->expected_size);
        } else {
            log_verbose("Recovered format %u from MFT stream: %s",
                        target->format_id,
                        target->output_path);
        }
    }
}

static int recovery_plan_job_is_terminal(RecoveryPlan *plan, const RecoveryWriteJob *job)
{
    RecoveryTarget *target;
    int terminal = 1;

    if (plan == NULL || job == NULL) {
        return 1;
    }

    pthread_mutex_lock(&plan->mutex);
    target = recovery_plan_find_target_for_commit_locked(plan, job);
    if (target != NULL) {
        terminal = recovery_target_is_terminal(target->state);
    }
    pthread_mutex_unlock(&plan->mutex);
    return terminal;
}

static ssize_t recovery_writer_find_active(
    RecoveryTarget *active,
    size_t active_count,
    const RecoveryWriteJob *job
)
{
    size_t i;

    if (active == NULL || job == NULL) {
        return -1;
    }
    for (i = 0; i < active_count; i++) {
        if (recovery_write_job_same_target(job, &active[i])) {
            return (ssize_t)i;
        }
    }
    return -1;
}

static int recovery_writer_add_active(
    RecoveryTarget **active,
    size_t *active_count,
    size_t *active_capacity,
    const RecoveryWriteJob *job
)
{
    RecoveryTarget *new_active;

    if (active == NULL || active_count == NULL ||
        active_capacity == NULL || job == NULL) {
        return 0;
    }
    if (*active_count == *active_capacity) {
        size_t new_capacity = *active_capacity == 0 ? 16U : *active_capacity * 2U;

        new_active = (RecoveryTarget *)realloc(
            *active,
            new_capacity * sizeof(*new_active)
        );
        if (new_active == NULL) {
            return 0;
        }
        *active = new_active;
        *active_capacity = new_capacity;
    }

    recovery_target_start_from_job(&(*active)[*active_count], job);
    (*active_count)++;
    return 1;
}

static void recovery_writer_remove_active(
    RecoveryTarget *active,
    size_t *active_count,
    size_t index
)
{
    if (active == NULL || active_count == NULL || index >= *active_count) {
        return;
    }
    if (index + 1U < *active_count) {
        memmove(
            &active[index],
            &active[index + 1U],
            (*active_count - index - 1U) * sizeof(*active)
        );
    }
    (*active_count)--;
}

static void *recovery_writer_worker_main(void *arg)
{
    RecoveryWriterWorker *worker = (RecoveryWriterWorker *)arg;
    RecoveryTarget *active = NULL;
    size_t active_count = 0;
    size_t active_capacity = 0;
    RecoveryWriteJob job;

    block_stop_signals_in_worker();
    worker->ok = 1;

    while (recovery_write_queue_pop(worker->queue, &job)) {
        RecoveryTarget *current;
        ssize_t active_index;

        if (recovery_plan_job_is_terminal(worker->recovery_plan, &job)) {
            recovery_write_job_clear(&job);
            continue;
        }

        active_index = recovery_writer_find_active(active, active_count, &job);
        if (active_index < 0) {
            if (!recovery_writer_add_active(
                    &active,
                    &active_count,
                    &active_capacity,
                    &job)) {
                worker->ok = 0;
                recovery_plan_mark_unqueued_write_job(
                    worker->recovery_plan,
                    &job,
                    "failed to allocate active recovery writer state"
                );
                recovery_write_job_clear(&job);
                break;
            }
            active_index = (ssize_t)(active_count - 1U);
        }
        current = &active[(size_t)active_index];

        if (job.chunk_offset != current->next_offset) {
            recovery_target_close_and_remove(current);
            current->state = TARGET_MISSED;
            snprintf(
                current->last_error,
                sizeof(current->last_error),
                "writer expected byte %llu but received byte %llu",
                (unsigned long long)current->next_offset,
                (unsigned long long)job.chunk_offset
            );
        } else if (!recovery_target_write_from_buffer(
                       current,
                       job.data,
                       job.chunk_offset,
                       job.data_len)) {
            recovery_target_close_and_remove(current);
        }

        if (recovery_target_is_terminal(current->state)) {
            recovery_writer_commit_terminal(worker->recovery_plan, &job, current);
            recovery_writer_remove_active(active, &active_count, (size_t)active_index);
        }

        ATOMIC_ADD_U64(&worker->jobs_completed, 1U);
        ATOMIC_ADD_U64(&worker->bytes_written, (uint64_t)job.data_len);

        recovery_write_job_clear(&job);
    }

    while (active_count > 0) {
        RecoveryTarget *current = &active[active_count - 1U];

        if (recovery_target_is_terminal(current->state)) {
            active_count--;
            continue;
        }
        recovery_target_close_and_remove(current);
        current->state = TARGET_DEFERRED;
        snprintf(current->last_error, sizeof(current->last_error), "writer stopped before target completed; deferred for post-scan recovery");
        pthread_mutex_lock(&worker->recovery_plan->mutex);
        {
            RecoveryWriteJob final_job;

            memset(&final_job, 0, sizeof(final_job));
            final_job.format_id = current->format_id;
            final_job.record = current->record;
            final_job.family = current->family;
            final_job.abs_offset = current->abs_offset;
            recovery_plan_commit_writer_result_locked(
                worker->recovery_plan,
                &final_job,
                current->state,
                current->last_error
            );
        }
        pthread_mutex_unlock(&worker->recovery_plan->mutex);
        active_count--;
    }
    free(active);

    return NULL;
}

static void recovery_plan_log_summary(RecoveryPlan *plan)
{
    size_t pending = 0;
    size_t active = 0;
    size_t deferred = 0;
    size_t i;

    if (plan == NULL) {
        return;
    }

    pthread_mutex_lock(&plan->mutex);
    for (i = 0; i < plan->count; i++) {
        if (plan->items[i].state == TARGET_DONE) {
            mft_note_recovered_output(
                plan->items[i].output_path,
                (long long)plan->items[i].abs_offset
            );
        } else if (plan->items[i].state == TARGET_PENDING) {
            pending++;
        } else if (plan->items[i].state == TARGET_ACTIVE ||
                   plan->items[i].state == TARGET_QUEUED) {
            active++;
        } else if (plan->items[i].state == TARGET_DEFERRED) {
            deferred++;
        }
    }

    log_info(
        "MFT-stream recovery: targets=%zu recovered=%zu missed=%zu skipped=%zu deferred=%zu pending_after_scan=%zu active_after_scan=%zu",
        plan->count,
        plan->recovered,
        plan->missed,
        plan->skipped,
        deferred,
        pending,
        active
    );
    g_last_engine_recovered_count = plan->recovered;
    pthread_mutex_unlock(&plan->mutex);
}

static void observation_write_run_start(const Config *config)
{
    FILE *file;
    uint32_t flags = 0;
    const uint32_t payload_len =
        8U + 8U + 8U + 8U + 8U + 4U + 4U + 4U +
        OBSERVATION_RUN_NAME_MAX + OBSERVATION_SOURCE_PATH_MAX;

    if (config == NULL || config->only_recover_missed) {
        return;
    }

    if (config->resume_requested) {
        flags |= 1U;
    }
    if (config->auto_recover_missed) {
        flags |= 2U;
    }

    file = open_observations_append();
    if (file == NULL) {
        return;
    }

    if (!observation_write_header(file, 1U, payload_len) ||
        !write_u64_value(file, config->observation_run_id) ||
        !write_u64_value(file, (uint64_t)time(NULL)) ||
        !write_u64_value(file, config->source_size) ||
        !write_u64_value(file, config->limit) ||
        !write_u64_value(file, (uint64_t)getpid()) ||
        !write_u32_value(file, flags) ||
        !write_u32_value(file, OBSERVATION_RUN_NAME_MAX) ||
        !write_u32_value(file, OBSERVATION_SOURCE_PATH_MAX) ||
        !observation_write_fixed_string(file, config->source_id, OBSERVATION_RUN_NAME_MAX) ||
        !observation_write_fixed_string(file, config->image_path, OBSERVATION_SOURCE_PATH_MAX)) {
        log_error("Failed to write MFT observation run start");
    }

    fclose(file);
}

static void observation_write_geometry(const Config *config)
{
    FILE *file;
    const uint32_t payload_len = 64U;

    if (config == NULL || config->only_recover_missed) {
        return;
    }

    file = open_observations_append();
    if (file == NULL) {
        return;
    }

    if (!observation_write_header(file, 2U, payload_len) ||
        !write_u64_value(file, config->observation_run_id) ||
        !write_u32_value(file, (uint32_t)config->ntfs.valid) ||
        !write_u32_value(file, (uint32_t)config->ntfs.bytes_per_sector) ||
        !write_u32_value(file, (uint32_t)config->ntfs.sectors_per_cluster) ||
        !write_u32_value(file, 0U) ||
        !write_u64_value(file, config->ntfs.volume_offset) ||
        !write_u64_value(file, config->ntfs.cluster_size) ||
        !write_u64_value(file, config->ntfs.volume_serial) ||
        !write_u64_value(file, config->source_size) ||
        !write_u64_value(file, ASSUMED_CLUSTER_SIZE)) {
        log_error("Failed to write MFT observation geometry");
    }

    fclose(file);
}

static void observation_count_recovery_plan(
    RecoveryPlan *plan,
    uint64_t *targets,
    uint64_t *recovered,
    uint64_t *missed,
    uint64_t *skipped,
    uint64_t *pending,
    uint64_t *active
)
{
    size_t i;

    *targets = 0;
    *recovered = 0;
    *missed = 0;
    *skipped = 0;
    *pending = 0;
    *active = 0;

    if (plan == NULL) {
        return;
    }

    pthread_mutex_lock(&plan->mutex);
    *targets = (uint64_t)plan->count;
    *recovered = (uint64_t)plan->recovered;
    *missed = (uint64_t)plan->missed;
    *skipped = (uint64_t)plan->skipped;
    for (i = 0; i < plan->count; i++) {
        if (plan->items[i].state == TARGET_PENDING) {
            (*pending)++;
        } else if (plan->items[i].state == TARGET_ACTIVE ||
                   plan->items[i].state == TARGET_QUEUED) {
            (*active)++;
        }
    }
    pthread_mutex_unlock(&plan->mutex);
}

static void observation_write_final(
    const Config *config,
    const SieveWorker *sieve,
    RecoveryPlan *plan,
    MftTable *table,
    int completed
)
{
    FILE *file;
    MftEntry *items = NULL;
    RecordIndex *index = NULL;
    size_t count = 0;
    size_t i;
    uint64_t selected_count = 0;
    uint64_t selected_before_record = 0;
    uint64_t first_selected_mftpos = 0;
    int64_t first_selected_filepos = -1;
    uint64_t selected_after_expected_end = 0;
    uint64_t selected_fragmented = 0;
    uint64_t selected_contiguous = 0;
    uint64_t selected_outside_source = 0;
    uint64_t bytes_until_users_tree_stable = 0;
    uint64_t targets = 0;
    uint64_t recovered = 0;
    uint64_t missed = 0;
    uint64_t skipped = 0;
    uint64_t pending = 0;
    uint64_t active = 0;
    const uint32_t payload_len = 264U;

    if (config == NULL || sieve == NULL || table == NULL || config->only_recover_missed) {
        return;
    }

    if (snapshot_entries(table, &items, &count)) {
        index = build_record_index(items, count);
        if (count == 0 || index != NULL) {
            for (i = 0; i < count; i++) {
                char full_path[PATH_MAX_LEN];
                uint64_t filepos;

                if (mftprobe_format_select_for_entry(config, &items[i]) == NULL) {
                    continue;
                }
                if (!build_path_if_under_users_root(
                        items,
                        index,
                        count,
                        &items[i],
                        full_path,
                        sizeof(full_path))) {
                    continue;
                }
                selected_count++;
                filepos = mft_data_offset_for_entry(config, &items[i]);
                if (first_selected_mftpos == 0) {
                    first_selected_mftpos = items[i].offset;
                    first_selected_filepos = filepos > 0 ? (int64_t)filepos : -1;
                }
                if (filepos > 0 && filepos < items[i].offset) {
                    selected_before_record++;
                }
                if (sieve->mft_expected_end_offset > 0 &&
                    items[i].offset >= sieve->mft_expected_end_offset) {
                    selected_after_expected_end++;
                }
                if (items[i].run_count > 1) {
                    selected_fragmented++;
                } else if (items[i].run_count == 1 && items[i].first_lcn > 0) {
                    selected_contiguous++;
                }
                if (filepos == 0 ||
                    (config->source_size > 0 && filepos >= config->source_size)) {
                    selected_outside_source++;
                }
            }
        }
    }

    if (sieve->have_users_root && first_selected_mftpos > 0) {
        bytes_until_users_tree_stable = first_selected_mftpos > sieve->users_root_first_seen_offset
            ? first_selected_mftpos
            : sieve->users_root_first_seen_offset;
    }

    observation_count_recovery_plan(
        plan,
        &targets,
        &recovered,
        &missed,
        &skipped,
        &pending,
        &active
    );

    file = open_observations_append();
    if (file == NULL) {
        free(index);
        free(items);
        return;
    }

    if (!observation_write_header(file, 3U, payload_len) ||
        !write_u64_value(file, config->observation_run_id) ||
        !write_u32_value(file, completed ? 1U : 0U) ||
        !write_u32_value(file, stop_requested() ? 1U : 0U) ||
        !write_u64_value(file, sieve->raw_records) ||
        !write_u64_value(file, sieve->accepted_records) ||
        !write_u64_value(file, sieve->hard_rejected_records) ||
        !write_u64_value(file, sieve->duplicate_offsets) ||
        !write_u64_value(file, sieve->duplicate_record_ids) ||
        !write_u64_value(file, sieve->family_count) ||
        !write_u64_value(file, sieve->first_record_offset) ||
        !write_u64_value(file, sieve->last_record_offset) ||
        !write_u64_value(file, sieve->users_root_count) ||
        !write_u64_value(file, sieve->users_root_first_seen_offset) ||
        !write_u64_value(file, selected_count) ||
        !write_u64_value(file, selected_before_record) ||
        !write_u64_value(file, first_selected_mftpos) ||
        !write_i64_value(file, first_selected_filepos) ||
        !write_u64_value(file, selected_after_expected_end) ||
        !write_u64_value(file, selected_fragmented) ||
        !write_u64_value(file, selected_contiguous) ||
        !write_u64_value(file, selected_outside_source) ||
        !write_u64_value(file, bytes_until_users_tree_stable) ||
        !write_u64_value(file, sieve->mft_expected_end_offset) ||
        !write_u64_value(file, sieve->expected_end_miss_count) ||
        !write_u64_value(file, sieve->mft_run_total_bytes) ||
        !write_u64_value(file, sieve->mft_run_count) ||
        !write_u64_value(file, sieve->mft_run_max_lcn_end) ||
        !write_u64_value(file, targets) ||
        !write_u64_value(file, recovered) ||
        !write_u64_value(file, missed) ||
        !write_u64_value(file, skipped) ||
        !write_u64_value(file, pending) ||
        !write_u64_value(file, active) ||
        !write_u64_value(file, config->source_size)) {
        log_error("Failed to write MFT observation final");
    }

    fclose(file);
    free(index);
    free(items);
}

static int compare_recovery_targets_by_offset(const void *left, const void *right)
{
    const RecoveryTarget *a = (const RecoveryTarget *)left;
    const RecoveryTarget *b = (const RecoveryTarget *)right;

    if (a->abs_offset < b->abs_offset) {
        return -1;
    }
    if (a->abs_offset > b->abs_offset) {
        return 1;
    }
    if (a->size < b->size) {
        return -1;
    }
    if (a->size > b->size) {
        return 1;
    }
    return strcmp(a->output_path, b->output_path);
}

static int compare_recovery_targets_by_schedule(const void *left, const void *right)
{
    const RecoveryTarget *a = (const RecoveryTarget *)left;
    const RecoveryTarget *b = (const RecoveryTarget *)right;
    uint64_t a_offset = recovery_target_schedule_offset(a);
    uint64_t b_offset = recovery_target_schedule_offset(b);

    if (a_offset < b_offset) {
        return -1;
    }
    if (a_offset > b_offset) {
        return 1;
    }
    return compare_recovery_targets_by_offset(left, right);
}

static int path_has_size(const char *path, uint64_t size)
{
    struct stat st;

    if (path == NULL || stat(path, &st) != 0) {
        return 0;
    }
    return S_ISREG(st.st_mode) && (uint64_t)st.st_size == size;
}

static void format_byte_size_human_local(
    uint64_t bytes,
    char *out,
    size_t out_size
)
{
    static const char *units[] = {"bytes", "KiB", "MiB", "GiB", "TiB"};
    double value = (double)bytes;
    size_t unit_index = 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }

    while (value >= 1024.0 &&
           unit_index + 1U < (sizeof(units) / sizeof(units[0]))) {
        value /= 1024.0;
        unit_index++;
    }

    if (unit_index == 0U) {
        snprintf(out, out_size, "%llu bytes", (unsigned long long)bytes);
    } else {
        snprintf(out, out_size, "%.2f %s", value, units[unit_index]);
    }
}

static int recovery_plan_preflight_output_space(
    RecoveryPlan *plan,
    const Config *config,
    int only_missed_like
)
{
    uint64_t available_bytes = 0;
    uint64_t bytes_to_write = 0;
    size_t targets_to_write = 0;
    size_t already_present = 0;
    size_t i;
    char need_text[64];
    char free_text[64];

    if (plan == NULL || config == NULL || config->out_dir == NULL ||
        config->out_dir[0] == '\0') {
        return 1;
    }

    if (!platform_get_free_space_bytes(config->out_dir, &available_bytes)) {
        log_info(
            "Direct recovery preflight: could not read free space for %s; continuing without space estimate",
            config->out_dir
        );
        return 1;
    }

    pthread_mutex_lock(&plan->mutex);
    for (i = 0; i < plan->count; i++) {
        RecoveryTarget *target = &plan->items[i];

        if (target->state == TARGET_DONE || target->state == TARGET_SKIPPED) {
            continue;
        }
        if (only_missed_like &&
            target->state != TARGET_MISSED &&
            target->state != TARGET_DEFERRED &&
            target->state != TARGET_PENDING) {
            continue;
        }
        if (path_has_size(target->output_path, target->size)) {
            already_present++;
            continue;
        }

        bytes_to_write += target->size;
        targets_to_write++;
    }
    pthread_mutex_unlock(&plan->mutex);

    format_byte_size_human_local(bytes_to_write, need_text, sizeof(need_text));
    format_byte_size_human_local(available_bytes, free_text, sizeof(free_text));

    log_info(
        "Direct recovery preflight: new_targets=%zu already_present=%zu need=%s free=%s out=%s",
        targets_to_write,
        already_present,
        need_text,
        free_text,
        config->out_dir
    );

    if (bytes_to_write > available_bytes) {
        log_error(
            "Insufficient output space before direct recovery: need=%s free=%s out=%s. Free space or choose another output and rerun.",
            need_text,
            free_text,
            config->out_dir
        );
        return 0;
    }

    return 1;
}

static int direct_recover_target(int image_fd, RecoveryTarget *target, unsigned char *buffer)
{
    return recovery_runner_recover_target_best_effort_fd(
        image_fd,
        target,
        buffer,
        READ_SIZE,
        stop_requested
    );
}

static int recovery_target_looks_like_image(const RecoveryTarget *target)
{
    const char *ext;

    if (target == NULL) {
        return 0;
    }

    ext = target->extension;
    if (ext == NULL || ext[0] == '\0') {
        return 0;
    }

    return strcasecmp(ext, "avif") == 0 ||
           strcasecmp(ext, "bmp") == 0 ||
           strcasecmp(ext, "dib") == 0 ||
           strcasecmp(ext, "gif") == 0 ||
           strcasecmp(ext, "heic") == 0 ||
           strcasecmp(ext, "heif") == 0 ||
           strcasecmp(ext, "iff") == 0 ||
           strcasecmp(ext, "jp2") == 0 ||
           strcasecmp(ext, "jpeg") == 0 ||
           strcasecmp(ext, "jpg") == 0 ||
           strcasecmp(ext, "png") == 0 ||
           strcasecmp(ext, "psd") == 0 ||
           strcasecmp(ext, "tif") == 0 ||
           strcasecmp(ext, "tiff") == 0;
}

static int recovery_plan_direct_recover(
    RecoveryPlan *plan,
    const Config *config,
    int only_missed_like
)
{
    int image_fd;
    unsigned char *buffer;
    double started_at;
    double elapsed;
    size_t attempted = 0;
    size_t recovered = 0;
    size_t already_present = 0;
    size_t outside_source = 0;
    size_t failed = 0;
    size_t unsure_moved = 0;
    size_t skipped_image_filter = 0;
    size_t failed_read_error = 0;
    size_t failed_start_mismatch = 0;
    size_t failed_truncated_or_end = 0;
    size_t failed_output_error = 0;
    size_t failed_invalid_target = 0;
    size_t failed_interrupted = 0;
    size_t failed_unknown = 0;
    size_t i;

    if (plan == NULL || config == NULL) {
        return 0;
    }
    started_at = monotonic_seconds();

    if (!recovery_plan_preflight_output_space(plan, config, only_missed_like)) {
        return 0;
    }

    image_fd = open(config->image_path, O_RDONLY);
    if (image_fd < 0) {
        log_error("Failed to open input for direct missed recovery: %s", config->image_path);
        return 0;
    }

    buffer = (unsigned char *)malloc(READ_SIZE);
    if (buffer == NULL) {
        close(image_fd);
        return 0;
    }

    pthread_mutex_lock(&plan->mutex);
    qsort(plan->items, plan->count, sizeof(*plan->items), compare_recovery_targets_by_offset);
    recovery_plan_mark_indexes_dirty_locked(plan);

    for (i = 0; i < plan->count && !stop_requested(); i++) {
        RecoveryTarget *target = &plan->items[i];
        RecoveryTargetState before = target->state;

        if (target->state == TARGET_DONE || target->state == TARGET_SKIPPED) {
            continue;
        }
        if (only_missed_like &&
            target->state != TARGET_MISSED &&
            target->state != TARGET_DEFERRED &&
            target->state != TARGET_PENDING) {
            continue;
        }

        if (path_has_size(target->output_path, target->size)) {
            mft_note_recovered_output(
                target->output_path,
                (long long)target->abs_offset
            );
            if (before == TARGET_MISSED && plan->missed > 0) {
                plan->missed--;
            } else if (before == TARGET_DEFERRED && plan->deferred > 0) {
                plan->deferred--;
            }
            target->state = TARGET_DONE;
            already_present++;
            continue;
        }

        if (!recovery_runs_within_source(config, target->runs, target->run_count)) {
            target->state = TARGET_SKIPPED;
            snprintf(target->last_error, sizeof(target->last_error), "outside source");
            plan->skipped++;
            outside_source++;
            continue;
        }
        if (recovery_target_looks_like_image(target) &&
            recovery_runner_target_should_skip_image_fd(
                image_fd,
                target,
                buffer,
                READ_SIZE)) {
            if (before == TARGET_MISSED && plan->missed > 0) {
                plan->missed--;
            } else if (before == TARGET_DEFERRED && plan->deferred > 0) {
                plan->deferred--;
            }
            target->state = TARGET_SKIPPED;
            snprintf(target->last_error, sizeof(target->last_error), "image filtered");
            plan->skipped++;
            skipped_image_filter++;
            continue;
        }

        attempted++;
        pthread_mutex_unlock(&plan->mutex);
        if (direct_recover_target(image_fd, target, buffer)) {
            int moved_to_unsure = maybe_relocate_deleted_jpeg_to_unsure_local(target);

            if (target->created_unix > 0) {
                (void)mft_engine_apply_created_time_value_to_path(
                    target->output_path,
                    target->created_unix
                );
            }
            mft_note_recovered_output(
                target->output_path,
                (long long)target->abs_offset
            );

            pthread_mutex_lock(&plan->mutex);
            if (before == TARGET_MISSED && plan->missed > 0) {
                plan->missed--;
            } else if (before == TARGET_DEFERRED && plan->deferred > 0) {
                plan->deferred--;
            }
            target->state = TARGET_DONE;
            target->remaining = 0;
            plan->recovered++;
            recovered++;
            if (moved_to_unsure) {
                unsure_moved++;
            }
            if (recovery_target_is_partial(target)) {
                log_verbose(
                    "Direct partial recovery succeeded: offset=%llu saved=%llu expected=%llu path=%s",
                    (unsigned long long)target->abs_offset,
                    (unsigned long long)target->size,
                    (unsigned long long)target->expected_size,
                    target->output_path
                );
            }
        } else {
            const char *failure_class;

            pthread_mutex_lock(&plan->mutex);
            if (stop_requested()) {
                break;
            }
            if (target->state != TARGET_MISSED) {
                if (before == TARGET_DEFERRED && plan->deferred > 0) {
                    plan->deferred--;
                }
                target->state = TARGET_MISSED;
                plan->missed++;
            }
            log_verbose(
                "Direct missed recovery failed: offset=%llu size=%llu path=%s reason=%s",
                (unsigned long long)target->abs_offset,
                (unsigned long long)target->size,
                target->source_path,
                target->last_error[0] != '\0' ? target->last_error : "unknown"
            );
            failure_class = recovery_runner_failure_class(target->last_error);
            if (strcmp(failure_class, "read_error") == 0) {
                failed_read_error++;
            } else if (strcmp(failure_class, "start_mismatch") == 0) {
                failed_start_mismatch++;
            } else if (strcmp(failure_class, "truncated_or_end_mismatch") == 0) {
                failed_truncated_or_end++;
            } else if (strcmp(failure_class, "output_error") == 0) {
                failed_output_error++;
            } else if (strcmp(failure_class, "invalid_target") == 0) {
                failed_invalid_target++;
            } else if (strcmp(failure_class, "interrupted") == 0) {
                failed_interrupted++;
            } else {
                failed_unknown++;
            }
            failed++;
        }
    }
    pthread_mutex_unlock(&plan->mutex);

    free(buffer);
    close(image_fd);
    elapsed = monotonic_seconds() - started_at;

    log_info(
        "Direct missed recovery: attempted=%zu recovered=%zu already_present=%zu outside_source=%zu failed=%zu t=%.2fs",
        attempted,
        recovered,
        already_present,
        outside_source,
        failed,
        elapsed
    );
    if (failed > 0) {
        log_info(
            "Direct missed recovery failures: read_error=%zu start_mismatch=%zu truncated_or_end=%zu output_error=%zu invalid_target=%zu interrupted=%zu unknown=%zu",
            failed_read_error,
            failed_start_mismatch,
            failed_truncated_or_end,
            failed_output_error,
            failed_invalid_target,
            failed_interrupted,
            failed_unknown
        );
    }
    if (skipped_image_filter > 0) {
        log_info(
            "Direct missed recovery skips: image_filter=%zu",
            skipped_image_filter
        );
    }
    if (unsure_moved > 0) {
        log_info(
            "Direct missed recovery unsure JPEGs: moved=%zu",
            unsure_moved
        );
    }
    return !stop_requested();
}

static int recovery_plan_replay_missed_jpeg_targets(
    RecoveryPlan *plan,
    const Config *config
)
{
    int image_fd;
    unsigned char *buffer;
    double started_at;
    double elapsed;
    size_t attempted = 0;
    size_t recovered = 0;
    size_t failed = 0;
    size_t unsure_moved = 0;
    size_t i;

    if (plan == NULL || config == NULL) {
        return 0;
    }

    started_at = monotonic_seconds();
    image_fd = open(config->image_path, O_RDONLY);
    if (image_fd < 0) {
        log_error("Failed to open input for JPEG replay recovery: %s", config->image_path);
        return 0;
    }

    buffer = (unsigned char *)malloc(READ_SIZE);
    if (buffer == NULL) {
        close(image_fd);
        return 0;
    }

    pthread_mutex_lock(&plan->mutex);
    for (i = 0; i < plan->count && !stop_requested(); i++) {
        RecoveryTarget *target = &plan->items[i];

        if (target->state != TARGET_MISSED ||
            target->validator_id != RECOVERY_VALIDATOR_JPEG ||
            strcmp(recovery_runner_failure_class(target->last_error), "start_mismatch") != 0) {
            continue;
        }

        attempted++;
        pthread_mutex_unlock(&plan->mutex);
        if (recovery_runner_recover_target_replay_fd(
                image_fd,
                target,
                buffer,
                READ_SIZE,
                stop_requested)) {
            int moved_to_unsure = maybe_relocate_deleted_jpeg_to_unsure_local(target);

            if (target->created_unix > 0) {
                (void)mft_engine_apply_created_time_value_to_path(
                    target->output_path,
                    target->created_unix
                );
            }

            pthread_mutex_lock(&plan->mutex);
            if (plan->missed > 0) {
                plan->missed--;
            }
            target->state = TARGET_DONE;
            target->remaining = 0;
            plan->recovered++;
            recovered++;
            if (moved_to_unsure) {
                unsure_moved++;
            }
        } else {
            pthread_mutex_lock(&plan->mutex);
            failed++;
            log_verbose(
                "Replay missed JPEG recovery failed: offset=%llu size=%llu path=%s reason=%s",
                (unsigned long long)target->abs_offset,
                (unsigned long long)target->size,
                target->source_path,
                target->last_error[0] != '\0' ? target->last_error : "unknown"
            );
        }
    }
    pthread_mutex_unlock(&plan->mutex);

    free(buffer);
    close(image_fd);
    elapsed = monotonic_seconds() - started_at;

    if (attempted > 0 || recovered > 0 || failed > 0) {
        log_info(
            "Replay missed JPEGs: attempted=%zu recovered=%zu failed=%zu t=%.2fs",
            attempted,
            recovered,
            failed,
            elapsed
        );
        if (unsure_moved > 0) {
            log_info(
                "Replay missed JPEGs unsure moves: moved=%zu",
                unsure_moved
            );
        }
    }

    return !stop_requested();
}

static int recovery_plan_replay_missed_png_targets(
    RecoveryPlan *plan,
    const Config *config
)
{
    int image_fd;
    unsigned char *buffer;
    double started_at;
    double elapsed;
    size_t attempted = 0;
    size_t recovered = 0;
    size_t failed = 0;
    size_t i;

    if (plan == NULL || config == NULL) {
        return 0;
    }

    started_at = monotonic_seconds();
    image_fd = open(config->image_path, O_RDONLY);
    if (image_fd < 0) {
        log_error("Failed to open input for PNG replay recovery: %s", config->image_path);
        return 0;
    }

    buffer = (unsigned char *)malloc(READ_SIZE);
    if (buffer == NULL) {
        close(image_fd);
        return 0;
    }

    pthread_mutex_lock(&plan->mutex);
    for (i = 0; i < plan->count && !stop_requested(); i++) {
        RecoveryTarget *target = &plan->items[i];

        if (target->state != TARGET_MISSED ||
            !streq_ci(target->extension, "png") ||
            strcmp(recovery_runner_failure_class(target->last_error), "start_mismatch") != 0) {
            continue;
        }

        attempted++;
        pthread_mutex_unlock(&plan->mutex);
        if (recovery_runner_recover_target_replay_fd(
                image_fd,
                target,
                buffer,
                READ_SIZE,
                stop_requested)) {
            if (target->created_unix > 0) {
                (void)mft_engine_apply_created_time_value_to_path(
                    target->output_path,
                    target->created_unix
                );
            }
            pthread_mutex_lock(&plan->mutex);
            if (plan->missed > 0) {
                plan->missed--;
            }
            target->state = TARGET_DONE;
            target->remaining = 0;
            plan->recovered++;
            recovered++;
        } else {
            pthread_mutex_lock(&plan->mutex);
            failed++;
            log_verbose(
                "Replay missed PNG recovery failed: offset=%llu size=%llu path=%s reason=%s",
                (unsigned long long)target->abs_offset,
                (unsigned long long)target->size,
                target->source_path,
                target->last_error[0] != '\0' ? target->last_error : "unknown"
            );
        }
    }
    pthread_mutex_unlock(&plan->mutex);

    free(buffer);
    close(image_fd);
    elapsed = monotonic_seconds() - started_at;

    if (attempted > 0 || recovered > 0 || failed > 0) {
        log_info(
            "Replay missed PNGs: attempted=%zu recovered=%zu failed=%zu t=%.2fs",
            attempted,
            recovered,
            failed,
            elapsed
        );
    }

    return !stop_requested();
}

static int recovery_plan_replay_missed_mov_targets(
    RecoveryPlan *plan,
    const Config *config
)
{
    int image_fd;
    unsigned char *buffer;
    double started_at;
    double elapsed;
    size_t attempted = 0;
    size_t recovered = 0;
    size_t failed = 0;
    size_t i;

    if (plan == NULL || config == NULL) {
        return 0;
    }

    started_at = monotonic_seconds();
    image_fd = open(config->image_path, O_RDONLY);
    if (image_fd < 0) {
        log_error("Failed to open input for MOV replay recovery: %s", config->image_path);
        return 0;
    }

    buffer = (unsigned char *)malloc(READ_SIZE);
    if (buffer == NULL) {
        close(image_fd);
        return 0;
    }

    pthread_mutex_lock(&plan->mutex);
    for (i = 0; i < plan->count && !stop_requested(); i++) {
        RecoveryTarget *target = &plan->items[i];

        if (target->state != TARGET_MISSED ||
            !(streq_ci(target->extension, "mov") ||
              streq_ci(target->extension, "mp4") ||
              streq_ci(target->extension, "m4v") ||
              streq_ci(target->extension, "3gp") ||
              streq_ci(target->extension, "3g2")) ||
            strcmp(recovery_runner_failure_class(target->last_error), "start_mismatch") != 0) {
            continue;
        }

        attempted++;
        pthread_mutex_unlock(&plan->mutex);
        if (recovery_runner_recover_target_replay_fd(
                image_fd,
                target,
                buffer,
                READ_SIZE,
                stop_requested)) {
            if (target->created_unix > 0) {
                (void)mft_engine_apply_created_time_value_to_path(
                    target->output_path,
                    target->created_unix
                );
            }
            pthread_mutex_lock(&plan->mutex);
            if (plan->missed > 0) {
                plan->missed--;
            }
            target->state = TARGET_DONE;
            target->remaining = 0;
            plan->recovered++;
            recovered++;
        } else {
            pthread_mutex_lock(&plan->mutex);
            failed++;
            log_verbose(
                "Replay missed MOV recovery failed: offset=%llu size=%llu path=%s reason=%s",
                (unsigned long long)target->abs_offset,
                (unsigned long long)target->size,
                target->source_path,
                target->last_error[0] != '\0' ? target->last_error : "unknown"
            );
        }
    }
    pthread_mutex_unlock(&plan->mutex);

    free(buffer);
    close(image_fd);
    elapsed = monotonic_seconds() - started_at;

    if (attempted > 0 || recovered > 0 || failed > 0) {
        log_info(
            "Replay missed MOVs: attempted=%zu recovered=%zu failed=%zu t=%.2fs",
            attempted,
            recovered,
            failed,
            elapsed
        );
    }

    return !stop_requested();
}

static int parse_record(const unsigned char *record, uint64_t offset, MftEntry *entry)
{
    MftProbeEntry probe;

    if (record == NULL || entry == NULL ||
        !mft_probe_parse_record(record, offset, &probe)) {
        return 0;
    }

    memset(entry, 0, sizeof(*entry));
    entry->offset = probe.offset;
    entry->record = probe.record;
    entry->raw_record = probe.raw_record;
    entry->base_record_ref = probe.base_record_ref;
    entry->base_record_seq = probe.base_record_seq;
    entry->parent = probe.parent;
    entry->data_offset = probe.data_offset;
    entry->data_low_vcn = probe.data_low_vcn;
    entry->volume_index = MFT_VOLUME_INDEX_NONE;
    entry->flags = probe.flags;
    entry->created_filetime = probe.created_filetime;
    entry->has_data = probe.has_data;
    entry->resident = probe.resident;
    entry->data_size = probe.data_size;
    entry->first_lcn = probe.first_lcn;
    entry->run_clusters = probe.run_clusters;
    entry->run_count = probe.run_count;
    entry->run_total_clusters = probe.run_total_clusters;
    entry->max_lcn_end = probe.max_lcn_end;
    entry->stored_run_count = probe.stored_run_count;
    entry->run_truncated = probe.run_truncated;
    memcpy(entry->runs, probe.runs, sizeof(entry->runs));
    snprintf(entry->name, sizeof(entry->name), "%s", probe.name);
    snprintf(entry->created, sizeof(entry->created), "%s", probe.created);
    return probe.name[0] != '\0';
}

static void copy_probe_to_entry(const MftProbeEntry *probe, MftEntry *entry)
{
    if (probe == NULL || entry == NULL) {
        return;
    }

    memset(entry, 0, sizeof(*entry));
    entry->offset = probe->offset;
    entry->record = probe->record;
    entry->raw_record = probe->raw_record;
    entry->base_record_ref = probe->base_record_ref;
    entry->base_record_seq = probe->base_record_seq;
    entry->parent = probe->parent;
    entry->data_offset = probe->data_offset;
    entry->data_low_vcn = probe->data_low_vcn;
    entry->volume_index = MFT_VOLUME_INDEX_NONE;
    entry->flags = probe->flags;
    entry->created_filetime = probe->created_filetime;
    entry->has_data = probe->has_data;
    entry->resident = probe->resident;
    entry->data_size = probe->data_size;
    entry->first_lcn = probe->first_lcn;
    entry->run_clusters = probe->run_clusters;
    entry->run_count = probe->run_count;
    entry->run_total_clusters = probe->run_total_clusters;
    entry->max_lcn_end = probe->max_lcn_end;
    entry->stored_run_count = probe->stored_run_count;
    entry->run_truncated = probe->run_truncated;
    memcpy(entry->runs, probe->runs, sizeof(entry->runs));
    snprintf(entry->name, sizeof(entry->name), "%s", probe->name);
    entry->name_namespace = probe->name_namespace;
    snprintf(entry->created, sizeof(entry->created), "%s", probe->created);
}

static void assign_primary_mft_logical_identity(
    const Config *config,
    MftEntry *entry,
    uint64_t logical_record
)
{
    if (entry == NULL) {
        return;
    }

    /*
     * Primary-$MFT-directed scans walk the logical MFT stream in record order
     * even when the record header's own record number is stale or zeroed.
     * Re-derive the stable logical record id here so parent chains and
     * additive --fold reruns can rebuild paths consistently.
     */
    if (logical_record <= (uint64_t)INT32_MAX) {
        entry->record = (int)logical_record;
    }
    entry->family = 0;
    assign_entry_volume(config, entry);
}

static int compare_extent_record_for_merge(const void *left, const void *right)
{
    const MftEntry *a = (const MftEntry *)left;
    const MftEntry *b = (const MftEntry *)right;

    if (a->volume_index < b->volume_index) {
        return -1;
    }
    if (a->volume_index > b->volume_index) {
        return 1;
    }
    if (a->family < b->family) {
        return -1;
    }
    if (a->family > b->family) {
        return 1;
    }
    if (a->base_record_ref < b->base_record_ref) {
        return -1;
    }
    if (a->base_record_ref > b->base_record_ref) {
        return 1;
    }
    if (a->data_low_vcn < b->data_low_vcn) {
        return -1;
    }
    if (a->data_low_vcn > b->data_low_vcn) {
        return 1;
    }
    if (a->offset < b->offset) {
        return -1;
    }
    if (a->offset > b->offset) {
        return 1;
    }
    return 0;
}

static void merge_nonresident_extent_into_entry(MftEntry *base, const MftEntry *extent)
{
    size_t run_index;

    if (base == NULL || extent == NULL || !extent->has_data || extent->resident) {
        return;
    }

    if (!base->has_data || base->resident) {
        base->has_data = 1;
        base->resident = 0;
        base->data_offset = -1;
        base->data_size = 0;
        base->data_low_vcn = 0;
        base->first_lcn = 0;
        base->run_clusters = 0;
        base->run_count = 0;
        base->run_total_clusters = 0;
        base->max_lcn_end = 0;
        base->stored_run_count = 0;
        base->run_truncated = 0;
        memset(base->runs, 0, sizeof(base->runs));
    }

    if (extent->data_size > base->data_size) {
        base->data_size = extent->data_size;
    }
    if (base->first_lcn == 0 && extent->first_lcn > 0) {
        base->first_lcn = extent->first_lcn;
        base->run_clusters = extent->run_clusters;
    }
    base->run_count += extent->run_count;
    base->run_total_clusters += extent->run_total_clusters;
    if (extent->max_lcn_end > base->max_lcn_end) {
        base->max_lcn_end = extent->max_lcn_end;
    }
    if (extent->run_truncated) {
        base->run_truncated = 1;
    }

    for (run_index = 0; run_index < extent->stored_run_count; run_index++) {
        if (extent->runs[run_index].clusters == 0) {
            continue;
        }
        if (base->stored_run_count < MFT_ENTRY_MAX_RUNS) {
            base->runs[base->stored_run_count++] = extent->runs[run_index];
        } else {
            base->run_truncated = 1;
        }
    }

    if (base->first_lcn == 0 && base->stored_run_count > 0) {
        base->first_lcn = base->runs[0].lcn;
        base->run_clusters = base->runs[0].clusters;
    }
}

static void merge_extent_record_into_entry(MftEntry *base, const MftEntry *extent)
{
    if (base == NULL || extent == NULL || !extent->has_data) {
        return;
    }

    if (extent->resident) {
        if (!base->has_data ||
            (base->resident && base->data_size == 0) ||
            (!base->resident && base->stored_run_count == 0 && base->data_size == 0)) {
            base->has_data = 1;
            base->resident = 1;
            base->data_offset = extent->data_offset;
            base->data_size = extent->data_size;
            base->data_low_vcn = 0;
            base->first_lcn = 0;
            base->run_clusters = 0;
            base->run_count = 0;
            base->run_total_clusters = 0;
            base->max_lcn_end = 0;
            base->stored_run_count = 0;
            base->run_truncated = 0;
            memset(base->runs, 0, sizeof(base->runs));
        }
        return;
    }

    merge_nonresident_extent_into_entry(base, extent);
}

static int write_binary_row_mftprobe(FILE *bin, const MftEntry *entry)
{
    unsigned char row[BIN_ROW_SIZE_V3];
    uint16_t name_len = (uint16_t)strlen(entry->name);
    uint32_t stored_run_count = (uint32_t)entry->stored_run_count;
    size_t i;

    memset(row, 0, sizeof(row));
    memcpy(row, BIN_MAGIC_V3, 7);
    wr64(row + 8, entry->offset);
    wr32(row + 16, (uint32_t)entry->record);
    wr64(row + 20, entry->parent);
    wr32(row + 28, entry->family);
    wr16(row + 32, entry->flags);
    wr16(row + 34, name_len);
    wr_i64(row + 36, entry->data_offset);
    wr64(row + 44, entry->data_size);
    wr64(row + 52, entry->first_lcn);
    wr64(row + 60, entry->run_clusters);
    wr32(row + 68, (uint32_t)entry->raw_record);
    snprintf((char *)(row + 72), 32, "%s", entry->created);
    wr64(row + 104, entry->volume_offset);
    wr64(row + 112, entry->volume_cluster_size);
    wr64(row + 120, entry->volume_serial);
    wr64(row + 128, entry->volume_size);
    wr32(row + 136, entry->volume_index);
    wr32(row + 140, stored_run_count);
    wr32(row + 144, (uint32_t)(entry->run_truncated ? 1U : 0U));

    if (fwrite(row, 1, sizeof(row), bin) != sizeof(row) ||
        fwrite(entry->name, 1, name_len, bin) != name_len) {
        return 0;
    }

    for (i = 0; i < entry->stored_run_count; i++) {
        unsigned char run_row[16];

        wr64(run_row, entry->runs[i].lcn);
        wr64(run_row + 8, entry->runs[i].clusters);
        if (fwrite(run_row, 1, sizeof(run_row), bin) != sizeof(run_row)) {
            return 0;
        }
    }

    return 1;
}

static int read_binary_row_mftprobe(FILE *bin, MftEntry *entry)
{
    unsigned char row[BIN_ROW_SIZE_V3];
    uint16_t name_len;
    uint32_t stored_run_count = 0;
    int version;
    size_t fixed_size;
    size_t i;

    memset(row, 0, sizeof(row));
    if (fread(row, 1, BIN_ROW_SIZE_V1, bin) != BIN_ROW_SIZE_V1) {
        return 0;
    }
    if (memcmp(row, BIN_MAGIC_V3, 7) == 0) {
        version = 3;
        fixed_size = BIN_ROW_SIZE_V3;
        if (fread(row + BIN_ROW_SIZE_V1, 1, fixed_size - BIN_ROW_SIZE_V1, bin) !=
            fixed_size - BIN_ROW_SIZE_V1) {
            return feof(bin) ? 0 : -1;
        }
    } else if (memcmp(row, BIN_MAGIC_V2, 7) == 0) {
        version = 2;
        fixed_size = BIN_ROW_SIZE;
        if (fread(row + BIN_ROW_SIZE_V1, 1, fixed_size - BIN_ROW_SIZE_V1, bin) !=
            fixed_size - BIN_ROW_SIZE_V1) {
            return feof(bin) ? 0 : -1;
        }
    } else if (memcmp(row, BIN_MAGIC_V1, 7) == 0) {
        version = 1;
        fixed_size = BIN_ROW_SIZE_V1;
    } else {
        return 0;
    }
    (void)fixed_size;

    name_len = rd16(row + 34);
    if (name_len == 0 || name_len >= NAME_MAX_LEN) {
        return 0;
    }

    memset(entry, 0, sizeof(*entry));
    entry->offset = rd64(row + 8);
    entry->record = (int)rd32(row + 16);
    entry->parent = rd64(row + 20);
    entry->family = rd32(row + 28);
    entry->flags = rd16(row + 32);
    entry->data_offset = (int64_t)rd64(row + 36);
    entry->data_size = rd64(row + 44);
    entry->first_lcn = rd64(row + 52);
    entry->run_clusters = rd64(row + 60);
    entry->raw_record = (int)rd32(row + 68);
    snprintf(entry->created, sizeof(entry->created), "%.*s", 31, (const char *)(row + 72));
    entry->volume_index = MFT_VOLUME_INDEX_NONE;
    if (version >= 2) {
        entry->volume_offset = rd64(row + 104);
        entry->volume_cluster_size = rd64(row + 112);
        entry->volume_serial = rd64(row + 120);
        entry->volume_size = rd64(row + 128);
        entry->volume_index = rd32(row + 136);
    }
    if (version >= 3) {
        stored_run_count = rd32(row + 140);
        entry->run_truncated = rd32(row + 144) != 0;
    }

    if (fread(entry->name, 1, name_len, bin) != name_len) {
        return feof(bin) ? 0 : -1;
    }
    entry->name[name_len] = '\0';
    if (version >= 3) {
        if (stored_run_count > MFT_ENTRY_MAX_RUNS) {
            return 0;
        }
        entry->stored_run_count = stored_run_count;
        for (i = 0; i < entry->stored_run_count; i++) {
            unsigned char run_row[16];

            if (fread(run_row, 1, sizeof(run_row), bin) != sizeof(run_row)) {
                return feof(bin) ? 0 : -1;
            }
            entry->runs[i].lcn = rd64(run_row);
            entry->runs[i].clusters = rd64(run_row + 8);
        }
    } else if (entry->first_lcn > 0 && entry->run_clusters > 0) {
        entry->stored_run_count = 1;
        entry->runs[0].lcn = entry->first_lcn;
        entry->runs[0].clusters = entry->run_clusters;
        entry->run_truncated = entry->run_count > 1;
    }
    entry->has_data = entry->data_size > 0;
    entry->resident = entry->data_offset >= 0 && entry->first_lcn == 0;
    return 1;
}

static int detect_binary_map_format(FILE *bin)
{
    unsigned char prefix[8];
    size_t read_count;

    if (bin == NULL) {
        return 0;
    }

    if (fseek(bin, 0L, SEEK_SET) != 0) {
        return 0;
    }

    read_count = fread(prefix, 1, sizeof(prefix), bin);
    if (read_count < 7U) {
        return 0;
    }

    if (memcmp(prefix, LEGACY_MAP_MAGIC, 7U) == 0 &&
        read_count >= 8U &&
        prefix[7] == '\0') {
        return 1;
    }

    if (memcmp(prefix, BIN_MAGIC_V3, 7U) == 0 ||
        memcmp(prefix, BIN_MAGIC_V2, 7U) == 0 ||
        memcmp(prefix, BIN_MAGIC_V1, 7U) == 0) {
        return 2;
    }

    return 0;
}

static int consume_legacy_map_header(FILE *bin)
{
    unsigned char magic[8];
    unsigned char header_rest[LEGACY_MAP_HEADER_SIZE - 8U];

    if (bin == NULL) {
        return 0;
    }

    if (fseek(bin, 0L, SEEK_SET) != 0 ||
        fread(magic, 1, sizeof(magic), bin) != sizeof(magic) ||
        memcmp(magic, LEGACY_MAP_MAGIC, 7U) != 0 ||
        fread(header_rest, 1, sizeof(header_rest), bin) != sizeof(header_rest)) {
        return 0;
    }

    return 1;
}

static int read_binary_row_legacy(FILE *bin, MftEntry *entry)
{
    unsigned char tag[4];
    unsigned char payload_len_raw[4];
    uint32_t payload_len;
    unsigned char *payload = NULL;
    uint32_t run_count;
    uint16_t name_len;
    uint32_t binary_flags;
    size_t cursor = 0;
    size_t i;
    int status = -1;

    if (bin == NULL || entry == NULL) {
        return -1;
    }

    if (fread(tag, 1, sizeof(tag), bin) != sizeof(tag)) {
        return feof(bin) ? 0 : -1;
    }
    if (memcmp(tag, LEGACY_RECORD_MAGIC, 4U) != 0) {
        return -1;
    }
    if (fread(payload_len_raw, 1, sizeof(payload_len_raw), bin) != sizeof(payload_len_raw)) {
        return feof(bin) ? 0 : -1;
    }

    payload_len = rd32(payload_len_raw);
    if (payload_len < LEGACY_MAP_RECORD_FIXED_SIZE) {
        return -1;
    }

    payload = (unsigned char *)malloc(payload_len);
    if (payload == NULL) {
        return -1;
    }
    if (fread(payload, 1, payload_len, bin) != payload_len) {
        if (feof(bin)) {
            status = 0;
        }
        goto done;
    }

    memset(entry, 0, sizeof(*entry));
    entry->record = (int)rd64(payload + cursor);
    cursor += 8;
    entry->raw_record = entry->record;
    entry->parent = rd64(payload + cursor);
    cursor += 8;
    cursor += 2; /* parent_seq */
    entry->flags = rd16(payload + cursor);
    cursor += 2;
    binary_flags = rd32(payload + cursor);
    cursor += 4;
    cursor += 4; /* record_size */
    cursor += 4; /* record_used */
    cursor += 4; /* record_allocated */
    cursor += 4; /* reserved */
    entry->offset = rd64(payload + cursor);
    cursor += 8;
    entry->data_offset = (int64_t)rd64(payload + cursor);
    cursor += 8;
    {
        int64_t family_base_offset = (int64_t)rd64(payload + cursor);

        entry->family = (uint32_t)hash_u64((uint64_t)family_base_offset);
        cursor += 8;
    }
    cursor += 8; /* created_filetime */
    entry->data_size = rd64(payload + cursor);
    cursor += 8;
    cursor += 8; /* allocated_size */
    cursor += 8; /* valid_data_size */
    entry->first_lcn = rd64(payload + cursor);
    cursor += 8;
    entry->run_clusters = rd64(payload + cursor);
    cursor += 8;
    run_count = rd32(payload + cursor);
    cursor += 4;
    name_len = rd16(payload + cursor);
    cursor += 2;
    cursor += 2; /* reserved */

    if (name_len == 0 ||
        name_len >= NAME_MAX_LEN ||
        payload_len < LEGACY_MAP_RECORD_FIXED_SIZE + (uint32_t)name_len + (run_count * 16U)) {
        goto done;
    }

    memcpy(entry->name, payload + cursor, name_len);
    entry->name[name_len] = '\0';
    cursor += name_len;

    entry->stored_run_count = run_count;
    if (entry->stored_run_count > MFT_ENTRY_MAX_RUNS) {
        entry->run_truncated = 1;
        entry->stored_run_count = MFT_ENTRY_MAX_RUNS;
    }

    for (i = 0; i < run_count; i++) {
        uint64_t lcn = rd64(payload + cursor);
        uint64_t clusters = rd64(payload + cursor + 8);

        if (i < entry->stored_run_count) {
            entry->runs[i].lcn = lcn;
            entry->runs[i].clusters = clusters;
        }

        cursor += 16;
    }

    entry->has_data = ((binary_flags & LEGACY_BINARY_FLAG_HAS_DATA) != 0U) ||
                      entry->data_size > 0;
    entry->resident = (binary_flags & LEGACY_BINARY_FLAG_IS_RESIDENT) != 0U;
    if (!entry->resident && entry->first_lcn > 0 && entry->stored_run_count == 0) {
        entry->stored_run_count = 1;
        entry->runs[0].lcn = entry->first_lcn;
        entry->runs[0].clusters = entry->run_clusters;
    }
    if (entry->resident || !entry->has_data) {
        entry->data_offset = -1;
    }
    entry->volume_index = MFT_VOLUME_INDEX_NONE;
    snprintf(entry->created, sizeof(entry->created), "UNKNOWN");
    status = 1;

done:
    free(payload);
    return status;
}

static int write_legacy_map_header(FILE *bin)
{
    unsigned char header[LEGACY_MAP_HEADER_SIZE];

    if (bin == NULL) {
        return 0;
    }

    memset(header, 0, sizeof(header));
    memcpy(header, LEGACY_MAP_MAGIC, 7U);
    wr16(header + 8, 1U);
    wr16(header + 10, LEGACY_MAP_HEADER_SIZE);
    wr32(header + 12, RECORD_SIZE);
    wr32(header + 16, 4096U);

    return fwrite(header, 1, sizeof(header), bin) == sizeof(header);
}

static int write_binary_row_legacy(FILE *bin, const MftEntry *entry)
{
    unsigned char fixed[LEGACY_MAP_RECORD_FIXED_SIZE];
    uint16_t name_len;
    uint32_t run_count;
    uint32_t payload_len;
    uint32_t flags = 0;
    size_t i;

    if (bin == NULL || entry == NULL) {
        return 0;
    }

    name_len = (uint16_t)strlen(entry->name);
    run_count = (uint32_t)entry->stored_run_count;
    payload_len = LEGACY_MAP_RECORD_FIXED_SIZE + (uint32_t)name_len + (run_count * 16U);
    if (name_len == 0) {
        return 1;
    }

    if (entry->has_data) {
        flags |= LEGACY_BINARY_FLAG_HAS_DATA;
    }
    if (entry->resident) {
        flags |= LEGACY_BINARY_FLAG_IS_RESIDENT;
    }

    memset(fixed, 0, sizeof(fixed));
    wr_i64(fixed + 0, (int64_t)entry->record);
    wr64(fixed + 8, entry->parent);
    wr16(fixed + 16, 0);
    wr16(fixed + 18, entry->flags);
    wr32(fixed + 20, flags);
    wr32(fixed + 24, RECORD_SIZE);
    wr32(fixed + 28, RECORD_SIZE);
    wr32(fixed + 32, RECORD_SIZE);
    wr32(fixed + 36, 0);
    wr64(fixed + 40, entry->offset);
    wr_i64(fixed + 48, entry->data_offset);
    wr_i64(fixed + 56, (int64_t)entry->family);
    wr64(fixed + 64, 0);
    wr64(fixed + 72, entry->data_size);
    wr64(fixed + 80, entry->data_size);
    wr64(fixed + 88, entry->data_size);
    wr64(fixed + 96, entry->first_lcn);
    wr64(fixed + 104, entry->run_clusters);
    wr32(fixed + 112, run_count);
    wr16(fixed + 116, name_len);
    wr16(fixed + 118, 0);

    if (fwrite(LEGACY_RECORD_MAGIC, 1, 4, bin) != 4 ||
        !write_u32_value(bin, payload_len) ||
        fwrite(fixed, 1, sizeof(fixed), bin) != sizeof(fixed) ||
        fwrite(entry->name, 1, name_len, bin) != name_len) {
        return 0;
    }

    for (i = 0; i < entry->stored_run_count; i++) {
        unsigned char run_row[16];

        wr64(run_row, entry->runs[i].lcn);
        wr64(run_row + 8, entry->runs[i].clusters);
        if (fwrite(run_row, 1, sizeof(run_row), bin) != sizeof(run_row)) {
            return 0;
        }
    }

    return 1;
}

static int write_binary_row(FILE *bin, const MftEntry *entry)
{
    if (g_binary_map_format == 1) {
        return write_binary_row_legacy(bin, entry);
    }

    return write_binary_row_mftprobe(bin, entry);
}

static int ensure_state_dir_for_out_dir(
    const char *out_dir,
    char *state_dir,
    size_t state_dir_size
)
{
    if (out_dir == NULL || out_dir[0] == '\0' ||
        state_dir == NULL || state_dir_size == 0) {
        return 0;
    }

    join_path(state_dir, state_dir_size, out_dir, APP_STATE_DIR_NAME);
    return ensure_parent_dirs(state_dir) && ensure_dir(state_dir);
}

static const char *recovery_target_state_label(RecoveryTargetState state)
{
    switch (state) {
        case TARGET_PENDING:
            return "pending";
        case TARGET_ACTIVE:
            return "active";
        case TARGET_QUEUED:
            return "queued";
        case TARGET_DONE:
            return "done";
        case TARGET_MISSED:
            return "missed";
        case TARGET_SKIPPED:
            return "skipped";
        case TARGET_DEFERRED:
            return "deferred";
        default:
            return "unknown";
    }
}

static void fprint_tsv_field(FILE *file, const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;

    if (file == NULL) {
        return;
    }
    if (cursor == NULL) {
        return;
    }

    while (*cursor != '\0') {
        unsigned char ch = *cursor++;

        if (ch == '\t' || ch == '\r' || ch == '\n') {
            fputc(' ', file);
        } else {
            fputc((int)ch, file);
        }
    }
}

static void fprint_recovery_runs_field(FILE *file, const RecoveryTarget *target)
{
    size_t i;

    if (file == NULL || target == NULL) {
        return;
    }

    for (i = 0; i < target->run_count; i++) {
        if (i > 0) {
            fputc(';', file);
        }
        fprintf(
            file,
            "%llu:%llu",
            (unsigned long long)target->runs[i].abs_offset,
            (unsigned long long)target->runs[i].byte_length
        );
    }
}

static int write_binary_map_snapshot(const Config *config, MftTable *table)
{
    FILE *bin = NULL;
    MftEntry *items = NULL;
    size_t count = 0;
    size_t i;
    char state_dir[PATH_MAX_LEN];
    char path[PATH_MAX_LEN];
    int ok = 0;

    if (config == NULL || table == NULL) {
        return 0;
    }
    if (!ensure_state_dir_for_out_dir(config->out_dir, state_dir, sizeof(state_dir))) {
        return 0;
    }
    if (!snapshot_entries(table, &items, &count)) {
        return 0;
    }

    join_path(path, sizeof(path), state_dir, "mft_map.c26mft");
    bin = fopen(path, "wb");
    if (bin == NULL) {
        goto cleanup;
    }
    if (g_binary_map_format == 1 && !write_legacy_map_header(bin)) {
        goto cleanup;
    }
    for (i = 0; i < count; i++) {
        if (!write_binary_row(bin, &items[i])) {
            goto cleanup;
        }
    }
    if (fflush(bin) != 0) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    if (bin != NULL) {
        fclose(bin);
    }
    free(items);
    return ok;
}

static int write_missed_targets_report(const Config *config, RecoveryPlan *plan)
{
    FILE *file = NULL;
    char state_dir[PATH_MAX_LEN];
    char path[PATH_MAX_LEN];
    size_t i;
    int ok = 0;

    if (config == NULL || plan == NULL) {
        return 0;
    }
    if (!ensure_state_dir_for_out_dir(config->out_dir, state_dir, sizeof(state_dir))) {
        return 0;
    }

    join_path(path, sizeof(path), state_dir, "missed_targets.tsv");
    file = fopen(path, "w");
    if (file == NULL) {
        return 0;
    }

    fprintf(
        file,
        "state\tfailure_class\tformat_id\text\trecord\tfamily\tabs_offset\tsize\texpected_size\trun_count\trun_truncated\tsource_path\toutput_path\truns\treason\n"
    );

    pthread_mutex_lock(&plan->mutex);
    for (i = 0; i < plan->count; i++) {
        const RecoveryTarget *target = &plan->items[i];
        const char *failure_class;

        if (target->state == TARGET_DONE) {
            continue;
        }

        failure_class =
            target->last_error[0] != '\0'
                ? recovery_runner_failure_class(target->last_error)
                : "";
        fprintf(
            file,
            "%s\t%s\t%u\t",
            recovery_target_state_label(target->state),
            failure_class,
            target->format_id
        );
        fprint_tsv_field(file, target->extension);
        fprintf(
            file,
            "\t%d\t%u\t%llu\t%llu\t%llu\t%zu\t%d\t",
            target->record,
            target->family,
            (unsigned long long)target->abs_offset,
            (unsigned long long)target->size,
            (unsigned long long)target->expected_size,
            target->run_count,
            target->run_truncated
        );
        fprint_tsv_field(file, target->source_path);
        fputc('\t', file);
        fprint_tsv_field(file, target->output_path);
        fputc('\t', file);
        fprint_recovery_runs_field(file, target);
        fputc('\t', file);
        fprint_tsv_field(file, target->last_error);
        fputc('\n', file);
    }
    pthread_mutex_unlock(&plan->mutex);

    ok = fflush(file) == 0;
    fclose(file);
    return ok;
}

static int snapshot_entries(MftTable *table, MftEntry **out_items, size_t *out_count)
{
    MftEntry *items = NULL;

    pthread_mutex_lock(&table->mutex);
    if (table->count > 0) {
        items = (MftEntry *)malloc(table->count * sizeof(*items));
        if (items != NULL) {
            memcpy(items, table->items, table->count * sizeof(*items));
        }
    }
    *out_count = table->count;
    pthread_mutex_unlock(&table->mutex);

    if (*out_count > 0 && items == NULL) {
        return 0;
    }
    *out_items = items;
    return 1;
}

static int write_users_selected_tree(const Config *config, MftTable *table)
{
    (void)config;
    (void)table;

    /*
     * The old human-readable Users selected tree report is intentionally
     * retired. We keep the call sites harmless so older flow structure does
     * not need special branching, but no report file is produced here.
     */
    return 1;
#if 0
    MftprobeUsersTreeOps ops = {
        snapshot_entries,
        stop_requested,
        build_record_index,
        is_users_root_entry,
        build_path_if_under_users_root,
        append_parent_dirs,
        append_path,
        mft_data_offset_for_entry,
        write_ascii_tree,
        free_paths,
        join_path,
        mftprobe_format_select_for_entry
    };

    return mftprobe_write_users_selected_tree(config, table, &ops);
#endif
}

static void signal_users_worker(UsersWorker *worker)
{
    pthread_mutex_lock(&worker->mutex);
    worker->refresh_requested = 1;
    pthread_cond_signal(&worker->cond);
    pthread_mutex_unlock(&worker->mutex);
}

static void stop_users_worker(UsersWorker *worker)
{
    pthread_mutex_lock(&worker->mutex);
    worker->done = 1;
    worker->refresh_requested = 1;
    pthread_cond_signal(&worker->cond);
    pthread_mutex_unlock(&worker->mutex);
}

static void *users_worker_main(void *arg)
{
    UsersWorker *worker = (UsersWorker *)arg;

    block_stop_signals_in_worker();
    for (;;) {
        int should_stop;
        int should_refresh;
        size_t count;

        pthread_mutex_lock(&worker->mutex);
        while (!worker->done && !worker->refresh_requested) {
            cond_wait_briefly(&worker->cond, &worker->mutex);
            if (stop_requested()) {
                worker->done = 1;
                worker->refresh_requested = 1;
            }
        }
        should_stop = worker->done;
        should_refresh = worker->refresh_requested;
        worker->refresh_requested = 0;
        pthread_mutex_unlock(&worker->mutex);

        pthread_mutex_lock(&worker->table->mutex);
        count = worker->table->count;
        pthread_mutex_unlock(&worker->table->mutex);

        if (should_refresh || should_stop) {
            double now = monotonic_seconds();
            int enough_time =
                worker->last_written_at <= 0.0 ||
                now - worker->last_written_at >= TREE_LIVE_REFRESH_MIN_SECONDS;

            if (!should_stop &&
                count > worker->last_written_count &&
                enough_time) {
                write_users_selected_tree(worker->config, worker->table);
                worker->last_written_at = now;
            }
            worker->last_written_count = count;
        }
        if (should_stop) {
            break;
        }
    }
    return NULL;
}

static void *sieve_worker_main(void *arg)
{
    SieveWorker *worker = (SieveWorker *)arg;
    RecordSeenSlot *seen_records;
    uint64_t last_offset = UINT64_MAX;
    uint64_t prev_offset = worker->initial_prev_offset;
    int prev_record = worker->initial_prev_record;
    int have_prev = worker->initial_have_prev;
    size_t seen_record_count = 0;
    int record_stats_disabled = 0;
    MftCandidate candidate;
    MftEntry entry;

    block_stop_signals_in_worker();
    worker->ok = 1;

    seen_records = (RecordSeenSlot *)calloc(RECORD_STATS_CAPACITY, sizeof(*seen_records));
    if (seen_records == NULL) {
        worker->ok = 0;
        offset_set_destroy(&worker->resume_offsets);
        queue_finish(worker->queue);
        event_queue_finish(worker->bin_queue);
        event_queue_finish(worker->live_queue);
        return NULL;
    }

    while (queue_pop(worker->queue, &candidate)) {
        MftEvent event;

        ATOMIC_ADD_U64(&worker->raw_records, 1U);
        if (!parse_record(candidate.bytes, candidate.offset, &entry)) {
            worker->hard_rejected_records++;
            continue;
        }

        if (entry.offset == last_offset ||
            (worker->resume_offsets.slots != NULL &&
             entry.offset <= worker->resume_offsets.max_offset &&
             offset_set_contains(&worker->resume_offsets, entry.offset))) {
            worker->duplicate_offsets++;
            worker->hard_rejected_records++;
            continue;
        }
        last_offset = entry.offset;

        if (have_prev && entry.offset > prev_offset &&
            (entry.offset - prev_offset) % RECORD_SIZE == 0) {
            uint64_t gap_records = (entry.offset - prev_offset) / RECORD_SIZE;
            uint64_t expected_record = (uint64_t)(uint32_t)prev_record + gap_records;

            if (gap_records <= MAX_INFER_GAP_RECORDS && expected_record <= (uint64_t)INT32_MAX) {
                entry.record = (int)expected_record;
            } else {
                worker->family_count++;
            }
        } else {
            worker->family_count++;
        }

        entry.family = worker->family_count;
        assign_entry_volume(worker->config, &entry);
        prev_offset = entry.offset;
        prev_record = entry.record;
        have_prev = 1;

        if (!worker->have_record) {
            worker->first_record_offset = entry.offset;
            worker->have_record = 1;
        }
        worker->last_record_offset = entry.offset;
        if (worker->mft_expected_end_offset > 0 &&
            entry.offset >= worker->mft_expected_end_offset) {
            worker->expected_end_miss_count++;
        }
        if (is_users_root_entry(&entry)) {
            worker->users_root_count++;
            if (!worker->have_users_root) {
                worker->users_root_first_seen_offset = entry.offset;
                worker->have_users_root = 1;
            }
        }
        if (strcmp(entry.name, "$MFT") == 0 && entry.run_count > 0) {
            uint64_t cluster_size = entry.volume_cluster_size;

            if (!entry_has_assigned_volume(&entry)) {
                cluster_size = 0;
            }
            worker->mft_run_count = entry.run_count;
            worker->mft_run_total_bytes = entry.run_total_clusters * cluster_size;
            worker->mft_run_max_lcn_end = entry.max_lcn_end;
            if (entry.max_lcn_end > 0 && cluster_size > 0) {
                worker->mft_expected_end_offset =
                    entry.volume_offset + entry.max_lcn_end * cluster_size;
            }
        }

        if (!record_stats_disabled) {
            if (record_seen_before(seen_records, RECORD_STATS_CAPACITY, entry.record)) {
                worker->duplicate_record_ids++;
                worker->soft_duplicate_record_ids_kept++;
            } else {
                seen_record_count++;
                if (seen_record_count >= (RECORD_STATS_CAPACITY / 2U)) {
                    record_stats_disabled = 1;
                }
            }
        }

        memset(&event, 0, sizeof(event));
        event.entry = entry;
        event.snapshot_relevant = entry_needed_for_binary_snapshot_with_root_scope(
            worker->config,
            &entry,
            &worker->root_scope_pruned
        );
        event.relevant =
            event.snapshot_relevant &&
            entry_needed_for_live_index(worker->config, &entry);

        if ((worker->config->root_scope_count == 0 || event.snapshot_relevant) &&
            !event_queue_push(worker->bin_queue, &event)) {
            if (!stop_requested()) {
                worker->ok = 0;
            }
            break;
        }

        if (event.relevant) {
            if (!event_queue_push(worker->live_queue, &event)) {
                if (!stop_requested()) {
                    worker->ok = 0;
                }
                break;
            }
        }

        ATOMIC_ADD_U64(&worker->accepted_records, 1U);
    }

    free(seen_records);
    offset_set_destroy(&worker->resume_offsets);
    root_scope_pruned_set_destroy(&worker->root_scope_pruned);
    queue_finish(worker->queue);
    event_queue_finish(worker->bin_queue);
    event_queue_finish(worker->live_queue);
    return NULL;
}

static void *bin_writer_worker_main(void *arg)
{
    BinWriterWorker *worker = (BinWriterWorker *)arg;
    FILE *bin;
    char path[PATH_MAX_LEN];
    MftEvent event;
    size_t pending_flush = 0;

    block_stop_signals_in_worker();
    worker->ok = 1;
    join_path(
        path,
        sizeof(path),
        worker->config->out_dir,
        APP_STATE_DIR_NAME "/mft_map.c26mft");
    if (!ensure_parent_dirs(path)) {
        fprintf(stderr, "failed to create parent dirs for binary log: %s\n", path);
        worker->ok = 0;
        event_queue_finish(worker->queue);
        return NULL;
    }
    bin = fopen(path, worker->config->resume_active ? "ab" : "wb");
    if (bin == NULL) {
        fprintf(stderr, "failed to open binary log: %s\n", path);
        worker->ok = 0;
        event_queue_finish(worker->queue);
        return NULL;
    }

    if (!worker->config->resume_active &&
        g_binary_map_format == 1 &&
        !write_legacy_map_header(bin)) {
        fprintf(stderr, "failed to write legacy binary map header\n");
        fclose(bin);
        worker->ok = 0;
        event_queue_finish(worker->queue);
        return NULL;
    }

    while (event_queue_pop(worker->queue, &event)) {
        if (!write_binary_row(bin, &event.entry)) {
            fprintf(stderr, "failed to write binary MFT row\n");
            worker->ok = 0;
            event_queue_finish(worker->queue);
            break;
        }
        ATOMIC_ADD_U64(&worker->rows_written, 1U);
        pending_flush++;
        if (pending_flush >= BIN_WRITER_FLUSH_EVENTS) {
            fflush(bin);
            pending_flush = 0;
        }
    }

    fflush(bin);
    fclose(bin);
    return NULL;
}

static void *live_index_worker_main(void *arg)
{
    LiveIndexWorker *worker = (LiveIndexWorker *)arg;
    LiveIndexState state;
    MftEvent event;
    size_t next_tree_refresh = TREE_INITIAL_REFRESH_RECORDS;

    block_stop_signals_in_worker();
    worker->ok = 1;
    if (!live_index_init(&state, worker->table)) {
        worker->ok = 0;
        event_queue_finish(worker->queue);
        return NULL;
    }

    while (event_queue_pop(worker->queue, &event)) {
        size_t table_index;
        int selected;
        int is_directory;
        LiveRecordKey event_key;

        if (!event.relevant) {
            continue;
        }

        pthread_mutex_lock(&worker->table->mutex);
        table_index = worker->table->count;
        if (!table_append(worker->table, &event.entry)) {
            pthread_mutex_unlock(&worker->table->mutex);
            fprintf(stderr, "failed to append live MFT entry\n");
            worker->ok = 0;
            event_queue_finish(worker->queue);
            break;
        }
        pthread_mutex_unlock(&worker->table->mutex);

        if ((table_index + 1U) >= next_tree_refresh) {
            signal_users_worker(worker->users_worker);
            if (next_tree_refresh <= SIZE_MAX - TREE_REFRESH_RECORDS) {
                next_tree_refresh += TREE_REFRESH_RECORDS;
            } else {
                next_tree_refresh = SIZE_MAX;
            }
        }

        if (!live_index_insert_record(&state, &event.entry, table_index)) {
            fprintf(stderr, "failed to update live MFT record index\n");
            worker->ok = 0;
            event_queue_finish(worker->queue);
            break;
        }

        selected =
            mftprobe_format_select_for_entry(worker->config, &event.entry) != NULL ||
            entry_is_generic_file_candidate(worker->config, &event.entry);
        is_directory = (event.entry.flags & 0x0002U) != 0;
        event_key = live_record_key_for_entry(&event.entry);

        if (selected) {
            LiveRecordKey missing_key;

            ATOMIC_ADD_U64(&worker->selected_candidates_seen, 1U);
            if (!live_index_try_selected_file(worker, &state, table_index, &missing_key)) {
                worker->ok = 0;
                event_queue_finish(worker->queue);
                break;
            }
            if (missing_key.record >= 0 &&
                !live_index_pending_insert(&state, table_index, missing_key)) {
                worker->ok = 0;
                event_queue_finish(worker->queue);
                break;
            }
            if (missing_key.record >= 0) {
                ATOMIC_ADD_U64(&worker->pending_waits_created, 1U);
            }
        }

        if (is_directory &&
            !live_index_retry_pending_for_key(worker, &state, event_key)) {
            worker->ok = 0;
            event_queue_finish(worker->queue);
            break;
        }
    }

    ATOMIC_STORE_U64(&worker->pending_remaining, live_index_count_pending_active(&state));
    live_index_destroy(&state);
    return NULL;
}

static size_t bounded_read_want(uint64_t total_read, uint64_t limit, size_t requested)
{
    if (limit != 0 && total_read + requested > limit) {
        return (size_t)(limit - total_read);
    }
    return requested;
}

static size_t capped_adaptive_read_size(size_t adaptive_read_size, uint64_t total_read, uint64_t cautious_until)
{
    size_t cap = total_read < cautious_until ? READ_RECOVERY_SIZE : READ_SIZE;

    if (adaptive_read_size == 0) {
        adaptive_read_size = READ_ERROR_MIN_SIZE;
    }
    if (adaptive_read_size > cap) {
        adaptive_read_size = cap;
    }
    if (adaptive_read_size < READ_ERROR_MIN_SIZE) {
        adaptive_read_size = READ_ERROR_MIN_SIZE;
    }
    return adaptive_read_size;
}

static int prefix_produce_mft_candidates(
    MftCandidateQueue *queue,
    const unsigned char *buffer,
    uint64_t absolute_base,
    size_t available
)
{
    size_t i = 0;

    if (queue == NULL || buffer == NULL || available < RECORD_SIZE) {
        return 1;
    }

    while (i + RECORD_SIZE <= available) {
        void *hit = memchr(buffer + i, 'F', available - RECORD_SIZE + 1U - i);

        if (hit == NULL) {
            break;
        }
        i = (size_t)((unsigned char *)hit - buffer);
        if (buffer[i] == 'F' && buffer[i + 1] == 'I' &&
            buffer[i + 2] == 'L' && buffer[i + 3] == 'E') {
            MftCandidate candidate;

            candidate.offset = absolute_base + i;
            memcpy(candidate.bytes, buffer + i, RECORD_SIZE);
            if (!queue_push(queue, &candidate)) {
                return stop_requested() ? 1 : 0;
            }
        }
        i++;
    }

    return 1;
}

static int prefix_produce_magic_candidates(
    MagicCandidateQueue *queue,
    const unsigned char *buffer,
    uint64_t absolute_base,
    size_t available
)
{
    (void)buffer;
    (void)absolute_base;
    (void)available;

    if (queue == NULL) {
        return 1;
    }

    return 1;
}

static void *prefix_worker_main(void *arg)
{
    PrefixWorker *worker = (PrefixWorker *)arg;
    unsigned char *scan_buffer;
    unsigned char carry[OVERLAP];
    size_t carry_len = 0;
    uint64_t carry_base = 0;
    ReadBlock block;

    block_stop_signals_in_worker();
    worker->ok = 1;
    scan_buffer = (unsigned char *)malloc(READ_SIZE + OVERLAP);
    if (scan_buffer == NULL) {
        worker->ok = 0;
        read_block_queue_finish(worker->read_queue);
        queue_finish(worker->mft_queue);
        return NULL;
    }

    while (read_block_queue_pop(worker->read_queue, &block)) {
        size_t prefix_len = 0;
        size_t available;
        uint64_t absolute_base = block.offset;

        ATOMIC_ADD_U64(&worker->blocks_processed, 1U);
        ATOMIC_ADD_U64(&worker->bytes_processed, (uint64_t)block.length);

        if (carry_len > 0 && carry_base + carry_len == block.offset) {
            memcpy(scan_buffer, carry, carry_len);
            prefix_len = carry_len;
            absolute_base = carry_base;
        } else {
            carry_len = 0;
        }

        memcpy(scan_buffer + prefix_len, block.data, block.length);
        available = prefix_len + block.length;

        if (!prefix_produce_mft_candidates(
                worker->mft_queue,
                scan_buffer,
                absolute_base,
                available) ||
            !prefix_produce_magic_candidates(
                worker->magic_queue,
                scan_buffer,
                absolute_base,
                available)) {
            worker->ok = stop_requested() ? 1 : 0;
            free(block.data);
            read_block_queue_finish(worker->read_queue);
            break;
        }

        if (!recovery_plan_process_buffer(
                worker->recovery_plan,
                worker->recovery_write_queue,
                scan_buffer,
                absolute_base,
                available)) {
            worker->ok = 0;
            free(block.data);
            read_block_queue_finish(worker->read_queue);
            break;
        }

        if (available > OVERLAP) {
            carry_len = OVERLAP;
            carry_base = absolute_base + available - carry_len;
            memcpy(carry, scan_buffer + available - carry_len, carry_len);
        } else {
            carry_len = available;
            carry_base = absolute_base;
            memcpy(carry, scan_buffer, carry_len);
        }

        free(block.data);
    }

    free(scan_buffer);
    queue_finish(worker->mft_queue);
    return NULL;
}

static uint64_t cautious_read_until(uint64_t offset)
{
    if (UINT64_MAX - offset < READ_RECOVERY_ZONE_BYTES) {
        return UINT64_MAX;
    }
    return offset + READ_RECOVERY_ZONE_BYTES;
}

static uint64_t read_error_skip_size(unsigned int consecutive_errors)
{
    uint64_t skip = READ_ERROR_FIRST_SKIP_SIZE;

    if (consecutive_errors >= 2U) {
        skip = READ_ERROR_SECOND_SKIP_SIZE;
    }
    if (consecutive_errors >= 3U) {
        skip = READ_ERROR_MAX_SKIP_SIZE;
    }
    return skip;
}

static int read_error_is_fatal_device_error(int error_code)
{
    if (error_code == ENXIO ||
        error_code == ENODEV ||
        error_code == EBADF) {
        return 1;
    }
#ifdef ENOMEDIUM
    if (error_code == ENOMEDIUM) {
        return 1;
    }
#endif
    return 0;
}

static size_t scan_read_with_fallback(
    FILE *image,
    const Config *config,
    unsigned char *buffer,
    size_t carry,
    uint64_t total_read,
    size_t want,
    uint64_t *skipped_bytes,
    int *skipped_errno_code,
    unsigned int *consecutive_errors,
    int *fatal_error
)
{
    size_t got;
    size_t small_want;
    size_t min_small_want;
    unsigned int error_count = 1U;
    int saved_errno = 0;

    /*
     * Try the optimistic large read first, then progressively degrade to
     * smaller reads when a flaky device starts failing. This keeps the
     * scan moving while still surfacing truly fatal device-loss errors.
     */
    if (skipped_bytes != NULL) {
        *skipped_bytes = 0;
    }
    if (skipped_errno_code != NULL) {
        *skipped_errno_code = 0;
    }
    if (fatal_error != NULL) {
        *fatal_error = 0;
    }
    if (image == NULL || config == NULL || buffer == NULL || want == 0) {
        return 0;
    }
    if (stop_requested()) {
        return 0;
    }

    errno = 0;
    got = fread(buffer + carry, 1, want, image);
    if (got > 0) {
        if (consecutive_errors != NULL) {
            *consecutive_errors = 0;
        }
        clearerr(image);
        return got;
    }
    if (!ferror(image)) {
        return 0;
    }

    saved_errno = errno;
    if (read_error_is_fatal_device_error(saved_errno)) {
        if (fatal_error != NULL) {
            *fatal_error = 1;
        }
        log_error(
            "Fatal read failure at byte %llu from %s: %s; device is no longer readable, stopping scan incomplete",
            (unsigned long long)total_read,
            config->image_path,
            saved_errno != 0 ? strerror(saved_errno) : "device unavailable"
        );
        clearerr(image);
        return 0;
    }
    if (consecutive_errors != NULL) {
        (*consecutive_errors)++;
        error_count = *consecutive_errors;
        if (*consecutive_errors == 1U || (*consecutive_errors % 128U) == 0U) {
            log_error(
                "Read failed at byte %llu from %s: %s; trying smaller reads",
                (unsigned long long)total_read,
                config->image_path,
                saved_errno != 0 ? strerror(saved_errno) : "I/O error"
            );
        }
    }

    clearerr(image);

    /*
     * After repeated errors in the same zone, avoid grinding on tiny reads.
     * A damaged disk is usually better served by logging a larger gap and
     * continuing than by forcing the firmware to retry 4 KiB forever.
     */
    if (error_count >= 3U) {
        goto skip_unreadable;
    }

    small_want = want / 4U;
    if (small_want > 1024U * 1024U) {
        small_want = 1024U * 1024U;
    }
    min_small_want = error_count >= 2U ? (64U * 1024U) : READ_ERROR_MIN_SIZE;

    while (small_want >= min_small_want) {
        if (stop_requested()) {
            return 0;
        }
        small_want = bounded_read_want(total_read, config->limit, small_want);
        if (small_want == 0) {
            return 0;
        }

        if (fseeko(image, (off_t)total_read, SEEK_SET) != 0) {
            saved_errno = errno;
            if (read_error_is_fatal_device_error(saved_errno) && fatal_error != NULL) {
                *fatal_error = 1;
            }
            return 0;
        }

        errno = 0;
        got = fread(buffer + carry, 1, small_want, image);
        if (got > 0) {
            clearerr(image);
            return got;
        }
        if (!ferror(image)) {
            return 0;
        }

        saved_errno = errno;
        if (read_error_is_fatal_device_error(saved_errno)) {
            if (fatal_error != NULL) {
                *fatal_error = 1;
            }
            log_error(
                "Fatal read failure at byte %llu from %s: %s; device is no longer readable, stopping scan incomplete",
                (unsigned long long)total_read,
                config->image_path,
                saved_errno != 0 ? strerror(saved_errno) : "device unavailable"
            );
            clearerr(image);
            return 0;
        }
        clearerr(image);
        small_want /= 4U;
    }

skip_unreadable:
    if (skipped_bytes != NULL) {
        uint64_t remaining = config->limit != 0 && total_read < config->limit
            ? config->limit - total_read
            : UINT64_MAX;
        uint64_t skip = read_error_skip_size(
            consecutive_errors != NULL ? *consecutive_errors : 1U
        );

        if (remaining != UINT64_MAX && skip > remaining) {
            skip = remaining;
        }
        if (skip > 0 && fseeko(image, (off_t)(total_read + skip), SEEK_SET) == 0) {
            *skipped_bytes = skip;
            if (skipped_errno_code != NULL) {
                *skipped_errno_code = saved_errno;
            }
            if (consecutive_errors == NULL ||
                *consecutive_errors == 1U ||
                (*consecutive_errors % 128U) == 0U) {
                log_error(
                    "Skipping unreadable %llu bytes at byte %llu",
                    (unsigned long long)skip,
                    (unsigned long long)total_read
                );
            }
        }
    }

    return 0;
}

static void append_read_error_gap(
    const Config *config,
    uint64_t offset,
    uint64_t bytes,
    int errno_code,
    const char *note
)
{
    char path[PATH_MAX_LEN];
    char run_id[PATH_MAX_LEN];
    FILE *file;
    int needs_header;

    if (config == NULL || config->out_dir == NULL || bytes == 0) {
        return;
    }

    join_path(path, sizeof(path), config->out_dir, "read_errors.tsv");
    needs_header = access(path, F_OK) != 0;
    file = fopen(path, "a");
    if (file == NULL) {
        return;
    }

    run_id[0] = '\0';
    {
        const char *slash = strrchr(config->out_dir, '/');
        const char *base = slash != NULL ? slash + 1 : config->out_dir;
        snprintf(run_id, sizeof(run_id), "%s", base != NULL ? base : "");
    }

    if (needs_header) {
        fprintf(
            file,
            "offset\tend_offset\tbytes\terrno_code\tgranularity_bytes\tsource_path\trun_id\tnote\n"
        );
    }
    fprintf(
        file,
        "%llu\t%llu\t%llu\t%d\t%u\t%s\t%s\t%s\n",
        (unsigned long long)offset,
        (unsigned long long)(offset + bytes),
        (unsigned long long)bytes,
        errno_code,
        (unsigned int)READ_ERROR_MIN_SIZE,
        config->image_path != NULL ? config->image_path : "",
        run_id,
        note != NULL && note[0] != '\0'
            ? note
            : "unreadable_gap_skipped_after_smaller_reads_absolute_offsets_preserved"
    );

    fclose(file);
}

static uint64_t advance_past_logged_read_gap(const Config *config, uint64_t start_offset)
{
    char path[PATH_MAX_LEN];
    char line[256];
    FILE *file;
    uint64_t adjusted = start_offset;

    if (config == NULL || config->out_dir == NULL) {
        return start_offset;
    }

    join_path(path, sizeof(path), config->out_dir, "read_errors.tsv");
    file = fopen(path, "r");
    if (file == NULL) {
        return start_offset;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned long long offset = 0;
        unsigned long long end_offset = 0;
        unsigned long long bytes = 0;

        if (sscanf(line, "%llu\t%llu\t%llu", &offset, &end_offset, &bytes) != 3) {
            continue;
        }
        if ((uint64_t)offset <= adjusted && adjusted < (uint64_t)end_offset) {
            adjusted = (uint64_t)end_offset;
        }
    }

    fclose(file);
    return adjusted;
}

static int scan_image(
    const Config *config,
    ReadBlockQueue *read_queue,
    MftCandidateQueue *mft_queue,
    MftEventQueue *bin_queue,
    MftEventQueue *live_queue,
    RecoveryWriteQueue *write_queue,
    MftTable *table,
    RecoveryPlan *recovery_plan
)
{
    FILE *image = NULL;
    unsigned char *buffer = NULL;
    Config read_config;
    uint64_t scan_limit;
    uint64_t total_read = config->start_offset;
    uint64_t next_state_update = config->start_offset + STATE_UPDATE_BYTES;
    uint64_t skipped_read_bytes = 0;
    uint64_t skipped_read_ranges = 0;
    int skipped_errno_code = 0;
    uint64_t cautious_until = config->resume_active
        ? cautious_read_until(config->start_offset)
        : 0;
    size_t adaptive_read_size = config->resume_active ? READ_ERROR_MIN_SIZE : READ_SIZE;
    unsigned int consecutive_read_errors = 0;
    int ok = 1;

    /*
     * Main sequential scan loop: read blocks from the source, adapt when
     * damaged regions appear, and feed downstream queues without letting
     * the producer outrun resume/state bookkeeping.
     */
    (void)mft_queue;
    (void)bin_queue;
    (void)live_queue;
    (void)write_queue;
    (void)table;
    (void)recovery_plan;

    read_config = *config;
    scan_limit = config->source_size;
    if (config->limit != 0 && (scan_limit == 0 || config->limit < scan_limit)) {
        scan_limit = config->limit;
    }
    read_config.limit = scan_limit;

    if (scan_limit != 0 && total_read > scan_limit) {
        total_read = scan_limit;
    }

    image = fopen(config->image_path, "rb");
    if (image == NULL) {
        fprintf(
            stderr,
            "failed to open image: %s (%s)\n",
            config->image_path,
            strerror(errno)
        );
        read_block_queue_finish(read_queue);
        return stop_requested() ? 1 : 0;
    }

    if (total_read > 0 &&
        fseeko(image, (off_t)total_read, SEEK_SET) != 0) {
        fprintf(stderr, "failed to seek to resume offset: %llu\n",
                (unsigned long long)total_read);
        ok = 0;
        goto cleanup;
    }

    while (!stop_requested() && (scan_limit == 0 || total_read < scan_limit)) {
        size_t read_cap = total_read < cautious_until ? READ_RECOVERY_SIZE : READ_SIZE;
        size_t want = bounded_read_want(total_read, scan_limit, adaptive_read_size);
        size_t got;
        uint64_t skipped = 0;
        int fatal_read_error = 0;
        ReadBlock block;

        adaptive_read_size = capped_adaptive_read_size(adaptive_read_size, total_read, cautious_until);
        want = bounded_read_want(total_read, scan_limit, adaptive_read_size);

        buffer = (unsigned char *)malloc(READ_SIZE);
        if (buffer == NULL) {
            ok = 0;
            goto cleanup;
        }

        got = scan_read_with_fallback(
            image,
            &read_config,
            buffer,
            0,
            total_read,
            want,
            &skipped,
            &skipped_errno_code,
            &consecutive_read_errors,
            &fatal_read_error
        );
        if (got == 0) {
            if (fatal_read_error) {
                ok = 0;
                free(buffer);
                buffer = NULL;
                goto cleanup;
            }
            if (skipped > 0) {
                append_read_error_gap(
                    config,
                    total_read,
                    skipped,
                    skipped_errno_code,
                    "unreadable_gap_skipped_after_smaller_reads_absolute_offsets_preserved"
                );
                skipped_read_bytes += skipped;
                skipped_read_ranges++;
                total_read += skipped;
                cautious_until = cautious_read_until(total_read);
                adaptive_read_size = READ_ERROR_MIN_SIZE;
                log_set_working_progress(total_read, 0);
                write_scan_state(config, total_read, 0);
                next_state_update = total_read + STATE_UPDATE_BYTES;
                free(buffer);
                buffer = NULL;
                continue;
            }
            free(buffer);
            buffer = NULL;
            break;
        }
        if (got < want && got >= READ_ERROR_MIN_SIZE) {
            adaptive_read_size = got;
        } else if (adaptive_read_size < READ_SIZE && got >= adaptive_read_size) {
            size_t next_read_size = adaptive_read_size * 4U;
            size_t cap = read_cap;

            adaptive_read_size = next_read_size > cap ? cap : next_read_size;
        }

        memset(&block, 0, sizeof(block));
        block.offset = total_read;
        block.length = got;
        block.data = buffer;
        if (!read_block_queue_push(read_queue, &block)) {
            free(buffer);
            buffer = NULL;
            ok = stop_requested() ? 1 : 0;
            goto cleanup;
        }
        buffer = NULL;

        total_read += got;
        log_set_working_progress(total_read, 0);

        if (total_read >= next_state_update) {
            uint64_t safe_offset =
                total_read > RESUME_BACKOFF_BYTES ? total_read - RESUME_BACKOFF_BYTES : 0;

            write_scan_state(config, safe_offset, 0);
            next_state_update = total_read + STATE_UPDATE_BYTES;
        }
    }

    if (stop_requested()) {
        log_info("Stop requested; closing partial MFT map and recovery outputs cleanly");
    }
    if (skipped_read_ranges > 0) {
        log_info(
            "I/O gaps skipped: ranges=%llu bytes=%llu; absolute offsets preserved, see %s/read_errors.tsv",
            (unsigned long long)skipped_read_ranges,
            (unsigned long long)skipped_read_bytes,
            config->out_dir
        );
    }

cleanup:
    {
        int completed =
            ok &&
            !stop_requested() &&
            (scan_limit == 0 || total_read >= scan_limit);
        uint64_t safe_offset =
            completed
                ? total_read
                : (total_read > RESUME_BACKOFF_BYTES ? total_read - RESUME_BACKOFF_BYTES : 0);

        write_scan_state(config, safe_offset, completed);
    }
    free(buffer);
    if (image != NULL) {
        fclose(image);
    }
    read_block_queue_finish(read_queue);
    return ok;
}

static int parse_state_value(const char *line, const char *key, char *out, size_t out_size)
{
    size_t key_len;
    size_t value_len;

    if (line == NULL || key == NULL || out == NULL || out_size == 0) {
        return 0;
    }

    key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0 || line[key_len] != '=') {
        return 0;
    }

    value_len = strcspn(line + key_len + 1U, "\r\n");
    if (value_len >= out_size) {
        value_len = out_size - 1U;
    }
    memcpy(out, line + key_len + 1U, value_len);
    out[value_len] = '\0';
    return 1;
}

static uint64_t parse_byte_count(const char *text)
{
    char *end = NULL;
    uint64_t value;

    if (text == NULL || text[0] == '\0') {
        return 0;
    }

    value = strtoull(text, &end, 10);
    if (end == text) {
        return 0;
    }

    while (*end == ' ' || *end == '\t') {
        end++;
    }
    if (*end == 'k' || *end == 'K') {
        value *= 1024ULL;
    } else if (*end == 'm' || *end == 'M') {
        value *= 1024ULL * 1024ULL;
    } else if (*end == 'g' || *end == 'G') {
        value *= 1024ULL * 1024ULL * 1024ULL;
    }

    return value;
}

static int write_scan_state(const Config *config, uint64_t scan_offset, int completed)
{
    FILE *state;

    if (config == NULL || config->state_path[0] == '\0') {
        return 1;
    }

    state = fopen(config->state_path, "w");
    if (state == NULL) {
        return 0;
    }

    fprintf(state, "version=1\n");
    fprintf(state, "source_id=%s\n", config->source_id);
    fprintf(state, "source_path=%s\n", config->image_path);
    fprintf(state, "scan_mode=folders\n");
    fprintf(state, "source_size=%llu\n", (unsigned long long)config->source_size);
    fprintf(state, "scan_offset=%llu\n", (unsigned long long)scan_offset);
    fprintf(state, "completed=%d\n", completed);

    return fclose(state) == 0;
}

static int load_scan_state(
    const Config *config,
    uint64_t *scan_offset,
    int *completed,
    char *scan_mode,
    size_t scan_mode_size
)
{
    FILE *state;
    char line[PATH_MAX_LEN + 64U];
    char source_id[128] = "";
    char source_path[PATH_MAX_LEN] = "";
    char parsed_scan_mode[32] = "";
    char value[128];
    uint64_t offset = 0;
    int done = 0;

    if (config == NULL || scan_offset == NULL || completed == NULL ||
        config->state_path[0] == '\0') {
        return 0;
    }

    state = fopen(config->state_path, "r");
    if (state == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), state) != NULL) {
        if (parse_state_value(line, "source_id", source_id, sizeof(source_id))) {
            continue;
        }
        if (parse_state_value(line, "source_path", source_path, sizeof(source_path))) {
            continue;
        }
        if (parse_state_value(line, "scan_mode", parsed_scan_mode, sizeof(parsed_scan_mode))) {
            continue;
        }
        if (parse_state_value(line, "scan_offset", value, sizeof(value))) {
            offset = strtoull(value, NULL, 10);
            continue;
        }
        if (parse_state_value(line, "completed", value, sizeof(value))) {
            done = atoi(value) != 0;
            continue;
        }
    }

    fclose(state);
    if (source_id[0] != '\0' &&
        strcmp(source_id, config->source_id) != 0) {
        return 0;
    }
    if (source_id[0] == '\0' &&
        source_path[0] != '\0' &&
        config->image_path != NULL &&
        strcmp(source_path, config->image_path) != 0) {
        return 0;
    }

    *scan_offset = offset;
    *completed = done;
    if (scan_mode != NULL && scan_mode_size > 0U) {
        snprintf(scan_mode, scan_mode_size, "%s", parsed_scan_mode);
    }
    return 1;
}

static int mft_binary_map_exists(const Config *config)
{
    char path[PATH_MAX_LEN];

    if (config == NULL || config->out_dir == NULL) {
        return 0;
    }

    join_path(
        path,
        sizeof(path),
        config->out_dir,
        APP_STATE_DIR_NAME "/mft_map.c26mft");
    return access(path, F_OK) == 0;
}

static uint64_t mft_binary_map_size(const Config *config)
{
    char path[PATH_MAX_LEN];
    struct stat st;

    if (config == NULL || config->out_dir == NULL) {
        return 0;
    }

    join_path(
        path,
        sizeof(path),
        config->out_dir,
        APP_STATE_DIR_NAME "/mft_map.c26mft");
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        return 0;
    }

    return (uint64_t)st.st_size;
}

static int mftprobe_preflight_open(const char *path)
{
    FILE *file;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "failed to open image: %s (%s)\n", path, strerror(errno));
        return 0;
    }
    fclose(file);
    return 1;
}

static int load_existing_binary_map(
    const Config *config,
    MftTable *table,
    SieveWorker *worker,
    int load_resume_offsets
)
{
    FILE *bin;
    char path[PATH_MAX_LEN];
    MftEntry entry;
    size_t total_rows = 0;
    size_t loaded = 0;
    size_t overlap_rows = 0;
    int map_format;
    double started_at;
    double phase_started_at;
    double open_detect_seconds = 0.0;
    double pass1_seconds = 0.0;
    double resume_set_init_seconds = 0.0;
    double rewind_seconds = 0.0;
    double pass2_seconds = 0.0;
    RootScopePrunedSet pruned_set = {0};

    if (config == NULL || table == NULL || worker == NULL) {
        return 0;
    }
    started_at = monotonic_seconds();

    join_path(
        path,
        sizeof(path),
        config->out_dir,
        APP_STATE_DIR_NAME "/mft_map.c26mft");
    bin = fopen(path, "rb");
    if (bin == NULL) {
        return 0;
    }

    map_format = detect_binary_map_format(bin);
    if (map_format == 0) {
        fclose(bin);
        return 0;
    }
    open_detect_seconds = monotonic_seconds() - started_at;
    g_binary_map_format = map_format;
    if (map_format == 1) {
        if (!consume_legacy_map_header(bin)) {
            fclose(bin);
            return 0;
        }
    } else if (fseek(bin, 0L, SEEK_SET) != 0) {
        fclose(bin);
        return 0;
    }

    if (load_resume_offsets) {
        log_info("Loading previous MFT map: pass 1/2 counting rows from %s", path);
        phase_started_at = monotonic_seconds();
        for (;;) {
            int read_status =
                (map_format == 1)
                    ? read_binary_row_legacy(bin, &entry)
                    : read_binary_row_mftprobe(bin, &entry);

            if (read_status == 0) {
                break;
            }
            if (read_status < 0) {
                fclose(bin);
                return 0;
            }

            if ((total_rows & 0xFFFFU) == 0 && stop_requested()) {
                fclose(bin);
                return 0;
            }
            assign_entry_volume(config, &entry);
            total_rows++;
            if (entry.offset >= config->start_offset) {
                overlap_rows++;
            }
        }
        pass1_seconds = monotonic_seconds() - phase_started_at;

        phase_started_at = monotonic_seconds();
        if (!offset_set_init(&worker->resume_offsets, overlap_rows)) {
            fclose(bin);
            return 0;
        }
        resume_set_init_seconds = monotonic_seconds() - phase_started_at;

        phase_started_at = monotonic_seconds();
        if (fseek(bin, 0L, SEEK_SET) != 0) {
            fclose(bin);
            return 0;
        }
        if (map_format == 1 && !consume_legacy_map_header(bin)) {
            fclose(bin);
            return 0;
        }
        rewind_seconds = monotonic_seconds() - phase_started_at;
        log_info(
            "Loading previous MFT map: pass 2/2 rows=%zu resume_overlap_estimate=%zu",
            total_rows,
            overlap_rows
        );
    } else {
        log_info("Loading previous MFT map: single-pass cache load from %s", path);
    }
    phase_started_at = monotonic_seconds();
    for (;;) {
        int read_status =
            (map_format == 1)
                ? read_binary_row_legacy(bin, &entry)
                : read_binary_row_mftprobe(bin, &entry);

        if (read_status == 0) {
            break;
        }
        if (read_status < 0) {
            root_scope_pruned_set_destroy(&pruned_set);
            fclose(bin);
            return 0;
        }

        if (((loaded + worker->resume_offsets.count) & 0xFFFFU) == 0 &&
            stop_requested()) {
            root_scope_pruned_set_destroy(&pruned_set);
            fclose(bin);
            return 0;
        }
        assign_entry_volume(config, &entry);
        if (!load_resume_offsets) {
            total_rows++;
        }
        if (entry_needed_for_live_index_with_root_scope(config, &entry, &pruned_set)) {
            if (!table_append(table, &entry)) {
                root_scope_pruned_set_destroy(&pruned_set);
                fclose(bin);
                return 0;
            }
            loaded++;
        }
        if (load_resume_offsets && entry.offset >= config->start_offset) {
            offset_set_add(&worker->resume_offsets, entry.offset);
        }
        if (entry.family > worker->family_count) {
            worker->family_count = entry.family;
        }
        worker->initial_prev_offset = entry.offset;
        worker->initial_prev_record = entry.record;
        worker->initial_have_prev = 1;
    }
    pass2_seconds = monotonic_seconds() - phase_started_at;

    root_scope_pruned_set_destroy(&pruned_set);
    fclose(bin);
    if (!prune_loaded_table_to_selected_root_scope(config, table)) {
        return 0;
    }
    log_info(
        "Loaded previous MFT map: rows=%zu live_index_pre_scope=%zu live_index=%zu resume_overlap_offsets=%zu",
        total_rows,
        loaded,
        table->count,
        load_resume_offsets ? worker->resume_offsets.count : 0U
    );
    log_info(
        "Resume map load timings: detect=%.2fs pass1=%.2fs offsetset=%.2fs rewind=%.2fs pass2=%.2fs total=%.2fs",
        open_detect_seconds,
        pass1_seconds,
        resume_set_init_seconds,
        rewind_seconds,
        pass2_seconds,
        monotonic_seconds() - started_at
    );
    return 1;
}

static void configure_source_id(const char *run_name, char *out, size_t out_size)
{
    if (out == NULL || out_size == 0) {
        return;
    }

    if (run_name != NULL && run_name[0] != '\0') {
        snprintf(out, out_size, "%s", run_name);
    } else {
        out[0] = '\0';
        return;
    }
    sanitize_id(out);
}

static void configure_timestamped_source_id(char *out, size_t out_size)
{
    time_t now;
    struct tm tm_value;

    if (out == NULL || out_size == 0) {
        return;
    }

    now = time(NULL);
    if (localtime_r(&now, &tm_value) == NULL) {
        snprintf(out, out_size, "run_unknown_pid%lu", (unsigned long)getpid());
        return;
    }

    snprintf(
        out,
        out_size,
        "run_%04d%02d%02d_%02d%02d%02d_pid%lu",
        tm_value.tm_year + 1900,
        tm_value.tm_mon + 1,
        tm_value.tm_mday,
        tm_value.tm_hour,
        tm_value.tm_min,
        tm_value.tm_sec,
        (unsigned long)getpid()
    );
    sanitize_id(out);
}

static int configure_unique_timestamped_source_id(
    const char *base_out_dir,
    char *out,
    size_t out_size
)
{
    char base[128];
    char candidate[128];
    char path[PATH_MAX_LEN];
    unsigned int suffix;

    configure_timestamped_source_id(base, sizeof(base));

    for (suffix = 0; suffix < 1000U; suffix++) {
        if (suffix == 0) {
            copy_text_truncated_local(candidate, sizeof(candidate), base);
        } else {
            char suffix_text[5];
            size_t base_len;

            snprintf(suffix_text, sizeof(suffix_text), "_%03u", suffix);
            copy_text_truncated_local(candidate, sizeof(candidate), base);
            base_len = strlen(candidate);
            if (base_len + strlen(suffix_text) >= sizeof(candidate)) {
                size_t keep_len = sizeof(candidate) - strlen(suffix_text) - 1U;

                candidate[keep_len] = '\0';
                base_len = keep_len;
            }

            memcpy(candidate + base_len, suffix_text, strlen(suffix_text) + 1U);
        }

        join_path(path, sizeof(path), base_out_dir, candidate);
        if (access(path, F_OK) != 0) {
            copy_text_truncated_local(out, out_size, candidate);
            return 1;
        }
    }

    return 0;
}

static void usage(const char *argv0)
{
    fprintf(
        stderr,
        "usage: %s --image PATH [--out DIR] [--run-name NAME] [--limit BYTES] [--resume]\n"
        "       [--categories LIST] [--formats LIST] [--dev-format EXT] [--deleted-filter 0|1|2] [--date-filter YYYYMMDD[-YYYYMMDD]]\n",
        argv0
    );
}

static int parse_date_filter_range_local(
    const char *value,
    int *out_start,
    int *out_end
)
{
    char copy[32];
    char *dash;
    int start_date = 0;
    int end_date = 0;

    if (value == NULL || out_start == NULL || out_end == NULL) {
        return 0;
    }
    if (strlen(value) >= sizeof(copy)) {
        return 0;
    }

    snprintf(copy, sizeof(copy), "%s", value);
    dash = strchr(copy, '-');
    if (dash != NULL) {
        *dash = '\0';
        if (!targeted_parse_exact_date(copy, &start_date) ||
            !targeted_parse_exact_date(dash + 1, &end_date) ||
            start_date > end_date) {
            return 0;
        }
    } else {
        if (!targeted_parse_exact_date(copy, &start_date)) {
            return 0;
        }
        end_date = start_date;
    }

    *out_start = start_date;
    *out_end = end_date;
    return 1;
}

static int mftprobe_engine_main(int argc, char **argv)
{
    Config config = {0};
    char resolved_image_path[PATH_MAX_LEN];
    MftTable table = {0};
    MftCandidateQueue queue = {0};
    MftEventQueue bin_event_queue = {0};
    MftEventQueue live_event_queue = {0};
    ReadBlockQueue read_queue = {0};
    RecoveryWriteQueue recovery_write_queue = {0};
    RecoveryPlan recovery_plan = {0};
    UsersWorker users_worker = {0};
    PrefixWorker prefix_worker = {0};
    SieveWorker sieve_worker = {0};
    BinWriterWorker bin_writer_worker = {0};
    LiveIndexWorker live_index_worker = {0};
    RecoveryWriterWorker recovery_writer_worker = {0};
    ThreadActivityStateContext thread_activity_context = {0};
    ThreadActivityWriterWorker thread_activity_writer = {0};
    pthread_t users_thread;
    pthread_t prefix_thread;
    pthread_t sieve_thread;
    pthread_t bin_writer_thread;
    pthread_t live_index_thread;
    pthread_t recovery_writer_thread;
    pthread_t thread_activity_thread;
    int users_thread_started = 0;
    int prefix_thread_started = 0;
    int bin_writer_thread_started = 0;
    int live_index_thread_started = 0;
    int recovery_writer_thread_started = 0;
    int thread_activity_thread_started = 0;
    int event_queues_initialized = 0;
    int read_queue_initialized = 0;
    int recovery_write_queue_initialized = 0;
    int sieve_thread_started = 0;
    int ok;
    int i;
    char base_out_dir[PATH_MAX_LEN];
    char source_out_dir[PATH_MAX_LEN];
    uint64_t resume_offset = 0;
    int resume_completed = 0;
    uint64_t existing_offset = 0;
    int existing_completed = 0;
    char existing_scan_mode[32] = "";
    char resume_scan_mode[32] = "";
    int run_name_provided = 0;
    int additive_users_pass = 0;
    int additive_cache_only_pass = 0;
    int root_scope_preview_done = 0;
    int has_existing_mft_map = 0;
    uint64_t existing_mft_map_size = 0;
    char root_scope_error[256];
    const char *categories_csv = NULL;
    const char *formats_csv = NULL;
    const char *dev_format = NULL;
    MftprobeFormatSelection format_selection = {0};
    char format_selection_error[256];
    char active_format_text[512];
    uint64_t requested_start_offset = 0;
    int start_offset_explicit = 0;

    /*
     * Primary orchestrator for the threaded engine. It owns config,
     * queue/worker lifetime, resume decisions, and the cleanup boundaries
     * that need to stay consistent when the run exits early.
     */
    config.out_dir = APP_DEFAULT_OUTPUT_DIR;
    config.auto_recover_missed = 1;
    config.recovery_order = mftprobe_format_default_order();
    (void)mftprobe_format_load_common_profiles(&config, FORMAT_PROFILE_DB_PATH);

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--image") == 0 && i + 1 < argc) {
            config.image_path = argv[++i];
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            config.out_dir = argv[++i];
        } else if ((strcmp(argv[i], "--run-name") == 0 ||
                    strcmp(argv[i], "--name") == 0) && i + 1 < argc) {
            configure_source_id(argv[++i], config.source_id, sizeof(config.source_id));
            run_name_provided = 1;
        } else if (strcmp(argv[i], "--limit") == 0 && i + 1 < argc) {
            config.limit = strtoull(argv[++i], NULL, 0);
        } else if (strcmp(argv[i], "--resume") == 0) {
            config.resume_requested = 1;
        } else if ((strcmp(argv[i], "--start") == 0 ||
                    strcmp(argv[i], "--start-offset") == 0) && i + 1 < argc) {
            requested_start_offset = strtoull(argv[++i], NULL, 0);
            start_offset_explicit = 1;
        } else if (strcmp(argv[i], "--retry") == 0 ||
                   strcmp(argv[i], "--auto-recover-missed") == 0) {
            config.auto_recover_missed = 1;
        } else if (strcmp(argv[i], "--no-retry") == 0 ||
                   strcmp(argv[i], "--no-auto-recover-missed") == 0) {
            config.auto_recover_missed = 1;
        } else if (strcmp(argv[i], "--only-recover-missed") == 0) {
            config.only_recover_missed = 1;
        } else if (strcmp(argv[i], "--generic-file-targets") == 0) {
            config.generic_file_targets = 1;
        } else if (strcmp(argv[i], "--root-scope-defaulted") == 0) {
            config.root_scope_defaulted = 1;
        } else if ((strcmp(argv[i], "--categories") == 0 ||
                    strcmp(argv[i], "--category") == 0) && i + 1 < argc) {
            categories_csv = argv[++i];
        } else if ((strcmp(argv[i], "--formats") == 0 ||
                    strcmp(argv[i], "--format") == 0) && i + 1 < argc) {
            formats_csv = argv[++i];
        } else if ((strcmp(argv[i], "--dev-format") == 0 ||
                    strcmp(argv[i], "--only-format") == 0) && i + 1 < argc) {
            dev_format = argv[++i];
        } else if (strcmp(argv[i], "--deleted-filter") == 0 && i + 1 < argc) {
            const char *value = argv[++i];

            if (strcmp(value, "1") == 0 ||
                strcasecmp(value, "deleted") == 0 ||
                strcasecmp(value, "true") == 0) {
                config.has_deleted_filter = 1;
                config.deleted_value = 1;
            } else if (strcmp(value, "0") == 0 ||
                       strcasecmp(value, "live") == 0 ||
                       strcasecmp(value, "false") == 0) {
                config.has_deleted_filter = 1;
                config.deleted_value = 0;
            } else if (strcmp(value, "2") == 0 ||
                       strcasecmp(value, "both") == 0 ||
                       strcasecmp(value, "all") == 0) {
                config.has_deleted_filter = 1;
                config.deleted_value = 2;
            } else {
                fprintf(stderr, "invalid --deleted-filter value: %s\n", value);
                return 1;
            }
        } else if (strcmp(argv[i], "--date-filter") == 0 && i + 1 < argc) {
            const char *value = argv[++i];

            if (!parse_date_filter_range_local(
                    value,
                    &config.date_start_yyyymmdd,
                    &config.date_end_yyyymmdd)) {
                fprintf(
                    stderr,
                    "invalid --date-filter value: %s (expected YYYYMMDD or YYYYMMDD-YYYYMMDD)\n",
                    value
                );
                return 1;
            }
            config.has_date_filter = 1;
        } else if ((strcmp(argv[i], "--fold") == 0 ||
                    strcmp(argv[i], "--root-folder") == 0 ||
                    strcmp(argv[i], "--roots") == 0) && i + 1 < argc) {
            if (!config_root_scope_add_csv(
                    &config,
                    argv[++i],
                    root_scope_error,
                    sizeof(root_scope_error))) {
                fprintf(
                    stderr,
                    "invalid --fold value: %s\n",
                    root_scope_error[0] != '\0' ? root_scope_error : "unknown reason"
                );
                return 1;
            }
        } else {
            usage(argv[0]);
            return 1;
        }
    }

    if (config.image_path == NULL) {
        usage(argv[0]);
        return 1;
    }
    if (!mftprobe_resolve_input_source_path(
            config.image_path,
            resolved_image_path,
            sizeof(resolved_image_path),
            &config.image_path)) {
        return 1;
    }

    format_selection.categories_csv = categories_csv;
    format_selection.formats_csv = formats_csv;
    format_selection.dev_format = dev_format;
    if (!mftprobe_format_configure_active_order(
            &config,
            &format_selection,
            format_selection_error,
            sizeof(format_selection_error))) {
        fprintf(
            stderr,
            "format selection failed: %s\n",
            format_selection_error[0] != '\0' ? format_selection_error : "unknown reason"
        );
        return 1;
    }
    mftprobe_format_describe_active_order(&config, active_format_text, sizeof(active_format_text));
    log_verbose("Active formats: %s", active_format_text);

    if (!mftprobe_preflight_open(config.image_path)) {
        return 1;
    }

    snprintf(base_out_dir, sizeof(base_out_dir), "%s", config.out_dir);
    if (!ensure_dir(base_out_dir)) {
        fprintf(stderr, "failed to create output dir: %s\n", base_out_dir);
        return 1;
    }
    config.source_size = mftprobe_detect_source_size(config.image_path);
    if (config.source_size == 0) {
        fprintf(stderr,
                "input size is zero or unavailable for %s; device may be offline, unreadable, or not ready\n",
                config.image_path);
        return 1;
    }
    if (start_offset_explicit && requested_start_offset > config.source_size) {
        fprintf(
            stderr,
            "manual start offset %llu exceeds source size %llu\n",
            (unsigned long long)requested_start_offset,
            (unsigned long long)config.source_size
        );
        return 1;
    }
    if (detect_ntfs_geometries(
            config.image_path,
            config.source_size,
            config.ntfs_volumes,
            &config.ntfs_volume_count)) {
        config.ntfs = config.ntfs_volumes[
            choose_preferred_ntfs_volume(config.ntfs_volumes, config.ntfs_volume_count)
        ];
    }
    if (config.source_id[0] == '\0') {
        const char *stats_label = getenv("CARV_MFT_STATS_LABEL");

        if (stats_label != NULL && stats_label[0] != '\0') {
            configure_source_id(stats_label, config.source_id, sizeof(config.source_id));
        }
    } else {
        const char *stats_label = getenv("CARV_MFT_STATS_LABEL");

        if (stats_label != NULL && stats_label[0] != '\0') {
            char sanitized_label[128];

            configure_source_id(stats_label, sanitized_label, sizeof(sanitized_label));
            if (sanitized_label[0] != '\0' &&
                strcmp(sanitized_label, config.source_id) != 0) {
                log_info(
                    "Folder name controls output dir; CARV_MFT_STATS_LABEL=%s differs and is ignored for saved output",
                    sanitized_label
                );
            }
        }
    }
    if (config.source_id[0] == '\0') {
        if (config.resume_requested || config.only_recover_missed) {
            fprintf(stderr,
                    "Service ID / folder name is required for resume/recover; use --out PATH/NAME\n");
            return 1;
        }
        if (!configure_unique_timestamped_source_id(
                base_out_dir,
                config.source_id,
                sizeof(config.source_id))) {
            fprintf(stderr, "failed to create a unique timestamped folder name\n");
            return 1;
        }
    }
    config.observation_run_id =
        (((uint64_t)time(NULL)) << 32) ^
        ((uint64_t)(unsigned int)getpid() << 16) ^
        config.ntfs.volume_serial;
    join_path(source_out_dir, sizeof(source_out_dir), base_out_dir, config.source_id);

    if (!ensure_dir(source_out_dir)) {
        fprintf(stderr, "failed to create output dir: %s\n", source_out_dir);
        return 1;
    }
    config.out_dir = source_out_dir;
    join_path(
        config.state_path,
        sizeof(config.state_path),
        config.out_dir,
        APP_STATE_DIR_NAME "/scan_state.txt");
    has_existing_mft_map = mft_binary_map_exists(&config);
    existing_mft_map_size = mft_binary_map_size(&config);

    if (config.root_scope_count > 0U && existing_mft_map_size > 0U) {
        if (load_root_scope_resolution_state(&config)) {
            root_scope_preview_done = 1;
        } else {
            /*
             * Older runs have no resolution state. Resolve once from the
             * primary MFT before the saved map is filtered, then persist it.
             */
            if (!users_root_scope_primary_preview(&config, NULL)) {
                return 1;
            }
            root_scope_preview_done = 1;
        }
    }

    log_info("Run name: %s%s", config.source_id, run_name_provided ? "" : " (auto)");
    log_info("Run dir: %s", config.out_dir);
    if (config.ntfs.valid) {
        log_info(
            "NTFS geometry: preferred_volume_offset=%llu cluster_size=%llu serial=%016llx volumes=%zu",
            (unsigned long long)config.ntfs.volume_offset,
            (unsigned long long)config.ntfs.cluster_size,
            (unsigned long long)config.ntfs.volume_serial,
            config.ntfs_volume_count
        );
    } else {
#ifdef __APPLE__
        char hinted_slice[64];
        char hinted_personality[128];
        char hinted_partition_type[128];
        int hinted_non_ntfs = 0;

        if (detect_macos_source_filesystem_hint(
                config.image_path,
                hinted_slice,
                sizeof(hinted_slice),
                hinted_personality,
                sizeof(hinted_personality),
                hinted_partition_type,
                sizeof(hinted_partition_type))) {
            log_info(
                "NTFS geometry: unavailable; source hint: %s personality=%s partition_type=%s",
                hinted_slice[0] != '\0' ? hinted_slice : config.image_path,
                hinted_personality[0] != '\0' ? hinted_personality : "unknown",
                hinted_partition_type[0] != '\0' ? hinted_partition_type : "unknown"
            );
            hinted_non_ntfs = macos_hint_is_definitely_non_ntfs(hinted_personality);
            if (hinted_non_ntfs) {
                log_error(
                    "Source appears to be %s, not NTFS. folders mode requires NTFS; use --mode all for ExFAT/FAT/APFS/HFS+ or general raw recovery",
                    hinted_personality
                );
                g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
                return 1;
            }
        } else {
            log_info("NTFS geometry: unavailable; MFT file data offsets will remain unknown");
        }
#else
        log_info("NTFS geometry: unavailable; MFT file data offsets will remain unknown");
#endif
    }
    if (config.root_scope_count > 0U) {
        log_info(
            "Folder path scoped snapshot mode: MFT map will keep named entries only under the selected folders"
        );
        {
            char selected_root_scopes[512];

            selected_root_scopes[0] = '\0';
            config_root_scope_format_csv(&config, selected_root_scopes, sizeof(selected_root_scopes));
            log_info(
                "Folder path selected folders: %s",
                selected_root_scopes[0] != '\0' ? selected_root_scopes : "Users"
            );
        }
    }
    if (!config.resume_requested &&
        !start_offset_explicit &&
        !config.only_recover_missed &&
        load_scan_state(
            &config,
            &existing_offset,
            &existing_completed,
            existing_scan_mode,
            sizeof(existing_scan_mode)
        ) &&
        scan_state_mode_is_users(existing_scan_mode) &&
        existing_mft_map_size > 0) {
        additive_users_pass = 1;
        if (!existing_completed && existing_offset > 0) {
            log_info(
                "Existing incomplete folders scan state found; starting a new additive folders pass in the same run directory (use --resume to continue from byte %llu instead)",
                (unsigned long long)existing_offset
            );
        } else {
            log_info("Existing folders run state found; starting additive folders pass in the same run directory");
            additive_cache_only_pass = 1;
        }
    } else if (!config.resume_requested &&
               !start_offset_explicit &&
               !config.only_recover_missed &&
               (!scan_state_mode_is_users(existing_scan_mode) || existing_scan_mode[0] == '\0') &&
               existing_mft_map_size > 0) {
        log_info(
            "Existing scan state belongs to mode %s; rebuilding folders-specific metadata in this run",
            existing_scan_mode[0] != '\0' ? existing_scan_mode : "unknown"
        );
    }

    if (config.root_scope_count > 0U &&
        !root_scope_preview_done &&
        !config.resume_requested &&
        !config.only_recover_missed &&
        !start_offset_explicit &&
        !additive_users_pass) {
        if (!users_root_scope_primary_preview(&config, NULL)) {
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }
    }

    remove_legacy_text_outputs(config.out_dir);
    observation_write_run_start(&config);
    observation_write_geometry(&config);

    pthread_mutex_init(&table.mutex, NULL);
    if (!queue_init(&queue, ENTRY_QUEUE_CAPACITY)) {
        pthread_mutex_destroy(&table.mutex);
        fprintf(stderr, "failed to allocate entry queue\n");
        return 1;
    }

    if (!recovery_plan_init(&recovery_plan)) {
        queue_destroy(&queue);
        pthread_mutex_destroy(&table.mutex);
        fprintf(stderr, "failed to initialize recovery plan\n");
        return 1;
    }

    if (additive_users_pass) {
        log_info("Additive folders mode: existing recovered files will be kept and this pass may add more results into the same run");
    }

    pthread_mutex_init(&users_worker.mutex, NULL);
    pthread_cond_init(&users_worker.cond, NULL);
    users_worker.table = &table;
    users_worker.config = &config;
    users_worker.recovery_plan = &recovery_plan;

    prefix_worker.read_queue = &read_queue;
    prefix_worker.mft_queue = &queue;
    prefix_worker.magic_queue = NULL;
    prefix_worker.recovery_plan = &recovery_plan;
    prefix_worker.recovery_write_queue = &recovery_write_queue;
    prefix_worker.ok = 1;

    sieve_worker.config = &config;
    sieve_worker.queue = &queue;
    sieve_worker.bin_queue = &bin_event_queue;
    sieve_worker.live_queue = &live_event_queue;
    sieve_worker.ok = 1;

    bin_writer_worker.config = &config;
    bin_writer_worker.queue = &bin_event_queue;
    bin_writer_worker.ok = 1;

    live_index_worker.config = &config;
    live_index_worker.table = &table;
    live_index_worker.queue = &live_event_queue;
    live_index_worker.users_worker = &users_worker;
    live_index_worker.recovery_plan = &recovery_plan;
    live_index_worker.ok = 1;

    recovery_writer_worker.queue = &recovery_write_queue;
    recovery_writer_worker.recovery_plan = &recovery_plan;
    recovery_writer_worker.ok = 1;

    if (config.only_recover_missed) {
        int used_primary_mft_fallback = 0;

        if (existing_mft_map_size == 0) {
            fprintf(stderr,
                    "no non-empty MFT map exists in %s; cannot recover missed files from this run\n",
                    config.out_dir);
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }
        log_info("Only recover missed: loading existing MFT map and skipping normal scan");
        if (!load_existing_binary_map(&config, &table, &sieve_worker, 0)) {
            fprintf(stderr, "failed to load previous binary MFT map for direct recovery\n");
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }

        if (!recovery_plan_refresh_users_with_primary_mft_fallback(
                &recovery_plan,
                &config,
                &table,
                &used_primary_mft_fallback,
                0)) {
            fprintf(stderr, "failed to build recovery targets from MFT map\n");
            free(table.items);
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }
        if (used_primary_mft_fallback &&
            !write_binary_map_snapshot(&config, &table)) {
            log_verbose("Only-recover-missed could not persist supplemented MFT snapshot state");
        }

        write_users_selected_tree(&config, &table);
        ok = recovery_plan_direct_recover(&recovery_plan, &config, 1);
        if (ok && !stop_requested() &&
            !recovery_plan_replay_missed_jpeg_targets(&recovery_plan, &config)) {
            ok = 0;
        }
        if (ok && !stop_requested() &&
            !recovery_plan_replay_missed_png_targets(&recovery_plan, &config)) {
            ok = 0;
        }
        if (ok && !stop_requested() &&
            !recovery_plan_replay_missed_mov_targets(&recovery_plan, &config)) {
            ok = 0;
        }
        if (!write_missed_targets_report(&config, &recovery_plan)) {
            log_verbose("Only-recover-missed could not persist missed-target report");
        }
        prune_empty_deleted_dirs(config.out_dir);
        recovery_plan_log_summary(&recovery_plan);

        free(table.items);
        recovery_plan_destroy(&recovery_plan);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&table.mutex);
        return ok ? 0 : 1;
    }

    if (additive_cache_only_pass && !start_offset_explicit) {
        int used_primary_mft_fallback = 0;

        log_info("Folders cache reuse: loading saved MFT map and fulfilling this request without a new disk scan");
        if (!load_existing_binary_map(&config, &table, &sieve_worker, 0)) {
            fprintf(stderr, "failed to load previous binary MFT map for additive folders pass\n");
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }

        if (!recovery_plan_refresh_users_with_primary_mft_fallback(
                &recovery_plan,
                &config,
                &table,
                &used_primary_mft_fallback,
                0)) {
            fprintf(stderr, "failed to build recovery targets from cached MFT map\n");
            free(table.items);
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }
        if (used_primary_mft_fallback) {
            if (!write_binary_map_snapshot(&config, &table)) {
                log_verbose("Additive folders pass could not persist supplemented MFT snapshot state");
            }
        } else {
            log_info(
                "Folders cache reuse: skipping MFT snapshot rewrite because no new disk scan data was gathered"
            );
        }

        write_users_selected_tree(&config, &table);
        ok = recovery_plan_direct_recover(&recovery_plan, &config, 0);
        if (ok && !stop_requested() &&
            !recovery_plan_replay_missed_jpeg_targets(&recovery_plan, &config)) {
            ok = 0;
        }
        if (ok && !stop_requested() &&
            !recovery_plan_replay_missed_png_targets(&recovery_plan, &config)) {
            ok = 0;
        }
        if (ok && !stop_requested() &&
            !recovery_plan_replay_missed_mov_targets(&recovery_plan, &config)) {
            ok = 0;
        }
        if (!write_missed_targets_report(&config, &recovery_plan)) {
            log_verbose("Additive folders pass could not persist missed-target report");
        }
        prune_empty_deleted_dirs(config.out_dir);
        recovery_plan_log_summary(&recovery_plan);
        (void)write_scan_state(&config, config.source_size, 1);

        free(table.items);
        recovery_plan_destroy(&recovery_plan);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&table.mutex);
        return ok ? 0 : 1;
    }

    if (config.resume_requested &&
        load_scan_state(
            &config,
            &resume_offset,
            &resume_completed,
            resume_scan_mode,
            sizeof(resume_scan_mode)
        ) &&
        scan_state_mode_is_users(resume_scan_mode) &&
        (!resume_completed || start_offset_explicit) &&
        ((resume_offset > 0 || existing_mft_map_size > 0) || start_offset_explicit)) {
        config.start_offset = start_offset_explicit ? requested_start_offset : resume_offset;
        {
            uint64_t manual_skip = parse_byte_count(getenv("CARV_RESUME_SKIP_BYTES"));

            if (manual_skip > 0) {
                uint64_t new_start = config.start_offset + manual_skip;

                if (new_start > config.source_size) {
                    new_start = config.source_size;
                    manual_skip = new_start > config.start_offset
                        ? new_start - config.start_offset
                        : 0;
                }
                if (manual_skip > 0) {
                    append_read_error_gap(
                        &config,
                        config.start_offset,
                        manual_skip,
                        0,
                        "manual_resume_skip_absolute_offsets_preserved"
                    );
                    config.start_offset = new_start;
                    log_info(
                        "Manual resume skip: %llu bytes; resuming from byte %llu",
                        (unsigned long long)manual_skip,
                        (unsigned long long)config.start_offset
                    );
                }
            }
        }
        {
            uint64_t gap_adjusted_offset =
                advance_past_logged_read_gap(&config, config.start_offset);

            if (gap_adjusted_offset != config.start_offset) {
                config.start_offset = gap_adjusted_offset;
                log_info(
                    "Resume advanced past logged read-error gap to byte %llu",
                    (unsigned long long)config.start_offset
                );
            }
        }
        pthread_mutex_lock(&table.mutex);
        if (!load_existing_binary_map(&config, &table, &sieve_worker, 1)) {
            pthread_mutex_unlock(&table.mutex);
            fprintf(stderr, "failed to load previous binary MFT map for resume\n");
            offset_set_destroy(&sieve_worker.resume_offsets);
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }
        pthread_mutex_unlock(&table.mutex);
        config.resume_active = 1;
        recovery_plan_refresh_from_table(&recovery_plan, &config, &table);
        log_set_working_speed_base(config.start_offset);
        log_set_working_progress(config.start_offset, 0);
        log_info(
            "%s scan from byte %llu",
            start_offset_explicit ? "Starting folders scan with manual offset" : "Resuming",
            (unsigned long long)config.start_offset
        );
    } else if (config.resume_requested &&
               start_offset_explicit &&
               existing_mft_map_size > 0) {
        config.start_offset = requested_start_offset;
        pthread_mutex_lock(&table.mutex);
        if (!load_existing_binary_map(&config, &table, &sieve_worker, 1)) {
            pthread_mutex_unlock(&table.mutex);
            fprintf(stderr, "failed to load previous binary MFT map for manual-offset start\n");
            offset_set_destroy(&sieve_worker.resume_offsets);
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }
        pthread_mutex_unlock(&table.mutex);
        config.resume_active = 1;
        recovery_plan_refresh_from_table(&recovery_plan, &config, &table);
        log_set_working_speed_base(config.start_offset);
        log_set_working_progress(config.start_offset, 0);
        log_info(
            "Starting folders scan from manual offset byte %llu using saved state artifacts",
            (unsigned long long)config.start_offset
        );
    } else if (config.resume_requested &&
               start_offset_explicit) {
        config.start_offset = requested_start_offset;
        config.resume_active = 1;
        log_set_working_speed_base(config.start_offset);
        log_set_working_progress(config.start_offset, 0);
        log_info(
            "Starting folders scan from manual offset byte %llu",
            (unsigned long long)config.start_offset
        );
    } else if (config.resume_requested) {
        if (existing_mft_map_size > 0) {
            fprintf(stderr,
                    "existing MFT map found in %s but no usable incomplete resume state was found; refusing to start over in the same run directory\n",
                    config.out_dir);
            offset_set_destroy(&sieve_worker.resume_offsets);
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }
        if (has_existing_mft_map) {
            log_info("Ignoring empty MFT map from previous failed start in %s", config.out_dir);
        }
        log_info("No usable resume state found; starting a new scan in empty run directory");
    }

    if (!config.resume_active &&
        config.has_deleted_filter &&
        config.deleted_value == 1) {
        int handled_deleted_fast_path = 0;

        if (!try_users_deleted_primary_mft_fast_path(
                &config,
                &table,
                &recovery_plan,
                &handled_deleted_fast_path)) {
            offset_set_destroy(&sieve_worker.resume_offsets);
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }
        if (handled_deleted_fast_path) {
            offset_set_destroy(&sieve_worker.resume_offsets);
            table_reset(&table);
            recovery_plan_destroy(&recovery_plan);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 0;
        }

        table_reset(&table);
        recovery_plan_destroy(&recovery_plan);
        if (!recovery_plan_init(&recovery_plan)) {
            offset_set_destroy(&sieve_worker.resume_offsets);
            queue_destroy(&queue);
            pthread_cond_destroy(&users_worker.cond);
            pthread_mutex_destroy(&users_worker.mutex);
            pthread_mutex_destroy(&table.mutex);
            return 1;
        }
    }

    if (!config.resume_active) {
        write_scan_state(&config, 0, 0);
    }

    if (!event_queue_init(&bin_event_queue, MFT_EVENT_QUEUE_CAPACITY) ||
        !event_queue_init(&live_event_queue, MFT_EVENT_QUEUE_CAPACITY)) {
        fprintf(stderr, "failed to allocate MFT event queues\n");
        offset_set_destroy(&sieve_worker.resume_offsets);
        if (bin_event_queue.items != NULL) {
            event_queue_destroy(&bin_event_queue);
        }
        if (live_event_queue.items != NULL) {
            event_queue_destroy(&live_event_queue);
        }
        recovery_plan_destroy(&recovery_plan);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&thread_activity_writer.mutex);
        pthread_mutex_destroy(&table.mutex);
        return 1;
    }
    event_queues_initialized = 1;

    if (!read_block_queue_init(&read_queue, READ_BLOCK_QUEUE_CAPACITY)) {
        fprintf(stderr, "failed to allocate read block queue\n");
        offset_set_destroy(&sieve_worker.resume_offsets);
        event_queue_destroy(&live_event_queue);
        event_queue_destroy(&bin_event_queue);
        recovery_plan_destroy(&recovery_plan);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&thread_activity_writer.mutex);
        pthread_mutex_destroy(&table.mutex);
        return 1;
    }
    read_queue_initialized = 1;

    if (!recovery_write_queue_init(&recovery_write_queue, RECOVERY_WRITE_QUEUE_CAPACITY)) {
        fprintf(stderr, "failed to allocate recovery write queue\n");
        offset_set_destroy(&sieve_worker.resume_offsets);
        read_block_queue_destroy(&read_queue);
        event_queue_destroy(&live_event_queue);
        event_queue_destroy(&bin_event_queue);
        recovery_plan_destroy(&recovery_plan);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&thread_activity_writer.mutex);
        pthread_mutex_destroy(&table.mutex);
        return 1;
    }
    recovery_write_queue_initialized = 1;

    thread_activity_context.config = &config;
    thread_activity_context.read_queue = &read_queue;
    thread_activity_context.mft_queue = &queue;
    thread_activity_context.bin_queue = &bin_event_queue;
    thread_activity_context.live_queue = &live_event_queue;
    thread_activity_context.write_queue = &recovery_write_queue;
    thread_activity_context.table = &table;
    thread_activity_context.recovery_plan = &recovery_plan;
    thread_activity_context.users_worker = &users_worker;
    thread_activity_context.prefix_worker = &prefix_worker;
    thread_activity_context.sieve_worker = &sieve_worker;
    thread_activity_context.bin_writer_worker = &bin_writer_worker;
    thread_activity_context.live_index_worker = &live_index_worker;
    thread_activity_context.recovery_writer_worker = &recovery_writer_worker;

    thread_activity_writer.context = &thread_activity_context;
    thread_activity_writer.ok = 1;
    pthread_mutex_init(&thread_activity_writer.mutex, NULL);

    if (pthread_create(&users_thread, NULL, users_worker_main, &users_worker) == 0) {
        users_thread_started = 1;
    } else {
        fprintf(stderr, "warning: Users/JPEG mapper thread unavailable; writing at end only\n");
    }

    if (pthread_create(&bin_writer_thread, NULL, bin_writer_worker_main, &bin_writer_worker) == 0) {
        bin_writer_thread_started = 1;
    } else {
        fprintf(stderr, "failed to start MFT binary writer thread\n");
        read_block_queue_finish(&read_queue);
        queue_finish(&queue);
        event_queue_finish(&bin_event_queue);
        event_queue_finish(&live_event_queue);
        if (users_thread_started) {
            stop_users_worker(&users_worker);
            pthread_join(users_thread, NULL);
        }
        offset_set_destroy(&sieve_worker.resume_offsets);
        recovery_plan_destroy(&recovery_plan);
        read_block_queue_destroy(&read_queue);
        recovery_write_queue_destroy(&recovery_write_queue);
        event_queue_destroy(&live_event_queue);
        event_queue_destroy(&bin_event_queue);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&thread_activity_writer.mutex);
        pthread_mutex_destroy(&table.mutex);
        return 1;
    }

    if (pthread_create(&live_index_thread, NULL, live_index_worker_main, &live_index_worker) == 0) {
        live_index_thread_started = 1;
    } else {
        fprintf(stderr, "failed to start live MFT index thread\n");
        read_block_queue_finish(&read_queue);
        queue_finish(&queue);
        event_queue_finish(&bin_event_queue);
        event_queue_finish(&live_event_queue);
        if (bin_writer_thread_started) {
            pthread_join(bin_writer_thread, NULL);
        }
        if (users_thread_started) {
            stop_users_worker(&users_worker);
            pthread_join(users_thread, NULL);
        }
        offset_set_destroy(&sieve_worker.resume_offsets);
        recovery_plan_destroy(&recovery_plan);
        read_block_queue_destroy(&read_queue);
        recovery_write_queue_destroy(&recovery_write_queue);
        event_queue_destroy(&live_event_queue);
        event_queue_destroy(&bin_event_queue);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&table.mutex);
        return 1;
    }

    if (pthread_create(&sieve_thread, NULL, sieve_worker_main, &sieve_worker) == 0) {
        sieve_thread_started = 1;
    } else {
        fprintf(stderr, "failed to start sieve thread\n");
        read_block_queue_finish(&read_queue);
        queue_finish(&queue);
        event_queue_finish(&bin_event_queue);
        event_queue_finish(&live_event_queue);
        if (live_index_thread_started) {
            pthread_join(live_index_thread, NULL);
        }
        if (bin_writer_thread_started) {
            pthread_join(bin_writer_thread, NULL);
        }
        if (users_thread_started) {
            stop_users_worker(&users_worker);
            pthread_join(users_thread, NULL);
        }
        offset_set_destroy(&sieve_worker.resume_offsets);
        recovery_plan_destroy(&recovery_plan);
        read_block_queue_destroy(&read_queue);
        recovery_write_queue_destroy(&recovery_write_queue);
        event_queue_destroy(&live_event_queue);
        event_queue_destroy(&bin_event_queue);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&table.mutex);
        return 1;
    }

    if (pthread_create(&recovery_writer_thread, NULL, recovery_writer_worker_main, &recovery_writer_worker) == 0) {
        recovery_writer_thread_started = 1;
    } else {
        fprintf(stderr, "failed to start recovery writer thread\n");
        read_block_queue_finish(&read_queue);
        recovery_write_queue_finish(&recovery_write_queue);
        queue_finish(&queue);
        event_queue_finish(&bin_event_queue);
        event_queue_finish(&live_event_queue);
        if (sieve_thread_started) {
            pthread_join(sieve_thread, NULL);
        }
        if (live_index_thread_started) {
            pthread_join(live_index_thread, NULL);
        }
        if (bin_writer_thread_started) {
            pthread_join(bin_writer_thread, NULL);
        }
        if (users_thread_started) {
            stop_users_worker(&users_worker);
            pthread_join(users_thread, NULL);
        }
        offset_set_destroy(&sieve_worker.resume_offsets);
        recovery_write_queue_destroy(&recovery_write_queue);
        recovery_plan_destroy(&recovery_plan);
        read_block_queue_destroy(&read_queue);
        event_queue_destroy(&live_event_queue);
        event_queue_destroy(&bin_event_queue);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&table.mutex);
        return 1;
    }

    if (pthread_create(&prefix_thread, NULL, prefix_worker_main, &prefix_worker) == 0) {
        prefix_thread_started = 1;
    } else {
        fprintf(stderr, "failed to start prefix thread\n");
        read_block_queue_finish(&read_queue);
        recovery_write_queue_finish(&recovery_write_queue);
        queue_finish(&queue);
        event_queue_finish(&bin_event_queue);
        event_queue_finish(&live_event_queue);
        if (recovery_writer_thread_started) {
            pthread_join(recovery_writer_thread, NULL);
        }
        if (sieve_thread_started) {
            pthread_join(sieve_thread, NULL);
        }
        if (live_index_thread_started) {
            pthread_join(live_index_thread, NULL);
        }
        if (bin_writer_thread_started) {
            pthread_join(bin_writer_thread, NULL);
        }
        if (users_thread_started) {
            stop_users_worker(&users_worker);
            pthread_join(users_thread, NULL);
        }
        offset_set_destroy(&sieve_worker.resume_offsets);
        recovery_plan_destroy(&recovery_plan);
        read_block_queue_destroy(&read_queue);
        recovery_write_queue_destroy(&recovery_write_queue);
        event_queue_destroy(&live_event_queue);
        event_queue_destroy(&bin_event_queue);
        queue_destroy(&queue);
        pthread_cond_destroy(&users_worker.cond);
        pthread_mutex_destroy(&users_worker.mutex);
        pthread_mutex_destroy(&thread_activity_writer.mutex);
        pthread_mutex_destroy(&table.mutex);
        return 1;
    }

    if (pthread_create(
            &thread_activity_thread,
            NULL,
            thread_activity_writer_worker_main,
            &thread_activity_writer) == 0) {
        thread_activity_thread_started = 1;
    } else {
        log_verbose("thread activity writer unavailable; GUI activity meters will use fallback mode");
    }

    ok = scan_image(
        &config,
        &read_queue,
        &queue,
        &bin_event_queue,
        &live_event_queue,
        &recovery_write_queue,
        &table,
        &recovery_plan);

    if (prefix_thread_started) {
        pthread_join(prefix_thread, NULL);
        if (!prefix_worker.ok) {
            ok = 0;
        }
    } else {
        queue_finish(&queue);
    }

    recovery_write_queue_finish(&recovery_write_queue);
    if (recovery_writer_thread_started) {
        pthread_join(recovery_writer_thread, NULL);
        if (!recovery_writer_worker.ok) {
            ok = 0;
        }
    }

    if (sieve_thread_started) {
        pthread_join(sieve_thread, NULL);
        if (!sieve_worker.ok) {
            ok = 0;
        }
    }

    if (bin_writer_thread_started) {
        pthread_join(bin_writer_thread, NULL);
        if (!bin_writer_worker.ok) {
            ok = 0;
        }
    }

    if (live_index_thread_started) {
        pthread_join(live_index_thread, NULL);
        if (!live_index_worker.ok) {
            ok = 0;
        }
    }

    stop_users_worker(&users_worker);

    if (users_thread_started) {
        pthread_join(users_thread, NULL);
    }

    {
        int skip_postscan_refresh = 0;
        char live_refresh_summary[256];

        if (live_index_thread_started &&
            users_live_index_can_skip_postscan_refresh(
                &config,
                &live_index_worker,
                &recovery_plan,
                live_refresh_summary,
                sizeof(live_refresh_summary))) {
            skip_postscan_refresh = 1;
            log_info(
                "Users live target coverage: %s; skipping full post-scan target rebuild",
                live_refresh_summary
            );
        }

        if (!recovery_plan_refresh_users_with_primary_mft_fallback(
                &recovery_plan,
                &config,
                &table,
                NULL,
                skip_postscan_refresh)) {
            ok = 0;
        }
    }
    write_users_selected_tree(&config, &table);
    recovery_plan_finish_stream(&recovery_plan);
    if (config.auto_recover_missed && ok && !stop_requested()) {
        if (!recovery_plan_direct_recover(&recovery_plan, &config, 1)) {
            ok = 0;
        }
        if (ok && !stop_requested() &&
            !recovery_plan_replay_missed_jpeg_targets(&recovery_plan, &config)) {
            ok = 0;
        }
        if (ok && !stop_requested() &&
            !recovery_plan_replay_missed_png_targets(&recovery_plan, &config)) {
            ok = 0;
        }
        if (ok && !stop_requested() &&
            !recovery_plan_replay_missed_mov_targets(&recovery_plan, &config)) {
            ok = 0;
        }
        if (!write_missed_targets_report(&config, &recovery_plan)) {
            log_verbose("Users retry could not persist missed-target report");
        }
        prune_empty_deleted_dirs(config.out_dir);
    } else if (config.auto_recover_missed && !ok) {
        log_info("Retry skipped because the initial scan did not complete cleanly");
    }

    if (ok &&
        !stop_requested() &&
        !config.ntfs.valid &&
        sieve_worker.raw_records == 0 &&
        sieve_worker.accepted_records == 0 &&
        table.count == 0 &&
        recovery_plan.count == 0) {
        log_error(
            "No NTFS MFT records were detected in the source. folders mode requires an NTFS source; for APFS/HFS+/exFAT/FAT or general raw recovery, use --mode all"
        );
        ok = 0;
    }

    recovery_plan_log_summary(&recovery_plan);
    observation_write_final(
        &config,
        &sieve_worker,
        &recovery_plan,
        &table,
        ok && !stop_requested()
    );

    log_info(
        "mftprobe: raw=%llu accepted=%llu hard_rejected=%llu duplicate_offsets=%llu duplicate_records_kept=%llu",
        (unsigned long long)sieve_worker.raw_records,
        (unsigned long long)sieve_worker.accepted_records,
        (unsigned long long)sieve_worker.hard_rejected_records,
        (unsigned long long)sieve_worker.duplicate_offsets,
        (unsigned long long)sieve_worker.soft_duplicate_record_ids_kept
    );

    pthread_mutex_lock(&thread_activity_writer.mutex);
    thread_activity_writer.done = 1;
    pthread_mutex_unlock(&thread_activity_writer.mutex);
    if (thread_activity_thread_started) {
        pthread_join(thread_activity_thread, NULL);
    }

    free(table.items);
    recovery_plan_destroy(&recovery_plan);
    if (read_queue_initialized) {
        read_block_queue_destroy(&read_queue);
    }
    if (recovery_write_queue_initialized) {
        recovery_write_queue_destroy(&recovery_write_queue);
    }
    if (event_queues_initialized) {
        event_queue_destroy(&live_event_queue);
        event_queue_destroy(&bin_event_queue);
    }
    queue_destroy(&queue);
    pthread_cond_destroy(&users_worker.cond);
    pthread_mutex_destroy(&users_worker.mutex);
    pthread_mutex_destroy(&thread_activity_writer.mutex);
    pthread_mutex_destroy(&table.mutex);
    return ok ? 0 : 1;
}

static uint64_t mftprobe_detect_source_size(const char *path)
{
    struct stat st;

    if (path == NULL || stat(path, &st) != 0) {
        return 0;
    }

    if (S_ISREG(st.st_mode) && st.st_size > 0) {
        return (uint64_t)st.st_size;
    }

#ifdef __APPLE__
    if (S_ISBLK(st.st_mode) || S_ISCHR(st.st_mode)) {
        int fd = open(path, O_RDONLY);
        uint64_t block_count = 0;
        uint32_t block_size = 0;

        if (fd < 0) {
            return 0;
        }

        if (ioctl(fd, DKIOCGETBLOCKCOUNT, &block_count) != 0 ||
            ioctl(fd, DKIOCGETBLOCKSIZE, &block_size) != 0) {
            close(fd);
            return 0;
        }

        close(fd);
        return block_count * (uint64_t)block_size;
    }
#endif

#ifdef __linux__
    if (S_ISBLK(st.st_mode)) {
        int fd = open(path, O_RDONLY);
        uint64_t bytes = 0;

        if (fd < 0) {
            return 0;
        }

        if (ioctl(fd, BLKGETSIZE64, &bytes) != 0) {
            close(fd);
            return 0;
        }

        close(fd);
        return bytes;
    }
#endif

    return 0;
}

typedef struct TargetedRecoveryFilter {
    int has_date;
    int date_yyyymmdd;
    int date_end_yyyymmdd;
    int has_deleted;
    int deleted_value;
    int has_format;
    char format_ext[FORMAT_EXTENSION_MAX];
    size_t root_scope_count;
    char root_scopes[64][NAME_MAX_LEN];
} TargetedRecoveryFilter;

typedef struct TargetedRecoveryStats {
    size_t skipped_invalid_target;
    size_t skipped_image_filter;
    size_t failed_read_error;
    size_t failed_start_mismatch;
    size_t failed_truncated_or_end_mismatch;
    size_t failed_output_error;
    size_t failed_invalid_target;
    size_t failed_interrupted;
    size_t failed_unknown;
} TargetedRecoveryStats;

typedef struct CompareCandidate {
    char rel_path[PATH_MAX_LEN];
    char compare_key[PATH_MAX_LEN];
    char created[32];
    uint64_t size;
    int deleted;
    int record;
} CompareCandidate;

typedef struct CompareCandidateList {
    CompareCandidate *items;
    size_t count;
    size_t capacity;
} CompareCandidateList;

typedef struct CompareScope {
    char items[COMPARE_SCOPE_MAX_ITEMS][COMPARE_SCOPE_ITEM_MAX];
    size_t count;
    int match_all;
} CompareScope;

typedef struct RecordList {
    int *records;
    size_t count;
    size_t capacity;
} RecordList;

typedef struct RecoverPathItem {
    char rel_path[PATH_MAX_LEN];
    char match_key[PATH_MAX_LEN];
    uint64_t size;
    int has_size;
} RecoverPathItem;

typedef struct RecoverPathList {
    RecoverPathItem *items;
    size_t count;
    size_t capacity;
} RecoverPathList;

static void targeted_trim_ascii(char *text)
{
    char *start;
    char *end;
    size_t length;

    if (text == NULL || text[0] == '\0') {
        return;
    }

    start = text;
    while (*start != '\0' && isspace((unsigned char)*start)) {
        start++;
    }

    end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) {
        end--;
    }

    length = (size_t)(end - start);
    if (start != text) {
        memmove(text, start, length);
    }
    text[length] = '\0';
}

static void compare_scope_normalize_token(char *text)
{
    size_t i;

    if (text == NULL) {
        return;
    }

    targeted_trim_ascii(text);
    while (text[0] == '/' || text[0] == '\\') {
        memmove(text, text + 1, strlen(text));
    }
    for (i = 0; text[i] != '\0'; i++) {
        if (text[i] == '\\') {
            text[i] = '/';
        } else {
            text[i] = (char)ascii_tolower((unsigned char)text[i]);
        }
    }
    while (i > 0 && text[i - 1U] == '/') {
        text[--i] = '\0';
    }
}

static void compare_scope_add_common_entries(CompareScope *scope)
{
    static const char *const common_items[] = {
        "desktop",
        "pictures",
        "documents",
        "downloads",
        "music",
        "videos"
    };
    size_t i;

    if (scope == NULL) {
        return;
    }

    for (i = 0; i < sizeof(common_items) / sizeof(common_items[0]); i++) {
        if (scope->count >= COMPARE_SCOPE_MAX_ITEMS) {
            break;
        }
        snprintf(
            scope->items[scope->count],
            sizeof(scope->items[scope->count]),
            "%s",
            common_items[i]
        );
        scope->count++;
    }
}

static int compare_scope_parse(
    const char *scope_csv,
    CompareScope *out_scope,
    char *error_text,
    size_t error_text_size
)
{
    char copy[512];
    char *token;

    if (error_text != NULL && error_text_size > 0) {
        error_text[0] = '\0';
    }
    if (out_scope == NULL) {
        return 0;
    }

    memset(out_scope, 0, sizeof(*out_scope));
    out_scope->match_all = 1;
    if (scope_csv == NULL || scope_csv[0] == '\0') {
        return 1;
    }
    if (strlen(scope_csv) >= sizeof(copy)) {
        snprintf(error_text, error_text_size, "Compare scope is too long");
        return 0;
    }

    snprintf(copy, sizeof(copy), "%s", scope_csv);
    token = strtok(copy, ",");
    out_scope->match_all = 0;
    while (token != NULL) {
        char normalized[COMPARE_SCOPE_ITEM_MAX];

        snprintf(normalized, sizeof(normalized), "%s", token);
        compare_scope_normalize_token(normalized);
        if (normalized[0] == '\0') {
            token = strtok(NULL, ",");
            continue;
        }
        if (strcmp(normalized, "all") == 0 ||
            strcmp(normalized, "*") == 0) {
            memset(out_scope, 0, sizeof(*out_scope));
            out_scope->match_all = 1;
            return 1;
        }
        if (strcmp(normalized, "common") == 0) {
            compare_scope_add_common_entries(out_scope);
            token = strtok(NULL, ",");
            continue;
        }
        if (out_scope->count >= COMPARE_SCOPE_MAX_ITEMS) {
            snprintf(
                error_text,
                error_text_size,
                "Too many compare scope items (max %u)",
                (unsigned int)COMPARE_SCOPE_MAX_ITEMS
            );
            return 0;
        }
        snprintf(
            out_scope->items[out_scope->count],
            sizeof(out_scope->items[out_scope->count]),
            "%s",
            normalized
        );
        out_scope->count++;
        token = strtok(NULL, ",");
    }

    if (out_scope->count == 0) {
        out_scope->match_all = 1;
    }
    return 1;
}

static int compare_scope_matches_rel_path(
    const CompareScope *scope,
    const char *rel_path
)
{
    char normalized[PATH_MAX_LEN];
    char *remainder;
    char *cursor;
    size_t i;

    if (scope == NULL || scope->match_all) {
        return 1;
    }
    if (rel_path == NULL || rel_path[0] == '\0') {
        return 0;
    }
    snprintf(normalized, sizeof(normalized), "%s", rel_path);
    compare_scope_normalize_token(normalized);
    if (normalized[0] == '\0') {
        return 0;
    }

    remainder = strchr(normalized, '/');
    if (remainder == NULL || remainder[1] == '\0') {
        return 0;
    }
    remainder++;
    for (i = 0; i < scope->count; i++) {
        size_t wanted_len = strlen(scope->items[i]);

        if (wanted_len == 0) {
            continue;
        }
        if (strncmp(remainder, scope->items[i], wanted_len) != 0) {
            continue;
        }
        cursor = remainder + wanted_len;
        if (*cursor == '\0' || *cursor == '/') {
            return 1;
        }
    }
    return 0;
}

static void targeted_root_scope_normalize_token(char *text)
{
    size_t i;

    if (text == NULL) {
        return;
    }

    targeted_trim_ascii(text);
    while (text[0] == '/' || text[0] == '\\') {
        memmove(text, text + 1, strlen(text));
    }
    for (i = 0; text[i] != '\0'; i++) {
        if (text[i] == '\\') {
            text[i] = '/';
        }
        text[i] = (char)ascii_tolower((unsigned char)text[i]);
    }
    while (i > 0 && (text[i - 1U] == '/' || text[i - 1U] == '\\')) {
        text[--i] = '\0';
    }
}

static int targeted_root_scope_has_item(
    const TargetedRecoveryFilter *filter,
    const char *item
)
{
    size_t i;

    if (filter == NULL || item == NULL || item[0] == '\0') {
        return 0;
    }

    for (i = 0; i < filter->root_scope_count; i++) {
        if (strcmp(filter->root_scopes[i], item) == 0) {
            return 1;
        }
    }
    return 0;
}

static int targeted_root_scope_add_item(
    TargetedRecoveryFilter *filter,
    const char *item,
    char *error_text,
    size_t error_text_size
)
{
    char normalized[NAME_MAX_LEN];

    if (filter == NULL || item == NULL) {
        return 0;
    }

    snprintf(normalized, sizeof(normalized), "%s", item);
    targeted_root_scope_normalize_token(normalized);
    if (normalized[0] == '\0') {
        return 1;
    }
    if (targeted_root_scope_has_item(filter, normalized)) {
        return 1;
    }
    if (filter->root_scope_count >=
        (sizeof(filter->root_scopes) / sizeof(filter->root_scopes[0]))) {
        snprintf(error_text, error_text_size, "Too many root folder filters");
        return 0;
    }

    snprintf(
        filter->root_scopes[filter->root_scope_count],
        sizeof(filter->root_scopes[filter->root_scope_count]),
        "%s",
        normalized
    );
    filter->root_scope_count++;
    return 1;
}

static int compare_int_order(const void *left, const void *right)
{
    const int a = *(const int *)left;
    const int b = *(const int *)right;

    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}

static int recover_path_item_order(const void *left, const void *right)
{
    const RecoverPathItem *a = (const RecoverPathItem *)left;
    const RecoverPathItem *b = (const RecoverPathItem *)right;
    int cmp = strcmp(a->match_key, b->match_key);

    if (cmp != 0) {
        return cmp;
    }
    if (a->has_size != b->has_size) {
        return a->has_size ? -1 : 1;
    }
    if (a->size < b->size) {
        return -1;
    }
    if (a->size > b->size) {
        return 1;
    }
    return strcmp(a->rel_path, b->rel_path);
}

static int recover_path_decode_utf8(
    const unsigned char *text,
    size_t remaining,
    uint32_t *codepoint,
    size_t *used
)
{
    uint32_t cp;

    if (text == NULL || remaining == 0 || codepoint == NULL || used == NULL) {
        return 0;
    }

    if (text[0] < 0x80U) {
        *codepoint = text[0];
        *used = 1U;
        return 1;
    }
    if ((text[0] & 0xE0U) == 0xC0U && remaining >= 2U &&
        (text[1] & 0xC0U) == 0x80U) {
        cp = ((uint32_t)(text[0] & 0x1FU) << 6) |
             (uint32_t)(text[1] & 0x3FU);
        if (cp >= 0x80U) {
            *codepoint = cp;
            *used = 2U;
            return 1;
        }
        return 0;
    }
    if ((text[0] & 0xF0U) == 0xE0U && remaining >= 3U &&
        (text[1] & 0xC0U) == 0x80U &&
        (text[2] & 0xC0U) == 0x80U) {
        cp = ((uint32_t)(text[0] & 0x0FU) << 12) |
             ((uint32_t)(text[1] & 0x3FU) << 6) |
             (uint32_t)(text[2] & 0x3FU);
        if (cp >= 0x800U) {
            *codepoint = cp;
            *used = 3U;
            return 1;
        }
        return 0;
    }
    if ((text[0] & 0xF8U) == 0xF0U && remaining >= 4U &&
        (text[1] & 0xC0U) == 0x80U &&
        (text[2] & 0xC0U) == 0x80U &&
        (text[3] & 0xC0U) == 0x80U) {
        cp = ((uint32_t)(text[0] & 0x07U) << 18) |
             ((uint32_t)(text[1] & 0x3FU) << 12) |
             ((uint32_t)(text[2] & 0x3FU) << 6) |
             (uint32_t)(text[3] & 0x3FU);
        if (cp >= 0x10000U && cp <= 0x10FFFFU) {
            *codepoint = cp;
            *used = 4U;
            return 1;
        }
    }
    return 0;
}

static int recover_path_base_letter(uint32_t codepoint)
{
    switch (codepoint) {
        case 0x00C0: case 0x00C1: case 0x00C2: case 0x00C3:
        case 0x00C4: case 0x00C5: case 0x00E0: case 0x00E1:
        case 0x00E2: case 0x00E3: case 0x00E4: case 0x00E5:
        case 0x0100: case 0x0101: case 0x0102: case 0x0103:
        case 0x0104: case 0x0105:
            return 'a';
        case 0x00C7: case 0x00E7: case 0x0106: case 0x0107:
        case 0x0108: case 0x0109: case 0x010A: case 0x010B:
        case 0x010C: case 0x010D:
            return 'c';
        case 0x00C8: case 0x00C9: case 0x00CA: case 0x00CB:
        case 0x00E8: case 0x00E9: case 0x00EA: case 0x00EB:
        case 0x0112: case 0x0113: case 0x0114: case 0x0115:
        case 0x0116: case 0x0117: case 0x0118: case 0x0119:
        case 0x011A: case 0x011B:
            return 'e';
        case 0x011C: case 0x011D: case 0x011E: case 0x011F:
        case 0x0120: case 0x0121: case 0x0122: case 0x0123:
            return 'g';
        case 0x00CC: case 0x00CD: case 0x00CE: case 0x00CF:
        case 0x00EC: case 0x00ED: case 0x00EE: case 0x00EF:
        case 0x0128: case 0x0129: case 0x012A: case 0x012B:
        case 0x012C: case 0x012D: case 0x012E: case 0x012F:
        case 0x0130: case 0x0131:
            return 'i';
        case 0x0134: case 0x0135:
            return 'j';
        case 0x0139: case 0x013A: case 0x013B: case 0x013C:
        case 0x013D: case 0x013E: case 0x0141: case 0x0142:
            return 'l';
        case 0x00D1: case 0x00F1: case 0x0143: case 0x0144:
        case 0x0145: case 0x0146: case 0x0147: case 0x0148:
            return 'n';
        case 0x00D2: case 0x00D3: case 0x00D4: case 0x00D5:
        case 0x00D6: case 0x00D8: case 0x00F2: case 0x00F3:
        case 0x00F4: case 0x00F5: case 0x00F6: case 0x00F8:
        case 0x014C: case 0x014D: case 0x014E: case 0x014F:
        case 0x0150: case 0x0151:
            return 'o';
        case 0x0154: case 0x0155: case 0x0156: case 0x0157:
        case 0x0158: case 0x0159:
            return 'r';
        case 0x015A: case 0x015B: case 0x015C: case 0x015D:
        case 0x015E: case 0x015F: case 0x0160: case 0x0161:
            return 's';
        case 0x0162: case 0x0163: case 0x0164: case 0x0165:
            return 't';
        case 0x00D9: case 0x00DA: case 0x00DB: case 0x00DC:
        case 0x00F9: case 0x00FA: case 0x00FB: case 0x00FC:
        case 0x0168: case 0x0169: case 0x016A: case 0x016B:
        case 0x016C: case 0x016D: case 0x016E: case 0x016F:
        case 0x0170: case 0x0171: case 0x0172: case 0x0173:
            return 'u';
        case 0x00DD: case 0x00FD: case 0x00FF: case 0x0176:
        case 0x0177: case 0x0178:
            return 'y';
        case 0x0179: case 0x017A: case 0x017B: case 0x017C:
        case 0x017D: case 0x017E:
            return 'z';
        default:
            return 0;
    }
}

static void recover_path_build_key(
    const char *rel_path,
    char *out,
    size_t out_size
)
{
    const unsigned char *cursor;
    size_t remaining;
    size_t pos = 0;

    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';
    if (rel_path == NULL) {
        return;
    }

    cursor = (const unsigned char *)rel_path;
    remaining = strlen(rel_path);
    while (remaining > 0 && *cursor != '\0' && pos + 1U < out_size) {
        const unsigned char *encoded = cursor;
        uint32_t codepoint = 0;
        size_t used = 0;
        int mapped;
        size_t i;

        if (*cursor < 0x80U) {
            unsigned char ch = *cursor;

            if (ch == '\\') {
                ch = '/';
            }
            out[pos++] = (char)tolower(ch);
            cursor++;
            remaining--;
            continue;
        }

        if (!recover_path_decode_utf8(cursor, remaining, &codepoint, &used)) {
            cursor++;
            remaining--;
            continue;
        }
        cursor += used;
        remaining -= used;

        if (codepoint >= 0x0300U && codepoint <= 0x036FU) {
            continue;
        }

        mapped = recover_path_base_letter(codepoint);
        if (mapped != 0) {
            out[pos++] = (char)mapped;
        } else {
            for (i = 0; i < used && pos + 1U < out_size; i++) {
                out[pos++] = (char)encoded[i];
            }
        }
    }

    out[pos] = '\0';
}

static int recover_path_list_append(
    RecoverPathList *list,
    const char *rel_path,
    uint64_t size,
    int has_size
)
{
    RecoverPathItem *new_items;
    char match_key[PATH_MAX_LEN];

    if (list == NULL || rel_path == NULL || rel_path[0] == '\0') {
        return 0;
    }

    recover_path_build_key(rel_path, match_key, sizeof(match_key));
    if (match_key[0] == '\0') {
        return 1;
    }

    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 1024U : list->capacity * 2U;

        new_items = (RecoverPathItem *)realloc(list->items, new_capacity * sizeof(*new_items));
        if (new_items == NULL) {
            return 0;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    snprintf(list->items[list->count].rel_path, sizeof(list->items[list->count].rel_path), "%s", rel_path);
    snprintf(list->items[list->count].match_key, sizeof(list->items[list->count].match_key), "%s", match_key);
    list->items[list->count].size = size;
    list->items[list->count].has_size = has_size ? 1 : 0;
    list->count++;
    return 1;
}

static void recover_path_list_finalize(RecoverPathList *list)
{
    size_t read_index;
    size_t write_index;

    if (list == NULL || list->count == 0) {
        return;
    }

    qsort(list->items, list->count, sizeof(*list->items), recover_path_item_order);
    write_index = 1;
    for (read_index = 1; read_index < list->count; read_index++) {
        if (strcmp(list->items[read_index].match_key, list->items[write_index - 1U].match_key) == 0 &&
            list->items[read_index].has_size == list->items[write_index - 1U].has_size &&
            (!list->items[read_index].has_size ||
             list->items[read_index].size == list->items[write_index - 1U].size)) {
            continue;
        }
        list->items[write_index++] = list->items[read_index];
    }
    list->count = write_index;
}

static void recover_path_list_free(RecoverPathList *list)
{
    if (list == NULL) {
        return;
    }

    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int recover_path_list_find_range(
    const RecoverPathList *list,
    const char *match_key,
    size_t *out_begin,
    size_t *out_end
)
{
    size_t begin = 0;
    size_t end;

    if (out_begin != NULL) {
        *out_begin = 0;
    }
    if (out_end != NULL) {
        *out_end = 0;
    }
    if (list == NULL || list->count == 0 || match_key == NULL || match_key[0] == '\0') {
        return 0;
    }

    end = list->count;
    while (begin < end) {
        size_t mid = begin + (end - begin) / 2U;
        int cmp = strcmp(list->items[mid].match_key, match_key);

        if (cmp < 0) {
            begin = mid + 1U;
        } else {
            end = mid;
        }
    }
    if (begin >= list->count || strcmp(list->items[begin].match_key, match_key) != 0) {
        return 0;
    }

    end = begin;
    while (end < list->count && strcmp(list->items[end].match_key, match_key) == 0) {
        end++;
    }
    if (out_begin != NULL) {
        *out_begin = begin;
    }
    if (out_end != NULL) {
        *out_end = end;
    }
    return 1;
}

static int recover_path_list_lookup_output(
    const RecoverPathList *list,
    const char *match_key,
    uint64_t size,
    char *out_rel_path,
    size_t out_rel_path_size
)
{
    size_t begin = 0;
    size_t end = 0;
    size_t i;

    if (out_rel_path != NULL && out_rel_path_size > 0) {
        out_rel_path[0] = '\0';
    }
    if (list == NULL ||
        match_key == NULL ||
        match_key[0] == '\0' ||
        out_rel_path == NULL ||
        out_rel_path_size == 0) {
        return 0;
    }
    if (!recover_path_list_find_range(list, match_key, &begin, &end)) {
        return 0;
    }

    for (i = begin; i < end; i++) {
        if (list->items[i].has_size && list->items[i].size != size) {
            continue;
        }
        snprintf(out_rel_path, out_rel_path_size, "%s", list->items[i].rel_path);
        return 1;
    }

    for (i = begin; i < end; i++) {
        snprintf(out_rel_path, out_rel_path_size, "%s", list->items[i].rel_path);
        return 1;
    }

    return 0;
}

static int recover_path_list_load_from_file(
    const char *path,
    RecoverPathList *out_list,
    char *error_text,
    size_t error_text_size
)
{
    FILE *file;
    char line[PATH_MAX_LEN * 2U];
    int rel_path_column = -1;
    int size_column = -1;
    int saw_header = 0;

    if (error_text != NULL && error_text_size > 0) {
        error_text[0] = '\0';
    }
    if (path == NULL || path[0] == '\0' || out_list == NULL) {
        snprintf(error_text, error_text_size, "Missing path list");
        return 0;
    }

    memset(out_list, 0, sizeof(*out_list));
    file = fopen(path, "rb");
    if (file == NULL) {
        snprintf(error_text, error_text_size, "Could not open path list: %s", path);
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char copy[PATH_MAX_LEN * 2U];
        char *cursor;
        char *saveptr = NULL;
        int current_column = 0;
        char rel_path[PATH_MAX_LEN];
        uint64_t size = 0;
        int have_rel_path = 0;
        int have_size = 0;

        snprintf(copy, sizeof(copy), "%s", line);
        targeted_trim_ascii(copy);
        if (copy[0] == '\0' || copy[0] == '#') {
            continue;
        }

        if (!saw_header) {
            char header[PATH_MAX_LEN * 2U];

            snprintf(header, sizeof(header), "%s", copy);
            cursor = strtok_r(header, "\t", &saveptr);
            while (cursor != NULL) {
                compare_scope_normalize_token(cursor);
                if (strcmp(cursor, "rel_path") == 0 ||
                    strcmp(cursor, "path") == 0) {
                    rel_path_column = current_column;
                    saw_header = 1;
                } else if (strcmp(cursor, "size") == 0 ||
                           strcmp(cursor, "source_size") == 0) {
                    size_column = current_column;
                    saw_header = 1;
                }
                current_column++;
                cursor = strtok_r(NULL, "\t", &saveptr);
            }
            if (saw_header && rel_path_column >= 0) {
                continue;
            }
        }

        rel_path[0] = '\0';
        saveptr = NULL;
        cursor = strtok_r(copy, "\t", &saveptr);
        while (cursor != NULL) {
            targeted_trim_ascii(cursor);
            if ((rel_path_column >= 0 && current_column == rel_path_column) ||
                (rel_path_column < 0 && current_column == 0)) {
                snprintf(rel_path, sizeof(rel_path), "%s", cursor);
                have_rel_path = rel_path[0] != '\0';
            }
            if (size_column >= 0 && current_column == size_column) {
                char *endptr = NULL;
                unsigned long long value = strtoull(cursor, &endptr, 10);

                if (endptr != cursor && *endptr == '\0') {
                    size = (uint64_t)value;
                    have_size = 1;
                }
            }
            current_column++;
            cursor = strtok_r(NULL, "\t", &saveptr);
        }

        if (!have_rel_path) {
            continue;
        }
        if (!recover_path_list_append(out_list, rel_path, size, have_size)) {
            fclose(file);
            recover_path_list_free(out_list);
            snprintf(error_text, error_text_size, "Out of memory while loading path list");
            return 0;
        }
    }

    fclose(file);
    recover_path_list_finalize(out_list);
    if (out_list->count == 0) {
        snprintf(error_text, error_text_size, "Path list did not contain any usable paths");
        return 0;
    }
    return 1;
}

static int record_list_append(RecordList *list, int record)
{
    int *new_records;

    if (list == NULL || record <= 0) {
        return 0;
    }
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 1024U : list->capacity * 2U;

        new_records = (int *)realloc(list->records, new_capacity * sizeof(*new_records));
        if (new_records == NULL) {
            return 0;
        }
        list->records = new_records;
        list->capacity = new_capacity;
    }

    list->records[list->count++] = record;
    return 1;
}

static void record_list_finalize(RecordList *list)
{
    size_t read_index;
    size_t write_index;

    if (list == NULL || list->count == 0) {
        return;
    }

    qsort(list->records, list->count, sizeof(*list->records), compare_int_order);
    write_index = 1;
    for (read_index = 1; read_index < list->count; read_index++) {
        if (list->records[read_index] == list->records[write_index - 1U]) {
            continue;
        }
        list->records[write_index++] = list->records[read_index];
    }
    list->count = write_index;
}

static int record_list_contains(const RecordList *list, int record)
{
    size_t lo = 0;
    size_t hi;

    if (list == NULL || list->count == 0 || record <= 0) {
        return 0;
    }

    hi = list->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2U;

        if (list->records[mid] == record) {
            return 1;
        }
        if (list->records[mid] < record) {
            lo = mid + 1U;
        } else {
            hi = mid;
        }
    }
    return 0;
}

static void record_list_free(RecordList *list)
{
    if (list == NULL) {
        return;
    }

    free(list->records);
    list->records = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int record_list_load_from_file(
    const char *path,
    RecordList *out_list,
    char *error_text,
    size_t error_text_size
)
{
    FILE *file;
    char line[PATH_MAX_LEN];
    int record_column = -1;
    int saw_header = 0;

    if (error_text != NULL && error_text_size > 0) {
        error_text[0] = '\0';
    }
    if (path == NULL || path[0] == '\0' || out_list == NULL) {
        snprintf(error_text, error_text_size, "Missing record list path");
        return 0;
    }

    memset(out_list, 0, sizeof(*out_list));
    file = fopen(path, "rb");
    if (file == NULL) {
        snprintf(error_text, error_text_size, "Could not open record list: %s", path);
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char copy[PATH_MAX_LEN];
        char *cursor;
        char *saveptr = NULL;
        int current_column = 0;
        int parsed_record = 0;
        int found_record = 0;

        snprintf(copy, sizeof(copy), "%s", line);
        targeted_trim_ascii(copy);
        if (copy[0] == '\0' || copy[0] == '#') {
            continue;
        }

        if (!saw_header) {
            char header[PATH_MAX_LEN];

            snprintf(header, sizeof(header), "%s", copy);
            cursor = strtok_r(header, "\t", &saveptr);
            while (cursor != NULL) {
                compare_scope_normalize_token(cursor);
                if (strcmp(cursor, "record") == 0) {
                    record_column = current_column;
                    saw_header = 1;
                    break;
                }
                current_column++;
                cursor = strtok_r(NULL, "\t", &saveptr);
            }
            if (saw_header) {
                continue;
            }
        }

        saveptr = NULL;
        cursor = strtok_r(copy, "\t", &saveptr);
        while (cursor != NULL) {
            targeted_trim_ascii(cursor);
            if ((record_column >= 0 && current_column == record_column) ||
                (record_column < 0 && current_column == 0)) {
                char *endptr = NULL;
                long value = strtol(cursor, &endptr, 10);

                if (endptr != cursor && *endptr == '\0' &&
                    value > 0 && value <= INT32_MAX) {
                    parsed_record = (int)value;
                    found_record = 1;
                    break;
                }
            }
            current_column++;
            cursor = strtok_r(NULL, "\t", &saveptr);
        }

        if (found_record && !record_list_append(out_list, parsed_record)) {
            fclose(file);
            record_list_free(out_list);
            snprintf(error_text, error_text_size, "Out of memory while loading record list");
            return 0;
        }
    }

    fclose(file);
    record_list_finalize(out_list);
    if (out_list->count == 0) {
        snprintf(error_text, error_text_size, "Record list did not contain any usable record ids");
        return 0;
    }
    return 1;
}

static void targeted_stats_note_failure(
    TargetedRecoveryStats *stats,
    const char *reason
)
{
    const char *failure_class;

    if (stats == NULL) {
        return;
    }

    failure_class = recovery_runner_failure_class(reason);
    if (strcmp(failure_class, "read_error") == 0) {
        stats->failed_read_error++;
    } else if (strcmp(failure_class, "start_mismatch") == 0) {
        stats->failed_start_mismatch++;
    } else if (strcmp(failure_class, "truncated_or_end_mismatch") == 0) {
        stats->failed_truncated_or_end_mismatch++;
    } else if (strcmp(failure_class, "output_error") == 0) {
        stats->failed_output_error++;
    } else if (strcmp(failure_class, "invalid_target") == 0) {
        stats->failed_invalid_target++;
    } else if (strcmp(failure_class, "interrupted") == 0) {
        stats->failed_interrupted++;
    } else {
        stats->failed_unknown++;
    }
}

static void targeted_stats_log_summary(const TargetedRecoveryStats *stats)
{
    if (stats == NULL) {
        return;
    }

    if (stats->skipped_invalid_target > 0 || stats->skipped_image_filter > 0) {
        log_info(
            "Targeted skips: image_filter=%zu invalid_target=%zu",
            stats->skipped_image_filter,
            stats->skipped_invalid_target
        );
    }

    if (stats->failed_read_error > 0 ||
        stats->failed_start_mismatch > 0 ||
        stats->failed_truncated_or_end_mismatch > 0 ||
        stats->failed_output_error > 0 ||
        stats->failed_invalid_target > 0 ||
        stats->failed_interrupted > 0 ||
        stats->failed_unknown > 0) {
        log_info(
            "Targeted failures: read_error=%zu start_mismatch=%zu truncated_or_end_mismatch=%zu output_error=%zu invalid_target=%zu interrupted=%zu unknown=%zu",
            stats->failed_read_error,
            stats->failed_start_mismatch,
            stats->failed_truncated_or_end_mismatch,
            stats->failed_output_error,
            stats->failed_invalid_target,
            stats->failed_interrupted,
            stats->failed_unknown
        );
    }
}

static int targeted_parse_exact_date(const char *value, int *out_date)
{
    int date_value = 0;
    int year;
    int month;
    int day;

    if (value == NULL || out_date == NULL || strlen(value) != 8U) {
        return 0;
    }
    if (sscanf(value, "%8d", &date_value) != 1) {
        return 0;
    }

    year = date_value / 10000;
    month = (date_value / 100) % 100;
    day = date_value % 100;
    if (year < 1970 || year > 2999 ||
        month < 1 || month > 12 ||
        day < 1 || day > 31) {
        return 0;
    }

    *out_date = date_value;
    return 1;
}

static void targeted_copy_text_truncated(
    char *dest,
    size_t dest_size,
    const char *src
)
{
    size_t copy_len;

    if (dest == NULL || dest_size == 0U) {
        return;
    }

    dest[0] = '\0';
    if (src == NULL) {
        return;
    }

    copy_len = strlen(src);
    if (copy_len >= dest_size) {
        copy_len = dest_size - 1U;
    }

    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
}

static void targeted_append_text_truncated(
    char *dest,
    size_t dest_size,
    const char *src
)
{
    size_t used;
    size_t copy_len;

    if (dest == NULL || dest_size == 0U || src == NULL || src[0] == '\0') {
        return;
    }

    used = strnlen(dest, dest_size);
    if (used >= dest_size - 1U) {
        dest[dest_size - 1U] = '\0';
        return;
    }

    copy_len = strlen(src);
    if (copy_len > dest_size - used - 1U) {
        copy_len = dest_size - used - 1U;
    }

    memcpy(dest + used, src, copy_len);
    dest[used + copy_len] = '\0';
}

static void targeted_set_error_with_value(
    char *error_text,
    size_t error_text_size,
    const char *prefix,
    const char *value,
    const char *suffix
)
{
    if (error_text == NULL || error_text_size == 0U) {
        return;
    }

    targeted_copy_text_truncated(error_text, error_text_size, prefix);
    targeted_append_text_truncated(error_text, error_text_size, value);
    targeted_append_text_truncated(error_text, error_text_size, suffix);
}

static void targeted_set_error_with_two_values(
    char *error_text,
    size_t error_text_size,
    const char *prefix,
    const char *left,
    const char *middle,
    const char *right,
    const char *suffix
)
{
    if (error_text == NULL || error_text_size == 0U) {
        return;
    }

    targeted_copy_text_truncated(error_text, error_text_size, prefix);
    targeted_append_text_truncated(error_text, error_text_size, left);
    targeted_append_text_truncated(error_text, error_text_size, middle);
    targeted_append_text_truncated(error_text, error_text_size, right);
    targeted_append_text_truncated(error_text, error_text_size, suffix);
}

static int targeted_parse_filter(
    const char *filter_csv,
    TargetedRecoveryFilter *out_filter,
    char *error_text,
    size_t error_text_size
)
{
    char filter_copy[2048];
    char *token;
    int recognized = 0;

    if (error_text != NULL && error_text_size > 0) {
        error_text[0] = '\0';
    }
    if (out_filter == NULL) {
        return 0;
    }

    memset(out_filter, 0, sizeof(*out_filter));
    if (filter_csv == NULL || filter_csv[0] == '\0') {
        snprintf(error_text, error_text_size, "Missing --filter expression");
        return 0;
    }
    if (strlen(filter_csv) >= sizeof(filter_copy)) {
        snprintf(error_text, error_text_size, "Filter expression is too long");
        return 0;
    }

    snprintf(filter_copy, sizeof(filter_copy), "%s", filter_csv);
    token = strtok(filter_copy, ",");
    while (token != NULL) {
        char *sep;
        char key[32];
        char value[NAME_MAX_LEN];
        size_t i;

        targeted_trim_ascii(token);
        sep = strchr(token, ':');
        if (sep == NULL) {
            sep = strchr(token, '=');
        }
        if (sep == NULL) {
            snprintf(error_text, error_text_size, "Invalid filter token: %s", token);
            return 0;
        }

        *sep = '\0';
        targeted_copy_text_truncated(key, sizeof(key), token);
        targeted_copy_text_truncated(value, sizeof(value), sep + 1);
        targeted_trim_ascii(key);
        targeted_trim_ascii(value);
        for (i = 0; key[i] != '\0'; i++) {
            key[i] = (char)ascii_tolower((unsigned char)key[i]);
        }
        for (i = 0; value[i] != '\0'; i++) {
            value[i] = (char)ascii_tolower((unsigned char)value[i]);
        }

        if (strcmp(key, "date") == 0 || strcmp(key, "created") == 0) {
            char *dash = strchr(value, '-');

            if (dash != NULL) {
                int start_date = 0;
                int end_date = 0;

                *dash = '\0';
                if (!targeted_parse_exact_date(value, &start_date) ||
                    !targeted_parse_exact_date(dash + 1, &end_date) ||
                    start_date > end_date) {
                    targeted_set_error_with_two_values(
                        error_text,
                        error_text_size,
                        "Invalid date filter: ",
                        value,
                        "-",
                        dash + 1,
                        " (expected YYYYMMDD or YYYYMMDD-YYYYMMDD)"
                    );
                    return 0;
                }
                out_filter->date_yyyymmdd = start_date;
                out_filter->date_end_yyyymmdd = end_date;
            } else {
                if (!targeted_parse_exact_date(value, &out_filter->date_yyyymmdd)) {
                    targeted_set_error_with_value(
                        error_text,
                        error_text_size,
                        "Invalid date filter: ",
                        value,
                        " (expected YYYYMMDD or YYYYMMDD-YYYYMMDD)"
                    );
                    return 0;
                }
                out_filter->date_end_yyyymmdd = out_filter->date_yyyymmdd;
            }
            out_filter->has_date = 1;
            recognized = 1;
        } else if (strcmp(key, "deleted") == 0 ||
                   strcmp(key, "trash") == 0 ||
                   strcmp(key, "state") == 0) {
            if (strcmp(value, "1") == 0 ||
                strcmp(value, "true") == 0 ||
                strcmp(value, "yes") == 0 ||
                strcmp(value, "deleted") == 0 ||
                strcmp(value, "trashed") == 0) {
                out_filter->deleted_value = 1;
                out_filter->has_deleted = 1;
            } else if (strcmp(value, "0") == 0 ||
                       strcmp(value, "false") == 0 ||
                       strcmp(value, "no") == 0 ||
                       strcmp(value, "live") == 0 ||
                       strcmp(value, "active") == 0) {
                out_filter->deleted_value = 0;
                out_filter->has_deleted = 1;
            } else if (strcmp(value, "2") == 0 ||
                       strcmp(value, "both") == 0 ||
                       strcmp(value, "all") == 0 ||
                       strcmp(value, "any") == 0) {
                out_filter->deleted_value = 2;
                out_filter->has_deleted = 1;
            } else {
                targeted_set_error_with_value(
                    error_text,
                    error_text_size,
                    "Invalid deleted filter: ",
                    value,
                    " (expected deleted/live/both/1/0/2/true/false)"
                );
                return 0;
            }
            recognized = 1;
        } else if (strcmp(key, "fmt") == 0 ||
                   strcmp(key, "format") == 0 ||
                   strcmp(key, "ext") == 0) {
            const char *src = value;
            size_t pos = 0;

            if (src[0] == '.') {
                src++;
            }
            if (src[0] == '\0') {
                snprintf(error_text, error_text_size, "Empty format filter");
                return 0;
            }
            while (src[pos] != '\0' && pos + 1U < sizeof(out_filter->format_ext)) {
                out_filter->format_ext[pos] = (char)ascii_tolower((unsigned char)src[pos]);
                pos++;
            }
            out_filter->format_ext[pos] = '\0';
            if (src[pos] != '\0') {
                snprintf(error_text, error_text_size, "Format filter is too long");
                return 0;
            }
            out_filter->has_format = 1;
            recognized = 1;
        } else if (strcmp(key, "root") == 0 ||
                   strcmp(key, "folder") == 0 ||
                   strcmp(key, "dir") == 0 ||
                   strcmp(key, "top") == 0) {
            if (!targeted_root_scope_add_item(
                    out_filter,
                    value,
                    error_text,
                    error_text_size)) {
                return 0;
            }
            recognized = 1;
        } else {
            snprintf(error_text, error_text_size, "Unknown filter key: %s", key);
            return 0;
        }

        token = strtok(NULL, ",");
    }

    if (!recognized) {
        snprintf(error_text, error_text_size, "No usable filter terms were found");
        return 0;
    }

    return 1;
}

static int targeted_filetime_to_yyyymmdd(uint64_t filetime)
{
    int64_t unix_seconds;
    time_t value;
    struct tm tm_value;

    if (filetime == 0) {
        return 0;
    }

    unix_seconds = (int64_t)(filetime / 10000000ULL) - 11644473600LL;
    if (unix_seconds <= 0) {
        return 0;
    }

    value = (time_t)unix_seconds;
    if (gmtime_r(&value, &tm_value) == NULL) {
        return 0;
    }

    return (tm_value.tm_year + 1900) * 10000 +
           (tm_value.tm_mon + 1) * 100 +
           tm_value.tm_mday;
}

static int targeted_name_is_recycle_root(const char *name)
{
    return name != NULL &&
           (streq_ci(name, "$Recycle.Bin") ||
            streq_ci(name, "Recycler") ||
            streq_ci(name, "Recycled"));
}

static int targeted_entry_is_deleted_like(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry
)
{
    const MftEntry *current = entry;
    size_t depth = 0;

    if (entry == NULL) {
        return 0;
    }
    if ((entry->flags & 0x0001U) == 0U) {
        return 1;
    }

    while (current != NULL && depth++ < 256U) {
        if (targeted_name_is_recycle_root(current->name)) {
            return 1;
        }
        if (current->record == 5 ||
            current->parent == (uint64_t)current->record ||
            current->parent > (uint64_t)INT32_MAX) {
            break;
        }
        current = find_entry_by_record_relaxed(
            items,
            index,
            count,
            current->volume_index,
            current->family,
            (int)current->parent);
    }

    return 0;
}

static const char *targeted_entry_extension(const MftEntry *entry)
{
    const char *dot;

    if (entry == NULL || entry->name[0] == '\0') {
        return NULL;
    }

    dot = strrchr(entry->name, '.');
    if (dot == NULL || dot[1] == '\0') {
        return NULL;
    }

    return dot + 1;
}

static const MftEntry *targeted_find_root_child_entry(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry
)
{
    const MftEntry *current = entry;
    size_t depth = 0;

    if (items == NULL || index == NULL || entry == NULL) {
        return NULL;
    }

    while (current != NULL && depth++ < 256U) {
        const MftEntry *parent;

        if (current->parent > (uint64_t)INT32_MAX ||
            current->parent == (uint64_t)current->record) {
            break;
        }

        parent = find_entry_by_record_relaxed(
            items,
            index,
            count,
            current->volume_index,
            current->family,
            (int)current->parent
        );
        if (parent == NULL) {
            break;
        }
        if (parent->record == 5) {
            if ((current->flags & 0x0002U) != 0U && current->name[0] != '\0') {
                return current;
            }
            return NULL;
        }
        current = parent;
    }

    return NULL;
}

static int targeted_root_scope_has_path_scope(const TargetedRecoveryFilter *filter)
{
    size_t i;

    if (filter == NULL) {
        return 0;
    }

    for (i = 0; i < filter->root_scope_count; i++) {
        if (root_scope_item_has_path_separator(filter->root_scopes[i])) {
            return 1;
        }
    }
    return 0;
}

static int targeted_build_normalized_mft_entry_scope_path(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    char *out,
    size_t out_size
)
{
    const MftEntry *chain[256];
    const MftEntry *cur = entry;
    size_t chain_count = 0;
    size_t i;
    int reached_root = 0;

    if (out == NULL || out_size == 0U) {
        return 0;
    }
    out[0] = '\0';

    if (items == NULL || index == NULL || entry == NULL || entry->name[0] == '\0') {
        return 0;
    }

    while (cur != NULL && chain_count < (sizeof(chain) / sizeof(chain[0]))) {
        chain[chain_count++] = cur;
        if (cur->parent == 5U) {
            reached_root = 1;
            break;
        }
        if (cur->record == 5 ||
            cur->parent == (uint64_t)cur->record ||
            cur->parent > (uint64_t)INT32_MAX) {
            break;
        }
        cur = find_entry_by_record_relaxed(
            items,
            index,
            count,
            cur->volume_index,
            cur->family,
            (int)cur->parent
        );
    }

    if (!reached_root) {
        return 0;
    }

    for (i = chain_count; i > 0; i--) {
        const MftEntry *part = chain[i - 1U];

        if (part->record == 5) {
            continue;
        }
        if (!append_normalized_scope_path_part(out, out_size, part->name)) {
            return 0;
        }
    }

    return out[0] != '\0';
}

static int targeted_normalized_scope_path_matches(
    const TargetedRecoveryFilter *filter,
    const char *normalized_path
)
{
    size_t i;

    if (filter == NULL || normalized_path == NULL || normalized_path[0] == '\0') {
        return 0;
    }

    for (i = 0; i < filter->root_scope_count; i++) {
        const char *scope = filter->root_scopes[i];
        size_t scope_len;

        if (scope == NULL || scope[0] == '\0') {
            continue;
        }
        scope_len = strlen(scope);
        if (strcmp(normalized_path, scope) == 0 ||
            (strncmp(normalized_path, scope, scope_len) == 0 &&
             normalized_path[scope_len] == '/')) {
            return 1;
        }
    }
    return 0;
}

static int targeted_entry_matches_root_scope(
    const TargetedRecoveryFilter *filter,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry
)
{
    char normalized_path[PATH_MAX_LEN];
    char normalized[NAME_MAX_LEN];
    const MftEntry *root_child;

    if (filter == NULL || filter->root_scope_count == 0) {
        return 1;
    }

    if (targeted_root_scope_has_path_scope(filter)) {
        if (!targeted_build_normalized_mft_entry_scope_path(
                items,
                index,
                count,
                entry,
                normalized_path,
                sizeof(normalized_path))) {
            return 0;
        }
        return targeted_normalized_scope_path_matches(filter, normalized_path);
    }

    root_child = targeted_find_root_child_entry(items, index, count, entry);
    if (root_child == NULL) {
        return 0;
    }

    snprintf(normalized, sizeof(normalized), "%s", root_child->name);
    targeted_root_scope_normalize_token(normalized);
    return targeted_root_scope_has_item(filter, normalized);
}

static int targeted_format_matches_extension(
    const RecoveryFormat *format,
    const char *extension
)
{
    size_t i;

    if (format == NULL || extension == NULL || extension[0] == '\0') {
        return 0;
    }

    if (format->default_extension != NULL &&
        streq_ci(format->default_extension, extension)) {
        return 1;
    }

    for (i = 0; i < format->extension_count; i++) {
        if (format->extensions != NULL &&
            format->extensions[i] != NULL &&
            streq_ci(format->extensions[i], extension)) {
            return 1;
        }
    }

    return 0;
}

static int prune_empty_dirs_recursive(const char *path, int remove_self)
{
    DIR *dir;
    struct dirent *entry;
    int has_content = 0;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    dir = opendir(path);
    if (dir == NULL) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        char child[PATH_MAX_LEN];
        struct stat st;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >= (int)sizeof(child)) {
            has_content = 1;
            continue;
        }
        if (lstat(child, &st) != 0) {
            has_content = 1;
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (!prune_empty_dirs_recursive(child, 1)) {
                has_content = 1;
            }
        } else {
            has_content = 1;
        }
    }

    closedir(dir);
    if (!has_content && remove_self) {
        if (rmdir(path) == 0) {
            return 1;
        }
        return 0;
    }

    return !has_content;
}

static void prune_empty_recovered_subdir(const char *out_dir, const char *subdir)
{
    char root[PATH_MAX_LEN];

    if (out_dir == NULL || out_dir[0] == '\0' ||
        subdir == NULL || subdir[0] == '\0') {
        return;
    }
    if (snprintf(
            root,
            sizeof(root),
            "%s/%s/%s",
            out_dir,
            APP_RECOVERED_DIR_NAME,
            subdir) >= (int)sizeof(root)) {
        return;
    }

    (void)prune_empty_dirs_recursive(root, 0);
}

static void targeted_prune_empty_filtered_dirs(const char *out_dir)
{
    prune_empty_recovered_subdir(out_dir, "filtered");
}

static void prune_empty_deleted_dirs(const char *out_dir)
{
    prune_empty_recovered_subdir(out_dir, "deleted");
}

static int targeted_entry_matches_filter(
    const TargetedRecoveryFilter *filter,
    const RecoveryFormat *format,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry
)
{
    const char *extension;
    int created_date;
    int filename_date = 0;
    int effective_date;

    if (filter == NULL || format == NULL || entry == NULL) {
        return 0;
    }
    if (!entry->has_data || entry->name[0] == '\0') {
        return 0;
    }
    if (filter->has_deleted) {
        int is_deleted = targeted_entry_is_deleted_like(
            items,
            index,
            count,
            entry);

        if (filter->deleted_value != 2 &&
            is_deleted != filter->deleted_value) {
            return 0;
        }
    }
    if (filter->has_date) {
        created_date = targeted_filetime_to_yyyymmdd(entry->created_filetime);
        if ((format->category_mask & (RECOVERY_CATEGORY_IMAGE | RECOVERY_CATEGORY_VIDEO)) != 0U) {
            filename_date = targeted_filename_to_yyyymmdd_local(entry->name);
        }
        effective_date = filename_date != 0 ? filename_date : created_date;
        if (effective_date == 0 ||
            effective_date < filter->date_yyyymmdd ||
            effective_date > filter->date_end_yyyymmdd) {
            return 0;
        }
    }
    if (!targeted_entry_matches_root_scope(filter, items, index, count, entry)) {
        return 0;
    }

    if (!filter->has_format) {
        return 1;
    }

    extension = targeted_entry_extension(entry);
    if (extension != NULL && streq_ci(extension, filter->format_ext)) {
        return 1;
    }

    return targeted_format_matches_extension(format, filter->format_ext);
}

static int config_entry_effective_date_matches_local(
    const Config *config,
    const RecoveryFormat *format,
    const MftEntry *entry
)
{
    int created_date;
    int filename_date = 0;
    int effective_date;

    if (config == NULL || entry == NULL) {
        return 0;
    }
    if (!config->has_date_filter) {
        return 1;
    }

    created_date = targeted_filetime_to_yyyymmdd(entry->created_filetime);
    if (format != NULL &&
        (format->category_mask & (RECOVERY_CATEGORY_IMAGE | RECOVERY_CATEGORY_VIDEO)) != 0U) {
        filename_date = targeted_filename_to_yyyymmdd_local(entry->name);
    }
    effective_date = filename_date != 0 ? filename_date : created_date;
    return effective_date != 0 &&
           effective_date >= config->date_start_yyyymmdd &&
           effective_date <= config->date_end_yyyymmdd;
}

static int config_entry_matches_users_runtime_filters_local(
    const Config *config,
    const RecoveryFormat *format,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry
)
{
    int is_deleted_like;

    if (config == NULL || entry == NULL ||
        !entry->has_data || entry->name[0] == '\0') {
        return 0;
    }

    if (config->has_deleted_filter) {
        is_deleted_like =
            entry_deleted_source_flags_in_table(items, index, count, entry) != 0U;
        if (config->deleted_value != 2 &&
            is_deleted_like != config->deleted_value) {
            return 0;
        }
    }

    return config_entry_effective_date_matches_local(config, format, entry);
}

static int compare_candidate_list_append(
    CompareCandidateList *list,
    const char *rel_path,
    const char *compare_key,
    uint64_t size,
    const char *created,
    int deleted,
    int record
)
{
    CompareCandidate *new_items;

    if (list == NULL ||
        rel_path == NULL || rel_path[0] == '\0' ||
        compare_key == NULL || compare_key[0] == '\0') {
        return 0;
    }

    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 4096U : list->capacity * 2U;

        new_items = (CompareCandidate *)realloc(list->items, new_capacity * sizeof(*new_items));
        if (new_items == NULL) {
            return 0;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    memset(&list->items[list->count], 0, sizeof(list->items[list->count]));
    snprintf(list->items[list->count].rel_path, sizeof(list->items[list->count].rel_path), "%s", rel_path);
    snprintf(list->items[list->count].compare_key, sizeof(list->items[list->count].compare_key), "%s", compare_key);
    snprintf(list->items[list->count].created, sizeof(list->items[list->count].created), "%s", created != NULL ? created : "");
    list->items[list->count].size = size;
    list->items[list->count].deleted = deleted;
    list->items[list->count].record = record;
    list->count++;
    return 1;
}

static void compare_candidate_list_free(CompareCandidateList *list)
{
    if (list == NULL) {
        return;
    }

    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int compare_candidate_order(const void *left, const void *right)
{
    const CompareCandidate *a = (const CompareCandidate *)left;
    const CompareCandidate *b = (const CompareCandidate *)right;
    int cmp = strcmp(a->compare_key, b->compare_key);

    if (cmp != 0) {
        return cmp;
    }
    if (a->size < b->size) {
        return -1;
    }
    if (a->size > b->size) {
        return 1;
    }
    return strcmp(a->rel_path, b->rel_path);
}

static int compare_path_decode_utf8(
    const unsigned char *text,
    size_t remaining,
    uint32_t *codepoint,
    size_t *used
)
{
    uint32_t cp;

    if (text == NULL || remaining == 0 || codepoint == NULL || used == NULL) {
        return 0;
    }

    if (text[0] < 0x80U) {
        *codepoint = text[0];
        *used = 1U;
        return 1;
    }
    if ((text[0] & 0xE0U) == 0xC0U && remaining >= 2U &&
        (text[1] & 0xC0U) == 0x80U) {
        cp = ((uint32_t)(text[0] & 0x1FU) << 6) |
             (uint32_t)(text[1] & 0x3FU);
        if (cp >= 0x80U) {
            *codepoint = cp;
            *used = 2U;
            return 1;
        }
        return 0;
    }
    if ((text[0] & 0xF0U) == 0xE0U && remaining >= 3U &&
        (text[1] & 0xC0U) == 0x80U &&
        (text[2] & 0xC0U) == 0x80U) {
        cp = ((uint32_t)(text[0] & 0x0FU) << 12) |
             ((uint32_t)(text[1] & 0x3FU) << 6) |
             (uint32_t)(text[2] & 0x3FU);
        if (cp >= 0x800U) {
            *codepoint = cp;
            *used = 3U;
            return 1;
        }
        return 0;
    }
    if ((text[0] & 0xF8U) == 0xF0U && remaining >= 4U &&
        (text[1] & 0xC0U) == 0x80U &&
        (text[2] & 0xC0U) == 0x80U &&
        (text[3] & 0xC0U) == 0x80U) {
        cp = ((uint32_t)(text[0] & 0x07U) << 18) |
             ((uint32_t)(text[1] & 0x3FU) << 12) |
             ((uint32_t)(text[2] & 0x3FU) << 6) |
             (uint32_t)(text[3] & 0x3FU);
        if (cp >= 0x10000U && cp <= 0x10FFFFU) {
            *codepoint = cp;
            *used = 4U;
            return 1;
        }
        return 0;
    }

    return 0;
}

static int compare_path_base_letter(uint32_t codepoint)
{
    switch (codepoint) {
        case 0x00C0: case 0x00C1: case 0x00C2: case 0x00C3:
        case 0x00C4: case 0x00C5: case 0x00E0: case 0x00E1:
        case 0x00E2: case 0x00E3: case 0x00E4: case 0x00E5:
        case 0x0100: case 0x0101: case 0x0102: case 0x0103:
        case 0x0104: case 0x0105:
            return 'a';
        case 0x00C7: case 0x00E7: case 0x0106: case 0x0107:
        case 0x0108: case 0x0109: case 0x010A: case 0x010B:
        case 0x010C: case 0x010D:
            return 'c';
        case 0x00C8: case 0x00C9: case 0x00CA: case 0x00CB:
        case 0x00E8: case 0x00E9: case 0x00EA: case 0x00EB:
        case 0x0112: case 0x0113: case 0x0114: case 0x0115:
        case 0x0116: case 0x0117: case 0x0118: case 0x0119:
        case 0x011A: case 0x011B:
            return 'e';
        case 0x011C: case 0x011D: case 0x011E: case 0x011F:
        case 0x0120: case 0x0121: case 0x0122: case 0x0123:
            return 'g';
        case 0x00CC: case 0x00CD: case 0x00CE: case 0x00CF:
        case 0x00EC: case 0x00ED: case 0x00EE: case 0x00EF:
        case 0x0128: case 0x0129: case 0x012A: case 0x012B:
        case 0x012C: case 0x012D: case 0x012E: case 0x012F:
        case 0x0130: case 0x0131:
            return 'i';
        case 0x0134: case 0x0135:
            return 'j';
        case 0x0139: case 0x013A: case 0x013B: case 0x013C:
        case 0x013D: case 0x013E: case 0x0141: case 0x0142:
            return 'l';
        case 0x00D1: case 0x00F1: case 0x0143: case 0x0144:
        case 0x0145: case 0x0146: case 0x0147: case 0x0148:
            return 'n';
        case 0x00D2: case 0x00D3: case 0x00D4: case 0x00D5:
        case 0x00D6: case 0x00D8: case 0x00F2: case 0x00F3:
        case 0x00F4: case 0x00F5: case 0x00F6: case 0x00F8:
        case 0x014C: case 0x014D: case 0x014E: case 0x014F:
        case 0x0150: case 0x0151:
            return 'o';
        case 0x0154: case 0x0155: case 0x0156: case 0x0157:
        case 0x0158: case 0x0159:
            return 'r';
        case 0x015A: case 0x015B: case 0x015C: case 0x015D:
        case 0x015E: case 0x015F: case 0x0160: case 0x0161:
            return 's';
        case 0x0162: case 0x0163: case 0x0164: case 0x0165:
            return 't';
        case 0x00D9: case 0x00DA: case 0x00DB: case 0x00DC:
        case 0x00F9: case 0x00FA: case 0x00FB: case 0x00FC:
        case 0x0168: case 0x0169: case 0x016A: case 0x016B:
        case 0x016C: case 0x016D: case 0x016E: case 0x016F:
        case 0x0170: case 0x0171: case 0x0172: case 0x0173:
            return 'u';
        case 0x00DD: case 0x00FD: case 0x00FF: case 0x0176:
        case 0x0177: case 0x0178:
            return 'y';
        case 0x0179: case 0x017A: case 0x017B: case 0x017C:
        case 0x017D: case 0x017E:
            return 'z';
        default:
            return 0;
    }
}

static void build_compare_key_from_rel_path(
    const char *rel_path,
    char *out,
    size_t out_size
)
{
    const unsigned char *cursor = (const unsigned char *)rel_path;
    size_t pos = 0;

    if (out == NULL || out_size == 0) {
        return;
    }

    out[0] = '\0';
    if (rel_path == NULL) {
        return;
    }

    while (*cursor != '\0' && pos + 1U < out_size) {
        uint32_t codepoint = 0;
        size_t used = 0;
        int mapped = 0;

        if (*cursor < 0x80U) {
            unsigned char ch = *cursor++;

            if (ch == '\\') {
                ch = '/';
            }
            out[pos++] = (char)ascii_tolower(ch);
            continue;
        }

        if (!compare_path_decode_utf8(cursor, strlen((const char *)cursor), &codepoint, &used)) {
            cursor++;
            continue;
        }
        cursor += used;

        if (codepoint >= 0x0300U && codepoint <= 0x036FU) {
            continue;
        }

        mapped = compare_path_base_letter(codepoint);
        if (mapped != 0 && pos + 1U < out_size) {
            out[pos++] = (char)mapped;
        }
    }

    out[pos] = '\0';
}

static int compare_format_matches_extension(
    const RecoveryFormat *format,
    const char *extension
)
{
    size_t i;

    if (format == NULL || extension == NULL || extension[0] == '\0') {
        return 0;
    }
    if (format->default_extension != NULL &&
        streq_ci(format->default_extension, extension)) {
        return 1;
    }
    for (i = 0; i < format->extension_count; i++) {
        if (format->extensions != NULL &&
            format->extensions[i] != NULL &&
            streq_ci(format->extensions[i], extension)) {
            return 1;
        }
    }
    return 0;
}

static const char *compare_path_extension(const char *path)
{
    const char *dot;

    if (path == NULL || path[0] == '\0') {
        return NULL;
    }

    dot = strrchr(path, '.');
    if (dot == NULL || dot[1] == '\0') {
        return NULL;
    }

    return dot + 1;
}

static int compare_mounted_path_matches_selection(
    const Config *config,
    const TargetedRecoveryFilter *filter,
    const CompareScope *scope,
    const char *rel_path
)
{
    const RecoveryOrder *order;
    const char *extension;
    size_t i;

    if (config == NULL || filter == NULL || rel_path == NULL || rel_path[0] == '\0') {
        return 0;
    }
    if (!compare_scope_matches_rel_path(scope, rel_path)) {
        return 0;
    }

    extension = compare_path_extension(rel_path);
    if (extension == NULL) {
        return 0;
    }
    if (filter->has_format) {
        return streq_ci(extension, filter->format_ext);
    }

    order = config->recovery_order;
    if (order == NULL || order->formats == NULL || order->count == 0) {
        return 0;
    }
    for (i = 0; i < order->count; i++) {
        if (compare_format_matches_extension(&order->formats[i], extension)) {
            return 1;
        }
    }
    return 0;
}

static int path_is_directory_local(const char *path)
{
    struct stat st;

    return path != NULL &&
           stat(path, &st) == 0 &&
           S_ISDIR(st.st_mode);
}

static int find_child_directory_ci(
    const char *parent,
    const char *wanted_name,
    char *out,
    size_t out_size
)
{
    DIR *dir;
    struct dirent *entry;
    int found = 0;

    if (parent == NULL || wanted_name == NULL || out == NULL || out_size == 0) {
        return 0;
    }

    dir = opendir(parent);
    if (dir == NULL) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL) {
        char candidate[PATH_MAX_LEN];

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (!streq_ci(entry->d_name, wanted_name)) {
            continue;
        }
        if (snprintf(candidate, sizeof(candidate), "%s/%s", parent, entry->d_name) >=
            (int)sizeof(candidate)) {
            continue;
        }
        if (!path_is_directory_local(candidate)) {
            continue;
        }
        snprintf(out, out_size, "%s", candidate);
        found = 1;
        break;
    }

    closedir(dir);
    return found;
}

static int resolve_compare_users_root(
    const char *mount_path,
    char *out,
    size_t out_size
)
{
    const char *base;

    if (mount_path == NULL || mount_path[0] == '\0' || out == NULL || out_size == 0) {
        return 0;
    }

    base = strrchr(mount_path, '/');
    base = base != NULL ? base + 1 : mount_path;
    if (streq_ci(base, "Users") && path_is_directory_local(mount_path)) {
        snprintf(out, out_size, "%s", mount_path);
        return 1;
    }

    if (find_child_directory_ci(mount_path, "Users", out, out_size)) {
        return 1;
    }

    return 0;
}

static int collect_mount_compare_entries_recursive(
    const char *root_path,
    const char *relative_path,
    const Config *config,
    const TargetedRecoveryFilter *filter,
    const CompareScope *scope,
    CompareCandidateList *list
)
{
    DIR *dir;
    struct dirent *entry;

    dir = opendir(root_path);
    if (dir == NULL) {
        return 0;
    }

    while ((entry = readdir(dir)) != NULL && !stop_requested()) {
        char child_path[PATH_MAX_LEN];
        char child_rel[PATH_MAX_LEN];
        struct stat st;
        char key[PATH_MAX_LEN];

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (snprintf(child_path, sizeof(child_path), "%s/%s", root_path, entry->d_name) >=
            (int)sizeof(child_path)) {
            continue;
        }
        if (relative_path != NULL && relative_path[0] != '\0') {
            if (snprintf(child_rel, sizeof(child_rel), "%s/%s", relative_path, entry->d_name) >=
                (int)sizeof(child_rel)) {
                continue;
            }
        } else {
            if (snprintf(child_rel, sizeof(child_rel), "%s", entry->d_name) >=
                (int)sizeof(child_rel)) {
                continue;
            }
        }
        if (lstat(child_path, &st) != 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (!collect_mount_compare_entries_recursive(
                    child_path,
                    child_rel,
                    config,
                    filter,
                    scope,
                    list)) {
                closedir(dir);
                return 0;
            }
            continue;
        }
        if (!S_ISREG(st.st_mode) ||
            !compare_mounted_path_matches_selection(config, filter, scope, child_rel)) {
            continue;
        }

        build_compare_key_from_rel_path(child_rel, key, sizeof(key));
        if (key[0] == '\0' ||
            !compare_candidate_list_append(
                list,
                child_rel,
                key,
                (uint64_t)st.st_size,
                "",
                0,
                -1)) {
            closedir(dir);
            return 0;
        }
    }

    closedir(dir);
    return !stop_requested();
}

static int collect_mft_compare_entries(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const Config *config,
    const TargetedRecoveryFilter *filter,
    const CompareScope *scope,
    CompareCandidateList *list
)
{
    size_t i;

    if (items == NULL || config == NULL || filter == NULL || list == NULL) {
        return 0;
    }

    for (i = 0; i < count && !stop_requested(); i++) {
        const RecoveryFormat *format;
        char full_path[PATH_MAX_LEN];
        char rel_path[PATH_MAX_LEN];
        char key[PATH_MAX_LEN];
        const char *users_relative;

        format = mftprobe_format_select_for_entry(config, &items[i]);
        if (format == NULL ||
            !targeted_entry_matches_filter(
                filter,
                format,
                items,
                index,
                count,
                &items[i])) {
            continue;
        }
        if (!build_path_if_under_users_root(
                items,
                index,
                count,
                &items[i],
                full_path,
                sizeof(full_path))) {
            continue;
        }
        users_relative = full_path;
        if (strncmp(users_relative, "\\Users\\", 7U) == 0) {
            users_relative += 7;
        } else if (strcmp(users_relative, "\\Users") == 0) {
            continue;
        } else if (users_relative[0] == '\\') {
            users_relative++;
        }

        snprintf(rel_path, sizeof(rel_path), "%s", users_relative);
        for (char *cursor = rel_path; *cursor != '\0'; cursor++) {
            if (*cursor == '\\') {
                *cursor = '/';
            }
        }
        if (!compare_scope_matches_rel_path(scope, rel_path)) {
            continue;
        }
        build_compare_key_from_rel_path(rel_path, key, sizeof(key));
        if (key[0] == '\0' ||
            !compare_candidate_list_append(
                list,
                rel_path,
                key,
                items[i].data_size,
                items[i].created,
                (items[i].flags & 0x0001U) == 0U,
                items[i].record)) {
            return 0;
        }
    }

    return !stop_requested();
}

static int write_compare_reports(
    const char *out_dir,
    const CompareCandidateList *mft_list,
    const CompareCandidateList *mount_list,
    size_t *matched_out,
    size_t *only_mft_out,
    size_t *only_mount_out,
    size_t *mismatch_out
)
{
    char state_dir[PATH_MAX_LEN];
    char only_mft_path[PATH_MAX_LEN];
    char only_mount_path[PATH_MAX_LEN];
    char mismatch_path[PATH_MAX_LEN];
    FILE *only_mft_file = NULL;
    FILE *only_mount_file = NULL;
    FILE *mismatch_file = NULL;
    size_t mft_pos = 0;
    size_t mount_pos = 0;
    size_t matched = 0;
    size_t only_mft = 0;
    size_t only_mount = 0;
    size_t mismatch = 0;

    if (matched_out != NULL) {
        *matched_out = 0;
    }
    if (only_mft_out != NULL) {
        *only_mft_out = 0;
    }
    if (only_mount_out != NULL) {
        *only_mount_out = 0;
    }
    if (mismatch_out != NULL) {
        *mismatch_out = 0;
    }
    if (out_dir == NULL || mft_list == NULL || mount_list == NULL) {
        return 0;
    }

    if (!ensure_parent_dirs(out_dir) ||
        !ensure_dir(out_dir) ||
        snprintf(state_dir, sizeof(state_dir), "%s/%s", out_dir, APP_STATE_DIR_NAME) >= (int)sizeof(state_dir) ||
        !ensure_dir(state_dir) ||
        snprintf(only_mft_path, sizeof(only_mft_path), "%s/compare_only_in_mft.tsv", state_dir) >= (int)sizeof(only_mft_path) ||
        snprintf(only_mount_path, sizeof(only_mount_path), "%s/compare_only_in_mount.tsv", state_dir) >= (int)sizeof(only_mount_path) ||
        snprintf(mismatch_path, sizeof(mismatch_path), "%s/compare_mismatch.tsv", state_dir) >= (int)sizeof(mismatch_path)) {
        return 0;
    }

    only_mft_file = fopen(only_mft_path, "wb");
    only_mount_file = fopen(only_mount_path, "wb");
    mismatch_file = fopen(mismatch_path, "wb");
    if (only_mft_file == NULL || only_mount_file == NULL || mismatch_file == NULL) {
        if (only_mft_file != NULL) fclose(only_mft_file);
        if (only_mount_file != NULL) fclose(only_mount_file);
        if (mismatch_file != NULL) fclose(mismatch_file);
        return 0;
    }

    fprintf(only_mft_file, "deleted\trecord\tcreated\tsize\trel_path\n");
    fprintf(only_mount_file, "size\trel_path\n");
    fprintf(mismatch_file, "deleted\trecord\tcreated\tmft_size\tmount_size\trel_path\n");

    while (mft_pos < mft_list->count && mount_pos < mount_list->count) {
        const CompareCandidate *mft_item = &mft_list->items[mft_pos];
        const CompareCandidate *mount_item = &mount_list->items[mount_pos];
        int cmp = strcmp(mft_item->compare_key, mount_item->compare_key);

        if (cmp == 0) {
            if (mft_item->size == mount_item->size) {
                matched++;
            } else {
                fprintf(
                    mismatch_file,
                    "%d\t%d\t%s\t%llu\t%llu\t%s\n",
                    mft_item->deleted,
                    mft_item->record,
                    mft_item->created,
                    (unsigned long long)mft_item->size,
                    (unsigned long long)mount_item->size,
                    mft_item->rel_path);
                mismatch++;
            }
            mft_pos++;
            mount_pos++;
            continue;
        }

        if (cmp < 0) {
            fprintf(
                only_mft_file,
                "%d\t%d\t%s\t%llu\t%s\n",
                mft_item->deleted,
                mft_item->record,
                mft_item->created,
                (unsigned long long)mft_item->size,
                mft_item->rel_path);
            only_mft++;
            mft_pos++;
        } else {
            fprintf(
                only_mount_file,
                "%llu\t%s\n",
                (unsigned long long)mount_item->size,
                mount_item->rel_path);
            only_mount++;
            mount_pos++;
        }
    }

    while (mft_pos < mft_list->count) {
        const CompareCandidate *mft_item = &mft_list->items[mft_pos++];

        fprintf(
            only_mft_file,
            "%d\t%d\t%s\t%llu\t%s\n",
            mft_item->deleted,
            mft_item->record,
            mft_item->created,
            (unsigned long long)mft_item->size,
            mft_item->rel_path);
        only_mft++;
    }

    while (mount_pos < mount_list->count) {
        const CompareCandidate *mount_item = &mount_list->items[mount_pos++];

        fprintf(
            only_mount_file,
            "%llu\t%s\n",
            (unsigned long long)mount_item->size,
            mount_item->rel_path);
        only_mount++;
    }

    fclose(only_mft_file);
    fclose(only_mount_file);
    fclose(mismatch_file);

    if (matched_out != NULL) {
        *matched_out = matched;
    }
    if (only_mft_out != NULL) {
        *only_mft_out = only_mft;
    }
    if (only_mount_out != NULL) {
        *only_mount_out = only_mount;
    }
    if (mismatch_out != NULL) {
        *mismatch_out = mismatch;
    }

    log_verbose("Compare reports: %s", only_mft_path);
    log_verbose("Compare reports: %s", only_mount_path);
    log_verbose("Compare reports: %s", mismatch_path);
    return 1;
}

static int write_compare_mount_snapshot(
    const char *out_dir,
    const CompareCandidateList *mount_list
)
{
    char state_dir[PATH_MAX_LEN];
    char snapshot_path[PATH_MAX_LEN];
    FILE *file = NULL;
    size_t i;

    if (out_dir == NULL || out_dir[0] == '\0' || mount_list == NULL) {
        return 0;
    }
    if (!ensure_parent_dirs(out_dir) ||
        !ensure_dir(out_dir) ||
        snprintf(state_dir, sizeof(state_dir), "%s/%s", out_dir, APP_STATE_DIR_NAME) >= (int)sizeof(state_dir) ||
        !ensure_dir(state_dir) ||
        snprintf(snapshot_path, sizeof(snapshot_path), "%s/compare_mount_snapshot.tsv", state_dir) >= (int)sizeof(snapshot_path)) {
        return 0;
    }

    file = fopen(snapshot_path, "wb");
    if (file == NULL) {
        return 0;
    }

    fprintf(file, "size\trel_path\tcompare_key\n");
    for (i = 0; i < mount_list->count; i++) {
        fprintf(
            file,
            "%llu\t%s\t%s\n",
            (unsigned long long)mount_list->items[i].size,
            mount_list->items[i].rel_path,
            mount_list->items[i].compare_key
        );
    }

    fclose(file);
    log_verbose("Compare snapshot: %s", snapshot_path);
    return 1;
}

static void targeted_build_relative_mft_path(
    const MftEntry *entry,
    const RecoveryFormat *format,
    const TargetedRecoveryFilter *filter,
    char *out,
    size_t out_size
)
{
    int created_date = 0;
    const char *root_name = "filtered";

    if (out == NULL || out_size == 0) {
        return;
    }

    out[0] = '\0';
    if (entry == NULL || entry->name[0] == '\0') {
        return;
    }

    if (filter != NULL && filter->has_deleted && filter->deleted_value == 1) {
        root_name = "deleted";
    }
    if (filter != NULL && filter->has_date && format != NULL &&
        (format->category_mask & (RECOVERY_CATEGORY_IMAGE | RECOVERY_CATEGORY_VIDEO)) != 0U) {
        created_date = targeted_filename_to_yyyymmdd_local(entry->name);
    }
    if (created_date == 0) {
        created_date = targeted_filetime_to_yyyymmdd(entry->created_filetime);
    }

    if (created_date != 0) {
        snprintf(out, out_size, "\\%s\\%08d\\%s", root_name, created_date, entry->name);
    } else {
        snprintf(out, out_size, "\\%s\\%s", root_name, entry->name);
    }
}

static int targeted_build_relative_path_from_scope_root(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    const MftEntry *scope_root,
    const char *root_name,
    char *out,
    size_t out_size
)
{
    const MftEntry *chain[256];
    const MftEntry *cur = entry;
    size_t chain_count = 0;
    size_t i;
    int found_scope_root = 0;

    if (out == NULL || out_size == 0U) {
        return 0;
    }
    out[0] = '\0';

    if (items == NULL ||
        index == NULL ||
        entry == NULL ||
        scope_root == NULL ||
        scope_root->name[0] == '\0') {
        return 0;
    }

    while (cur != NULL && chain_count < (sizeof(chain) / sizeof(chain[0]))) {
        chain[chain_count++] = cur;
        if (cur == scope_root ||
            (cur->record == scope_root->record &&
             cur->volume_index == scope_root->volume_index)) {
            found_scope_root = 1;
            break;
        }
        if (cur->record == 5 ||
            cur->parent == (uint64_t)cur->record ||
            cur->parent > (uint64_t)INT32_MAX) {
            break;
        }
        cur = find_entry_by_record_relaxed(
            items,
            index,
            count,
            cur->volume_index,
            cur->family,
            (int)cur->parent
        );
    }

    if (!found_scope_root) {
        return 0;
    }

    snprintf(out, out_size, "\\%s", root_name != NULL ? root_name : "filtered");
    for (i = chain_count; i > 0; i--) {
        const MftEntry *part = chain[i - 1U];
        int is_leaf = (i - 1U) == 0U;

        if (part->record == 5 || part->name[0] == '\0') {
            continue;
        }
        if (!is_leaf && (part->flags & 0x0002U) == 0U) {
            return 0;
        }
        strncat(out, "\\", out_size - strlen(out) - 1U);
        strncat(out, part->name, out_size - strlen(out) - 1U);
    }

    return out[0] != '\0' && strcmp(out, "\\") != 0;
}

static void targeted_build_relative_mft_path_with_folders(
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    const MftEntry *entry,
    const RecoveryFormat *format,
    const TargetedRecoveryFilter *filter,
    int folder_levels,
    char *out,
    size_t out_size
)
{
    const MftEntry *level_one = NULL;
    const MftEntry *level_two = NULL;
    const MftEntry *scope_root = NULL;
    int created_date = 0;
    const char *root_name = "filtered";

    if (out == NULL || out_size == 0) {
        return;
    }

    out[0] = '\0';
    if (entry == NULL || entry->name[0] == '\0') {
        return;
    }
    if (filter != NULL && filter->has_deleted && filter->deleted_value == 1) {
        root_name = "deleted";
    }
    if (filter != NULL && filter->root_scope_count > 0) {
        scope_root = targeted_find_root_child_entry(items, index, count, entry);
    }

    if (scope_root != NULL) {
        if (targeted_build_relative_path_from_scope_root(
                items,
                index,
                count,
                entry,
                scope_root,
                root_name,
                out,
                out_size)) {
            return;
        }
    }

    if (folder_levels > 0 &&
        entry->parent <= (uint64_t)INT32_MAX) {
        level_one = find_entry_by_record_relaxed(
            items,
            index,
            count,
            entry->volume_index,
            entry->family,
            (int)entry->parent
        );
    }
    if (folder_levels > 1 &&
        level_one != NULL &&
        level_one->name[0] != '\0' &&
        level_one->parent <= (uint64_t)INT32_MAX) {
        level_two = find_entry_by_record_relaxed(
            items,
            index,
            count,
            level_one->volume_index,
            level_one->family,
            (int)level_one->parent
        );
        if (level_two != NULL &&
            (level_two->record == 5 || level_two->name[0] == '\0')) {
            level_two = NULL;
        }
    }
    if (level_one != NULL &&
        (level_one->record == 5 || level_one->name[0] == '\0')) {
        level_one = NULL;
    }
    if (scope_root != NULL) {
        if (level_one == scope_root) {
            level_one = NULL;
        }
        if (level_two == scope_root) {
            level_two = NULL;
        }
    }

    if (filter != NULL && filter->has_date && format != NULL &&
        (format->category_mask & (RECOVERY_CATEGORY_IMAGE | RECOVERY_CATEGORY_VIDEO)) != 0U) {
        created_date = targeted_filename_to_yyyymmdd_local(entry->name);
    }
    if (created_date == 0) {
        created_date = targeted_filetime_to_yyyymmdd(entry->created_filetime);
    }
    snprintf(out, out_size, "\\%s", root_name);
    if (scope_root != NULL && scope_root->name[0] != '\0') {
        strncat(out, "\\", out_size - strlen(out) - 1U);
        strncat(out, scope_root->name, out_size - strlen(out) - 1U);
    }
    if (created_date != 0) {
        char date_part[16];

        snprintf(date_part, sizeof(date_part), "%08d", created_date);
        strncat(out, "\\", out_size - strlen(out) - 1U);
        strncat(out, date_part, out_size - strlen(out) - 1U);
    }
    if (level_two != NULL) {
        strncat(out, "\\", out_size - strlen(out) - 1U);
        strncat(out, level_two->name, out_size - strlen(out) - 1U);
    }
    if (level_one != NULL) {
        strncat(out, "\\", out_size - strlen(out) - 1U);
        strncat(out, level_one->name, out_size - strlen(out) - 1U);
    }
    strncat(out, "\\", out_size - strlen(out) - 1U);
    strncat(out, entry->name, out_size - strlen(out) - 1U);

}

static void targeted_append_record_suffix(
    char *path,
    size_t path_size,
    int record,
    unsigned int suffix
)
{
    char original[PATH_MAX_LEN];
    char *slash;
    char *dot;
    char file_name[NAME_MAX_LEN];
    char directory[PATH_MAX_LEN];
    char stem[NAME_MAX_LEN];
    char extension[FORMAT_EXTENSION_MAX];
    char suffix_text[64];
    size_t used = 0U;
    size_t stem_length = 0U;
    size_t extension_length = 0U;

    if (path == NULL || path_size == 0) {
        return;
    }

    snprintf(original, sizeof(original), "%s", path);
    slash = strrchr(original, '/');
    snprintf(suffix_text, sizeof(suffix_text), "_r%d_%u", record, suffix);
    if (slash == NULL) {
        size_t original_length = strnlen(original, sizeof(original));
        size_t suffix_length = strnlen(suffix_text, sizeof(suffix_text));
        size_t keep = 0U;

        if (path_size > suffix_length + 1U) {
            keep = path_size - suffix_length - 1U;
            if (keep > original_length) {
                keep = original_length;
            }
        }
        if (keep > 0U) {
            memcpy(path, original, keep);
        }
        path[keep] = '\0';
        strncat(path, suffix_text, path_size - keep - 1U);
        return;
    }

    *slash = '\0';
    snprintf(directory, sizeof(directory), "%s", original);
    snprintf(file_name, sizeof(file_name), "%s", slash + 1);
    dot = strrchr(file_name, '.');
    if (dot != NULL) {
        snprintf(extension, sizeof(extension), "%s", dot);
        *dot = '\0';
    } else {
        extension[0] = '\0';
    }
    snprintf(stem, sizeof(stem), "%s", file_name);
    path[0] = '\0';
    used = strnlen(directory, sizeof(directory));
    if (used >= path_size) {
        used = path_size - 1U;
    }
    if (used > 0U) {
        memcpy(path, directory, used);
        path[used] = '\0';
    }
    if (used + 1U < path_size) {
        path[used++] = '/';
        path[used] = '\0';
    }

    extension_length = strnlen(extension, sizeof(extension));
    stem_length = strnlen(stem, sizeof(stem));
    if (used < path_size - 1U) {
        size_t reserve = strnlen(suffix_text, sizeof(suffix_text)) + extension_length;
        size_t available_for_stem = path_size - used - 1U;

        if (reserve < available_for_stem) {
            available_for_stem -= reserve;
        } else {
            available_for_stem = 0U;
        }
        if (stem_length > available_for_stem) {
            stem_length = available_for_stem;
        }
        if (stem_length > 0U) {
            memcpy(path + used, stem, stem_length);
            used += stem_length;
            path[used] = '\0';
        }
    }

    if (used < path_size - 1U) {
        strncat(path, suffix_text, path_size - used - 1U);
        used = strnlen(path, path_size);
    }
    if (used < path_size - 1U && extension_length > 0U) {
        strncat(path, extension, path_size - used - 1U);
    }
}

static void targeted_ensure_unique_output_path(char *path, size_t path_size, int record)
{
    struct stat st;
    unsigned int suffix = 1;

    if (path == NULL || path[0] == '\0') {
        return;
    }

    while (stat(path, &st) == 0) {
        targeted_append_record_suffix(path, path_size, record, suffix);
        suffix++;
    }
}

static int targeted_prepare_recovery_target(
    RecoveryTarget *target,
    const Config *config,
    const RecoveryFormat *format,
    const MftEntry *entry,
    const char *mft_path
)
{
    RecoveryRun runs[RECOVERY_TARGET_MAX_RUNS];
    uint64_t available_bytes;
    uint64_t target_size;
    size_t run_count = 0;
    int run_truncated = 0;
    int partial_target = 0;

    if (target == NULL || config == NULL || format == NULL || entry == NULL || mft_path == NULL ||
        entry->data_size == 0) {
        return 0;
    }

    if (!recovery_runs_from_entry(config, entry, runs, &run_count, &run_truncated)) {
        return 0;
    }
    if (!recovery_runs_within_source(config, runs, run_count)) {
        return 0;
    }

    available_bytes = mft_run_available_bytes(config, entry);
    target_size = entry->data_size;
    if (run_truncated || available_bytes < entry->data_size) {
        if (!mftprobe_format_allows_partial_target(format, available_bytes)) {
            return 0;
        }
        target_size = available_bytes;
        partial_target = 1;
    }

    memset(target, 0, sizeof(*target));
    target->format_id = format->format_id;
    target->validator_id = format->validator_id;
    snprintf(target->extension, sizeof(target->extension), "%s", format->default_extension);
    memcpy(target->blob_start, format->blob_start, sizeof(target->blob_start));
    target->blob_start_length = format->blob_start_length;
    target->abs_offset = mft_data_offset_for_entry(config, entry);
    target->size = target_size;
    target->expected_size = entry->data_size;
    target->remaining = target_size;
    target->next_offset = target->abs_offset;
    memcpy(target->runs, runs, run_count * sizeof(*runs));
    target->run_count = run_count;
    target->run_index = 0;
    target->run_truncated = run_truncated;
    target->record = entry->record;
    target->family = entry->family;
    target->state = TARGET_PENDING;
    snprintf(target->source_path, sizeof(target->source_path), "%s", mft_path);
    recovery_output_path_from_mft_path(
        target->output_path,
        sizeof(target->output_path),
        config->out_dir,
        mft_path
    );
    if (partial_target &&
        !append_partial_suffix(target->output_path, sizeof(target->output_path))) {
        return 0;
    }

    if (!path_has_size(target->output_path, target->size)) {
        targeted_ensure_unique_output_path(
            target->output_path,
            sizeof(target->output_path),
            entry->record
        );
    }
    return target->output_path[0] != '\0' && target->abs_offset > 0;
}

static int MFTPROBE_MAYBE_UNUSED targeted_recover_from_primary_mft(
    FILE *file,
    int image_fd,
    unsigned char *buffer,
    const Config *config,
    const TargetedRecoveryFilter *filter,
    const RecordList *record_list,
    TargetedRecoveryStats *stats,
    uint64_t *out_scanned_bytes,
    size_t *out_entries,
    size_t *out_matched,
    size_t *out_recovered,
    size_t *out_skipped
)
{
    const uint64_t progress_step = 4ULL * 1024ULL * 1024ULL;
    unsigned char record[RECORD_SIZE];
    MftProbeEntry probe;
    unsigned char *chunk_buffer = NULL;
    MftEntry mft_entry;
    MftEntry entry;
    RecoveryRun mft_runs[RECOVERY_TARGET_MAX_RUNS];
    char filter_relative_path[PATH_MAX_LEN];
    size_t mft_run_count = 0;
    int mft_run_truncated = 0;
    uint64_t mft_file_bytes = 0;
    uint64_t bytes_scanned = 0;
    uint64_t last_progress_bytes = 0;
    uint64_t scan_limit;
    size_t run_index;
    uint32_t record_size;

    if (out_scanned_bytes != NULL) {
        *out_scanned_bytes = 0;
    }
    if (out_entries != NULL) {
        *out_entries = 0;
    }
    if (out_matched != NULL) {
        *out_matched = 0;
    }
    if (out_recovered != NULL) {
        *out_recovered = 0;
    }
    if (out_skipped != NULL) {
        *out_skipped = 0;
    }
    if (file == NULL || image_fd < 0 || buffer == NULL || config == NULL || filter == NULL || !config->ntfs.valid) {
        return 0;
    }

    record_size = config->ntfs.mft_record_size;
    if (record_size == 0) {
        record_size = RECORD_SIZE;
    }
    if (record_size != RECORD_SIZE) {
        log_error(
            "Targeted MFT recovery currently expects 1024-byte MFT records, not %u",
            record_size
        );
        return 0;
    }

    if (!read_exact_at(file, config->ntfs.mft_abs_offset, record, sizeof(record)) ||
        !mft_probe_parse_record(record, config->ntfs.mft_abs_offset, &probe)) {
        log_error("Failed to parse primary $MFT record");
        return 0;
    }
    copy_probe_to_entry(&probe, &mft_entry);
    mft_entry.family = 0;
    assign_entry_volume(config, &mft_entry);
    if (!recovery_runs_from_entry(config, &mft_entry, mft_runs, &mft_run_count, &mft_run_truncated)) {
        log_error("Failed to resolve primary $MFT runlist");
        return 0;
    }

    mft_file_bytes = mft_entry.data_size;
    scan_limit = mft_file_bytes;
    if (config->limit > 0 && config->limit < scan_limit) {
        scan_limit = config->limit;
    }
    if (scan_limit == 0) {
        scan_limit = mft_file_bytes;
    }

    chunk_buffer = (unsigned char *)malloc(MFT_SCAN_CHUNK_BYTES);
    if (chunk_buffer == NULL) {
        return 0;
    }

    log_set_working_progress(0, scan_limit);
    log_set_working_speed_base(0);
    log_set_working_activity("targeted MFT scan");

    for (run_index = 0; run_index < mft_run_count && !stop_requested() && bytes_scanned < scan_limit; run_index++) {
        uint64_t run_offset = mft_runs[run_index].abs_offset;
        uint64_t run_length = mft_runs[run_index].byte_length;
        uint64_t run_pos = 0;

        while (run_pos + RECORD_SIZE <= run_length &&
               bytes_scanned + RECORD_SIZE <= scan_limit &&
               !stop_requested()) {
            size_t chunk_want;
            size_t chunk_got;
            size_t chunk_pos;
            uint64_t chunk_logical_record_base;

            chunk_want = (size_t)(run_length - run_pos);
            if (chunk_want > (size_t)(scan_limit - bytes_scanned)) {
                chunk_want = (size_t)(scan_limit - bytes_scanned);
            }
            if (chunk_want > MFT_SCAN_CHUNK_BYTES) {
                chunk_want = MFT_SCAN_CHUNK_BYTES;
            }
            chunk_want -= chunk_want % RECORD_SIZE;
            if (chunk_want < RECORD_SIZE) {
                break;
            }

            chunk_got = read_chunk_at_fd(
                image_fd,
                run_offset + run_pos,
                chunk_buffer,
                chunk_want
            );
            chunk_got -= chunk_got % RECORD_SIZE;
            if (chunk_got < RECORD_SIZE) {
                break;
            }

            chunk_logical_record_base = bytes_scanned / RECORD_SIZE;

            for (chunk_pos = 0; chunk_pos + RECORD_SIZE <= chunk_got && !stop_requested(); chunk_pos += RECORD_SIZE) {
                uint64_t record_offset = run_offset + run_pos + chunk_pos;
                uint64_t logical_record = chunk_logical_record_base + (chunk_pos / RECORD_SIZE);

                memcpy(record, chunk_buffer + chunk_pos, RECORD_SIZE);
                memset(&probe, 0, sizeof(probe));
                if (mft_probe_parse_record_any(record, record_offset, &probe)) {
                    RecoveryTarget target;
                    const RecoveryFormat *format;

                    copy_probe_to_entry(&probe, &entry);
                    assign_primary_mft_logical_identity(config, &entry, logical_record);
                    if (out_entries != NULL) {
                        (*out_entries)++;
                    }

                    format = mftprobe_format_select_for_entry(config, &entry);
                    if (format != NULL &&
                        (record_list == NULL || record_list_contains(record_list, entry.record)) &&
                        targeted_entry_matches_filter(
                            filter,
                            format,
                            NULL,
                            NULL,
                            0,
                            &entry)) {
                        if (out_matched != NULL) {
                            (*out_matched)++;
                        }

                        targeted_build_relative_mft_path(
                            &entry,
                            format,
                            filter,
                            filter_relative_path,
                            sizeof(filter_relative_path)
                        );
                        if (!targeted_prepare_recovery_target(
                                &target,
                                config,
                                format,
                                &entry,
                                filter_relative_path)) {
                            if (out_skipped != NULL) {
                                (*out_skipped)++;
                            }
                            if (stats != NULL) {
                                stats->skipped_invalid_target++;
                            }
                        } else if ((format->category_mask & RECOVERY_CATEGORY_IMAGE) != 0U &&
                                   recovery_runner_target_should_skip_image_fd(
                                       image_fd,
                                       &target,
                                       buffer,
                                       READ_SIZE)) {
                            if (out_skipped != NULL) {
                                (*out_skipped)++;
                            }
                            if (stats != NULL) {
                                stats->skipped_image_filter++;
                            }
                        } else if (path_has_size(target.output_path, target.size)) {
                            mft_note_recovered_output(
                                target.output_path,
                                (long long)target.abs_offset
                            );
                            if (out_recovered != NULL) {
                                (*out_recovered)++;
                            }
                        } else if (direct_recover_target(image_fd, &target, buffer)) {
                            mft_note_recovered_output(
                                target.output_path,
                                (long long)target.abs_offset
                            );
                            if (out_recovered != NULL) {
                                (*out_recovered)++;
                            }
                            if (recovery_target_is_partial(&target)) {
                                log_verbose(
                                    "Targeted partial recovery succeeded: created=%s path=%s",
                                    entry.created,
                                    target.output_path
                                );
                            } else {
                                log_verbose(
                                    "Targeted recovery succeeded: created=%s path=%s",
                                    entry.created,
                                    target.output_path
                                );
                            }
                        } else {
                            targeted_stats_note_failure(stats, target.last_error);
                            log_verbose(
                                "Targeted recovery failed: created=%s name=%s class=%s reason=%s",
                                entry.created,
                                entry.name,
                                recovery_runner_failure_class(target.last_error),
                                target.last_error
                            );
                        }
                    }
                }

                bytes_scanned += RECORD_SIZE;
                if (bytes_scanned - last_progress_bytes >= progress_step) {
                    log_set_working_progress(bytes_scanned, scan_limit);
                    last_progress_bytes = bytes_scanned;
                }
            }
            run_pos += chunk_got;
        }
        if (bytes_scanned != last_progress_bytes) {
            log_set_working_progress(bytes_scanned, scan_limit);
            last_progress_bytes = bytes_scanned;
        }
    }

    log_set_working_progress(bytes_scanned, scan_limit);
    free(chunk_buffer);
    if (out_scanned_bytes != NULL) {
        *out_scanned_bytes = bytes_scanned;
    }
    return 1;
}

static int build_primary_mft_scan_context(
    FILE *file,
    const Config *config,
    const NtfsGeometry *geometry,
    PrimaryMftScanContext *out
)
{
    unsigned char record[RECORD_SIZE];
    MftProbeEntry probe;
    MftEntry mft_entry;
    uint32_t record_size;
    int primary_seed_ok;

    if (out == NULL) {
        return 0;
    }
    memset(out, 0, sizeof(*out));

    if (file == NULL || config == NULL || geometry == NULL || !geometry->valid) {
        return 0;
    }

    record_size = geometry->mft_record_size;
    if (record_size == 0) {
        record_size = RECORD_SIZE;
    }
    if (record_size != RECORD_SIZE) {
        return 0;
    }

    primary_seed_ok =
        (config->coverage_map == NULL ||
         ddrescue_map_range_is_finished(
             config->coverage_map,
             geometry->mft_abs_offset,
             sizeof(record))) &&
        read_exact_at(file, geometry->mft_abs_offset, record, sizeof(record)) &&
        mft_probe_parse_record(record, geometry->mft_abs_offset, &probe);
    if (!primary_seed_ok) {
        if (geometry->mft_mirror_abs_offset == geometry->mft_abs_offset ||
            (config->coverage_map != NULL &&
             !ddrescue_map_range_is_finished(
                 config->coverage_map,
                 geometry->mft_mirror_abs_offset,
                 sizeof(record))) ||
            !read_exact_at(
                file,
                geometry->mft_mirror_abs_offset,
                record,
                sizeof(record)) ||
            !mft_probe_parse_record(
                record,
                geometry->mft_mirror_abs_offset,
                &probe)) {
            return 0;
        }
        log_info(
            "Primary NTFS $MFT record 0 is unavailable; using $MFTMirr record 0 for the MFT runlist"
        );
    }

    copy_probe_to_entry(&probe, &mft_entry);
    mft_entry.family = 0;
    assign_entry_volume(config, &mft_entry);
    if (!recovery_runs_from_entry(
            config,
            &mft_entry,
            out->runs,
            &out->run_count,
            &out->run_truncated)) {
        return 0;
    }

    out->geometry = geometry;
    out->mft_file_bytes = mft_entry.data_size;
    out->scan_limit = out->mft_file_bytes;
    if (out->scan_limit == 0) {
        out->scan_limit = out->mft_file_bytes;
    }

    return out->run_count > 0 && out->scan_limit > 0;
}

static int collect_primary_mft_entries_from_context(
    int image_fd,
    const Config *config,
    const PrimaryMftScanContext *context,
    MftTable *table,
    MftTable *extent_table,
    RootScopePrunedSet *pruned_set,
    unsigned char *chunk_buffer,
    uint64_t total_scan_limit,
    uint64_t *inout_bytes_scanned,
    uint64_t *inout_last_progress_bytes
)
{
    const uint64_t progress_step = 4ULL * 1024ULL * 1024ULL;
    unsigned char record[RECORD_SIZE];
    MftProbeEntry probe;
    MftEntry entry;
    uint64_t bytes_scanned;
    uint64_t last_progress_bytes;
    size_t run_index;

    if (image_fd < 0 ||
        config == NULL ||
        context == NULL ||
        table == NULL ||
        extent_table == NULL ||
        chunk_buffer == NULL ||
        inout_bytes_scanned == NULL ||
        inout_last_progress_bytes == NULL) {
        return 0;
    }

    bytes_scanned = *inout_bytes_scanned;
    last_progress_bytes = *inout_last_progress_bytes;

    for (run_index = 0;
         run_index < context->run_count &&
         !stop_requested() &&
         bytes_scanned < total_scan_limit;
         run_index++) {
        uint64_t run_offset = context->runs[run_index].abs_offset;
        uint64_t run_length = context->runs[run_index].byte_length;
        uint64_t run_pos = 0;
        uint64_t context_scanned = 0;

        while (run_pos + RECORD_SIZE <= run_length &&
               context_scanned + RECORD_SIZE <= context->scan_limit &&
               bytes_scanned + RECORD_SIZE <= total_scan_limit &&
               !stop_requested()) {
            size_t chunk_want;
            size_t chunk_got;
            size_t chunk_pos;
            uint64_t chunk_logical_record_base;

            if (config->coverage_map != NULL &&
                !ddrescue_map_range_is_finished(
                    config->coverage_map,
                    run_offset + run_pos,
                    RECORD_SIZE)) {
                run_pos += RECORD_SIZE;
                bytes_scanned += RECORD_SIZE;
                context_scanned += RECORD_SIZE;
                continue;
            }

            chunk_want = (size_t)(run_length - run_pos);
            if (chunk_want > (size_t)(context->scan_limit - context_scanned)) {
                chunk_want = (size_t)(context->scan_limit - context_scanned);
            }
            if (chunk_want > (size_t)(total_scan_limit - bytes_scanned)) {
                chunk_want = (size_t)(total_scan_limit - bytes_scanned);
            }
            if (chunk_want > MFT_SCAN_CHUNK_BYTES) {
                chunk_want = MFT_SCAN_CHUNK_BYTES;
            }
            if (config->coverage_map != NULL) {
                char map_status = '?';
                uint64_t map_end = 0U;

                if (!ddrescue_map_status_span(
                        config->coverage_map,
                        run_offset + run_pos,
                        &map_status,
                        &map_end) ||
                    map_status != '+' ||
                    map_end <= run_offset + run_pos) {
                    run_pos += RECORD_SIZE;
                    bytes_scanned += RECORD_SIZE;
                    context_scanned += RECORD_SIZE;
                    continue;
                }
                if (map_end - (run_offset + run_pos) < chunk_want) {
                    chunk_want = (size_t)(map_end - (run_offset + run_pos));
                }
            }
            chunk_want -= chunk_want % RECORD_SIZE;
            if (chunk_want < RECORD_SIZE) {
                break;
            }

            chunk_got = read_chunk_at_fd(
                image_fd,
                run_offset + run_pos,
                chunk_buffer,
                chunk_want
            );
            chunk_got -= chunk_got % RECORD_SIZE;
            if (chunk_got < RECORD_SIZE) {
                break;
            }

            chunk_logical_record_base = context_scanned / RECORD_SIZE;

            for (chunk_pos = 0;
                 chunk_pos + RECORD_SIZE <= chunk_got && !stop_requested();
                 chunk_pos += RECORD_SIZE) {
                uint64_t record_offset = run_offset + run_pos + chunk_pos;
                uint64_t logical_record = chunk_logical_record_base + (chunk_pos / RECORD_SIZE);

                memcpy(record, chunk_buffer + chunk_pos, RECORD_SIZE);
                memset(&probe, 0, sizeof(probe));
                if (mft_probe_parse_record_any(record, record_offset, &probe)) {
                    copy_probe_to_entry(&probe, &entry);
                    assign_primary_mft_logical_identity(config, &entry, logical_record);

                    if (entry.name[0] != '\0' &&
                        !root_scope_prune_entry_for_live_scan(config, &entry, pruned_set) &&
                        !table_append(table, &entry)) {
                        return 0;
                    }
                    if (entry.name[0] != '\0' &&
                        !root_scope_prune_entry_for_live_scan(config, &entry, pruned_set) &&
                        entry.has_data &&
                        entry.base_record_ref != 0 &&
                        entry.base_record_ref != (uint64_t)(uint32_t)entry.record &&
                        !table_append(extent_table, &entry)) {
                        return 0;
                    }
                }

                bytes_scanned += RECORD_SIZE;
                context_scanned += RECORD_SIZE;
                if (bytes_scanned - last_progress_bytes >= progress_step) {
                    log_set_working_progress(bytes_scanned, total_scan_limit);
                    last_progress_bytes = bytes_scanned;
                }
            }
            run_pos += chunk_got;
        }

        if (bytes_scanned != last_progress_bytes) {
            log_set_working_progress(bytes_scanned, total_scan_limit);
            last_progress_bytes = bytes_scanned;
        }
    }

    *inout_bytes_scanned = bytes_scanned;
    *inout_last_progress_bytes = last_progress_bytes;
    return 1;
}

static int collect_primary_mft_entries(
    FILE *file,
    int image_fd,
    const Config *config,
    MftTable *table,
    uint64_t *out_scanned_bytes
)
{
    PrimaryMftScanContext contexts[MAX_NTFS_VOLUMES];
    unsigned char *chunk_buffer = NULL;
    MftTable extent_table = {0};
    RecordIndex *record_index = NULL;
    RootScopePrunedSet pruned_set = {0};
    uint64_t total_scan_limit = 0;
    uint64_t bytes_scanned = 0;
    uint64_t last_progress_bytes = 0;
    size_t context_count = 0;
    size_t geometry_count = 0;
    size_t i;

    if (out_scanned_bytes != NULL) {
        *out_scanned_bytes = 0;
    }
    if (file == NULL || image_fd < 0 || config == NULL || table == NULL) {
        return 0;
    }

    if (config->ntfs_volume_count > 0) {
        geometry_count = config->ntfs_volume_count;
    } else if (config->ntfs.valid) {
        geometry_count = 1;
    } else {
        return 0;
    }

    memset(contexts, 0, sizeof(contexts));
    for (i = 0; i < geometry_count && context_count < MAX_NTFS_VOLUMES; i++) {
        const NtfsGeometry *geometry =
            config->ntfs_volume_count > 0 ? &config->ntfs_volumes[i] : &config->ntfs;

        if (!build_primary_mft_scan_context(file, config, geometry, &contexts[context_count])) {
            continue;
        }

        total_scan_limit += contexts[context_count].scan_limit;
        context_count++;
    }

    if (context_count == 0 || total_scan_limit == 0) {
        return 0;
    }
    if (config->limit > 0 && config->limit < total_scan_limit) {
        total_scan_limit = config->limit;
    }

    chunk_buffer = (unsigned char *)malloc(MFT_SCAN_CHUNK_BYTES);
    if (chunk_buffer == NULL) {
        return 0;
    }

    log_set_working_progress(0, total_scan_limit);
    log_set_working_speed_base(0);
    log_set_working_activity(context_count > 1 ? "scanning primary $MFTs" : "scanning primary $MFT");

    for (i = 0; i < context_count && !stop_requested(); i++) {
        if (!collect_primary_mft_entries_from_context(
                image_fd,
                config,
                &contexts[i],
                table,
                &extent_table,
                &pruned_set,
                chunk_buffer,
                total_scan_limit,
                &bytes_scanned,
                &last_progress_bytes)) {
            free(chunk_buffer);
            table_reset(&extent_table);
            root_scope_pruned_set_destroy(&pruned_set);
            return 0;
        }
    }

    if (extent_table.count > 0 && table->count > 0) {
        size_t extent_index;

        if (!table_ensure_record_index(table)) {
            free(chunk_buffer);
            table_reset(&extent_table);
            root_scope_pruned_set_destroy(&pruned_set);
            return 0;
        }
        record_index = table->record_index;

        qsort(
            extent_table.items,
            extent_table.count,
            sizeof(*extent_table.items),
            compare_extent_record_for_merge
        );

        for (extent_index = 0; extent_index < extent_table.count; extent_index++) {
            MftEntry *base_entry;
            const MftEntry *extent = &extent_table.items[extent_index];

            if (extent->base_record_ref > (uint64_t)INT32_MAX) {
                continue;
            }

            base_entry = (MftEntry *)find_entry_by_record(
                table->items,
                record_index,
                table->count,
                extent->volume_index,
                extent->family,
                (int)extent->base_record_ref
            );
            if (base_entry == NULL) {
                continue;
            }

            merge_extent_record_into_entry(base_entry, extent);
        }
    }

    table_reset(&extent_table);
    free(chunk_buffer);
    root_scope_pruned_set_destroy(&pruned_set);
    log_set_working_progress(bytes_scanned, total_scan_limit);
    if (out_scanned_bytes != NULL) {
        *out_scanned_bytes = bytes_scanned;
    }
    return 1;
}

static int collect_primary_mft_entries_resolving_folder_terms(
    FILE *file,
    int image_fd,
    Config *config,
    MftTable *table,
    uint64_t *out_scanned_bytes,
    int *out_folder_search_failed
)
{
    Config requested_config;
    Config unscoped_config;

    if (out_folder_search_failed != NULL) {
        *out_folder_search_failed = 0;
    }
    if (config == NULL) {
        return 0;
    }
    requested_config = *config;
    (void)load_root_scope_resolution_state(config);

    if (!collect_primary_mft_entries(
            file,
            image_fd,
            config,
            table,
            out_scanned_bytes)) {
        return 0;
    }
    if (config->root_scope_count == 0U ||
        config_root_scopes_are_all_exact_in_table(config, table)) {
        if (requested_config.root_scope_count > 0U &&
            !write_root_scope_resolution_state(&requested_config, config)) {
            log_verbose("Folder search could not save resolved --fold state");
        }
        return 1;
    }

    /*
     * The fast first pass deliberately keeps only exact root/path branches.
     * If a term was not exact, read the MFT once without early pruning, turn
     * the term into exact paths, then shrink the in-memory table again.
     */
    log_info(
        "No exact directory existed for at least one --fold term; searching folder names in the primary $MFT"
    );
    table_reset(table);
    unscoped_config = *config;
    unscoped_config.root_scope_count = 0U;
    if (!collect_primary_mft_entries(
            file,
            image_fd,
            &unscoped_config,
            table,
            out_scanned_bytes) ||
        !config_resolve_partial_root_scopes_from_table(config, table)) {
        if (out_folder_search_failed != NULL && !stop_requested()) {
            *out_folder_search_failed = 1;
        }
        return 0;
    }
    if (!prune_loaded_table_to_selected_root_scope(config, table)) {
        return 0;
    }
    if (!write_root_scope_resolution_state(&requested_config, config)) {
        log_verbose("Folder search could not save resolved --fold state");
    }

    return 1;
}

static int root_folder_name_order(const void *left, const void *right)
{
    const char *const *a = (const char *const *)left;
    const char *const *b = (const char *const *)right;

    return strcasecmp(*a, *b);
}

static int preview_folder_name_is_ignored(const char *name)
{
    return name == NULL ||
           name[0] == '\0' ||
           strcmp(name, ".") == 0 ||
           strcmp(name, "..") == 0 ||
           strcasecmp(name, "$Extend") == 0;
}

static int preview_folder_name_already_seen(
    char **names,
    size_t name_count,
    const char *name
)
{
    size_t i;

    if (name == NULL || name[0] == '\0') {
        return 1;
    }
    for (i = 0U; i < name_count; i++) {
        if (strcasecmp(names[i], name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int preview_append_folder_name(
    char ***names,
    size_t *name_count,
    const char *name
)
{
    char **expanded;

    if (names == NULL ||
        name_count == NULL ||
        name == NULL ||
        name[0] == '\0') {
        return 0;
    }

    expanded = (char **)realloc(
        *names,
        (*name_count + 1U) * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }
    *names = expanded;
    (*names)[*name_count] = strdup(name);
    if ((*names)[*name_count] == NULL) {
        return 0;
    }
    (*name_count)++;
    return 1;
}

typedef struct PreviewI30FolderContext {
    char ***names;
    size_t *name_count;
    int failed;
} PreviewI30FolderContext;

static int preview_append_i30_child_folder_name(
    const MftProbeI30Child *child,
    void *user_data
)
{
    PreviewI30FolderContext *context = (PreviewI30FolderContext *)user_data;

    if (child == NULL || context == NULL ||
        context->names == NULL || context->name_count == NULL) {
        return 0;
    }
    if ((child->file_attributes & NTFS_FILE_ATTRIBUTE_DIRECTORY) == 0U ||
        preview_folder_name_is_ignored(child->name) ||
        preview_folder_name_already_seen(
            *context->names,
            *context->name_count,
            child->name)) {
        return 1;
    }
    if (!preview_append_folder_name(
            context->names,
            context->name_count,
            child->name)) {
        context->failed = 1;
        return 0;
    }
    return 1;
}

static int read_primary_mft_logical_record_from_context(
    int image_fd,
    const PrimaryMftScanContext *context,
    const DdrescueMap *coverage_map,
    uint64_t logical_record,
    unsigned char *record,
    uint64_t *out_abs_offset
)
{
    uint64_t target_stream_offset;
    uint64_t logical_base = 0U;
    uint64_t copied = 0U;
    size_t run_index;

    if (out_abs_offset != NULL) {
        *out_abs_offset = 0U;
    }
    if (image_fd < 0 || context == NULL || record == NULL ||
        logical_record > UINT64_MAX / RECORD_SIZE) {
        return 0;
    }

    target_stream_offset = logical_record * (uint64_t)RECORD_SIZE;
    for (run_index = 0U;
         run_index < context->run_count && copied < RECORD_SIZE;
         run_index++) {
        const RecoveryRun *run = &context->runs[run_index];
        uint64_t run_available;
        uint64_t in_run_offset;
        uint64_t want;
        size_t got;

        if (run->byte_length == 0U) {
            continue;
        }
        {
            uint64_t run_logical_end =
                logical_base > UINT64_MAX - run->byte_length
                    ? UINT64_MAX
                    : logical_base + run->byte_length;
            if (target_stream_offset >= run_logical_end) {
                logical_base = run_logical_end;
                continue;
            }
        }

        if (target_stream_offset < logical_base) {
            return 0;
        }

        in_run_offset = target_stream_offset - logical_base;
        if (in_run_offset >= run->byte_length) {
            logical_base += run->byte_length;
            continue;
        }

        run_available = run->byte_length - in_run_offset;
        want = (uint64_t)RECORD_SIZE - copied;
        if (want > run_available) {
            want = run_available;
        }
        if (want == 0U || want > SIZE_MAX) {
            return 0;
        }
        if (coverage_map != NULL &&
            !ddrescue_map_range_is_finished(
                coverage_map,
                run->abs_offset + in_run_offset,
                want)) {
            return 0;
        }
        got = read_chunk_at_fd(
            image_fd,
            run->abs_offset + in_run_offset,
            record + copied,
            (size_t)want
        );
        if (got != (size_t)want) {
            return 0;
        }
        if (copied == 0U && out_abs_offset != NULL) {
            *out_abs_offset = run->abs_offset + in_run_offset;
        }
        copied += want;
        target_stream_offset += want;
        logical_base += run->byte_length;
    }

    return copied == RECORD_SIZE;
}

static int preview_visit_i30_allocation_runs(
    int image_fd,
    const NtfsGeometry *geometry,
    const MftProbeEntry *root_probe,
    const DdrescueMap *coverage_map,
    PreviewI30FolderContext *visitor_context,
    size_t *out_blocks_seen
)
{
    unsigned char *block = NULL;
    uint32_t block_size;
    size_t run_index;
    size_t blocks_seen = 0U;
    int ok = 1;

    if (out_blocks_seen != NULL) {
        *out_blocks_seen = 0U;
    }
    if (image_fd < 0 || geometry == NULL || root_probe == NULL ||
        visitor_context == NULL ||
        !root_probe->has_i30_allocation ||
        root_probe->i30_stored_run_count == 0U ||
        geometry->cluster_size == 0U) {
        return 1;
    }

    block_size = root_probe->i30_index_block_size;
    if (block_size < 512U || block_size > 65536U) {
        block_size = 4096U;
    }
    block = (unsigned char *)malloc(block_size);
    if (block == NULL) {
        return 0;
    }

    for (run_index = 0U;
         run_index < root_probe->i30_stored_run_count &&
         !stop_requested() &&
         !visitor_context->failed;
         run_index++) {
        const MftDataRun *run = &root_probe->i30_runs[run_index];
        uint64_t run_abs_offset;
        uint64_t run_byte_length;
        uint64_t run_pos;

        if (run->lcn == 0U || run->clusters == 0U ||
            run->clusters > UINT64_MAX / geometry->cluster_size ||
            run->lcn > (UINT64_MAX - geometry->volume_offset) / geometry->cluster_size) {
            continue;
        }

        run_abs_offset = geometry->volume_offset + run->lcn * geometry->cluster_size;
        run_byte_length = run->clusters * geometry->cluster_size;
        for (run_pos = 0U;
             run_pos + block_size <= run_byte_length &&
             !stop_requested() &&
             !visitor_context->failed;
             run_pos += block_size) {
            size_t got;
            int truncated = 0;

            if (coverage_map != NULL &&
                !ddrescue_map_range_is_finished(
                    coverage_map,
                    run_abs_offset + run_pos,
                    block_size)) {
                ok = 0;
                break;
            }
            got = read_chunk_at_fd(
                image_fd,
                run_abs_offset + run_pos,
                block,
                (size_t)block_size
            );
            if (got != (size_t)block_size) {
                ok = 0;
                break;
            }
            if (mft_probe_visit_i30_index_block_children(
                    block,
                    block_size,
                    preview_append_i30_child_folder_name,
                    visitor_context,
                    &truncated) > 0U) {
                blocks_seen++;
            }
            if (truncated) {
                ok = 0;
                break;
            }
        }
    }

    if (out_blocks_seen != NULL) {
        *out_blocks_seen = blocks_seen;
    }
    free(block);
    return ok && !visitor_context->failed;
}

static int preview_collect_root_folders_from_i30(
    FILE *file,
    int image_fd,
    const Config *config,
    char ***names,
    size_t *name_count
)
{
    PrimaryMftScanContext contexts[MAX_NTFS_VOLUMES];
    PreviewI30FolderContext visitor_context;
    unsigned char record[RECORD_SIZE];
    size_t context_count = 0U;
    size_t geometry_count = 0U;
    size_t parsed_roots = 0U;
    size_t i;

    if (file == NULL || image_fd < 0 || config == NULL ||
        names == NULL || name_count == NULL) {
        return 0;
    }

    if (config->ntfs_volume_count > 0) {
        geometry_count = config->ntfs_volume_count;
    } else if (config->ntfs.valid) {
        geometry_count = 1U;
    } else {
        return 0;
    }

    memset(contexts, 0, sizeof(contexts));
    for (i = 0U; i < geometry_count && context_count < MAX_NTFS_VOLUMES; i++) {
        const NtfsGeometry *geometry =
            config->ntfs_volume_count > 0 ? &config->ntfs_volumes[i] : &config->ntfs;

        if (build_primary_mft_scan_context(file, config, geometry, &contexts[context_count])) {
            context_count++;
        }
    }
    if (context_count == 0U) {
        return 0;
    }

    visitor_context.names = names;
    visitor_context.name_count = name_count;
    visitor_context.failed = 0;

    for (i = 0U; i < context_count && !stop_requested() && !visitor_context.failed; i++) {
        MftProbeEntry root_probe;
        uint64_t root_abs_offset = 0U;
        size_t child_index;
        size_t blocks_seen = 0U;

        if (!read_primary_mft_logical_record_from_context(
                image_fd,
                &contexts[i],
                config->coverage_map,
                5U,
                record,
                &root_abs_offset)) {
            continue;
        }
        memset(&root_probe, 0, sizeof(root_probe));
        if (!mft_probe_parse_record_any(record, root_abs_offset, &root_probe) ||
            (root_probe.flags & 0x0002U) == 0U) {
            continue;
        }

        parsed_roots++;
        for (child_index = 0U;
             child_index < root_probe.i30_child_count && !visitor_context.failed;
             child_index++) {
            if (!preview_append_i30_child_folder_name(
                    &root_probe.i30_children[child_index],
                    &visitor_context)) {
                break;
            }
        }

        if (!preview_visit_i30_allocation_runs(
                image_fd,
                contexts[i].geometry,
                &root_probe,
                config->coverage_map,
                &visitor_context,
                &blocks_seen)) {
            return 0;
        }
        if (root_probe.has_i30_allocation &&
            root_probe.i30_stored_run_count > 0U &&
            blocks_seen == 0U) {
            return 0;
        }
    }

    return parsed_roots > 0U && !visitor_context.failed && !stop_requested();
}

static const MftEntry *preview_find_child_directory(
    const MftTable *table,
    const MftEntry *parent,
    uint64_t parent_record,
    const char *name
)
{
    size_t i;

    if (table == NULL || name == NULL || name[0] == '\0') {
        return NULL;
    }

    for (i = 0U; i < table->count && !stop_requested(); i++) {
        const MftEntry *entry = &table->items[i];

        if ((entry->flags & 0x0002U) == 0U ||
            entry->parent != parent_record ||
            preview_folder_name_is_ignored(entry->name) ||
            strcasecmp(entry->name, name) != 0) {
            continue;
        }
        if (parent != NULL &&
            (entry->volume_index != parent->volume_index ||
             entry->family != parent->family)) {
            continue;
        }
        return entry;
    }

    return NULL;
}

static int preview_resolve_parent_folder(
    const MftTable *table,
    const char *parent_path,
    const MftEntry **out_parent,
    uint64_t *out_parent_record,
    char *out_normalized_parent,
    size_t out_normalized_parent_size
)
{
    char copy[PATH_MAX_LEN];
    char normalized[PATH_MAX_LEN] = "";
    char *saveptr = NULL;
    char *cursor;
    char *token;
    const MftEntry *parent = NULL;
    uint64_t parent_record = 5ULL;

    if (out_parent != NULL) {
        *out_parent = NULL;
    }
    if (out_parent_record != NULL) {
        *out_parent_record = 5ULL;
    }
    if (out_normalized_parent != NULL && out_normalized_parent_size > 0U) {
        out_normalized_parent[0] = '\0';
    }

    if (parent_path == NULL || parent_path[0] == '\0') {
        return 1;
    }

    snprintf(copy, sizeof(copy), "%s", parent_path);
    for (cursor = copy; *cursor != '\0'; cursor++) {
        if (*cursor == '\\') {
            *cursor = '/';
        }
    }

    token = strtok_r(copy, "/", &saveptr);
    while (token != NULL) {
        const MftEntry *child;

        while (*token == ' ' || *token == '\t') {
            token++;
        }
        if (token[0] == '\0') {
            token = strtok_r(NULL, "/", &saveptr);
            continue;
        }

        child = preview_find_child_directory(
            table,
            parent,
            parent_record,
            token
        );
        if (child == NULL) {
            log_error(
                "Folder preview could not find parent path component: %s",
                token
            );
            return 0;
        }
        if (normalized[0] != '\0') {
            strncat(normalized, "/", sizeof(normalized) - strlen(normalized) - 1U);
        }
        strncat(normalized, child->name, sizeof(normalized) - strlen(normalized) - 1U);

        parent = child;
        parent_record = (uint64_t)child->record;
        token = strtok_r(NULL, "/", &saveptr);
    }

    if (out_parent != NULL) {
        *out_parent = parent;
    }
    if (out_parent_record != NULL) {
        *out_parent_record = parent_record;
    }
    if (out_normalized_parent != NULL && out_normalized_parent_size > 0U) {
        snprintf(out_normalized_parent, out_normalized_parent_size, "%s", normalized);
    }
    return 1;
}

static int configure_partial_ntfs_source(
    Config *config,
    const MftprobePartialNtfsSource *source,
    DdrescueMap *coverage_map
)
{
    uint64_t volume_end;

    if (config == NULL || source == NULL || coverage_map == NULL ||
        source->coverage_map_path == NULL ||
        source->source_size == 0U ||
        source->volume_offset >= source->source_size ||
        source->volume_size == 0U ||
        source->volume_size > source->source_size - source->volume_offset ||
        source->cluster_size == 0U ||
        source->mft_record_size != RECORD_SIZE) {
        return 0;
    }
    volume_end = source->volume_offset + source->volume_size;
    if (source->mft_abs_offset < source->volume_offset ||
        source->mft_abs_offset >= volume_end ||
        source->mft_mirror_abs_offset < source->volume_offset ||
        source->mft_mirror_abs_offset >= volume_end ||
        !ddrescue_map_load(source->coverage_map_path, coverage_map)) {
        return 0;
    }

    config->source_size = source->source_size;
    config->ntfs.valid = 1;
    config->ntfs.volume_offset = source->volume_offset;
    config->ntfs.volume_size = source->volume_size;
    config->ntfs.cluster_size = source->cluster_size;
    config->ntfs.volume_serial = source->volume_serial;
    config->ntfs.mft_abs_offset = source->mft_abs_offset;
    config->ntfs.mft_mirror_abs_offset = source->mft_mirror_abs_offset;
    config->ntfs.mft_record_size = source->mft_record_size;
    config->ntfs.bytes_per_sector = source->bytes_per_sector;
    config->ntfs.sectors_per_cluster = source->sectors_per_cluster;
    config->ntfs.is_basic_data = source->is_basic_data;
    config->ntfs.mft_lcn =
        (source->mft_abs_offset - source->volume_offset) /
        source->cluster_size;
    config->ntfs.mft_mirror_lcn =
        (source->mft_mirror_abs_offset - source->volume_offset) /
        source->cluster_size;
    config->ntfs_volumes[0] = config->ntfs;
    config->ntfs_volume_count = 1U;
    config->coverage_map = coverage_map;
    return 1;
}

static int mftprobe_engine_list_folders_under_path(
    const char *image_path,
    const char *parent_path,
    const MftprobePartialNtfsSource *partial_source,
    FILE *out_stream
)
{
    char resolved_image_path[PATH_MAX_LEN];
    const char *effective_image_path = image_path;
    Config config = {0};
    FILE *file = NULL;
    int image_fd = -1;
    MftTable table = {0};
    char **names = NULL;
    size_t name_count = 0;
    const MftEntry *parent = NULL;
    uint64_t parent_record = 5ULL;
    char normalized_parent[PATH_MAX_LEN] = "";
    uint64_t scanned_bytes = 0;
    size_t i;
    int ok = 0;
    DdrescueMap coverage_map = {0};

    g_last_engine_status = MFTPROBE_ENGINE_STATUS_NONE;
    g_last_engine_recovered_count = 0;

    if (out_stream == NULL) {
        out_stream = stdout;
    }
    if (image_path == NULL || image_path[0] == '\0') {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!mftprobe_resolve_input_source_path(
            image_path,
            resolved_image_path,
            sizeof(resolved_image_path),
            &effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!mftprobe_preflight_open(effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    memset(&config, 0, sizeof(config));
    config.image_path = effective_image_path;
    if (partial_source != NULL) {
        if (!configure_partial_ntfs_source(
                &config, partial_source, &coverage_map)) {
            log_error("Hypersafe folder preview is missing a valid coverage map or NTFS geometry");
            g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
            ddrescue_map_reset(&coverage_map);
            return 0;
        }
    } else {
        config.source_size = mftprobe_detect_source_size(effective_image_path);
        if (config.source_size == 0U) {
            log_error("Failed to detect source size for root-folder preview");
            g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
            return 0;
        }
        if (!detect_ntfs_geometries(
                effective_image_path,
                config.source_size,
                config.ntfs_volumes,
                &config.ntfs_volume_count) ||
            config.ntfs_volume_count == 0) {
            log_error("No readable NTFS geometry was found for root-folder preview");
            g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
            ddrescue_map_reset(&coverage_map);
            return 0;
        }
        config.ntfs = config.ntfs_volumes[
            choose_preferred_ntfs_volume(config.ntfs_volumes, config.ntfs_volume_count)
        ];
    }

    file = fopen(effective_image_path, "rb");
    if (file == NULL) {
        log_error(
            "Failed to open source for root-folder preview: %s (%s)",
            effective_image_path,
            strerror(errno)
        );
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        ddrescue_map_reset(&coverage_map);
        return 0;
    }

    image_fd = open(effective_image_path, O_RDONLY);
    if (image_fd < 0) {
        log_error(
            "Failed to open source fd for root-folder preview: %s (%s)",
            effective_image_path,
            strerror(errno)
        );
        fclose(file);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        ddrescue_map_reset(&coverage_map);
        return 0;
    }

    if (parent_path == NULL || parent_path[0] == '\0') {
        if (preview_collect_root_folders_from_i30(
                file,
                image_fd,
                &config,
                &names,
                &name_count)) {
            if (name_count > 1U) {
                qsort(names, name_count, sizeof(*names), root_folder_name_order);
            }
            for (i = 0; i < name_count; i++) {
                fprintf(out_stream, "%s\n", names[i]);
            }
            ok = !stop_requested();
            goto cleanup;
        }
        for (i = 0; i < name_count; i++) {
            free(names[i]);
        }
        free(names);
        names = NULL;
        name_count = 0U;
    }

    if (!collect_primary_mft_entries(file, image_fd, &config, &table, &scanned_bytes)) {
        log_error(
            "NTFS geometry was found for folder preview, but the primary $MFT folder tree could not be read"
        );
        goto cleanup;
    }
    (void)scanned_bytes;

    if (!preview_resolve_parent_folder(
            &table,
            parent_path,
            &parent,
            &parent_record,
            normalized_parent,
            sizeof(normalized_parent))) {
        goto cleanup;
    }

    for (i = 0; i < table.count && !stop_requested(); i++) {
        char display_name[PATH_MAX_LEN];

        if ((table.items[i].flags & 0x0002U) == 0U ||
            table.items[i].parent != parent_record ||
            preview_folder_name_is_ignored(table.items[i].name)) {
            continue;
        }
        if (parent != NULL &&
            (table.items[i].volume_index != parent->volume_index ||
             table.items[i].family != parent->family)) {
            continue;
        }
        if (normalized_parent[0] != '\0') {
            if (snprintf(
                    display_name,
                    sizeof(display_name),
                    "%s/%s",
                    normalized_parent,
                    table.items[i].name) >= (int)sizeof(display_name)) {
                continue;
            }
        } else {
            snprintf(display_name, sizeof(display_name), "%s", table.items[i].name);
        }
        if (preview_folder_name_already_seen(names, name_count, display_name)) {
            continue;
        }

        if (!preview_append_folder_name(&names, &name_count, display_name)) {
            goto cleanup;
        }
    }

    if (name_count > 1U) {
        qsort(names, name_count, sizeof(*names), root_folder_name_order);
    }
    for (i = 0; i < name_count; i++) {
        fprintf(out_stream, "%s\n", names[i]);
    }
    ok = !stop_requested();

cleanup:
    for (i = 0; i < name_count; i++) {
        free(names[i]);
    }
    free(names);
    free(table.items);
    if (file != NULL) {
        fclose(file);
    }
    if (image_fd >= 0) {
        close(image_fd);
    }
    ddrescue_map_reset(&coverage_map);

    g_last_engine_status = ok ?
        MFTPROBE_ENGINE_STATUS_OK :
        (stop_requested() ? MFTPROBE_ENGINE_STATUS_INTERRUPTED : MFTPROBE_ENGINE_STATUS_FAILED);
    return ok;
}

int mftprobe_engine_list_root_folders(const char *image_path, FILE *out_stream)
{
    return mftprobe_engine_list_folders_under_path(image_path, NULL, NULL, out_stream);
}

int mftprobe_engine_list_child_folders(
    const char *image_path,
    const char *parent_path,
    FILE *out_stream
)
{
    if (parent_path == NULL || parent_path[0] == '\0') {
        return mftprobe_engine_list_root_folders(image_path, out_stream);
    }
    return mftprobe_engine_list_folders_under_path(
        image_path,
        parent_path,
        NULL,
        out_stream
    );
}

int mftprobe_engine_list_root_folders_partial(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    FILE *out_stream
)
{
    return mftprobe_engine_list_folders_under_path(
        image_path,
        NULL,
        source,
        out_stream
    );
}

int mftprobe_engine_list_child_folders_partial(
    const char *image_path,
    const char *parent_path,
    const MftprobePartialNtfsSource *source,
    FILE *out_stream
)
{
    return mftprobe_engine_list_folders_under_path(
        image_path,
        parent_path,
        source,
        out_stream
    );
}

static int targeted_recover_from_table(
    int image_fd,
    unsigned char *buffer,
    const Config *config,
    const TargetedRecoveryFilter *filter,
    const RecordList *record_list,
    const RecoverPathList *recover_path_list,
    TargetedRecoveryStats *stats,
    const MftEntry *items,
    const RecordIndex *index,
    size_t count,
    int folder_levels,
    size_t *out_matched,
    size_t *out_recovered,
    size_t *out_skipped
)
{
    size_t i;
    size_t recovered_count = 0;

    if (out_matched != NULL) {
        *out_matched = 0;
    }
    if (out_recovered != NULL) {
        *out_recovered = 0;
    }
    if (out_skipped != NULL) {
        *out_skipped = 0;
    }
    if (image_fd < 0 || buffer == NULL || config == NULL || filter == NULL || items == NULL) {
        return 0;
    }

    log_set_working_activity("recovering filtered files");

    for (i = 0; i < count && !stop_requested(); i++) {
        RecoveryTarget target;
        const RecoveryFormat *format;
        char relative_path[PATH_MAX_LEN];

        format = mftprobe_format_select_for_entry(config, &items[i]);
        if (format == NULL ||
            (record_list != NULL && !record_list_contains(record_list, items[i].record)) ||
            !targeted_entry_matches_filter(
                filter,
                format,
                items,
                index,
                count,
                &items[i])) {
            continue;
        }

        if (recover_path_list != NULL) {
            if (!targeted_find_recover_path_match(
                    recover_path_list,
                    items,
                    index,
                    count,
                    &items[i],
                    relative_path,
                    sizeof(relative_path))) {
                continue;
            }
        } else {
            if (filter->root_scope_count == 0 &&
                filter->has_deleted &&
                filter->deleted_value == 2) {
                if (targeted_entry_is_deleted_like(
                        items,
                        index,
                        count,
                        &items[i])) {
                    if (!build_path_for_deleted_recovery(
                            items,
                            index,
                            count,
                            &items[i],
                            relative_path,
                            sizeof(relative_path))) {
                        if (out_skipped != NULL) {
                            (*out_skipped)++;
                        }
                        if (stats != NULL) {
                            stats->skipped_invalid_target++;
                        }
                        continue;
                    }
                } else if (!build_path_if_under_users_root(
                               items,
                               index,
                               count,
                               &items[i],
                               relative_path,
                               sizeof(relative_path))) {
                    if (out_skipped != NULL) {
                        (*out_skipped)++;
                    }
                    if (stats != NULL) {
                        stats->skipped_invalid_target++;
                    }
                    continue;
                }
            } else {
                targeted_build_relative_mft_path_with_folders(
                    items,
                    index,
                    count,
                    &items[i],
                    format,
                    filter,
                    folder_levels,
                    relative_path,
                    sizeof(relative_path)
                );
            }
        }
        if (out_matched != NULL) {
            (*out_matched)++;
        }
        if (!targeted_prepare_recovery_target(
                &target,
                config,
                format,
                &items[i],
                relative_path)) {
            if (out_skipped != NULL) {
                (*out_skipped)++;
            }
            if (stats != NULL) {
                stats->skipped_invalid_target++;
            }
            continue;
        }
        if ((format->category_mask & RECOVERY_CATEGORY_IMAGE) != 0U &&
            recovery_runner_target_should_skip_image_fd(
                image_fd,
                &target,
                buffer,
                READ_SIZE)) {
            if (out_skipped != NULL) {
                (*out_skipped)++;
            }
            if (stats != NULL) {
                stats->skipped_image_filter++;
            }
            continue;
        }
        if (path_has_size(target.output_path, target.size)) {
            mft_note_recovered_output(
                target.output_path,
                (long long)target.abs_offset
            );
            recovered_count++;
            if (out_recovered != NULL) {
                (*out_recovered)++;
            }
            log_set_working_recovered_files(recovered_count);
            log_set_working_named_files(recovered_count);
            continue;
        }
        if (direct_recover_target(image_fd, &target, buffer)) {
            mft_note_recovered_output(
                target.output_path,
                (long long)target.abs_offset
            );
            recovered_count++;
            if (out_recovered != NULL) {
                (*out_recovered)++;
            }
            log_set_working_recovered_files(recovered_count);
            log_set_working_named_files(recovered_count);
        } else {
            targeted_stats_note_failure(stats, target.last_error);
            log_verbose(
                "Targeted recovery failed: created=%s name=%s class=%s reason=%s",
                items[i].created,
                items[i].name,
                recovery_runner_failure_class(target.last_error),
                target.last_error
            );
        }
    }

    return 1;
}

int mftprobe_engine_run_filtered_recovery_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    const char *filter_csv,
    uint64_t limit,
    const MftprobeEngineOptions *options
)
{
    char resolved_image_path[PATH_MAX_LEN];
    const char *effective_image_path = image_path;
    Config config = {0};
    FILE *file = NULL;
    int image_fd = -1;
    unsigned char *buffer = NULL;
    MftTable table = {0};
    RecordIndex *record_index = NULL;
    TargetedRecoveryFilter filter = {0};
    RecordList record_list = {0};
    RecoverPathList recover_path_list = {0};
    MftprobeFormatSelection selection = {0};
    char filter_error[256];
    char format_error[256];
    char record_list_error[256];
    char recover_path_error[256];
    char active_formats[512];
    uint64_t scanned_bytes = 0;
    size_t entry_count = 0;
    size_t matched = 0;
    size_t recovered = 0;
    size_t skipped_unsupported = 0;
    TargetedRecoveryStats stats = {0};
    int folder_levels = 0;
    int ok = 0;

    /*
     * Targeted recovery narrows work to a filtered slice of the MFT view
     * instead of running the full threaded scan pipeline.
     */
    (void)run_name;

    g_last_engine_status = MFTPROBE_ENGINE_STATUS_NONE;
    g_last_engine_recovered_count = 0;

    if (image_path == NULL || image_path[0] == '\0') {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!mftprobe_resolve_input_source_path(
            image_path,
            resolved_image_path,
            sizeof(resolved_image_path),
            &effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (out_dir == NULL || out_dir[0] == '\0') {
        out_dir = APP_DEFAULT_OUTPUT_DIR;
    }
    if (options != NULL && options->folder_levels > 0) {
        folder_levels = options->folder_levels;
        if (folder_levels > 2) {
            folder_levels = 2;
        }
    }
    if (filter_csv != NULL && filter_csv[0] != '\0') {
        if (!targeted_parse_filter(filter_csv, &filter, filter_error, sizeof(filter_error))) {
            log_error("Invalid --filter: %s", filter_error);
            g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
            return 0;
        }
    }
    if (options != NULL &&
        options->record_list_path != NULL &&
        options->record_list_path[0] != '\0') {
        if (!record_list_load_from_file(
                options->record_list_path,
                &record_list,
                record_list_error,
                sizeof(record_list_error))) {
            if (!recover_path_list_load_from_file(
                    options->record_list_path,
                    &recover_path_list,
                    recover_path_error,
                    sizeof(recover_path_error))) {
                log_error(
                    "Invalid --record-list: %s; path-list fallback also failed: %s",
                    record_list_error,
                    recover_path_error
                );
                g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
                return 0;
            }
        }
    }
    if ((filter_csv == NULL || filter_csv[0] == '\0') &&
        record_list.count == 0 &&
        recover_path_list.count == 0) {
        log_error("Targeted MFT recovery needs a filter or a --record-list");
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        recover_path_list_free(&recover_path_list);
        return 0;
    }
    if (!mftprobe_preflight_open(effective_image_path)) {
        record_list_free(&record_list);
        recover_path_list_free(&recover_path_list);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    memset(&config, 0, sizeof(config));
    config.image_path = effective_image_path;
    config.out_dir = out_dir;
    config.limit = limit;
    config.source_size = mftprobe_detect_source_size(effective_image_path);
    config.generic_file_targets =
        (options != NULL && options->generic_file_targets) ? 1 : 0;
    config.root_scope_defaulted =
        (options != NULL && options->root_scope_defaulted) ? 1 : 0;
    if (config.source_size == 0) {
        log_error("Failed to detect source size for targeted MFT recovery");
        record_list_free(&record_list);
        recover_path_list_free(&recover_path_list);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    if (!detect_ntfs_geometries(
            effective_image_path,
            config.source_size,
            config.ntfs_volumes,
            &config.ntfs_volume_count) ||
        config.ntfs_volume_count == 0) {
        log_error("No readable NTFS geometry was found for targeted MFT recovery");
        record_list_free(&record_list);
        recover_path_list_free(&recover_path_list);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    config.ntfs = config.ntfs_volumes[
        choose_preferred_ntfs_volume(config.ntfs_volumes, config.ntfs_volume_count)
    ];

    if (!mftprobe_format_load_common_profiles(&config, FORMAT_PROFILE_DB_PATH)) {
        log_error("Failed to load format profiles for targeted MFT recovery");
        record_list_free(&record_list);
        recover_path_list_free(&recover_path_list);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    selection.categories_csv = options != NULL ? options->categories_csv : NULL;
    if (options != NULL && options->formats_csv != NULL && options->formats_csv[0] != '\0') {
        selection.formats_csv = options->formats_csv;
    } else if (filter.has_format) {
        selection.formats_csv = filter.format_ext;
    }
    selection.dev_format = options != NULL ? options->dev_format : NULL;
    if ((selection.categories_csv == NULL || selection.categories_csv[0] == '\0') &&
        (selection.formats_csv == NULL || selection.formats_csv[0] == '\0') &&
        (selection.dev_format == NULL || selection.dev_format[0] == '\0')) {
        selection.categories_csv = "all";
    }
    if (!mftprobe_format_configure_active_order(
            &config,
            &selection,
            format_error,
            sizeof(format_error))) {
        log_error("Targeted MFT recovery format selection failed: %s", format_error);
        record_list_free(&record_list);
        recover_path_list_free(&recover_path_list);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    mftprobe_format_describe_active_order(&config, active_formats, sizeof(active_formats));

    log_info("Targeted MFT recovery started");
    log_verbose("Input path: %s", effective_image_path);
    log_verbose("Output dir: %s", out_dir);
    if (filter_csv != NULL && filter_csv[0] != '\0') {
        log_info("Filter: %s", filter_csv);
    }
    if (record_list.count > 0 && options != NULL && options->record_list_path != NULL) {
        log_info("Record list: %s (%zu records)", options->record_list_path, record_list.count);
    } else if (recover_path_list.count > 0 &&
               options != NULL &&
               options->record_list_path != NULL) {
        log_info("Record/path list: %s (%zu paths)", options->record_list_path, recover_path_list.count);
    }
    log_verbose("Active formats: %s", active_formats);

    /*
     * A previous targeted run may have left empty date folders behind after
     * failed recoveries. Prune them up front so the result tree reflects only
     * the current run even if the caller reuses the same output directory.
     */
    targeted_prune_empty_filtered_dirs(out_dir);

    file = fopen(effective_image_path, "rb");
    if (file == NULL) {
        log_error(
            "Failed to open source for targeted MFT recovery: %s (%s)",
            effective_image_path,
            strerror(errno)
        );
        record_list_free(&record_list);
        recover_path_list_free(&recover_path_list);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    image_fd = open(effective_image_path, O_RDONLY);
    if (image_fd < 0) {
        log_error(
            "Failed to open source fd for targeted MFT recovery: %s (%s)",
            effective_image_path,
            strerror(errno)
        );
        fclose(file);
        record_list_free(&record_list);
        recover_path_list_free(&recover_path_list);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    buffer = (unsigned char *)malloc(READ_SIZE);
    if (buffer == NULL) {
        fclose(file);
        close(image_fd);
        record_list_free(&record_list);
        recover_path_list_free(&recover_path_list);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    install_signal_handlers();
    log_set_working_suffix("targeted");
    log_start_working_indicator();

    if (folder_levels <= 0 &&
        !filter.has_deleted &&
        filter.root_scope_count == 0 &&
        recover_path_list.count == 0) {
        if (!targeted_recover_from_primary_mft(
                file,
                image_fd,
                buffer,
                &config,
                &filter,
                &record_list,
                &stats,
                &scanned_bytes,
                &entry_count,
                &matched,
                &recovered,
                &skipped_unsupported)) {
            goto cleanup;
        }
    } else {
        if (!collect_primary_mft_entries(file, image_fd, &config, &table, &scanned_bytes)) {
            goto cleanup;
        }
        entry_count = table.count;
        if (table.count > 0) {
            if (!table_ensure_record_index(&table) && !stop_requested()) {
                goto cleanup;
            }
            record_index = table.record_index;
        }
        if (!targeted_recover_from_table(
                image_fd,
                buffer,
                &config,
                &filter,
                &record_list,
                &recover_path_list,
                &stats,
                table.items,
                record_index,
                table.count,
                folder_levels,
                &matched,
                &recovered,
                &skipped_unsupported)) {
            goto cleanup;
        }
    }

    ok = !stop_requested();

cleanup:
    log_stop_working_indicator();
    restore_signal_handlers();
    table_reset(&table);
    record_list_free(&record_list);
    recover_path_list_free(&recover_path_list);
    free(buffer);
    if (file != NULL) {
        fclose(file);
    }
    if (image_fd >= 0) {
        close(image_fd);
    }

    if (stop_requested()) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_INTERRUPTED;
    } else {
        g_last_engine_status = ok ?
            MFTPROBE_ENGINE_STATUS_OK :
            MFTPROBE_ENGINE_STATUS_FAILED;
    }
    g_last_engine_recovered_count = recovered;

    if (!stop_requested()) {
        targeted_prune_empty_filtered_dirs(out_dir);
        log_info(
            "Targeted MFT recovery finished: scanned=%llu bytes entries=%zu matched=%zu recovered=%zu skipped=%zu",
            (unsigned long long)scanned_bytes,
            entry_count,
            matched,
            recovered,
            skipped_unsupported
        );
        targeted_stats_log_summary(&stats);
    }

    return ok;
}

int mftprobe_engine_run_metadata_jpeg_test(
    const char *image_path,
    const char *out_dir,
    size_t max_files,
    size_t *out_recovered_count
)
{
    char resolved_image_path[PATH_MAX_LEN];
    const char *effective_image_path = image_path;
    Config config = {0};
    FILE *file = NULL;
    int image_fd = -1;
    unsigned char *buffer = NULL;
    MftTable table = {0};
    MftprobeFormatSelection selection = {0};
    char format_error[256];
    char active_formats[512];
    uint64_t scanned_bytes = 0;
    size_t entry_count = 0U;
    size_t matched = 0U;
    size_t recovered = 0U;
    size_t skipped = 0U;
    size_t i;
    int ok = 0;

    if (out_recovered_count != NULL) {
        *out_recovered_count = 0U;
    }
    g_last_engine_status = MFTPROBE_ENGINE_STATUS_NONE;
    g_last_engine_recovered_count = 0U;

    if (image_path == NULL || image_path[0] == '\0' ||
        out_dir == NULL || out_dir[0] == '\0' ||
        max_files == 0U) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!mftprobe_resolve_input_source_path(
            image_path,
            resolved_image_path,
            sizeof(resolved_image_path),
            &effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!mftprobe_preflight_open(effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    memset(&config, 0, sizeof(config));
    config.image_path = effective_image_path;
    config.out_dir = out_dir;
    config.limit = 0ULL;
    config.source_size = mftprobe_detect_source_size(effective_image_path);
    config.generic_file_targets = 1;
    if (config.source_size == 0) {
        log_error("Failed to detect source size for NTFS JPEG test");
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!detect_ntfs_geometries(
            effective_image_path,
            config.source_size,
            config.ntfs_volumes,
            &config.ntfs_volume_count) ||
        config.ntfs_volume_count == 0) {
        log_error("No readable NTFS geometry was found for NTFS JPEG test");
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    config.ntfs = config.ntfs_volumes[
        choose_preferred_ntfs_volume(config.ntfs_volumes, config.ntfs_volume_count)
    ];

    if (!mftprobe_format_load_common_profiles(&config, FORMAT_PROFILE_DB_PATH)) {
        log_error("Failed to load format profiles for NTFS JPEG test");
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    selection.formats_csv = "jpg,jpeg";
    if (!mftprobe_format_configure_active_order(
            &config,
            &selection,
            format_error,
            sizeof(format_error))) {
        log_error("NTFS JPEG test format selection failed: %s", format_error);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    mftprobe_format_describe_active_order(&config, active_formats, sizeof(active_formats));

    file = fopen(effective_image_path, "rb");
    if (file == NULL) {
        log_error(
            "Failed to open source for NTFS JPEG test: %s (%s)",
            effective_image_path,
            strerror(errno)
        );
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    image_fd = open(effective_image_path, O_RDONLY);
    if (image_fd < 0) {
        log_error(
            "Failed to open source fd for NTFS JPEG test: %s (%s)",
            effective_image_path,
            strerror(errno)
        );
        fclose(file);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    buffer = (unsigned char *)malloc(READ_SIZE);
    if (buffer == NULL) {
        fclose(file);
        close(image_fd);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    install_signal_handlers();
    log_set_working_suffix("jpeg-test");
    log_set_working_activity("collecting NTFS MFT entries for JPEG test");
    log_start_working_indicator();

    log_info(
        "NTFS metadata JPEG test: recovering up to %zu MFT JPEG file%s into %s/%s/test",
        max_files,
        max_files == 1U ? "" : "s",
        out_dir,
        APP_RECOVERED_DIR_NAME
    );
    log_verbose("Input path: %s", effective_image_path);
    log_verbose("Active formats: %s", active_formats);

    if (!collect_primary_mft_entries(file, image_fd, &config, &table, &scanned_bytes)) {
        goto cleanup;
    }
    entry_count = table.count;
    log_set_working_activity("recovering JPEG test files from NTFS metadata");

    for (i = 0U; i < table.count && recovered < max_files && !stop_requested(); ++i) {
        const RecoveryFormat *format;
        RecoveryTarget target;
        char relative_path[PATH_MAX_LEN];

        if ((table.items[i].flags & 0x0002U) != 0U ||
            table.items[i].name[0] == '\0' ||
            table.items[i].data_size == 0U) {
            continue;
        }
        format = mftprobe_format_select_for_entry(&config, &table.items[i]);
        if (format == NULL) {
            continue;
        }
        ++matched;
        if (snprintf(
                relative_path,
                sizeof(relative_path),
                "\\test\\test_%02zu_%s",
                recovered + 1U,
                table.items[i].name) >= (int)sizeof(relative_path)) {
            ++skipped;
            continue;
        }
        if (!targeted_prepare_recovery_target(
                &target,
                &config,
                format,
                &table.items[i],
                relative_path)) {
            ++skipped;
            continue;
        }
        target.created_unix = filetime_to_unix_time_local(table.items[i].created_filetime);
        /*
         * A repeated smoke-test should read from the source again rather than
         * silently counting an old file in recovered/test as success.
         */
        targeted_ensure_unique_output_path(
            target.output_path,
            sizeof(target.output_path),
            table.items[i].record
        );
        if ((format->category_mask & RECOVERY_CATEGORY_IMAGE) != 0U &&
            recovery_runner_target_should_skip_image_fd(
                image_fd,
                &target,
                buffer,
                READ_SIZE)) {
            ++skipped;
            continue;
        }
        if (direct_recover_target(image_fd, &target, buffer)) {
            if (target.created_unix > 0) {
                (void)mft_engine_apply_created_time_value_to_path(
                    target.output_path,
                    target.created_unix
                );
            }
            mft_note_recovered_output(target.output_path, (long long)target.abs_offset);
            ++recovered;
            log_set_working_recovered_files(recovered);
            log_set_working_named_files(recovered);
            log_info("NTFS JPEG test recovered: %s", target.output_path);
        } else {
            ++skipped;
            log_verbose(
                "NTFS JPEG test skipped candidate record=%d name=%s reason=%s",
                table.items[i].record,
                table.items[i].name,
                target.last_error[0] != '\0' ? target.last_error : "recovery failed"
            );
        }
    }

    ok = !stop_requested() && recovered > 0U;

cleanup:
    log_stop_working_indicator();
    restore_signal_handlers();
    table_reset(&table);
    free(buffer);
    if (file != NULL) {
        fclose(file);
    }
    if (image_fd >= 0) {
        close(image_fd);
    }
    if (out_recovered_count != NULL) {
        *out_recovered_count = recovered;
    }
    g_last_engine_recovered_count = recovered;
    if (stop_requested()) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_INTERRUPTED;
    } else {
        g_last_engine_status = ok
            ? MFTPROBE_ENGINE_STATUS_OK
            : MFTPROBE_ENGINE_STATUS_FAILED;
    }
    if (!stop_requested()) {
        log_info(
            "NTFS metadata JPEG test finished: scanned=%llu bytes entries=%zu matched=%zu recovered=%zu skipped=%zu",
            (unsigned long long)scanned_bytes,
            entry_count,
            matched,
            recovered,
            skipped
        );
    }
    return ok;
}

int mftprobe_engine_run_compare_mount_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    const char *mount_path,
    const char *filter_csv,
    uint64_t limit,
    const MftprobeEngineOptions *options
)
{
    char resolved_image_path[PATH_MAX_LEN];
    const char *effective_image_path = image_path;
    Config config = {0};
    FILE *file = NULL;
    MftTable table = {0};
    RecordIndex *record_index = NULL;
    TargetedRecoveryFilter filter = {0};
    CompareScope scope = {0};
    MftprobeFormatSelection selection = {0};
    CompareCandidateList mft_list = {0};
    CompareCandidateList mount_list = {0};
    char filter_error[256];
    char format_error[256];
    char scope_error[256];
    char active_formats[512];
    char mount_users_root[PATH_MAX_LEN];
    uint64_t scanned_bytes = 0;
    size_t entry_count = 0;
    size_t mft_candidate_count = 0;
    size_t mount_candidate_count = 0;
    size_t matched = 0;
    size_t only_mft = 0;
    size_t only_mount = 0;
    size_t mismatch = 0;
    int ok = 0;

    (void)run_name;
    g_last_engine_status = MFTPROBE_ENGINE_STATUS_NONE;
    g_last_engine_recovered_count = 0;

    if (image_path == NULL || image_path[0] == '\0' ||
        out_dir == NULL || out_dir[0] == '\0' ||
        mount_path == NULL || mount_path[0] == '\0') {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!mftprobe_resolve_input_source_path(
            image_path,
            resolved_image_path,
            sizeof(resolved_image_path),
            &effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    if (filter_csv != NULL && filter_csv[0] != '\0') {
        if (!targeted_parse_filter(filter_csv, &filter, filter_error, sizeof(filter_error))) {
            log_error("Invalid compare filter: %s", filter_error);
            g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
            return 0;
        }
    }
    if (!compare_scope_parse(
            options != NULL ? options->compare_scope_csv : NULL,
            &scope,
            scope_error,
            sizeof(scope_error))) {
        log_error("Invalid compare scope: %s", scope_error);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!resolve_compare_users_root(mount_path, mount_users_root, sizeof(mount_users_root))) {
        log_error("Could not resolve mounted Users root under: %s", mount_path);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!mftprobe_preflight_open(effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    memset(&config, 0, sizeof(config));
    config.image_path = effective_image_path;
    config.out_dir = out_dir;
    config.limit = limit;
    config.source_size = mftprobe_detect_source_size(effective_image_path);
    config.generic_file_targets =
        (options != NULL && options->generic_file_targets) ? 1 : 0;
    config.root_scope_defaulted =
        (options != NULL && options->root_scope_defaulted) ? 1 : 0;
    if (config.source_size == 0) {
        log_error("Failed to detect source size for MFT/mount compare");
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!detect_ntfs_geometries(
            effective_image_path,
            config.source_size,
            config.ntfs_volumes,
            &config.ntfs_volume_count) ||
        config.ntfs_volume_count == 0) {
        log_error("No readable NTFS geometry was found for MFT/mount compare");
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    config.ntfs = config.ntfs_volumes[
        choose_preferred_ntfs_volume(config.ntfs_volumes, config.ntfs_volume_count)
    ];

    if (!mftprobe_format_load_common_profiles(&config, FORMAT_PROFILE_DB_PATH)) {
        log_error("Failed to load format profiles for MFT/mount compare");
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    selection.categories_csv = options != NULL ? options->categories_csv : NULL;
    if (options != NULL && options->formats_csv != NULL && options->formats_csv[0] != '\0') {
        selection.formats_csv = options->formats_csv;
    } else if (filter.has_format) {
        selection.formats_csv = filter.format_ext;
    }
    selection.dev_format = options != NULL ? options->dev_format : NULL;
    if ((selection.categories_csv == NULL || selection.categories_csv[0] == '\0') &&
        (selection.formats_csv == NULL || selection.formats_csv[0] == '\0') &&
        (selection.dev_format == NULL || selection.dev_format[0] == '\0')) {
        selection.categories_csv = "all";
    }
    if (!mftprobe_format_configure_active_order(
            &config,
            &selection,
            format_error,
            sizeof(format_error))) {
        log_error("MFT/mount compare format selection failed: %s", format_error);
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    mftprobe_format_describe_active_order(&config, active_formats, sizeof(active_formats));

    log_info("MFT/mount compare started");
    log_verbose("Input path: %s", effective_image_path);
    log_verbose("Mounted Users root: %s", mount_users_root);
    log_verbose("Output dir: %s", out_dir);
    if (filter_csv != NULL && filter_csv[0] != '\0') {
        log_info("Filter: %s", filter_csv);
    }
    if (options != NULL &&
        options->compare_scope_csv != NULL &&
        options->compare_scope_csv[0] != '\0') {
        log_info("Compare scope: %s", options->compare_scope_csv);
    }
    log_verbose("Active formats: %s", active_formats);

    if (!collect_mount_compare_entries_recursive(
            mount_users_root,
            "",
            &config,
            &filter,
            &scope,
            &mount_list)) {
        goto compare_cleanup;
    }
    mount_candidate_count = mount_list.count;
    if (mount_list.count > 1) {
        qsort(mount_list.items, mount_list.count, sizeof(*mount_list.items), compare_candidate_order);
    }
    if (!write_compare_mount_snapshot(out_dir, &mount_list)) {
        log_error("Failed to write compare mount snapshot");
        goto compare_cleanup;
    }

    file = fopen(effective_image_path, "rb");
    if (file == NULL) {
        log_error(
            "Failed to open source for MFT/mount compare: %s (%s)",
            effective_image_path,
            strerror(errno)
        );
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    if (!collect_primary_mft_entries(file, fileno(file), &config, &table, &scanned_bytes)) {
        goto compare_cleanup;
    }
    entry_count = table.count;
    if (table.count > 0) {
        if (!table_ensure_record_index(&table) && !stop_requested()) {
            goto compare_cleanup;
        }
        record_index = table.record_index;
    }
    if (!collect_mft_compare_entries(
            table.items,
            record_index,
            table.count,
            &config,
            &filter,
            &scope,
            &mft_list)) {
        goto compare_cleanup;
    }
    mft_candidate_count = mft_list.count;

    if (mft_list.count > 1) {
        qsort(mft_list.items, mft_list.count, sizeof(*mft_list.items), compare_candidate_order);
    }

    if (!write_compare_reports(
            out_dir,
            &mft_list,
            &mount_list,
            &matched,
            &only_mft,
            &only_mount,
            &mismatch)) {
        goto compare_cleanup;
    }

    ok = !stop_requested();

compare_cleanup:
    compare_candidate_list_free(&mount_list);
    compare_candidate_list_free(&mft_list);
    table_reset(&table);
    if (file != NULL) {
        fclose(file);
    }

    if (stop_requested()) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_INTERRUPTED;
    } else {
        g_last_engine_status = ok ?
            MFTPROBE_ENGINE_STATUS_OK :
            MFTPROBE_ENGINE_STATUS_FAILED;
    }

    if (!stop_requested()) {
        log_info(
            "MFT/mount compare finished: scanned=%.1f MiB entries=%zu mft_candidates=%zu mount_candidates=%zu matched=%zu only_in_mft=%zu only_in_mount=%zu mismatch=%zu",
            (double)scanned_bytes / (1024.0 * 1024.0),
            entry_count,
            mft_candidate_count,
            mount_candidate_count,
            matched,
            only_mft,
            only_mount,
            mismatch);
    }

    return ok;
}

static int append_ntfs_domain_range(
    NtfsDomainRange **ranges,
    size_t *range_count,
    size_t *range_capacity,
    uint64_t source_size,
    uint64_t start,
    uint64_t length
)
{
    NtfsDomainRange *expanded;

    if (ranges == NULL ||
        range_count == NULL ||
        range_capacity == NULL ||
        length == 0U ||
        start >= source_size) {
        return 1;
    }
    if (length > source_size - start) {
        length = source_size - start;
    }
    if (length == 0U || start > UINT64_MAX - length) {
        return 1;
    }
    if (*range_count >= *range_capacity) {
        size_t new_capacity = *range_capacity == 0U ? 256U : *range_capacity * 2U;

        if (new_capacity <= *range_capacity) {
            return 0;
        }
        expanded = (NtfsDomainRange *)realloc(*ranges, new_capacity * sizeof(*expanded));
        if (expanded == NULL) {
            return 0;
        }
        *ranges = expanded;
        *range_capacity = new_capacity;
    }

    (*ranges)[*range_count].start = start;
    (*ranges)[*range_count].end = start + length;
    (*range_count)++;
    return 1;
}

static int compare_ntfs_domain_ranges(const void *a, const void *b)
{
    const NtfsDomainRange *left = (const NtfsDomainRange *)a;
    const NtfsDomainRange *right = (const NtfsDomainRange *)b;

    if (left->start < right->start) {
        return -1;
    }
    if (left->start > right->start) {
        return 1;
    }
    if (left->end < right->end) {
        return -1;
    }
    if (left->end > right->end) {
        return 1;
    }
    return 0;
}

static size_t merge_ntfs_domain_ranges(
    NtfsDomainRange *ranges,
    size_t range_count,
    uint64_t max_gap_bytes
)
{
    size_t read_index;
    size_t write_index = 0U;

    if (ranges == NULL || range_count == 0U) {
        return 0U;
    }
    qsort(ranges, range_count, sizeof(*ranges), compare_ntfs_domain_ranges);
    for (read_index = 0U; read_index < range_count; ++read_index) {
        if (ranges[read_index].start >= ranges[read_index].end) {
            continue;
        }
        if (write_index == 0U) {
            ranges[write_index++] = ranges[read_index];
            continue;
        }
        {
            uint64_t previous_end = ranges[write_index - 1U].end;
            int close_enough = ranges[read_index].start <= previous_end;

            if (!close_enough &&
                max_gap_bytes > 0ULL &&
                previous_end <= UINT64_MAX - max_gap_bytes &&
                ranges[read_index].start <= previous_end + max_gap_bytes) {
                close_enough = 1;
            }
            if (!close_enough) {
                ranges[write_index++] = ranges[read_index];
                continue;
            }
        }
        if (ranges[read_index].end > ranges[write_index - 1U].end) {
            ranges[write_index - 1U].end = ranges[read_index].end;
        }
    }
    return write_index;
}

static int write_ntfs_domain_map(
    const char *domain_map_path,
    NtfsDomainRange *ranges,
    size_t range_count,
    uint64_t source_size,
    uint64_t *out_total_bytes
)
{
    FILE *file;
    size_t i;
    uint64_t total_bytes = 0ULL;
    uint64_t cursor = 0ULL;

    if (out_total_bytes != NULL) {
        *out_total_bytes = 0ULL;
    }
    if (domain_map_path == NULL ||
        domain_map_path[0] == '\0' ||
        ranges == NULL ||
        range_count == 0U ||
        source_size == 0U ||
        !ensure_parent_dirs(domain_map_path)) {
        return 0;
    }

    file = fopen(domain_map_path, "wb");
    if (file == NULL) {
        return 0;
    }
    fprintf(file, "# Mapfile. Created by Carv NTFS selected-folder domain.\n");
    fprintf(file, "# current_pos  current_status  current_pass\n");
    fprintf(file, "0x%08llX     +               1\n", 0ULL);
    fprintf(file, "#      pos        size  status\n");
    for (i = 0U; i < range_count; ++i) {
        uint64_t length;

        if (ranges[i].start >= ranges[i].end) {
            continue;
        }
        if (ranges[i].start > cursor) {
            fprintf(
                file,
                "0x%llX  0x%llX  ?\n",
                (unsigned long long)cursor,
                (unsigned long long)(ranges[i].start - cursor)
            );
        }
        length = ranges[i].end - ranges[i].start;
        total_bytes += length;
        fprintf(
            file,
            "0x%llX  0x%llX  +\n",
            (unsigned long long)ranges[i].start,
            (unsigned long long)length
        );
        cursor = ranges[i].end;
    }
    if (cursor < source_size) {
        fprintf(
            file,
            "0x%llX  0x%llX  ?\n",
            (unsigned long long)cursor,
            (unsigned long long)(source_size - cursor)
        );
    }
    if (fclose(file) != 0) {
        return 0;
    }
    if (out_total_bytes != NULL) {
        *out_total_bytes = total_bytes;
    }
    return total_bytes > 0ULL;
}

static int mftprobe_engine_write_selected_tree_ddrescue_domain_for_source(
    const char *image_path,
    const MftprobePartialNtfsSource *partial_source,
    const MftprobeEngineOptions *options,
    const char *legacy_root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes,
    uint64_t *out_file_count
)
{
    char resolved_image_path[PATH_MAX_LEN];
    char domain_run_dir[PATH_MAX_LEN] = "";
    const char *effective_image_path = image_path;
    Config config;
    MftTable table = {0};
    FILE *file = NULL;
    int image_fd = -1;
    int table_mutex_initialized = 0;
    NtfsDomainRange *ranges = NULL;
    size_t range_count = 0U;
    size_t range_capacity = 0U;
    size_t merged_count = 0U;
    int *owner_cache = NULL;
    uint64_t scanned_bytes = 0ULL;
    uint64_t total_bytes = 0ULL;
    uint64_t file_count = 0ULL;
    char scope_error[256] = "";
    char format_error[256] = "";
    MftprobeFormatSelection selection = {0};
    const char *root_scope_csv = legacy_root_scope_csv;
    size_t i;
    int ok = 0;
    DdrescueMap coverage_map = {0};

    if (out_range_count != NULL) {
        *out_range_count = 0ULL;
    }
    if (out_total_bytes != NULL) {
        *out_total_bytes = 0ULL;
    }
    if (out_file_count != NULL) {
        *out_file_count = 0ULL;
    }
    if (options != NULL) {
        root_scope_csv = options->root_scope_csv;
    }
    if (image_path == NULL ||
        image_path[0] == '\0' ||
        root_scope_csv == NULL ||
        root_scope_csv[0] == '\0' ||
        domain_map_path == NULL ||
        domain_map_path[0] == '\0') {
        return 0;
    }
    if (!mftprobe_resolve_input_source_path(
            image_path,
            resolved_image_path,
            sizeof(resolved_image_path),
            &effective_image_path) ||
        !mftprobe_preflight_open(effective_image_path)) {
        return 0;
    }

    memset(&config, 0, sizeof(config));
    config.image_path = effective_image_path;
    if (snprintf(
            domain_run_dir,
            sizeof(domain_run_dir),
            "%s",
            domain_map_path) < (int)sizeof(domain_run_dir)) {
        char *slash = strrchr(domain_run_dir, '/');

        if (slash != NULL) {
            *slash = '\0';
            slash = strrchr(domain_run_dir, '/');
            if (slash != NULL && strcmp(slash + 1, APP_STATE_DIR_NAME) == 0) {
                *slash = '\0';
                config.out_dir = domain_run_dir;
            }
        }
    }
    if (partial_source != NULL) {
        if (!configure_partial_ntfs_source(
                &config, partial_source, &coverage_map)) {
            ddrescue_map_reset(&coverage_map);
            return 0;
        }
    } else {
        config.source_size = mftprobe_detect_source_size(effective_image_path);
        if (config.source_size == 0U ||
            !detect_ntfs_geometries(
                effective_image_path,
                config.source_size,
                config.ntfs_volumes,
                &config.ntfs_volume_count) ||
            config.ntfs_volume_count == 0U) {
            return 0;
        }
        config.ntfs = config.ntfs_volumes[
            choose_preferred_ntfs_volume(
                config.ntfs_volumes,
                config.ntfs_volume_count
            )
        ];
    }
    if (!config_root_scope_add_csv(
            &config,
            root_scope_csv,
            scope_error,
            sizeof(scope_error)) ||
        config.root_scope_count == 0U) {
        ddrescue_map_reset(&coverage_map);
        return 0;
    }
    config.root_scope_defaulted =
        options != NULL && options->root_scope_defaulted;
    config.generic_file_targets =
        options != NULL && options->generic_file_targets;
    if (options != NULL && options->date_filter_value != NULL &&
        options->date_filter_value[0] != '\0') {
        if (!parse_date_filter_range_local(
                options->date_filter_value,
                &config.date_start_yyyymmdd,
                &config.date_end_yyyymmdd)) {
            ddrescue_map_reset(&coverage_map);
            return 0;
        }
        config.has_date_filter = 1;
    }
    if (options != NULL && options->deleted_filter_value != NULL &&
        options->deleted_filter_value[0] != '\0') {
        if (strcmp(options->deleted_filter_value, "1") == 0 ||
            strcasecmp(options->deleted_filter_value, "deleted") == 0 ||
            strcasecmp(options->deleted_filter_value, "true") == 0) {
            config.has_deleted_filter = 1;
            config.deleted_value = 1;
        } else if (strcmp(options->deleted_filter_value, "0") == 0 ||
                   strcasecmp(options->deleted_filter_value, "live") == 0 ||
                   strcasecmp(options->deleted_filter_value, "false") == 0) {
            config.has_deleted_filter = 1;
            config.deleted_value = 0;
        } else if (strcmp(options->deleted_filter_value, "2") == 0 ||
                   strcasecmp(options->deleted_filter_value, "both") == 0 ||
                   strcasecmp(options->deleted_filter_value, "all") == 0) {
            config.has_deleted_filter = 1;
            config.deleted_value = 2;
        } else {
            ddrescue_map_reset(&coverage_map);
            return 0;
        }
    }
    if (!mftprobe_format_load_common_profiles(&config, FORMAT_PROFILE_DB_PATH)) {
        ddrescue_map_reset(&coverage_map);
        return 0;
    }
    selection.categories_csv = options != NULL ? options->categories_csv : NULL;
    selection.formats_csv = options != NULL ? options->formats_csv : NULL;
    selection.dev_format = options != NULL ? options->dev_format : NULL;
    if ((selection.categories_csv == NULL || selection.categories_csv[0] == '\0') &&
        (selection.formats_csv == NULL || selection.formats_csv[0] == '\0') &&
        (selection.dev_format == NULL || selection.dev_format[0] == '\0')) {
        selection.categories_csv = "all";
    }
    if (!mftprobe_format_configure_active_order(
            &config, &selection, format_error, sizeof(format_error))) {
        log_error("Hypersafe NTFS domain format selection failed: %s", format_error);
        ddrescue_map_reset(&coverage_map);
        return 0;
    }

    if (pthread_mutex_init(&table.mutex, NULL) != 0) {
        ddrescue_map_reset(&coverage_map);
        return 0;
    }
    table_mutex_initialized = 1;
    file = fopen(effective_image_path, "rb");
    if (file == NULL) {
        goto cleanup;
    }
    image_fd = open(effective_image_path, O_RDONLY);
    if (image_fd < 0) {
        goto cleanup;
    }
    if (!collect_primary_mft_entries_resolving_folder_terms(
            file,
            image_fd,
            &config,
            &table,
            &scanned_bytes,
            NULL) ||
        !table_ensure_record_index(&table)) {
        goto cleanup;
    }

    if (!append_ntfs_domain_range(
            &ranges,
            &range_count,
            &range_capacity,
            config.source_size,
            0ULL,
            16ULL * 1024ULL * 1024ULL)) {
        goto cleanup;
    }
    for (i = 0U; i < config.ntfs_volume_count; ++i) {
        const NtfsGeometry *geometry = &config.ntfs_volumes[i];
        uint64_t front_length = geometry->volume_size < (2ULL * 1024ULL * 1024ULL)
            ? geometry->volume_size
            : (2ULL * 1024ULL * 1024ULL);

        if (!append_ntfs_domain_range(
                &ranges,
                &range_count,
                &range_capacity,
                config.source_size,
                geometry->volume_offset,
                front_length) ||
            !append_ntfs_domain_range(
                &ranges,
                &range_count,
                &range_capacity,
                config.source_size,
                geometry->mft_mirror_abs_offset,
                16ULL * 1024ULL * 1024ULL)) {
            goto cleanup;
        }
    }

    owner_cache = (int *)malloc(table.count * sizeof(*owner_cache));
    if (owner_cache == NULL) {
        goto cleanup;
    }
    for (i = 0U; i < table.count; ++i) {
        owner_cache[i] = ROOT_SCOPE_OWNER_UNKNOWN;
    }

    for (i = 0U; i < table.count; ++i) {
        const MftEntry *entry = &table.items[i];
        const RecoveryFormat *format = NULL;
        RecoveryRun runs[RECOVERY_TARGET_MAX_RUNS];
        size_t run_count_for_entry = 0U;
        int run_truncated = 0;
        size_t run_index;

        if (entry->record == 0 &&
            recovery_runs_from_entry(
                &config,
                entry,
                runs,
                &run_count_for_entry,
                &run_truncated)) {
            for (run_index = 0U; run_index < run_count_for_entry; ++run_index) {
                if (!append_ntfs_domain_range(
                        &ranges,
                        &range_count,
                        &range_capacity,
                        config.source_size,
                        runs[run_index].abs_offset,
                        runs[run_index].byte_length)) {
                    goto cleanup;
                }
            }
        }

        format = mftprobe_format_select_for_entry(&config, entry);
        if ((entry->flags & 0x0002U) != 0U ||
            entry->data_size == 0U ||
            (format == NULL && !entry_is_generic_file_candidate(&config, entry)) ||
            !config_entry_matches_users_runtime_filters_local(
                &config,
                format,
                table.items,
                table.record_index,
                table.count,
                entry) ||
            selected_root_scope_index_for_entry(
                &config,
                table.items,
                table.record_index,
                table.count,
                i,
                owner_cache) < 0 ||
            !recovery_runs_from_entry(
                &config,
                entry,
                runs,
                &run_count_for_entry,
                &run_truncated)) {
            continue;
        }
        (void)run_truncated;
        file_count++;
        for (run_index = 0U; run_index < run_count_for_entry; ++run_index) {
            if (!append_ntfs_domain_range(
                    &ranges,
                    &range_count,
                    &range_capacity,
                    config.source_size,
                    runs[run_index].abs_offset,
                    runs[run_index].byte_length)) {
                goto cleanup;
            }
        }
    }

    merged_count = merge_ntfs_domain_ranges(
        ranges,
        range_count,
        NTFS_DDRESCUE_DOMAIN_COALESCE_GAP_BYTES
    );
    if (merged_count < range_count) {
        log_info(
            "NTFS selected-folder ddrescue domain coalesced %llu raw extent range%s into %llu imaging range%s by bridging gaps up to 1 MiB",
            (unsigned long long)range_count,
            range_count == 1U ? "" : "s",
            (unsigned long long)merged_count,
            merged_count == 1U ? "" : "s"
        );
    }
    if (!write_ntfs_domain_map(
            domain_map_path,
            ranges,
            merged_count,
            config.source_size,
            &total_bytes)) {
        goto cleanup;
    }
    if (out_range_count != NULL) {
        *out_range_count = (uint64_t)merged_count;
    }
    if (out_total_bytes != NULL) {
        *out_total_bytes = total_bytes;
    }
    if (out_file_count != NULL) {
        *out_file_count = file_count;
    }
    ok = 1;

cleanup:
    free(owner_cache);
    free(ranges);
    table_reset(&table);
    if (image_fd >= 0) {
        close(image_fd);
    }
    if (file != NULL) {
        fclose(file);
    }
    if (table_mutex_initialized) {
        pthread_mutex_destroy(&table.mutex);
    }
    ddrescue_map_reset(&coverage_map);
    return ok;
}

int mftprobe_engine_write_selected_tree_ddrescue_domain(
    const char *image_path,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
)
{
    return mftprobe_engine_write_selected_tree_ddrescue_domain_for_source(
        image_path,
        NULL,
        NULL,
        root_scope_csv,
        domain_map_path,
        out_range_count,
        out_total_bytes,
        NULL
    );
}

int mftprobe_engine_write_selected_tree_ddrescue_domain_partial(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
)
{
    if (source == NULL) return 0;
    return mftprobe_engine_write_selected_tree_ddrescue_domain_for_source(
        image_path,
        source,
        NULL,
        root_scope_csv,
        domain_map_path,
        out_range_count,
        out_total_bytes,
        NULL
    );
}

int mftprobe_engine_write_selected_tree_ddrescue_domain_partial_with_options(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    const MftprobeEngineOptions *options,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes,
    uint64_t *out_file_count
)
{
    int installed_signal_handlers_here = 0;
    int interrupted;
    int ok;

    if (source == NULL || options == NULL) return 0;
    g_last_engine_status = MFTPROBE_ENGINE_STATUS_NONE;
    g_last_engine_recovered_count = 0U;
    if (!g_signal_handlers_installed) {
        install_signal_handlers();
        installed_signal_handlers_here = g_signal_handlers_installed;
    }
    ok = mftprobe_engine_write_selected_tree_ddrescue_domain_for_source(
        image_path,
        source,
        options,
        NULL,
        domain_map_path,
        out_range_count,
        out_total_bytes,
        out_file_count
    );
    interrupted = stop_requested();
    g_last_engine_status = ok
        ? MFTPROBE_ENGINE_STATUS_OK
        : (interrupted
            ? MFTPROBE_ENGINE_STATUS_INTERRUPTED
            : MFTPROBE_ENGINE_STATUS_FAILED);
    if (installed_signal_handlers_here) {
        restore_signal_handlers();
    }
    return ok;
}

static int hypersafe_target_has_complete_coverage(
    const DdrescueMap *coverage_map,
    const RecoveryTarget *target
)
{
    uint64_t remaining;
    size_t i;

    if (coverage_map == NULL || target == NULL || target->size == 0U) {
        return 0;
    }
    remaining = target->size;
    for (i = 0U; i < target->run_count && remaining > 0U; ++i) {
        uint64_t length = target->runs[i].byte_length;

        if (length > remaining) length = remaining;
        if (length == 0U ||
            !ddrescue_map_range_is_finished(
                coverage_map,
                target->runs[i].abs_offset,
                length)) {
            return 0;
        }
        remaining -= length;
    }
    return remaining == 0U;
}

static int write_hypersafe_selected_missing_report(
    const char *out_dir,
    RecoveryPlan *plan,
    const DdrescueMap *coverage_map
)
{
    char state_dir[PATH_MAX_LEN];
    char report_path[PATH_MAX_LEN];
    char temp_path[PATH_MAX_LEN + 32];
    FILE *file = NULL;
    size_t i;
    int ok = 0;

    if (out_dir == NULL || plan == NULL || coverage_map == NULL ||
        !ensure_state_dir_for_out_dir(out_dir, state_dir, sizeof(state_dir))) {
        return 0;
    }
    join_path(
        report_path,
        sizeof(report_path),
        state_dir,
        "hypersafe_selected_missing.tsv"
    );
    if (snprintf(temp_path, sizeof(temp_path), "%s.tmp", report_path) >=
        (int)sizeof(temp_path)) {
        return 0;
    }
    file = fopen(temp_path, "wb");
    if (file == NULL) return 0;

    fprintf(
        file,
        "problem\trecord\tfamily\tsize\texpected_size\tsource_path\toutput_path\textents\tdetail\n"
    );
    pthread_mutex_lock(&plan->mutex);
    for (i = 0U; i < plan->count; ++i) {
        const RecoveryTarget *target = &plan->items[i];
        const char *problem;
        const char *detail;

        if (path_has_size(target->output_path, target->size)) continue;
        if (!hypersafe_target_has_complete_coverage(coverage_map, target)) {
            problem = "waiting_for_readable_extents";
            detail = "one or more file extents are still unresolved in the ddrescue map";
        } else {
            problem = "validation_or_write_failed";
            detail = target->last_error[0] != '\0'
                ? target->last_error
                : "all extents are readable but the file was not accepted or written";
        }
        fprintf(
            file,
            "%s\t%d\t%u\t%llu\t%llu\t",
            problem,
            target->record,
            target->family,
            (unsigned long long)target->size,
            (unsigned long long)target->expected_size
        );
        fprint_tsv_field(file, target->source_path);
        fputc('\t', file);
        fprint_tsv_field(file, target->output_path);
        fputc('\t', file);
        fprint_recovery_runs_field(file, target);
        fputc('\t', file);
        fprint_tsv_field(file, detail);
        fputc('\n', file);
    }
    pthread_mutex_unlock(&plan->mutex);

    if (fflush(file) == 0 && fsync(fileno(file)) == 0 && fclose(file) == 0) {
        file = NULL;
        ok = rename(temp_path, report_path) == 0;
    } else {
        fclose(file);
        file = NULL;
    }
    if (!ok) (void)unlink(temp_path);
    return ok;
}

static int selected_path_is_within_scope(
    const char *source_path,
    const char *scope_path
)
{
    const unsigned char *path = (const unsigned char *)source_path;
    const unsigned char *scope = (const unsigned char *)scope_path;

    if (source_path == NULL || scope_path == NULL) return 0;
    while (*path == '/' || *path == '\\') path++;
    while (*scope == '/' || *scope == '\\') scope++;
    if (*scope == '\0') return 0;

    while (*scope != '\0') {
        int path_separator = *path == '/' || *path == '\\';
        int scope_separator = *scope == '/' || *scope == '\\';

        if (scope_separator) {
            if (!path_separator) return 0;
        } else if (*path == '\0' || path_separator ||
                   tolower(*path) != tolower(*scope)) {
            return 0;
        }
        path++;
        scope++;
    }
    return *path == '\0' || *path == '/' || *path == '\\';
}

static void mark_selected_scope_with_complete_file(
    const Config *config,
    const char *source_path,
    uint8_t *scope_has_complete_file,
    size_t scope_capacity
)
{
    size_t scope_index;

    if (config == NULL || source_path == NULL ||
        scope_has_complete_file == NULL || scope_capacity == 0U) {
        return;
    }
    for (scope_index = 0U;
         scope_index < config->root_scope_count &&
         scope_index < scope_capacity;
         ++scope_index) {
        if (selected_path_is_within_scope(
                source_path,
                config->root_scopes[scope_index])) {
            scope_has_complete_file[scope_index] = 1U;
        }
    }
}

int mftprobe_engine_run_selected_partial_recovery(
    const char *image_path,
    const char *out_dir,
    const MftprobePartialNtfsSource *source,
    const MftprobeEngineOptions *options,
    size_t *out_recovered_count,
    size_t *out_waiting_for_coverage,
    size_t *out_already_present,
    size_t *out_failed,
    size_t *out_folders_with_complete_files
)
{
    char resolved_image_path[PATH_MAX_LEN];
    const char *effective_image_path = image_path;
    Config config = {0};
    DdrescueMap coverage_map = {0};
    MftTable table = {0};
    RecoveryPlan plan;
    MftprobeFormatSelection selection = {0};
    FILE *file = NULL;
    int image_fd = -1;
    unsigned char *buffer = NULL;
    uint64_t scanned_bytes = 0U;
    size_t recovered = 0U;
    size_t already_present = 0U;
    size_t waiting = 0U;
    size_t failed = 0U;
    size_t matched = 0U;
    size_t folders_with_complete_files = 0U;
    uint8_t scope_has_complete_file[64] = {0};
    size_t i;
    int table_mutex_initialized = 0;
    int plan_initialized = 0;
    int installed_signal_handlers_here = 0;
    int ok = 0;
    int interrupted = 0;
    char scope_error[256] = "";
    char format_error[256] = "";

    if (out_recovered_count != NULL) *out_recovered_count = 0U;
    if (out_waiting_for_coverage != NULL) *out_waiting_for_coverage = 0U;
    if (out_already_present != NULL) *out_already_present = 0U;
    if (out_failed != NULL) *out_failed = 0U;
    if (out_folders_with_complete_files != NULL) {
        *out_folders_with_complete_files = 0U;
    }
    g_last_engine_status = MFTPROBE_ENGINE_STATUS_NONE;
    g_last_engine_recovered_count = 0U;

    if (image_path == NULL || image_path[0] == '\0' ||
        out_dir == NULL || out_dir[0] == '\0' ||
        source == NULL || options == NULL ||
        options->root_scope_csv == NULL || options->root_scope_csv[0] == '\0' ||
        !mftprobe_resolve_input_source_path(
            image_path,
            resolved_image_path,
            sizeof(resolved_image_path),
            &effective_image_path) ||
        !mftprobe_preflight_open(effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    if (!g_signal_handlers_installed) {
        install_signal_handlers();
        installed_signal_handlers_here = g_signal_handlers_installed;
    }

    config.image_path = effective_image_path;
    config.out_dir = out_dir;
    config.generic_file_targets = options->generic_file_targets;
    config.root_scope_defaulted = options->root_scope_defaulted;
    if (!configure_partial_ntfs_source(&config, source, &coverage_map) ||
        !config_root_scope_add_csv(
            &config,
            options->root_scope_csv,
            scope_error,
            sizeof(scope_error))) {
        log_error(
            "Hypersafe direct recovery setup failed%s%s",
            scope_error[0] != '\0' ? ": " : "",
            scope_error[0] != '\0' ? scope_error : ""
        );
        goto cleanup;
    }
    if (options->date_filter_value != NULL &&
        options->date_filter_value[0] != '\0') {
        if (!parse_date_filter_range_local(
                options->date_filter_value,
                &config.date_start_yyyymmdd,
                &config.date_end_yyyymmdd)) {
            log_error("Hypersafe direct recovery date filter is invalid");
            goto cleanup;
        }
        config.has_date_filter = 1;
    }
    if (options->deleted_filter_value != NULL &&
        options->deleted_filter_value[0] != '\0') {
        if (strcmp(options->deleted_filter_value, "1") == 0 ||
            strcasecmp(options->deleted_filter_value, "deleted") == 0 ||
            strcasecmp(options->deleted_filter_value, "true") == 0) {
            config.has_deleted_filter = 1;
            config.deleted_value = 1;
        } else if (strcmp(options->deleted_filter_value, "0") == 0 ||
                   strcasecmp(options->deleted_filter_value, "live") == 0 ||
                   strcasecmp(options->deleted_filter_value, "false") == 0) {
            config.has_deleted_filter = 1;
            config.deleted_value = 0;
        } else if (strcmp(options->deleted_filter_value, "2") == 0 ||
                   strcasecmp(options->deleted_filter_value, "both") == 0 ||
                   strcasecmp(options->deleted_filter_value, "all") == 0) {
            config.has_deleted_filter = 1;
            config.deleted_value = 2;
        } else {
            log_error("Hypersafe direct recovery deleted filter is invalid");
            goto cleanup;
        }
    }
    if (!mftprobe_format_load_common_profiles(&config, FORMAT_PROFILE_DB_PATH)) {
        log_error("Hypersafe direct recovery could not load format profiles");
        goto cleanup;
    }
    selection.categories_csv = options->categories_csv;
    selection.formats_csv = options->formats_csv;
    selection.dev_format = options->dev_format;
    if ((selection.categories_csv == NULL || selection.categories_csv[0] == '\0') &&
        (selection.formats_csv == NULL || selection.formats_csv[0] == '\0') &&
        (selection.dev_format == NULL || selection.dev_format[0] == '\0')) {
        selection.categories_csv = "all";
    }
    if (!mftprobe_format_configure_active_order(
            &config,
            &selection,
            format_error,
            sizeof(format_error))) {
        log_error("Hypersafe direct recovery format selection failed: %s", format_error);
        goto cleanup;
    }

    if (pthread_mutex_init(&table.mutex, NULL) != 0) goto cleanup;
    table_mutex_initialized = 1;
    if (!recovery_plan_init(&plan)) goto cleanup;
    plan_initialized = 1;
    file = fopen(effective_image_path, "rb");
    if (file == NULL) goto cleanup;
    image_fd = open(effective_image_path, O_RDONLY);
    if (image_fd < 0) goto cleanup;
    if (!collect_primary_mft_entries_resolving_folder_terms(
            file, image_fd, &config, &table, &scanned_bytes, NULL) ||
        !recovery_plan_refresh_from_table(&plan, &config, &table)) {
        goto cleanup;
    }
    buffer = (unsigned char *)malloc(READ_SIZE);
    if (buffer == NULL) goto cleanup;

    log_set_working_activity("recovering selected files");
    pthread_mutex_lock(&plan.mutex);
    qsort(plan.items, plan.count, sizeof(*plan.items), compare_recovery_targets_by_offset);
    recovery_plan_mark_indexes_dirty_locked(&plan);
    for (i = 0U; i < plan.count && !stop_requested(); ++i) {
        RecoveryTarget *target = &plan.items[i];

        matched++;
        if (path_has_size(target->output_path, target->size)) {
            mft_note_recovered_output(
                target->output_path,
                (long long)target->abs_offset
            );
            already_present++;
            mark_selected_scope_with_complete_file(
                &config,
                target->source_path,
                scope_has_complete_file,
                sizeof(scope_has_complete_file) /
                    sizeof(scope_has_complete_file[0])
            );
            continue;
        }
        if (!hypersafe_target_has_complete_coverage(&coverage_map, target)) {
            waiting++;
            continue;
        }
        if (recovery_target_looks_like_image(target) &&
            recovery_runner_target_should_skip_image_fd(
                image_fd, target, buffer, READ_SIZE)) {
            snprintf(
                target->last_error,
                sizeof(target->last_error),
                "%s",
                "image validation rejected the recovered content"
            );
            failed++;
            continue;
        }

        pthread_mutex_unlock(&plan.mutex);
        if (direct_recover_target(image_fd, target, buffer)) {
            if (target->created_unix > 0) {
                (void)mft_engine_apply_created_time_value_to_path(
                    target->output_path,
                    target->created_unix
                );
            }
            mft_note_recovered_output(
                target->output_path,
                (long long)target->abs_offset
            );
            recovered++;
            mark_selected_scope_with_complete_file(
                &config,
                target->source_path,
                scope_has_complete_file,
                sizeof(scope_has_complete_file) /
                    sizeof(scope_has_complete_file[0])
            );
            log_set_working_recovered_files(recovered + already_present);
            log_set_working_named_files(recovered + already_present);
            log_info("Hypersafe early file ready: %s", target->output_path);
        } else {
            failed++;
            log_verbose(
                "Hypersafe direct recovery could not complete %s: %s",
                target->source_path,
                target->last_error[0] != '\0' ? target->last_error : "unknown"
            );
        }
        pthread_mutex_lock(&plan.mutex);
    }
    pthread_mutex_unlock(&plan.mutex);

    for (i = 0U;
         i < config.root_scope_count &&
         i < sizeof(scope_has_complete_file) /
             sizeof(scope_has_complete_file[0]);
         ++i) {
        if (scope_has_complete_file[i]) folders_with_complete_files++;
    }

    if (!write_hypersafe_selected_missing_report(
            config.out_dir,
            &plan,
            &coverage_map)) {
        log_verbose("Hypersafe selected-file missing report could not be updated");
    }

    ok = !stop_requested();
    log_info(
        "Hypersafe selected-folder recovery: matched=%zu new=%zu already_present=%zu waiting_for_readable_extents=%zu failed_validation_or_write=%zu",
        matched,
        recovered,
        already_present,
        waiting,
        failed
    );

cleanup:
    free(buffer);
    if (image_fd >= 0) close(image_fd);
    if (file != NULL) fclose(file);
    if (plan_initialized) recovery_plan_destroy(&plan);
    table_reset(&table);
    if (table_mutex_initialized) pthread_mutex_destroy(&table.mutex);
    ddrescue_map_reset(&coverage_map);
    if (out_recovered_count != NULL) *out_recovered_count = recovered;
    if (out_waiting_for_coverage != NULL) *out_waiting_for_coverage = waiting;
    if (out_already_present != NULL) *out_already_present = already_present;
    if (out_failed != NULL) *out_failed = failed;
    if (out_folders_with_complete_files != NULL) {
        *out_folders_with_complete_files = folders_with_complete_files;
    }
    g_last_engine_recovered_count = recovered;
    interrupted = stop_requested();
    g_last_engine_status = ok
        ? MFTPROBE_ENGINE_STATUS_OK
        : (interrupted
            ? MFTPROBE_ENGINE_STATUS_INTERRUPTED
            : MFTPROBE_ENGINE_STATUS_FAILED);
    if (installed_signal_handlers_here) {
        restore_signal_handlers();
    }
    return ok;
}

int mftprobe_engine_run_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    uint64_t limit,
    int quick_resume,
    int auto_recover_missed,
    int only_recover_missed,
    const MftprobeEngineOptions *options
)
{
    char resolved_image_path[PATH_MAX_LEN];
    const char *effective_image_path = image_path;
    char limit_text[32];
    char date_filter_text[32];
    char root_scope_text[1024];
    char *argv[40];
    int argc = 0;
    int ok;
    int show_working_indicator;
    uint64_t total_size;
    char start_offset_text[32];

    /*
     * Public wrapper used by the rest of the program. It translates the
     * higher-level app options into a CLI-style argv and then reuses the
     * same engine entry point as the standalone path.
     */
    (void)auto_recover_missed;
    g_last_engine_status = MFTPROBE_ENGINE_STATUS_NONE;
    g_last_engine_recovered_count = 0;

    if (image_path == NULL || image_path[0] == '\0') {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }
    if (!mftprobe_resolve_input_source_path(
            image_path,
            resolved_image_path,
            sizeof(resolved_image_path),
            &effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    if (out_dir == NULL || out_dir[0] == '\0') {
        out_dir = APP_DEFAULT_OUTPUT_DIR;
    }

    if (!mftprobe_preflight_open(effective_image_path)) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_FAILED;
        return 0;
    }

    argv[argc++] = "mftprobe";
    argv[argc++] = "--image";
    argv[argc++] = (char *)effective_image_path;
    argv[argc++] = "--out";
    argv[argc++] = (char *)out_dir;
    if (run_name != NULL && run_name[0] != '\0') {
        argv[argc++] = "--run-name";
        argv[argc++] = (char *)run_name;
    }

    if (limit > 0) {
        snprintf(limit_text, sizeof(limit_text), "%llu", (unsigned long long)limit);
        argv[argc++] = "--limit";
        argv[argc++] = limit_text;
    }

    if (quick_resume) {
        argv[argc++] = "--resume";
    }

    if (only_recover_missed) {
        argv[argc++] = "--only-recover-missed";
    }

    if (options != NULL) {
        if (options->categories_csv != NULL && options->categories_csv[0] != '\0') {
            argv[argc++] = "--categories";
            argv[argc++] = (char *)options->categories_csv;
        }
        if (options->formats_csv != NULL && options->formats_csv[0] != '\0') {
            argv[argc++] = "--formats";
            argv[argc++] = (char *)options->formats_csv;
        }
        if (options->dev_format != NULL && options->dev_format[0] != '\0') {
            argv[argc++] = "--dev-format";
            argv[argc++] = (char *)options->dev_format;
        }
        if (options->deleted_filter_value != NULL &&
            options->deleted_filter_value[0] != '\0') {
            argv[argc++] = "--deleted-filter";
            argv[argc++] = (char *)options->deleted_filter_value;
        }
        if (options->date_filter_value != NULL &&
            options->date_filter_value[0] != '\0') {
            snprintf(date_filter_text, sizeof(date_filter_text), "%s", options->date_filter_value);
            argv[argc++] = "--date-filter";
            argv[argc++] = date_filter_text;
        }
        if (options->root_scope_csv != NULL &&
            options->root_scope_csv[0] != '\0') {
            snprintf(root_scope_text, sizeof(root_scope_text), "%s", options->root_scope_csv);
            argv[argc++] = "--fold";
            argv[argc++] = root_scope_text;
        }
        if (options->start_offset_explicit) {
            snprintf(
                start_offset_text,
                sizeof(start_offset_text),
                "%llu",
                (unsigned long long)options->start_offset
            );
            argv[argc++] = "--start-offset";
            argv[argc++] = start_offset_text;
        }
        if (options->generic_file_targets) {
            argv[argc++] = "--generic-file-targets";
        }
        if (options->root_scope_defaulted) {
            argv[argc++] = "--root-scope-defaulted";
        }
    }

    argv[argc] = NULL;

    total_size = mftprobe_detect_source_size(effective_image_path);
    if (limit > 0 && (total_size == 0 || limit < total_size)) {
        total_size = limit;
    }

    install_signal_handlers();

    show_working_indicator = !only_recover_missed;
    if (show_working_indicator) {
        log_set_working_suffix("mftprobe");
        if (options != NULL && options->start_offset_explicit) {
            log_set_working_progress(options->start_offset, total_size);
            log_set_working_speed_base(options->start_offset);
        } else {
            log_set_working_progress(0, total_size);
            log_set_working_speed_base(0);
        }
        log_start_working_indicator();
    }

    ok = (mftprobe_engine_main(argc, argv) == 0);
    if (stop_requested()) {
        g_last_engine_status = MFTPROBE_ENGINE_STATUS_INTERRUPTED;
    } else {
        g_last_engine_status = ok ?
            MFTPROBE_ENGINE_STATUS_OK :
            MFTPROBE_ENGINE_STATUS_FAILED;
    }
    if (show_working_indicator) {
        log_stop_working_indicator();
    }
    restore_signal_handlers();
    return ok;
}

int mftprobe_engine_run(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    uint64_t limit,
    int quick_resume,
    int auto_recover_missed,
    int only_recover_missed
)
{
    return mftprobe_engine_run_with_options(
        image_path,
        out_dir,
        run_name,
        limit,
        quick_resume,
        auto_recover_missed,
        only_recover_missed,
        NULL
    );
}

MftprobeEngineStatus mftprobe_engine_last_status(void)
{
    return g_last_engine_status;
}

size_t mftprobe_engine_last_recovered_count(void)
{
    return g_last_engine_recovered_count;
}
