/*
 * scanner.c
 * Reads input sequentially, observes filesystem metadata records, and lets
 * backend-provided metadata targets recover as their file offsets pass by.
 *
 * Some implementations remain NTFS-specific under the hood, but this scanner
 * should present itself as the generic metadata-aware recovery path.
 */

#include "scanner.h"
#include "app.h"
#include "blob_start.h"
#include "carver_jpeg.h"
#include "carver_mkv.h"
#include "carver_mpeg_ps.h"
#include "carver_mov.h"
#include "carver_pdf.h"
#include "carver_png.h"
#include "carver_riff.h"
#include "carver_output.h"
#include "fs_backend.h"
#include "format_pipeline.h"
#include "log.h"
#include "magic.h"
#include "matcher.h"
#include "performance_ledger.h"
#include "platform.h"
#include "metadata_outcome.h"
#include "run_identity.h"
#include "scan_state.h"

#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __APPLE__
int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
#endif

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

/*
 * Keep this local declaration so scanner.c stays buildable if another machine
 * is momentarily on an older fs_backend.h during cross-machine iteration.
 */
int fs_backend_has_metadata_context_for_raw_scan(void);
const char *fs_backend_current_id(void);
const char *log_target_throughput_profile_label(double target_mib_per_sec);
const char *log_target_throughput_profile_ui_label(double target_mib_per_sec);
int fs_backend_background_worker_expected_running(void);
static int primary_metadata_runlist_is_trustworthy_for_live_observation(void);

#if defined(__GNUC__) || defined(__clang__)
#define SCANNER_MAYBE_UNUSED __attribute__((unused))
#else
#define SCANNER_MAYBE_UNUSED
#endif

#define RAW_ALL_STATE_WRITE_INTERVAL (256U * 1024U * 1024U)
#define RAW_ALL_PROGRESS_UPDATE_INTERVAL (4U * 1024U * 1024U)
#define RAW_ALL_SLOW_CANDIDATE_LOG_SECONDS 1.5
#define RAW_ALL_SLOW_METADATA_OBSERVE_LOG_SECONDS 1.0
#define RAW_ALL_RECOVERED_STATE_REFRESH_SECONDS 5.0
#define PRIMARY_METADATA_STARTUP_RUNLIST_PROBE_BYTES (8ULL * 1024ULL * 1024ULL)
#define PRIMARY_METADATA_STARTUP_BOOTSTRAP_BYTES (96ULL * 1024ULL * 1024ULL)
#define PRIMARY_METADATA_STARTUP_FALLBACK_BYTES (192ULL * 1024ULL * 1024ULL)
#define PRIMARY_METADATA_PRE_DEFERRED_PROBE_BYTES (8ULL * 1024ULL * 1024ULL)
#define PRIMARY_METADATA_PRE_DEFERRED_BYTES (16ULL * 1024ULL * 1024ULL)
#define PRIMARY_METADATA_POST_DEFERRED_PROBE_BYTES (16ULL * 1024ULL * 1024ULL)
#define PRIMARY_METADATA_POST_DEFERRED_BYTES (96ULL * 1024ULL * 1024ULL)
#define PRIMARY_METADATA_POST_DEFERRED_REVERSE_WINDOW_BYTES (4ULL * 1024ULL * 1024ULL)
#define PRIMARY_METADATA_MIRROR_SWEEP_MAX_BYTES (1ULL * 1024ULL * 1024ULL)
#define PRIMARY_METADATA_STARTUP_MAX_SECONDS 90.0
#define PRIMARY_METADATA_PRE_DEFERRED_MAX_SECONDS 12.0
#define PRIMARY_METADATA_POST_DEFERRED_MAX_SECONDS 60.0
#define PRIMARY_METADATA_STARTUP_CHUNK_CAP_BYTES (128U * 1024U)
#define PRIMARY_METADATA_PRE_DEFERRED_CHUNK_CAP_BYTES (64U * 1024U)
#define PRIMARY_METADATA_POST_DEFERRED_CHUNK_CAP_BYTES (64U * 1024U)
#define WORKING_QUEUE_STATS_UPDATE_INTERVAL_SECONDS 0.75
#define RAW_ALL_ACTIVITY_WRITE_INTERVAL_SECONDS 2.0
#define PRIMARY_METADATA_PROGRESS_WRITE_INTERVAL_SECONDS 1.0
#define PRIMARY_METADATA_PROGRESS_STATE_NAME "primary_metadata_progress.txt"
#define RAW_ALL_CLAIM_AUDIT_DISCOVERY_CHUNK_CAP_BYTES (1U * 1024U * 1024U)
#define RAW_ALL_CLAIM_AUDIT_DISCOVERY_REGULAR_FILE_CHUNK_CAP_BYTES (4U * 1024U * 1024U)
#define RAW_ALL_CLAIM_AUDIT_CANDIDATE_CHUNK_CAP_BYTES (2U * 1024U * 1024U)
#define RAW_ALL_CLAIM_AUDIT_CANDIDATE_REGULAR_FILE_CHUNK_CAP_BYTES (8U * 1024U * 1024U)
#define RAW_ALL_CLAIM_AUDIT_DISCOVERY_AGGRESSIVE_CHUNK_CAP_BYTES (8U * 1024U * 1024U)
#define RAW_ALL_CLAIM_AUDIT_CANDIDATE_AGGRESSIVE_CHUNK_CAP_BYTES (16U * 1024U * 1024U)
#define RAW_ALL_REGULAR_FILE_LIVE_METADATA_STRIDE_BYTES (64ULL * 1024ULL * 1024ULL)
#define RAW_ALL_REGULAR_FILE_LIVE_METADATA_RICH_STRIDE_BYTES (128ULL * 1024ULL * 1024ULL)
#define RAW_ALL_REGULAR_FILE_LIVE_METADATA_RECORD_INDEX_READY 32768U
#define RAW_ALL_REGULAR_FILE_LIVE_METADATA_RECORD_INDEX_RICH 131072U
#define RAW_ALL_REGULAR_FILE_LIVE_METADATA_RANGE_INDEX_READY 8192U
#define RAW_ALL_REGULAR_FILE_LIVE_METADATA_RANGE_INDEX_RICH 32768U
#define RAW_ALL_REGULAR_FILE_LIVE_METADATA_I30_READY 32768U
#define RAW_ALL_REGULAR_FILE_LIVE_METADATA_I30_RICH 131072U

static int raw_all_should_stop(void)
{
    return app_stop_requested() ||
           app_source_reconnect_requested();
}

static int raw_all_background_worker_is_healthy(void)
{
    if (!fs_backend_background_worker_expected_running()) {
        return 1;
    }
    if (fs_backend_background_worker_running()) {
        return 1;
    }

    log_runtime_event_error(
        "Filesystem metadata background helper exited unexpectedly during raw-all; stopping this pass so the supervisor can restart cleanly from saved state instead of leaving a zombie child behind"
    );
    return 0;
}

typedef struct {
    uint64_t passes;
    uint64_t records_observed;
    uint64_t bytes_scanned;
    double seconds_total;
} MetadataObserveStats;

typedef enum {
    RAW_ALL_RESOURCE_PROFILE_CONSTRAINED = 0,
    RAW_ALL_RESOURCE_PROFILE_BALANCED = 1,
    RAW_ALL_RESOURCE_PROFILE_AGGRESSIVE = 2
} RawAllResourceProfile;

static const char *raw_all_resource_profile_label(RawAllResourceProfile profile)
{
    switch (profile) {
        case RAW_ALL_RESOURCE_PROFILE_AGGRESSIVE:
            return "aggressive";
        case RAW_ALL_RESOURCE_PROFILE_BALANCED:
            return "balanced";
        default:
            return "constrained";
    }
}

typedef struct {
    uint64_t abs_offset;
    uint64_t end_offset;
    uint64_t logical_start;
    uint64_t logical_length;
} PrimaryMetadataRunWindow;

typedef struct {
    FsDirectoryIndexTarget target;
    uint64_t end_offset;
} LiveDirectoryIndexWindow;

typedef struct {
    const char *phase_label;
    uint64_t probe_length;
    uint64_t bootstrap_length;
    uint64_t fallback_length;
    uint64_t runlist_target_bytes;
    double max_seconds;
    size_t max_chunk_bytes;
    int include_mirror_before;
    int include_mirror_after;
    int reverse_primary_windows_after;
    int reverse_prefetched_windows_after;
    int disable_live_observation_on_fail;
    int skip_if_attached;
} PrimaryMetadataAcquirePlan;

typedef struct {
    PlatformProcessResourceUsage usage;
    double sampled_at;
    double cpu_percent;
    double io_wait_percent;
    double cores_used;
    long cpu_count;
    int have_usage;
} RawAllResourceSample;

typedef struct {
    double sampled_at;
    double cpu_total_seconds;
    double io_wait_seconds;
    int valid;
} RawAllResourceRateBaseline;

static MetadataObserveStats g_metadata_observe_stats = {0};
static MetadataObserveStats g_metadata_observe_stats_last_logged = {0};
static FsBackendProcessStats g_metadata_process_stats_last_logged = {0};
static FormatPipelineLiveStats g_format_pipeline_live_stats_last_logged = {0};
static FsBackendLiveStats g_metadata_live_stats_last_logged = {0};
static CarverJpegStats g_jpeg_stats_last_logged = {0};
static CarverJpegLastExtendedFailure g_jpeg_last_extended_failure_logged = {0};
static CarverPngStats g_png_stats_last_logged = {0};
static int g_raw_all_metadata_observe_mode = -1;
static int g_raw_all_passive_indx_live_scan_suppressed_logged = 0;
static int g_raw_all_passive_indx_live_scan_enabled_logged = 0;
static double g_last_working_queue_stats_update_at = 0.0;
static PrimaryMetadataRunWindow *g_primary_metadata_run_windows = NULL;
static size_t g_primary_metadata_run_window_count = 0;
static size_t g_primary_metadata_run_window_cursor = 0;
static size_t g_primary_metadata_run_source_count = 0;
static uint64_t g_primary_metadata_prefetched_logical_bytes = 0U;
static LiveDirectoryIndexWindow *g_live_directory_index_windows = NULL;
static size_t g_live_directory_index_window_count = 0U;
static size_t g_live_directory_index_window_cursor = 0U;
static size_t g_live_directory_index_window_source_entry_count = 0U;
static uint64_t g_live_directory_index_window_source_stored_entries = 0ULL;
static long long g_live_directory_index_window_source_primary_start = -1LL;
static long long g_live_directory_index_window_source_partition_start = -1LL;
static int g_primary_metadata_bootstrap_should_disable_live_observation = 0;
static double g_primary_metadata_acquire_deadline_at = 0.0;
static size_t g_primary_metadata_chunk_cap_bytes = 0U;
static int g_primary_metadata_budget_yield_logged = 0;
static double g_primary_metadata_progress_last_write_at = 0.0;
static char g_primary_metadata_progress_phase_label[64] = "";
static RawAllResourceRateBaseline g_raw_all_resource_rate_baseline = {0};
static RawAllResourceProfile g_raw_all_active_resource_profile =
    RAW_ALL_RESOURCE_PROFILE_CONSTRAINED;
static size_t g_raw_all_active_discovery_worker_count = 1U;
static size_t g_raw_all_active_validation_worker_count = 1U;
typedef struct {
    char output_dir[PATH_MAX_LEN];
    double refreshed_at;
    size_t recovered_files;
    size_t named_files;
    size_t unident_files;
    int valid;
} RawAllRecoveredStateCache;
static RawAllRecoveredStateCache g_raw_all_recovered_state_cache = {0};
static MetadataCandidateStats g_raw_all_metadata_candidate_stats = {0};
typedef struct {
    uint64_t region_base;
    uint64_t slow_candidates;
    double slow_seconds;
    uint64_t png_no_iend_base;
    uint64_t png_recovered_base;
    double last_logged_seconds;
} RawAllLowYieldRegionStats;
static RawAllLowYieldRegionStats g_low_yield_region = {0};

static int raw_all_get_metadata_candidate_context(
    uint64_t absolute_offset,
    MetadataIndexCandidateContext *context_out,
    int *counted_out)
{
    int count_observation;
    int result;

    if (counted_out != NULL) *counted_out = 0;
    if (context_out == NULL) return 0;
    memset(context_out, 0, sizeof(*context_out));
    if (fs_backend_current_kind() != FS_BACKEND_KIND_HFSPLUS) return 0;
    count_observation = metadata_candidate_stats_note_offset(
        &g_raw_all_metadata_candidate_stats,
        absolute_offset);
    if (count_observation && counted_out != NULL) *counted_out = 1;
    result = fs_backend_get_candidate_context(absolute_offset, context_out);
    if (result < 0) {
        if (count_observation) {
            g_raw_all_metadata_candidate_stats.lookup_failures++;
        }
        memset(context_out, 0, sizeof(*context_out));
        return 0;
    }
    if (!count_observation) return 1;
    if (result == 0 || !context_out->has_owner) {
        g_raw_all_metadata_candidate_stats.no_owner++;
        return 1;
    }
    if (!context_out->unique_owner) {
        g_raw_all_metadata_candidate_stats.ambiguous_owner++;
    } else if (context_out->fork.fork_kind != METADATA_INDEX_FORK_DATA) {
        g_raw_all_metadata_candidate_stats.non_data_owner++;
    } else if (!context_out->complete_data_fork) {
        g_raw_all_metadata_candidate_stats.incomplete_owner++;
    } else if (context_out->exact_file_start) {
        g_raw_all_metadata_candidate_stats.trusted_exact_start++;
    } else {
        g_raw_all_metadata_candidate_stats.trusted_interior++;
    }
    return 1;
}

static int raw_all_candidate_stats_path_local(
    const AppConfig *config,
    char *out,
    size_t out_size)
{
    if (config == NULL || config->output_dir == NULL ||
        config->output_dir[0] == '\0' || out == NULL || out_size == 0U) {
        return 0;
    }
    return snprintf(
               out,
               out_size,
               "%s/%s/raw_candidate_stats.txt",
               config->output_dir,
               APP_STATE_DIR_NAME) < (int)out_size;
}

static void raw_all_load_candidate_stats_state(const AppConfig *config)
{
    char path[PATH_MAX_LEN];
    char line[256];
    FILE *file;
    MetadataCandidateStats loaded = {0};
    unsigned long long value;

    if (!raw_all_candidate_stats_path_local(config, path, sizeof(path))) return;
    file = fopen(path, "r");
    if (file == NULL) return;
    while (fgets(line, sizeof(line), file) != NULL) {
        if (sscanf(line, "lookups=%llu", &value) == 1) loaded.lookups = value;
        else if (sscanf(line, "lookup_failures=%llu", &value) == 1) loaded.lookup_failures = value;
        else if (sscanf(line, "no_owner=%llu", &value) == 1) loaded.no_owner = value;
        else if (sscanf(line, "ambiguous_owner=%llu", &value) == 1) loaded.ambiguous_owner = value;
        else if (sscanf(line, "non_data_owner=%llu", &value) == 1) loaded.non_data_owner = value;
        else if (sscanf(line, "incomplete_owner=%llu", &value) == 1) loaded.incomplete_owner = value;
        else if (sscanf(line, "trusted_exact_start=%llu", &value) == 1) loaded.trusted_exact_start = value;
        else if (sscanf(line, "trusted_interior=%llu", &value) == 1) loaded.trusted_interior = value;
        else if (sscanf(line, "shared_with_dispatch=%llu", &value) == 1) loaded.shared_with_dispatch = value;
        else if (sscanf(line, "high_water_offset=%llu", &value) == 1) loaded.high_water_offset = value;
        else if (sscanf(line, "high_water_valid=%llu", &value) == 1) loaded.high_water_valid = value != 0ULL;
    }
    (void)fclose(file);
    if (metadata_candidate_stats_is_consistent(&loaded)) {
        g_raw_all_metadata_candidate_stats = loaded;
    }
}

static int raw_all_write_candidate_stats_state(const AppConfig *config)
{
    char path[PATH_MAX_LEN];
    char temp_path[PATH_MAX_LEN + 32];
    FILE *file;

    if (fs_backend_current_kind() != FS_BACKEND_KIND_HFSPLUS ||
        !raw_all_candidate_stats_path_local(config, path, sizeof(path)) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >=
            (int)sizeof(temp_path)) {
        return 0;
    }
    file = fopen(temp_path, "w");
    if (file == NULL) return 0;
    fprintf(file, "format_version=1\n");
    fprintf(file, "backend=hfsplus\n");
    fprintf(file, "semantics=unique_monotonic_candidate_offsets\n");
    fprintf(file, "supervisor_generation=%llu\n",
            (unsigned long long)carv_run_supervisor_generation_inline());
    fprintf(file, "updated_unix=%llu\n", (unsigned long long)time(NULL));
    fprintf(file, "lookups=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.lookups);
    fprintf(file, "lookup_failures=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.lookup_failures);
    fprintf(file, "no_owner=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.no_owner);
    fprintf(file, "ambiguous_owner=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.ambiguous_owner);
    fprintf(file, "non_data_owner=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.non_data_owner);
    fprintf(file, "incomplete_owner=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.incomplete_owner);
    fprintf(file, "trusted_exact_start=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.trusted_exact_start);
    fprintf(file, "trusted_interior=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.trusted_interior);
    fprintf(file, "shared_with_dispatch=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.shared_with_dispatch);
    fprintf(file, "high_water_valid=%d\n", g_raw_all_metadata_candidate_stats.high_water_valid ? 1 : 0);
    fprintf(file, "high_water_offset=%llu\n", (unsigned long long)g_raw_all_metadata_candidate_stats.high_water_offset);
    if (fclose(file) != 0) {
        (void)remove(temp_path);
        return 0;
    }
    if (rename(temp_path, path) != 0) {
        (void)remove(temp_path);
        return 0;
    }
    (void)chmod(path, 0644);
    return fs_backend_apply_output_owner_to_path(path);
}

typedef struct {
    uint64_t *offsets;
    size_t count;
    size_t capacity;
} RawAllDeferredJpegStarts;

typedef enum {
    RAW_ALL_IMAGE_SAFETY_JPEG = 1,
    RAW_ALL_IMAGE_SAFETY_PNG = 2,
    RAW_ALL_IMAGE_SAFETY_MOV = 3,
    RAW_ALL_IMAGE_SAFETY_RIFF = 4,
    RAW_ALL_IMAGE_SAFETY_MPEG_PS = 5,
    RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT = 6,
    RAW_ALL_IMAGE_SAFETY_AAC = 7,
    RAW_ALL_IMAGE_SAFETY_PDF = 8,
    RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT = 9,
    RAW_ALL_IMAGE_SAFETY_MKV = 10,
    RAW_ALL_IMAGE_SAFETY_KIND_LIMIT = 11
} RawAllImageSafetyKind;

typedef struct RawAllImageSafetyQueue RawAllImageSafetyQueue;
typedef struct RawAllImageSafetyCandidate RawAllImageSafetyCandidate;

typedef int (*RawAllClaimAuditProbeFn)(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t rel
);

typedef struct {
    uint64_t start;
    uint64_t end;
    RawAllImageSafetyKind preferred_kind;
    char reason[32];
} RawAllClaimAuditChildRange;

#define RAW_ALL_CLAIM_AUDIT_MAX_CHILD_RANGES 4U

typedef struct {
    int attempted;
    int recovered;
    size_t confirmed_span;
    uint64_t claim_span;
    char status[32];
    char reject_reason[64];
    char trailing_child_reason[32];
    RawAllClaimAuditChildRange child_ranges[RAW_ALL_CLAIM_AUDIT_MAX_CHILD_RANGES];
    size_t child_range_count;
    int child_range_truncated;
} RawAllClaimAuditValidation;

typedef int (*RawAllClaimAuditValidateFn)(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const RawAllImageSafetyCandidate *candidate,
    size_t start_offset,
    RawAllClaimAuditValidation *out
);

typedef struct {
    RawAllImageSafetyKind kind;
    const char *label;
    size_t min_bytes;
    int scan_in_video_audit;
    RawAllClaimAuditProbeFn probe;
    RawAllClaimAuditValidateFn validate;
} RawAllClaimAuditProbe;

struct RawAllImageSafetyCandidate {
    uint64_t offset;
    uint64_t owner_offset;
    uint64_t owner_end_offset;
    RawAllImageSafetyKind kind;
    int processed;
    char reason[32];
    char owner_label[48];
};

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t owner_offset;
    uint64_t owner_end_offset;
    RawAllImageSafetyKind preferred_kind;
    int scanned;
    char reason[32];
    char owner_label[48];
} RawAllImageSafetyInterval;

typedef struct {
    uint64_t region_start;
    uint64_t bytes_queued;
} RawAllImageSafetyRegionBudget;

struct RawAllImageSafetyQueue {
    RawAllImageSafetyCandidate *candidates;
    size_t candidate_count;
    size_t candidate_capacity;
    RawAllImageSafetyInterval *intervals;
    size_t interval_count;
    size_t interval_capacity;
    RawAllImageSafetyRegionBudget *regions;
    size_t region_count;
    size_t region_capacity;
    uint64_t interval_bytes_queued;
    uint64_t interval_bytes_dropped;
    uint64_t interval_region_bytes_dropped;
    uint64_t interval_generic_bytes_dropped;
    uint64_t video_audit_interval_bytes_queued;
    uint64_t video_audit_interval_bytes_dropped;
    uint64_t video_audit_interval_count;
    uint64_t child_audit_interval_bytes_queued;
    uint64_t child_audit_interval_bytes_dropped;
    uint64_t child_audit_interval_count;
    uint64_t candidate_duplicates;
    uint64_t candidate_capacity_drops;
    uint64_t interval_capacity_drops;
    uint64_t persisted_swallowed_loaded;
    uint64_t persisted_legacy_drop_loaded;
    uint64_t audit_intervals_scanned;
    uint64_t audit_bytes_scanned;
    uint64_t candidate_by_kind[RAW_ALL_IMAGE_SAFETY_KIND_LIMIT];
    uint64_t attempted_by_kind[RAW_ALL_IMAGE_SAFETY_KIND_LIMIT];
    uint64_t recovered_by_kind[RAW_ALL_IMAGE_SAFETY_KIND_LIMIT];
    uint64_t rejected_by_kind[RAW_ALL_IMAGE_SAFETY_KIND_LIMIT];
    uint64_t already_recovered_by_kind[RAW_ALL_IMAGE_SAFETY_KIND_LIMIT];
    uint64_t covered_by_earlier_by_kind[RAW_ALL_IMAGE_SAFETY_KIND_LIMIT];
    uint64_t child_ranges_emitted_by_kind[RAW_ALL_IMAGE_SAFETY_KIND_LIMIT];
    uint64_t child_ranges_truncated_by_kind[RAW_ALL_IMAGE_SAFETY_KIND_LIMIT];
    uint64_t validated_claim_span_by_kind[RAW_ALL_IMAGE_SAFETY_KIND_LIMIT];
    RawAllResourceProfile resource_profile;
    long resource_cpu_count;
    uint64_t resource_memory_total_bytes;
    uint64_t resource_memory_available_bytes;
    uint64_t max_interval_bytes;
    uint64_t max_total_bytes;
    uint64_t max_region_bytes;
    uint64_t video_max_interval_bytes;
    uint64_t video_max_total_bytes;
    uint64_t child_max_interval_bytes;
    uint64_t child_max_total_bytes;
    size_t discovery_chunk_cap_bytes;
    size_t candidate_chunk_cap_bytes;
    size_t discovery_worker_count;
    size_t validation_worker_count;
};

typedef struct {
    uint64_t *offsets;
    size_t count;
    size_t next_index;
    int loaded;
} RawAllTraceOffsets;
static RawAllTraceOffsets g_trace_offsets = {0};

#define RAW_ALL_LOW_YIELD_REGION_BYTES (64ULL * 1024ULL * 1024ULL)
#define RAW_ALL_LOW_YIELD_LOG_MIN_CANDIDATES 4ULL
#define RAW_ALL_LOW_YIELD_LOG_MIN_SECONDS 15.0
#define RAW_ALL_LOW_YIELD_LOG_REPEAT_SECONDS 20.0
#define RAW_ALL_IMAGE_SAFETY_MIN_CLAIM_BYTES (1ULL * 1024ULL * 1024ULL)
#define RAW_ALL_IMAGE_SAFETY_MAX_INTERVAL_BYTES (256ULL * 1024ULL * 1024ULL)
#define RAW_ALL_IMAGE_SAFETY_MAX_TOTAL_BYTES (4ULL * 1024ULL * 1024ULL * 1024ULL)
#define RAW_ALL_IMAGE_SAFETY_REGION_BYTES (1ULL * 1024ULL * 1024ULL * 1024ULL)
#define RAW_ALL_IMAGE_SAFETY_MAX_REGION_BYTES (128ULL * 1024ULL * 1024ULL)
#define RAW_ALL_IMAGE_SAFETY_GENERIC_CLAIM_BYTES (8ULL * 1024ULL * 1024ULL)
#define RAW_ALL_IMAGE_SAFETY_JPEG_JUMP_BYTES (64ULL * 1024ULL * 1024ULL)
#define RAW_ALL_IMAGE_SAFETY_DENSE_LOOKBACK_BYTES (12ULL * 1024ULL * 1024ULL)
#define RAW_ALL_PDF_SAFETY_MIN_CLAIM_BYTES (128ULL * 1024ULL)
#define RAW_ALL_VIDEO_AUDIT_MAX_INTERVAL_BYTES (16ULL * 1024ULL * 1024ULL)
#define RAW_ALL_VIDEO_AUDIT_MAX_TOTAL_BYTES (512ULL * 1024ULL * 1024ULL)
#define RAW_ALL_CHILD_AUDIT_MAX_INTERVAL_BYTES (1536ULL * 1024ULL * 1024ULL)
#define RAW_ALL_CHILD_AUDIT_MAX_TOTAL_BYTES (8ULL * 1024ULL * 1024ULL * 1024ULL)
#define RAW_ALL_IMAGE_SAFETY_MAX_CANDIDATES 131072U
#define RAW_ALL_CLAIM_AUDIT_MAX_DRAIN_PASSES 6U
#define RAW_ALL_IMAGE_SAFETY_MAX_INTERVALS 8192U
#define RAW_ALL_IMAGE_SAFETY_REPORT_NAME APP_STATE_DIR_NAME "/missed_image_candidates.tsv"
#define RAW_ALL_IMAGE_SAFETY_DROP_REPORT_NAME APP_STATE_DIR_NAME "/safety_interval_dropped.tsv"
#define RAW_ALL_SWALLOWED_INTERVALS_NAME APP_STATE_DIR_NAME "/swallowed_file_intervals.tsv"
#define RAW_ALL_CLAIM_AUDIT_STATE_NAME APP_STATE_DIR_NAME "/claim_audit_state.tsv"
#define RAW_ALL_CLAIM_CANDIDATE_AUDIT_NAME APP_STATE_DIR_NAME "/claim_candidate_audit.tsv"
#define RAW_ALL_VIDEO_CANDIDATE_AUDIT_NAME APP_STATE_DIR_NAME "/video_candidate_audit.tsv"
#define RAW_ALL_PDF_CANDIDATE_AUDIT_NAME APP_STATE_DIR_NAME "/pdf_candidate_audit.tsv"

static int raw_all_diagnostic_audit_logs_enabled(void)
{
    const char *audit_logs = getenv("CARV_ENABLE_AUDIT_DETAIL_LOGS");
    const char *debug_logs = getenv("CARV_DEBUG_LOGS");

    return (audit_logs != NULL && audit_logs[0] != '\0' && audit_logs[0] != '0') ||
           (debug_logs != NULL && debug_logs[0] != '\0' && debug_logs[0] != '0');
}

static uint64_t raw_all_u64_or_default(uint64_t value, uint64_t fallback)
{
    return value > 0ULL ? value : fallback;
}

static size_t raw_all_size_or_default(size_t value, size_t fallback)
{
    return value > 0U ? value : fallback;
}

static long raw_all_online_cpu_count(void);

static uint64_t raw_all_scale_u64(uint64_t value, unsigned multiplier)
{
    if (multiplier <= 1U || value == 0ULL) {
        return value;
    }
    if (value > UINT64_MAX / (uint64_t)multiplier) {
        return UINT64_MAX;
    }
    return value * (uint64_t)multiplier;
}

static RawAllResourceProfile raw_all_detect_resource_profile(
    const Reader *reader,
    long *out_cpu_count,
    uint64_t *out_total_bytes,
    uint64_t *out_available_bytes
)
{
    PlatformSystemMemory memory = {0};
    long cpu_count = raw_all_online_cpu_count();
    uint64_t total_bytes = 0ULL;
    uint64_t available_bytes = 0ULL;
    const char *override = getenv("CARV_RESOURCE_PROFILE");

    if (out_cpu_count != NULL) {
        *out_cpu_count = cpu_count > 0 ? cpu_count : 0L;
    }
    if (out_total_bytes != NULL) {
        *out_total_bytes = 0ULL;
    }
    if (out_available_bytes != NULL) {
        *out_available_bytes = 0ULL;
    }

    if (override != NULL && override[0] != '\0') {
        if (strcmp(override, "aggressive") == 0) {
            return RAW_ALL_RESOURCE_PROFILE_AGGRESSIVE;
        }
        if (strcmp(override, "balanced") == 0) {
            return RAW_ALL_RESOURCE_PROFILE_BALANCED;
        }
        if (strcmp(override, "constrained") == 0 ||
            strcmp(override, "safe") == 0) {
            return RAW_ALL_RESOURCE_PROFILE_CONSTRAINED;
        }
    }

    if (platform_get_system_memory(&memory)) {
        total_bytes = memory.has_total ? memory.total_bytes : 0ULL;
        available_bytes = memory.has_available ? memory.available_bytes : 0ULL;
        if (out_total_bytes != NULL) {
            *out_total_bytes = total_bytes;
        }
        if (out_available_bytes != NULL) {
            *out_available_bytes = available_bytes;
        }
    }

    if (reader == NULL || !reader->source_is_regular_file) {
        return RAW_ALL_RESOURCE_PROFILE_CONSTRAINED;
    }

    if (cpu_count > 0 &&
        cpu_count <= 4 &&
        ((available_bytes > 0ULL &&
          available_bytes < 4ULL * 1024ULL * 1024ULL * 1024ULL) ||
         (total_bytes > 0ULL &&
          total_bytes < 8ULL * 1024ULL * 1024ULL * 1024ULL))) {
        return RAW_ALL_RESOURCE_PROFILE_CONSTRAINED;
    }

    if (cpu_count >= 8 &&
        ((available_bytes >= 10ULL * 1024ULL * 1024ULL * 1024ULL) ||
         (total_bytes >= 16ULL * 1024ULL * 1024ULL * 1024ULL))) {
        return RAW_ALL_RESOURCE_PROFILE_AGGRESSIVE;
    }

    return RAW_ALL_RESOURCE_PROFILE_BALANCED;
}

static void raw_all_image_safety_queue_configure(
    RawAllImageSafetyQueue *queue,
    const Reader *reader
)
{
    unsigned multiplier = 1U;
    long cpu_count = 0L;
    uint64_t total_bytes = 0ULL;
    uint64_t available_bytes = 0ULL;

    if (queue == NULL) {
        return;
    }

    queue->resource_profile = raw_all_detect_resource_profile(
        reader,
        &cpu_count,
        &total_bytes,
        &available_bytes);
    queue->resource_cpu_count = cpu_count;
    queue->resource_memory_total_bytes = total_bytes;
    queue->resource_memory_available_bytes = available_bytes;

    if (queue->resource_profile == RAW_ALL_RESOURCE_PROFILE_AGGRESSIVE) {
        multiplier = 2U;
    } else if (queue->resource_profile == RAW_ALL_RESOURCE_PROFILE_BALANCED &&
               reader != NULL &&
               reader->source_is_regular_file) {
        multiplier = 1U;
    }

    queue->max_interval_bytes =
        raw_all_scale_u64(RAW_ALL_IMAGE_SAFETY_MAX_INTERVAL_BYTES, multiplier);
    queue->max_total_bytes =
        raw_all_scale_u64(RAW_ALL_IMAGE_SAFETY_MAX_TOTAL_BYTES, multiplier);
    queue->max_region_bytes =
        raw_all_scale_u64(RAW_ALL_IMAGE_SAFETY_MAX_REGION_BYTES, multiplier);
    queue->video_max_interval_bytes =
        raw_all_scale_u64(RAW_ALL_VIDEO_AUDIT_MAX_INTERVAL_BYTES, multiplier);
    queue->video_max_total_bytes =
        raw_all_scale_u64(RAW_ALL_VIDEO_AUDIT_MAX_TOTAL_BYTES, multiplier);
    queue->child_max_interval_bytes =
        raw_all_scale_u64(RAW_ALL_CHILD_AUDIT_MAX_INTERVAL_BYTES, multiplier);
    queue->child_max_total_bytes =
        raw_all_scale_u64(RAW_ALL_CHILD_AUDIT_MAX_TOTAL_BYTES, multiplier);

    queue->discovery_chunk_cap_bytes =
        reader != NULL && reader->source_is_regular_file
            ? RAW_ALL_CLAIM_AUDIT_DISCOVERY_REGULAR_FILE_CHUNK_CAP_BYTES
            : RAW_ALL_CLAIM_AUDIT_DISCOVERY_CHUNK_CAP_BYTES;
    queue->candidate_chunk_cap_bytes =
        reader != NULL && reader->source_is_regular_file
            ? RAW_ALL_CLAIM_AUDIT_CANDIDATE_REGULAR_FILE_CHUNK_CAP_BYTES
            : RAW_ALL_CLAIM_AUDIT_CANDIDATE_CHUNK_CAP_BYTES;

    if (queue->resource_profile == RAW_ALL_RESOURCE_PROFILE_AGGRESSIVE) {
        queue->discovery_chunk_cap_bytes =
            RAW_ALL_CLAIM_AUDIT_DISCOVERY_AGGRESSIVE_CHUNK_CAP_BYTES;
        queue->candidate_chunk_cap_bytes =
            RAW_ALL_CLAIM_AUDIT_CANDIDATE_AGGRESSIVE_CHUNK_CAP_BYTES;
        queue->discovery_worker_count = 3U;
    } else if (queue->resource_profile == RAW_ALL_RESOURCE_PROFILE_BALANCED &&
               reader != NULL &&
               reader->source_is_regular_file &&
               cpu_count >= 6) {
        queue->discovery_worker_count = 2U;
    } else {
        queue->discovery_worker_count = 1U;
    }

    if (cpu_count > 0 && queue->discovery_worker_count > (size_t)cpu_count / 2U) {
        queue->discovery_worker_count = (size_t)cpu_count / 2U;
        if (queue->discovery_worker_count == 0U) {
            queue->discovery_worker_count = 1U;
        }
    }

    queue->validation_worker_count = 1U;
    g_raw_all_active_resource_profile = queue->resource_profile;
    g_raw_all_active_discovery_worker_count = queue->discovery_worker_count;
    g_raw_all_active_validation_worker_count = queue->validation_worker_count;

    log_info(
        "Raw-all audit tuning: profile=%s cpu=%ld memory_total=%.1f GiB memory_available=%.1f GiB discovery_workers=%zu validation_workers=%zu discovery_chunk=%.1f MiB candidate_chunk=%.1f MiB child_budget=%.1f GiB video_budget=%.1f GiB",
        raw_all_resource_profile_label(queue->resource_profile),
        cpu_count > 0 ? cpu_count : 0L,
        (double)total_bytes / (1024.0 * 1024.0 * 1024.0),
        (double)available_bytes / (1024.0 * 1024.0 * 1024.0),
        queue->discovery_worker_count,
        queue->validation_worker_count,
        (double)queue->discovery_chunk_cap_bytes / (1024.0 * 1024.0),
        (double)queue->candidate_chunk_cap_bytes / (1024.0 * 1024.0),
        (double)queue->child_max_total_bytes / (1024.0 * 1024.0 * 1024.0),
        (double)queue->video_max_total_bytes / (1024.0 * 1024.0 * 1024.0)
    );
}

static double scanner_now_seconds(void);
static RawAllResourceSample raw_all_sample_resource_usage(void);

static long raw_all_online_cpu_count(void)
{
    long cpu_count = 0L;

#ifdef __APPLE__
    {
        int logical_cpu = 0;
        size_t logical_cpu_size = sizeof(logical_cpu);

        if (sysctlbyname(
                "hw.logicalcpu",
                &logical_cpu,
                &logical_cpu_size,
                NULL,
                0) == 0 &&
            logical_cpu > 0) {
            cpu_count = (long)logical_cpu;
        }
    }
#elif defined(__linux__)
    cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
#endif

    return cpu_count > 0 ? cpu_count : 0L;
}
static int write_raw_all_activity_state(
    const AppConfig *config,
    Reader *reader,
    uint64_t scan_offset,
    int skip_live_metadata_observation
);
static uint64_t raw_all_effective_progress_total_bytes(
    const Reader *reader,
    const AppConfig *config
);
static size_t primary_metadata_effective_chunk_cap_bytes(
    const Reader *reader,
    size_t base_cap_bytes
);
static size_t raw_all_claim_audit_effective_chunk_cap_bytes(
    const RawAllImageSafetyQueue *queue,
    const Reader *reader,
    RawAllImageSafetyKind kind,
    int discovery_pass
);
static int raw_all_should_scan_passive_directory_signatures_live(
    const Reader *reader,
    int live_main_scan
);
static int raw_all_regular_file_live_metadata_picture_established(
    FsBackendLiveStats *out_live_stats,
    size_t *out_i30_names
);
static int raw_all_should_run_live_metadata_now(
    const Reader *reader,
    uint64_t buffer_base_offset,
    uint64_t *io_next_offset,
    int *io_logged_fast_path
);
static void raw_all_reset_recovered_state_cache(void);
static int raw_all_get_cached_recovered_state_summary(
    const char *output_dir,
    size_t *out_recovered_files,
    size_t *out_named_files,
    size_t *out_unident_files
);
static uint64_t raw_all_effective_progress_processed_bytes(
    const Reader *reader,
    const AppConfig *config,
    uint64_t processed_bytes
);
static uint64_t raw_all_effective_scan_end_offset(
    const Reader *reader,
    const AppConfig *config
);
static void raw_all_set_working_progress_limited(
    const Reader *reader,
    const AppConfig *config,
    uint64_t processed_bytes
);
static size_t raw_all_reader_read_next_limited(
    Reader *reader,
    uint64_t scan_limit
);
static void set_raw_all_signature_scan_activity(int skip_live_metadata_observation);
static int write_raw_all_metadata_live_stats(
    const AppConfig *config,
    const FsBackendLiveStats *metadata_stats
);
static void write_primary_metadata_progress_state(
    const char *phase_label,
    const char *step,
    const Reader *reader,
    uint64_t records_observed,
    uint64_t bytes_scanned,
    uint64_t range_start,
    uint64_t range_end,
    int force
);
static int scan_primary_metadata_range_observed(
    Reader *reader,
    uint64_t start,
    uint64_t observed_start,
    uint64_t length,
    int allow_unaligned,
    int stop_when_users_root_seen,
    uint64_t *out_records_observed,
    uint64_t *out_bytes_scanned
);
static int scan_primary_directory_index_targets(
    Reader *reader,
    uint64_t max_total_bytes,
    const char *phase_label,
    uint64_t *out_bytes_scanned
);
static size_t observe_directory_index_targets_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
static size_t observe_directory_index_signatures_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
);
static void maybe_write_raw_all_activity_state(
    const AppConfig *config,
    Reader *reader,
    uint64_t scan_offset,
    int skip_live_metadata_observation,
    double *io_last_activity_write_at,
    int force
);
static void log_all_live_stats_snapshot(void);
static void log_jpeg_stats_snapshot(void);
static void log_png_stats_snapshot(void);
static void note_foreground_candidate_activity(void);
static void note_low_yield_candidate_region(
    size_t absolute_offset,
    double candidate_seconds
);
static void raw_all_deferred_jpeg_starts_free(
    RawAllDeferredJpegStarts *queue
);
static int raw_all_deferred_jpeg_starts_push(
    RawAllDeferredJpegStarts *queue,
    uint64_t absolute_offset
);
static void raw_all_deferred_jpeg_starts_sort(
    RawAllDeferredJpegStarts *queue
);
static void raw_all_deferred_jpeg_starts_append_claim(
    RawAllDeferredJpegStarts *queue,
    const CarverJpegLastDominantClaim *claim
);
static uint32_t raw_all_deferred_jpeg_starts_append_large_exif_from_buffer(
    RawAllDeferredJpegStarts *queue,
    const uint8_t *buffer,
    size_t buffer_length,
    size_t buffer_base_offset,
    size_t start_offset,
    size_t owner_absolute_offset
);
static void raw_all_process_deferred_jpeg_starts(
    RawAllDeferredJpegStarts *queue,
    Reader *reader,
    const AppConfig *config,
    uint64_t primary_pass_end_offset,
    const FormatPipelineDispatchContext *dispatch_context
);
static void raw_all_image_safety_queue_free(
    RawAllImageSafetyQueue *queue
);
static void raw_all_image_safety_append_interval(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t start,
    uint64_t end,
    uint64_t owner_offset,
    uint64_t owner_end_offset,
    RawAllImageSafetyKind preferred_kind,
    const char *reason,
    const char *owner_label
);
static void raw_all_image_safety_append_dense_lookback(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t image_offset,
    uint64_t image_end,
    RawAllImageSafetyKind preferred_kind,
    const char *owner_label
);
static void raw_all_image_safety_append_jpeg_jump_audit(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t image_offset,
    uint64_t image_end,
    const char *owner_label
);
static void raw_all_image_safety_append_large_claim(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t owner_offset,
    uint64_t owner_end,
    const char *owner_label
);
static void raw_all_image_safety_process(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    uint64_t primary_pass_end_offset,
    const FormatPipelineDispatchContext *dispatch_context
);
static void raw_all_trace_offsets_maybe_load(void);
static void raw_all_trace_offsets_reset_progress(void);
static void raw_all_trace_offsets_note_buffer(
    const Reader *reader,
    size_t buffer_base_offset
);
static int primary_metadata_acquisition_should_yield(
    const Reader *reader,
    uint64_t read_errors_before,
    const char *scan_label,
    int disable_live_observation_on_fail
);
static int primary_metadata_acquisition_time_budget_reached(
    const char *scan_label
);

static const char *raw_all_dispatch_result_name(
    FormatPipelineDispatchResult result
)
{
    switch (result) {
        case FORMAT_PIPELINE_DISPATCH_NO_HANDLER:
            return "no_handler";
        case FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED:
            return "skipped_disabled";
        case FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE:
            return "handled_advance";
        case FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME:
            return "handled_resume";
        default:
            return "unknown";
    }
}

static const char *raw_all_match_label(
    const MagicEntry *match,
    char *buffer,
    size_t buffer_size
)
{
    const char *label = NULL;

    if (buffer == NULL || buffer_size == 0U) {
        return "unknown";
    }
    buffer[0] = '\0';

    if (match == NULL) {
        snprintf(buffer, buffer_size, "%s", "unknown");
        return buffer;
    }

    if (match->type_name != NULL && match->type_name[0] != '\0') {
        label = match->type_name;
    } else if (match->type != NULL && match->type[0] != '\0') {
        label = match->type;
    } else if (match->name != NULL && match->name[0] != '\0') {
        label = match->name;
    } else if (match->category != NULL && match->category[0] != '\0') {
        label = match->category;
    }

    if (label == NULL || label[0] == '\0') {
        snprintf(buffer, buffer_size, "magic-%d", match->id);
        return buffer;
    }

    snprintf(buffer, buffer_size, "%s", label);
    return buffer;
}

static int raw_all_buffer_has_jpeg_soi(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
)
{
    return buffer != NULL &&
           offset + 2U < buffer_length &&
           buffer[offset] == 0xFFU &&
           buffer[offset + 1U] == 0xD8U &&
           buffer[offset + 2U] == 0xFFU;
}

static int raw_all_debug_jpeg_direct_enabled(void)
{
    const char *env = getenv("CARV_DEBUG_JPEG_DIRECT");

    return env != NULL &&
           env[0] != '\0' &&
           strcmp(env, "0") != 0;
}

static int raw_all_find_first_jpeg_soi_in_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t *offset_out
)
{
    size_t i;

    if (offset_out != NULL) {
        *offset_out = 0U;
    }
    if (buffer == NULL || buffer_length < 3U) {
        return 0;
    }

    for (i = 0; i + 2U < buffer_length; i++) {
        if (raw_all_buffer_has_jpeg_soi(buffer, buffer_length, i)) {
            if (offset_out != NULL) {
                *offset_out = i;
            }
            return 1;
        }
    }
    return 0;
}

static void note_foreground_candidate_activity(void)
{
    fs_backend_note_foreground_activity();
}

static int primary_metadata_acquisition_should_yield(
    const Reader *reader,
    uint64_t read_errors_before,
    const char *scan_label,
    int disable_live_observation_on_fail
)
{
    uint64_t read_errors_after;
    uint64_t last_error_offset;
    uint64_t last_error_length;
    size_t run_count;

    if (reader == NULL) {
        return 0;
    }

    if (primary_metadata_acquisition_time_budget_reached(scan_label)) {
        return 1;
    }

    read_errors_after = reader_get_read_error_count(reader);
    if (read_errors_after <= read_errors_before) {
        return 0;
    }

    run_count = fs_backend_primary_run_count();
    if (run_count > 0U || fs_backend_has_primary_catalog_root()) {
        return 0;
    }

    last_error_offset = reader_get_last_read_error_offset(reader);
    last_error_length = reader_get_last_read_error_length(reader);
    if (disable_live_observation_on_fail) {
        /*
         * Early trouble in the primary window is not proof that the source
         * lacks useful NTFS metadata. Rescueable disks can still yield good
         * MFT records later in the main scan, so leave live observation
         * enabled and simply stop the synchronous bootstrap pass here.
         */
        g_primary_metadata_bootstrap_should_disable_live_observation = 0;
        log_info(
            "Primary metadata acquisition hit read trouble during %s before a usable root/runlist was found (bad span at byte %llu length %llu); keeping live filesystem metadata observation enabled so the main scan can keep discovering MFT records outside the early bootstrap window",
            (scan_label != NULL && scan_label[0] != '\0') ? scan_label : "startup scan",
            (unsigned long long)last_error_offset,
            (unsigned long long)last_error_length
        );
    } else {
        log_info(
            "Primary metadata revisit hit read trouble during %s before a usable root/runlist was found (bad span at byte %llu length %llu); keeping the current metadata state and continuing the main workflow",
            (scan_label != NULL && scan_label[0] != '\0') ? scan_label : "metadata revisit",
            (unsigned long long)last_error_offset,
            (unsigned long long)last_error_length
        );
    }
    return 1;
}

static int primary_metadata_acquisition_time_budget_reached(
    const char *scan_label
)
{
    if (g_primary_metadata_acquire_deadline_at <= 0.0) {
        return 0;
    }
    if (scanner_now_seconds() < g_primary_metadata_acquire_deadline_at) {
        return 0;
    }
    if (!g_primary_metadata_budget_yield_logged) {
        g_primary_metadata_budget_yield_logged = 1;
        log_info(
            "Primary metadata %s reached its time budget; keeping the metadata found so far and continuing the main workflow instead of sitting in a long synchronous reread",
            (scan_label != NULL && scan_label[0] != '\0') ? scan_label : "acquisition"
        );
    }
    return 1;
}

static void note_low_yield_candidate_region(
    size_t absolute_offset,
    double candidate_seconds
)
{
    uint64_t region_base =
        ((uint64_t)absolute_offset / RAW_ALL_LOW_YIELD_REGION_BYTES) *
        RAW_ALL_LOW_YIELD_REGION_BYTES;
    CarverPngStats png_stats;
    uint64_t png_no_iend_delta;
    uint64_t png_recovered_delta;

    if (g_low_yield_region.region_base != region_base) {
        memset(&g_low_yield_region, 0, sizeof(g_low_yield_region));
        g_low_yield_region.region_base = region_base;
        carver_png_get_stats(&png_stats);
        g_low_yield_region.png_no_iend_base = png_stats.extended_window_failed_no_iend;
        g_low_yield_region.png_recovered_base = png_stats.extended_window_recovered;
    }

    g_low_yield_region.slow_candidates++;
    g_low_yield_region.slow_seconds += candidate_seconds;

    carver_png_get_stats(&png_stats);
    png_no_iend_delta =
        png_stats.extended_window_failed_no_iend -
        g_low_yield_region.png_no_iend_base;
    png_recovered_delta =
        png_stats.extended_window_recovered -
        g_low_yield_region.png_recovered_base;

    if (g_low_yield_region.slow_candidates < RAW_ALL_LOW_YIELD_LOG_MIN_CANDIDATES ||
        g_low_yield_region.slow_seconds < RAW_ALL_LOW_YIELD_LOG_MIN_SECONDS) {
        return;
    }
    if (g_low_yield_region.last_logged_seconds > 0.0 &&
        g_low_yield_region.slow_seconds <
            g_low_yield_region.last_logged_seconds + RAW_ALL_LOW_YIELD_LOG_REPEAT_SECONDS) {
        return;
    }

    log_info(
        "All low-yield region: %.1f-%.1f GiB slow_candidates=%llu dt=%.2fs png_noiend=%llu png_recovered=%llu; still working, but this region is mostly producing incomplete image candidates",
        (double)g_low_yield_region.region_base /
            (1024.0 * 1024.0 * 1024.0),
        (double)(g_low_yield_region.region_base + RAW_ALL_LOW_YIELD_REGION_BYTES) /
            (1024.0 * 1024.0 * 1024.0),
        (unsigned long long)g_low_yield_region.slow_candidates,
        g_low_yield_region.slow_seconds,
        (unsigned long long)png_no_iend_delta,
        (unsigned long long)png_recovered_delta
    );
    g_low_yield_region.last_logged_seconds = g_low_yield_region.slow_seconds;
}

static void raw_all_deferred_jpeg_starts_free(
    RawAllDeferredJpegStarts *queue
)
{
    if (queue == NULL) {
        return;
    }

    free(queue->offsets);
    memset(queue, 0, sizeof(*queue));
}

static int compare_u64_local(const void *left, const void *right)
{
    const uint64_t a = *(const uint64_t *)left;
    const uint64_t b = *(const uint64_t *)right;

    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}

static void raw_all_trace_offsets_maybe_load(void)
{
    const char *env;
    char *copy;
    char *token;
    size_t count = 0U;

    if (g_trace_offsets.loaded) {
        return;
    }
    g_trace_offsets.loaded = 1;
    env = getenv("CARV_TRACE_OFFSETS");
    if (env == NULL || env[0] == '\0') {
        return;
    }

    copy = strdup(env);
    if (copy == NULL) {
        return;
    }

    token = strtok(copy, ", ");
    while (token != NULL) {
        char *end = NULL;
        unsigned long long value = strtoull(token, &end, 10);
        if (end != token && *end == '\0') {
            uint64_t *grown = (uint64_t *)realloc(
                g_trace_offsets.offsets,
                (count + 1U) * sizeof(*g_trace_offsets.offsets));
            if (grown == NULL) {
                free(copy);
                return;
            }
            g_trace_offsets.offsets = grown;
            g_trace_offsets.offsets[count++] = (uint64_t)value;
        }
        token = strtok(NULL, ", ");
    }
    free(copy);

    if (count == 0U) {
        free(g_trace_offsets.offsets);
        g_trace_offsets.offsets = NULL;
        return;
    }

    qsort(
        g_trace_offsets.offsets,
        count,
        sizeof(*g_trace_offsets.offsets),
        compare_u64_local
    );
    g_trace_offsets.count = count;
    g_trace_offsets.next_index = 0U;
    log_info(
        "Raw-all trace offsets loaded: %zu target%s",
        count,
        count == 1U ? "" : "s"
    );
}

static void raw_all_trace_offsets_reset_progress(void)
{
    raw_all_trace_offsets_maybe_load();
    g_trace_offsets.next_index = 0U;
}

static void raw_all_trace_offsets_note_buffer(
    const Reader *reader,
    size_t buffer_base_offset
)
{
    uint64_t buffer_end;

    raw_all_trace_offsets_maybe_load();
    if (reader == NULL ||
        reader->buffer == NULL ||
        reader->bytes_in_buffer < 8U ||
        g_trace_offsets.count == 0U) {
        return;
    }

    buffer_end = (uint64_t)buffer_base_offset + (uint64_t)reader->bytes_in_buffer;
    while (g_trace_offsets.next_index < g_trace_offsets.count) {
        uint64_t target = g_trace_offsets.offsets[g_trace_offsets.next_index];
        size_t exif_span = 0U;
        size_t rel;
        const unsigned char *p;
        int large_exif;

        if (target < (uint64_t)buffer_base_offset) {
            g_trace_offsets.next_index++;
            continue;
        }
        if (target + 8U > buffer_end) {
            break;
        }

        rel = (size_t)(target - (uint64_t)buffer_base_offset);
        p = reader->buffer + rel;
        large_exif = carver_jpeg_has_large_leading_exif(
            reader->buffer,
            reader->bytes_in_buffer,
            rel,
            &exif_span
        );
        log_info(
            "Trace offset %llu visible in buffer: bytes=%02X %02X %02X %02X %02X %02X exif_span=%zu large_exif=%d",
            (unsigned long long)target,
            (unsigned)p[0],
            (unsigned)p[1],
            (unsigned)p[2],
            (unsigned)p[3],
            (unsigned)p[4],
            (unsigned)p[5],
            exif_span,
            large_exif
        );
        g_trace_offsets.next_index++;
    }
}

static int raw_all_deferred_jpeg_starts_push(
    RawAllDeferredJpegStarts *queue,
    uint64_t absolute_offset
)
{
    size_t i;

    if (queue == NULL || absolute_offset == 0U) {
        return 0;
    }
    if (absolute_offset != UINT64_MAX &&
        fs_backend_range_has_trusted_metadata_owner(
            absolute_offset,
            absolute_offset + 1U)) {
        return 0;
    }

    for (i = 0; i < queue->count; i++) {
        if (queue->offsets[i] == absolute_offset) {
            return 0;
        }
    }

    if (queue->count == queue->capacity) {
        size_t new_capacity = queue->capacity == 0U ? 32U : queue->capacity * 2U;
        uint64_t *grown = (uint64_t *)realloc(
            queue->offsets,
            new_capacity * sizeof(*queue->offsets));
        if (grown == NULL) {
            return 0;
        }
        queue->offsets = grown;
        queue->capacity = new_capacity;
    }

    queue->offsets[queue->count++] = absolute_offset;
    return 1;
}

static int raw_all_deferred_jpeg_starts_compare(
    const void *left,
    const void *right
)
{
    const uint64_t a = *(const uint64_t *)left;
    const uint64_t b = *(const uint64_t *)right;

    if (a < b) {
        return -1;
    }
    if (a > b) {
        return 1;
    }
    return 0;
}

static void raw_all_deferred_jpeg_starts_sort(
    RawAllDeferredJpegStarts *queue
)
{
    if (queue == NULL || queue->count < 2U) {
        return;
    }

    qsort(
        queue->offsets,
        queue->count,
        sizeof(*queue->offsets),
        raw_all_deferred_jpeg_starts_compare
    );
}

static void raw_all_deferred_jpeg_starts_append_claim(
    RawAllDeferredJpegStarts *queue,
    const CarverJpegLastDominantClaim *claim
)
{
    uint32_t appended = 0U;
    uint32_t i;

    if (queue == NULL || claim == NULL || !claim->active ||
        claim->revisit_count == 0U) {
        return;
    }

    for (i = 0U; i < claim->revisit_count; i++) {
        if (raw_all_deferred_jpeg_starts_push(queue, claim->revisit_offsets[i])) {
            appended++;
        }
    }

    log_verbose(
        "Deferred JPEG revisit queued: owner=%llu span=%.1f MiB revisit=%u%s total_queue=%zu",
        (unsigned long long)claim->absolute_offset,
        (double)claim->claimed_span / (1024.0 * 1024.0),
        appended,
        claim->revisit_overflow ? "+" : "",
        queue->count
    );
}

static uint32_t raw_all_deferred_jpeg_starts_append_large_exif_from_buffer(
    RawAllDeferredJpegStarts *queue,
    const uint8_t *buffer,
    size_t buffer_length,
    size_t buffer_base_offset,
    size_t start_offset,
    size_t owner_absolute_offset
)
{
    uint32_t appended = 0U;
    size_t rel;

    if (queue == NULL || buffer == NULL || buffer_length <= start_offset + 4U) {
        return 0U;
    }

    for (rel = start_offset + 1U; rel + 4U <= buffer_length; rel++) {
        size_t exif_span = 0U;
        uint64_t revisit_abs;

        if (buffer[rel] != 0xFFU ||
            buffer[rel + 1U] != 0xD8U ||
            buffer[rel + 2U] != 0xFFU ||
            buffer[rel + 3U] != 0xE1U) {
            continue;
        }
        if (!carver_jpeg_has_large_leading_exif(
                buffer,
                buffer_length,
                rel,
                &exif_span)) {
            continue;
        }

        revisit_abs = (uint64_t)buffer_base_offset + (uint64_t)rel;
        if (revisit_abs == (uint64_t)owner_absolute_offset) {
            continue;
        }
        if (raw_all_deferred_jpeg_starts_push(queue, revisit_abs)) {
            appended++;
        }
        if (exif_span > 4U) {
            rel += exif_span - 4U;
        }
    }

    if (appended > 0U) {
        log_verbose(
            "Deferred large Exif revisit queued: owner=%zu appended=%u total_queue=%zu",
            owner_absolute_offset,
            appended,
            queue->count
        );
    }

    return appended;
}

static void raw_all_process_deferred_jpeg_starts(
    RawAllDeferredJpegStarts *queue,
    Reader *reader,
    const AppConfig *config,
    uint64_t primary_pass_end_offset,
    const FormatPipelineDispatchContext *dispatch_context
)
{
    size_t index;
    uint64_t attempted = 0U;
    uint64_t recovered = 0U;
    uint64_t overlap_kept = 0U;

    if (queue == NULL || reader == NULL || queue->count == 0U) {
        return;
    }

    if (!format_pipeline_dispatch_context_allows_jpeg(dispatch_context)) {
        log_info(
            "Skipping %zu deferred JPEG revisit start%s because JPEG is not enabled in this run",
            queue->count,
            queue->count == 1U ? "" : "s"
        );
        return;
    }

    raw_all_deferred_jpeg_starts_sort(queue);

    log_info(
        "Processing %zu deferred JPEG revisit start%s after the primary raw-all pass",
        queue->count,
        queue->count == 1U ? "" : "s"
    );
    raw_all_set_working_progress_limited(reader, config, primary_pass_end_offset);

    for (index = 0U; index < queue->count && !raw_all_should_stop(); index++) {
        uint64_t absolute_offset = queue->offsets[index];
        size_t buffer_base_offset;
        size_t start_offset;
        size_t confirmed_span = 0U;
        CarverJpegLastDominantClaim nested_claim = {0};

        if (!reader_seek_absolute(reader, absolute_offset)) {
            continue;
        }
        if (reader_read_next(reader) == 0U) {
            continue;
        }

        buffer_base_offset = reader->total_bytes_read - reader->bytes_in_buffer;
        if (absolute_offset < (uint64_t)buffer_base_offset ||
            absolute_offset >= (uint64_t)(buffer_base_offset + reader->bytes_in_buffer)) {
            continue;
        }

        start_offset = (size_t)(absolute_offset - (uint64_t)buffer_base_offset);
        attempted++;
        raw_all_set_working_progress_limited(reader, config, absolute_offset);
        log_set_working_activity("revisiting deferred JPEG starts");
        note_foreground_candidate_activity();

        if (carver_jpeg_from_reader(
                reader,
                start_offset,
                (size_t)absolute_offset,
                &confirmed_span) &&
            confirmed_span > 0U) {
            uint64_t recovered_end = absolute_offset + (uint64_t)confirmed_span;
            size_t lookahead = index + 1U;

            recovered++;
            while (lookahead < queue->count &&
                   queue->offsets[lookahead] < recovered_end) {
                overlap_kept++;
                lookahead++;
            }
        }

        carver_jpeg_get_last_dominant_claim(&nested_claim);
        raw_all_deferred_jpeg_starts_append_claim(queue, &nested_claim);
    }

    log_info(
        "Deferred JPEG revisit finished: attempted=%llu recovered=%llu overlap_kept=%llu queue_total=%zu",
        (unsigned long long)attempted,
        (unsigned long long)recovered,
        (unsigned long long)overlap_kept,
        queue->count
    );
    set_raw_all_signature_scan_activity(1);
    raw_all_set_working_progress_limited(reader, config, primary_pass_end_offset);
    if (reader->total_bytes_read != (size_t)primary_pass_end_offset ||
        reader->bytes_in_buffer != 0U) {
        (void)reader_seek_absolute(reader, primary_pass_end_offset);
    }
}

static const char *raw_all_image_safety_kind_name(RawAllImageSafetyKind kind)
{
    switch (kind) {
        case RAW_ALL_IMAGE_SAFETY_JPEG:
            return "jpg";
        case RAW_ALL_IMAGE_SAFETY_PNG:
            return "png";
        case RAW_ALL_IMAGE_SAFETY_MOV:
            return "ftyp";
        case RAW_ALL_IMAGE_SAFETY_RIFF:
            return "riff";
        case RAW_ALL_IMAGE_SAFETY_MPEG_PS:
            return "mpeg_ps";
        case RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT:
            return "video_audit";
        case RAW_ALL_IMAGE_SAFETY_AAC:
            return "aac";
        case RAW_ALL_IMAGE_SAFETY_PDF:
            return "pdf";
        case RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT:
            return "child_audit";
        case RAW_ALL_IMAGE_SAFETY_MKV:
            return "mkv";
        default:
            return "unknown";
    }
}

static RawAllImageSafetyKind raw_all_image_safety_kind_from_name(const char *name)
{
    if (name == NULL) {
        return 0;
    }
    if (strcmp(name, "jpg") == 0 || strcmp(name, "jpeg") == 0) {
        return RAW_ALL_IMAGE_SAFETY_JPEG;
    }
    if (strcmp(name, "png") == 0) {
        return RAW_ALL_IMAGE_SAFETY_PNG;
    }
    if (strcmp(name, "ftyp") == 0 || strcmp(name, "mov") == 0 ||
        strcmp(name, "mp4") == 0) {
        return RAW_ALL_IMAGE_SAFETY_MOV;
    }
    if (strcmp(name, "riff") == 0 || strcmp(name, "avi") == 0) {
        return RAW_ALL_IMAGE_SAFETY_RIFF;
    }
    if (strcmp(name, "mpeg_ps") == 0 || strcmp(name, "mpg") == 0 ||
        strcmp(name, "mpeg") == 0) {
        return RAW_ALL_IMAGE_SAFETY_MPEG_PS;
    }
    if (strcmp(name, "video_audit") == 0) {
        return RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT;
    }
    if (strcmp(name, "aac") == 0) {
        return RAW_ALL_IMAGE_SAFETY_AAC;
    }
    if (strcmp(name, "pdf") == 0) {
        return RAW_ALL_IMAGE_SAFETY_PDF;
    }
    if (strcmp(name, "child_audit") == 0) {
        return RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT;
    }
    if (strcmp(name, "mkv") == 0 ||
        strcmp(name, "matroska") == 0 ||
        strcmp(name, "webm") == 0) {
        return RAW_ALL_IMAGE_SAFETY_MKV;
    }
    return 0;
}

static void raw_all_copy_small_string(char *out, size_t out_size, const char *value)
{
    if (out == NULL || out_size == 0U) {
        return;
    }
    if (value == NULL || value[0] == '\0') {
        value = "unknown";
    }
    snprintf(out, out_size, "%s", value);
}

static uint16_t raw_all_read_u16_be_local(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static uint32_t raw_all_read_u32_be_local(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static uint32_t raw_all_read_u32_le_local(const uint8_t *data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static int raw_all_fourcc_printable_local(const uint8_t *data)
{
    size_t i;

    if (data == NULL) {
        return 0;
    }
    for (i = 0U; i < 4U; i++) {
        if (data[i] < 0x20U || data[i] > 0x7eU) {
            return 0;
        }
    }
    return 1;
}

static int raw_all_png_ihdr_fields_plausible(const uint8_t *data)
{
    uint32_t width;
    uint32_t height;
    uint8_t bit_depth;
    uint8_t color_type;
    uint8_t compression_method;
    uint8_t filter_method;
    uint8_t interlace_method;
    int bit_depth_ok = 0;

    if (data == NULL) {
        return 0;
    }

    width = raw_all_read_u32_be_local(data);
    height = raw_all_read_u32_be_local(data + 4U);
    bit_depth = data[8U];
    color_type = data[9U];
    compression_method = data[10U];
    filter_method = data[11U];
    interlace_method = data[12U];

    if (width == 0U || height == 0U ||
        width > 200000U || height > 200000U ||
        compression_method != 0U ||
        filter_method != 0U ||
        interlace_method > 1U) {
        return 0;
    }

    switch (color_type) {
        case 0:
            bit_depth_ok = bit_depth == 1U || bit_depth == 2U ||
                           bit_depth == 4U || bit_depth == 8U ||
                           bit_depth == 16U;
            break;
        case 2:
        case 4:
        case 6:
            bit_depth_ok = bit_depth == 8U || bit_depth == 16U;
            break;
        case 3:
            bit_depth_ok = bit_depth == 1U || bit_depth == 2U ||
                           bit_depth == 4U || bit_depth == 8U;
            break;
        default:
            bit_depth_ok = 0;
            break;
    }

    return bit_depth_ok;
}

static int raw_all_image_safety_is_jpeg_start(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t rel
)
{
    uint8_t marker;
    uint16_t segment_length;

    if (buffer == NULL || rel + 6U > buffer_length) {
        return 0;
    }
    if (buffer[rel] != 0xFFU ||
        buffer[rel + 1U] != 0xD8U ||
        buffer[rel + 2U] != 0xFFU) {
        return 0;
    }

    marker = buffer[rel + 3U];
    if (marker == 0xD8U || marker == 0xD9U || marker == 0x00U) {
        return 0;
    }

    if (marker == 0xE0U || marker == 0xE1U || marker == 0xE2U) {
        segment_length = raw_all_read_u16_be_local(buffer + rel + 4U);
        if (segment_length < 8U) {
            return 0;
        }
        if (marker == 0xE0U &&
            segment_length >= 7U &&
            rel + 10U <= buffer_length &&
            memcmp(buffer + rel + 6U, "JFIF", 4U) == 0) {
            return 1;
        }
        if (marker == 0xE1U &&
            segment_length >= 8U &&
            ((rel + 12U <= buffer_length &&
              memcmp(buffer + rel + 6U, "Exif\0\0", 6U) == 0) ||
             (rel + 13U <= buffer_length &&
              memcmp(buffer + rel + 6U, "http://", 7U) == 0) ||
             (rel + 9U <= buffer_length &&
              memcmp(buffer + rel + 6U, "XMP", 3U) == 0))) {
            return 1;
        }
        if (marker == 0xE2U &&
            segment_length >= 14U &&
            rel + 17U <= buffer_length &&
            memcmp(buffer + rel + 6U, "ICC_PROFILE", 11U) == 0) {
            return 1;
        }
    }

    return 0;
}

static int raw_all_image_safety_is_png_start(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t rel
)
{
    static const uint8_t png_signature[8] =
        {0x89U, 'P', 'N', 'G', 0x0DU, 0x0AU, 0x1AU, 0x0AU};

    if (buffer == NULL || rel + 33U > buffer_length) {
        return 0;
    }
    if (memcmp(buffer + rel, png_signature, sizeof(png_signature)) != 0) {
        return 0;
    }
    if (raw_all_read_u32_be_local(buffer + rel + 8U) != 13U ||
        memcmp(buffer + rel + 12U, "IHDR", 4U) != 0) {
        return 0;
    }

    return raw_all_png_ihdr_fields_plausible(buffer + rel + 16U);
}

static int raw_all_image_safety_is_mov_start(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t rel
)
{
    uint32_t atom_size;

    if (buffer == NULL || rel + 16U > buffer_length) {
        return 0;
    }
    atom_size = raw_all_read_u32_be_local(buffer + rel);
    if (atom_size < 16U || atom_size > 4096U) {
        return 0;
    }
    if (memcmp(buffer + rel + 4U, "ftyp", 4U) != 0) {
        return 0;
    }
    return raw_all_fourcc_printable_local(buffer + rel + 8U);
}

static int raw_all_image_safety_is_riff_start(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t rel
)
{
    uint32_t riff_size;

    if (buffer == NULL || rel + 12U > buffer_length) {
        return 0;
    }
    if (memcmp(buffer + rel, "RIFF", 4U) != 0) {
        return 0;
    }
    if (!raw_all_fourcc_printable_local(buffer + rel + 8U)) {
        return 0;
    }
    riff_size = raw_all_read_u32_le_local(buffer + rel + 4U);
    return riff_size >= 4U && riff_size < (512U * 1024U * 1024U);
}

static int raw_all_image_safety_is_mpeg_ps_start(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t rel
)
{
    uint8_t control;

    if (buffer == NULL || rel + 4U > buffer_length) {
        return 0;
    }
    if (buffer[rel] != 0x00U ||
        buffer[rel + 1U] != 0x00U ||
        buffer[rel + 2U] != 0x01U ||
        buffer[rel + 3U] != 0xBAU ||
        rel + 12U > buffer_length) {
        return 0;
    }

    control = buffer[rel + 4U];
    if ((control & 0xF0U) == 0x20U) {
        return 1;
    }

    return rel + 14U <= buffer_length &&
           (control & 0xC4U) == 0x44U &&
           (buffer[rel + 6U] & 0x04U) != 0U &&
           (buffer[rel + 8U] & 0x04U) != 0U &&
           (buffer[rel + 9U] & 0x01U) != 0U &&
           (buffer[rel + 12U] & 0x01U) != 0U &&
           (buffer[rel + 13U] & 0xF8U) == 0xF8U;
}

static int raw_all_image_safety_is_mkv_start(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t rel
)
{
    size_t search_start;
    size_t search_end;
    size_t i;

    if (buffer == NULL || rel + 16U > buffer_length) {
        return 0;
    }
    if (buffer[rel] != 0x1AU ||
        buffer[rel + 1U] != 0x45U ||
        buffer[rel + 2U] != 0xDFU ||
        buffer[rel + 3U] != 0xA3U) {
        return 0;
    }

    search_start = rel + 4U;
    search_end = rel + 4096U;
    if (search_end > buffer_length) {
        search_end = buffer_length;
    }

    for (i = search_start; i + 8U <= search_end; i++) {
        if (memcmp(buffer + i, "matroska", 8U) == 0) {
            return 1;
        }
        if (i + 4U <= search_end && memcmp(buffer + i, "webm", 4U) == 0) {
            return 1;
        }
    }
    return 0;
}

static int raw_all_image_safety_is_pdf_start(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t rel
)
{
    if (buffer == NULL || rel + 8U > buffer_length) {
        return 0;
    }
    return memcmp(buffer + rel, "%PDF-", 5U) == 0 &&
           buffer[rel + 5U] >= '0' &&
           buffer[rel + 5U] <= '9' &&
           buffer[rel + 6U] == '.' &&
           buffer[rel + 7U] >= '0' &&
           buffer[rel + 7U] <= '9';
}

static int raw_all_image_safety_parse_aac_adts_header(
    const uint8_t *header,
    uint32_t *frame_length_out
)
{
    uint8_t profile;
    uint8_t sample_rate_index;
    uint8_t channel_config;
    uint32_t frame_length;
    uint32_t header_length;

    if (header == NULL) {
        return 0;
    }
    if (header[0] != 0xFFU || (header[1] & 0xF6U) != 0xF0U) {
        return 0;
    }

    profile = (header[2] >> 6) & 0x03U;
    sample_rate_index = (header[2] >> 2) & 0x0FU;
    channel_config = (uint8_t)(((header[2] & 0x01U) << 2) |
                               ((header[3] >> 6) & 0x03U));
    frame_length = ((uint32_t)(header[3] & 0x03U) << 11) |
                   ((uint32_t)header[4] << 3) |
                   ((uint32_t)header[5] >> 5);
    header_length = (header[1] & 0x01U) != 0U ? 7U : 9U;

    if (profile == 3U ||
        sample_rate_index == 0x0FU ||
        sample_rate_index >= 13U ||
        channel_config == 0U ||
        channel_config > 7U ||
        frame_length < header_length ||
        frame_length > 8192U) {
        return 0;
    }

    if (frame_length_out != NULL) {
        *frame_length_out = frame_length;
    }
    return 1;
}

static int raw_all_image_safety_is_aac_start(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t rel
)
{
    uint32_t first_frame_length = 0U;
    size_t next_rel;

    if (buffer == NULL || rel + 14U > buffer_length) {
        return 0;
    }
    if (!raw_all_image_safety_parse_aac_adts_header(
            buffer + rel,
            &first_frame_length)) {
        return 0;
    }

    next_rel = rel + (size_t)first_frame_length;
    if (next_rel + 7U > buffer_length) {
        return 0;
    }
    return raw_all_image_safety_parse_aac_adts_header(
        buffer + next_rel,
        NULL);
}

static int raw_all_image_safety_kind_allowed(
    const FormatPipelineDispatchContext *dispatch_context,
    RawAllImageSafetyKind kind
)
{
    if (kind == RAW_ALL_IMAGE_SAFETY_JPEG) {
        return format_pipeline_dispatch_context_allows_jpeg(dispatch_context);
    }
    if (kind == RAW_ALL_IMAGE_SAFETY_PNG) {
        return format_pipeline_dispatch_context_allows_png(dispatch_context);
    }
    if (kind == RAW_ALL_IMAGE_SAFETY_PDF) {
        return format_pipeline_dispatch_context_allows_pdf(dispatch_context);
    }
    if (kind == RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT) {
        return format_pipeline_dispatch_context_allows_pdf(dispatch_context) ||
               (dispatch_context != NULL &&
                dispatch_context->enabled_format_mask != 0U);
    }
    if (kind == RAW_ALL_IMAGE_SAFETY_MOV ||
        kind == RAW_ALL_IMAGE_SAFETY_RIFF ||
        kind == RAW_ALL_IMAGE_SAFETY_MPEG_PS ||
        kind == RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT ||
        kind == RAW_ALL_IMAGE_SAFETY_AAC ||
        kind == RAW_ALL_IMAGE_SAFETY_MKV) {
        return dispatch_context != NULL &&
               dispatch_context->enabled_format_mask != 0U;
    }
    return 0;
}

static int raw_all_claim_audit_kind_index(RawAllImageSafetyKind kind)
{
    return kind > 0 && kind < RAW_ALL_IMAGE_SAFETY_KIND_LIMIT
        ? (int)kind
        : 0;
}

static int raw_all_claim_audit_validate_jpeg(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const RawAllImageSafetyCandidate *candidate,
    size_t start_offset,
    RawAllClaimAuditValidation *out
);
static int raw_all_claim_audit_validate_png(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const RawAllImageSafetyCandidate *candidate,
    size_t start_offset,
    RawAllClaimAuditValidation *out
);
static int raw_all_claim_audit_validate_pdf(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const RawAllImageSafetyCandidate *candidate,
    size_t start_offset,
    RawAllClaimAuditValidation *out
);
static int raw_all_claim_audit_validate_pipeline(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const RawAllImageSafetyCandidate *candidate,
    size_t start_offset,
    RawAllClaimAuditValidation *out
);

static const RawAllClaimAuditProbe *raw_all_claim_audit_probes(size_t *out_count)
{
    static const RawAllClaimAuditProbe probes[] = {
        {
            RAW_ALL_IMAGE_SAFETY_JPEG,
            "jpg",
            17U,
            0,
            raw_all_image_safety_is_jpeg_start,
            raw_all_claim_audit_validate_jpeg
        },
        {
            RAW_ALL_IMAGE_SAFETY_PNG,
            "png",
            33U,
            0,
            raw_all_image_safety_is_png_start,
            raw_all_claim_audit_validate_png
        },
        {
            RAW_ALL_IMAGE_SAFETY_PDF,
            "pdf",
            8U,
            0,
            raw_all_image_safety_is_pdf_start,
            raw_all_claim_audit_validate_pdf
        },
        {
            RAW_ALL_IMAGE_SAFETY_MOV,
            "ftyp",
            16U,
            1,
            raw_all_image_safety_is_mov_start,
            raw_all_claim_audit_validate_pipeline
        },
        {
            RAW_ALL_IMAGE_SAFETY_RIFF,
            "riff",
            12U,
            1,
            raw_all_image_safety_is_riff_start,
            raw_all_claim_audit_validate_pipeline
        },
        {
            RAW_ALL_IMAGE_SAFETY_MPEG_PS,
            "mpeg_ps",
            14U,
            1,
            raw_all_image_safety_is_mpeg_ps_start,
            raw_all_claim_audit_validate_pipeline
        },
        {
            RAW_ALL_IMAGE_SAFETY_MKV,
            "mkv",
            16U,
            1,
            raw_all_image_safety_is_mkv_start,
            raw_all_claim_audit_validate_pipeline
        },
        {
            RAW_ALL_IMAGE_SAFETY_AAC,
            "aac",
            14U,
            1,
            raw_all_image_safety_is_aac_start,
            raw_all_claim_audit_validate_pipeline
        }
    };

    if (out_count != NULL) {
        *out_count = sizeof(probes) / sizeof(probes[0]);
    }
    return probes;
}

static int raw_all_claim_audit_probe_allowed_for_interval(
    const RawAllClaimAuditProbe *probe,
    const RawAllImageSafetyInterval *interval,
    const FormatPipelineDispatchContext *dispatch_context
)
{
    if (probe == NULL ||
        !raw_all_image_safety_kind_allowed(dispatch_context, probe->kind)) {
        return 0;
    }
    if (interval != NULL &&
        interval->preferred_kind == RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT &&
        !probe->scan_in_video_audit) {
        return 0;
    }
    return 1;
}

static int raw_all_claim_audit_any_probe_allowed(
    const FormatPipelineDispatchContext *dispatch_context
)
{
    const RawAllClaimAuditProbe *probes;
    size_t probe_count = 0U;
    size_t i;

    probes = raw_all_claim_audit_probes(&probe_count);
    for (i = 0U; i < probe_count; i++) {
        if (raw_all_image_safety_kind_allowed(dispatch_context, probes[i].kind)) {
            return 1;
        }
    }
    return 0;
}

static void raw_all_image_safety_queue_free(RawAllImageSafetyQueue *queue)
{
    if (queue == NULL) {
        return;
    }
    free(queue->candidates);
    free(queue->intervals);
    free(queue->regions);
    memset(queue, 0, sizeof(*queue));
}

static int raw_all_image_safety_candidate_compare(
    const void *left,
    const void *right
)
{
    const RawAllImageSafetyCandidate *a =
        (const RawAllImageSafetyCandidate *)left;
    const RawAllImageSafetyCandidate *b =
        (const RawAllImageSafetyCandidate *)right;

    if (a->offset < b->offset) {
        return -1;
    }
    if (a->offset > b->offset) {
        return 1;
    }
    if (a->kind < b->kind) {
        return -1;
    }
    if (a->kind > b->kind) {
        return 1;
    }
    return 0;
}

static int raw_all_image_safety_push_candidate(
    RawAllImageSafetyQueue *queue,
    uint64_t offset,
    uint64_t owner_offset,
    uint64_t owner_end_offset,
    RawAllImageSafetyKind kind,
    const char *reason,
    const char *owner_label
)
{
    RawAllImageSafetyCandidate *grown;
    size_t new_capacity;

    if (queue == NULL ||
        queue->candidate_count >= RAW_ALL_IMAGE_SAFETY_MAX_CANDIDATES) {
        if (queue != NULL) {
            queue->candidate_capacity_drops++;
        }
        return 0;
    }

    if (queue->candidate_count == queue->candidate_capacity) {
        new_capacity =
            queue->candidate_capacity == 0U ? 128U : queue->candidate_capacity * 2U;
        if (new_capacity > RAW_ALL_IMAGE_SAFETY_MAX_CANDIDATES) {
            new_capacity = RAW_ALL_IMAGE_SAFETY_MAX_CANDIDATES;
        }
        if (new_capacity <= queue->candidate_capacity) {
            queue->candidate_capacity_drops++;
            return 0;
        }
        grown = (RawAllImageSafetyCandidate *)realloc(
            queue->candidates,
            new_capacity * sizeof(*queue->candidates));
        if (grown == NULL) {
            queue->candidate_capacity_drops++;
            return 0;
        }
        queue->candidates = grown;
        queue->candidate_capacity = new_capacity;
    }

    queue->candidates[queue->candidate_count].offset = offset;
    queue->candidates[queue->candidate_count].owner_offset = owner_offset;
    queue->candidates[queue->candidate_count].owner_end_offset = owner_end_offset;
    queue->candidates[queue->candidate_count].kind = kind;
    queue->candidates[queue->candidate_count].processed = 0;
    raw_all_copy_small_string(
        queue->candidates[queue->candidate_count].reason,
        sizeof(queue->candidates[queue->candidate_count].reason),
        reason);
    raw_all_copy_small_string(
        queue->candidates[queue->candidate_count].owner_label,
        sizeof(queue->candidates[queue->candidate_count].owner_label),
        owner_label);
    queue->candidate_count++;
    {
        int kind_index = raw_all_claim_audit_kind_index(kind);
        if (kind_index > 0) {
            queue->candidate_by_kind[kind_index]++;
        }
    }
    return 1;
}

static uint64_t raw_all_image_safety_region_start(uint64_t offset)
{
    return (offset / RAW_ALL_IMAGE_SAFETY_REGION_BYTES) *
           RAW_ALL_IMAGE_SAFETY_REGION_BYTES;
}

static RawAllImageSafetyRegionBudget *raw_all_image_safety_find_region(
    RawAllImageSafetyQueue *queue,
    uint64_t region_start,
    int create
)
{
    size_t i;
    RawAllImageSafetyRegionBudget *grown;
    size_t new_capacity;

    if (queue == NULL) {
        return NULL;
    }
    for (i = 0U; i < queue->region_count; i++) {
        if (queue->regions[i].region_start == region_start) {
            return &queue->regions[i];
        }
    }
    if (!create) {
        return NULL;
    }
    if (queue->region_count == queue->region_capacity) {
        new_capacity =
            queue->region_capacity == 0U ? 32U : queue->region_capacity * 2U;
        grown = (RawAllImageSafetyRegionBudget *)realloc(
            queue->regions,
            new_capacity * sizeof(*queue->regions));
        if (grown == NULL) {
            return NULL;
        }
        queue->regions = grown;
        queue->region_capacity = new_capacity;
    }
    queue->regions[queue->region_count].region_start = region_start;
    queue->regions[queue->region_count].bytes_queued = 0U;
    return &queue->regions[queue->region_count++];
}

static uint64_t raw_all_image_safety_region_bytes_queued(
    RawAllImageSafetyQueue *queue,
    uint64_t region_start
)
{
    RawAllImageSafetyRegionBudget *region =
        raw_all_image_safety_find_region(queue, region_start, 0);
    return region != NULL ? region->bytes_queued : 0U;
}

static int raw_all_image_safety_add_region_bytes(
    RawAllImageSafetyQueue *queue,
    uint64_t region_start,
    uint64_t bytes
)
{
    RawAllImageSafetyRegionBudget *region;

    if (bytes == 0U) {
        return 1;
    }
    region = raw_all_image_safety_find_region(queue, region_start, 1);
    if (region == NULL) {
        return 0;
    }
    region->bytes_queued += bytes;
    return 1;
}

static void raw_all_image_safety_append_drop_report(
    const AppConfig *config,
    uint64_t start,
    uint64_t end,
    uint64_t owner_offset,
    uint64_t owner_end_offset,
    RawAllImageSafetyKind preferred_kind,
    const char *reason,
    const char *owner_label,
    const char *drop_reason,
    uint64_t dropped_bytes
)
{
    char path[1024];
    struct stat st;
    int have_existing;
    FILE *file;

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        end <= start ||
        dropped_bytes == 0U) {
        return;
    }
    if (snprintf(
            path,
            sizeof(path),
            "%s/%s",
            config->output_dir,
            RAW_ALL_IMAGE_SAFETY_DROP_REPORT_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    file = fopen(path, "a");
    if (file == NULL) {
        return;
    }
    if (!have_existing) {
        fprintf(
            file,
            "start\tend\tdropped_bytes\tkind\treason\tdrop_reason\towner_offset\towner_end_offset\towner_label\n"
        );
    }
    fprintf(
        file,
        "%llu\t%llu\t%llu\t%s\t%s\t%s\t%llu\t%llu\t%s\n",
        (unsigned long long)start,
        (unsigned long long)end,
        (unsigned long long)dropped_bytes,
        raw_all_image_safety_kind_name(preferred_kind),
        reason != NULL ? reason : "unknown",
        drop_reason != NULL ? drop_reason : "unknown",
        (unsigned long long)owner_offset,
        (unsigned long long)owner_end_offset,
        owner_label != NULL ? owner_label : "unknown"
    );
    fclose(file);
}

static void raw_all_image_safety_append_swallowed_interval_report(
    const AppConfig *config,
    uint64_t start,
    uint64_t end,
    uint64_t owner_offset,
    uint64_t owner_end_offset,
    RawAllImageSafetyKind preferred_kind,
    const char *reason,
    const char *owner_label,
    const char *source
)
{
    char path[1024];
    struct stat st;
    int have_existing;
    FILE *file;

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        end <= start) {
        return;
    }
    if (snprintf(
            path,
            sizeof(path),
            "%s/%s",
            config->output_dir,
            RAW_ALL_SWALLOWED_INTERVALS_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    file = fopen(path, "a");
    if (file == NULL) {
        return;
    }
    if (!have_existing) {
        fprintf(
            file,
            "start\tend\towner_offset\towner_end_offset\tkind\treason\towner_label\tsource\n"
        );
    }
    fprintf(
        file,
        "%llu\t%llu\t%llu\t%llu\t%s\t%s\t%s\t%s\n",
        (unsigned long long)start,
        (unsigned long long)end,
        (unsigned long long)owner_offset,
        (unsigned long long)owner_end_offset,
        raw_all_image_safety_kind_name(preferred_kind),
        reason != NULL ? reason : "unknown",
        owner_label != NULL ? owner_label : "unknown",
        source != NULL ? source : "raw_all"
    );
    fclose(file);
}

static int raw_all_image_safety_owner_is_generic_picture_claim(
    const char *reason,
    const char *owner_label
)
{
    if (reason == NULL ||
        strcmp(reason, "inside_large_claim") != 0 ||
        owner_label == NULL) {
        return 0;
    }
    return strcmp(owner_label, "Picture") == 0 ||
           strcmp(owner_label, "unknown") == 0;
}

static int raw_all_image_safety_is_generic_picture_tail(
    const char *reason,
    const char *owner_label
)
{
    if (reason == NULL || owner_label == NULL) {
        return 0;
    }
    if (strcmp(owner_label, "Picture") != 0 &&
        strcmp(owner_label, "unknown") != 0) {
        return 0;
    }
    return strcmp(reason, "generic_picture_cap") == 0 ||
           strcmp(reason, "child_audit_generic_picture_cap") == 0 ||
           strcmp(reason, "video_audit_cap") == 0 ||
           strcmp(reason, "child_audit_budget") == 0 ||
           strcmp(reason, "video_audit_budget") == 0 ||
           strcmp(reason, "region_budget_exhausted") == 0 ||
           strcmp(reason, "global_budget_exhausted") == 0 ||
           strcmp(reason, "region_budget_trim") == 0 ||
           strcmp(reason, "global_budget_trim") == 0 ||
           strcmp(reason, "merge_budget_exhausted") == 0;
}

static int raw_all_image_safety_audit_interval_covered(
    const RawAllImageSafetyQueue *queue,
    uint64_t start,
    uint64_t end,
    RawAllImageSafetyKind kind
)
{
    size_t i;

    if (queue == NULL || end <= start) {
        return 1;
    }
    for (i = 0U; i < queue->interval_count; i++) {
        const RawAllImageSafetyInterval *interval = &queue->intervals[i];
        if (interval->preferred_kind != kind) {
            continue;
        }
        if (start >= interval->start && end <= interval->end) {
            return 1;
        }
    }
    return 0;
}

static int raw_all_image_safety_append_audit_interval(
    RawAllImageSafetyQueue *queue,
    uint64_t start,
    uint64_t end,
    uint64_t owner_offset,
    uint64_t owner_end_offset,
    RawAllImageSafetyKind audit_kind,
    uint64_t max_interval_bytes,
    uint64_t max_total_bytes,
    uint64_t *bytes_queued,
    uint64_t *bytes_dropped,
    uint64_t *interval_count,
    const char *reason,
    const char *owner_label
)
{
    uint64_t span;
    uint64_t remaining;
    RawAllImageSafetyInterval *grown;
    size_t new_capacity;

    if (queue == NULL ||
        bytes_queued == NULL ||
        bytes_dropped == NULL ||
        interval_count == NULL ||
        end <= start) {
        return 0;
    }

    span = end - start;
    if (span > max_interval_bytes) {
        *bytes_dropped += span - max_interval_bytes;
        end = start + max_interval_bytes;
        span = end - start;
    }

    remaining = *bytes_queued < max_total_bytes
        ? max_total_bytes - *bytes_queued
        : 0U;
    if (remaining < 4096U) {
        *bytes_dropped += span;
        return 0;
    }
    if (span > remaining) {
        *bytes_dropped += span - remaining;
        end = start + remaining;
        span = remaining;
    }
    if (span == 0U ||
        raw_all_image_safety_audit_interval_covered(
            queue,
            start,
            end,
            audit_kind)) {
        return 0;
    }

    if (queue->interval_count >= RAW_ALL_IMAGE_SAFETY_MAX_INTERVALS) {
        queue->interval_capacity_drops++;
        *bytes_dropped += span;
        return 0;
    }
    if (queue->interval_count == queue->interval_capacity) {
        new_capacity =
            queue->interval_capacity == 0U ? 64U : queue->interval_capacity * 2U;
        if (new_capacity > RAW_ALL_IMAGE_SAFETY_MAX_INTERVALS) {
            new_capacity = RAW_ALL_IMAGE_SAFETY_MAX_INTERVALS;
        }
        if (new_capacity <= queue->interval_capacity) {
            queue->interval_capacity_drops++;
            *bytes_dropped += span;
            return 0;
        }
        grown = (RawAllImageSafetyInterval *)realloc(
            queue->intervals,
            new_capacity * sizeof(*queue->intervals));
        if (grown == NULL) {
            queue->interval_capacity_drops++;
            *bytes_dropped += span;
            return 0;
        }
        queue->intervals = grown;
        queue->interval_capacity = new_capacity;
    }

    queue->intervals[queue->interval_count].start = start;
    queue->intervals[queue->interval_count].end = end;
    queue->intervals[queue->interval_count].owner_offset = owner_offset;
    queue->intervals[queue->interval_count].owner_end_offset =
        owner_end_offset > owner_offset ? owner_end_offset : end;
    queue->intervals[queue->interval_count].preferred_kind = audit_kind;
    queue->intervals[queue->interval_count].scanned = 0;
    raw_all_copy_small_string(
        queue->intervals[queue->interval_count].reason,
        sizeof(queue->intervals[queue->interval_count].reason),
        reason != NULL ? reason : raw_all_image_safety_kind_name(audit_kind));
    raw_all_copy_small_string(
        queue->intervals[queue->interval_count].owner_label,
        sizeof(queue->intervals[queue->interval_count].owner_label),
        owner_label);
    queue->interval_count++;
    (*interval_count)++;
    *bytes_queued += span;
    return 1;
}

static void raw_all_image_safety_append_video_audit_interval(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t start,
    uint64_t end,
    uint64_t owner_offset,
    uint64_t owner_end_offset,
    const char *reason,
    const char *owner_label
)
{
    if (raw_all_image_safety_append_audit_interval(
        queue,
        start,
        end,
        owner_offset,
        owner_end_offset,
        RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT,
        raw_all_u64_or_default(
            queue->video_max_interval_bytes,
            RAW_ALL_VIDEO_AUDIT_MAX_INTERVAL_BYTES),
        raw_all_u64_or_default(
            queue->video_max_total_bytes,
            RAW_ALL_VIDEO_AUDIT_MAX_TOTAL_BYTES),
        &queue->video_audit_interval_bytes_queued,
        &queue->video_audit_interval_bytes_dropped,
        &queue->video_audit_interval_count,
        reason != NULL ? reason : "video_audit",
        owner_label)) {
        raw_all_image_safety_append_swallowed_interval_report(
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT,
            reason != NULL ? reason : "video_audit",
            owner_label,
            "video_audit");
    }
}

static void raw_all_image_safety_append_child_audit_interval(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t start,
    uint64_t end,
    uint64_t owner_offset,
    uint64_t owner_end_offset,
    const char *reason,
    const char *owner_label
)
{
    if (raw_all_image_safety_append_audit_interval(
        queue,
        start,
        end,
        owner_offset,
        owner_end_offset,
        RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT,
        raw_all_u64_or_default(
            queue->child_max_interval_bytes,
            RAW_ALL_CHILD_AUDIT_MAX_INTERVAL_BYTES),
        raw_all_u64_or_default(
            queue->child_max_total_bytes,
            RAW_ALL_CHILD_AUDIT_MAX_TOTAL_BYTES),
        &queue->child_audit_interval_bytes_queued,
        &queue->child_audit_interval_bytes_dropped,
        &queue->child_audit_interval_count,
        reason != NULL ? reason : "child_audit",
        owner_label)) {
        raw_all_image_safety_append_swallowed_interval_report(
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT,
            reason != NULL ? reason : "child_audit",
            owner_label,
            "child_audit");
    }
}

static int raw_all_parse_u64_field(const char *text, uint64_t *out)
{
    char *end = NULL;
    unsigned long long value;

    if (text == NULL || text[0] == '\0' || out == NULL) {
        return 0;
    }
    value = strtoull(text, &end, 10);
    if (end == text || (end != NULL && *end != '\0')) {
        return 0;
    }
    *out = (uint64_t)value;
    return 1;
}

static size_t raw_all_split_tsv_line(char *line, char **fields, size_t max_fields)
{
    char *cursor;
    size_t count = 0U;

    if (line == NULL || fields == NULL || max_fields == 0U) {
        return 0U;
    }

    cursor = line;
    while (count < max_fields) {
        char *start = cursor;

        while (*cursor != '\0' &&
               *cursor != '\t' &&
               *cursor != '\r' &&
               *cursor != '\n') {
            cursor++;
        }

        fields[count++] = start;
        if (*cursor == '\0') {
            break;
        }
        {
            char delimiter = *cursor;

            *cursor = '\0';
            cursor++;
            if (delimiter == '\r' || delimiter == '\n') {
                break;
            }
        }
    }

    return count;
}

static int raw_all_persisted_interval_import_range(
    const AppConfig *config,
    uint64_t *out_start,
    uint64_t *out_end
)
{
    uint64_t start;
    uint64_t end;

    if (out_start != NULL) {
        *out_start = 0ULL;
    }
    if (out_end != NULL) {
        *out_end = 0ULL;
    }
    if (config == NULL ||
        !config->only_recover_missed ||
        !config->manual_start_explicit ||
        config->mft_limit == 0ULL) {
        return 0;
    }

    start = (uint64_t)config->manual_start_offset;
    end = (uint64_t)config->mft_limit;
    if (end <= start) {
        if (UINT64_MAX - start < end) {
            end = UINT64_MAX;
        } else {
            end = start + end;
        }
    }
    if (end <= start) {
        return 0;
    }

    if (out_start != NULL) {
        *out_start = start;
    }
    if (out_end != NULL) {
        *out_end = end;
    }
    return 1;
}

static size_t raw_all_image_safety_import_interval_file(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    const char *state_name,
    int legacy_drop_format
)
{
    char path[1024];
    char line[1024];
    FILE *file;
    size_t loaded = 0U;
    uint64_t import_start = 0ULL;
    uint64_t import_end = 0ULL;
    int clamp_to_active_range =
        raw_all_persisted_interval_import_range(
            config,
            &import_start,
            &import_end);

    if (queue == NULL ||
        config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        state_name == NULL) {
        return 0U;
    }
    if (snprintf(path, sizeof(path), "%s/%s", config->output_dir, state_name) >=
        (int)sizeof(path)) {
        return 0U;
    }

    file = fopen(path, "r");
    if (file == NULL) {
        return 0U;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *fields[10] = {0};
        size_t count = 0U;
        uint64_t start = 0U;
        uint64_t end = 0U;
        uint64_t owner_offset = 0U;
        uint64_t owner_end_offset = 0U;
        const char *kind_text;
        const char *reason;
        const char *owner_label;
        RawAllImageSafetyKind saved_kind;

        count = raw_all_split_tsv_line(line, fields, sizeof(fields) / sizeof(fields[0]));
        if (count < 2U || fields[0] == NULL || strcmp(fields[0], "start") == 0) {
            continue;
        }

        if (!raw_all_parse_u64_field(fields[0], &start) ||
            !raw_all_parse_u64_field(fields[1], &end) ||
            end <= start) {
            continue;
        }

        if (legacy_drop_format) {
            if (count < 9U ||
                !raw_all_parse_u64_field(fields[6], &owner_offset) ||
                !raw_all_parse_u64_field(fields[7], &owner_end_offset)) {
                owner_offset = start;
                owner_end_offset = end;
            }
            kind_text = fields[3];
            reason = fields[5] != NULL && fields[5][0] != '\0'
                ? fields[5]
                : "persisted_drop";
            owner_label = fields[8] != NULL ? fields[8] : "unknown";
        } else {
            if (count < 8U ||
                !raw_all_parse_u64_field(fields[2], &owner_offset) ||
                !raw_all_parse_u64_field(fields[3], &owner_end_offset)) {
                owner_offset = start;
                owner_end_offset = end;
            }
            kind_text = fields[4];
            reason = fields[5] != NULL && fields[5][0] != '\0'
                ? fields[5]
                : "persisted_swallowed";
            owner_label = fields[6] != NULL ? fields[6] : "unknown";
        }

        if (raw_all_image_safety_is_generic_picture_tail(reason, owner_label)) {
            continue;
        }

        if (clamp_to_active_range) {
            if (end <= import_start || start >= import_end) {
                continue;
            }
            if (start < import_start) {
                start = import_start;
            }
            if (end > import_end) {
                end = import_end;
            }
            if (end <= start) {
                continue;
            }
        }

        saved_kind = raw_all_image_safety_kind_from_name(kind_text);
        if (saved_kind == RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT) {
            if (raw_all_image_safety_append_audit_interval(
                    queue,
                    start,
                    end,
                    owner_offset,
                    owner_end_offset,
                    RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT,
                    raw_all_u64_or_default(
                        queue->video_max_interval_bytes,
                        RAW_ALL_VIDEO_AUDIT_MAX_INTERVAL_BYTES),
                    raw_all_u64_or_default(
                        queue->video_max_total_bytes,
                        RAW_ALL_VIDEO_AUDIT_MAX_TOTAL_BYTES),
                    &queue->video_audit_interval_bytes_queued,
                    &queue->video_audit_interval_bytes_dropped,
                    &queue->video_audit_interval_count,
                    reason,
                    owner_label)) {
                loaded++;
            }
            continue;
        }

        /*
         * A persisted swallowed interval means "bytes were skipped inside a
         * claim"; on resume, scan it with the generic child-audit engine so
         * the active format set, not the original owner, decides what can be
         * recovered.
         */
        if (raw_all_image_safety_append_audit_interval(
                queue,
                start,
                end,
                owner_offset,
                owner_end_offset,
                RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT,
                raw_all_u64_or_default(
                    queue->child_max_interval_bytes,
                    RAW_ALL_CHILD_AUDIT_MAX_INTERVAL_BYTES),
                raw_all_u64_or_default(
                    queue->child_max_total_bytes,
                    RAW_ALL_CHILD_AUDIT_MAX_TOTAL_BYTES),
                &queue->child_audit_interval_bytes_queued,
                &queue->child_audit_interval_bytes_dropped,
                &queue->child_audit_interval_count,
                reason,
                owner_label)) {
            loaded++;
        }
    }

    fclose(file);
    return loaded;
}

static void raw_all_image_safety_load_persisted_intervals(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config
)
{
    size_t swallowed_loaded;
    size_t legacy_drop_loaded;

    if (queue == NULL || config == NULL) {
        return;
    }

    swallowed_loaded = raw_all_image_safety_import_interval_file(
        queue,
        config,
        RAW_ALL_SWALLOWED_INTERVALS_NAME,
        0);
    legacy_drop_loaded = raw_all_image_safety_import_interval_file(
        queue,
        config,
        RAW_ALL_IMAGE_SAFETY_DROP_REPORT_NAME,
        1);
    queue->persisted_swallowed_loaded += (uint64_t)swallowed_loaded;
    queue->persisted_legacy_drop_loaded += (uint64_t)legacy_drop_loaded;

    if (swallowed_loaded > 0U || legacy_drop_loaded > 0U) {
        log_info(
            "Loaded persisted swallowed-file intervals: journal=%zu legacy_drops=%zu child_audit_intervals=%llu video_audit_intervals=%llu",
            swallowed_loaded,
            legacy_drop_loaded,
            (unsigned long long)queue->child_audit_interval_count,
            (unsigned long long)queue->video_audit_interval_count);
    }
}

static uint64_t raw_all_claim_audit_sum_counts(const uint64_t *counts)
{
    uint64_t total = 0U;
    int i;

    if (counts == NULL) {
        return 0U;
    }
    for (i = 1; i < RAW_ALL_IMAGE_SAFETY_KIND_LIMIT; i++) {
        total += counts[i];
    }
    return total;
}

static size_t raw_all_image_safety_unscanned_interval_count(
    const RawAllImageSafetyQueue *queue
)
{
    size_t count = 0U;
    size_t i;

    if (queue == NULL) {
        return 0U;
    }
    for (i = 0U; i < queue->interval_count; i++) {
        if (!queue->intervals[i].scanned) {
            count++;
        }
    }
    return count;
}

static size_t raw_all_image_safety_unprocessed_candidate_count(
    const RawAllImageSafetyQueue *queue
)
{
    size_t count = 0U;
    size_t i;

    if (queue == NULL) {
        return 0U;
    }
    for (i = 0U; i < queue->candidate_count; i++) {
        if (!queue->candidates[i].processed) {
            count++;
        }
    }
    return count;
}

static int raw_all_image_safety_candidate_same_key(
    const RawAllImageSafetyCandidate *a,
    const RawAllImageSafetyCandidate *b
)
{
    return a != NULL &&
           b != NULL &&
           a->offset == b->offset &&
           a->kind == b->kind;
}

static int raw_all_image_safety_candidate_has_processed_twin(
    const RawAllImageSafetyQueue *queue,
    size_t index
)
{
    size_t i;

    if (queue == NULL || index >= queue->candidate_count) {
        return 0;
    }

    i = index;
    while (i > 0U &&
           raw_all_image_safety_candidate_same_key(
               &queue->candidates[index],
               &queue->candidates[i - 1U])) {
        i--;
        if (queue->candidates[i].processed) {
            return 1;
        }
    }

    for (i = index + 1U;
         i < queue->candidate_count &&
         raw_all_image_safety_candidate_same_key(
             &queue->candidates[index],
             &queue->candidates[i]);
         i++) {
        if (queue->candidates[i].processed) {
            return 1;
        }
    }

    return 0;
}

static void raw_all_claim_audit_write_state(
    const AppConfig *config,
    const RawAllImageSafetyQueue *queue,
    const char *phase,
    const char *stop_reason
)
{
    char path[1024];
    struct stat st;
    int have_existing;
    FILE *file;

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        queue == NULL ||
        snprintf(
            path,
            sizeof(path),
            "%s/%s",
            config->output_dir,
            RAW_ALL_CLAIM_AUDIT_STATE_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    file = fopen(path, "a");
    if (file == NULL) {
        return;
    }

    if (!have_existing) {
        fprintf(
            file,
            "updated_unix\tgeneration\tpass_id\tphase\tstop_reason\tprofile\tcpu_count\tdiscovery_workers\tvalidation_workers\tdiscovery_chunk_bytes\tcandidate_chunk_bytes\tmax_total_bytes\tchild_max_total_bytes\tvideo_max_total_bytes\tintervals\tintervals_scanned\taudit_bytes_scanned\tbytes_queued\tbytes_dropped\tvideo_intervals\tchild_intervals\tpersisted_swallowed\tpersisted_legacy_drop\tcandidates\tcand_jpg\tcand_png\tcand_pdf\tcand_ftyp\tcand_riff\tcand_mpeg_ps\tcand_mkv\tcand_aac\tattempted\trecovered\trejected\talready_recovered\tcovered_by_earlier\tvalidated_claim_span\tchild_ranges_emitted\tchild_ranges_truncated\tcandidate_capacity_drops\tinterval_capacity_drops\tcandidate_duplicates\n"
        );
    }

    fprintf(
        file,
        "%llu\t%llu\t",
        (unsigned long long)time(NULL),
        (unsigned long long)carv_run_supervisor_generation_inline()
    );
    performance_ledger_write_text_inline(file, carv_run_pass_id_inline());
    fputc('\t', file);
    performance_ledger_write_text_inline(file, phase != NULL ? phase : "unknown");
    fputc('\t', file);
    performance_ledger_write_text_inline(
        file,
        stop_reason != NULL ? stop_reason : "running"
    );
    fputc('\t', file);
    performance_ledger_write_text_inline(
        file,
        raw_all_resource_profile_label(queue->resource_profile)
    );
    fprintf(
        file,
        "\t%ld\t%zu\t%zu\t%zu\t%zu\t%llu\t%llu\t%llu",
        queue->resource_cpu_count > 0 ? queue->resource_cpu_count : 0L,
        queue->discovery_worker_count,
        queue->validation_worker_count,
        queue->discovery_chunk_cap_bytes,
        queue->candidate_chunk_cap_bytes,
        (unsigned long long)raw_all_u64_or_default(
            queue->max_total_bytes,
            RAW_ALL_IMAGE_SAFETY_MAX_TOTAL_BYTES),
        (unsigned long long)raw_all_u64_or_default(
            queue->child_max_total_bytes,
            RAW_ALL_CHILD_AUDIT_MAX_TOTAL_BYTES),
        (unsigned long long)raw_all_u64_or_default(
            queue->video_max_total_bytes,
            RAW_ALL_VIDEO_AUDIT_MAX_TOTAL_BYTES)
    );
    fprintf(
        file,
        "\t%zu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%zu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\n",
        queue->interval_count,
        (unsigned long long)queue->audit_intervals_scanned,
        (unsigned long long)queue->audit_bytes_scanned,
        (unsigned long long)queue->interval_bytes_queued,
        (unsigned long long)queue->interval_bytes_dropped,
        (unsigned long long)queue->video_audit_interval_count,
        (unsigned long long)queue->child_audit_interval_count,
        (unsigned long long)queue->persisted_swallowed_loaded,
        (unsigned long long)queue->persisted_legacy_drop_loaded,
        queue->candidate_count,
        (unsigned long long)queue->candidate_by_kind[RAW_ALL_IMAGE_SAFETY_JPEG],
        (unsigned long long)queue->candidate_by_kind[RAW_ALL_IMAGE_SAFETY_PNG],
        (unsigned long long)queue->candidate_by_kind[RAW_ALL_IMAGE_SAFETY_PDF],
        (unsigned long long)queue->candidate_by_kind[RAW_ALL_IMAGE_SAFETY_MOV],
        (unsigned long long)queue->candidate_by_kind[RAW_ALL_IMAGE_SAFETY_RIFF],
        (unsigned long long)queue->candidate_by_kind[RAW_ALL_IMAGE_SAFETY_MPEG_PS],
        (unsigned long long)queue->candidate_by_kind[RAW_ALL_IMAGE_SAFETY_MKV],
        (unsigned long long)queue->candidate_by_kind[RAW_ALL_IMAGE_SAFETY_AAC],
        (unsigned long long)raw_all_claim_audit_sum_counts(queue->attempted_by_kind),
        (unsigned long long)raw_all_claim_audit_sum_counts(queue->recovered_by_kind),
        (unsigned long long)raw_all_claim_audit_sum_counts(queue->rejected_by_kind),
        (unsigned long long)raw_all_claim_audit_sum_counts(queue->already_recovered_by_kind),
        (unsigned long long)raw_all_claim_audit_sum_counts(queue->covered_by_earlier_by_kind),
        (unsigned long long)raw_all_claim_audit_sum_counts(queue->validated_claim_span_by_kind),
        (unsigned long long)raw_all_claim_audit_sum_counts(queue->child_ranges_emitted_by_kind),
        (unsigned long long)raw_all_claim_audit_sum_counts(queue->child_ranges_truncated_by_kind),
        (unsigned long long)queue->candidate_capacity_drops,
        (unsigned long long)queue->interval_capacity_drops,
        (unsigned long long)queue->candidate_duplicates
    );

    fclose(file);
}

static void raw_all_image_safety_append_interval_chunk(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t start,
    uint64_t end,
    uint64_t owner_offset,
    uint64_t owner_end_offset,
    RawAllImageSafetyKind preferred_kind,
    const char *reason,
    const char *owner_label
)
{
    size_t i;
    uint64_t span;
    uint64_t old_span;
    uint64_t new_span;
    uint64_t region_start;
    uint64_t region_used;
    uint64_t region_budget;
    uint64_t total_budget;
    uint64_t region_remaining;
    uint64_t global_remaining;
    RawAllImageSafetyInterval *grown;
    size_t new_capacity;

    if (queue == NULL || end <= start) {
        return;
    }

    if (fs_backend_range_has_trusted_metadata_owner(start, end)) {
        raw_all_image_safety_append_swallowed_interval_report(
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            preferred_kind,
            reason,
            owner_label,
            "suppressed_trusted_metadata_owner"
        );
        return;
    }

    region_start = raw_all_image_safety_region_start(start);
    region_used = raw_all_image_safety_region_bytes_queued(queue, region_start);
    region_budget = raw_all_u64_or_default(
        queue->max_region_bytes,
        RAW_ALL_IMAGE_SAFETY_MAX_REGION_BYTES);
    total_budget = raw_all_u64_or_default(
        queue->max_total_bytes,
        RAW_ALL_IMAGE_SAFETY_MAX_TOTAL_BYTES);
    region_remaining = region_used < region_budget
        ? region_budget - region_used
        : 0U;
    global_remaining =
        queue->interval_bytes_queued < total_budget
            ? total_budget - queue->interval_bytes_queued
            : 0U;
    if (region_remaining < global_remaining) {
        global_remaining = region_remaining;
    }
    if (global_remaining < RAW_ALL_IMAGE_SAFETY_MIN_CLAIM_BYTES) {
        span = end - start;
        queue->interval_bytes_dropped += span;
        queue->interval_region_bytes_dropped += span;
        raw_all_image_safety_append_video_audit_interval(
            queue,
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            "video_audit_budget",
            owner_label);
        raw_all_image_safety_append_child_audit_interval(
            queue,
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            "child_audit_budget",
            owner_label);
        raw_all_image_safety_append_drop_report(
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            preferred_kind,
            reason,
            owner_label,
            region_remaining == 0U ? "region_budget_exhausted" : "global_budget_exhausted",
            span);
        return;
    }

    span = end - start;
    if (span > global_remaining) {
        uint64_t kept = global_remaining;
        uint64_t dropped = span - kept;
        end = start + kept;
        span = kept;
        queue->interval_bytes_dropped += dropped;
        queue->interval_region_bytes_dropped += dropped;
        raw_all_image_safety_append_video_audit_interval(
            queue,
            config,
            end,
            end + dropped,
            owner_offset,
            owner_end_offset,
            "video_audit_trim",
            owner_label);
        raw_all_image_safety_append_child_audit_interval(
            queue,
            config,
            end,
            end + dropped,
            owner_offset,
            owner_end_offset,
            "child_audit_trim",
            owner_label);
        raw_all_image_safety_append_drop_report(
            config,
            end,
            end + dropped,
            owner_offset,
            owner_end_offset,
            preferred_kind,
            reason,
            owner_label,
            region_remaining < region_budget
                ? "region_budget_trim"
                : "global_budget_trim",
            dropped);
    }

    for (i = 0U; i < queue->interval_count; i++) {
        RawAllImageSafetyInterval *existing = &queue->intervals[i];
        uint64_t merge_slop = 1024U * 1024U;
        uint64_t old_start;
        uint64_t old_end;
        uint64_t existing_region = raw_all_image_safety_region_start(existing->start);
        int overlaps =
            existing_region == region_start &&
            start <= existing->end + merge_slop &&
            end + merge_slop >= existing->start;
        if (existing->preferred_kind == RAW_ALL_IMAGE_SAFETY_VIDEO_AUDIT ||
            existing->preferred_kind == RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT) {
            continue;
        }
        if (!overlaps) {
            continue;
        }

        old_start = existing->start;
        old_end = existing->end;
        old_span = existing->end > existing->start
            ? existing->end - existing->start
            : 0U;
        if (start < existing->start) {
            existing->start = start;
        }
        if (end > existing->end) {
            existing->end = end;
        }
        new_span = existing->end > existing->start
            ? existing->end - existing->start
            : 0U;
        if (new_span > old_span) {
            uint64_t added = new_span - old_span;
            uint64_t region_now =
                raw_all_image_safety_region_bytes_queued(queue, region_start);
            uint64_t region_can_add =
                region_now < region_budget
                    ? region_budget - region_now
                    : 0U;
            uint64_t global_can_add =
                queue->interval_bytes_queued < total_budget
                    ? total_budget - queue->interval_bytes_queued
                    : 0U;
            if (region_can_add < global_can_add) {
                global_can_add = region_can_add;
            }
            if (added > global_can_add ||
                !raw_all_image_safety_add_region_bytes(queue, region_start, added)) {
                queue->interval_bytes_dropped += added;
                queue->interval_region_bytes_dropped += added;
                raw_all_image_safety_append_video_audit_interval(
                    queue,
                    config,
                    old_start < start ? old_end : start,
                    old_start < start ? old_end + added : start + added,
                    owner_offset,
                    owner_end_offset,
                    "video_audit_merge",
                    owner_label);
                raw_all_image_safety_append_child_audit_interval(
                    queue,
                    config,
                    old_start < start ? old_end : start,
                    old_start < start ? old_end + added : start + added,
                    owner_offset,
                    owner_end_offset,
                    "child_audit_merge",
                    owner_label);
                raw_all_image_safety_append_drop_report(
                    config,
                    old_start < start ? old_end : start,
                    old_start < start ? old_end + added : start + added,
                    owner_offset,
                    owner_end_offset,
                    preferred_kind,
                    reason,
                    owner_label,
                    "merge_budget_exhausted",
                    added);
                existing->start = old_start;
                existing->end = old_end;
            } else {
                queue->interval_bytes_queued += added;
            }
            existing->scanned = 0;
        }
        if (owner_end_offset > existing->owner_end_offset) {
            existing->owner_end_offset = owner_end_offset;
        }
        raw_all_image_safety_append_swallowed_interval_report(
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            preferred_kind,
            reason,
            owner_label,
            "merge");
        return;
    }

    if (queue->interval_count >= RAW_ALL_IMAGE_SAFETY_MAX_INTERVALS) {
        queue->interval_capacity_drops++;
        queue->interval_bytes_dropped += span;
        raw_all_image_safety_append_drop_report(
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            preferred_kind,
            reason,
            owner_label,
            "interval_capacity",
            span);
        return;
    }

    if (queue->interval_count == queue->interval_capacity) {
        new_capacity =
            queue->interval_capacity == 0U ? 64U : queue->interval_capacity * 2U;
        if (new_capacity > RAW_ALL_IMAGE_SAFETY_MAX_INTERVALS) {
            new_capacity = RAW_ALL_IMAGE_SAFETY_MAX_INTERVALS;
        }
        if (new_capacity <= queue->interval_capacity) {
            queue->interval_capacity_drops++;
            queue->interval_bytes_dropped += span;
            raw_all_image_safety_append_drop_report(
                config,
                start,
                end,
                owner_offset,
                owner_end_offset,
                preferred_kind,
                reason,
                owner_label,
                "interval_capacity",
                span);
            return;
        }
        grown = (RawAllImageSafetyInterval *)realloc(
            queue->intervals,
            new_capacity * sizeof(*queue->intervals));
        if (grown == NULL) {
            queue->interval_capacity_drops++;
            queue->interval_bytes_dropped += span;
            raw_all_image_safety_append_drop_report(
                config,
                start,
                end,
                owner_offset,
                owner_end_offset,
                preferred_kind,
                reason,
                owner_label,
                "interval_alloc_failed",
                span);
            return;
        }
        queue->intervals = grown;
        queue->interval_capacity = new_capacity;
    }

    if (!raw_all_image_safety_add_region_bytes(queue, region_start, span)) {
        queue->interval_bytes_dropped += span;
        queue->interval_region_bytes_dropped += span;
        raw_all_image_safety_append_video_audit_interval(
            queue,
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            "video_audit_region",
            owner_label);
        raw_all_image_safety_append_child_audit_interval(
            queue,
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            "child_audit_region",
            owner_label);
        raw_all_image_safety_append_drop_report(
            config,
            start,
            end,
            owner_offset,
            owner_end_offset,
            preferred_kind,
            reason,
            owner_label,
            "region_alloc_failed",
            span);
        return;
    }

    queue->intervals[queue->interval_count].start = start;
    queue->intervals[queue->interval_count].end = end;
    queue->intervals[queue->interval_count].owner_offset = owner_offset;
    queue->intervals[queue->interval_count].owner_end_offset =
        owner_end_offset > owner_offset ? owner_end_offset : end;
    queue->intervals[queue->interval_count].preferred_kind = preferred_kind;
    queue->intervals[queue->interval_count].scanned = 0;
    raw_all_copy_small_string(
        queue->intervals[queue->interval_count].reason,
        sizeof(queue->intervals[queue->interval_count].reason),
        reason);
    raw_all_copy_small_string(
        queue->intervals[queue->interval_count].owner_label,
        sizeof(queue->intervals[queue->interval_count].owner_label),
        owner_label);
    queue->interval_count++;
    queue->interval_bytes_queued += span;
    raw_all_image_safety_append_swallowed_interval_report(
        config,
        start,
        end,
        owner_offset,
        owner_end_offset,
        preferred_kind,
        reason,
        owner_label,
        "queued");
}

static void raw_all_image_safety_append_interval(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t start,
    uint64_t end,
    uint64_t owner_offset,
    uint64_t owner_end_offset,
    RawAllImageSafetyKind preferred_kind,
    const char *reason,
    const char *owner_label
)
{
    uint64_t span;
    uint64_t max_span = raw_all_u64_or_default(
        queue != NULL ? queue->max_interval_bytes : 0ULL,
        RAW_ALL_IMAGE_SAFETY_MAX_INTERVAL_BYTES);

    if (queue == NULL || end <= start) {
        return;
    }

    span = end - start;
    if (raw_all_image_safety_owner_is_generic_picture_claim(reason, owner_label)) {
        max_span = RAW_ALL_IMAGE_SAFETY_GENERIC_CLAIM_BYTES;
    }
    if (span > max_span) {
        uint64_t old_end = end;
        int generic_tail = max_span == RAW_ALL_IMAGE_SAFETY_GENERIC_CLAIM_BYTES;

        end = start + max_span;
        queue->interval_bytes_dropped += old_end - end;
        if (generic_tail) {
            queue->interval_generic_bytes_dropped += old_end - end;
        }
        if (!generic_tail) {
            raw_all_image_safety_append_video_audit_interval(
                queue,
                config,
                end,
                old_end,
                owner_offset,
                owner_end_offset,
                "video_audit_cap",
                owner_label);
            raw_all_image_safety_append_child_audit_interval(
                queue,
                config,
                end,
                old_end,
                owner_offset,
                owner_end_offset,
                "child_audit_max_interval_cap",
                owner_label);
        }
        raw_all_image_safety_append_drop_report(
            config,
            end,
            old_end,
            owner_offset,
            owner_end_offset,
            preferred_kind,
            reason,
            owner_label,
            generic_tail
                ? "generic_picture_cap"
                : "max_interval_cap",
            old_end - end);
        span = end - start;
    }

    while (start < end) {
        uint64_t region_end =
            raw_all_image_safety_region_start(start) +
            RAW_ALL_IMAGE_SAFETY_REGION_BYTES;
        uint64_t chunk_end = end < region_end ? end : region_end;
        raw_all_image_safety_append_interval_chunk(
            queue,
            config,
            start,
            chunk_end,
            owner_offset,
            owner_end_offset,
            preferred_kind,
            reason,
            owner_label);
        start = chunk_end;
    }
}

static void raw_all_image_safety_append_dense_lookback(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t image_offset,
    uint64_t image_end,
    RawAllImageSafetyKind preferred_kind,
    const char *owner_label
)
{
    uint64_t start;

    if (queue == NULL ||
        image_offset == 0U ||
        image_end <= image_offset ||
        image_end - image_offset < RAW_ALL_IMAGE_SAFETY_MIN_CLAIM_BYTES) {
        return;
    }

    start = image_offset > RAW_ALL_IMAGE_SAFETY_DENSE_LOOKBACK_BYTES
        ? image_offset - RAW_ALL_IMAGE_SAFETY_DENSE_LOOKBACK_BYTES
        : 0U;
    raw_all_image_safety_append_interval(
        queue,
        config,
        start,
        image_offset,
        image_offset,
        image_end,
        preferred_kind,
        "dense_lookback",
        owner_label);
}

static void raw_all_image_safety_append_jpeg_jump_audit(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t image_offset,
    uint64_t image_end,
    const char *owner_label
)
{
    uint64_t span_end;

    if (queue == NULL ||
        image_offset == 0U ||
        image_end <= image_offset ||
        image_end - image_offset < RAW_ALL_IMAGE_SAFETY_MIN_CLAIM_BYTES) {
        return;
    }

    raw_all_image_safety_append_dense_lookback(
        queue,
        config,
        image_offset,
        image_end,
        RAW_ALL_IMAGE_SAFETY_JPEG,
        owner_label);

    span_end = image_end;
    if (span_end - image_offset > RAW_ALL_IMAGE_SAFETY_JPEG_JUMP_BYTES) {
        span_end = image_offset + RAW_ALL_IMAGE_SAFETY_JPEG_JUMP_BYTES;
    }
    raw_all_image_safety_append_interval(
        queue,
        config,
        image_offset,
        span_end,
        image_offset,
        image_end,
        RAW_ALL_IMAGE_SAFETY_JPEG,
        "jpeg_jump_span",
        owner_label);
}

static void raw_all_image_safety_append_large_claim(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t owner_offset,
    uint64_t owner_end,
    const char *owner_label
)
{
    if (queue == NULL ||
        owner_end <= owner_offset ||
        owner_end - owner_offset < RAW_ALL_IMAGE_SAFETY_MIN_CLAIM_BYTES) {
        return;
    }

    raw_all_image_safety_append_interval(
        queue,
        config,
        owner_offset,
        owner_end,
        owner_offset,
        owner_end,
        0,
        "inside_large_claim",
        owner_label);
}

static void raw_all_image_safety_append_pdf_claim_audit(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    uint64_t owner_offset,
    uint64_t owner_end,
    const char *owner_label
)
{
    if (queue == NULL ||
        owner_end <= owner_offset ||
        owner_end - owner_offset < RAW_ALL_PDF_SAFETY_MIN_CLAIM_BYTES) {
        return;
    }

    raw_all_image_safety_append_interval(
        queue,
        config,
        owner_offset,
        owner_end,
        owner_offset,
        owner_end,
        RAW_ALL_IMAGE_SAFETY_PDF,
        "pdf_claim_span",
        owner_label);
}

static int raw_all_image_safety_kind_is_video_candidate(
    RawAllImageSafetyKind kind
)
{
    return kind == RAW_ALL_IMAGE_SAFETY_MOV ||
           kind == RAW_ALL_IMAGE_SAFETY_RIFF ||
           kind == RAW_ALL_IMAGE_SAFETY_MPEG_PS ||
           kind == RAW_ALL_IMAGE_SAFETY_AAC ||
           kind == RAW_ALL_IMAGE_SAFETY_MKV;
}

static void raw_all_video_candidate_audit_append_report(
    const AppConfig *config,
    const RawAllImageSafetyCandidate *candidate,
    const char *status,
    size_t confirmed_span
)
{
    char path[1024];
    struct stat st;
    int have_existing = 0;
    FILE *file;

    if (!raw_all_diagnostic_audit_logs_enabled()) {
        (void)config;
        (void)candidate;
        (void)status;
        (void)confirmed_span;
        return;
    }

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        candidate == NULL ||
        !raw_all_image_safety_kind_is_video_candidate(candidate->kind)) {
        return;
    }

    if (snprintf(
            path,
            sizeof(path),
            "%s/%s",
            config->output_dir,
            RAW_ALL_VIDEO_CANDIDATE_AUDIT_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    file = fopen(path, "a");
    if (file == NULL) {
        return;
    }

    if (!have_existing) {
        fprintf(
            file,
            "offset\tkind\treason\tstatus\tconfirmed_span\towner_offset\towner_end_offset\towner_label\n"
        );
    }
    fprintf(
        file,
        "%llu\t%s\t%s\t%s\t%zu\t%llu\t%llu\t%s\n",
        (unsigned long long)candidate->offset,
        raw_all_image_safety_kind_name(candidate->kind),
        candidate->reason,
        status != NULL ? status : "unknown",
        confirmed_span,
        (unsigned long long)candidate->owner_offset,
        (unsigned long long)candidate->owner_end_offset,
        candidate->owner_label
    );
    fclose(file);
}

static void raw_all_pdf_candidate_audit_append_report(
    const AppConfig *config,
    const RawAllImageSafetyCandidate *candidate,
    const char *status,
    size_t confirmed_span
)
{
    char path[1024];
    struct stat st;
    int have_existing = 0;
    FILE *file;

    if (!raw_all_diagnostic_audit_logs_enabled()) {
        (void)config;
        (void)candidate;
        (void)status;
        (void)confirmed_span;
        return;
    }

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        candidate == NULL ||
        candidate->kind != RAW_ALL_IMAGE_SAFETY_PDF) {
        return;
    }

    if (snprintf(
            path,
            sizeof(path),
            "%s/%s",
            config->output_dir,
            RAW_ALL_PDF_CANDIDATE_AUDIT_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    file = fopen(path, "a");
    if (file == NULL) {
        return;
    }

    if (!have_existing) {
        fprintf(
            file,
            "offset\tkind\treason\tstatus\tconfirmed_span\towner_offset\towner_end_offset\towner_label\n"
        );
    }
    fprintf(
        file,
        "%llu\t%s\t%s\t%s\t%zu\t%llu\t%llu\t%s\n",
        (unsigned long long)candidate->offset,
        raw_all_image_safety_kind_name(candidate->kind),
        candidate->reason,
        status != NULL ? status : "unknown",
        confirmed_span,
        (unsigned long long)candidate->owner_offset,
        (unsigned long long)candidate->owner_end_offset,
        candidate->owner_label
    );
    fclose(file);
}

static void raw_all_claim_candidate_audit_append_report(
    const AppConfig *config,
    const RawAllImageSafetyCandidate *candidate,
    const RawAllClaimAuditValidation *validation
)
{
    char path[1024];
    struct stat st;
    int have_existing = 0;
    FILE *file;
    uint64_t owner_claim_span = 0U;
    uint64_t first_child_start = 0U;
    uint64_t first_child_end = 0U;

    if (!raw_all_diagnostic_audit_logs_enabled()) {
        (void)config;
        (void)candidate;
        (void)validation;
        return;
    }

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        candidate == NULL ||
        validation == NULL) {
        return;
    }
    if (candidate->owner_end_offset > candidate->owner_offset) {
        owner_claim_span = candidate->owner_end_offset - candidate->owner_offset;
    }
    if (validation->child_range_count > 0U) {
        first_child_start = validation->child_ranges[0].start;
        first_child_end = validation->child_ranges[0].end;
    }

    if (snprintf(
            path,
            sizeof(path),
            "%s/%s",
            config->output_dir,
            RAW_ALL_CLAIM_CANDIDATE_AUDIT_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    file = fopen(path, "a");
    if (file == NULL) {
        return;
    }

    if (!have_existing) {
        fprintf(
            file,
            "updated_unix\tgeneration\tpass_id\toffset\tkind\treason\tstatus\treject_reason\ttrailing_child_reason\tconfirmed_span\tvalidated_claim_span\towner_claim_span\towner_offset\towner_end_offset\towner_label\tchild_ranges\tchild_truncated\tfirst_child_start\tfirst_child_end\n"
        );
    }
    fprintf(
        file,
        "%llu\t%llu\t",
        (unsigned long long)time(NULL),
        (unsigned long long)carv_run_supervisor_generation_inline()
    );
    performance_ledger_write_text_inline(file, carv_run_pass_id_inline());
    fprintf(
        file,
        "\t%llu\t%s\t",
        (unsigned long long)candidate->offset,
        raw_all_image_safety_kind_name(candidate->kind)
    );
    performance_ledger_write_text_inline(file, candidate->reason);
    fputc('\t', file);
    performance_ledger_write_text_inline(
        file,
        validation->status[0] != '\0' ? validation->status : "unknown"
    );
    fputc('\t', file);
    performance_ledger_write_text_inline(
        file,
        validation->reject_reason
    );
    fputc('\t', file);
    performance_ledger_write_text_inline(
        file,
        validation->trailing_child_reason
    );
    fprintf(
        file,
        "\t%zu\t%llu\t%llu\t%llu\t%llu\t",
        validation->confirmed_span,
        (unsigned long long)validation->claim_span,
        (unsigned long long)owner_claim_span,
        (unsigned long long)candidate->owner_offset,
        (unsigned long long)candidate->owner_end_offset
    );
    performance_ledger_write_text_inline(file, candidate->owner_label);
    fprintf(
        file,
        "\t%zu\t%d\t%llu\t%llu\n",
        validation->child_range_count,
        validation->child_range_truncated,
        (unsigned long long)first_child_start,
        (unsigned long long)first_child_end
    );
    fclose(file);
}

static void raw_all_image_safety_append_report(
    const AppConfig *config,
    const RawAllImageSafetyCandidate *candidate,
    const char *status,
    size_t confirmed_span
)
{
    char path[1024];
    struct stat st;
    int have_existing = 0;
    FILE *file;

    if (!raw_all_diagnostic_audit_logs_enabled()) {
        (void)config;
        (void)candidate;
        (void)status;
        (void)confirmed_span;
        return;
    }

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        candidate == NULL) {
        return;
    }

    if (snprintf(
            path,
            sizeof(path),
            "%s/%s",
            config->output_dir,
            RAW_ALL_IMAGE_SAFETY_REPORT_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    file = fopen(path, "a");
    if (file == NULL) {
        return;
    }

    if (!have_existing) {
        fprintf(
            file,
            "offset\tkind\treason\tstatus\tconfirmed_span\towner_offset\towner_end_offset\towner_label\n"
        );
    }
    fprintf(
        file,
        "%llu\t%s\t%s\t%s\t%zu\t%llu\t%llu\t%s\n",
        (unsigned long long)candidate->offset,
        raw_all_image_safety_kind_name(candidate->kind),
        candidate->reason,
        status != NULL ? status : "unknown",
        confirmed_span,
        (unsigned long long)candidate->owner_offset,
        (unsigned long long)candidate->owner_end_offset,
        candidate->owner_label
    );
    fclose(file);

    raw_all_video_candidate_audit_append_report(
        config,
        candidate,
        status,
        confirmed_span);
    raw_all_pdf_candidate_audit_append_report(
        config,
        candidate,
        status,
        confirmed_span);
}

static void raw_all_image_safety_scan_buffer_for_candidates_with_mutex(
    RawAllImageSafetyQueue *queue,
    const RawAllImageSafetyInterval *interval,
    const uint8_t *buffer,
    size_t buffer_length,
    uint64_t buffer_base,
    const FormatPipelineDispatchContext *dispatch_context,
    pthread_mutex_t *candidate_mutex
)
{
    uint64_t scan_start;
    uint64_t scan_end;
    uint64_t abs;
    uint64_t owner_end_offset;
    const RawAllClaimAuditProbe *probes;
    size_t probe_count = 0U;
    size_t min_required_bytes = 0U;
    int have_allowed_probe = 0;
    size_t probe_index;

    if (queue == NULL || interval == NULL || buffer == NULL || buffer_length < 12U) {
        return;
    }

    scan_start = interval->start > buffer_base ? interval->start : buffer_base;
    scan_end = interval->end < buffer_base + (uint64_t)buffer_length
        ? interval->end
        : buffer_base + (uint64_t)buffer_length;
    if (scan_end <= scan_start + 12U) {
        return;
    }

    probes = raw_all_claim_audit_probes(&probe_count);
    for (probe_index = 0U; probe_index < probe_count; probe_index++) {
        if (raw_all_claim_audit_probe_allowed_for_interval(
                &probes[probe_index],
                interval,
                dispatch_context)) {
            have_allowed_probe = 1;
            if (min_required_bytes == 0U ||
                probes[probe_index].min_bytes < min_required_bytes) {
                min_required_bytes = probes[probe_index].min_bytes;
            }
        }
    }
    if (!have_allowed_probe) {
        return;
    }

    owner_end_offset = interval->owner_end_offset > interval->owner_offset
        ? interval->owner_end_offset
        : interval->end;
    abs = scan_start;
    if ((abs % 512U) != 0U) {
        abs += 512U - (abs % 512U);
    }

    for (; abs + min_required_bytes <= scan_end && !raw_all_should_stop(); abs += 512U) {
        size_t rel = (size_t)(abs - buffer_base);
        int matched = 0;

        for (probe_index = 0U; probe_index < probe_count; probe_index++) {
            const RawAllClaimAuditProbe *probe = &probes[probe_index];

            if (!raw_all_claim_audit_probe_allowed_for_interval(
                    probe,
                    interval,
                    dispatch_context) ||
                abs + (uint64_t)probe->min_bytes > scan_end ||
                probe->probe == NULL ||
                !probe->probe(buffer, buffer_length, rel)) {
                continue;
            }

            if (candidate_mutex != NULL) {
                pthread_mutex_lock(candidate_mutex);
            }
            (void)raw_all_image_safety_push_candidate(
                queue,
                abs,
                interval->owner_offset,
                owner_end_offset,
                probe->kind,
                interval->reason,
                interval->owner_label);
            if (candidate_mutex != NULL) {
                pthread_mutex_unlock(candidate_mutex);
            }
            matched = 1;
            break;
        }
        if (matched) {
            continue;
        }
    }
}

static void raw_all_image_safety_scan_buffer_for_candidates(
    RawAllImageSafetyQueue *queue,
    const RawAllImageSafetyInterval *interval,
    const uint8_t *buffer,
    size_t buffer_length,
    uint64_t buffer_base,
    const FormatPipelineDispatchContext *dispatch_context
)
{
    raw_all_image_safety_scan_buffer_for_candidates_with_mutex(
        queue,
        interval,
        buffer,
        buffer_length,
        buffer_base,
        dispatch_context,
        NULL);
}

typedef struct {
    RawAllImageSafetyQueue *queue;
    const char *source_path;
    size_t chunk_size;
    const FormatPipelineDispatchContext *dispatch_context;
    pthread_mutex_t work_mutex;
    pthread_mutex_t candidate_mutex;
    size_t next_interval;
} RawAllClaimDiscoveryShared;

typedef struct {
    RawAllClaimDiscoveryShared *shared;
    size_t intervals_scanned;
    uint64_t bytes_scanned;
    int had_error;
} RawAllClaimDiscoveryWorker;

static void *raw_all_claim_discovery_worker_main(void *opaque)
{
    RawAllClaimDiscoveryWorker *worker = (RawAllClaimDiscoveryWorker *)opaque;
    RawAllClaimDiscoveryShared *shared;
    uint8_t *buffer = NULL;
    int fd = -1;

    if (worker == NULL || worker->shared == NULL) {
        return NULL;
    }
    shared = worker->shared;
    if (shared->source_path == NULL ||
        shared->source_path[0] == '\0' ||
        shared->chunk_size == 0U) {
        worker->had_error = 1;
        return NULL;
    }

#ifdef O_CLOEXEC
    fd = open(shared->source_path, O_RDONLY | O_CLOEXEC);
#else
    fd = open(shared->source_path, O_RDONLY);
#endif
    if (fd < 0) {
        worker->had_error = 1;
        return NULL;
    }
    buffer = (uint8_t *)malloc(shared->chunk_size);
    if (buffer == NULL) {
        close(fd);
        worker->had_error = 1;
        return NULL;
    }

    while (!raw_all_should_stop()) {
        RawAllImageSafetyInterval *interval = NULL;
        size_t interval_index;
        uint64_t cursor;

        pthread_mutex_lock(&shared->work_mutex);
        while (shared->next_interval < shared->queue->interval_count) {
            interval_index = shared->next_interval++;
            if (!shared->queue->intervals[interval_index].scanned) {
                interval = &shared->queue->intervals[interval_index];
                interval->scanned = 2;
                break;
            }
        }
        pthread_mutex_unlock(&shared->work_mutex);

        if (interval == NULL) {
            break;
        }

        cursor = interval->start;
        while (cursor < interval->end && !raw_all_should_stop()) {
            uint64_t remaining = interval->end - cursor;
            size_t want = shared->chunk_size;
            ssize_t bytes_read;

            if ((uint64_t)want > remaining) {
                want = (size_t)remaining;
            }
            if (want == 0U) {
                break;
            }

            bytes_read = pread(fd, buffer, want, (off_t)cursor);
            if (bytes_read <= 0) {
                worker->had_error = 1;
                break;
            }

            raw_all_image_safety_scan_buffer_for_candidates_with_mutex(
                shared->queue,
                interval,
                buffer,
                (size_t)bytes_read,
                cursor,
                shared->dispatch_context,
                &shared->candidate_mutex);

            worker->bytes_scanned += (uint64_t)bytes_read;
            cursor += (uint64_t)bytes_read;
            if ((size_t)bytes_read < want) {
                break;
            }
        }

        interval->scanned = 1;
        worker->intervals_scanned++;
    }

    free(buffer);
    close(fd);
    return NULL;
}

static int raw_all_image_safety_discover_candidates_parallel(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const FormatPipelineDispatchContext *dispatch_context,
    size_t pending_intervals
)
{
    RawAllClaimDiscoveryShared shared;
    RawAllClaimDiscoveryWorker workers[4];
    pthread_t threads[4];
    int thread_started[4] = {0};
    size_t worker_count;
    size_t started = 0U;
    size_t i;
    size_t intervals_scanned = 0U;
    uint64_t bytes_scanned = 0U;

    if (queue == NULL ||
        reader == NULL ||
        !reader->source_is_regular_file ||
        reader->path == NULL ||
        reader->path[0] == '\0' ||
        pending_intervals < 2U ||
        queue->discovery_worker_count < 2U) {
        return 0;
    }

    worker_count = queue->discovery_worker_count;
    if (worker_count > sizeof(workers) / sizeof(workers[0])) {
        worker_count = sizeof(workers) / sizeof(workers[0]);
    }
    if (worker_count > pending_intervals) {
        worker_count = pending_intervals;
    }
    if (worker_count < 2U) {
        return 0;
    }

    memset(&shared, 0, sizeof(shared));
    memset(workers, 0, sizeof(workers));
    shared.queue = queue;
    shared.source_path = reader->path;
    shared.chunk_size = raw_all_claim_audit_effective_chunk_cap_bytes(
        queue,
        reader,
        RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT,
        1);
    shared.dispatch_context = dispatch_context;
    if (shared.chunk_size == 0U) {
        return 0;
    }
    pthread_mutex_init(&shared.work_mutex, NULL);
    pthread_mutex_init(&shared.candidate_mutex, NULL);

    log_info(
        "Claim safety sweep: using %zu bounded discovery worker%s for %zu suspicious intervals (chunk %.1f MiB); recovery validation remains serialized",
        worker_count,
        worker_count == 1U ? "" : "s",
        pending_intervals,
        (double)shared.chunk_size / (1024.0 * 1024.0)
    );

    for (i = 0U; i < worker_count; i++) {
        workers[i].shared = &shared;
        if (pthread_create(&threads[i], NULL, raw_all_claim_discovery_worker_main, &workers[i]) != 0) {
            workers[i].had_error = 1;
            continue;
        }
        thread_started[i] = 1;
        started++;
    }

    if (started == 0U) {
        pthread_mutex_destroy(&shared.candidate_mutex);
        pthread_mutex_destroy(&shared.work_mutex);
        return 0;
    }

    for (i = 0U; i < worker_count; i++) {
        if (thread_started[i]) {
            pthread_join(threads[i], NULL);
        }
    }

    for (i = 0U; i < worker_count; i++) {
        intervals_scanned += workers[i].intervals_scanned;
        bytes_scanned += workers[i].bytes_scanned;
    }
    queue->audit_intervals_scanned += (uint64_t)intervals_scanned;
    queue->audit_bytes_scanned += bytes_scanned;

    pthread_mutex_destroy(&shared.candidate_mutex);
    pthread_mutex_destroy(&shared.work_mutex);

    return intervals_scanned > 0U;
}

static void raw_all_image_safety_discover_candidates(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const FormatPipelineDispatchContext *dispatch_context
)
{
    size_t interval_index;
    size_t intervals_scanned = 0U;
    uint64_t bytes_scanned = 0U;
    size_t pending_intervals;
    size_t saved_chunk_size = 0U;

    if (queue == NULL ||
        reader == NULL ||
        queue->interval_count == 0U) {
        return;
    }

    pending_intervals = raw_all_image_safety_unscanned_interval_count(queue);
    if (pending_intervals == 0U) {
        return;
    }

    saved_chunk_size = reader->chunk_size;

    log_info(
        "Claim safety sweep: scanning %zu pending suspicious interval%s (%zu total; %.1f MiB queued, %.1f MiB video-audit, %.1f MiB child-audit, %.1f MiB dropped by budget; region=%.1f MiB generic=%.1f MiB video_dropped=%.1f MiB child_dropped=%.1f MiB)",
        pending_intervals,
        pending_intervals == 1U ? "" : "s",
        queue->interval_count,
        (double)queue->interval_bytes_queued / (1024.0 * 1024.0),
        (double)queue->video_audit_interval_bytes_queued / (1024.0 * 1024.0),
        (double)queue->child_audit_interval_bytes_queued / (1024.0 * 1024.0),
        (double)queue->interval_bytes_dropped / (1024.0 * 1024.0),
        (double)queue->interval_region_bytes_dropped / (1024.0 * 1024.0),
        (double)queue->interval_generic_bytes_dropped / (1024.0 * 1024.0),
        (double)queue->video_audit_interval_bytes_dropped / (1024.0 * 1024.0),
        (double)queue->child_audit_interval_bytes_dropped / (1024.0 * 1024.0)
    );

    if (raw_all_image_safety_discover_candidates_parallel(
            queue,
            reader,
            dispatch_context,
            pending_intervals)) {
        reader->chunk_size = saved_chunk_size;
        return;
    }

    for (interval_index = 0U;
         interval_index < queue->interval_count && !raw_all_should_stop();
         interval_index++) {
        RawAllImageSafetyInterval *interval = &queue->intervals[interval_index];
        uint64_t cursor = interval->start;

        if (interval->scanned) {
            continue;
        }

        while (cursor < interval->end && !raw_all_should_stop()) {
            uint64_t buffer_base;
            uint64_t buffer_end;
            uint64_t remaining;
            size_t limited_chunk_size;
            size_t bytes_read;

            if (!reader_seek_absolute(reader, cursor)) {
                break;
            }
            remaining = interval->end - cursor;
            limited_chunk_size = raw_all_claim_audit_effective_chunk_cap_bytes(
                queue,
                reader,
                interval->preferred_kind,
                1
            );
            if (limited_chunk_size == 0U) {
                limited_chunk_size = saved_chunk_size;
            }
            if ((uint64_t)limited_chunk_size > remaining) {
                limited_chunk_size = (size_t)remaining;
            }
            if (limited_chunk_size == 0U) {
                break;
            }
            reader->chunk_size = limited_chunk_size;
            bytes_read = reader_read_next(reader);
            reader->chunk_size = saved_chunk_size;
            if (bytes_read == 0U || reader->bytes_in_buffer == 0U) {
                break;
            }

            buffer_base =
                (uint64_t)(reader->total_bytes_read - reader->bytes_in_buffer);
            buffer_end = buffer_base + (uint64_t)reader->bytes_in_buffer;
            if (buffer_end > interval->end) {
                buffer_end = interval->end;
            }
            raw_all_image_safety_scan_buffer_for_candidates(
                queue,
                interval,
                reader->buffer,
                reader->bytes_in_buffer,
                buffer_base,
                dispatch_context);

            if (buffer_end <= cursor) {
                break;
            }
            bytes_scanned += buffer_end - cursor;
            cursor = buffer_end;
        }
        interval->scanned = 1;
        intervals_scanned++;
    }
    queue->audit_intervals_scanned += (uint64_t)intervals_scanned;
    queue->audit_bytes_scanned += bytes_scanned;
    reader->chunk_size = saved_chunk_size;

    log_info(
        "Claim safety sweep discovery: intervals_scanned=%zu bytes=%.1f MiB candidates=%zu video_audit_intervals=%llu child_audit_intervals=%llu drops(candidate=%llu interval=%llu duplicate=%llu interval_bytes=%.1f MiB region=%.1f MiB generic=%.1f MiB video_dropped=%.1f MiB child_dropped=%.1f MiB)",
        intervals_scanned,
        (double)bytes_scanned / (1024.0 * 1024.0),
        queue->candidate_count,
        (unsigned long long)queue->video_audit_interval_count,
        (unsigned long long)queue->child_audit_interval_count,
        (unsigned long long)queue->candidate_capacity_drops,
        (unsigned long long)queue->interval_capacity_drops,
        (unsigned long long)queue->candidate_duplicates,
        (double)queue->interval_bytes_dropped / (1024.0 * 1024.0),
        (double)queue->interval_region_bytes_dropped / (1024.0 * 1024.0),
        (double)queue->interval_generic_bytes_dropped / (1024.0 * 1024.0),
        (double)queue->video_audit_interval_bytes_dropped / (1024.0 * 1024.0),
        (double)queue->child_audit_interval_bytes_dropped / (1024.0 * 1024.0)
    );
}

static const MagicEntry *raw_all_image_safety_synthetic_match(
    RawAllImageSafetyKind kind
)
{
    static MagicEntry mov_match = {
        .id = -1001,
        .name = "Claim-rescue ftyp",
        .type = "mp4",
        .type_name = "MOV/MP4",
        .category = "video"
    };
    static MagicEntry riff_match = {
        .id = -1002,
        .name = "Claim-rescue RIFF",
        .type = "riff",
        .type_name = "RIFF",
        .category = "video"
    };
    static MagicEntry mpeg_ps_match = {
        .id = -1003,
        .name = "Claim-rescue MPEG-PS",
        .type = "mpg",
        .type_name = "MPEG-PS",
        .category = "video"
    };
    static MagicEntry aac_match = {
        .id = -1004,
        .name = "Claim-rescue AAC",
        .type = "aac",
        .type_name = "AAC",
        .category = "audio"
    };
    static MagicEntry pdf_match = {
        .id = -1005,
        .name = "Claim-rescue PDF",
        .type = "pdf",
        .type_name = "PDF",
        .category = "document"
    };
    static MagicEntry mkv_match = {
        .id = -1006,
        .name = "Claim-rescue MKV",
        .type = "mkv",
        .type_name = "MKV/WebM",
        .category = "video"
    };

    switch (kind) {
        case RAW_ALL_IMAGE_SAFETY_MOV:
            return &mov_match;
        case RAW_ALL_IMAGE_SAFETY_RIFF:
            return &riff_match;
        case RAW_ALL_IMAGE_SAFETY_MPEG_PS:
            return &mpeg_ps_match;
        case RAW_ALL_IMAGE_SAFETY_AAC:
            return &aac_match;
        case RAW_ALL_IMAGE_SAFETY_PDF:
            return &pdf_match;
        case RAW_ALL_IMAGE_SAFETY_MKV:
            return &mkv_match;
        default:
            return NULL;
    }
}

static const RawAllClaimAuditProbe *raw_all_claim_audit_probe_for_kind(
    RawAllImageSafetyKind kind
)
{
    const RawAllClaimAuditProbe *probes;
    size_t probe_count = 0U;
    size_t i;

    probes = raw_all_claim_audit_probes(&probe_count);
    for (i = 0U; i < probe_count; i++) {
        if (probes[i].kind == kind) {
            return &probes[i];
        }
    }
    return NULL;
}

static void raw_all_claim_audit_validation_init(
    const RawAllImageSafetyCandidate *candidate,
    RawAllClaimAuditValidation *out
)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->attempted = 1;
    snprintf(out->status, sizeof(out->status), "%s", "rejected");
    snprintf(out->reject_reason, sizeof(out->reject_reason), "%s", "not_run");
    (void)candidate;
}

static void raw_all_claim_audit_validation_set_status(
    RawAllClaimAuditValidation *validation,
    const char *status,
    const char *reject_reason
)
{
    if (validation == NULL) {
        return;
    }
    snprintf(
        validation->status,
        sizeof(validation->status),
        "%s",
        status != NULL && status[0] != '\0' ? status : "unknown"
    );
    snprintf(
        validation->reject_reason,
        sizeof(validation->reject_reason),
        "%s",
        reject_reason != NULL ? reject_reason : ""
    );
}

static void raw_all_claim_audit_validation_add_child_range(
    RawAllClaimAuditValidation *validation,
    uint64_t start,
    uint64_t end,
    RawAllImageSafetyKind preferred_kind,
    const char *reason
)
{
    size_t index;

    if (validation == NULL || end <= start) {
        return;
    }
    if (validation->child_range_count >= RAW_ALL_CLAIM_AUDIT_MAX_CHILD_RANGES) {
        validation->child_range_truncated = 1;
        return;
    }
    index = validation->child_range_count++;
    validation->child_ranges[index].start = start;
    validation->child_ranges[index].end = end;
    validation->child_ranges[index].preferred_kind = preferred_kind;
    raw_all_copy_small_string(
        validation->child_ranges[index].reason,
        sizeof(validation->child_ranges[index].reason),
        reason);
}

static void raw_all_claim_audit_validation_import_carver_report(
    RawAllClaimAuditValidation *validation,
    const CarverAuditReport *report,
    RawAllImageSafetyKind preferred_kind
)
{
    size_t i;

    if (validation == NULL || report == NULL) {
        return;
    }
    if (report->confirmed_span > 0U) {
        validation->confirmed_span = report->confirmed_span;
        validation->claim_span = report->confirmed_span;
    }
    if (report->status[0] != '\0' || report->reject_reason[0] != '\0') {
        raw_all_claim_audit_validation_set_status(
            validation,
            report->status,
            report->reject_reason);
    }
    if (report->trailing_child_reason[0] != '\0') {
        raw_all_copy_small_string(
            validation->trailing_child_reason,
            sizeof(validation->trailing_child_reason),
            report->trailing_child_reason);
    }
    for (i = 0U; i < report->child_range_count; i++) {
        raw_all_claim_audit_validation_add_child_range(
            validation,
            report->child_ranges[i].start,
            report->child_ranges[i].end,
            preferred_kind,
            report->child_ranges[i].reason);
    }
    if (report->child_range_truncated) {
        validation->child_range_truncated = 1;
    }
}

static const char *raw_all_claim_audit_post_span_reason(
    const RawAllImageSafetyCandidate *candidate,
    const RawAllClaimAuditValidation *validation
)
{
    if (validation != NULL && validation->trailing_child_reason[0] != '\0') {
        return validation->trailing_child_reason;
    }
    if (candidate == NULL) {
        return "post_validated_span";
    }
    switch (candidate->kind) {
        case RAW_ALL_IMAGE_SAFETY_MOV:
            return "mov_after_last_atom";
        case RAW_ALL_IMAGE_SAFETY_MKV:
            return "mkv_after_segment";
        case RAW_ALL_IMAGE_SAFETY_PDF:
            return "pdf_after_valid_span";
        case RAW_ALL_IMAGE_SAFETY_JPEG:
            return "jpeg_after_eoi";
        case RAW_ALL_IMAGE_SAFETY_PNG:
            return "png_after_iend";
        default:
            return "post_validated_span";
    }
}

static void raw_all_claim_audit_validation_add_post_span_range(
    const RawAllImageSafetyCandidate *candidate,
    RawAllClaimAuditValidation *validation
)
{
    uint64_t child_start;

    if (candidate == NULL ||
        validation == NULL ||
        !validation->recovered ||
        validation->confirmed_span == 0U ||
        candidate->owner_end_offset <= candidate->offset) {
        return;
    }

    child_start = candidate->offset + (uint64_t)validation->confirmed_span;
    if (candidate->owner_end_offset <= child_start + 4096U) {
        return;
    }
    raw_all_claim_audit_validation_add_child_range(
        validation,
        child_start,
        candidate->owner_end_offset,
        RAW_ALL_IMAGE_SAFETY_CHILD_AUDIT,
        raw_all_claim_audit_post_span_reason(candidate, validation));
}

static int raw_all_claim_audit_validate_jpeg(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const RawAllImageSafetyCandidate *candidate,
    size_t start_offset,
    RawAllClaimAuditValidation *out
)
{
    int ok;

    (void)queue;
    (void)config;
    (void)active_order;
    (void)dispatch_context;
    raw_all_claim_audit_validation_init(candidate, out);
    if (reader == NULL || candidate == NULL || out == NULL) {
        return 0;
    }

    ok = carver_jpeg_from_reader(
        reader,
        start_offset,
        (size_t)candidate->offset,
        &out->confirmed_span);
    if (ok && out->confirmed_span > 0U) {
        out->recovered = 1;
        out->claim_span = out->confirmed_span;
        raw_all_claim_audit_validation_set_status(out, "recovered", "");
        raw_all_claim_audit_validation_add_post_span_range(candidate, out);
    } else {
        raw_all_claim_audit_validation_set_status(
            out,
            "rejected",
            "jpeg_carver_rejected");
    }
    return 1;
}

static int raw_all_claim_audit_validate_png(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const RawAllImageSafetyCandidate *candidate,
    size_t start_offset,
    RawAllClaimAuditValidation *out
)
{
    int ok;

    (void)queue;
    (void)config;
    (void)active_order;
    (void)dispatch_context;
    raw_all_claim_audit_validation_init(candidate, out);
    if (reader == NULL || candidate == NULL || out == NULL) {
        return 0;
    }

    ok = carver_png_from_reader(
        reader,
        start_offset,
        (size_t)candidate->offset,
        &out->confirmed_span);
    if (ok && out->confirmed_span > 0U) {
        out->recovered = 1;
        out->claim_span = out->confirmed_span;
        raw_all_claim_audit_validation_set_status(out, "recovered", "");
        raw_all_claim_audit_validation_add_post_span_range(candidate, out);
    } else {
        raw_all_claim_audit_validation_set_status(
            out,
            "rejected",
            "png_carver_rejected");
    }
    return 1;
}

static int raw_all_claim_audit_validate_pdf(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const RawAllImageSafetyCandidate *candidate,
    size_t start_offset,
    RawAllClaimAuditValidation *out
)
{
    int ok;
    const char *reject_reason;
    CarverAuditReport report;

    (void)queue;
    (void)config;
    (void)active_order;
    (void)dispatch_context;
    raw_all_claim_audit_validation_init(candidate, out);
    if (reader == NULL || candidate == NULL || out == NULL) {
        return 0;
    }

    ok = carver_pdf_from_reader(
        reader,
        start_offset,
        (size_t)candidate->offset,
        &out->confirmed_span);
    if (ok && out->confirmed_span > 0U) {
        out->recovered = 1;
        out->claim_span = out->confirmed_span;
        raw_all_claim_audit_validation_set_status(out, "recovered", "");
        carver_pdf_get_last_audit(&report);
        raw_all_claim_audit_validation_import_carver_report(
            out,
            &report,
            RAW_ALL_IMAGE_SAFETY_PDF);
        raw_all_claim_audit_validation_add_post_span_range(candidate, out);
        return 1;
    }

    carver_pdf_get_last_audit(&report);
    raw_all_claim_audit_validation_import_carver_report(
        out,
        &report,
        RAW_ALL_IMAGE_SAFETY_PDF);
    reject_reason = carver_pdf_last_reject_reason();
    if (reject_reason == NULL ||
        reject_reason[0] == '\0' ||
        strcmp(reject_reason, "accepted") == 0 ||
        strcmp(reject_reason, "not_run") == 0) {
        reject_reason = "pdf_carver_rejected";
    }
    raw_all_claim_audit_validation_set_status(out, "rejected", reject_reason);
    return 1;
}

static int raw_all_claim_audit_validate_pipeline(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const RawAllImageSafetyCandidate *candidate,
    size_t start_offset,
    RawAllClaimAuditValidation *out
)
{
    const MagicEntry *synthetic_match;
    size_t local_resume;
    FormatPipelineDispatchResult dispatch_result;
    CarverAuditReport format_report;
    int have_format_report = 0;

    (void)queue;
    raw_all_claim_audit_validation_init(candidate, out);
    if (reader == NULL || candidate == NULL || out == NULL) {
        return 0;
    }

    synthetic_match = raw_all_image_safety_synthetic_match(candidate->kind);
    if (synthetic_match == NULL) {
        raw_all_claim_audit_validation_set_status(
            out,
            "rejected",
            "unsupported_kind");
        return 1;
    }

    local_resume = start_offset;
    if (candidate->kind == RAW_ALL_IMAGE_SAFETY_MOV) {
        carver_mov_reset_last_audit();
    } else if (candidate->kind == RAW_ALL_IMAGE_SAFETY_RIFF) {
        carver_riff_reset_last_audit();
    } else if (candidate->kind == RAW_ALL_IMAGE_SAFETY_MPEG_PS) {
        carver_mpeg_ps_reset_last_audit();
    } else if (candidate->kind == RAW_ALL_IMAGE_SAFETY_MKV) {
        carver_mkv_reset_last_audit();
    }
    dispatch_result = format_pipeline_dispatch_raw_match_with_context(
        reader,
        config,
        active_order,
        dispatch_context,
        NULL,
        synthetic_match,
        start_offset,
        (size_t)candidate->offset,
        &local_resume
    );
    memset(&format_report, 0, sizeof(format_report));
    if (candidate->kind == RAW_ALL_IMAGE_SAFETY_MOV) {
        carver_mov_get_last_audit(&format_report);
        have_format_report = strcmp(format_report.status, "not_run") != 0;
    } else if (candidate->kind == RAW_ALL_IMAGE_SAFETY_RIFF) {
        carver_riff_get_last_audit(&format_report);
        have_format_report = strcmp(format_report.status, "not_run") != 0;
    } else if (candidate->kind == RAW_ALL_IMAGE_SAFETY_MPEG_PS) {
        carver_mpeg_ps_get_last_audit(&format_report);
        have_format_report = strcmp(format_report.status, "not_run") != 0;
    } else if (candidate->kind == RAW_ALL_IMAGE_SAFETY_MKV) {
        carver_mkv_get_last_audit(&format_report);
        have_format_report = strcmp(format_report.status, "not_run") != 0;
    }
    if (dispatch_result == FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME) {
        out->recovered = 1;
        if (local_resume > start_offset) {
            out->confirmed_span = local_resume - start_offset;
            out->claim_span = out->confirmed_span;
        }
        raw_all_claim_audit_validation_set_status(out, "recovered", "");
        if (have_format_report) {
            raw_all_claim_audit_validation_import_carver_report(
                out,
                &format_report,
                candidate->kind);
        }
        raw_all_claim_audit_validation_add_post_span_range(candidate, out);
    } else if (dispatch_result == FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED) {
        raw_all_claim_audit_validation_set_status(
            out,
            "skipped_disabled",
            "disabled_by_format_filter");
    } else if (dispatch_result == FORMAT_PIPELINE_DISPATCH_NO_HANDLER) {
        raw_all_claim_audit_validation_set_status(
            out,
            "rejected",
            "no_pipeline_handler");
    } else {
        raw_all_claim_audit_validation_set_status(
            out,
            "rejected",
            "pipeline_carver_rejected");
    }
    if (have_format_report && !out->recovered) {
        raw_all_claim_audit_validation_import_carver_report(
            out,
            &format_report,
            candidate->kind);
    }
    return 1;
}

static void raw_all_claim_audit_emit_child_ranges(
    RawAllImageSafetyQueue *queue,
    const AppConfig *config,
    const RawAllImageSafetyCandidate *candidate,
    const RawAllClaimAuditValidation *validation
)
{
    size_t i;
    int kind_index;

    if (queue == NULL || candidate == NULL || validation == NULL) {
        return;
    }
    kind_index = raw_all_claim_audit_kind_index(candidate->kind);
    if (kind_index > 0) {
        queue->child_ranges_emitted_by_kind[kind_index] +=
            (uint64_t)validation->child_range_count;
        if (validation->child_range_truncated) {
            queue->child_ranges_truncated_by_kind[kind_index]++;
        }
    }

    for (i = 0U; i < validation->child_range_count; i++) {
        const RawAllClaimAuditChildRange *range = &validation->child_ranges[i];
        if (range->end <= range->start) {
            continue;
        }
        raw_all_image_safety_append_child_audit_interval(
            queue,
            config,
            range->start,
            range->end,
            candidate->offset,
            candidate->offset + validation->claim_span,
            range->reason,
            candidate->owner_label);
    }
}

static void raw_all_image_safety_process_candidates(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    uint64_t primary_pass_end_offset,
    const FormatPipelineDispatchContext *dispatch_context
)
{
    size_t i;
    uint64_t attempted = 0U;
    uint64_t recovered = 0U;
    uint64_t rejected = 0U;
    uint64_t covered_by_earlier = 0U;
    uint64_t covered_start = 0U;
    uint64_t covered_end = 0U;
    size_t pending_candidates;
    size_t saved_chunk_size = 0U;
    RawAllImageSafetyKind covered_kind = 0;

    if (queue == NULL ||
        reader == NULL ||
        queue->candidate_count == 0U) {
        return;
    }

    saved_chunk_size = reader->chunk_size;
    qsort(
        queue->candidates,
        queue->candidate_count,
        sizeof(*queue->candidates),
        raw_all_image_safety_candidate_compare);
    pending_candidates = raw_all_image_safety_unprocessed_candidate_count(queue);

    log_info(
        "Claim safety sweep: validating %zu pending high-confidence claim-audit candidate%s (%zu total)",
        pending_candidates,
        pending_candidates == 1U ? "" : "s",
        queue->candidate_count
    );

    for (i = 0U; i < queue->candidate_count && !raw_all_should_stop(); i++) {
        RawAllImageSafetyCandidate *candidate = &queue->candidates[i];
        size_t start_offset;
        uint64_t buffer_base;
        int kind_index = raw_all_claim_audit_kind_index(candidate->kind);
        const RawAllClaimAuditProbe *probe;
        RawAllClaimAuditValidation validation;
        const char *legacy_status;

        if (candidate->processed) {
            continue;
        }

        if (raw_all_image_safety_candidate_has_processed_twin(queue, i)) {
            queue->candidate_duplicates++;
            candidate->processed = 1;
            continue;
        }

        if (!raw_all_image_safety_kind_allowed(dispatch_context, candidate->kind)) {
            candidate->processed = 1;
            continue;
        }

        if (covered_end > covered_start &&
            candidate->kind == covered_kind &&
            candidate->offset > covered_start &&
            candidate->offset < covered_end) {
            raw_all_image_safety_append_report(
                config,
                candidate,
                "covered_by_earlier_candidate",
                (size_t)(covered_end - covered_start));
            if (kind_index > 0) {
                queue->covered_by_earlier_by_kind[kind_index]++;
            }
            covered_by_earlier++;
            candidate->processed = 1;
            continue;
        }

        {
            size_t existing_resume = 0U;
            if (carver_output_should_skip_existing_recovered(
                    (long long)candidate->offset,
                    0U,
                    &existing_resume)) {
                raw_all_image_safety_append_report(
                    config,
                    candidate,
                    "already_recovered",
                    existing_resume);
                if (kind_index > 0) {
                    queue->already_recovered_by_kind[kind_index]++;
                }
                candidate->processed = 1;
                continue;
            }
        }

        attempted++;
        if (kind_index > 0) {
            queue->attempted_by_kind[kind_index]++;
        }
        raw_all_set_working_progress_limited(reader, config, candidate->offset);
        log_set_working_activity("validating claim-audit candidates");

        reader->chunk_size = raw_all_claim_audit_effective_chunk_cap_bytes(
            queue,
            reader,
            candidate->kind,
            0
        );
        if (reader->chunk_size == 0U) {
            reader->chunk_size = saved_chunk_size;
        }
        if (!reader_seek_absolute(reader, candidate->offset) ||
            reader_read_next(reader) == 0U) {
            reader->chunk_size = saved_chunk_size;
            raw_all_image_safety_append_report(config, candidate, "read_failed", 0U);
            if (kind_index > 0) {
                queue->rejected_by_kind[kind_index]++;
            }
            rejected++;
            candidate->processed = 1;
            continue;
        }
        reader->chunk_size = saved_chunk_size;

        buffer_base =
            (uint64_t)(reader->total_bytes_read - reader->bytes_in_buffer);
        if (candidate->offset < buffer_base ||
            candidate->offset >= buffer_base + (uint64_t)reader->bytes_in_buffer) {
            raw_all_image_safety_append_report(config, candidate, "outside_buffer", 0U);
            if (kind_index > 0) {
                queue->rejected_by_kind[kind_index]++;
            }
            rejected++;
            candidate->processed = 1;
            continue;
        }
        start_offset = (size_t)(candidate->offset - buffer_base);

        probe = raw_all_claim_audit_probe_for_kind(candidate->kind);
        raw_all_claim_audit_validation_init(candidate, &validation);
        if (probe == NULL || probe->validate == NULL) {
            raw_all_claim_audit_validation_set_status(
                &validation,
                "rejected",
                "unsupported_kind");
        } else if (!probe->validate(
                       queue,
                       reader,
                       config,
                       active_order,
                       dispatch_context,
                       candidate,
                       start_offset,
                       &validation)) {
            raw_all_claim_audit_validation_set_status(
                &validation,
                "rejected",
                "validation_failed");
        }

        if (kind_index > 0 && validation.claim_span > 0U) {
            queue->validated_claim_span_by_kind[kind_index] += validation.claim_span;
        }
        raw_all_claim_audit_emit_child_ranges(queue, config, candidate, &validation);
        raw_all_claim_candidate_audit_append_report(config, candidate, &validation);
        legacy_status = validation.recovered
            ? "recovered"
            : (validation.reject_reason[0] != '\0'
                ? validation.reject_reason
                : validation.status);

        if (validation.recovered && validation.confirmed_span > 0U) {
            recovered++;
            if (kind_index > 0) {
                queue->recovered_by_kind[kind_index]++;
            }
            covered_start = candidate->offset;
            covered_end = candidate->offset + (uint64_t)validation.confirmed_span;
            covered_kind = candidate->kind;
            raw_all_image_safety_append_report(
                config,
                candidate,
                "recovered",
                validation.confirmed_span);
        } else {
            rejected++;
            if (kind_index > 0) {
                queue->rejected_by_kind[kind_index]++;
            }
            raw_all_image_safety_append_report(
                config,
                candidate,
                legacy_status,
                validation.confirmed_span);
        }
        candidate->processed = 1;
    }

    log_info(
        "Claim safety sweep finished: attempted=%llu recovered=%llu rejected=%llu duplicates=%llu covered_by_earlier=%llu",
        (unsigned long long)attempted,
        (unsigned long long)recovered,
        (unsigned long long)rejected,
        (unsigned long long)queue->candidate_duplicates,
        (unsigned long long)covered_by_earlier
    );

    raw_all_set_working_progress_limited(reader, config, primary_pass_end_offset);
    reader->chunk_size = saved_chunk_size;
    if (reader->total_bytes_read != (size_t)primary_pass_end_offset ||
        reader->bytes_in_buffer != 0U) {
        (void)reader_seek_absolute(reader, primary_pass_end_offset);
    }
}

static void raw_all_image_safety_process(
    RawAllImageSafetyQueue *queue,
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    uint64_t primary_pass_end_offset,
    const FormatPipelineDispatchContext *dispatch_context
)
{
    double started_at;
    uint64_t recovered_total = 0U;
    uint64_t rejected_total = 0U;
    const char *status = "no_recovery";
    size_t pass;

    if (queue == NULL || reader == NULL) {
        return;
    }

    started_at = scanner_now_seconds();
    raw_all_image_safety_load_persisted_intervals(queue, config);

    if (queue->interval_count == 0U) {
        return;
    }

    if (!raw_all_claim_audit_any_probe_allowed(dispatch_context)) {
        raw_all_claim_audit_write_state(
            config,
            queue,
            "skipped",
            "no_active_audit_probe");
        return;
    }

    raw_all_claim_audit_write_state(config, queue, "start", "running");

    for (pass = 1U;
         pass <= RAW_ALL_CLAIM_AUDIT_MAX_DRAIN_PASSES && !raw_all_should_stop();
         pass++) {
        char phase[48];
        const char *pass_status = "running";
        size_t pending_before =
            raw_all_image_safety_unscanned_interval_count(queue);
        size_t unprocessed_before =
            raw_all_image_safety_unprocessed_candidate_count(queue);
        size_t candidates_before = queue->candidate_count;
        uint64_t intervals_scanned_before = queue->audit_intervals_scanned;
        uint64_t bytes_scanned_before = queue->audit_bytes_scanned;
        uint64_t attempted_before =
            raw_all_claim_audit_sum_counts(queue->attempted_by_kind);
        uint64_t recovered_before =
            raw_all_claim_audit_sum_counts(queue->recovered_by_kind);
        uint64_t rejected_before =
            raw_all_claim_audit_sum_counts(queue->rejected_by_kind);
        uint64_t child_ranges_before =
            raw_all_claim_audit_sum_counts(queue->child_ranges_emitted_by_kind);
        uint64_t existing_skip_before =
            raw_all_claim_audit_sum_counts(queue->already_recovered_by_kind) +
            raw_all_claim_audit_sum_counts(queue->covered_by_earlier_by_kind);
        size_t pending_after;
        size_t unprocessed_after;
        size_t candidates_delta;
        uint64_t intervals_scanned_delta;
        uint64_t bytes_scanned_delta;
        uint64_t attempted_delta;
        uint64_t recovered_delta;
        uint64_t rejected_delta;
        uint64_t child_ranges_delta;
        uint64_t existing_skip_delta;

        if (pending_before == 0U && unprocessed_before == 0U) {
            status = pass == 1U ? "no_pending_intervals" : status;
            break;
        }

        snprintf(
            phase,
            sizeof(phase),
            "pass_%zu_discovery",
            pass);
        raw_all_claim_audit_write_state(config, queue, phase, "running");

        if (pending_before > 0U) {
            raw_all_image_safety_discover_candidates(
                queue,
                reader,
                dispatch_context);
        }

        snprintf(
            phase,
            sizeof(phase),
            "pass_%zu_post_discovery",
            pass);
        raw_all_claim_audit_write_state(config, queue, phase, "running");

        raw_all_image_safety_process_candidates(
            queue,
            reader,
            config,
            active_order,
            primary_pass_end_offset,
            dispatch_context);

        pending_after = raw_all_image_safety_unscanned_interval_count(queue);
        unprocessed_after = raw_all_image_safety_unprocessed_candidate_count(queue);
        candidates_delta = queue->candidate_count - candidates_before;
        intervals_scanned_delta =
            queue->audit_intervals_scanned - intervals_scanned_before;
        bytes_scanned_delta = queue->audit_bytes_scanned - bytes_scanned_before;
        attempted_delta =
            raw_all_claim_audit_sum_counts(queue->attempted_by_kind) -
            attempted_before;
        recovered_delta =
            raw_all_claim_audit_sum_counts(queue->recovered_by_kind) -
            recovered_before;
        rejected_delta =
            raw_all_claim_audit_sum_counts(queue->rejected_by_kind) -
            rejected_before;
        child_ranges_delta =
            raw_all_claim_audit_sum_counts(queue->child_ranges_emitted_by_kind) -
            child_ranges_before;
        existing_skip_delta =
            raw_all_claim_audit_sum_counts(queue->already_recovered_by_kind) +
            raw_all_claim_audit_sum_counts(queue->covered_by_earlier_by_kind) -
            existing_skip_before;

        if (raw_all_should_stop()) {
            pass_status = "interrupted";
            status = "interrupted";
        } else if (pending_after == 0U && unprocessed_after == 0U) {
            pass_status = recovered_delta > 0U || child_ranges_delta > 0U
                ? "drained_productive"
                : "drained_no_more_candidates";
            status = raw_all_claim_audit_sum_counts(queue->recovered_by_kind) > 0U
                ? "productive"
                : "no_recovery";
        } else if (recovered_delta == 0U &&
                   child_ranges_delta == 0U &&
                   candidates_delta == 0U &&
                   attempted_delta == 0U &&
                   existing_skip_delta == 0U) {
            pass_status = "zero_delta";
            status = "zero_delta";
        } else if (pass == RAW_ALL_CLAIM_AUDIT_MAX_DRAIN_PASSES) {
            pass_status = "pass_limit";
            status = "pass_limit";
        } else {
            pass_status = "productive_continue";
            status = "productive";
        }

        log_info(
            "Claim safety recursive pass %zu: intervals=%zu->%zu scanned_delta=%llu bytes=%.1f MiB candidates_delta=%zu attempted_delta=%llu recovered_delta=%llu rejected_delta=%llu existing_skip_delta=%llu child_ranges_delta=%llu pending_after=%zu unprocessed_after=%zu stop=%s",
            pass,
            pending_before,
            pending_after,
            (unsigned long long)intervals_scanned_delta,
            (double)bytes_scanned_delta / (1024.0 * 1024.0),
            candidates_delta,
            (unsigned long long)attempted_delta,
            (unsigned long long)recovered_delta,
            (unsigned long long)rejected_delta,
            (unsigned long long)existing_skip_delta,
            (unsigned long long)child_ranges_delta,
            pending_after,
            unprocessed_after,
            pass_status
        );

        snprintf(
            phase,
            sizeof(phase),
            "pass_%zu_done",
            pass);
        raw_all_claim_audit_write_state(config, queue, phase, pass_status);

        if (strcmp(pass_status, "productive_continue") != 0) {
            break;
        }
    }

    if (raw_all_should_stop()) {
        status = "interrupted";
    } else if (pass > RAW_ALL_CLAIM_AUDIT_MAX_DRAIN_PASSES &&
               (raw_all_image_safety_unscanned_interval_count(queue) > 0U ||
                raw_all_image_safety_unprocessed_candidate_count(queue) > 0U)) {
        status = "pass_limit";
    }

    recovered_total = raw_all_claim_audit_sum_counts(queue->recovered_by_kind);
    rejected_total = raw_all_claim_audit_sum_counts(queue->rejected_by_kind);
    if (strcmp(status, "productive") == 0 && recovered_total == 0U) {
        status = "no_recovery";
    }
    raw_all_claim_audit_write_state(config, queue, "done", status);
    performance_ledger_append(
        config,
        "claim_audit",
        "sweep",
        scanner_now_seconds() - started_at,
        queue->audit_bytes_scanned,
        0U,
        (uint64_t)queue->candidate_count,
        recovered_total,
        rejected_total +
            raw_all_claim_audit_sum_counts(queue->already_recovered_by_kind) +
            raw_all_claim_audit_sum_counts(queue->covered_by_earlier_by_kind),
        status,
        "persistent swallowed intervals plus active format probes"
    );
}

static void set_raw_all_label_activity(
    const char *label,
    size_t absolute_offset
)
{
    char activity[96];
    double gib =
        (double)absolute_offset / (1024.0 * 1024.0 * 1024.0);

    snprintf(
        activity,
        sizeof(activity),
        "validating %.48s @ %.1f GiB",
        (label != NULL && label[0] != '\0') ? label : "unknown",
        gib
    );
    log_set_working_activity(activity);
}

static void set_raw_all_match_activity(
    const MagicEntry *match,
    size_t absolute_offset
)
{
    char label[48];

    raw_all_match_label(match, label, sizeof(label));
    set_raw_all_label_activity(label, absolute_offset);
}

static void update_working_queue_from_metadata_stats(void)
{
    FsBackendLiveStats metadata_stats;
    size_t recovered_files = fs_backend_recovered_output_count();
    size_t named_files = fs_backend_named_output_count();
    size_t unident_files = fs_backend_unreconciled_output_count();
    size_t repair_pending_files = 0U;
    size_t repair_queue_files = 0U;
    int metadata_counts_ready = 0;
    double now = scanner_now_seconds();
    const char *background_activity = NULL;

    if (g_last_working_queue_stats_update_at > 0.0 &&
        now > g_last_working_queue_stats_update_at &&
        now - g_last_working_queue_stats_update_at <
            WORKING_QUEUE_STATS_UPDATE_INTERVAL_SECONDS) {
        return;
    }
    g_last_working_queue_stats_update_at = now;

    fs_backend_get_live_queue_stats(&metadata_stats);

    if (metadata_stats.recovered_outputs_current > recovered_files) {
        recovered_files = (size_t)metadata_stats.recovered_outputs_current;
    }
    metadata_counts_ready =
        metadata_stats.recovered_outputs_current > 0U &&
        (metadata_stats.named_outputs_current > 0U ||
         metadata_stats.unident_outputs_current > 0U ||
         metadata_stats.repair_pending_outputs > 0U ||
         metadata_stats.repair_queue_events > 0U);

    if (metadata_counts_ready) {
        named_files = (size_t)metadata_stats.named_outputs_current;
        unident_files = (size_t)metadata_stats.unident_outputs_current;
        repair_pending_files = (size_t)metadata_stats.repair_pending_outputs;
        repair_queue_files = (size_t)metadata_stats.repair_queue_events;
    }

    switch ((FsBackendBackgroundPhase)metadata_stats.background_phase) {
        case FS_BACKEND_BACKGROUND_PHASE_TREE:
            background_activity = "tree";
            break;
        case FS_BACKEND_BACKGROUND_PHASE_INDEX:
            background_activity = "index";
            break;
        case FS_BACKEND_BACKGROUND_PHASE_NAMING:
            background_activity = "naming";
            break;
        case FS_BACKEND_BACKGROUND_PHASE_REPAIR:
            background_activity = "repair";
            break;
        case FS_BACKEND_BACKGROUND_PHASE_IDLE:
        default:
            background_activity = NULL;
            break;
    }

    log_set_working_recovered_files(recovered_files);
    log_set_working_named_files(named_files);
    log_set_working_queue_stats(
        unident_files,
        repair_pending_files,
        repair_queue_files,
        metadata_stats.record_index_count,
        metadata_stats.range_index_count,
        metadata_stats.scan_stalled_seconds,
        background_activity
    );
}

static double scanner_now_seconds(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0.0;
    }

    return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
}

static size_t observe_metadata_records_timed(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset,
    int allow_unaligned
)
{
    double start = scanner_now_seconds();
    size_t observed = fs_backend_observe_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset,
        allow_unaligned
    );

    g_metadata_observe_stats.passes++;
    g_metadata_observe_stats.records_observed += (uint64_t)observed;
    g_metadata_observe_stats.bytes_scanned += (uint64_t)buffer_length;
    {
        double elapsed = scanner_now_seconds() - start;
        g_metadata_observe_stats.seconds_total += elapsed;
        if (elapsed >= RAW_ALL_SLOW_METADATA_OBSERVE_LOG_SECONDS) {
            const char *mode_label = "broad backend record scan";

            if (g_raw_all_metadata_observe_mode == 2) {
                mode_label = "primary metadata runlist";
            } else if (g_raw_all_metadata_observe_mode == 1) {
                mode_label = "aligned native records";
            }

            log_info(
                "All slow metadata mapping: mode=%s abs=%.1f GiB scanned=%.1f MiB observed=%zu dt=%.2fs allow_unaligned=%d",
                mode_label,
                (double)buffer_base_offset / (1024.0 * 1024.0 * 1024.0),
                (double)buffer_length / (1024.0 * 1024.0),
                observed,
                elapsed,
                allow_unaligned
            );
        }
    }

    return observed;
}

static void maybe_write_raw_all_resume_state(
    const AppConfig *config,
    uint64_t source_size,
    uint64_t scan_offset,
    size_t *io_last_state_write_offset
)
{
    size_t last_state_write_offset;
    double write_started_at;
    double write_elapsed;
    int wrote_state;

    if (config == NULL ||
        io_last_state_write_offset == NULL ||
        config->scan_state_path == NULL ||
        config->scan_state_path[0] == '\0' ||
        app_supervisor_generation_stale()) {
        return;
    }

    last_state_write_offset = *io_last_state_write_offset;
    if (scan_offset < last_state_write_offset ||
        scan_offset - last_state_write_offset <
            RAW_ALL_STATE_WRITE_INTERVAL) {
        return;
    }

    if (!config->manual_start_explicit && !config->additive_pass) {
        ScanState existing_state = {0};

        if (scan_state_load(config->scan_state_path, &existing_state) &&
            strcmp(existing_state.scan_mode, "all") == 0 &&
            existing_state.scan_offset > scan_offset) {
            *io_last_state_write_offset = (size_t)existing_state.scan_offset;
            return;
        }
    }

    write_started_at = scanner_now_seconds();
    wrote_state = scan_state_write(
        config->scan_state_path,
        config->input_path,
        "all",
        source_size,
        scan_offset,
        0,
        0);
    write_elapsed = scanner_now_seconds() - write_started_at;
    if (write_elapsed >= 1.0) {
        log_info(
            "Raw-all resume state write took %.2fs at byte %llu",
            write_elapsed,
            (unsigned long long)scan_offset
        );
    }
    if (wrote_state) {
        *io_last_state_write_offset = (size_t)scan_offset;
        log_all_live_stats_snapshot();
    }
}

static uint64_t raw_all_effective_progress_total_bytes(
    const Reader *reader,
    const AppConfig *config
)
{
    uint64_t stop_offset = raw_all_effective_scan_end_offset(reader, config);
    uint64_t start_offset = 0ULL;

    if (config != NULL &&
        config->mft_limit > 0ULL) {
        if (config->manual_start_explicit &&
            config->manual_start_offset < stop_offset) {
            start_offset = (uint64_t)config->manual_start_offset;
        }
    }

    return stop_offset > start_offset ? stop_offset - start_offset : stop_offset;
}

static uint64_t raw_all_effective_scan_end_offset(
    const Reader *reader,
    const AppConfig *config
)
{
    uint64_t source_size = reader_get_source_size(reader);
    uint64_t stop_offset = source_size;

    if (config != NULL && config->mft_limit > 0ULL) {
        stop_offset = (uint64_t)config->mft_limit;
        if (config->manual_start_explicit &&
            config->manual_start_offset > 0ULL &&
            stop_offset <= (uint64_t)config->manual_start_offset) {
            uint64_t start_offset = (uint64_t)config->manual_start_offset;
            if (UINT64_MAX - start_offset < stop_offset) {
                stop_offset = UINT64_MAX;
            } else {
                stop_offset = start_offset + stop_offset;
            }
        }
        if (source_size > 0ULL && stop_offset > source_size) {
            stop_offset = source_size;
        }
    }

    return stop_offset;
}

static uint64_t raw_all_effective_progress_processed_bytes(
    const Reader *reader,
    const AppConfig *config,
    uint64_t processed_bytes
)
{
    uint64_t total_bytes = raw_all_effective_progress_total_bytes(reader, config);
    uint64_t start_offset = 0ULL;

    if (config != NULL &&
        config->mft_limit > 0ULL &&
        config->manual_start_explicit) {
        start_offset = (uint64_t)config->manual_start_offset;
    }

    if (start_offset > 0ULL) {
        processed_bytes =
            processed_bytes > start_offset ? processed_bytes - start_offset : 0ULL;
    }

    if (total_bytes > 0ULL && processed_bytes > total_bytes) {
        processed_bytes = total_bytes;
    }

    return processed_bytes;
}

static void raw_all_set_working_progress_limited(
    const Reader *reader,
    const AppConfig *config,
    uint64_t processed_bytes
)
{
    uint64_t total_bytes = raw_all_effective_progress_total_bytes(reader, config);
    processed_bytes =
        raw_all_effective_progress_processed_bytes(reader, config, processed_bytes);

    log_set_working_progress(processed_bytes, total_bytes);
}

static size_t raw_all_reader_read_next_limited(
    Reader *reader,
    uint64_t scan_limit)
{
    size_t saved_chunk_size;
    uint64_t remaining;
    size_t result;

    if (reader == NULL) return 0U;
    if (scan_limit == 0U) return reader_read_next(reader);
    if (reader->progress_bytes_read >= scan_limit) return 0U;
    remaining = scan_limit - reader->progress_bytes_read;
    saved_chunk_size = reader->chunk_size;
    if (remaining < (uint64_t)reader->chunk_size) {
        reader->chunk_size = (size_t)remaining;
    }
    result = reader_read_next(reader);
    reader->chunk_size = saved_chunk_size;
    return result;
}

static void note_raw_all_metadata_observe_mode(int mode, const char *label)
{
    if (g_raw_all_metadata_observe_mode == mode) {
        return;
    }

    g_raw_all_metadata_observe_mode = mode;
    log_verbose("Raw-all live metadata observation mode: %s", label);
}

static void set_raw_all_signature_scan_activity(int skip_metadata_observation)
{
    FsBackendLiveStats metadata_stats = {0};

    fs_backend_get_live_queue_stats(&metadata_stats);

    if (!skip_metadata_observation &&
        fs_backend_supports_live_metadata_observation()) {
        if (metadata_stats.record_index_count == 0U &&
            metadata_stats.range_index_count == 0U &&
            metadata_stats.named_outputs_current == 0U) {
            log_set_working_activity(
                "scanning file signatures; live filesystem metadata not attached yet");
            return;
        }
        log_set_working_activity(
            "scanning file signatures with live filesystem metadata");
        return;
    }

    if (fs_backend_has_metadata_context_for_raw_scan()) {
        if (metadata_stats.record_index_count == 0U &&
            metadata_stats.range_index_count == 0U &&
            metadata_stats.named_outputs_current == 0U) {
            log_set_working_activity(
                "scanning file signatures; filesystem metadata context is loaded but naming is not attached yet");
            return;
        }
        log_set_working_activity(
            "scanning file signatures with filesystem metadata context");
        return;
    }

    log_set_working_activity("scanning file signatures");
}

static int write_raw_all_activity_state(
    const AppConfig *config,
    Reader *reader,
    uint64_t scan_offset,
    int skip_live_metadata_observation
)
{
    char path[PATH_MAX_LEN];
    char temp_path[PATH_MAX_LEN + 32];
    FILE *file;
    FormatPipelineLiveStats pipeline_stats;
    FsBackendLiveStats metadata_stats;
    FsBackendLiveStats reported_metadata_stats;
    FsBackendProcessStats process_stats;
    AsyncOutputLiveStats async_stats;
    LogWorkingSnapshot working_snapshot = {0};
    RawAllResourceSample resource_sample;
    uint64_t progress_bytes = raw_all_effective_progress_processed_bytes(
        reader,
        config,
        scan_offset
    );
    uint64_t total_bytes = raw_all_effective_progress_total_bytes(reader, config);
    double target_mib_per_sec = 0.0;
    size_t reported_named_files = 0U;
    size_t reported_unident_files = 0U;
    size_t reported_repair_pending_files = 0U;
    size_t reported_recovered_files = 0U;
    size_t cumulative_named_files = 0U;
    size_t cumulative_unident_files = 0U;
    size_t cumulative_recovered_files = 0U;
    int metadata_context_available = 0;
    int live_metadata_observation_available = 0;

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        reader == NULL ||
        app_supervisor_generation_stale()) {
        return 0;
    }

    format_pipeline_get_live_stats(&pipeline_stats);
    fs_backend_get_live_queue_stats(&metadata_stats);
    reported_metadata_stats = metadata_stats;
    fs_backend_get_process_stats(&process_stats);
    carver_output_async_get_live_stats(&async_stats);
    (void)log_get_working_snapshot(&working_snapshot);
    resource_sample = raw_all_sample_resource_usage();
    metadata_context_available =
        fs_backend_has_metadata_context_for_raw_scan() ? 1 : 0;
    live_metadata_observation_available =
        fs_backend_supports_live_metadata_observation() ? 1 : 0;
    target_mib_per_sec =
        working_snapshot.target_mib_per_sec > 0.0
            ? working_snapshot.target_mib_per_sec
            : log_get_target_throughput_mib_per_sec();
    if (working_snapshot.total_bytes > 0ULL &&
        (total_bytes == 0ULL || working_snapshot.total_bytes == total_bytes) &&
        working_snapshot.processed_bytes > progress_bytes) {
        progress_bytes = working_snapshot.processed_bytes;
        if (total_bytes == 0ULL) {
            total_bytes = working_snapshot.total_bytes;
        }
    }
    if (total_bytes > 0ULL && progress_bytes > total_bytes) {
        progress_bytes = total_bytes;
    }
    reported_named_files = working_snapshot.named_files;
    reported_unident_files = working_snapshot.unident_files;
    reported_repair_pending_files = working_snapshot.repair_pending_files;
    reported_recovered_files = working_snapshot.recovered_files;
    if ((size_t)metadata_stats.named_outputs_current > reported_named_files) {
        reported_named_files = (size_t)metadata_stats.named_outputs_current;
    }
    if ((size_t)metadata_stats.unident_outputs_current > reported_unident_files) {
        reported_unident_files = (size_t)metadata_stats.unident_outputs_current;
    }
    if ((size_t)metadata_stats.repair_pending_outputs > reported_repair_pending_files) {
        reported_repair_pending_files = (size_t)metadata_stats.repair_pending_outputs;
    }
    if ((size_t)metadata_stats.recovered_outputs_current > reported_recovered_files) {
        reported_recovered_files = (size_t)metadata_stats.recovered_outputs_current;
    }
    if (!raw_all_get_cached_recovered_state_summary(
            config->output_dir,
            &cumulative_recovered_files,
            &cumulative_named_files,
            &cumulative_unident_files)) {
        cumulative_recovered_files = 0U;
        cumulative_named_files = 0U;
        cumulative_unident_files = 0U;
    }
    if (cumulative_recovered_files > reported_recovered_files) {
        reported_recovered_files = cumulative_recovered_files;
    }
    if (cumulative_named_files > reported_named_files) {
        reported_named_files = cumulative_named_files;
    }
    if (cumulative_unident_files > reported_unident_files) {
        reported_unident_files = cumulative_unident_files;
    }
    if ((uint64_t)reported_recovered_files >
        reported_metadata_stats.recovered_outputs_current) {
        reported_metadata_stats.recovered_outputs_current =
            (uint64_t)reported_recovered_files;
    }
    if ((uint64_t)reported_named_files >
        reported_metadata_stats.named_outputs_current) {
        reported_metadata_stats.named_outputs_current =
            (uint64_t)reported_named_files;
    }
    if ((uint64_t)reported_unident_files >
        reported_metadata_stats.unident_outputs_current) {
        reported_metadata_stats.unident_outputs_current =
            (uint64_t)reported_unident_files;
    }

    if (snprintf(
            path,
            sizeof(path),
            "%s/%s/thread_activity.txt",
            config->output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(path) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >= (int)sizeof(temp_path)) {
        return 0;
    }

    file = fopen(temp_path, "w");
    if (file == NULL) {
        return 0;
    }

    fprintf(file, "version=1\n");
    fprintf(file, "mode=all\n");
    fprintf(file, "updated_unix=%llu\n", (unsigned long long)time(NULL));
    fprintf(file, "scan.offset=%llu\n", (unsigned long long)scan_offset);
    fprintf(file, "scan.progress_bytes=%llu\n", (unsigned long long)progress_bytes);
    fprintf(file, "scan.total_bytes_read=%llu\n", (unsigned long long)reader->total_bytes_read);
    fprintf(file, "scan.buffered_bytes=%zu\n", reader->bytes_in_buffer);
    fprintf(file, "scan.source_size=%llu\n", (unsigned long long)reader_get_source_size(reader));
    fprintf(file, "scan.total_bytes=%llu\n", (unsigned long long)total_bytes);
    fprintf(file, "scan.skip_live_metadata_observation=%d\n", skip_live_metadata_observation ? 1 : 0);
    fprintf(file, "scan.skip_mft_observation=%d\n", skip_live_metadata_observation ? 1 : 0);
    fprintf(file, "scan.fs_backend_kind=%d\n", (int)fs_backend_current_kind());
    fprintf(file, "scan.fs_backend=%s\n", fs_backend_current_id());
    fprintf(file, "scan.fs_backend_name=%s\n", fs_backend_current_name());
    fprintf(
        file,
        "audit.profile=%s\n",
        raw_all_resource_profile_label(g_raw_all_active_resource_profile)
    );
    fprintf(file, "audit.discovery_workers=%zu\n", g_raw_all_active_discovery_worker_count);
    fprintf(file, "audit.validation_workers=%zu\n", g_raw_all_active_validation_worker_count);
    fprintf(
        file,
        "scan.metadata_context_available=%d\n",
        metadata_context_available);
    fprintf(
        file,
        "scan.live_metadata_observation_available=%d\n",
        live_metadata_observation_available);
    fprintf(file, "scan.target_mib_per_sec=%.3f\n", target_mib_per_sec);
    fprintf(
        file,
        "scan.throughput_profile=%s\n",
        log_target_throughput_profile_label(target_mib_per_sec)
    );
    fprintf(
        file,
        "scan.throughput_profile_ui=%s\n",
        log_target_throughput_profile_ui_label(target_mib_per_sec)
    );
    fprintf(file, "scan.budget_base_bytes=%llu\n", (unsigned long long)working_snapshot.budget_base_bytes);
    fprintf(file, "scan.budget_penalty_bytes=%llu\n", (unsigned long long)working_snapshot.budget_penalty_bytes);
    fprintf(file, "scan.eta_seconds=%llu\n", working_snapshot.eta_seconds);
    fprintf(file, "scan.elapsed_seconds=%.3f\n", working_snapshot.elapsed_seconds);
    fprintf(file, "scan.budget_elapsed_seconds=%.3f\n", working_snapshot.budget_elapsed_seconds);
    fprintf(file, "scan.recent_mib_per_sec=%.3f\n", working_snapshot.recent_mib_per_sec);
    fprintf(file, "scan.stalled_seconds=%llu\n", working_snapshot.stalled_seconds);
    fprintf(file, "scan.nominal_total_seconds=%llu\n", working_snapshot.nominal_total_seconds);
    fprintf(file, "scan.nominal_remaining_seconds=%llu\n", working_snapshot.nominal_remaining_seconds);
    fprintf(file, "scan.budget_eta_seconds=%llu\n", working_snapshot.budget_eta_seconds);
    fprintf(file, "scan.schedule_delta_seconds=%lld\n", working_snapshot.schedule_delta_seconds);
    fprintf(file, "scan.eta_phase=%d\n", working_snapshot.eta_phase);
    fprintf(file, "scan.load_eta_done=%d\n", working_snapshot.load_eta_done);
    fprintf(file, "scan.trouble_budget_state=%d\n", working_snapshot.trouble_budget_state);
    fprintf(
        file,
        "scan.trouble_budget=%s\n",
        log_trouble_budget_state_label(
            (LogTroubleBudgetState)working_snapshot.trouble_budget_state
        )
    );
    fprintf(file, "scan.validator_budget_state=%d\n", working_snapshot.validator_budget_state);
    fprintf(
        file,
        "scan.validator_budget=%s\n",
        log_trouble_budget_state_label(
            (LogTroubleBudgetState)working_snapshot.validator_budget_state
        )
    );
    fprintf(file, "scan.recovered_files=%zu\n", reported_recovered_files);
    fprintf(file, "scan.named_files=%zu\n", reported_named_files);
    fprintf(file, "scan.unident_files=%zu\n", reported_unident_files);
    fprintf(file, "scan.repair_pending_files=%zu\n", reported_repair_pending_files);
    fprintf(file, "scan.repair_queue_files=%zu\n", working_snapshot.repair_queue_files);
    fprintf(file, "scan.activity=%s\n", working_snapshot.activity);
    fprintf(file, "scan.background_activity=%s\n", working_snapshot.background_activity);
    fprintf(file, "resource.cpu_percent=%.3f\n", resource_sample.cpu_percent);
    fprintf(file, "resource.cores_used=%.3f\n", resource_sample.cores_used);
    fprintf(file, "resource.cpu_count=%ld\n", resource_sample.cpu_count > 0 ? resource_sample.cpu_count : 0L);
    fprintf(file, "resource.cpu_user_seconds=%.6f\n", resource_sample.usage.has_cpu ? resource_sample.usage.user_cpu_seconds : 0.0);
    fprintf(file, "resource.cpu_system_seconds=%.6f\n", resource_sample.usage.has_cpu ? resource_sample.usage.system_cpu_seconds : 0.0);
    fprintf(file, "resource.cpu_total_seconds=%.6f\n", resource_sample.usage.has_cpu ? resource_sample.usage.total_cpu_seconds : 0.0);
    fprintf(file, "resource.io_wait_seconds=%.6f\n", resource_sample.usage.has_io_wait ? resource_sample.usage.io_wait_seconds : 0.0);
    fprintf(file, "resource.io_wait_percent=%.3f\n", resource_sample.usage.has_io_wait ? resource_sample.io_wait_percent : 0.0);
    fprintf(file, "resource.rss_bytes=%llu\n", (unsigned long long)(resource_sample.usage.memory.has_resident ? resource_sample.usage.memory.resident_bytes : 0ULL));
    fprintf(file, "resource.peak_rss_bytes=%llu\n", (unsigned long long)(resource_sample.usage.memory.has_peak_rss ? resource_sample.usage.memory.peak_rss_bytes : 0ULL));
    fprintf(file, "resource.footprint_bytes=%llu\n", (unsigned long long)(resource_sample.usage.memory.has_footprint ? resource_sample.usage.memory.footprint_bytes : 0ULL));
    fprintf(file, "async.queue_count=%zu\n", async_stats.queue_count);
    fprintf(file, "async.queue_capacity=%zu\n", async_stats.queue_capacity);
    fprintf(file, "async.active_jobs=%zu\n", async_stats.active_jobs);
    fprintf(file, "async.outstanding_bytes=%llu\n", (unsigned long long)async_stats.outstanding_bytes);
    fprintf(file, "async.running=%d\n", async_stats.running);
    fprintf(file, "metadata.background_phase=%u\n", reported_metadata_stats.background_phase);
    fprintf(file, "metadata.record_index_count=%zu\n", reported_metadata_stats.record_index_count);
    fprintf(file, "metadata.range_index_count=%zu\n", reported_metadata_stats.range_index_count);
    fprintf(file, "metadata.background_conservative=%u\n", reported_metadata_stats.background_conservative);
    fprintf(file, "metadata.recovered_outputs_current=%llu\n", (unsigned long long)reported_metadata_stats.recovered_outputs_current);
    fprintf(file, "metadata.named_outputs_current=%llu\n", (unsigned long long)reported_metadata_stats.named_outputs_current);
    fprintf(file, "metadata.files_outside_unident=%llu\n", (unsigned long long)reported_metadata_stats.named_outputs_current);
    fprintf(file, "metadata.files_still_in_unident=%llu\n", (unsigned long long)reported_metadata_stats.unident_outputs_current);
    fprintf(file, "metadata.rename_operations=%llu\n", (unsigned long long)reported_metadata_stats.renamed_outputs);
    fprintf(file, "metadata.scan_stalled_seconds=%llu\n", reported_metadata_stats.scan_stalled_seconds);
    fprintf(file, "spool.background_phase=%u\n", reported_metadata_stats.background_phase);
    fprintf(file, "spool.record_index_count=%zu\n", reported_metadata_stats.record_index_count);
    fprintf(file, "spool.range_index_count=%zu\n", reported_metadata_stats.range_index_count);
    fprintf(file, "spool.background_conservative=%u\n", reported_metadata_stats.background_conservative);
    fprintf(file, "spool.recovered_outputs_current=%llu\n", (unsigned long long)reported_metadata_stats.recovered_outputs_current);
    fprintf(file, "spool.named_outputs_current=%llu\n", (unsigned long long)reported_metadata_stats.named_outputs_current);
    fprintf(file, "spool.files_outside_unident=%llu\n", (unsigned long long)reported_metadata_stats.named_outputs_current);
    fprintf(file, "spool.files_still_in_unident=%llu\n", (unsigned long long)reported_metadata_stats.unident_outputs_current);
    fprintf(file, "spool.rename_operations=%llu\n", (unsigned long long)reported_metadata_stats.renamed_outputs);
    fprintf(file, "spool.scan_stalled_seconds=%llu\n", reported_metadata_stats.scan_stalled_seconds);
    fprintf(file, "pipeline.metadata_exact_mft_attempts=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_mft_attempts);
    fprintf(file, "pipeline.metadata_exact_mft_recovered=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_mft_recovered);
    fprintf(file, "pipeline.metadata_exact_mft_run_truncated=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_mft_run_truncated);
    fprintf(file, "pipeline.metadata_exact_jpeg_attempts=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_jpeg_attempts);
    fprintf(file, "pipeline.metadata_exact_jpeg_recovered=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_jpeg_recovered);
    fprintf(file, "pipeline.mft_exact_attempts=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_mft_attempts);
    fprintf(file, "pipeline.mft_exact_recovered=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_mft_recovered);
    fprintf(file, "pipeline.mft_exact_run_truncated=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_mft_run_truncated);
    fprintf(file, "pipeline.mft_exact_jpeg_attempts=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_jpeg_attempts);
    fprintf(file, "pipeline.mft_exact_jpeg_recovered=%llu\n", (unsigned long long)pipeline_stats.metadata_exact_jpeg_recovered);
    fprintf(file, "metadata_candidates.lookups=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.lookups);
    fprintf(file, "metadata_candidates.lookup_failures=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.lookup_failures);
    fprintf(file, "metadata_candidates.no_owner=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.no_owner);
    fprintf(file, "metadata_candidates.ambiguous_owner=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.ambiguous_owner);
    fprintf(file, "metadata_candidates.non_data_owner=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.non_data_owner);
    fprintf(file, "metadata_candidates.incomplete_owner=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.incomplete_owner);
    fprintf(file, "metadata_candidates.trusted_exact_start=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.trusted_exact_start);
    fprintf(file, "metadata_candidates.trusted_interior=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.trusted_interior);
    fprintf(file, "metadata_candidates.shared_with_dispatch=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.shared_with_dispatch);
    fprintf(file, "metadata_candidates.scope=cumulative_unique_offsets\n");
    fprintf(file, "metadata_candidates.high_water_valid=%d\n",
            g_raw_all_metadata_candidate_stats.high_water_valid ? 1 : 0);
    fprintf(file, "metadata_candidates.high_water_offset=%llu\n",
            (unsigned long long)g_raw_all_metadata_candidate_stats.high_water_offset);
    fprintf(file, "process.parsed_metadata_units=%llu\n", (unsigned long long)process_stats.parsed_metadata_units);
    fprintf(file, "process.indexed_metadata_units=%llu\n", (unsigned long long)process_stats.indexed_metadata_units);
    fprintf(file, "process.parsed_records=%llu\n", (unsigned long long)process_stats.parsed_metadata_units);
    fprintf(file, "process.spooled_records=%llu\n", (unsigned long long)process_stats.indexed_metadata_units);
    fprintf(file, "process.built_entries=%llu\n", (unsigned long long)process_stats.built_entries);
    fprintf(file, "process.stored_entries=%llu\n", (unsigned long long)process_stats.stored_entries);

    if (fclose(file) != 0) {
        (void)remove(temp_path);
        return 0;
    }
    if (rename(temp_path, path) != 0) {
        (void)remove(temp_path);
        return 0;
    }
    (void)raw_all_write_candidate_stats_state(config);
    (void)write_raw_all_metadata_live_stats(config, &reported_metadata_stats);
    return 1;
}

static int write_raw_all_live_stats_file(
    const char *path,
    const FsBackendLiveStats *metadata_stats
)
{
    char temp_path[PATH_MAX_LEN + 32];
    FILE *file;

    if (path == NULL || path[0] == '\0' || metadata_stats == NULL ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >= (int)sizeof(temp_path)) {
        return 0;
    }

    file = fopen(temp_path, "w");
    if (file == NULL) {
        return 0;
    }

    fprintf(file, "version=1\n");
    fprintf(file, "renamed_outputs=%llu\n",
            (unsigned long long)metadata_stats->renamed_outputs);
    fprintf(file, "rename_operations=%llu\n",
            (unsigned long long)metadata_stats->renamed_outputs);
    fprintf(file, "repaired_outputs=%llu\n",
            (unsigned long long)metadata_stats->repaired_outputs);
    fprintf(file, "recovered_outputs_current=%llu\n",
            (unsigned long long)metadata_stats->recovered_outputs_current);
    fprintf(file, "named_outputs_current=%llu\n",
            (unsigned long long)metadata_stats->named_outputs_current);
    fprintf(file, "files_outside_unident=%llu\n",
            (unsigned long long)metadata_stats->named_outputs_current);
    fprintf(file, "unident_outputs_current=%llu\n",
            (unsigned long long)metadata_stats->unident_outputs_current);
    fprintf(file, "files_still_in_unident=%llu\n",
            (unsigned long long)metadata_stats->unident_outputs_current);
    fprintf(file, "repair_pending_outputs=%llu\n",
            (unsigned long long)metadata_stats->repair_pending_outputs);
    fprintf(file, "repair_pending_files=%llu\n",
            (unsigned long long)metadata_stats->repair_pending_outputs);
    fprintf(file, "repair_queue_events=%llu\n",
            (unsigned long long)metadata_stats->repair_queue_events);
    fprintf(file, "record_index_count=%zu\n", metadata_stats->record_index_count);
    fprintf(file, "range_index_count=%zu\n", metadata_stats->range_index_count);
    fprintf(file, "scan_stalled_seconds=%llu\n",
            metadata_stats->scan_stalled_seconds);
    fprintf(file, "background_phase=%u\n", metadata_stats->background_phase);
    fprintf(file, "background_conservative=%u\n", metadata_stats->background_conservative);

    if (fclose(file) != 0) {
        (void)remove(temp_path);
        return 0;
    }
    if (rename(temp_path, path) != 0) {
        (void)remove(temp_path);
        return 0;
    }
    return 1;
}

static int write_raw_all_metadata_live_stats(
    const AppConfig *config,
    const FsBackendLiveStats *metadata_stats
)
{
    char metadata_path[PATH_MAX_LEN];
    char legacy_path[PATH_MAX_LEN];
    int wrote_any = 0;

    if (config == NULL ||
        metadata_stats == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0') {
        return 0;
    }

    if (snprintf(
            metadata_path,
            sizeof(metadata_path),
            "%s/%s/metadata_live_stats.txt",
            config->output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(metadata_path) ||
        snprintf(
            legacy_path,
            sizeof(legacy_path),
            "%s/%s/spool_live_stats.txt",
            config->output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(legacy_path)) {
        return 0;
    }

    if (write_raw_all_live_stats_file(metadata_path, metadata_stats)) {
        wrote_any = 1;
    }
    if (write_raw_all_live_stats_file(legacy_path, metadata_stats)) {
        wrote_any = 1;
    }
    return wrote_any;
}

static int build_primary_metadata_progress_path_local(
    const char *run_dir,
    char *out,
    size_t out_size
)
{
    if (run_dir == NULL ||
        run_dir[0] == '\0' ||
        out == NULL ||
        out_size == 0U) {
        return 0;
    }

    return snprintf(
               out,
               out_size,
               "%s/%s/%s",
               run_dir,
               APP_STATE_DIR_NAME,
               PRIMARY_METADATA_PROGRESS_STATE_NAME) < (int)out_size;
}

static void write_primary_metadata_progress_state(
    const char *phase_label,
    const char *step,
    const Reader *reader,
    uint64_t records_observed,
    uint64_t bytes_scanned,
    uint64_t range_start,
    uint64_t range_end,
    int force
)
{
    const char *run_dir = fs_backend_current_output_dir();
    char path[PATH_MAX_LEN];
    char temp_path[PATH_MAX_LEN + 32];
    FsBackendLiveStats live_stats = {0};
    FILE *file;
    double now = scanner_now_seconds();

    if (!force &&
        g_primary_metadata_progress_last_write_at > 0.0 &&
        now > g_primary_metadata_progress_last_write_at &&
        now - g_primary_metadata_progress_last_write_at <
            PRIMARY_METADATA_PROGRESS_WRITE_INTERVAL_SECONDS) {
        return;
    }
    if (!build_primary_metadata_progress_path_local(
            run_dir,
            path,
            sizeof(path)) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >=
            (int)sizeof(temp_path)) {
        return;
    }

    fs_backend_get_live_queue_stats(&live_stats);
    file = fopen(temp_path, "w");
    if (file == NULL) {
        return;
    }

    fprintf(file, "version=1\n");
    fprintf(file, "updated_unix=%llu\n", (unsigned long long)time(NULL));
    fprintf(
        file,
        "phase_label=%s\n",
        phase_label != NULL && phase_label[0] != '\0'
            ? phase_label
            : g_primary_metadata_progress_phase_label
    );
    fprintf(file, "step=%s\n", step != NULL ? step : "");
    fprintf(file, "records_observed=%llu\n", (unsigned long long)records_observed);
    fprintf(file, "bytes_scanned=%llu\n", (unsigned long long)bytes_scanned);
    fprintf(
        file,
        "reader_offset=%llu\n",
        (unsigned long long)(reader != NULL ? reader->progress_bytes_read : 0ULL)
    );
    fprintf(file, "range_start=%llu\n", (unsigned long long)range_start);
    fprintf(file, "range_end=%llu\n", (unsigned long long)range_end);
    fprintf(file, "primary_run_count=%zu\n", fs_backend_primary_run_count());
    fprintf(
        file,
        "directory_index_names=%zu\n",
        fs_backend_directory_index_name_count()
    );
    fprintf(file, "record_index_count=%zu\n", live_stats.record_index_count);
    fprintf(file, "range_index_count=%zu\n", live_stats.range_index_count);
    fprintf(
        file,
        "read_errors=%llu\n",
        (unsigned long long)(reader != NULL ? reader_get_read_error_count(reader) : 0ULL)
    );

    if (fclose(file) != 0) {
        (void)remove(temp_path);
        return;
    }
    if (rename(temp_path, path) != 0) {
        (void)remove(temp_path);
        return;
    }
    g_primary_metadata_progress_last_write_at = now;
}

static void maybe_write_raw_all_activity_state(
    const AppConfig *config,
    Reader *reader,
    uint64_t scan_offset,
    int skip_live_metadata_observation,
    double *io_last_activity_write_at,
    int force
)
{
    double now;

    if (io_last_activity_write_at == NULL) {
        return;
    }

    now = scanner_now_seconds();
    if (!force &&
        *io_last_activity_write_at > 0.0 &&
        now > *io_last_activity_write_at &&
        now - *io_last_activity_write_at < RAW_ALL_ACTIVITY_WRITE_INTERVAL_SECONDS) {
        return;
    }

    if (write_raw_all_activity_state(config, reader, scan_offset, skip_live_metadata_observation)) {
        *io_last_activity_write_at = now;
    }
}

static int compare_primary_metadata_run_windows(const void *left, const void *right)
{
    const PrimaryMetadataRunWindow *a = (const PrimaryMetadataRunWindow *)left;
    const PrimaryMetadataRunWindow *b = (const PrimaryMetadataRunWindow *)right;

    if (a->abs_offset < b->abs_offset) {
        return -1;
    }
    if (a->abs_offset > b->abs_offset) {
        return 1;
    }
    if (a->end_offset < b->end_offset) {
        return -1;
    }
    if (a->end_offset > b->end_offset) {
        return 1;
    }
    if (a->logical_start < b->logical_start) {
        return -1;
    }
    if (a->logical_start > b->logical_start) {
        return 1;
    }
    return 0;
}

static int compare_live_directory_index_windows(
    const void *left,
    const void *right
)
{
    const LiveDirectoryIndexWindow *a = (const LiveDirectoryIndexWindow *)left;
    const LiveDirectoryIndexWindow *b = (const LiveDirectoryIndexWindow *)right;

    if (a->target.abs_offset < b->target.abs_offset) {
        return -1;
    }
    if (a->target.abs_offset > b->target.abs_offset) {
        return 1;
    }
    if (a->end_offset < b->end_offset) {
        return -1;
    }
    if (a->end_offset > b->end_offset) {
        return 1;
    }
    if (a->target.directory_record_number < b->target.directory_record_number) {
        return -1;
    }
    if (a->target.directory_record_number > b->target.directory_record_number) {
        return 1;
    }
    return 0;
}

static void clear_primary_metadata_run_windows(void)
{
    free(g_primary_metadata_run_windows);
    g_primary_metadata_run_windows = NULL;
    g_primary_metadata_run_window_count = 0U;
    g_primary_metadata_run_window_cursor = 0U;
    g_primary_metadata_run_source_count = 0U;
}

static void clear_live_directory_index_windows(void)
{
    free(g_live_directory_index_windows);
    g_live_directory_index_windows = NULL;
    g_live_directory_index_window_count = 0U;
    g_live_directory_index_window_cursor = 0U;
    g_live_directory_index_window_source_entry_count = 0U;
    g_live_directory_index_window_source_stored_entries = 0ULL;
    g_live_directory_index_window_source_primary_start = -1LL;
    g_live_directory_index_window_source_partition_start = -1LL;
}

static int ensure_primary_metadata_run_windows(void)
{
    PrimaryMetadataRunWindow *windows;
    size_t run_count = fs_backend_primary_run_count();
    size_t run_index;
    size_t window_count = 0U;
    uint64_t logical_pos = 0U;

    if (run_count == 0U) {
        clear_primary_metadata_run_windows();
        return 0;
    }
    if (g_primary_metadata_run_windows != NULL &&
        g_primary_metadata_run_source_count == run_count) {
        return g_primary_metadata_run_window_count > 0U;
    }

    windows = (PrimaryMetadataRunWindow *)calloc(run_count, sizeof(*windows));
    if (windows == NULL) {
        clear_primary_metadata_run_windows();
        return 0;
    }

    for (run_index = 0; run_index < run_count; run_index++) {
        uint64_t run_abs = 0U;
        uint64_t run_length = 0U;
        uint64_t run_end;

        if (!fs_backend_get_primary_run(run_index, &run_abs, &run_length) ||
            run_length == 0U) {
            continue;
        }

        run_end = run_abs + run_length;
        if (run_end < run_abs) {
            run_end = UINT64_MAX;
        }

        windows[window_count].abs_offset = run_abs;
        windows[window_count].end_offset = run_end;
        windows[window_count].logical_start = logical_pos;
        windows[window_count].logical_length = run_length;
        window_count++;

        if (UINT64_MAX - logical_pos < run_length) {
            logical_pos = UINT64_MAX;
        } else {
            logical_pos += run_length;
        }
    }

    if (window_count > 1U) {
        qsort(windows, window_count, sizeof(*windows), compare_primary_metadata_run_windows);
    }

    free(g_primary_metadata_run_windows);
    g_primary_metadata_run_windows = windows;
    g_primary_metadata_run_window_count = window_count;
    g_primary_metadata_run_window_cursor = 0U;
    g_primary_metadata_run_source_count = run_count;
    return window_count > 0U;
}

static int ensure_live_directory_index_windows(void)
{
    FsBackendProcessStats process_stats = {0};
    FsDirectoryIndexTarget *targets = NULL;
    LiveDirectoryIndexWindow *windows;
    size_t target_count;
    size_t target_index;
    size_t window_count = 0U;
    size_t source_entry_count = fs_backend_entry_count();
    uint64_t source_stored_entries;
    long long source_primary_start = fs_backend_primary_scan_start_offset();
    long long source_partition_start = fs_backend_partition_start_offset();

    fs_backend_get_process_stats(&process_stats);
    source_stored_entries = process_stats.stored_entries;

    if (g_live_directory_index_windows != NULL &&
        g_live_directory_index_window_source_entry_count == source_entry_count &&
        g_live_directory_index_window_source_stored_entries == source_stored_entries &&
        g_live_directory_index_window_source_primary_start == source_primary_start &&
        g_live_directory_index_window_source_partition_start == source_partition_start) {
        return g_live_directory_index_window_count > 0U;
    }

    target_count = fs_backend_collect_directory_index_targets(NULL, 0U, 0U);
    if (target_count == 0U) {
        clear_live_directory_index_windows();
        return 0;
    }

    windows = (LiveDirectoryIndexWindow *)calloc(target_count, sizeof(*windows));
    if (windows == NULL) {
        clear_live_directory_index_windows();
        return 0;
    }

    targets = (FsDirectoryIndexTarget *)calloc(target_count, sizeof(*targets));
    if (targets == NULL) {
        free(windows);
        clear_live_directory_index_windows();
        return 0;
    }

    target_count = fs_backend_collect_directory_index_targets(
        targets,
        target_count,
        0U
    );
    for (target_index = 0U; target_index < target_count; target_index++) {
        LiveDirectoryIndexWindow *window = &windows[target_index];

        window->target = targets[target_index];
        {
            uint64_t end_offset =
                window->target.abs_offset + window->target.byte_length;

            if (end_offset < window->target.abs_offset) {
                end_offset = UINT64_MAX;
            }
            window->end_offset = end_offset;
        }
        window_count++;
    }
    free(targets);

    if (window_count == 0U) {
        free(windows);
        clear_live_directory_index_windows();
        return 0;
    }
    if (window_count > 1U) {
        qsort(
            windows,
            window_count,
            sizeof(*windows),
            compare_live_directory_index_windows
        );
    }

    free(g_live_directory_index_windows);
    g_live_directory_index_windows = windows;
    g_live_directory_index_window_count = window_count;
    g_live_directory_index_window_cursor = 0U;
    g_live_directory_index_window_source_entry_count = source_entry_count;
    g_live_directory_index_window_source_stored_entries = source_stored_entries;
    g_live_directory_index_window_source_primary_start = source_primary_start;
    g_live_directory_index_window_source_partition_start = source_partition_start;
    return 1;
}

static uint64_t scanner_align_up_u64(uint64_t value, uint64_t alignment)
{
    uint64_t remainder;

    if (alignment == 0U) {
        return value;
    }

    remainder = value % alignment;
    if (remainder == 0U) {
        return value;
    }
    if (UINT64_MAX - value < alignment - remainder) {
        return UINT64_MAX;
    }
    return value + (alignment - remainder);
}

static size_t observe_metadata_records_from_primary_runlist(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    long long primary_start_ll = -1;
    uint64_t primary_start = 0U;
    uint64_t buffer_end;
    size_t window_index;
    size_t observed_total = 0U;

    if (buffer == NULL || buffer_length == 0U) {
        return 0U;
    }

    primary_start_ll = fs_backend_primary_scan_start_offset();
    if (primary_start_ll < 0) {
        return 0U;
    }
    primary_start = (uint64_t)primary_start_ll;
    buffer_end = buffer_base_offset + (uint64_t)buffer_length;
    if (buffer_end < buffer_base_offset) {
        buffer_end = UINT64_MAX;
    }

    if (!ensure_primary_metadata_run_windows()) {
        return 0U;
    }

    if (g_primary_metadata_run_window_cursor > 0U &&
        buffer_base_offset <
            g_primary_metadata_run_windows[g_primary_metadata_run_window_cursor - 1U].abs_offset) {
        g_primary_metadata_run_window_cursor = 0U;
    }

    while (g_primary_metadata_run_window_cursor < g_primary_metadata_run_window_count &&
           g_primary_metadata_run_windows[g_primary_metadata_run_window_cursor].end_offset <=
               buffer_base_offset) {
        g_primary_metadata_run_window_cursor++;
    }

    for (window_index = g_primary_metadata_run_window_cursor;
         window_index < g_primary_metadata_run_window_count;
         window_index++) {
        const PrimaryMetadataRunWindow *window = &g_primary_metadata_run_windows[window_index];
        uint64_t overlap_start;
        uint64_t overlap_end;
        uint64_t overlap_length;
        uint64_t buffer_delta;
        uint64_t run_delta;
        uint64_t logical_overlap_start;
        uint64_t observed_start;

        if (window->abs_offset >= buffer_end) {
            break;
        }

        overlap_start = buffer_base_offset > window->abs_offset
            ? buffer_base_offset
            : window->abs_offset;
        overlap_end = buffer_end < window->end_offset ? buffer_end : window->end_offset;
        if (overlap_start >= overlap_end) {
            continue;
        }
        overlap_length = overlap_end - overlap_start;
        buffer_delta = overlap_start - buffer_base_offset;
        run_delta = overlap_start - window->abs_offset;
        logical_overlap_start = window->logical_start + run_delta;
        if (logical_overlap_start < window->logical_start) {
            continue;
        }
        if (logical_overlap_start < g_primary_metadata_prefetched_logical_bytes) {
            uint64_t skip = g_primary_metadata_prefetched_logical_bytes - logical_overlap_start;

            if (skip >= overlap_length) {
                continue;
            }
            overlap_start += skip;
            overlap_length -= skip;
            buffer_delta += skip;
            run_delta += skip;
            logical_overlap_start += skip;
        }

        if (buffer_delta > (uint64_t)SIZE_MAX ||
            overlap_length > (uint64_t)SIZE_MAX ||
            primary_start > UINT64_MAX - logical_overlap_start) {
            return observed_total;
        }

        observed_start = primary_start + logical_overlap_start;
        observed_total += observe_metadata_records_timed(
            buffer + (size_t)buffer_delta,
            (size_t)overlap_length,
            observed_start,
            0
        );
    }

    return observed_total;
}

static size_t observe_metadata_records_for_raw_all(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    if (!fs_backend_supports_live_metadata_observation()) {
        note_raw_all_metadata_observe_mode(
            -1,
            fs_backend_has_metadata_context_for_raw_scan()
                ? "live observation unavailable; preloaded metadata context active"
                : "backend metadata observation unavailable");
        return 0U;
    }

    if (fs_backend_has_native_geometry() &&
        primary_metadata_runlist_is_trustworthy_for_live_observation()) {
        note_raw_all_metadata_observe_mode(2, "primary metadata runlist");
        return observe_metadata_records_from_primary_runlist(
            buffer,
            buffer_length,
            buffer_base_offset
        );
    }

    if (fs_backend_has_native_geometry()) {
        note_raw_all_metadata_observe_mode(1, "aligned native records");
        return observe_metadata_records_timed(
            buffer,
            buffer_length,
            buffer_base_offset,
            0
        );
    }

    note_raw_all_metadata_observe_mode(0, "broad backend record scan");
    return observe_metadata_records_timed(
        buffer,
        buffer_length,
        buffer_base_offset,
        1
    );
}

static size_t observe_directory_index_targets_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    uint64_t buffer_end;
    size_t window_index;
    size_t updates = 0U;

    if (buffer == NULL ||
        buffer_length == 0U ||
        fs_backend_current_kind() != FS_BACKEND_KIND_NTFS ||
        !ensure_live_directory_index_windows()) {
        return 0U;
    }

    buffer_end = buffer_base_offset + (uint64_t)buffer_length;
    if (buffer_end < buffer_base_offset) {
        buffer_end = UINT64_MAX;
    }

    if (g_live_directory_index_window_cursor > 0U &&
        buffer_base_offset <
            g_live_directory_index_windows
                [g_live_directory_index_window_cursor - 1U]
                    .target.abs_offset) {
        g_live_directory_index_window_cursor = 0U;
    }

    while (g_live_directory_index_window_cursor <
               g_live_directory_index_window_count &&
           g_live_directory_index_windows
                   [g_live_directory_index_window_cursor]
                       .end_offset <= buffer_base_offset) {
        g_live_directory_index_window_cursor++;
    }

    for (window_index = g_live_directory_index_window_cursor;
         window_index < g_live_directory_index_window_count;
         window_index++) {
        const LiveDirectoryIndexWindow *window =
            &g_live_directory_index_windows[window_index];
        uint64_t overlap_start;
        uint64_t overlap_end;
        uint64_t aligned_start;
        uint64_t aligned_end;
        uint64_t scan_length;
        size_t buffer_offset;

        if (window->target.abs_offset >= buffer_end) {
            break;
        }

        overlap_start = buffer_base_offset > window->target.abs_offset
            ? buffer_base_offset
            : window->target.abs_offset;
        overlap_end = buffer_end < window->end_offset
            ? buffer_end
            : window->end_offset;
        if (overlap_start >= overlap_end) {
            continue;
        }

        aligned_start = scanner_align_up_u64(
            overlap_start,
            (uint64_t)window->target.index_block_size
        );
        if (aligned_start >= overlap_end ||
            aligned_start == UINT64_MAX) {
            continue;
        }

        aligned_end = overlap_end;
        scan_length = aligned_end - aligned_start;
        if (scan_length < (uint64_t)window->target.index_block_size ||
            aligned_start < buffer_base_offset ||
            aligned_start - buffer_base_offset > (uint64_t)SIZE_MAX) {
            continue;
        }

        buffer_offset = (size_t)(aligned_start - buffer_base_offset);
        updates += fs_backend_absorb_directory_index_buffer(
            &window->target,
            buffer + buffer_offset,
            (size_t)scan_length,
            aligned_start
        );
    }

    return updates;
}

static size_t observe_directory_index_signatures_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    FsDirectoryIndexTarget target = {0};
    uint64_t buffer_end;
    uint64_t index_block_size;
    uint64_t candidate_offset;
    size_t updates = 0U;

    if (buffer == NULL ||
        buffer_length < 512U ||
        fs_backend_current_kind() != FS_BACKEND_KIND_NTFS) {
        return 0U;
    }

    target.family_base_offset = fs_backend_primary_scan_start_offset();
    index_block_size = fs_backend_cluster_size();
    if (index_block_size < 512U || index_block_size > 8192U) {
        index_block_size = 4096U;
    }
    target.index_block_size = (uint32_t)index_block_size;

    buffer_end = buffer_base_offset + (uint64_t)buffer_length;
    if (buffer_end < buffer_base_offset) {
        buffer_end = UINT64_MAX;
    }

    candidate_offset = scanner_align_up_u64(buffer_base_offset, index_block_size);
    while (candidate_offset != UINT64_MAX &&
           candidate_offset + index_block_size <= buffer_end) {
        size_t buffer_offset;

        if (candidate_offset < buffer_base_offset ||
            candidate_offset - buffer_base_offset > (uint64_t)SIZE_MAX) {
            break;
        }

        buffer_offset = (size_t)(candidate_offset - buffer_base_offset);
        if (memcmp(buffer + buffer_offset, "INDX", 4U) == 0) {
            updates += fs_backend_absorb_directory_index_buffer(
                &target,
                buffer + buffer_offset,
                (size_t)index_block_size,
                candidate_offset
            );
        }

        if (UINT64_MAX - candidate_offset < index_block_size) {
            break;
        }
        candidate_offset += index_block_size;
    }

    return updates;
}

static void observe_directory_indexes_for_current_buffer(
    const Reader *reader,
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset,
    const char *phase_label,
    int live_main_scan
)
{
    size_t names_before;
    size_t names_after;
    size_t target_updates;
    size_t signature_updates;

    if (buffer == NULL ||
        buffer_length == 0U ||
        fs_backend_current_kind() != FS_BACKEND_KIND_NTFS) {
        return;
    }

    names_before = fs_backend_directory_index_name_count();
    target_updates = observe_directory_index_targets_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
    if (raw_all_should_scan_passive_directory_signatures_live(
            reader,
            live_main_scan)) {
        signature_updates = observe_directory_index_signatures_in_buffer(
            buffer,
            buffer_length,
            buffer_base_offset
        );
    } else {
        signature_updates = 0U;
    }
    names_after = fs_backend_directory_index_name_count();

    if (names_after > names_before ||
        target_updates > 0U ||
        signature_updates > 0U) {
        log_info(
            "Live NTFS directory-index wake-up during %s: known-target updates=%zu passive-INDX updates=%zu i30_names=%zu->%zu",
            phase_label != NULL ? phase_label : "scan",
            target_updates,
            signature_updates,
            names_before,
            names_after
        );
        update_working_queue_from_metadata_stats();
    }
}

static uint64_t scanner_min_u64(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}

static uint64_t clamp_range_length_to_source(
    uint64_t start,
    uint64_t length,
    uint64_t source_size
)
{
    if (length == 0U) {
        return 0U;
    }
    if (source_size > 0U) {
        if (start >= source_size) {
            return 0U;
        }
        return scanner_min_u64(length, source_size - start);
    }
    if (UINT64_MAX - start < length) {
        return UINT64_MAX - start;
    }
    return length;
}

static int primary_metadata_attachment_is_usable(void)
{
    FsBackendLiveStats metadata_stats = {0};

    if (!fs_backend_has_primary_catalog_root() &&
        fs_backend_primary_run_count() == 0U) {
        return 0;
    }

    fs_backend_get_live_queue_stats(&metadata_stats);
    return metadata_stats.record_index_count > 0U ||
           metadata_stats.range_index_count > 0U;
}

static int primary_metadata_runlist_is_trustworthy_for_live_observation(void)
{
    /*
     * Do not narrow the whole raw-all metadata scan to the discovered $MFT
     * runlist until the primary catalog picture has proven itself enough to
     * find a real root-level foothold. Thin/partial $MFT salvage can expose
     * some extents early, but trusting them too soon makes rescueable disks
     * look "empty" when the rest of the MFT is still recoverable by aligned
     * foreground observation.
     */
    return fs_backend_has_primary_catalog_root() &&
           fs_backend_primary_run_count() > 0U;
}

static int scan_primary_metadata_mirror(
    Reader *reader,
    uint64_t primary_start,
    uint64_t source_size,
    int allow_unaligned,
    int stop_when_users_root_seen,
    uint64_t *out_records_observed,
    uint64_t *out_bytes_scanned
)
{
    long long mirror_start_ll;
    uint64_t mirror_start;
    uint64_t mirror_length;

    if (reader == NULL) {
        return 0;
    }

    mirror_start_ll = fs_backend_expected_mirror_offset();
    if (mirror_start_ll < 0) {
        return 1;
    }

    mirror_start = (uint64_t)mirror_start_ll;
    mirror_length = fs_backend_estimated_mirror_bytes();
    if (mirror_length == 0U) {
        size_t record_size = fs_backend_record_size();

        if (record_size == 0U) {
            record_size = 1024U;
        }
        mirror_length = (uint64_t)record_size * 4ULL;
    }
    if (mirror_length > PRIMARY_METADATA_MIRROR_SWEEP_MAX_BYTES) {
        mirror_length = PRIMARY_METADATA_MIRROR_SWEEP_MAX_BYTES;
    }
    mirror_length = clamp_range_length_to_source(
        mirror_start,
        mirror_length,
        source_size
    );
    if (mirror_length == 0U) {
        return 1;
    }

    log_info(
        "Sweeping primary metadata mirror at byte %llu for %.1f KiB",
        (unsigned long long)mirror_start,
        (double)mirror_length / 1024.0
    );

    return scan_primary_metadata_range_observed(
        reader,
        mirror_start,
        primary_start,
        mirror_length,
        allow_unaligned,
        stop_when_users_root_seen,
        out_records_observed,
        out_bytes_scanned
    );
}

static int scan_primary_metadata_reverse_windows(
    Reader *reader,
    uint64_t start,
    uint64_t observed_start,
    uint64_t length,
    uint64_t window_bytes,
    int allow_unaligned,
    int stop_when_users_root_seen,
    uint64_t *out_records_observed,
    uint64_t *out_bytes_scanned
)
{
    uint64_t remaining = length;

    if (reader == NULL || length == 0U || window_bytes == 0U) {
        return 1;
    }

    while (remaining > 0U &&
           !app_stop_requested() &&
           !app_source_reconnect_requested()) {
        if (primary_metadata_acquisition_time_budget_reached(
                "reverse metadata revisit")) {
            break;
        }
        uint64_t chunk_length = remaining > window_bytes ? window_bytes : remaining;
        uint64_t chunk_offset = remaining - chunk_length;
        uint64_t physical_start = start + chunk_offset;
        uint64_t logical_start = observed_start + chunk_offset;

        if (!scan_primary_metadata_range_observed(
                reader,
                physical_start,
                logical_start,
                chunk_length,
                allow_unaligned,
                stop_when_users_root_seen,
                out_records_observed,
                out_bytes_scanned)) {
            return 0;
        }
        if (stop_when_users_root_seen && fs_backend_has_primary_catalog_root()) {
            break;
        }
        remaining = chunk_offset;
    }

    return !app_stop_requested() && !app_source_reconnect_requested();
}

static int scan_primary_metadata_range_observed(
    Reader *reader,
    uint64_t start,
    uint64_t observed_start,
    uint64_t length,
    int allow_unaligned,
    int stop_when_users_root_seen,
    uint64_t *out_records_observed,
    uint64_t *out_bytes_scanned
)
{
    size_t saved_chunk_size;
    int saved_progress_reporting;
    uint64_t range_end;

    if (reader == NULL || length == 0U) {
        return 1;
    }
    if (start > (uint64_t)SIZE_MAX) {
        return 0;
    }

    range_end = start + length;
    if (range_end < start) {
        range_end = UINT64_MAX;
    }

    saved_progress_reporting = reader_set_progress_reporting(reader, 0);
    if (!reader_seek_absolute(reader, start)) {
        (void)reader_set_progress_reporting(reader, saved_progress_reporting);
        return 0;
    }

    saved_chunk_size = reader->chunk_size;
    while (!app_stop_requested() && !app_source_reconnect_requested()) {
        uint64_t buffer_base;
        uint64_t buffer_end;
        uint64_t read_offset;
        uint64_t remaining_in_range;
        size_t limited_chunk_size;
        size_t observe_length;
        size_t observed;

        read_offset = reader->progress_bytes_read;
        if (read_offset >= range_end) {
            break;
        }
        if (primary_metadata_acquisition_time_budget_reached(
                "metadata range scan")) {
            break;
        }

        remaining_in_range = range_end - read_offset;
        limited_chunk_size = saved_chunk_size;
        if (g_primary_metadata_chunk_cap_bytes > 0U &&
            limited_chunk_size > g_primary_metadata_chunk_cap_bytes) {
            limited_chunk_size = g_primary_metadata_chunk_cap_bytes;
        }
        if (remaining_in_range < (uint64_t)limited_chunk_size) {
            limited_chunk_size = (size_t)remaining_in_range;
        }
        if (limited_chunk_size == 0U) {
            break;
        }

        reader->chunk_size = limited_chunk_size;
        if (reader_read_next(reader) == 0) {
            reader->chunk_size = saved_chunk_size;
            if (app_source_reconnect_requested()) {
                (void)reader_set_progress_reporting(reader, saved_progress_reporting);
                return 0;
            }
            break;
        }
        reader->chunk_size = saved_chunk_size;

        buffer_base = (uint64_t)(reader->total_bytes_read - reader->bytes_in_buffer);
        buffer_end = buffer_base + (uint64_t)reader->bytes_in_buffer;
        if (buffer_end < buffer_base) {
            buffer_end = UINT64_MAX;
        }

        if (buffer_base >= range_end) {
            break;
        }

        observe_length = reader->bytes_in_buffer;
        if (buffer_end > range_end) {
            observe_length = (size_t)(range_end - buffer_base);
        }

        if (observe_length > 0U) {
            uint64_t observed_base = observed_start;

            if (buffer_base >= start) {
                uint64_t physical_delta = buffer_base - start;

                if (observed_start <= UINT64_MAX - physical_delta) {
                    observed_base = observed_start + physical_delta;
                } else {
                    observed_base = UINT64_MAX;
                }
            }

            observed = observe_metadata_records_timed(
                reader->buffer,
                observe_length,
                observed_base,
                allow_unaligned
            );
            if (out_records_observed != NULL) {
                *out_records_observed += (uint64_t)observed;
            }
            if (out_bytes_scanned != NULL) {
                *out_bytes_scanned += (uint64_t)observe_length;
            }
            write_primary_metadata_progress_state(
                NULL,
                "range_scan",
                reader,
                out_records_observed != NULL ? *out_records_observed : 0ULL,
                out_bytes_scanned != NULL ? *out_bytes_scanned : 0ULL,
                start,
                range_end,
                0
            );
            update_working_queue_from_metadata_stats();
            if (stop_when_users_root_seen && fs_backend_has_primary_catalog_root()) {
                break;
            }
        }

        if ((uint64_t)reader->total_bytes_read >= range_end) {
            break;
        }
    }
    reader->chunk_size = saved_chunk_size;
    (void)reader_set_progress_reporting(reader, saved_progress_reporting);

    return !app_stop_requested() && !app_source_reconnect_requested();
}

static int scan_primary_metadata_range(
    Reader *reader,
    uint64_t start,
    uint64_t length,
    int allow_unaligned,
    int stop_when_users_root_seen,
    uint64_t *out_records_observed,
    uint64_t *out_bytes_scanned
)
{
    return scan_primary_metadata_range_observed(
        reader,
        start,
        start,
        length,
        allow_unaligned,
        stop_when_users_root_seen,
        out_records_observed,
        out_bytes_scanned
    );
}

static int scan_primary_metadata_runlist(
    Reader *reader,
    uint64_t primary_start,
    uint64_t target_logical_bytes,
    uint64_t already_scanned_logical_bytes,
    uint64_t source_size,
    uint64_t *out_records_observed,
    uint64_t *out_bytes_scanned
)
{
    size_t run_count;
    size_t run_index;
    uint64_t logical_pos = 0U;
    uint64_t total_run_bytes = 0U;

    if (reader == NULL || target_logical_bytes == 0U) {
        return 1;
    }

    run_count = fs_backend_primary_run_count();
    if (run_count == 0U) {
        return 1;
    }

    for (run_index = 0; run_index < run_count; run_index++) {
        uint64_t run_abs = 0U;
        uint64_t run_length = 0U;

        if (!fs_backend_get_primary_run(run_index, &run_abs, &run_length)) {
            continue;
        }
        if (UINT64_MAX - total_run_bytes < run_length) {
            total_run_bytes = UINT64_MAX;
            break;
        }
        total_run_bytes += run_length;
    }

    log_info(
        "Primary metadata runlist discovered with %zu run%s; indexing up to %.1f MiB of logical metadata before raw-all scan",
        run_count,
        run_count == 1U ? "" : "s",
        (double)scanner_min_u64(target_logical_bytes, total_run_bytes) /
            (1024.0 * 1024.0)
    );

    for (run_index = 0;
         run_index < run_count &&
         !app_stop_requested() &&
         !app_source_reconnect_requested();
         run_index++) {
        uint64_t run_abs = 0U;
        uint64_t run_length = 0U;
        uint64_t logical_end;
        uint64_t scan_logical_start;
        uint64_t scan_length;
        uint64_t run_skip;
        uint64_t physical_start;
        uint64_t observed_start;

        if (!fs_backend_get_primary_run(run_index, &run_abs, &run_length) ||
            run_length == 0U) {
            continue;
        }

        logical_end = logical_pos + run_length;
        if (logical_end < logical_pos) {
            logical_end = UINT64_MAX;
        }

        if (logical_end <= already_scanned_logical_bytes) {
            logical_pos = logical_end;
            continue;
        }
        if (logical_pos >= target_logical_bytes) {
            break;
        }

        scan_logical_start = logical_pos;
        if (scan_logical_start < already_scanned_logical_bytes) {
            scan_logical_start = already_scanned_logical_bytes;
        }
        if (scan_logical_start >= target_logical_bytes) {
            break;
        }

        scan_length = logical_end - scan_logical_start;
        if (scan_length > target_logical_bytes - scan_logical_start) {
            scan_length = target_logical_bytes - scan_logical_start;
        }
        run_skip = scan_logical_start - logical_pos;
        if (run_abs > UINT64_MAX - run_skip ||
            primary_start > UINT64_MAX - scan_logical_start) {
            return 0;
        }
        physical_start = run_abs + run_skip;
        observed_start = primary_start + scan_logical_start;
        scan_length = clamp_range_length_to_source(
            physical_start,
            scan_length,
            source_size
        );
        if (scan_length == 0U) {
            logical_pos = logical_end;
            continue;
        }

        log_set_working_activity("indexing primary metadata");
        if (!scan_primary_metadata_range_observed(
                reader,
                physical_start,
                observed_start,
                scan_length,
                0,
                0,
                out_records_observed,
                out_bytes_scanned)) {
            return 0;
        }

        logical_pos = logical_end;
    }

    return !app_stop_requested() && !app_source_reconnect_requested();
}

static int scan_primary_directory_index_targets(
    Reader *reader,
    uint64_t max_total_bytes,
    const char *phase_label,
    uint64_t *out_bytes_scanned
)
{
    FsDirectoryIndexTarget *targets = NULL;
    size_t target_count;
    size_t target_index;
    size_t names_before;
    size_t names_after;
    uint64_t bytes_scanned = 0U;
    size_t saved_chunk_size;
    int saved_progress_reporting;
    int saved_precise_mode;
    int saved_first_sector_only;
    size_t saved_probe_bytes;
    size_t saved_first_sector_cap_bytes;

    if (out_bytes_scanned != NULL) {
        *out_bytes_scanned = 0U;
    }
    if (reader == NULL || max_total_bytes == 0U) {
        return 1;
    }

    target_count = fs_backend_collect_directory_index_targets(
        NULL,
        0U,
        max_total_bytes
    );
    if (target_count == 0U) {
        return 1;
    }

    targets = (FsDirectoryIndexTarget *)calloc(target_count, sizeof(*targets));
    if (targets == NULL) {
        log_error(
            "Primary metadata %s could not allocate %zu directory-index target%s",
            phase_label != NULL ? phase_label : "directory index assist",
            target_count,
            target_count == 1U ? "" : "s"
        );
        return 0;
    }

    target_count = fs_backend_collect_directory_index_targets(
        targets,
        target_count,
        max_total_bytes
    );
    if (target_count == 0U) {
        free(targets);
        return 1;
    }

    names_before = fs_backend_directory_index_name_count();
    saved_chunk_size = reader->chunk_size;
    saved_progress_reporting = reader_set_progress_reporting(reader, 0);
    saved_precise_mode = reader->precise_record_mode;
    saved_first_sector_only = reader->precise_record_first_sector_only;
    saved_probe_bytes = reader->precise_record_probe_bytes;
    saved_first_sector_cap_bytes = reader->precise_record_first_sector_cap_bytes;
    (void)reader_set_precise_record_mode(reader, 0);
    (void)reader_set_precise_record_first_sector_only(reader, 0);
    (void)reader_set_precise_record_probe_bytes(reader, 0U);
    (void)reader_set_precise_record_first_sector_cap_bytes(reader, 0U);

    log_info(
        "Primary metadata %s: absorbing up to %.1f MiB of known directory-index runs across %zu target%s",
        phase_label != NULL ? phase_label : "directory index assist",
        (double)max_total_bytes / (1024.0 * 1024.0),
        target_count,
        target_count == 1U ? "" : "s"
    );

    for (target_index = 0U;
         target_index < target_count &&
         !app_stop_requested() &&
         !app_source_reconnect_requested();
         target_index++) {
        const FsDirectoryIndexTarget *target = &targets[target_index];
        uint64_t target_length = clamp_range_length_to_source(
            target->abs_offset,
            target->byte_length,
            reader_get_source_size(reader)
        );
        uint64_t target_end;
        uint64_t cursor;

        if (target_length == 0U) {
            continue;
        }
        if (primary_metadata_acquisition_time_budget_reached(
                "directory index scan")) {
            break;
        }

        if (UINT64_MAX - target->abs_offset < target_length) {
            target_end = UINT64_MAX;
        } else {
            target_end = target->abs_offset + target_length;
        }
        cursor = target->abs_offset;

        while (cursor < target_end &&
               !app_stop_requested() &&
               !app_source_reconnect_requested()) {
            uint64_t remaining;
            size_t limited_chunk_size;
            size_t bytes_read;
            size_t available;

            if (primary_metadata_acquisition_time_budget_reached(
                    "directory index scan")) {
                break;
            }
            if (!reader_seek_absolute(reader, cursor)) {
                if (app_source_reconnect_requested()) {
                    goto restore_reader;
                }
                break;
            }

            remaining = target_end - cursor;
            limited_chunk_size = saved_chunk_size;
            if (g_primary_metadata_chunk_cap_bytes > 0U &&
                limited_chunk_size > g_primary_metadata_chunk_cap_bytes) {
                limited_chunk_size = g_primary_metadata_chunk_cap_bytes;
            }
            if ((uint64_t)limited_chunk_size > remaining) {
                limited_chunk_size = (size_t)remaining;
            }
            if (limited_chunk_size < (size_t)target->index_block_size) {
                limited_chunk_size = (size_t)scanner_min_u64(
                    remaining,
                    (uint64_t)target->index_block_size
                );
            }
            if (limited_chunk_size == 0U) {
                break;
            }

            reader->chunk_size = limited_chunk_size;
            bytes_read = reader_read_next(reader);
            reader->chunk_size = saved_chunk_size;
            if (bytes_read == 0U || reader->bytes_in_buffer == 0U) {
                if (app_source_reconnect_requested()) {
                    goto restore_reader;
                }
                break;
            }

            available = reader->bytes_in_buffer;
            if ((uint64_t)available > remaining) {
                available = (size_t)remaining;
            }
            if (available < (size_t)target->index_block_size) {
                break;
            }

            (void)fs_backend_absorb_directory_index_buffer(
                target,
                reader->buffer,
                available,
                cursor
            );
            bytes_scanned += (uint64_t)available;
            cursor += (uint64_t)available;
            write_primary_metadata_progress_state(
                phase_label,
                "directory_index_scan",
                reader,
                0ULL,
                bytes_scanned,
                target->abs_offset,
                target_end,
                0
            );
            update_working_queue_from_metadata_stats();
        }
    }

restore_reader:
    reader->chunk_size = saved_chunk_size;
    (void)reader_set_precise_record_mode(reader, saved_precise_mode);
    (void)reader_set_precise_record_first_sector_only(reader, saved_first_sector_only);
    (void)reader_set_precise_record_probe_bytes(reader, saved_probe_bytes);
    (void)reader_set_precise_record_first_sector_cap_bytes(reader, saved_first_sector_cap_bytes);
    (void)reader_set_progress_reporting(reader, saved_progress_reporting);

    names_after = fs_backend_directory_index_name_count();
    if (out_bytes_scanned != NULL) {
        *out_bytes_scanned = bytes_scanned;
    }
    if (bytes_scanned > 0U || names_after > names_before) {
        log_info(
            "Primary metadata %s: directory-index spool scanned %.1f MiB and grew naming entries from %zu to %zu",
            phase_label != NULL ? phase_label : "directory index assist",
            (double)bytes_scanned / (1024.0 * 1024.0),
            names_before,
            names_after
        );
    }

    free(targets);
    return !app_stop_requested() && !app_source_reconnect_requested();
}

static int scanner_run_primary_metadata_acquisition_plan(
    Reader *reader,
    const PrimaryMetadataAcquirePlan *plan
)
{
    long long primary_start_ll = -1;
    uint64_t primary_start = 0U;
    uint64_t source_size;
    uint64_t bootstrap_length;
    uint64_t probe_length;
    uint64_t logical_prefix_scanned = 0U;
    uint64_t logical_prefetched_bytes = 0U;
    uint64_t records_observed = 0U;
    uint64_t bytes_scanned = 0U;
    uint64_t read_errors_before = 0U;
    size_t run_count = 0U;
    const char *phase_label;
    int result = 0;

    if (reader == NULL || plan == NULL) {
        return 0;
    }

    phase_label =
        (plan->phase_label != NULL && plan->phase_label[0] != '\0')
            ? plan->phase_label
            : "metadata acquisition";

    if (plan->skip_if_attached && primary_metadata_attachment_is_usable()) {
        log_info(
            "Primary metadata %s skipped; a usable naming index is already attached",
            phase_label
        );
        return 1;
    }

    clear_primary_metadata_run_windows();
    g_primary_metadata_prefetched_logical_bytes = 0U;
    g_primary_metadata_acquire_deadline_at =
        plan->max_seconds > 0.0
            ? (scanner_now_seconds() + plan->max_seconds)
            : 0.0;
    g_primary_metadata_chunk_cap_bytes =
        primary_metadata_effective_chunk_cap_bytes(
            reader,
            plan->max_chunk_bytes
        );
    if (g_primary_metadata_chunk_cap_bytes > plan->max_chunk_bytes) {
        log_info(
            "Primary metadata chunk tuning: source=regular-file cap=%.1f->%.1f KiB",
            (double)plan->max_chunk_bytes / 1024.0,
            (double)g_primary_metadata_chunk_cap_bytes / 1024.0
        );
    }
    g_primary_metadata_budget_yield_logged = 0;
    g_primary_metadata_progress_last_write_at = 0.0;
    snprintf(
        g_primary_metadata_progress_phase_label,
        sizeof(g_primary_metadata_progress_phase_label),
        "%s",
        phase_label
    );
    if (plan->disable_live_observation_on_fail) {
        g_primary_metadata_bootstrap_should_disable_live_observation = 0;
    }

    if (!fs_backend_has_native_geometry()) {
        log_info(
            "Primary metadata %s skipped; native filesystem geometry is not available",
            phase_label
        );
        result = 1;
        goto cleanup;
    }

    primary_start_ll = fs_backend_primary_scan_start_offset();
    if (primary_start_ll < 0) {
        log_info(
            "Primary metadata %s skipped; no primary metadata offset is known",
            phase_label
        );
        result = 1;
        goto cleanup;
    }

    primary_start = (uint64_t)primary_start_ll;
    source_size = reader_get_source_size(reader);
    if (source_size > 0U && primary_start >= source_size) {
        log_info(
            "Primary metadata %s skipped; primary metadata offset %llu is outside source size %llu",
            phase_label,
            (unsigned long long)primary_start,
            (unsigned long long)source_size
        );
        result = 1;
        goto cleanup;
    }

    bootstrap_length = clamp_range_length_to_source(
        primary_start,
        plan->bootstrap_length,
        source_size
    );
    if (bootstrap_length == 0U) {
        result = 1;
        goto cleanup;
    }

    probe_length = scanner_min_u64(
        plan->probe_length > 0U ? plan->probe_length : bootstrap_length,
        bootstrap_length
    );
    logical_prefix_scanned = probe_length;

    log_set_working_activity("acquiring primary metadata");
    log_info(
        "Primary metadata %s: scanning from byte %llu with %.1f MiB bootstrap budget",
        phase_label,
        (unsigned long long)primary_start,
        (double)bootstrap_length / (1024.0 * 1024.0)
    );
    write_primary_metadata_progress_state(
        phase_label,
        "start",
        reader,
        records_observed,
        bytes_scanned,
        primary_start,
        primary_start <= UINT64_MAX - bootstrap_length
            ? primary_start + bootstrap_length
            : UINT64_MAX,
        1
    );
    read_errors_before = reader_get_read_error_count(reader);

    if (plan->include_mirror_before && !primary_metadata_attachment_is_usable()) {
        if (!scan_primary_metadata_mirror(
                reader,
                primary_start,
                source_size,
                1,
                0,
                &records_observed,
                &bytes_scanned)) {
            result = 0;
            goto cleanup;
        }
        if (primary_metadata_acquisition_should_yield(
                reader,
                read_errors_before,
                phase_label,
                plan->disable_live_observation_on_fail)) {
            result = 1;
            goto cleanup;
        }
    }

    if (!scan_primary_metadata_range(
            reader,
            primary_start,
            probe_length,
            1,
            0,
            &records_observed,
            &bytes_scanned)) {
        result = 0;
        goto cleanup;
    }
    if (primary_metadata_acquisition_should_yield(
            reader,
            read_errors_before,
            phase_label,
            plan->disable_live_observation_on_fail)) {
        result = 1;
        goto cleanup;
    }

    run_count = fs_backend_primary_run_count();
    if (run_count == 0U && probe_length < bootstrap_length) {
        if (!scan_primary_metadata_range(
                reader,
                primary_start + probe_length,
                bootstrap_length - probe_length,
                1,
                0,
                &records_observed,
                &bytes_scanned)) {
            result = 0;
            goto cleanup;
        }
        if (primary_metadata_acquisition_should_yield(
                reader,
                read_errors_before,
                phase_label,
                plan->disable_live_observation_on_fail)) {
            result = 1;
            goto cleanup;
        }
        logical_prefix_scanned = bootstrap_length;
        run_count = fs_backend_primary_run_count();
    }

    if (run_count == 0U &&
        !fs_backend_has_primary_catalog_root() &&
        plan->fallback_length > bootstrap_length) {
        uint64_t fallback_length = clamp_range_length_to_source(
            primary_start,
            plan->fallback_length,
            source_size
        );

        if (fallback_length > bootstrap_length) {
            log_info(
                "Primary metadata %s: usable root/runlist was not available after the bootstrap window; extending to %.1f MiB",
                phase_label,
                (double)fallback_length / (1024.0 * 1024.0)
            );
            if (!scan_primary_metadata_range(
                    reader,
                    primary_start + bootstrap_length,
                    fallback_length - bootstrap_length,
                    1,
                    0,
                    &records_observed,
                    &bytes_scanned)) {
                result = 0;
                goto cleanup;
            }
            if (primary_metadata_acquisition_should_yield(
                    reader,
                    read_errors_before,
                    phase_label,
                    plan->disable_live_observation_on_fail)) {
                result = 1;
                goto cleanup;
            }
            logical_prefix_scanned = fallback_length;
            run_count = fs_backend_primary_run_count();
        }
    }

    if (plan->include_mirror_after && !primary_metadata_attachment_is_usable()) {
        if (!scan_primary_metadata_mirror(
                reader,
                primary_start,
                source_size,
                1,
                0,
                &records_observed,
                &bytes_scanned)) {
            result = 0;
            goto cleanup;
        }
        if (primary_metadata_acquisition_should_yield(
                reader,
                read_errors_before,
                phase_label,
                plan->disable_live_observation_on_fail)) {
            result = 1;
            goto cleanup;
        }
        run_count = fs_backend_primary_run_count();
    }

    if (run_count > 0U) {
        uint64_t directory_index_bytes_scanned = 0U;
        uint64_t runlist_target_bytes = plan->runlist_target_bytes;
        uint64_t primary_total_bytes = fs_backend_primary_total_bytes();

        if (runlist_target_bytes < logical_prefix_scanned) {
            runlist_target_bytes = logical_prefix_scanned;
        }

        if (!scan_primary_metadata_runlist(
                reader,
                primary_start,
                runlist_target_bytes,
                logical_prefix_scanned,
                source_size,
                &records_observed,
                &bytes_scanned)) {
            result = 0;
            goto cleanup;
        }
        if (primary_metadata_acquisition_should_yield(
                reader,
                read_errors_before,
                phase_label,
                plan->disable_live_observation_on_fail)) {
            result = 1;
            goto cleanup;
        }

        if (!scan_primary_directory_index_targets(
                reader,
                runlist_target_bytes,
                phase_label,
                &directory_index_bytes_scanned)) {
            result = 0;
            goto cleanup;
        }
        if (directory_index_bytes_scanned > 0U) {
            bytes_scanned += directory_index_bytes_scanned;
        }
        if (primary_metadata_acquisition_should_yield(
                reader,
                read_errors_before,
                phase_label,
                plan->disable_live_observation_on_fail)) {
            result = 1;
            goto cleanup;
        }

        logical_prefetched_bytes = runlist_target_bytes;
        if (primary_total_bytes > 0U &&
            logical_prefetched_bytes > primary_total_bytes) {
            logical_prefetched_bytes = primary_total_bytes;
        }
        if (logical_prefetched_bytes < logical_prefix_scanned) {
            logical_prefetched_bytes = logical_prefix_scanned;
        }
    } else {
        log_info(
            "Primary metadata %s did not discover a runlist yet; the main workflow will keep the current metadata state and continue",
            phase_label
        );
    }

    if (plan->reverse_primary_windows_after &&
        !primary_metadata_attachment_is_usable() &&
        logical_prefix_scanned > 0U) {
        log_info(
            "Primary metadata %s: retrying the primary metadata window in reverse %.1f MiB chunks",
            phase_label,
            (double)PRIMARY_METADATA_POST_DEFERRED_REVERSE_WINDOW_BYTES /
                (1024.0 * 1024.0)
        );
        if (!scan_primary_metadata_reverse_windows(
                reader,
                primary_start,
                primary_start,
                logical_prefix_scanned,
                PRIMARY_METADATA_POST_DEFERRED_REVERSE_WINDOW_BYTES,
                1,
                0,
                &records_observed,
                &bytes_scanned)) {
            result = 0;
            goto cleanup;
        }
        if (primary_metadata_acquisition_should_yield(
                reader,
                read_errors_before,
                phase_label,
                plan->disable_live_observation_on_fail)) {
            result = 1;
            goto cleanup;
        }
    }

    if (plan->reverse_prefetched_windows_after &&
        !primary_metadata_attachment_is_usable() &&
        logical_prefetched_bytes > logical_prefix_scanned) {
        log_info(
            "Primary metadata %s: running one more bounded reverse pass across the prefetched primary-MFT window (%.1f MiB) to chase parent chains and late records before giving up",
            phase_label,
            (double)logical_prefetched_bytes / (1024.0 * 1024.0)
        );
        if (!scan_primary_metadata_reverse_windows(
                reader,
                primary_start,
                primary_start,
                logical_prefetched_bytes,
                PRIMARY_METADATA_POST_DEFERRED_REVERSE_WINDOW_BYTES,
                1,
                0,
                &records_observed,
                &bytes_scanned)) {
            result = 0;
            goto cleanup;
        }
        if (primary_metadata_acquisition_should_yield(
                reader,
                read_errors_before,
                phase_label,
                plan->disable_live_observation_on_fail)) {
            result = 1;
            goto cleanup;
        }
    }

    if (logical_prefetched_bytes > 0U) {
        g_primary_metadata_prefetched_logical_bytes = logical_prefetched_bytes;
    }

    log_info(
        "Primary metadata %s observed %llu candidate records across %.1f MiB%s%s",
        phase_label,
        (unsigned long long)records_observed,
        (double)bytes_scanned / (1024.0 * 1024.0),
        fs_backend_has_primary_catalog_root() ? " and found a usable catalog root" : "",
        primary_metadata_attachment_is_usable()
            ? " with a usable naming index attached"
            : ""
    );
    update_working_queue_from_metadata_stats();
    result = !app_stop_requested() && !app_source_reconnect_requested();

cleanup:
    write_primary_metadata_progress_state(
        phase_label,
        result ? "finished" : "stopped",
        reader,
        records_observed,
        bytes_scanned,
        primary_start_ll >= 0 ? (uint64_t)primary_start_ll : 0ULL,
        0ULL,
        1
    );
    g_primary_metadata_acquire_deadline_at = 0.0;
    g_primary_metadata_chunk_cap_bytes = 0U;
    g_primary_metadata_budget_yield_logged = 0;
    g_primary_metadata_progress_phase_label[0] = '\0';
    return result;
}

static void reset_metadata_observe_stats(void)
{
    memset(&g_metadata_observe_stats, 0, sizeof(g_metadata_observe_stats));
    memset(&g_metadata_observe_stats_last_logged, 0, sizeof(g_metadata_observe_stats_last_logged));
    memset(&g_metadata_process_stats_last_logged, 0, sizeof(g_metadata_process_stats_last_logged));
    memset(&g_format_pipeline_live_stats_last_logged, 0, sizeof(g_format_pipeline_live_stats_last_logged));
    memset(&g_metadata_live_stats_last_logged, 0, sizeof(g_metadata_live_stats_last_logged));
    memset(&g_jpeg_stats_last_logged, 0, sizeof(g_jpeg_stats_last_logged));
    memset(&g_png_stats_last_logged, 0, sizeof(g_png_stats_last_logged));
    g_raw_all_metadata_observe_mode = -1;
    g_raw_all_passive_indx_live_scan_suppressed_logged = 0;
    g_raw_all_passive_indx_live_scan_enabled_logged = 0;
    g_last_working_queue_stats_update_at = 0.0;
    memset(&g_raw_all_resource_rate_baseline, 0, sizeof(g_raw_all_resource_rate_baseline));
    g_raw_all_active_resource_profile = RAW_ALL_RESOURCE_PROFILE_CONSTRAINED;
    g_raw_all_active_discovery_worker_count = 1U;
    g_raw_all_active_validation_worker_count = 1U;
    clear_primary_metadata_run_windows();
    if (fs_backend_entry_count() == 0U &&
        !fs_backend_has_metadata_context_for_raw_scan()) {
        fs_backend_reset_process_stats();
    }
}

static void raw_all_reset_recovered_state_cache(void)
{
    memset(
        &g_raw_all_recovered_state_cache,
        0,
        sizeof(g_raw_all_recovered_state_cache)
    );
}

static int raw_all_get_cached_recovered_state_summary(
    const char *output_dir,
    size_t *out_recovered_files,
    size_t *out_named_files,
    size_t *out_unident_files
)
{
    double now;
    int needs_refresh = 0;

    if (out_recovered_files != NULL) {
        *out_recovered_files = 0U;
    }
    if (out_named_files != NULL) {
        *out_named_files = 0U;
    }
    if (out_unident_files != NULL) {
        *out_unident_files = 0U;
    }

    if (output_dir == NULL || output_dir[0] == '\0') {
        return 0;
    }

    now = scanner_now_seconds();
    if (strcmp(g_raw_all_recovered_state_cache.output_dir, output_dir) != 0) {
        raw_all_reset_recovered_state_cache();
        snprintf(
            g_raw_all_recovered_state_cache.output_dir,
            sizeof(g_raw_all_recovered_state_cache.output_dir),
            "%s",
            output_dir
        );
        needs_refresh = 1;
    } else if (!g_raw_all_recovered_state_cache.valid ||
               now < g_raw_all_recovered_state_cache.refreshed_at ||
               now - g_raw_all_recovered_state_cache.refreshed_at >=
                   RAW_ALL_RECOVERED_STATE_REFRESH_SECONDS) {
        needs_refresh = 1;
    }

    if (needs_refresh) {
        g_raw_all_recovered_state_cache.recovered_files =
            app_best_effort_recovered_count_for_run(output_dir);
        g_raw_all_recovered_state_cache.named_files =
            app_best_effort_named_count_for_run(output_dir);
        g_raw_all_recovered_state_cache.unident_files =
            app_best_effort_unident_count_for_run(output_dir);
        g_raw_all_recovered_state_cache.refreshed_at = now;
        g_raw_all_recovered_state_cache.valid = 1;
    }

    if (!g_raw_all_recovered_state_cache.valid) {
        return 0;
    }

    if (out_recovered_files != NULL) {
        *out_recovered_files = g_raw_all_recovered_state_cache.recovered_files;
    }
    if (out_named_files != NULL) {
        *out_named_files = g_raw_all_recovered_state_cache.named_files;
    }
    if (out_unident_files != NULL) {
        *out_unident_files = g_raw_all_recovered_state_cache.unident_files;
    }

    return 1;
}

static RawAllResourceSample raw_all_sample_resource_usage(void)
{
    RawAllResourceSample sample;
    double now = scanner_now_seconds();
    long cpu_count = raw_all_online_cpu_count();

    memset(&sample, 0, sizeof(sample));
    sample.sampled_at = now;
    sample.cpu_count = cpu_count > 0 ? cpu_count : 0L;

    if (!platform_get_process_resource_usage(&sample.usage)) {
        return sample;
    }
    sample.have_usage = 1;

    if (g_raw_all_resource_rate_baseline.valid &&
        now > g_raw_all_resource_rate_baseline.sampled_at) {
        double elapsed = now - g_raw_all_resource_rate_baseline.sampled_at;
        double cpu_delta = sample.usage.has_cpu
            ? sample.usage.total_cpu_seconds -
              g_raw_all_resource_rate_baseline.cpu_total_seconds
            : 0.0;
        double io_wait_delta = sample.usage.has_io_wait
            ? sample.usage.io_wait_seconds -
              g_raw_all_resource_rate_baseline.io_wait_seconds
            : 0.0;

        if (cpu_delta < 0.0) {
            cpu_delta = 0.0;
        }
        if (io_wait_delta < 0.0) {
            io_wait_delta = 0.0;
        }
        if (elapsed > 0.0) {
            sample.cores_used = cpu_delta / elapsed;
            sample.cpu_percent = sample.cores_used * 100.0;
            sample.io_wait_percent = (io_wait_delta / elapsed) * 100.0;
        }
    }

    if (sample.usage.has_cpu) {
        g_raw_all_resource_rate_baseline.sampled_at = now;
        g_raw_all_resource_rate_baseline.cpu_total_seconds =
            sample.usage.total_cpu_seconds;
        g_raw_all_resource_rate_baseline.io_wait_seconds =
            sample.usage.has_io_wait ? sample.usage.io_wait_seconds : 0.0;
        g_raw_all_resource_rate_baseline.valid = 1;
    }

    return sample;
}

static size_t primary_metadata_effective_chunk_cap_bytes(
    const Reader *reader,
    size_t base_cap_bytes
)
{
    size_t tuned_cap_bytes = base_cap_bytes;
    size_t suggested_cap_bytes;
    const size_t max_regular_file_cap_bytes = 2U * 1024U * 1024U;

    if (base_cap_bytes == 0U || reader == NULL) {
        return base_cap_bytes;
    }

    if (!reader->source_is_regular_file || reader->chunk_size == 0U) {
        return base_cap_bytes;
    }

    suggested_cap_bytes = reader->chunk_size / 32U;
    if (suggested_cap_bytes < base_cap_bytes) {
        suggested_cap_bytes = base_cap_bytes;
    }
    if (suggested_cap_bytes > max_regular_file_cap_bytes) {
        suggested_cap_bytes = max_regular_file_cap_bytes;
    }
    if (suggested_cap_bytes > tuned_cap_bytes) {
        tuned_cap_bytes = suggested_cap_bytes;
    }

    return tuned_cap_bytes;
}

static size_t raw_all_claim_audit_effective_chunk_cap_bytes(
    const RawAllImageSafetyQueue *queue,
    const Reader *reader,
    RawAllImageSafetyKind kind,
    int discovery_pass
)
{
    size_t cap_bytes;

    if (discovery_pass) {
        cap_bytes = raw_all_size_or_default(
            queue != NULL ? queue->discovery_chunk_cap_bytes : 0U,
            RAW_ALL_CLAIM_AUDIT_DISCOVERY_CHUNK_CAP_BYTES);
    } else {
        cap_bytes = raw_all_size_or_default(
            queue != NULL ? queue->candidate_chunk_cap_bytes : 0U,
            RAW_ALL_CLAIM_AUDIT_CANDIDATE_CHUNK_CAP_BYTES);
        if (kind == RAW_ALL_IMAGE_SAFETY_MOV ||
            kind == RAW_ALL_IMAGE_SAFETY_RIFF ||
            kind == RAW_ALL_IMAGE_SAFETY_MPEG_PS ||
            kind == RAW_ALL_IMAGE_SAFETY_AAC ||
            kind == RAW_ALL_IMAGE_SAFETY_MKV) {
            if (cap_bytes <= SIZE_MAX / 2U) {
                cap_bytes *= 2U;
            } else {
                cap_bytes = SIZE_MAX;
            }
        }
    }

    if (reader != NULL &&
        reader->chunk_size > 0U &&
        cap_bytes > reader->chunk_size) {
        cap_bytes = reader->chunk_size;
    }

    return cap_bytes;
}

static int raw_all_should_scan_passive_directory_signatures_live(
    const Reader *reader,
    int live_main_scan
)
{
    size_t i30_names;

    if (!live_main_scan ||
        reader == NULL ||
        !reader->source_is_regular_file ||
        fs_backend_current_kind() != FS_BACKEND_KIND_NTFS) {
        return 1;
    }

    /*
     * On image/regular-file sources the bytes are already in memory during the
     * main scan, so checking 4 KiB boundaries for loose INDX pages is cheap
     * compared with a later reread.  This is especially important for
     * overwritten NTFS volumes where the primary MFT is damaged and the useful
     * folder evidence survives as orphaned directory-index blocks.
     */
    i30_names = fs_backend_directory_index_name_count();
    if (i30_names < RAW_ALL_REGULAR_FILE_LIVE_METADATA_I30_RICH) {
        if (!g_raw_all_passive_indx_live_scan_enabled_logged) {
            log_info(
                "Raw-all regular-file NTFS path: passive INDX signature sweeps stay enabled until the directory-name catalog is rich enough (i30=%zu target=%u)",
                i30_names,
                (unsigned int)RAW_ALL_REGULAR_FILE_LIVE_METADATA_I30_RICH
            );
            g_raw_all_passive_indx_live_scan_enabled_logged = 1;
        }
        return 1;
    }

    if (!g_raw_all_passive_indx_live_scan_suppressed_logged) {
        log_info(
            "Raw-all regular-file fast path: passive INDX signature sweeps are paused because the directory-name catalog is already rich (i30=%zu)",
            i30_names
        );
        g_raw_all_passive_indx_live_scan_suppressed_logged = 1;
    }

    return 0;
}

static int raw_all_regular_file_live_metadata_picture_established(
    FsBackendLiveStats *out_live_stats,
    size_t *out_i30_names
)
{
    FsBackendLiveStats live_stats = {0};
    size_t i30_names = 0U;

    if (out_live_stats != NULL) {
        memset(out_live_stats, 0, sizeof(*out_live_stats));
    }
    if (out_i30_names != NULL) {
        *out_i30_names = 0U;
    }

    if (fs_backend_current_kind() != FS_BACKEND_KIND_NTFS ||
        !primary_metadata_runlist_is_trustworthy_for_live_observation() ||
        fs_backend_primary_run_count() == 0U) {
        return 0;
    }

    fs_backend_get_live_queue_stats(&live_stats);
    i30_names = fs_backend_directory_index_name_count();

    if (out_live_stats != NULL) {
        *out_live_stats = live_stats;
    }
    if (out_i30_names != NULL) {
        *out_i30_names = i30_names;
    }

    return live_stats.record_index_count >=
               RAW_ALL_REGULAR_FILE_LIVE_METADATA_RECORD_INDEX_READY ||
           live_stats.range_index_count >=
               RAW_ALL_REGULAR_FILE_LIVE_METADATA_RANGE_INDEX_READY ||
           i30_names >= RAW_ALL_REGULAR_FILE_LIVE_METADATA_I30_READY;
}

static int raw_all_should_run_live_metadata_now(
    const Reader *reader,
    uint64_t buffer_base_offset,
    uint64_t *io_next_offset,
    int *io_logged_fast_path
)
{
    FsBackendLiveStats live_stats = {0};
    size_t i30_names = 0U;
    uint64_t stride_bytes = RAW_ALL_REGULAR_FILE_LIVE_METADATA_STRIDE_BYTES;

    if (reader == NULL ||
        io_next_offset == NULL ||
        !reader->source_is_regular_file ||
        fs_backend_current_kind() != FS_BACKEND_KIND_NTFS) {
        return 1;
    }

    if (!raw_all_regular_file_live_metadata_picture_established(
            &live_stats,
            &i30_names)) {
        return 1;
    }

    if (live_stats.record_index_count >=
            RAW_ALL_REGULAR_FILE_LIVE_METADATA_RECORD_INDEX_RICH ||
        live_stats.range_index_count >=
            RAW_ALL_REGULAR_FILE_LIVE_METADATA_RANGE_INDEX_RICH ||
        i30_names >= RAW_ALL_REGULAR_FILE_LIVE_METADATA_I30_RICH) {
        stride_bytes = RAW_ALL_REGULAR_FILE_LIVE_METADATA_RICH_STRIDE_BYTES;
    }

    if (io_logged_fast_path != NULL && !*io_logged_fast_path) {
        log_info(
            "Raw-all regular-file fast path: the NTFS metadata picture is already established (records=%zu ranges=%zu i30=%zu), so main-thread live metadata observation will now run about once per %.0f MiB while the background helper and targeted $I30 absorption keep filling state",
            live_stats.record_index_count,
            live_stats.range_index_count,
            i30_names,
            (double)stride_bytes / (1024.0 * 1024.0)
        );
        *io_logged_fast_path = 1;
    }

    if (*io_next_offset == 0ULL || buffer_base_offset >= *io_next_offset) {
        if (UINT64_MAX - buffer_base_offset < stride_bytes) {
            *io_next_offset = UINT64_MAX;
        } else {
            *io_next_offset = buffer_base_offset + stride_bytes;
        }
        return 1;
    }

    return 0;
}

static void log_all_live_stats_snapshot(void)
{
    FormatPipelineLiveStats pipeline_stats;
    FsBackendLiveStats metadata_stats;
    uint64_t exact_mft_attempts_delta;
    uint64_t exact_mft_recovered_delta;
    uint64_t exact_attempts_delta;
    uint64_t exact_recovered_delta;
    uint64_t renamed_delta;
    uint64_t repaired_delta;

    format_pipeline_get_live_stats(&pipeline_stats);
    fs_backend_get_live_queue_stats(&metadata_stats);
    update_working_queue_from_metadata_stats();

    exact_mft_attempts_delta =
        pipeline_stats.metadata_exact_mft_attempts -
        g_format_pipeline_live_stats_last_logged.metadata_exact_mft_attempts;
    exact_mft_recovered_delta =
        pipeline_stats.metadata_exact_mft_recovered -
        g_format_pipeline_live_stats_last_logged.metadata_exact_mft_recovered;
    exact_attempts_delta =
        pipeline_stats.metadata_exact_jpeg_attempts -
        g_format_pipeline_live_stats_last_logged.metadata_exact_jpeg_attempts;
    exact_recovered_delta =
        pipeline_stats.metadata_exact_jpeg_recovered -
        g_format_pipeline_live_stats_last_logged.metadata_exact_jpeg_recovered;
    renamed_delta =
        metadata_stats.renamed_outputs -
        g_metadata_live_stats_last_logged.renamed_outputs;
    repaired_delta =
        metadata_stats.repaired_outputs -
        g_metadata_live_stats_last_logged.repaired_outputs;

    if (exact_mft_attempts_delta > 0U ||
        exact_mft_recovered_delta > 0U ||
        exact_attempts_delta > 0U ||
        exact_recovered_delta > 0U ||
        renamed_delta > 0U ||
        repaired_delta > 0U) {
        log_verbose(
            "All live stats: metadata_exact_mft=%llu/%llu metadata_jpeg=%llu/%llu named=+%llu repaired=+%llu totals(recovered=%llu named=%llu unident=%llu repair_queue=%llu repairable_jpg=%llu repaired=%llu idx=%zu/%zu stall=%llus)",
            (unsigned long long)exact_mft_recovered_delta,
            (unsigned long long)exact_mft_attempts_delta,
            (unsigned long long)exact_recovered_delta,
            (unsigned long long)exact_attempts_delta,
            (unsigned long long)renamed_delta,
            (unsigned long long)repaired_delta,
            (unsigned long long)metadata_stats.recovered_outputs_current,
            (unsigned long long)metadata_stats.named_outputs_current,
            (unsigned long long)metadata_stats.unident_outputs_current,
            (unsigned long long)metadata_stats.repair_queue_events,
            (unsigned long long)metadata_stats.repair_pending_outputs,
            (unsigned long long)metadata_stats.repaired_outputs,
            metadata_stats.record_index_count,
            metadata_stats.range_index_count,
            metadata_stats.scan_stalled_seconds
        );
    }

    g_format_pipeline_live_stats_last_logged = pipeline_stats;
    g_metadata_live_stats_last_logged = metadata_stats;
    log_jpeg_stats_snapshot();
    log_png_stats_snapshot();
}

static void SCANNER_MAYBE_UNUSED log_metadata_observe_stats_snapshot(void)
{
    MetadataObserveStats delta;
    FsBackendProcessStats process_stats;
    FsBackendProcessStats process_delta;
    double mib_per_sec = 0.0;
    double avg_ms_per_pass = 0.0;
    double parse_ms = 0.0;
    double index_ms = 0.0;
    double build_ms = 0.0;
    double store_ms = 0.0;

    memset(&delta, 0, sizeof(delta));
    memset(&process_delta, 0, sizeof(process_delta));
    delta.passes =
        g_metadata_observe_stats.passes - g_metadata_observe_stats_last_logged.passes;
    delta.records_observed =
        g_metadata_observe_stats.records_observed - g_metadata_observe_stats_last_logged.records_observed;
    delta.bytes_scanned =
        g_metadata_observe_stats.bytes_scanned - g_metadata_observe_stats_last_logged.bytes_scanned;
    delta.seconds_total =
        g_metadata_observe_stats.seconds_total - g_metadata_observe_stats_last_logged.seconds_total;

    fs_backend_get_process_stats(&process_stats);
    process_delta.parsed_metadata_units =
        process_stats.parsed_metadata_units - g_metadata_process_stats_last_logged.parsed_metadata_units;
    process_delta.indexed_metadata_units =
        process_stats.indexed_metadata_units - g_metadata_process_stats_last_logged.indexed_metadata_units;
    process_delta.built_entries =
        process_stats.built_entries - g_metadata_process_stats_last_logged.built_entries;
    process_delta.stored_entries =
        process_stats.stored_entries - g_metadata_process_stats_last_logged.stored_entries;
    process_delta.seconds_parse =
        process_stats.seconds_parse - g_metadata_process_stats_last_logged.seconds_parse;
    process_delta.seconds_index =
        process_stats.seconds_index - g_metadata_process_stats_last_logged.seconds_index;
    process_delta.seconds_build =
        process_stats.seconds_build - g_metadata_process_stats_last_logged.seconds_build;
    process_delta.seconds_store =
        process_stats.seconds_store - g_metadata_process_stats_last_logged.seconds_store;

    if (delta.seconds_total > 0.0) {
        mib_per_sec =
            ((double)delta.bytes_scanned / (1024.0 * 1024.0)) /
            delta.seconds_total;
    }
    if (delta.passes > 0) {
        avg_ms_per_pass =
            (delta.seconds_total * 1000.0) /
            (double)delta.passes;
    }
    if (process_delta.parsed_metadata_units > 0) {
        parse_ms =
            (process_delta.seconds_parse * 1000.0) /
            (double)process_delta.parsed_metadata_units;
        index_ms =
            (process_delta.seconds_index * 1000.0) /
            (double)process_delta.parsed_metadata_units;
        build_ms =
            (process_delta.seconds_build * 1000.0) /
            (double)process_delta.parsed_metadata_units;
        store_ms =
            (process_delta.seconds_store * 1000.0) /
            (double)process_delta.parsed_metadata_units;
    }

    log_verbose(
        "Metadata observe stats: passes=%llu records=%llu scanned=%.1f MiB t=%.2fs avg=%.2fms rate=%.1f MiB/s parse=%.3fms index=%.3fms build=%.3fms store=%.3fms total_records=%llu total_scanned=%.1f MiB",
        (unsigned long long)delta.passes,
        (unsigned long long)delta.records_observed,
        (double)delta.bytes_scanned / (1024.0 * 1024.0),
        delta.seconds_total,
        avg_ms_per_pass,
        mib_per_sec,
        parse_ms,
        index_ms,
        build_ms,
        store_ms,
        (unsigned long long)g_metadata_observe_stats.records_observed,
        (double)g_metadata_observe_stats.bytes_scanned / (1024.0 * 1024.0)
    );

    g_metadata_observe_stats_last_logged = g_metadata_observe_stats;
    g_metadata_process_stats_last_logged = process_stats;
}

static void SCANNER_MAYBE_UNUSED log_jpeg_stats_snapshot(void)
{
    CarverJpegStats stats;
    CarverJpegLastExtendedFailure last_failure;
    double avg_ms_per_candidate = 0.0;
    double avg_ms_per_eoi = 0.0;
    double avg_ms_per_extended_attempt = 0.0;
    uint64_t ext_attempts_delta;
    uint64_t ext_recovered_delta;
    uint64_t ext_probe_plausible_delta;
    uint64_t ext_probe_recovered_delta;
    uint64_t ext_failed_no_eoi_delta;
    uint64_t ext_failed_small_delta;
    uint64_t ext_failed_write_delta;
    uint64_t ext_failed_other_delta;
    double ext_seconds_delta;

    carver_jpeg_get_stats(&stats);
    carver_jpeg_get_last_extended_failure(&last_failure);
    ext_attempts_delta =
        stats.extended_window_attempts -
        g_jpeg_stats_last_logged.extended_window_attempts;
    ext_recovered_delta =
        stats.extended_window_recovered -
        g_jpeg_stats_last_logged.extended_window_recovered;
    ext_probe_plausible_delta =
        stats.extended_window_probe_plausible -
        g_jpeg_stats_last_logged.extended_window_probe_plausible;
    ext_probe_recovered_delta =
        stats.extended_window_probe_recovered -
        g_jpeg_stats_last_logged.extended_window_probe_recovered;
    ext_seconds_delta =
        stats.seconds_extended_window -
        g_jpeg_stats_last_logged.seconds_extended_window;
    ext_failed_no_eoi_delta =
        stats.extended_window_failed_no_eoi -
        g_jpeg_stats_last_logged.extended_window_failed_no_eoi;
    ext_failed_small_delta =
        stats.extended_window_failed_small_image -
        g_jpeg_stats_last_logged.extended_window_failed_small_image;
    ext_failed_write_delta =
        stats.extended_window_failed_write -
        g_jpeg_stats_last_logged.extended_window_failed_write;
    ext_failed_other_delta =
        stats.extended_window_failed_other -
        g_jpeg_stats_last_logged.extended_window_failed_other;

    if (stats.candidates_total > 0) {
        avg_ms_per_candidate =
            (stats.seconds_total_analysis * 1000.0) /
            (double)stats.candidates_total;
    }
    if (stats.eoi_found > 0) {
        avg_ms_per_eoi =
            (stats.seconds_eoi * 1000.0) /
            (double)stats.eoi_found;
    }
    if (stats.extended_window_attempts > 0) {
        avg_ms_per_extended_attempt =
            (stats.seconds_extended_window * 1000.0) /
            (double)stats.extended_window_attempts;
    }

    if (ext_attempts_delta > 0U) {
        double ext_avg_ms =
            ext_attempts_delta > 0U
                ? (ext_seconds_delta * 1000.0) / (double)ext_attempts_delta
                : 0.0;

        log_info(
            "JPEG block-bridge: recovered=%llu/%llu probe=%llu/%llu fail(noeoi=%llu small=%llu write=%llu other=%llu) dt=%.2fs avg=%.2fms total=%llu/%llu",
            (unsigned long long)ext_recovered_delta,
            (unsigned long long)ext_attempts_delta,
            (unsigned long long)ext_probe_recovered_delta,
            (unsigned long long)ext_probe_plausible_delta,
            (unsigned long long)ext_failed_no_eoi_delta,
            (unsigned long long)ext_failed_small_delta,
            (unsigned long long)ext_failed_write_delta,
            (unsigned long long)ext_failed_other_delta,
            ext_seconds_delta,
            ext_avg_ms,
            (unsigned long long)stats.extended_window_recovered,
            (unsigned long long)stats.extended_window_attempts
        );

        if (last_failure.active &&
            (g_jpeg_last_extended_failure_logged.active == 0 ||
             last_failure.absolute_offset != g_jpeg_last_extended_failure_logged.absolute_offset ||
             last_failure.total_bytes != g_jpeg_last_extended_failure_logged.total_bytes ||
             last_failure.error_offset != g_jpeg_last_extended_failure_logged.error_offset ||
             last_failure.probe_status != g_jpeg_last_extended_failure_logged.probe_status)) {
            log_info(
                "JPEG block-bridge detail: abs=%llu status=%d break=%s marker=0x%02X first=0x%02X score=%d gates(complete=%d recoverable=%d has_eoi=%d) bytes=%llu est=%llu err=%llu eoi=%llu entropy=%llu dims=%ux%u flags(exif=%d jfif=%d sof=%d sos=%d eoi=%d prefix=%d/%d/%d restart=%d entropy_bad=%d)",
                (unsigned long long)last_failure.absolute_offset,
                last_failure.probe_status,
                carver_jpeg_breakpoint_kind_name(last_failure.breakpoint_kind),
                last_failure.breakpoint_marker & 0xFF,
                last_failure.first_marker_after_soi & 0xFF,
                last_failure.analysis_score,
                last_failure.gate_complete,
                last_failure.gate_recoverable_complete,
                last_failure.gate_has_eoi,
                (unsigned long long)last_failure.total_bytes,
                (unsigned long long)last_failure.estimated_size,
                (unsigned long long)last_failure.error_offset,
                (unsigned long long)last_failure.eoi_offset,
                (unsigned long long)last_failure.entropy_data_bytes,
                (unsigned int)last_failure.width,
                (unsigned int)last_failure.height,
                last_failure.saw_exif,
                last_failure.saw_jfif,
                last_failure.saw_sof,
                last_failure.saw_sos,
                last_failure.saw_eoi,
                last_failure.saw_prefix_support_segment,
                last_failure.saw_prefix_app_segment,
                last_failure.saw_prefix_table_segment,
                last_failure.saw_restart_marker,
                last_failure.saw_entropy_marker_anomaly
            );
            g_jpeg_last_extended_failure_logged = last_failure;
        }
    }

    log_verbose(
        "JPEG stats: cand=%llu weak=%llu low=%llu nohdr=%llu noeoi=%llu small=%llu layout=%llu/%llu dimq=%llu dimf=%llu eoi=%llu recov=%llu skipmeta=%llu ext=%llu/%llu claim=%llu probe=%llu/%llu fail(noeoi=%llu small=%llu write=%llu other=%llu) extt=%.2fs extavg=%.2fms t=%.2fs avg=%.2fms eoiavg=%.2fms",
        (unsigned long long)stats.candidates_total,
        (unsigned long long)stats.rejected_weak_early,
        (unsigned long long)stats.rejected_low_score,
        (unsigned long long)stats.rejected_no_header,
        (unsigned long long)stats.rejected_missing_eoi,
        (unsigned long long)stats.rejected_small_image,
        (unsigned long long)stats.marker_layout_successes,
        (unsigned long long)stats.marker_layout_checks,
        (unsigned long long)stats.early_dimensions_ok,
        (unsigned long long)stats.full_dimensions_ok,
        (unsigned long long)stats.eoi_found,
        (unsigned long long)stats.recovered_files,
        (unsigned long long)stats.skipped_by_mft_context,
        (unsigned long long)stats.extended_window_recovered,
        (unsigned long long)stats.extended_window_attempts,
        (unsigned long long)stats.extended_window_claimed_dominant_span,
        (unsigned long long)stats.extended_window_probe_recovered,
        (unsigned long long)stats.extended_window_probe_plausible,
        (unsigned long long)stats.extended_window_failed_no_eoi,
        (unsigned long long)stats.extended_window_failed_small_image,
        (unsigned long long)stats.extended_window_failed_write,
        (unsigned long long)stats.extended_window_failed_other,
        stats.seconds_extended_window,
        avg_ms_per_extended_attempt,
        stats.seconds_total_analysis,
        avg_ms_per_candidate,
        avg_ms_per_eoi
    );
    g_jpeg_stats_last_logged = stats;
}

static void SCANNER_MAYBE_UNUSED log_png_stats_snapshot(void)
{
    CarverPngStats stats;
    double avg_ms_per_candidate = 0.0;
    double avg_ms_per_extended_attempt = 0.0;
    uint64_t ext_attempts_delta;
    uint64_t ext_recovered_delta;
    uint64_t ext_failed_no_iend_delta;
    uint64_t ext_failed_small_delta;
    uint64_t ext_failed_write_delta;
    uint64_t ext_failed_other_delta;
    double ext_seconds_delta;

    carver_png_get_stats(&stats);
    ext_attempts_delta =
        stats.extended_window_attempts -
        g_png_stats_last_logged.extended_window_attempts;
    ext_recovered_delta =
        stats.extended_window_recovered -
        g_png_stats_last_logged.extended_window_recovered;
    ext_seconds_delta =
        stats.seconds_extended_window -
        g_png_stats_last_logged.seconds_extended_window;
    ext_failed_no_iend_delta =
        stats.extended_window_failed_no_iend -
        g_png_stats_last_logged.extended_window_failed_no_iend;
    ext_failed_small_delta =
        stats.extended_window_failed_small_image -
        g_png_stats_last_logged.extended_window_failed_small_image;
    ext_failed_write_delta =
        stats.extended_window_failed_write -
        g_png_stats_last_logged.extended_window_failed_write;
    ext_failed_other_delta =
        stats.extended_window_failed_other -
        g_png_stats_last_logged.extended_window_failed_other;

    if (stats.candidates_total > 0) {
        avg_ms_per_candidate =
            (stats.seconds_total_analysis * 1000.0) /
            (double)stats.candidates_total;
    }
    if (stats.extended_window_attempts > 0) {
        avg_ms_per_extended_attempt =
            (stats.seconds_extended_window * 1000.0) /
            (double)stats.extended_window_attempts;
    }

    if (ext_attempts_delta > 0U) {
        double ext_avg_ms =
            ext_attempts_delta > 0U
                ? (ext_seconds_delta * 1000.0) / (double)ext_attempts_delta
                : 0.0;

        log_info(
            "PNG block-bridge: recovered=%llu/%llu fail(noiend=%llu small=%llu write=%llu other=%llu) capped=%llu dt=%.2fs avg=%.2fms total=%llu/%llu",
            (unsigned long long)ext_recovered_delta,
            (unsigned long long)ext_attempts_delta,
            (unsigned long long)ext_failed_no_iend_delta,
            (unsigned long long)ext_failed_small_delta,
            (unsigned long long)ext_failed_write_delta,
            (unsigned long long)ext_failed_other_delta,
            (unsigned long long)(
                stats.extended_window_region_capped -
                g_png_stats_last_logged.extended_window_region_capped),
            ext_seconds_delta,
            ext_avg_ms,
            (unsigned long long)stats.extended_window_recovered,
            (unsigned long long)stats.extended_window_attempts
        );
    }

    log_verbose(
        "PNG stats: cand=%llu recov=%llu small=%llu skipmeta=%llu ext=%llu/%llu fail(noiend=%llu small=%llu write=%llu other=%llu) capped=%llu extt=%.2fs extavg=%.2fms t=%.2fs avg=%.2fms",
        (unsigned long long)stats.candidates_total,
        (unsigned long long)stats.recovered_files,
        (unsigned long long)stats.skipped_small_image,
        (unsigned long long)stats.skipped_by_mft_context,
        (unsigned long long)stats.extended_window_recovered,
        (unsigned long long)stats.extended_window_attempts,
        (unsigned long long)stats.extended_window_failed_no_iend,
        (unsigned long long)stats.extended_window_failed_small_image,
        (unsigned long long)stats.extended_window_failed_write,
        (unsigned long long)stats.extended_window_failed_other,
        (unsigned long long)stats.extended_window_region_capped,
        stats.seconds_extended_window,
        avg_ms_per_extended_attempt,
        stats.seconds_total_analysis,
        avg_ms_per_candidate
    );
    g_png_stats_last_logged = stats;
}

static const MagicEntry *match_magic_in_bucket_fast(
    const MagicTable *table,
    const MagicIndexBucket *bucket,
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
)
{
    uint32_t key4 = 0;
    int have_key4 = 0;
    size_t i;

    if (table == NULL ||
        bucket == NULL ||
        buffer == NULL ||
        offset + 1 >= buffer_length) {
        return NULL;
    }
    if (bucket->count == 0 || bucket->entry_indexes == NULL) {
        return NULL;
    }

    if (offset + 3 < buffer_length && bucket->prefix4_count > 0) {
        key4 = ((uint32_t)buffer[offset] << 24) |
               ((uint32_t)buffer[offset + 1] << 16) |
               ((uint32_t)buffer[offset + 2] << 8) |
               (uint32_t)buffer[offset + 3];
        have_key4 = 1;

        if (!bucket->has_short_index_pattern) {
            size_t prefix_index;
            int found_prefix4 = 0;

            for (prefix_index = 0; prefix_index < bucket->prefix4_count; prefix_index++) {
                if (bucket->prefix4_values[prefix_index] == key4) {
                    found_prefix4 = 1;
                    break;
                }
            }

            if (!found_prefix4) {
                return NULL;
            }
        }
    }

    for (i = 0; i < bucket->count; i++) {
        const MagicEntry *entry = &table->entries[bucket->entry_indexes[i]];
        const uint8_t *start_pattern =
            entry->start_pattern != NULL ? entry->start_pattern : entry->pattern;
        size_t start_pattern_length =
            entry->start_pattern != NULL ? entry->start_pattern_length : entry->pattern_length;
        const uint8_t *index_pattern;
        size_t index_pattern_length;
        size_t pattern_offset;

        if (entry->pattern == NULL || entry->pattern_length == 0) {
            continue;
        }
        if (start_pattern == NULL || start_pattern_length == 0) {
            continue;
        }

        index_pattern = entry->pattern;
        index_pattern_length = 0;
        if (entry->pattern != NULL &&
            entry->pattern_length > 0 &&
            entry->pattern_offset == 0) {
            index_pattern = entry->pattern;
            index_pattern_length = entry->pattern_length;
        } else if (entry->start_pattern != NULL && entry->start_pattern_length > 0) {
            index_pattern = entry->start_pattern;
            index_pattern_length = entry->start_pattern_length;
        }

        if (index_pattern != NULL && index_pattern_length >= 4) {
            uint32_t entry_key4;

            if (!have_key4) {
                continue;
            }

            entry_key4 = ((uint32_t)index_pattern[0] << 24) |
                         ((uint32_t)index_pattern[1] << 16) |
                         ((uint32_t)index_pattern[2] << 8) |
                         (uint32_t)index_pattern[3];
            if (entry_key4 != key4) {
                continue;
            }
        }

        if (!blob_start_matches(
                buffer + offset,
                buffer_length - offset,
                start_pattern,
                start_pattern_length)) {
            continue;
        }

        pattern_offset = offset + entry->pattern_offset;
        if (pattern_offset < offset ||
            pattern_offset + entry->pattern_length > buffer_length) {
            continue;
        }

        if (memcmp(
                buffer + pattern_offset,
                entry->pattern,
                entry->pattern_length) == 0) {
            return entry;
        }
    }

    return NULL;
}

/* ========================= MAIN ========================= */

int scanner_run(
    Reader *reader,
    const MagicTable *table,
    const AppConfig *config,
    const RecoveryOrder *active_order
)
{
#if !TEMP_TREE_ONLY_MODE
    size_t next_scan_absolute_offset = 0;
    size_t last_recovery_mode_entry_count = fs_backend_entry_count();
#endif

    if (reader == NULL) {
        return 0;
    }

#if TEMP_TREE_ONLY_MODE
    (void)table;
    (void)config;
    (void)active_order;
#endif

    if (reader_read_next(reader) == 0) {
        return 1;
    }
    log_set_working_activity("scanning metadata catalog");

    for (;;) {
        size_t buffer_base_offset =
            reader->total_bytes_read - reader->bytes_in_buffer;

        log_set_working_activity("scanning metadata records");
        (void)observe_metadata_records_timed(
            reader->buffer,
            reader->bytes_in_buffer,
            (uint64_t)buffer_base_offset,
            0
        );
        observe_directory_indexes_for_current_buffer(
            reader,
            reader->buffer,
            reader->bytes_in_buffer,
            (uint64_t)buffer_base_offset,
            "metadata scan",
            0
        );

#if TEMP_TREE_ONLY_MODE
        /*
         * Temporary tree-only mode:
         * keep metadata parsing active, but skip signature matching and
         * file carving until the directory-tree issues are resolved.
         */
#else
    (void)table;

    if (fs_backend_entry_count() != last_recovery_mode_entry_count) {
        log_set_working_activity("naming/moving recovered files");
        fs_backend_refresh_recovery_state(&last_recovery_mode_entry_count);
    }

    {
            FsViewEntry *targets = NULL;
            size_t target_count;
            size_t target_index;
            long long scan_start =
                (long long)(buffer_base_offset + reader->overlap_bytes);
            long long scan_end =
                (long long)(buffer_base_offset + reader->bytes_in_buffer);
            int restart_with_current_buffer = 0;

            if (!format_pipeline_allows_metadata_stream_recovery(config, active_order)) {
                target_count = 0;
            } else {
                target_count = fs_backend_collect_view_entries_in_range(
                    scan_start,
                    scan_end,
                    &targets
                );
            }

            for (target_index = 0; target_index < target_count; target_index++) {
                FsViewEntry *view = &targets[target_index];
                size_t i;
                size_t absolute_offset;

                if (view->abs_offset < 0 ||
                    (uint64_t)view->abs_offset < next_scan_absolute_offset ||
                    view->abs_offset < (long long)buffer_base_offset ||
                    view->abs_offset >= scan_end) {
                    continue;
                }

                absolute_offset = (size_t)view->abs_offset;
                i = absolute_offset - buffer_base_offset;

                if (i < reader->overlap_bytes) {
                    continue;
                }

                {
                    size_t reader_bytes_before = reader->total_bytes_read;
                    size_t buffer_bytes_before = reader->bytes_in_buffer;

                    log_set_working_activity("recovering metadata-mapped file");
                    if (format_pipeline_recover_metadata_target(
                            reader,
                            config,
                            active_order,
                            i,
                            absolute_offset,
                            view)) {
                        next_scan_absolute_offset =
                            absolute_offset + (size_t)view->data_size;
                        restart_with_current_buffer = 1;
                        break;
                    }

                    if (reader->total_bytes_read != reader_bytes_before ||
                        reader->bytes_in_buffer != buffer_bytes_before) {
                        next_scan_absolute_offset =
                            reader->total_bytes_read - reader->bytes_in_buffer;
                        restart_with_current_buffer = 1;
                        break;
                    }
                    log_set_working_activity("scanning metadata targets");
                }
            }

            free(targets);

            if (restart_with_current_buffer) {
                continue;
            }
        }
#endif

        if (reader_read_next(reader) == 0) {
            break;
        }
        log_set_working_activity("scanning metadata catalog");
    }

    return 1;
}

typedef struct {
    uint64_t scope_start;
    uint64_t scope_end;
} RawAllSequentialObserverContext;

static void raw_all_observe_reader_chunk(
    uint64_t absolute_offset,
    const uint8_t *bytes,
    size_t byte_count,
    void *context)
{
    const RawAllSequentialObserverContext *scope =
        (const RawAllSequentialObserverContext *)context;
    uint64_t chunk_end;
    uint64_t deliver_start = absolute_offset;
    uint64_t deliver_end;

    if (bytes == NULL || byte_count == 0U ||
        (uint64_t)byte_count > UINT64_MAX - absolute_offset) {
        return;
    }
    chunk_end = absolute_offset + (uint64_t)byte_count;
    deliver_end = chunk_end;
    if (scope != NULL) {
        if (deliver_end <= scope->scope_start ||
            deliver_start >= scope->scope_end) {
            return;
        }
        if (deliver_start < scope->scope_start) {
            deliver_start = scope->scope_start;
        }
        if (deliver_end > scope->scope_end) {
            deliver_end = scope->scope_end;
        }
    }
    if (deliver_end > deliver_start) {
        fs_backend_observe_sequential_bytes(
            deliver_start,
            bytes + (size_t)(deliver_start - absolute_offset),
            (size_t)(deliver_end - deliver_start)
        );
    }
}

int scanner_run_raw_all(
    Reader *reader,
    const MagicTable *table,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    int *out_completed_full_scan
)
{
#if !TEMP_TREE_ONLY_MODE
    size_t last_handled_offset = (size_t)-1;
    size_t last_logged_promoted_large_exif_offset = (size_t)-1;
    size_t last_state_write_offset = 0;
    size_t last_progress_update_offset = 0;
    uint64_t current_scan_offset = 0U;
    uint64_t primary_pass_end_offset = 0U;
    int async_outputs_started = 0;
    RawAllSequentialObserverContext sequential_observer = {0};
    int background_worker_failed = 0;
    uint64_t scan_limit = 0;
    int limit_reached = 0;
    int skip_live_metadata_observation = 0;
    int regular_file_live_metadata_fast_path_logged = 0;
    double last_activity_write_at = 0.0;
    uint64_t next_regular_file_live_metadata_offset = 0ULL;
    FormatPipelineDispatchContext dispatch_context;
    RawAllDeferredJpegStarts deferred_jpeg_starts = {0};
    RawAllImageSafetyQueue image_safety_queue = {0};
    int jpeg_direct_debug = raw_all_debug_jpeg_direct_enabled();
    uint64_t jpeg_direct_debug_lines = 0U;

    if (reader == NULL || table == NULL) {
        return 0;
    }
    if (out_completed_full_scan != NULL) {
        *out_completed_full_scan = 0;
    }

    async_outputs_started = carver_output_async_start();

    if (config != NULL) {
        last_state_write_offset = (size_t)config->resume_offset;
        last_progress_update_offset = (size_t)config->resume_offset;
        current_scan_offset = (uint64_t)config->resume_offset;
        scan_limit = config->mft_limit > 0ULL
            ? raw_all_effective_scan_end_offset(reader, config)
            : 0ULL;
        skip_live_metadata_observation = config->skip_mft_observation ? 1 : 0;
    }

    carver_jpeg_reset_stats();
    carver_png_reset_stats();
    format_pipeline_reset_live_stats();
    format_pipeline_prepare_dispatch_context(&dispatch_context, config, active_order);
    reset_metadata_observe_stats();
    memset(&g_raw_all_metadata_candidate_stats, 0,
           sizeof(g_raw_all_metadata_candidate_stats));
    raw_all_load_candidate_stats_state(config);
    raw_all_image_safety_queue_configure(&image_safety_queue, reader);
    raw_all_reset_recovered_state_cache();
    raw_all_trace_offsets_reset_progress();

    sequential_observer.scope_end = config != NULL
        ? raw_all_effective_scan_end_offset(reader, config)
        : reader_get_source_size(reader);
    sequential_observer.scope_start =
        config != NULL && config->manual_start_explicit &&
        config->manual_start_offset < sequential_observer.scope_end
            ? (uint64_t)config->manual_start_offset
            : 0ULL;
    if (sequential_observer.scope_end <= sequential_observer.scope_start) {
        sequential_observer.scope_end = reader_get_source_size(reader);
    }
    reader_set_sequential_chunk_observer(
        reader,
        raw_all_observe_reader_chunk,
        &sequential_observer
    );
    if (scan_limit > 0U && reader->progress_bytes_read >= scan_limit) {
        limit_reached = 1;
        current_scan_offset = scan_limit;
        goto raw_all_primary_scan_done;
    }
    if (raw_all_reader_read_next_limited(reader, scan_limit) == 0) {
        reader_set_sequential_chunk_observer(reader, NULL, NULL);
        if (async_outputs_started) {
            carver_output_async_stop();
        }
        if (app_source_reconnect_requested()) {
            if (out_completed_full_scan != NULL) {
                *out_completed_full_scan = 0;
            }
            return 0;
        }
        if (out_completed_full_scan != NULL) {
            *out_completed_full_scan = 1;
        }
        /* App-level durable coverage decides whether this was truly complete.
         * An endpoint alone is not enough after supervised stall retries. */
        fs_backend_finish_sequential_measurement(0);
        return 1;
    }
    raw_all_set_working_progress_limited(
        reader,
        config,
        (uint64_t)(reader->total_bytes_read - reader->bytes_in_buffer));
    set_raw_all_signature_scan_activity(skip_live_metadata_observation);
    raw_all_trace_offsets_note_buffer(
        reader,
        reader->total_bytes_read - reader->bytes_in_buffer
    );
    maybe_write_raw_all_activity_state(
        config,
        reader,
        current_scan_offset,
        skip_live_metadata_observation,
        &last_activity_write_at,
        1
    );
    if (!raw_all_background_worker_is_healthy()) {
        background_worker_failed = 1;
    }

    for (; !background_worker_failed;) {
        size_t i = 0;
        size_t buffer_base_offset =
            reader->total_bytes_read - reader->bytes_in_buffer;
        size_t candidate_limit =
            reader->bytes_in_buffer > 0 ? reader->bytes_in_buffer - 1 : 0;
        const uint8_t *prefix_2byte =
            table->prefix_2byte_present != NULL
                ? table->prefix_2byte_present
                : NULL;
        const MagicIndexBucket *index_2byte =
            table->index_2byte != NULL
                ? table->index_2byte
                : NULL;
        int direct_jpeg_scan_enabled =
            format_pipeline_dispatch_context_allows_jpeg(&dispatch_context);
        if (jpeg_direct_debug && jpeg_direct_debug_lines < 32U) {
            size_t first_soi = 0U;
            int found_soi = raw_all_find_first_jpeg_soi_in_buffer(
                reader->buffer,
                reader->bytes_in_buffer,
                &first_soi);
            log_info(
                "JPEG direct debug buffer: base=%zu bytes=%zu direct_enabled=%d first_soi=%s%zu",
                buffer_base_offset,
                reader->bytes_in_buffer,
                direct_jpeg_scan_enabled ? 1 : 0,
                found_soi ? "" : "none@",
                found_soi ? (buffer_base_offset + first_soi) : 0U);
            jpeg_direct_debug_lines++;
        }

        if (buffer_base_offset > last_progress_update_offset) {
            raw_all_set_working_progress_limited(
                reader,
                config,
                (uint64_t)buffer_base_offset);
            last_progress_update_offset = buffer_base_offset;
        }
        current_scan_offset = (uint64_t)buffer_base_offset;
        raw_all_trace_offsets_note_buffer(reader, buffer_base_offset);

        if (!raw_all_background_worker_is_healthy()) {
            background_worker_failed = 1;
            break;
        }

        if (!skip_live_metadata_observation) {
            int run_live_metadata_now = raw_all_should_run_live_metadata_now(
                reader,
                (uint64_t)buffer_base_offset,
                &next_regular_file_live_metadata_offset,
                &regular_file_live_metadata_fast_path_logged
            );
            log_set_working_activity("mapping live filesystem metadata");
            if (run_live_metadata_now) {
                (void)observe_metadata_records_for_raw_all(
                    reader->buffer,
                    reader->bytes_in_buffer,
                    (uint64_t)buffer_base_offset
                );
            }
            observe_directory_indexes_for_current_buffer(
                reader,
                reader->buffer,
                reader->bytes_in_buffer,
                (uint64_t)buffer_base_offset,
                "raw-all live buffer",
                1
            );
        }
        if (fs_backend_has_metadata_context_for_raw_scan() &&
            !fs_backend_supports_live_metadata_observation()) {
            fs_backend_reconcile_recovered_outputs_live();
        }
        update_working_queue_from_metadata_stats();
        maybe_write_raw_all_activity_state(
            config,
            reader,
            current_scan_offset,
            skip_live_metadata_observation,
            &last_activity_write_at,
            0
        );
        set_raw_all_signature_scan_activity(skip_live_metadata_observation);

        if (scan_limit > 0U &&
            (uint64_t)buffer_base_offset >= scan_limit) {
            limit_reached = 1;
            break;
        }

        if (raw_all_should_stop()) {
            break;
        }

        while (i < candidate_limit && !raw_all_should_stop()) {
            const MagicEntry *match;
            size_t start_offset;
            size_t absolute_offset;
            unsigned int key;
            const MagicIndexBucket *bucket;
            size_t promoted_exif_span = 0U;
            MetadataIndexCandidateContext metadata_candidate_context = {0};
            int metadata_candidate_context_loaded = 0;
            int metadata_candidate_context_counted = 0;

            current_scan_offset = (uint64_t)(buffer_base_offset + i);

            if (prefix_2byte != NULL) {
                while (i + 8U <= candidate_limit) {
                    if (direct_jpeg_scan_enabled &&
                        (raw_all_buffer_has_jpeg_soi(reader->buffer, reader->bytes_in_buffer, i) ||
                         raw_all_buffer_has_jpeg_soi(reader->buffer, reader->bytes_in_buffer, i + 1U) ||
                         raw_all_buffer_has_jpeg_soi(reader->buffer, reader->bytes_in_buffer, i + 2U) ||
                         raw_all_buffer_has_jpeg_soi(reader->buffer, reader->bytes_in_buffer, i + 3U) ||
                         raw_all_buffer_has_jpeg_soi(reader->buffer, reader->bytes_in_buffer, i + 4U) ||
                         raw_all_buffer_has_jpeg_soi(reader->buffer, reader->bytes_in_buffer, i + 5U) ||
                         raw_all_buffer_has_jpeg_soi(reader->buffer, reader->bytes_in_buffer, i + 6U) ||
                         raw_all_buffer_has_jpeg_soi(reader->buffer, reader->bytes_in_buffer, i + 7U) ||
                         raw_all_buffer_has_jpeg_soi(reader->buffer, reader->bytes_in_buffer, i + 8U))) {
                        break;
                    }
                    if (prefix_2byte[((unsigned int)reader->buffer[i] << 8) |
                                     (unsigned int)reader->buffer[i + 1U]] != 0 ||
                        prefix_2byte[((unsigned int)reader->buffer[i + 1U] << 8) |
                                     (unsigned int)reader->buffer[i + 2U]] != 0 ||
                        prefix_2byte[((unsigned int)reader->buffer[i + 2U] << 8) |
                                     (unsigned int)reader->buffer[i + 3U]] != 0 ||
                        prefix_2byte[((unsigned int)reader->buffer[i + 3U] << 8) |
                                     (unsigned int)reader->buffer[i + 4U]] != 0 ||
                        prefix_2byte[((unsigned int)reader->buffer[i + 4U] << 8) |
                                     (unsigned int)reader->buffer[i + 5U]] != 0 ||
                        prefix_2byte[((unsigned int)reader->buffer[i + 5U] << 8) |
                                     (unsigned int)reader->buffer[i + 6U]] != 0 ||
                        prefix_2byte[((unsigned int)reader->buffer[i + 6U] << 8) |
                                     (unsigned int)reader->buffer[i + 7U]] != 0 ||
                        prefix_2byte[((unsigned int)reader->buffer[i + 7U] << 8) |
                                     (unsigned int)reader->buffer[i + 8U]] != 0) {
                        break;
                    }
                    i += 8U;
                }

                while (i < candidate_limit &&
                       prefix_2byte[((unsigned int)reader->buffer[i] << 8) |
                                    (unsigned int)reader->buffer[i + 1U]] == 0 &&
                       !(direct_jpeg_scan_enabled &&
                         raw_all_buffer_has_jpeg_soi(
                             reader->buffer,
                             reader->bytes_in_buffer,
                             i))) {
                    i++;
                }

                if (i >= candidate_limit) {
                    current_scan_offset = (uint64_t)(buffer_base_offset + i);
                    break;
                }
            }

            start_offset = i;
            absolute_offset = buffer_base_offset + start_offset;
            if (absolute_offset == last_handled_offset) {
                i++;
                continue;
            }

            if (direct_jpeg_scan_enabled &&
                raw_all_buffer_has_jpeg_soi(
                    reader->buffer,
                    reader->bytes_in_buffer,
                    start_offset)) {
                size_t promoted_span = 0U;
                size_t reader_bytes_before = reader->total_bytes_read;
                size_t buffer_bytes_before = reader->bytes_in_buffer;
                double dispatch_started_at = scanner_now_seconds();
                double dispatch_elapsed;
                int direct_jpeg_ok;
                int jpeg_has_large_leading_exif =
                    carver_jpeg_has_large_leading_exif(
                        reader->buffer,
                        reader->bytes_in_buffer,
                        start_offset,
                        &promoted_exif_span);

                metadata_candidate_context_loaded =
                    raw_all_get_metadata_candidate_context(
                        (uint64_t)absolute_offset,
                        &metadata_candidate_context,
                        &metadata_candidate_context_counted);

                if (jpeg_has_large_leading_exif) {
                    (void)raw_all_deferred_jpeg_starts_append_large_exif_from_buffer(
                        &deferred_jpeg_starts,
                        reader->buffer,
                        reader->bytes_in_buffer,
                        buffer_base_offset,
                        start_offset,
                        absolute_offset
                    );
                    if (absolute_offset != last_logged_promoted_large_exif_offset) {
                        log_info(
                            "Promoted large Exif JPEG start: abs=%zu exif_span=%zu",
                            absolute_offset,
                            promoted_exif_span
                        );
                        last_logged_promoted_large_exif_offset = absolute_offset;
                    }
                }
                set_raw_all_label_activity(
                    jpeg_has_large_leading_exif ? "JPEG-large-Exif" : "JPEG-direct",
                    absolute_offset
                );
                note_foreground_candidate_activity();
                direct_jpeg_ok = carver_jpeg_from_reader(
                    reader,
                    start_offset,
                    absolute_offset,
                    &promoted_span);
                if (jpeg_direct_debug && jpeg_direct_debug_lines < 64U) {
                    log_info(
                        "JPEG direct debug attempt: abs=%zu rel=%zu ok=%d span=%zu large_exif=%d",
                        absolute_offset,
                        start_offset,
                        direct_jpeg_ok ? 1 : 0,
                        promoted_span,
                        jpeg_has_large_leading_exif ? 1 : 0);
                    jpeg_direct_debug_lines++;
                }
                if (direct_jpeg_ok) {
                    CarverJpegLastDominantClaim dominant_claim = {0};

                    dispatch_elapsed = scanner_now_seconds() - dispatch_started_at;
                    carver_jpeg_get_last_dominant_claim(&dominant_claim);
                    raw_all_deferred_jpeg_starts_append_claim(
                        &deferred_jpeg_starts,
                        &dominant_claim
                    );
                    if (promoted_span > 0U) {
                        raw_all_image_safety_append_jpeg_jump_audit(
                            &image_safety_queue,
                            config,
                            (uint64_t)absolute_offset,
                            (uint64_t)absolute_offset + (uint64_t)promoted_span,
                            "jpg");
                    }
                    last_handled_offset = absolute_offset;
                    update_working_queue_from_metadata_stats();
                    if (dispatch_elapsed >= RAW_ALL_SLOW_CANDIDATE_LOG_SECONDS) {
                        log_info(
                            "All slow candidate: format=%s abs=%zu (%.1f GiB) dt=%.2fs result=%s resume_at=%zu buffer_base=%zu",
                            jpeg_has_large_leading_exif ? "JPEG-large-Exif" : "JPEG-direct",
                            absolute_offset,
                            (double)absolute_offset / (1024.0 * 1024.0 * 1024.0),
                            dispatch_elapsed,
                            "handled_resume",
                            buffer_base_offset + start_offset + promoted_span,
                            buffer_base_offset
                        );
                    }
                    if (reader->total_bytes_read != reader_bytes_before ||
                        reader->bytes_in_buffer != buffer_bytes_before) {
                        buffer_base_offset =
                            reader->total_bytes_read - reader->bytes_in_buffer;
                        raw_all_trace_offsets_note_buffer(reader, buffer_base_offset);
                        (void)raw_all_deferred_jpeg_starts_append_large_exif_from_buffer(
                            &deferred_jpeg_starts,
                            reader->buffer,
                            reader->bytes_in_buffer,
                            buffer_base_offset,
                            0U,
                            absolute_offset
                        );
                        candidate_limit =
                            reader->bytes_in_buffer > 0 ? reader->bytes_in_buffer - 1 : 0;
                        current_scan_offset = (uint64_t)buffer_base_offset;
                        if (!skip_live_metadata_observation) {
                            int run_live_metadata_now =
                                raw_all_should_run_live_metadata_now(
                                    reader,
                                    (uint64_t)buffer_base_offset,
                                    &next_regular_file_live_metadata_offset,
                                    &regular_file_live_metadata_fast_path_logged
                                );
                            if (run_live_metadata_now) {
                                (void)observe_metadata_records_for_raw_all(
                                    reader->buffer,
                                    reader->bytes_in_buffer,
                                    (uint64_t)buffer_base_offset
                                );
                            }
                            observe_directory_indexes_for_current_buffer(
                                reader,
                                reader->buffer,
                                reader->bytes_in_buffer,
                                (uint64_t)buffer_base_offset,
                                "raw-all restarted buffer",
                                1
                            );
                        }
                    } else {
                        size_t next_i = start_offset + (promoted_span > 0U ? promoted_span : 1U);
                        if (next_i <= start_offset) {
                            next_i = start_offset + 1U;
                        }
                        if (next_i > candidate_limit) {
                            next_i = candidate_limit;
                        }
                        i = next_i;
                        current_scan_offset = (uint64_t)(buffer_base_offset + i);
                    }
                    maybe_write_raw_all_resume_state(
                        config,
                        reader_get_source_size(reader),
                        current_scan_offset,
                        &last_state_write_offset
                    );
                    maybe_write_raw_all_activity_state(
                        config,
                        reader,
                        current_scan_offset,
                        skip_live_metadata_observation,
                        &last_activity_write_at,
                        0
                    );
                    set_raw_all_signature_scan_activity(skip_live_metadata_observation);
                    continue;
                }
            }

            key = ((unsigned int)reader->buffer[i] << 8) |
                  (unsigned int)reader->buffer[i + 1U];
            bucket = index_2byte != NULL ? &index_2byte[key] : NULL;

            match = match_magic_in_bucket_fast(
                table,
                bucket,
                reader->buffer,
                reader->bytes_in_buffer,
                i
            );

            if (match == NULL) {
                if (buffer_base_offset + i >= last_progress_update_offset &&
                    buffer_base_offset + i - last_progress_update_offset >=
                        RAW_ALL_PROGRESS_UPDATE_INTERVAL) {
                    raw_all_set_working_progress_limited(
                        reader,
                        config,
                        (uint64_t)(buffer_base_offset + i));
                    last_progress_update_offset = buffer_base_offset + i;
                }
                i++;
                continue;
            }

            if (!metadata_candidate_context_loaded) {
                metadata_candidate_context_loaded =
                    raw_all_get_metadata_candidate_context(
                        (uint64_t)absolute_offset,
                        &metadata_candidate_context,
                        &metadata_candidate_context_counted);
            }

            {
                FormatPipelineDispatchResult dispatch_result;
                FormatPipelineDispatchContext candidate_dispatch_context =
                    dispatch_context;
                size_t resume_offset = start_offset;
                size_t reader_bytes_before = reader->total_bytes_read;
                size_t buffer_bytes_before = reader->bytes_in_buffer;
                double dispatch_started_at = scanner_now_seconds();
                double dispatch_elapsed = 0.0;
                char match_label[48];
                const char *owner_label =
                    raw_all_match_label(match, match_label, sizeof(match_label));
                int owner_start_is_jpeg =
                    start_offset + 3U < reader->bytes_in_buffer &&
                    reader->buffer[start_offset] == 0xFFU &&
                    reader->buffer[start_offset + 1U] == 0xD8U &&
                    reader->buffer[start_offset + 2U] == 0xFFU;
                int owner_start_is_png =
                    start_offset + 8U <= reader->bytes_in_buffer &&
                    memcmp(
                        reader->buffer + start_offset,
                        "\x89PNG\r\n\x1a\n",
                        8U) == 0;
                int owner_start_is_pdf =
                    raw_all_image_safety_is_pdf_start(
                        reader->buffer,
                        reader->bytes_in_buffer,
                        start_offset);

                if (metadata_candidate_context_loaded) {
                    candidate_dispatch_context.metadata_candidate_context_available = 1;
                    candidate_dispatch_context.metadata_candidate_context =
                        metadata_candidate_context;
                    if (metadata_candidate_context_counted) {
                        g_raw_all_metadata_candidate_stats.shared_with_dispatch++;
                    }
                }

                set_raw_all_match_activity(match, absolute_offset);
                note_foreground_candidate_activity();
                if (app_stop_requested()) {
                    app_note_shutdown_progress("raw-all candidate validation");
                }
                dispatch_result = format_pipeline_dispatch_raw_match_with_context(
                    reader,
                    config,
                    active_order,
                    &candidate_dispatch_context,
                    table,
                    match,
                    start_offset,
                    absolute_offset,
                    &resume_offset
                );
                dispatch_elapsed = scanner_now_seconds() - dispatch_started_at;
                note_foreground_candidate_activity();
                if (dispatch_elapsed >= RAW_ALL_SLOW_CANDIDATE_LOG_SECONDS) {
                    log_info(
                        "All slow candidate: format=%s abs=%zu (%.1f GiB) dt=%.2fs result=%s resume_at=%zu buffer_base=%zu",
                        owner_label,
                        absolute_offset,
                        (double)absolute_offset / (1024.0 * 1024.0 * 1024.0),
                        dispatch_elapsed,
                        raw_all_dispatch_result_name(dispatch_result),
                        buffer_base_offset + resume_offset,
                        buffer_base_offset
                    );
                    if (dispatch_result == FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE) {
                        note_low_yield_candidate_region(absolute_offset, dispatch_elapsed);
                    }
                }

                if (dispatch_result == FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME) {
                    CarverJpegLastDominantClaim dominant_claim = {0};
                    uint64_t resume_base_for_claim =
                        (reader->total_bytes_read != reader_bytes_before ||
                         reader->bytes_in_buffer != buffer_bytes_before)
                            ? (uint64_t)(reader->total_bytes_read - reader->bytes_in_buffer)
                            : (uint64_t)buffer_base_offset;
                    uint64_t resume_abs;

                    resume_abs = resume_base_for_claim + (uint64_t)resume_offset;

                    carver_jpeg_get_last_dominant_claim(&dominant_claim);
                    raw_all_deferred_jpeg_starts_append_claim(
                        &deferred_jpeg_starts,
                        &dominant_claim
                    );
                    (void)raw_all_deferred_jpeg_starts_append_large_exif_from_buffer(
                        &deferred_jpeg_starts,
                        reader->buffer,
                        reader->bytes_in_buffer,
                        buffer_base_offset,
                        start_offset,
                        absolute_offset
                    );
                    if (resume_abs > (uint64_t)absolute_offset) {
                        if (owner_start_is_jpeg) {
                            raw_all_image_safety_append_jpeg_jump_audit(
                                &image_safety_queue,
                                config,
                                (uint64_t)absolute_offset,
                                resume_abs,
                                owner_label);
                        } else if (owner_start_is_png) {
                            raw_all_image_safety_append_dense_lookback(
                                &image_safety_queue,
                                config,
                                (uint64_t)absolute_offset,
                                resume_abs,
                                RAW_ALL_IMAGE_SAFETY_PNG,
                                owner_label);
                        } else if (owner_start_is_pdf) {
                            raw_all_image_safety_append_pdf_claim_audit(
                                &image_safety_queue,
                                config,
                                (uint64_t)absolute_offset,
                                resume_abs,
                                owner_label);
                        } else {
                            raw_all_image_safety_append_large_claim(
                                &image_safety_queue,
                                config,
                                (uint64_t)absolute_offset,
                                resume_abs,
                                owner_label);
                        }
                    }
                    last_handled_offset = absolute_offset;
                    update_working_queue_from_metadata_stats();
                    i = resume_offset;
                    current_scan_offset = (uint64_t)(buffer_base_offset + i);

                    if (reader->total_bytes_read != reader_bytes_before ||
                        reader->bytes_in_buffer != buffer_bytes_before) {
                        buffer_base_offset =
                            reader->total_bytes_read - reader->bytes_in_buffer;
                        raw_all_trace_offsets_note_buffer(reader, buffer_base_offset);
                        (void)raw_all_deferred_jpeg_starts_append_large_exif_from_buffer(
                            &deferred_jpeg_starts,
                            reader->buffer,
                            reader->bytes_in_buffer,
                            buffer_base_offset,
                            0U,
                            absolute_offset
                        );
                        candidate_limit =
                            reader->bytes_in_buffer > 0 ? reader->bytes_in_buffer - 1 : 0;
                        current_scan_offset = (uint64_t)buffer_base_offset;
                        if (!skip_live_metadata_observation) {
                            int run_live_metadata_now =
                                raw_all_should_run_live_metadata_now(
                                    reader,
                                    (uint64_t)buffer_base_offset,
                                    &next_regular_file_live_metadata_offset,
                                    &regular_file_live_metadata_fast_path_logged
                                );
                            if (run_live_metadata_now) {
                                (void)observe_metadata_records_for_raw_all(
                                    reader->buffer,
                                    reader->bytes_in_buffer,
                                    (uint64_t)buffer_base_offset
                                );
                            }
                            observe_directory_indexes_for_current_buffer(
                                reader,
                                reader->buffer,
                                reader->bytes_in_buffer,
                                (uint64_t)buffer_base_offset,
                                "raw-all dispatch restart",
                                1
                            );
                        }
                    }
                    maybe_write_raw_all_resume_state(
                        config,
                        reader_get_source_size(reader),
                        current_scan_offset,
                        &last_state_write_offset
                    );
                    maybe_write_raw_all_activity_state(
                        config,
                        reader,
                        current_scan_offset,
                        skip_live_metadata_observation,
                        &last_activity_write_at,
                        0
                    );
                    set_raw_all_signature_scan_activity(skip_live_metadata_observation);
                    continue;
                }

                if (dispatch_result == FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED) {
                    set_raw_all_signature_scan_activity(skip_live_metadata_observation);
                    i++;
                    current_scan_offset = (uint64_t)(buffer_base_offset + i);
                    continue;
                }

                last_handled_offset = absolute_offset;
                update_working_queue_from_metadata_stats();
                set_raw_all_signature_scan_activity(skip_live_metadata_observation);
                if (buffer_base_offset + i >= last_progress_update_offset &&
                    buffer_base_offset + i - last_progress_update_offset >=
                        RAW_ALL_PROGRESS_UPDATE_INTERVAL) {
                    raw_all_set_working_progress_limited(
                        reader,
                        config,
                        (uint64_t)(buffer_base_offset + i));
                    last_progress_update_offset = buffer_base_offset + i;
                }
                i++;
                current_scan_offset = (uint64_t)(buffer_base_offset + i);
            }
        }

        if (i >= candidate_limit) {
            current_scan_offset = (uint64_t)(buffer_base_offset + i);
        }

        maybe_write_raw_all_resume_state(
            config,
            reader_get_source_size(reader),
            current_scan_offset,
            &last_state_write_offset
        );
        maybe_write_raw_all_activity_state(
            config,
            reader,
            current_scan_offset,
            skip_live_metadata_observation,
            &last_activity_write_at,
            0
        );

        if (raw_all_should_stop()) {
            break;
        }

        if (scan_limit > 0U &&
            (uint64_t)reader->total_bytes_read >= scan_limit) {
            limit_reached = 1;
            break;
        }

        if (raw_all_reader_read_next_limited(reader, scan_limit) == 0) {
            break;
        }
        if (!raw_all_background_worker_is_healthy()) {
            background_worker_failed = 1;
            break;
        }
        raw_all_set_working_progress_limited(
            reader,
            config,
            (uint64_t)(reader->total_bytes_read - reader->bytes_in_buffer));
        set_raw_all_signature_scan_activity(skip_live_metadata_observation);
        if (app_stop_requested()) {
            app_note_shutdown_progress("raw-all sequential scan");
        }
        maybe_write_raw_all_activity_state(
            config,
            reader,
            (uint64_t)(reader->total_bytes_read - reader->bytes_in_buffer),
            skip_live_metadata_observation,
            &last_activity_write_at,
            0
        );
    }

raw_all_primary_scan_done:
    if (app_stop_requested() &&
        !app_supervisor_generation_stale() &&
        config != NULL &&
        config->scan_state_path != NULL &&
        config->scan_state_path[0] != '\0') {
        (void)scan_state_write(
            config->scan_state_path,
            config->input_path,
            "all",
            reader_get_source_size(reader),
            current_scan_offset,
            0,
            0);
        log_all_live_stats_snapshot();
    }
    maybe_write_raw_all_activity_state(
        config,
        reader,
        current_scan_offset,
        skip_live_metadata_observation,
        &last_activity_write_at,
        1
    );

    primary_pass_end_offset = current_scan_offset;
    if (!background_worker_failed && !raw_all_should_stop()) {
        uint64_t read_end_offset = (uint64_t)reader->total_bytes_read;

        if (read_end_offset > primary_pass_end_offset) {
            primary_pass_end_offset = read_end_offset;
        }
    }
    reader_set_sequential_chunk_observer(reader, NULL, NULL);
    if (!raw_all_should_stop() && reader->source_is_regular_file) {
        raw_all_process_deferred_jpeg_starts(
            &deferred_jpeg_starts,
            reader,
            config,
            primary_pass_end_offset,
            &dispatch_context
        );
    }
    if (!raw_all_should_stop() && reader->source_is_regular_file) {
        raw_all_image_safety_process(
            &image_safety_queue,
            reader,
            config,
            active_order,
            primary_pass_end_offset,
            &dispatch_context
        );
    } else if (!raw_all_should_stop() && !reader->source_is_regular_file) {
        /*
         * A physical rescue source gets one predictable, monotonic primary
         * pass.  The queues and swallowed-range reports remain persisted for
         * an explicit later audit, but must not silently turn the end of a
         * gentle scan into hours of random seeks against a failing disk.
         * Regular image files retain the automatic safety sweep.
         */
        log_info(
            "Physical-source policy: primary sequential pass complete; keeping %zu deferred JPEG start%s and %zu claim-audit interval%s as plan-only work (no automatic random rereads)",
            deferred_jpeg_starts.count,
            deferred_jpeg_starts.count == 1U ? "" : "s",
            image_safety_queue.interval_count,
            image_safety_queue.interval_count == 1U ? "" : "s"
        );
        raw_all_claim_audit_write_state(
            config,
            &image_safety_queue,
            "plan_only",
            "physical_source_no_automatic_random_rereads"
        );
    }
    current_scan_offset = primary_pass_end_offset;
    raw_all_deferred_jpeg_starts_free(&deferred_jpeg_starts);
    raw_all_image_safety_queue_free(&image_safety_queue);
    if (g_raw_all_metadata_candidate_stats.lookups > 0U) {
        log_info(
            "Raw-all cumulative metadata candidate context (unique offsets through %llu): lookups=%llu no_owner=%llu ambiguous=%llu non_data=%llu incomplete=%llu trusted_start=%llu trusted_interior=%llu shared_with_dispatch=%llu failures=%llu",
            (unsigned long long)g_raw_all_metadata_candidate_stats.high_water_offset,
            (unsigned long long)g_raw_all_metadata_candidate_stats.lookups,
            (unsigned long long)g_raw_all_metadata_candidate_stats.no_owner,
            (unsigned long long)g_raw_all_metadata_candidate_stats.ambiguous_owner,
            (unsigned long long)g_raw_all_metadata_candidate_stats.non_data_owner,
            (unsigned long long)g_raw_all_metadata_candidate_stats.incomplete_owner,
            (unsigned long long)g_raw_all_metadata_candidate_stats.trusted_exact_start,
            (unsigned long long)g_raw_all_metadata_candidate_stats.trusted_interior,
            (unsigned long long)g_raw_all_metadata_candidate_stats.shared_with_dispatch,
            (unsigned long long)g_raw_all_metadata_candidate_stats.lookup_failures
        );
    }
    log_all_live_stats_snapshot();
    maybe_write_raw_all_activity_state(
        config,
        reader,
        current_scan_offset,
        skip_live_metadata_observation,
        &last_activity_write_at,
        1
    );

    if (async_outputs_started) {
        carver_output_async_stop();
        maybe_write_raw_all_activity_state(
            config,
            reader,
            current_scan_offset,
            skip_live_metadata_observation,
            &last_activity_write_at,
            1
        );
    }
    {
        uint64_t source_size = reader_get_source_size(reader);
        int completed_full_scan =
            !background_worker_failed &&
            !raw_all_should_stop() &&
            !limit_reached &&
            (source_size == 0U || primary_pass_end_offset >= source_size);
        if (out_completed_full_scan != NULL) {
            *out_completed_full_scan = completed_full_scan;
        }
        /* Publish a checkpoint here.  The app promotes it to complete only
         * after checking the union of durable read-coverage ranges. */
        fs_backend_finish_sequential_measurement(0);
    }
    return (background_worker_failed || raw_all_should_stop()) ? 0 : 1;
#else
    (void)reader;
    (void)table;
    (void)config;
    (void)active_order;
    (void)out_completed_full_scan;
    log_error("Raw-all scan mode is unavailable in tree-only build mode");
    return 0;
#endif
}

int scanner_index_primary_metadata_catalog(Reader *reader)
{
    static const PrimaryMetadataAcquirePlan startup_plan = {
        "startup bootstrap",
        PRIMARY_METADATA_STARTUP_RUNLIST_PROBE_BYTES,
        PRIMARY_METADATA_STARTUP_BOOTSTRAP_BYTES,
        PRIMARY_METADATA_STARTUP_FALLBACK_BYTES,
        PRIMARY_METADATA_STARTUP_FALLBACK_BYTES,
        PRIMARY_METADATA_STARTUP_MAX_SECONDS,
        PRIMARY_METADATA_STARTUP_CHUNK_CAP_BYTES,
        0,
        1,
        0,
        0,
        1,
        0
    };

    return scanner_run_primary_metadata_acquisition_plan(
        reader,
        &startup_plan
    );
}

int scanner_run_primary_metadata_acquisition(Reader *reader, int phase)
{
    static const PrimaryMetadataAcquirePlan startup_plan = {
        "startup bootstrap",
        PRIMARY_METADATA_STARTUP_RUNLIST_PROBE_BYTES,
        PRIMARY_METADATA_STARTUP_BOOTSTRAP_BYTES,
        PRIMARY_METADATA_STARTUP_FALLBACK_BYTES,
        PRIMARY_METADATA_STARTUP_FALLBACK_BYTES,
        PRIMARY_METADATA_STARTUP_MAX_SECONDS,
        PRIMARY_METADATA_STARTUP_CHUNK_CAP_BYTES,
        0,
        1,
        0,
        0,
        1,
        0
    };
    static const PrimaryMetadataAcquirePlan pre_deferred_plan = {
        "pre-deferred revisit",
        PRIMARY_METADATA_PRE_DEFERRED_PROBE_BYTES,
        PRIMARY_METADATA_PRE_DEFERRED_BYTES,
        PRIMARY_METADATA_PRE_DEFERRED_BYTES,
        PRIMARY_METADATA_PRE_DEFERRED_BYTES,
        PRIMARY_METADATA_PRE_DEFERRED_MAX_SECONDS,
        PRIMARY_METADATA_PRE_DEFERRED_CHUNK_CAP_BYTES,
        0,
        1,
        0,
        0,
        0,
        1
    };
    static const PrimaryMetadataAcquirePlan post_deferred_plan = {
        "post-deferred revisit",
        PRIMARY_METADATA_POST_DEFERRED_PROBE_BYTES,
        PRIMARY_METADATA_POST_DEFERRED_BYTES,
        PRIMARY_METADATA_POST_DEFERRED_BYTES,
        PRIMARY_METADATA_POST_DEFERRED_BYTES,
        PRIMARY_METADATA_POST_DEFERRED_MAX_SECONDS,
        PRIMARY_METADATA_POST_DEFERRED_CHUNK_CAP_BYTES,
        0,
        1,
        1,
        1,
        0,
        1
    };
    const PrimaryMetadataAcquirePlan *plan = &startup_plan;

    switch (phase) {
        case FS_BACKEND_METADATA_ACQUIRE_PRE_DEFERRED:
            plan = &pre_deferred_plan;
            break;
        case FS_BACKEND_METADATA_ACQUIRE_POST_DEFERRED:
            plan = &post_deferred_plan;
            break;
        case FS_BACKEND_METADATA_ACQUIRE_STARTUP:
        default:
            plan = &startup_plan;
            break;
    }

    return scanner_run_primary_metadata_acquisition_plan(reader, plan);
}

int scanner_primary_metadata_bootstrap_should_disable_live_observation(void)
{
    return g_primary_metadata_bootstrap_should_disable_live_observation;
}

int scanner_index_primary_mft(Reader *reader)
{
    return scanner_index_primary_metadata_catalog(reader);
}

int scanner_primary_mft_bootstrap_should_skip_mft(void)
{
    return scanner_primary_metadata_bootstrap_should_disable_live_observation();
}
