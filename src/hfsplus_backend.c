#define _POSIX_C_SOURCE 200809L

#include "hfsplus_backend.h"

#include "app.h"
#include "config.h"
#include "container_context.h"
#include "fs_backend.h"
#include "image_triage.h"
#include "log.h"
#include "metadata_index.h"
#include "metadata_outcome.h"
#include "platform.h"
#include "mft.h"
#include "mft_spool.h"
#include "reader.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#define HFSPLUS_SECTOR_SIZE 512U
#define HFSPLUS_VOLUME_HEADER_OFFSET 1024ULL
#define HFSPLUS_VOLUME_HEADER_SIZE 512U
#define HFSPLUS_SIGNATURE 0x482BU
#define HFSX_SIGNATURE 0x4858U
#define HFSPLUS_VERSION 4U
#define HFSX_VERSION 5U
#define HFS_WRAPPER_SIGNATURE 0x4244U
#define HFSPLUS_ROOT_FOLDER_ID 2U
#define HFSPLUS_EXTENTS_FILE_ID 3U
#define HFSPLUS_CATALOG_FILE_ID 4U
#define HFSPLUS_CATALOG_FOLDER_RECORD 0x0001U
#define HFSPLUS_CATALOG_FILE_RECORD 0x0002U
#define HFSPLUS_FORK_TYPE_DATA 0x00U
#define HFSPLUS_FORK_TYPE_RESOURCE 0xFFU
#define HFSPLUS_BT_LEAF_NODE (-1)
#define HFSPLUS_BT_HEADER_NODE 1
#define HFSPLUS_BT_MAP_NODE 2
#define HFSPLUS_BTREE_NODE_MIN 512U
#define HFSPLUS_BTREE_NODE_MAX 32768U
#define HFSPLUS_EXTENT_COUNT 8U
#define HFSPLUS_MAX_FORK_EXTENTS 4096U
#define HFSPLUS_MAX_OVERFLOW_RECORDS 262144U
#define HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS 2000000U
#define HFSPLUS_MAX_ORPHAN_STRING_BYTES (256ULL * 1024ULL * 1024ULL)
#define HFSPLUS_JOURNAL_INFO_SIZE 180U
#define HFSPLUS_JOURNAL_IN_FS_MASK 0x00000001U
#define HFSPLUS_JOURNAL_EXTERNAL_MASK 0x00000002U
#define HFSPLUS_JOURNAL_NEED_INIT_MASK 0x00000004U
#define HFSPLUS_JOURNAL_HEADER_MAGIC 0x4A4E4C78U
#define HFSPLUS_OLD_JOURNAL_HEADER_MAGIC 0x4A484452U
#define HFSPLUS_JOURNAL_ENDIAN_MAGIC 0x12345678U
#define HFSPLUS_JOURNAL_HEADER_CHECKSUM_SIZE 44U
#define HFSPLUS_JOURNAL_BLOCK_HEADER_CHECKSUM_SIZE 32U
#define HFSPLUS_JOURNAL_BLOCK_INFO_SIZE 16U
#define HFSPLUS_JOURNAL_BLOCK_LIST_BASE_SIZE 16U
#define HFSPLUS_JOURNAL_CHECK_BLOCK_CHECKSUMS 0x00000001U
#define HFSPLUS_JOURNAL_MAX_BYTES (1024ULL * 1024ULL * 1024ULL)
#define HFSPLUS_JOURNAL_SCAN_BUFFER_BYTES (8U * 1024U * 1024U)
#define GPT_PARTITION_ENTRY_MIN 128U
#define GPT_PARTITION_ENTRY_MAX 4096U
#define GPT_PARTITION_ENTRY_LIMIT 4096U
#define HFSPLUS_NAME_MAX 512U
#define HFSPLUS_PATH_MAX 1024U
#define HFSPLUS_PROGRESS_FILE_WORK_BYTES (64ULL * 1024ULL)
#define HFSPLUS_PROGRESS_DIRECTORY_WORK_BYTES (16ULL * 1024ULL)
#define HFSPLUS_PROGRESS_PUBLISH_INTERVAL_SECONDS 1.00
#define HFSPLUS_HFS_EPOCH_DELTA 2082844800ULL
#define HFSPLUS_RECOVERED_OUTPUT_INDEX_PENDING_LIMIT 256U
#define HFSPLUS_LIVE_RECONCILE_BATCH_LIMIT 128U
#define HFSPLUS_LIVE_RECONCILE_CONSERVATIVE_BATCH_LIMIT 8U
#define HFSPLUS_LIVE_RECONCILE_IDLE_BATCH_LIMIT 32U
#define HFSPLUS_LIVE_RECONCILE_MIN_INTERVAL_SECONDS 0.050
#define HFSPLUS_LIVE_RECONCILE_FOREGROUND_COOLDOWN_SECONDS 0.250
#define HFSPLUS_LIVE_RECONCILE_CONSERVATIVE_BUDGET_SECONDS 0.002
#define HFSPLUS_LIVE_RECONCILE_IDLE_BUDGET_SECONDS 0.008
#define HFSPLUS_LIVE_RECONCILE_REWRITE_INTERVAL_SECONDS 1.000
#define HFSPLUS_SNAPSHOT_MAGIC "HFSPSNP1"
#define HFSPLUS_SNAPSHOT_MAGIC_SIZE 8U
#define HFSPLUS_SNAPSHOT_VERSION 4U
#define HFSPLUS_SNAPSHOT_FLAG_HAS_WRAPPER 0x00000001U
#define HFSPLUS_SNAPSHOT_FLAG_IS_HFSX 0x00000002U
#define HFSPLUS_SNAPSHOT_FLAG_SORT_CASE_SENSITIVE 0x00000004U
#define HFSPLUS_SNAPSHOT_ENTRY_FLAG_RUN_TRUNCATED 0x00000001U
#define HFSPLUS_SNAPSHOT_ENTRY_FLAG_DIRECTORY 0x00000002U
#define HFSPLUS_SNAPSHOT_ENTRY_FLAG_HAS_DATA 0x00000004U
#define HFSPLUS_SNAPSHOT_ENTRY_FLAG_HAS_NAME 0x00000008U
#define HFSPLUS_SNAPSHOT_ENTRY_FLAG_PATH_COMPLETE 0x00000010U
#define HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_PLACEHOLDER 0x00000020U
#define HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_INODE 0x00000040U
#define HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_RESOLVED 0x00000080U
#define HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_METADATA_DIR 0x00000100U
#define HFSPLUS_HARDLINK_FILE_TYPE 0x686C6E6BU /* 'hlnk' */
#define HFSPLUS_HARDLINK_CREATOR 0x6866732BU   /* 'hfs+' */
#define HFSPLUS_HARDLINK_PRIVATE_DIR_PORTABLE "____HFS+ Private Data"
#define HFSPLUS_DIRECTORY_HARDLINK_PRIVATE_DIR_PORTABLE \
    ".HFS+ Private Directory Data_"
#define HFSPLUS_SHADOW_SCHEMA_VERSION 2U
#define HFSPLUS_CATALOG_READ_AHEAD_BYTES (8U * 1024U * 1024U)
#define HFSPLUS_CATALOG_PROGRESS_INTERVAL_SECONDS 0.50
#define HFSPLUS_CATALOG_PROGRESS_LOG_INTERVAL_SECONDS 10.0
#define HFSPLUS_EXTENT_MEASUREMENT_PUBLISH_INTERVAL_SECONDS 5.0
#define HFSPLUS_OUTPUT_CLASS_UNCLASSIFIED 0U
#define HFSPLUS_OUTPUT_CLASS_EMBEDDED 1U

typedef struct {
    uint32_t start_block;
    uint32_t block_count;
} HfsPlusExtentDescriptorLocal;

typedef struct {
    uint64_t logical_size;
    uint32_t total_blocks;
    HfsPlusExtentDescriptorLocal extents[HFSPLUS_EXTENT_COUNT];
} HfsPlusForkDataLocal;

typedef struct {
    uint64_t logical_size;
    uint32_t total_blocks;
    size_t extent_count;
    int overflow_used;
    int truncated;
    HfsPlusExtentDescriptorLocal *extents;
} HfsPlusResolvedForkLocal;

typedef struct {
    uint32_t root_node;
    uint32_t first_leaf_node;
    uint32_t last_leaf_node;
    uint32_t total_nodes;
    uint32_t free_nodes;
    uint32_t leaf_records;
    uint16_t node_size;
    uint8_t key_compare_type;
} HfsPlusBTreeHeaderLocal;

typedef enum {
    HFSPLUS_ORPHAN_FREE_LEAF_TABLE = 1,
    HFSPLUS_ORPHAN_FREE_NODE_SCAN = 2,
    HFSPLUS_ORPHAN_ALLOCATED_LEAF_SLACK = 3,
    HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK = 4
} HfsPlusOrphanProvenanceLocal;

typedef struct {
    uint64_t abs_offset;
    uint64_t data_size;
    uint64_t allocated_size;
    uint64_t name_offset;
    uint32_t journal_observations;
    uint32_t journal_active_observations;
    uint32_t journal_active_first_rank;
    uint32_t journal_active_last_rank;
    uint32_t file_id;
    uint32_t parent_id;
    uint32_t create_date_hfs;
    uint32_t source_node;
    uint32_t name_length;
    uint16_t record_offset;
    uint8_t confidence;
    uint8_t provenance;
} HfsPlusOrphanCatalogRecordLocal;

typedef struct {
    uint64_t name_offset;
    uint32_t journal_observations;
    uint32_t journal_active_observations;
    uint32_t journal_active_first_rank;
    uint32_t journal_active_last_rank;
    uint32_t folder_id;
    uint32_t parent_id;
    uint32_t create_date_hfs;
    uint32_t source_node;
    uint32_t name_length;
    uint16_t record_offset;
    uint8_t confidence;
    uint8_t provenance;
} HfsPlusHistoricalFolderRecordLocal;

typedef struct {
    uint8_t fork_type;
    uint32_t file_id;
    uint32_t start_block;
    HfsPlusExtentDescriptorLocal extents[HFSPLUS_EXTENT_COUNT];
} HfsPlusExtentOverflowRecordLocal;

typedef struct {
    uint32_t file_id;
    uint32_t parent_id;
    uint32_t create_date_hfs;
    time_t created_unix;
    uint64_t abs_offset;
    uint64_t data_size;
    uint64_t allocated_size;
    size_t run_count;
    int run_truncated;
    int is_directory;
    int has_data;
    int has_name;
    int path_complete;
    MftViewRun runs[MFT_VIEW_MAX_RUNS];
    MftViewRun *extra_runs;
    size_t extra_run_count;
    uint32_t hardlink_reference;
    uint32_t hardlink_backing_file_id;
    char name[HFSPLUS_NAME_MAX];
    char path[HFSPLUS_PATH_MAX];
    int is_hardlink_placeholder;
    int is_hardlink_inode;
    int hardlink_resolved;
    int is_hardlink_metadata_directory;
} HfsPlusCatalogEntry;

typedef struct {
    uint32_t reference;
    size_t entry_index;
} HfsPlusHardlinkAliasLocal;

typedef struct {
    uint32_t file_id;
    size_t entry_index;
} HfsPlusIdIndexEntry;

typedef struct {
    uint64_t abs_offset;
    size_t entry_index;
} HfsPlusOffsetIndexEntry;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t max_end_seen;
    size_t entry_index;
} HfsPlusSpanIndexEntry;

typedef struct {
    uint64_t start;
    uint64_t end;
} HfsPlusDomainRangeLocal;

#define HFSPLUS_DDRESCUE_DOMAIN_COALESCE_GAP_BYTES (1024ULL * 1024ULL)

typedef struct {
    char path[HFSPLUS_PATH_MAX];
    long long abs_offset;
    int reconciled;
    unsigned int classification;
} HfsPlusRecoveredOutput;

typedef struct {
    uint64_t object_key;
    uint32_t fork_row;
    uint64_t logical_position;
    uint64_t physical_start;
    uint64_t physical_end;
    uint64_t output_size;
    char owner_path[HFSPLUS_PATH_MAX];
} HfsPlusEmbeddedContextLocal;

typedef enum {
    HFSPLUS_AUDIT_ELIGIBLE_EMBEDDED = 0,
    HFSPLUS_AUDIT_OUTPUT_UNAVAILABLE,
    HFSPLUS_AUDIT_COMPACT_INDEX_UNAVAILABLE,
    HFSPLUS_AUDIT_NO_METADATA_OWNER,
    HFSPLUS_AUDIT_AMBIGUOUS_METADATA_OWNER,
    HFSPLUS_AUDIT_EXACT_CATALOG_START_UNRESOLVED,
    HFSPLUS_AUDIT_FORK_UNAVAILABLE,
    HFSPLUS_AUDIT_NON_DATA_FORK,
    HFSPLUS_AUDIT_INCOMPLETE_DATA_FORK,
    HFSPLUS_AUDIT_CROSSES_PHYSICAL_EXTENT,
    HFSPLUS_AUDIT_EXCEEDS_LOGICAL_FORK,
    HFSPLUS_AUDIT_OWNER_PATH_UNAVAILABLE,
    HFSPLUS_AUDIT_REASON_COUNT
} HfsPlusUnresolvedAuditReasonLocal;

typedef struct {
    HfsPlusUnresolvedAuditReasonLocal reason;
    HfsPlusEmbeddedContextLocal context;
    MetadataIndexFork fork;
    size_t match_count;
    int have_match;
    int have_fork;
    int have_owner_path;
} HfsPlusUnresolvedAnalysisLocal;

typedef struct {
    long long abs_offset;
    size_t output_index;
} HfsPlusRecoveredOutputIndexEntry;

typedef struct {
    const char *phase;
    const char *activity;
    int plan_ready;
    uint64_t work_completed;
    uint64_t work_total;
    uint64_t files_total;
    uint64_t files_completed;
    uint64_t files_incomplete;
    uint64_t files_failed;
    uint64_t bytes_total;
    uint64_t bytes_written;
    uint64_t bytes_copied;
    uint64_t directories_total;
    uint64_t directories_completed;
    uint64_t planning_entries_processed;
    uint64_t planning_entries_total;
    uint64_t current_source_offset;
    char current_path[HFSPLUS_PATH_MAX];
    double started_at;
    double work_started_at;
    double last_publish_at;
} HfsPlusRecoveryProgressLocal;

typedef struct {
    const char *reason;
    int error_code;
    uint64_t source_offset;
    uint64_t requested_bytes;
    uint64_t completed_bytes;
    uint64_t unreadable_bytes;
    size_t run_index;
} HfsPlusRecoveryFailureLocal;

static HfsPlusBackendGeometry g_hfsplus_geometry = {0};
static HfsPlusForkDataLocal g_hfsplus_catalog_fork = {0};
static HfsPlusForkDataLocal g_hfsplus_extents_fork = {0};
static HfsPlusResolvedForkLocal g_hfsplus_catalog_resolved_fork = {0};
static char g_hfsplus_source_hint[32] = "";
static char g_hfsplus_source_path[HFSPLUS_PATH_MAX] = "";
static int g_hfsplus_sort_case_sensitive = 0;
static int g_hfsplus_catalog_loaded = 0;
static char g_hfsplus_output_dir[HFSPLUS_PATH_MAX] = "";
static HfsPlusRecoveryProgressLocal g_hfsplus_recovery_progress = {0};
static int g_hfsplus_recovery_lock_fd = -1;

static HfsPlusCatalogEntry *g_hfsplus_entries = NULL;
static size_t g_hfsplus_entry_count = 0U;
static size_t g_hfsplus_entry_capacity = 0U;
static HfsPlusIdIndexEntry *g_hfsplus_id_index = NULL;
static size_t g_hfsplus_id_index_count = 0U;
static HfsPlusOffsetIndexEntry *g_hfsplus_offset_index = NULL;
static size_t g_hfsplus_offset_index_count = 0U;
static size_t g_hfsplus_offset_index_capacity = 0U;
static HfsPlusSpanIndexEntry *g_hfsplus_span_index = NULL;
static size_t g_hfsplus_span_index_count = 0U;
static size_t g_hfsplus_span_index_capacity = 0U;
static size_t g_hfsplus_lookup_index_entry_count = (size_t)-1;
static HfsPlusRecoveredOutput *g_hfsplus_recovered_outputs = NULL;
static size_t g_hfsplus_recovered_output_count = 0U;
static size_t g_hfsplus_recovered_output_capacity = 0U;
static size_t g_hfsplus_reconciled_output_count = 0U;
static int g_hfsplus_recovered_outputs_log_needs_rewrite = 0;
static HfsPlusRecoveredOutputIndexEntry *g_hfsplus_recovered_output_index = NULL;
static size_t g_hfsplus_recovered_output_index_count = 0U;
static size_t g_hfsplus_recovered_output_index_capacity = 0U;
static size_t g_hfsplus_recovered_output_index_sorted_count = 0U;
static size_t g_hfsplus_recovered_output_index_output_count = (size_t)-1;
static unsigned char *g_hfsplus_pending_output_flags = NULL;
static size_t g_hfsplus_pending_output_flags_capacity = 0U;
static size_t *g_hfsplus_pending_output_queue = NULL;
static size_t g_hfsplus_pending_output_queue_head = 0U;
static size_t g_hfsplus_pending_output_queue_count = 0U;
static size_t g_hfsplus_pending_output_queue_capacity = 0U;
static size_t g_hfsplus_live_reconcile_cursor = 0U;
static uint64_t g_hfsplus_live_renamed_outputs = 0ULL;
static uint64_t g_hfsplus_embedded_output_count = 0ULL;
static uint64_t g_hfsplus_live_embedded_moves = 0ULL;
static int g_hfsplus_live_background_conservative = 0;
static double g_hfsplus_live_last_foreground_activity_at = 0.0;
static double g_hfsplus_live_last_reconcile_at = 0.0;
static double g_hfsplus_live_last_rewrite_at = 0.0;
static double g_hfsplus_finalize_budget_seconds = 0.0;
static char g_hfsplus_finalize_budget_profile[32] = "";
static HfsPlusExtentOverflowRecordLocal *g_hfsplus_overflow_records = NULL;
static size_t g_hfsplus_overflow_record_count = 0U;
static size_t g_hfsplus_overflow_record_capacity = 0U;
static int g_hfsplus_overflow_loaded = 0;
static unsigned int g_hfsplus_live_background_phase =
    MFT_SPOOL_BACKGROUND_PHASE_IDLE;
static int g_hfsplus_photos_library_signal_logged = 0;
static int g_hfsplus_shadow_index_ready = 0;
static int g_hfsplus_prefer_compact_metadata = 0;
static int g_hfsplus_compact_only = 0;
static MetadataIndexReader *g_hfsplus_compact_reader = NULL;
static MetadataIndexStats g_hfsplus_compact_stats = {0};
static MetadataIndexSequentialMeter *g_hfsplus_extent_meter = NULL;
static double g_hfsplus_extent_meter_last_publish_at = 0.0;
static uint64_t g_hfsplus_extent_meter_seeded_ranges = 0ULL;
static uint64_t g_hfsplus_extent_meter_seeded_bytes = 0ULL;
static int g_hfsplus_extent_measurement_completed = 0;
static char g_hfsplus_active_formats[512] = "";
static int g_hfsplus_assemble_all_catalog_files = 0;
static uint64_t *g_hfsplus_assembly_fork_bytes = NULL;
static uint64_t *g_hfsplus_assembly_extent_prefix = NULL;
static unsigned char *g_hfsplus_assembly_fork_done = NULL;
static size_t g_hfsplus_assembly_fork_count = 0U;
static uint64_t g_hfsplus_assembly_bytes_written = 0ULL;
static uint64_t g_hfsplus_assembly_intersections = 0ULL;
static uint64_t g_hfsplus_assembly_files_completed = 0ULL;
static uint64_t g_hfsplus_assembly_write_failures = 0ULL;
static uint64_t g_hfsplus_assembly_empty_files = 0ULL;
static uint64_t g_hfsplus_assembly_empty_files_deferred = 0ULL;
static uint64_t g_hfsplus_assembly_directories = 0ULL;
static uint64_t g_hfsplus_assembly_hardlinks = 0ULL;
static uint64_t g_hfsplus_assembly_inherited_generation = 0ULL;
static int g_hfsplus_assembly_disabled = 0;
static int g_hfsplus_assembly_parts_ready = 0;
static FILE *g_hfsplus_assembly_journal = NULL;
static HfsPlusOrphanCatalogRecordLocal *g_hfsplus_orphan_records = NULL;
static size_t g_hfsplus_orphan_record_count = 0U;
static size_t g_hfsplus_orphan_record_capacity = 0U;
static HfsPlusHistoricalFolderRecordLocal *g_hfsplus_historical_folders = NULL;
static size_t g_hfsplus_historical_folder_count = 0U;
static size_t g_hfsplus_historical_folder_capacity = 0U;
static char *g_hfsplus_orphan_strings = NULL;
static size_t g_hfsplus_orphan_string_bytes = 0U;
static size_t g_hfsplus_orphan_string_capacity = 0U;
static uint64_t g_hfsplus_orphan_nodes_scanned = 0ULL;
static uint64_t g_hfsplus_orphan_free_nodes_scanned = 0ULL;
static uint64_t g_hfsplus_orphan_slack_bytes_scanned = 0ULL;
static uint64_t g_hfsplus_orphan_rejected_candidates = 0ULL;
static uint64_t g_hfsplus_journal_offset = 0ULL;
static uint64_t g_hfsplus_journal_size = 0ULL;
static uint64_t g_hfsplus_journal_bytes_read = 0ULL;
static uint64_t g_hfsplus_journal_header_candidates = 0ULL;
static uint64_t g_hfsplus_journal_valid_transactions = 0ULL;
static uint64_t g_hfsplus_journal_active_transactions = 0ULL;
static uint64_t g_hfsplus_journal_checksum_rejections = 0ULL;
static uint64_t g_hfsplus_journal_catalog_blocks = 0ULL;
static uint64_t g_hfsplus_journal_catalog_records = 0ULL;
static uint64_t g_hfsplus_journal_folder_records = 0ULL;
static uint32_t g_hfsplus_journal_sequence = 0U;
static uint32_t g_hfsplus_journal_header_checksum = 0U;
static int g_hfsplus_journal_header_valid = 0;
static int g_hfsplus_journal_little_endian = 0;
static int g_hfsplus_journal_scan_attempted = 0;
static int g_hfsplus_orphan_truncated = 0;
static int g_hfsplus_orphan_ready = 0;
static uint64_t g_hfsplus_journal_names_recovered_current = 0ULL;

static void free_lookup_index_local(void);
static void free_recovered_output_index_local(void);
static void free_recovered_outputs_local(void);
static void free_catalog_metadata_local(void);
static void free_orphan_catalog_local(void);
static int ensure_recovered_output_capacity_local(size_t needed);
static int ensure_pending_output_flags_capacity_local(size_t needed);
static int save_metadata_snapshot_local(void);
static int rewrite_recovered_outputs_log_local(void);
static int append_recovered_output_log_entry_local(
    const char *path,
    long long abs_offset,
    int reconciled,
    unsigned int classification);
static int write_recovered_output_metadata_outcomes_local(void);
static size_t find_recovered_output_index_local(long long abs_offset);
static int hfsplus_catalog_available_local(void);
static int hfsplus_compact_available_local(void);
static int hfsplus_metadata_ready_local(void);
static void hfsplus_reset_metadata_local(void);
static int hfsplus_ensure_shadow_index_local(void);
static void hfsplus_shadow_identity_local(MetadataIndexVolumeIdentity *identity);
static int configure_from_source_internal_local(
    const char *input_path,
    int allow_snapshot,
    int preserve_recovery_state
);
static int build_recovered_output_path_internal_local(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension,
    const char *current_path,
    int *out_contextual,
    time_t *out_created_time);
static int build_embedded_output_path_local(
    char *out_path,
    size_t out_size,
    const HfsPlusRecoveredOutput *output,
    const char *extension,
    HfsPlusEmbeddedContextLocal *context_out);
static HfsPlusUnresolvedAuditReasonLocal analyze_unresolved_output_local(
    const HfsPlusRecoveredOutput *output,
    HfsPlusUnresolvedAnalysisLocal *analysis_out);
static int write_unresolved_output_audit_local(void);
static int find_entry_index_by_file_id_local(
    uint32_t file_id,
    size_t *out_index);
static size_t reconcile_pending_output_queue_local(
    size_t max_candidates,
    int require_contextual,
    double deadline_seconds,
    int *out_exhausted,
    int *out_any_change,
    size_t *out_next_output_index);
static int hfsplus_create_extent_meter_local(void);
static int hfsplus_sequential_assembly_init_local(void);
static int hfsplus_write_extent_measurement_local(const char *status);

static uint16_t read_u16_be_local(const unsigned char *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static uint32_t read_u32_be_local(const unsigned char *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static uint64_t read_u64_be_local(const unsigned char *data)
{
    return ((uint64_t)read_u32_be_local(data) << 32) |
           (uint64_t)read_u32_be_local(data + 4U);
}

static uint32_t read_u32_le_local(const unsigned char *data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint16_t read_u16_le_local(const unsigned char *data)
{
    return (uint16_t)data[0] |
           (uint16_t)((uint16_t)data[1] << 8);
}

static uint64_t read_u64_le_local(const unsigned char *data)
{
    return (uint64_t)read_u32_le_local(data) |
           ((uint64_t)read_u32_le_local(data + 4U) << 32);
}

static void write_u16_le_local(unsigned char *data, uint16_t value)
{
    data[0] = (unsigned char)(value & 0xFFU);
    data[1] = (unsigned char)((value >> 8) & 0xFFU);
}

static void write_u32_le_local(unsigned char *data, uint32_t value)
{
    data[0] = (unsigned char)(value & 0xFFU);
    data[1] = (unsigned char)((value >> 8) & 0xFFU);
    data[2] = (unsigned char)((value >> 16) & 0xFFU);
    data[3] = (unsigned char)((value >> 24) & 0xFFU);
}

static void write_u64_le_local(unsigned char *data, uint64_t value)
{
    write_u32_le_local(data, (uint32_t)(value & 0xFFFFFFFFULL));
    write_u32_le_local(data + 4U, (uint32_t)((value >> 32) & 0xFFFFFFFFULL));
}

static int write_bytes_local(FILE *file, const void *buffer, size_t length)
{
    return file != NULL &&
           buffer != NULL &&
           length > 0U &&
           fwrite(buffer, 1U, length, file) == length;
}

static int write_u16_le_file_local(FILE *file, uint16_t value)
{
    unsigned char buffer[2];

    write_u16_le_local(buffer, value);
    return write_bytes_local(file, buffer, sizeof(buffer));
}

static int write_u32_le_file_local(FILE *file, uint32_t value)
{
    unsigned char buffer[4];

    write_u32_le_local(buffer, value);
    return write_bytes_local(file, buffer, sizeof(buffer));
}

static int write_u64_le_file_local(FILE *file, uint64_t value)
{
    unsigned char buffer[8];

    write_u64_le_local(buffer, value);
    return write_bytes_local(file, buffer, sizeof(buffer));
}

static int read_exact_local(FILE *file, void *buffer, size_t length)
{
    return file != NULL &&
           buffer != NULL &&
           length > 0U &&
           fread(buffer, 1U, length, file) == length;
}

static int ensure_parent_dirs_for_path_local(const char *path)
{
    char temp[HFSPLUS_PATH_MAX];
    char *cursor;

    if (path == NULL || path[0] == '\0' || strlen(path) >= sizeof(temp)) {
        return 0;
    }
    if (!fs_backend_output_path_write_guard_allows(path)) {
        log_error(
            "Refusing to create HFS+ output directories because the mounted output volume is not live: %s",
            path
        );
        return 0;
    }

    snprintf(temp, sizeof(temp), "%s", path);
    cursor = temp;

    while ((cursor = strchr(cursor + 1, '/')) != NULL) {
        *cursor = '\0';
        if (!fs_backend_output_path_write_guard_allows(temp)) {
            return 0;
        }
        if (mkdir(temp, 0777) != 0 && errno != EEXIST) {
            return 0;
        }
        *cursor = '/';
    }

    return 1;
}

static int ensure_directory_path_local(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    if (!fs_backend_output_path_write_guard_allows(path)) {
        log_error(
            "Refusing to create HFS+ output directory because the mounted output volume is not live: %s",
            path
        );
        return 0;
    }
    if (!ensure_parent_dirs_for_path_local(path)) {
        return 0;
    }
    if (mkdir(path, 0777) != 0 && errno != EEXIST) {
        return 0;
    }
    return mft_apply_output_owner_to_path(path);
}

static double monotonic_seconds_local(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + ((double)now.tv_nsec / 1000000000.0);
}

static size_t hfsplus_live_reconcile_batch_limit_local(void)
{
    return g_hfsplus_live_background_conservative
        ? HFSPLUS_LIVE_RECONCILE_CONSERVATIVE_BATCH_LIMIT
        : HFSPLUS_LIVE_RECONCILE_IDLE_BATCH_LIMIT;
}

static double hfsplus_live_reconcile_budget_seconds_local(void)
{
    return g_hfsplus_live_background_conservative
        ? HFSPLUS_LIVE_RECONCILE_CONSERVATIVE_BUDGET_SECONDS
        : HFSPLUS_LIVE_RECONCILE_IDLE_BUDGET_SECONDS;
}

static int hfsplus_live_reconcile_should_pause_local(double now)
{
    if (g_hfsplus_live_last_reconcile_at > 0.0 &&
        now - g_hfsplus_live_last_reconcile_at <
            HFSPLUS_LIVE_RECONCILE_MIN_INTERVAL_SECONDS) {
        return 1;
    }

    if (g_hfsplus_live_background_conservative &&
        g_hfsplus_live_last_foreground_activity_at > 0.0 &&
        now - g_hfsplus_live_last_foreground_activity_at <
            HFSPLUS_LIVE_RECONCILE_FOREGROUND_COOLDOWN_SECONDS) {
        return 1;
    }

    return 0;
}

static int hfsplus_should_defer_immediate_reconcile_local(double now)
{
    return g_hfsplus_live_background_conservative &&
           g_hfsplus_live_last_foreground_activity_at > 0.0 &&
           now - g_hfsplus_live_last_foreground_activity_at <
               HFSPLUS_LIVE_RECONCILE_FOREGROUND_COOLDOWN_SECONDS;
}

static int is_power_of_two_u32_local(uint32_t value)
{
    return value != 0U && (value & (value - 1U)) == 0U;
}

static int bytes_are_all_zero_local(const unsigned char *data, size_t length)
{
    size_t i;

    if (data == NULL) {
        return 1;
    }

    for (i = 0U; i < length; ++i) {
        if (data[i] != 0x00U) {
            return 0;
        }
    }

    return 1;
}

static int has_valid_sector_signature_local(const unsigned char *sector, size_t length)
{
    if (sector == NULL || length < HFSPLUS_SECTOR_SIZE) {
        return 0;
    }

    return sector[510] == 0x55U && sector[511] == 0xAAU;
}

static int read_bytes_at_local(
    FILE *input_file,
    uint64_t absolute_offset,
    void *buffer,
    size_t buffer_size
)
{
    if (input_file == NULL || buffer == NULL || buffer_size == 0U) {
        return 0;
    }
    if (absolute_offset > (uint64_t)LLONG_MAX) {
        return 0;
    }
    if (fseeko(input_file, (off_t)absolute_offset, SEEK_SET) != 0) {
        return 0;
    }

    return fread(buffer, 1, buffer_size, input_file) == buffer_size;
}

static int detect_source_size_local(const char *path, uint64_t *out_size)
{
    uint64_t size;

    if (out_size == NULL) {
        return 0;
    }

    *out_size = 0U;
    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    size = reader_detect_source_size(path);
    if (size == 0U) return 0;
    *out_size = size;
    return 1;
}

static size_t append_utf8_codepoint_local(
    char *out,
    size_t out_size,
    size_t pos,
    uint32_t codepoint
)
{
    if (out == NULL || out_size == 0U || pos >= out_size - 1U) {
        return pos;
    }

    if (codepoint <= 0x7FU) {
        out[pos++] = (char)codepoint;
    } else if (codepoint <= 0x7FFU && pos + 2U < out_size) {
        out[pos++] = (char)(0xC0U | (codepoint >> 6));
        out[pos++] = (char)(0x80U | (codepoint & 0x3FU));
    } else if (codepoint <= 0xFFFFU && pos + 3U < out_size) {
        out[pos++] = (char)(0xE0U | (codepoint >> 12));
        out[pos++] = (char)(0x80U | ((codepoint >> 6) & 0x3FU));
        out[pos++] = (char)(0x80U | (codepoint & 0x3FU));
    } else if (codepoint <= 0x10FFFFU && pos + 4U < out_size) {
        out[pos++] = (char)(0xF0U | (codepoint >> 18));
        out[pos++] = (char)(0x80U | ((codepoint >> 12) & 0x3FU));
        out[pos++] = (char)(0x80U | ((codepoint >> 6) & 0x3FU));
        out[pos++] = (char)(0x80U | (codepoint & 0x3FU));
    } else {
        out[pos++] = '_';
    }

    return pos;
}

static void utf16be_to_utf8_local(
    const unsigned char *in,
    size_t char_count,
    char *out,
    size_t out_size
)
{
    size_t i;
    size_t pos = 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }

    for (i = 0U; i < char_count && pos + 1U < out_size; ++i) {
        uint16_t ch;

        if (in == NULL) {
            break;
        }
        ch = read_u16_be_local(in + (i * 2U));
        if (ch == 0U) {
            /* HFS+ deliberately uses four leading NUL characters in the
             * private hard-link metadata directory name.  NUL cannot be
             * represented in a host pathname, but stopping here loses the
             * parent entirely and makes every iNode child look root-owned. */
            out[pos++] = '_';
            continue;
        }
        if (ch < 32U) {
            out[pos++] = '_';
        } else if (ch >= 0xD800U && ch <= 0xDBFFU) {
            if (i + 1U < char_count) {
                uint16_t low = read_u16_be_local(in + ((i + 1U) * 2U));

                if (low >= 0xDC00U && low <= 0xDFFFU) {
                    uint32_t codepoint =
                        0x10000U +
                        (((uint32_t)(ch - 0xD800U) << 10) |
                         (uint32_t)(low - 0xDC00U));
                    pos = append_utf8_codepoint_local(out, out_size, pos, codepoint);
                    ++i;
                } else {
                    out[pos++] = '_';
                }
            } else {
                out[pos++] = '_';
            }
        } else if (ch >= 0xDC00U && ch <= 0xDFFFU) {
            out[pos++] = '_';
        } else {
            pos = append_utf8_codepoint_local(out, out_size, pos, ch);
        }
    }

    out[pos] = '\0';
}

static int hfsplus_name_is_hardlink_metadata_directory_local(
    const unsigned char *utf16be,
    size_t char_count)
{
    static const char suffix[] = "HFS+ Private Data";
    size_t index;

    if (utf16be == NULL || char_count != 4U + sizeof(suffix) - 1U) return 0;
    for (index = 0U; index < 4U; ++index) {
        if (read_u16_be_local(utf16be + index * 2U) != 0U) return 0;
    }
    for (index = 0U; index < sizeof(suffix) - 1U; ++index) {
        if (read_u16_be_local(utf16be + (index + 4U) * 2U) !=
            (uint16_t)(unsigned char)suffix[index]) {
            return 0;
        }
    }
    return 1;
}

static void copy_text_bounded_local(char *out, size_t out_size, const char *text)
{
    size_t length;

    if (out == NULL || out_size == 0U) {
        return;
    }

    if (text == NULL) {
        out[0] = '\0';
        return;
    }

    length = strlen(text);
    if (length >= out_size) {
        length = out_size - 1U;
    }

    if (length > 0U) {
        memcpy(out, text, length);
    }
    out[length] = '\0';
}

void hfsplus_backend_set_output_dir(const char *output_dir)
{
    copy_text_bounded_local(
        g_hfsplus_output_dir,
        sizeof(g_hfsplus_output_dir),
        output_dir
    );
}

void hfsplus_backend_set_compact_metadata_preferred(int enabled)
{
    g_hfsplus_prefer_compact_metadata = enabled ? 1 : 0;
}

void hfsplus_backend_set_active_formats(const char *formats_csv)
{
    copy_text_bounded_local(
        g_hfsplus_active_formats,
        sizeof(g_hfsplus_active_formats),
        formats_csv
    );
}

void hfsplus_backend_set_assemble_all_catalog_files(int enabled)
{
    g_hfsplus_assemble_all_catalog_files = enabled ? 1 : 0;
}

static int hfsplus_name_compare_local(const void *left, const void *right)
{
    const char *const *a = (const char *const *)left;
    const char *const *b = (const char *const *)right;

    if (g_hfsplus_sort_case_sensitive) {
        return strcmp(*a, *b);
    }
    return strcasecmp(*a, *b);
}

static int hfsplus_id_index_compare_local(const void *left, const void *right)
{
    const HfsPlusIdIndexEntry *a = (const HfsPlusIdIndexEntry *)left;
    const HfsPlusIdIndexEntry *b = (const HfsPlusIdIndexEntry *)right;

    if (a->file_id < b->file_id) {
        return -1;
    }
    if (a->file_id > b->file_id) {
        return 1;
    }
    if (a->entry_index < b->entry_index) {
        return -1;
    }
    if (a->entry_index > b->entry_index) {
        return 1;
    }

    return 0;
}

static int hfsplus_offset_index_compare_local(const void *left, const void *right)
{
    const HfsPlusOffsetIndexEntry *a = (const HfsPlusOffsetIndexEntry *)left;
    const HfsPlusOffsetIndexEntry *b = (const HfsPlusOffsetIndexEntry *)right;

    if (a->abs_offset < b->abs_offset) {
        return -1;
    }
    if (a->abs_offset > b->abs_offset) {
        return 1;
    }
    if (a->entry_index < b->entry_index) {
        return -1;
    }
    if (a->entry_index > b->entry_index) {
        return 1;
    }

    return 0;
}

static int hfsplus_span_index_compare_local(const void *left, const void *right)
{
    const HfsPlusSpanIndexEntry *a = (const HfsPlusSpanIndexEntry *)left;
    const HfsPlusSpanIndexEntry *b = (const HfsPlusSpanIndexEntry *)right;

    if (a->start < b->start) {
        return -1;
    }
    if (a->start > b->start) {
        return 1;
    }
    if (a->end < b->end) {
        return -1;
    }
    if (a->end > b->end) {
        return 1;
    }
    if (a->entry_index < b->entry_index) {
        return -1;
    }
    if (a->entry_index > b->entry_index) {
        return 1;
    }

    return 0;
}

static int hfsplus_recovered_output_index_compare_local(
    const void *left,
    const void *right
)
{
    const HfsPlusRecoveredOutputIndexEntry *a =
        (const HfsPlusRecoveredOutputIndexEntry *)left;
    const HfsPlusRecoveredOutputIndexEntry *b =
        (const HfsPlusRecoveredOutputIndexEntry *)right;

    if (a->abs_offset < b->abs_offset) {
        return -1;
    }
    if (a->abs_offset > b->abs_offset) {
        return 1;
    }
    if (a->output_index < b->output_index) {
        return -1;
    }
    if (a->output_index > b->output_index) {
        return 1;
    }

    return 0;
}

static int hfsplus_names_equal_local(const char *left, const char *right, int case_sensitive)
{
    if (left == NULL || right == NULL) {
        return 0;
    }

    if (case_sensitive) {
        return strcmp(left, right) == 0;
    }
    return strcasecmp(left, right) == 0;
}

static int is_internal_hfsplus_root_name_local(const char *name)
{
    static const char private_dir_prefix[] = ".HFS+ Private Directory Data";
    size_t prefix_length;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }

    prefix_length = strlen(private_dir_prefix);
    if (strncmp(name, private_dir_prefix, prefix_length) != 0) {
        return 0;
    }

    return name[prefix_length] == '\0' || name[prefix_length] == '_';
}

static time_t hfsplus_seconds_to_unix_local(uint32_t hfs_seconds)
{
    if ((uint64_t)hfs_seconds <= HFSPLUS_HFS_EPOCH_DELTA) {
        return (time_t)0;
    }

    return (time_t)((uint64_t)hfs_seconds - HFSPLUS_HFS_EPOCH_DELTA);
}

static int file_exists_local(const char *path)
{
    struct stat st;

    return path != NULL && path[0] != '\0' && stat(path, &st) == 0;
}

static int ensure_directory_recursive_local(const char *path)
{
    char partial[HFSPLUS_PATH_MAX];
    size_t i;
    size_t length;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    if (!fs_backend_output_path_write_guard_allows(path)) {
        log_error(
            "Refusing to create HFS+ output directory because the mounted output volume is not live: %s",
            path
        );
        return 0;
    }

    length = strlen(path);
    if (length >= sizeof(partial)) {
        return 0;
    }

    snprintf(partial, sizeof(partial), "%s", path);
    for (i = 1U; i < length; ++i) {
        if (partial[i] != '/') {
            continue;
        }
        partial[i] = '\0';
        if (!fs_backend_output_path_write_guard_allows(partial)) {
            partial[i] = '/';
            return 0;
        }
        if (mkdir(partial, 0777) != 0 && errno != EEXIST) {
            partial[i] = '/';
            return 0;
        }
        partial[i] = '/';
    }

    if (mkdir(partial, 0777) != 0 && errno != EEXIST) {
        return 0;
    }

    return 1;
}

static void hfsplus_release_recovery_lock_local(void);

/*
 * One output run must have exactly one metadata writer.  HFS+ recovery writes
 * both a reconstructed tree and live state below the run directory; allowing
 * a second process to reuse that directory makes exFAT directory operations
 * contend heavily and produces misleading mixed progress.  The advisory lock is released
 * by the kernel even after SIGKILL, so a stale lock file never blocks a later
 * recovery.
 */
static int hfsplus_acquire_recovery_lock_local(void)
{
    char state_dir[HFSPLUS_PATH_MAX];
    char lock_path[HFSPLUS_PATH_MAX];
    int fd;

    if (g_hfsplus_recovery_lock_fd >= 0) {
        return 1;
    }
    if (g_hfsplus_output_dir[0] == '\0' ||
        snprintf(state_dir, sizeof(state_dir), "%s/%s", g_hfsplus_output_dir,
                 APP_STATE_DIR_NAME) >= (int)sizeof(state_dir) ||
        !ensure_directory_recursive_local(state_dir) ||
        snprintf(lock_path, sizeof(lock_path), "%s/hfsplus_recovery.lock",
                 state_dir) >= (int)sizeof(lock_path)) {
        log_error("HFS+ recovery could not prepare its exclusive run lock");
        return 0;
    }

    fd = open(lock_path, O_WRONLY | O_CREAT, 0600);
    if (fd < 0) {
        log_error("HFS+ recovery could not open run lock %s: %s", lock_path, strerror(errno));
        return 0;
    }
    {
        struct flock lock = {0};

        lock.l_type = F_WRLCK;
        lock.l_whence = SEEK_SET;
        if (fcntl(fd, F_SETLK, &lock) == 0) {
            g_hfsplus_recovery_lock_fd = fd;
        }
    }
    if (g_hfsplus_recovery_lock_fd < 0) {
        int lock_error = errno;

        close(fd);
        if (lock_error == EWOULDBLOCK || lock_error == EAGAIN) {
            log_error(
                "Another HFS+ recovery is already using this output run; refusing concurrent writers: %s",
                g_hfsplus_output_dir
            );
        } else {
            log_error("HFS+ recovery could not lock %s: %s", lock_path, strerror(lock_error));
        }
        return 0;
    }

    if (ftruncate(g_hfsplus_recovery_lock_fd, 0) != 0) {
        const int truncate_error = errno;

        log_error("HFS+ recovery could not reset run lock %s: %s",
                  lock_path,
                  strerror(truncate_error));
        hfsplus_release_recovery_lock_local();
        return 0;
    }
    if (dprintf(
        g_hfsplus_recovery_lock_fd,
        "pid=%ld\nsource=%s\n",
        (long)getpid(),
        g_hfsplus_source_path
    ) < 0) {
        const int write_error = errno;

        log_error("HFS+ recovery could not write run lock %s: %s",
                  lock_path,
                  strerror(write_error));
        hfsplus_release_recovery_lock_local();
        return 0;
    }
    return 1;
}

static void hfsplus_release_recovery_lock_local(void)
{
    if (g_hfsplus_recovery_lock_fd < 0) {
        return;
    }
    {
        struct flock lock = {0};

        lock.l_type = F_UNLCK;
        lock.l_whence = SEEK_SET;
        (void)fcntl(g_hfsplus_recovery_lock_fd, F_SETLK, &lock);
    }
    (void)close(g_hfsplus_recovery_lock_fd);
    g_hfsplus_recovery_lock_fd = -1;
}

static uint64_t hfsplus_progress_add_local(uint64_t left, uint64_t right)
{
    return right > UINT64_MAX - left ? UINT64_MAX : left + right;
}

static void hfsplus_progress_set_path_local(const char *path, uint64_t source_offset)
{
    size_t index;

    g_hfsplus_recovery_progress.current_source_offset = source_offset;
    snprintf(
        g_hfsplus_recovery_progress.current_path,
        sizeof(g_hfsplus_recovery_progress.current_path),
        "%s",
        path != NULL ? path : ""
    );
    for (index = 0U;
         g_hfsplus_recovery_progress.current_path[index] != '\0';
         ++index) {
        if (g_hfsplus_recovery_progress.current_path[index] == '\n' ||
            g_hfsplus_recovery_progress.current_path[index] == '\r') {
            g_hfsplus_recovery_progress.current_path[index] = ' ';
        }
    }
}

static void hfsplus_progress_publish_local(int force)
{
    HfsPlusRecoveryProgressLocal *progress = &g_hfsplus_recovery_progress;
    char state_dir[HFSPLUS_PATH_MAX];
    char state_path[HFSPLUS_PATH_MAX];
    char temp_path[HFSPLUS_PATH_MAX + 48U];
    FILE *state_file;
    int write_ok;
    double now = monotonic_seconds_local();
    double elapsed;
    double work_elapsed;
    double work_rate = 0.0;
    double byte_rate = 0.0;
    double eta_seconds = -1.0;
    double percent = 0.0;

    if (!force && progress->last_publish_at > 0.0 &&
        now - progress->last_publish_at < HFSPLUS_PROGRESS_PUBLISH_INTERVAL_SECONDS) {
        return;
    }
    if (g_hfsplus_output_dir[0] == '\0' ||
        snprintf(state_dir, sizeof(state_dir), "%s/%s", g_hfsplus_output_dir,
                 APP_STATE_DIR_NAME) >= (int)sizeof(state_dir) ||
        !ensure_directory_recursive_local(state_dir) ||
        snprintf(state_path, sizeof(state_path), "%s/hfsplus_recovery_progress.txt",
                 state_dir) >= (int)sizeof(state_path) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp.%ld", state_path,
                 (long)getpid()) >= (int)sizeof(temp_path)) {
        return;
    }

    elapsed = progress->started_at > 0.0 ? now - progress->started_at : 0.0;
    work_elapsed = progress->work_started_at > 0.0 ? now - progress->work_started_at : 0.0;
    if (progress->plan_ready && progress->work_total > 0U) {
        percent = 100.0 * (double)progress->work_completed /
                  (double)progress->work_total;
        if (percent > 100.0) {
            percent = 100.0;
        }
    }
    if (work_elapsed > 0.25) {
        work_rate = (double)progress->work_completed / work_elapsed;
        byte_rate = (double)progress->bytes_copied / work_elapsed;
        if (work_rate > 0.0 && progress->work_total > progress->work_completed) {
            eta_seconds = (double)(progress->work_total - progress->work_completed) /
                          work_rate;
        } else if (progress->work_total <= progress->work_completed) {
            eta_seconds = 0.0;
        }
    }

    state_file = fopen(temp_path, "wb");
    if (state_file == NULL) {
        return;
    }
    fprintf(state_file, "version=1\nbackend=hfsplus\nmode=folders\n");
    fprintf(state_file, "phase=%s\nactivity=%s\n",
            progress->phase != NULL ? progress->phase : "starting",
            progress->activity != NULL ? progress->activity : "Starting HFS+ recovery");
    fprintf(state_file, "plan_ready=%d\n", progress->plan_ready);
    fprintf(state_file, "work_completed=%llu\nwork_total=%llu\nprogress_percent=%.4f\n",
            (unsigned long long)progress->work_completed,
            (unsigned long long)progress->work_total,
            percent);
    fprintf(state_file, "files_total=%llu\nfiles_completed=%llu\nfiles_incomplete=%llu\nfiles_failed=%llu\n",
            (unsigned long long)progress->files_total,
            (unsigned long long)progress->files_completed,
            (unsigned long long)progress->files_incomplete,
            (unsigned long long)progress->files_failed);
    fprintf(state_file, "bytes_total=%llu\nbytes_written=%llu\nbytes_copied=%llu\n",
            (unsigned long long)progress->bytes_total,
            (unsigned long long)progress->bytes_written,
            (unsigned long long)progress->bytes_copied);
    fprintf(state_file, "directories_total=%llu\ndirectories_completed=%llu\n",
            (unsigned long long)progress->directories_total,
            (unsigned long long)progress->directories_completed);
    fprintf(state_file, "planning_entries_processed=%llu\nplanning_entries_total=%llu\n",
            (unsigned long long)progress->planning_entries_processed,
            (unsigned long long)progress->planning_entries_total);
    fprintf(state_file, "current_source_offset=%llu\ncurrent_path=%s\n",
            (unsigned long long)progress->current_source_offset,
            progress->current_path);
    fprintf(state_file, "elapsed_seconds=%.3f\nrecent_mib_per_sec=%.3f\neta_seconds=%.3f\n",
            elapsed, byte_rate / (1024.0 * 1024.0), eta_seconds);
    fprintf(state_file, "updated_unix=%lld\n", (long long)time(NULL));
    write_ok = fflush(state_file) == 0;
    if (fclose(state_file) != 0) {
        write_ok = 0;
    }
    if (!write_ok || rename(temp_path, state_path) != 0) {
        unlink(temp_path);
        return;
    }
    progress->last_publish_at = now;
}

static void write_tsv_text_local(FILE *file, const char *text_value)
{
    const unsigned char *cursor = (const unsigned char *)(text_value != NULL ? text_value : "");

    while (*cursor != '\0') {
        unsigned char value = *cursor++;

        fputc(value == '\t' || value == '\n' || value == '\r' ? ' ' : value, file);
    }
}

static void append_hfsplus_recovery_failure_local(
    const HfsPlusCatalogEntry *entry,
    const char *output_path,
    const HfsPlusRecoveryFailureLocal *failure
)
{
    char state_dir[HFSPLUS_PATH_MAX];
    char journal_path[HFSPLUS_PATH_MAX];
    struct stat existing;
    FILE *journal;
    int needs_header;

    if (failure != NULL && failure->reason != NULL &&
        strncmp(failure->reason, "source_read_", 12U) == 0 &&
        failure->requested_bytes > 0U) {
        uint64_t end_offset = UINT64_MAX - failure->source_offset <
                failure->requested_bytes
            ? UINT64_MAX
            : failure->source_offset + failure->requested_bytes;

        app_gui_note_trouble(
            failure->source_offset,
            end_offset,
            "read_fail"
        );
    }

    if (entry == NULL || failure == NULL || g_hfsplus_output_dir[0] == '\0' ||
        snprintf(state_dir, sizeof(state_dir), "%s/%s", g_hfsplus_output_dir,
                 APP_STATE_DIR_NAME) >= (int)sizeof(state_dir) ||
        !ensure_directory_recursive_local(state_dir) ||
        snprintf(journal_path, sizeof(journal_path),
                 "%s/hfsplus_recovery_failures.tsv", state_dir) >=
            (int)sizeof(journal_path)) {
        return;
    }
    needs_header = stat(journal_path, &existing) != 0 || existing.st_size == 0;
    journal = fopen(journal_path, "ab");
    if (journal == NULL) {
        return;
    }
    if (needs_header) {
        fputs(
            "unix_time\tcnid\treason\terrno\tsource_offset\trequested_bytes\tcompleted_bytes\tunreadable_bytes\trun_index\tlogical_size\trun_count\tcatalog_path\toutput_path\n",
            journal
        );
    }
    fprintf(
        journal,
        "%lld\t%u\t",
        (long long)time(NULL),
        entry->file_id
    );
    write_tsv_text_local(journal, failure->reason);
    fprintf(
        journal,
        "\t%d\t%llu\t%llu\t%llu\t%llu\t%zu\t%llu\t%zu\t",
        failure->error_code,
        (unsigned long long)failure->source_offset,
        (unsigned long long)failure->requested_bytes,
        (unsigned long long)failure->completed_bytes,
        (unsigned long long)failure->unreadable_bytes,
        failure->run_index,
        (unsigned long long)entry->data_size,
        entry->run_count
    );
    write_tsv_text_local(journal, entry->path);
    fputc('\t', journal);
    write_tsv_text_local(journal, output_path);
    fputc('\n', journal);
    (void)fflush(journal);
    (void)fsync(fileno(journal));
    (void)fclose(journal);
}

static const char *path_basename_local(const char *path)
{
    const char *basename;

    if (path == NULL) {
        return NULL;
    }

    basename = strrchr(path, '/');
    return (basename != NULL) ? (basename + 1) : path;
}

static const char *path_extension_local(const char *path)
{
    const char *basename;
    const char *dot;

    if (path == NULL) {
        return NULL;
    }

    basename = path_basename_local(path);
    dot = strrchr(basename, '.');
    if (dot == NULL || dot[1] == '\0') {
        return NULL;
    }

    return dot + 1;
}

static void copy_name_without_extension_local(
    const char *name,
    char *out,
    size_t out_size
)
{
    const char *dot;
    size_t length;

    if (out == NULL || out_size == 0U) {
        return;
    }

    out[0] = '\0';
    if (name == NULL) {
        return;
    }

    dot = strrchr(name, '.');
    if (dot == NULL || dot == name) {
        snprintf(out, out_size, "%s", name);
        return;
    }

    length = (size_t)(dot - name);
    if (length >= out_size) {
        length = out_size - 1U;
    }
    memcpy(out, name, length);
    out[length] = '\0';
}

static int extensions_are_same_recovery_family_local(const char *lhs, const char *rhs)
{
    if (lhs == NULL || rhs == NULL) {
        return 0;
    }
    if (strcasecmp(lhs, rhs) == 0) {
        return 1;
    }
    if ((strcasecmp(lhs, "jpg") == 0 && strcasecmp(rhs, "jpeg") == 0) ||
        (strcasecmp(lhs, "jpeg") == 0 && strcasecmp(rhs, "jpg") == 0)) {
        return 1;
    }
    if ((strcasecmp(lhs, "tif") == 0 && strcasecmp(rhs, "tiff") == 0) ||
        (strcasecmp(lhs, "tiff") == 0 && strcasecmp(rhs, "tif") == 0)) {
        return 1;
    }
    if ((strcasecmp(lhs, "mpg") == 0 && strcasecmp(rhs, "mpeg") == 0) ||
        (strcasecmp(lhs, "mpeg") == 0 && strcasecmp(rhs, "mpg") == 0)) {
        return 1;
    }

    return 0;
}

static void append_sanitized_visible_component_local(
    char *out,
    size_t out_size,
    size_t *io_length,
    const char *component
)
{
    size_t pos = io_length != NULL ? *io_length : 0U;
    size_t i;

    if (out == NULL || out_size == 0U || component == NULL) {
        return;
    }

    for (i = 0U; component[i] != '\0' && pos + 1U < out_size; ++i) {
        unsigned char ch = (unsigned char)component[i];

        if (ch < 32U || ch == '/' || ch == '\\' || ch == ':' || ch == '$' ||
            ch == '?' || ch == '*' || ch == '"' || ch == '<' || ch == '>' ||
            ch == '|') {
            out[pos++] = '_';
        } else {
            out[pos++] = (char)ch;
        }
    }

    out[pos] = '\0';
    if (io_length != NULL) {
        *io_length = pos;
    }
}

static int append_visible_recovery_relative_path_local(
    char *out,
    size_t out_size,
    const char *relative_path
)
{
    char segment[HFSPLUS_NAME_MAX];
    size_t out_len = 0U;
    size_t seg_len = 0U;
    const char *src;

    if (out == NULL || out_size == 0U) {
        return 0;
    }

    out[0] = '\0';
    if (relative_path == NULL) {
        return 1;
    }

    src = relative_path;
    while (*src == '/') {
        ++src;
    }

    while (*src != '\0') {
        if (*src == '/') {
            const char *visible;

            if (seg_len > 0U) {
                segment[seg_len] = '\0';
                visible = mft_visible_windows_component_name(segment);
                if (out_len > 0U) {
                    if (out_len + 1U >= out_size) {
                        return 0;
                    }
                    out[out_len++] = '/';
                    out[out_len] = '\0';
                }
                append_sanitized_visible_component_local(
                    out,
                    out_size,
                    &out_len,
                    visible
                );
                seg_len = 0U;
            }

            ++src;
            while (*src == '/') {
                ++src;
            }
            continue;
        }

        if (seg_len + 1U < sizeof(segment)) {
            segment[seg_len++] = *src;
        }
        ++src;
    }

    if (seg_len > 0U) {
        const char *visible;

        segment[seg_len] = '\0';
        visible = mft_visible_windows_component_name(segment);
        if (out_len > 0U) {
            if (out_len + 1U >= out_size) {
                return 0;
            }
            out[out_len++] = '/';
            out[out_len] = '\0';
        }
        append_sanitized_visible_component_local(
            out,
            out_size,
            &out_len,
            visible
        );
    }

    return 1;
}

static int build_output_path_from_relative_local(
    char *out_path,
    size_t out_size,
    const char *relative_path
)
{
    char visible_relative[HFSPLUS_PATH_MAX];
    char recovered_relative[HFSPLUS_PATH_MAX];

    if (out_path == NULL || out_size == 0U || relative_path == NULL) {
        return 0;
    }
    if (!append_visible_recovery_relative_path_local(
            visible_relative,
            sizeof(visible_relative),
            relative_path)) {
        return 0;
    }
    if (g_hfsplus_output_dir[0] == '\0') {
        return 0;
    }
    if (visible_relative[0] == '\0') {
        return snprintf(
                   out_path,
                   out_size,
                   "%s/%s",
                   g_hfsplus_output_dir,
                   APP_RECOVERED_DIR_NAME) < (int)out_size;
    }
    if (snprintf(
            recovered_relative,
            sizeof(recovered_relative),
            "%s/%s",
            APP_RECOVERED_DIR_NAME,
            visible_relative) >= (int)sizeof(recovered_relative)) {
        return 0;
    }

    return snprintf(
               out_path,
               out_size,
               "%s/%s",
               g_hfsplus_output_dir,
               recovered_relative) < (int)out_size;
}

static int build_unique_path_from_base_local(
    char *out_path,
    size_t out_size,
    const char *base_path,
    const char *current_path
)
{
    char candidate[HFSPLUS_PATH_MAX];
    const char *dot;
    int index = 1;

    if (out_path == NULL || out_size == 0U || base_path == NULL || base_path[0] == '\0') {
        return 0;
    }

    if ((current_path != NULL && strcmp(base_path, current_path) == 0) ||
        !file_exists_local(base_path)) {
        return snprintf(out_path, out_size, "%s", base_path) < (int)out_size;
    }

    dot = strrchr(base_path, '.');
    if (dot == NULL) {
        while (1) {
            if (snprintf(candidate, sizeof(candidate), "%s_%d", base_path, index) >=
                (int)sizeof(candidate)) {
                return 0;
            }
            if ((current_path != NULL && strcmp(candidate, current_path) == 0) ||
                !file_exists_local(candidate)) {
                return snprintf(out_path, out_size, "%s", candidate) < (int)out_size;
            }
            ++index;
        }
    }

    while (1) {
        size_t stem_len = (size_t)(dot - base_path);

        if (stem_len + 16U + strlen(dot) + 1U > sizeof(candidate)) {
            return 0;
        }
        memcpy(candidate, base_path, stem_len);
        candidate[stem_len] = '\0';
        if (snprintf(
                candidate + stem_len,
                sizeof(candidate) - stem_len,
                "_%d%s",
                index,
                dot) >= (int)(sizeof(candidate) - stem_len)) {
            return 0;
        }
        if ((current_path != NULL && strcmp(candidate, current_path) == 0) ||
            !file_exists_local(candidate)) {
            return snprintf(out_path, out_size, "%s", candidate) < (int)out_size;
        }
        ++index;
    }
}

static int build_unique_contextual_output_path_local(
    char *out_path,
    size_t out_size,
    const char *relative_path,
    const char *current_path
)
{
    char base[HFSPLUS_PATH_MAX];
    char conflict_safe[HFSPLUS_PATH_MAX];
    char parent_dir[HFSPLUS_PATH_MAX];
    char *last_slash;

    if (!build_output_path_from_relative_local(base, sizeof(base), relative_path) ||
        !mft_normalize_directory_conflicts_for_path(
            conflict_safe,
            sizeof(conflict_safe),
            base,
            0) ||
        !build_unique_path_from_base_local(
            out_path,
            out_size,
            conflict_safe,
            current_path)) {
        return 0;
    }

    snprintf(parent_dir, sizeof(parent_dir), "%s", out_path);
    last_slash = strrchr(parent_dir, '/');
    if (last_slash != NULL) {
        *last_slash = '\0';
        if (!ensure_directory_recursive_local(parent_dir)) {
            return 0;
        }
    }

    return 1;
}

static int build_unique_default_output_path_local(
    char *out_path,
    size_t out_size,
    const char *directory,
    const char *prefix,
    long long abs_offset,
    const char *extension,
    const char *current_path
)
{
    char base[HFSPLUS_PATH_MAX];

    if (out_path == NULL || out_size == 0U ||
        directory == NULL || prefix == NULL || extension == NULL) {
        return 0;
    }

    if (!ensure_directory_recursive_local(directory)) {
        return 0;
    }
    if (snprintf(
            base,
            sizeof(base),
            "%s/%s_%lld.%s",
            directory,
            prefix,
            abs_offset,
            extension) >= (int)sizeof(base)) {
        return 0;
    }

    return build_unique_path_from_base_local(out_path, out_size, base, current_path);
}

static int build_unique_flat_name_output_path_local(
    char *out_path,
    size_t out_size,
    const char *directory,
    const char *name,
    const char *extension,
    int force_extension,
    const char *current_path
)
{
    char visible_name[HFSPLUS_NAME_MAX];
    char stem[HFSPLUS_NAME_MAX];
    char base[HFSPLUS_PATH_MAX];
    size_t visible_length = 0U;

    if (out_path == NULL || out_size == 0U || directory == NULL || name == NULL) {
        return 0;
    }
    if (!ensure_directory_recursive_local(directory)) {
        return 0;
    }

    visible_name[0] = '\0';
    append_sanitized_visible_component_local(
        visible_name,
        sizeof(visible_name),
        &visible_length,
        mft_visible_windows_component_name(name)
    );
    if (visible_name[0] == '\0') {
        return 0;
    }

    if (!force_extension) {
        if (snprintf(base, sizeof(base), "%s/%s", directory, visible_name) >= (int)sizeof(base)) {
            return 0;
        }
        return build_unique_path_from_base_local(out_path, out_size, base, current_path);
    }

    copy_name_without_extension_local(visible_name, stem, sizeof(stem));
    if (stem[0] == '\0') {
        snprintf(stem, sizeof(stem), "%s", visible_name);
    }
    if (snprintf(base, sizeof(base), "%s/%s.%s", directory, stem, extension) >= (int)sizeof(base)) {
        return 0;
    }

    return build_unique_path_from_base_local(out_path, out_size, base, current_path);
}

static void parse_fork_data_local(
    const unsigned char *fork_base,
    HfsPlusForkDataLocal *out_fork
)
{
    size_t i;

    if (out_fork == NULL) {
        return;
    }

    memset(out_fork, 0, sizeof(*out_fork));
    if (fork_base == NULL) {
        return;
    }

    out_fork->logical_size = read_u64_be_local(fork_base);
    out_fork->total_blocks = read_u32_be_local(fork_base + 12U);
    for (i = 0U; i < HFSPLUS_EXTENT_COUNT; ++i) {
        const unsigned char *extent = fork_base + 16U + (i * 8U);

        out_fork->extents[i].start_block = read_u32_be_local(extent);
        out_fork->extents[i].block_count = read_u32_be_local(extent + 4U);
    }
}

static int copy_fork_from_volume_header_local(
    const unsigned char *header,
    size_t fork_offset,
    HfsPlusForkDataLocal *out_fork
)
{
    if (header == NULL || out_fork == NULL) {
        return 0;
    }

    if (fork_offset > HFSPLUS_VOLUME_HEADER_SIZE ||
        HFSPLUS_VOLUME_HEADER_SIZE - fork_offset < 80U) {
        return 0;
    }

    parse_fork_data_local(header + fork_offset, out_fork);
    return 1;
}

static int fork_extents_fit_volume_local(
    const HfsPlusForkDataLocal *fork_data,
    uint32_t total_blocks
)
{
    size_t i;

    if (fork_data == NULL) {
        return 0;
    }

    for (i = 0U; i < HFSPLUS_EXTENT_COUNT; ++i) {
        uint32_t start_block = fork_data->extents[i].start_block;
        uint32_t block_count = fork_data->extents[i].block_count;

        if (block_count == 0U) {
            continue;
        }
        if (start_block >= total_blocks) {
            return 0;
        }
        if (block_count > total_blocks - start_block) {
            return 0;
        }
    }

    return 1;
}

static int parse_hfsplus_volume_header_local(
    const unsigned char *header,
    uint64_t source_size,
    uint64_t container_offset,
    uint64_t volume_offset,
    int has_wrapper,
    HfsPlusBackendGeometry *out_geometry,
    HfsPlusForkDataLocal *out_catalog_fork
)
{
    uint16_t signature;
    uint16_t version;
    uint32_t block_size;
    uint32_t total_blocks;
    uint64_t volume_size;
    HfsPlusForkDataLocal catalog_fork = {0};

    if (header == NULL || out_geometry == NULL || out_catalog_fork == NULL) {
        return 0;
    }

    signature = read_u16_be_local(header);
    version = read_u16_be_local(header + 2U);
    if (signature != HFSPLUS_SIGNATURE && signature != HFSX_SIGNATURE) {
        return 0;
    }
    if ((signature == HFSPLUS_SIGNATURE && version != HFSPLUS_VERSION) ||
        (signature == HFSX_SIGNATURE && version != HFSX_VERSION)) {
        return 0;
    }

    block_size = read_u32_be_local(header + 40U);
    total_blocks = read_u32_be_local(header + 44U);
    if (!is_power_of_two_u32_local(block_size) ||
        block_size < HFSPLUS_SECTOR_SIZE ||
        total_blocks == 0U) {
        return 0;
    }

    volume_size = (uint64_t)block_size * (uint64_t)total_blocks;
    if (volume_size < HFSPLUS_VOLUME_HEADER_OFFSET + HFSPLUS_VOLUME_HEADER_SIZE) {
        return 0;
    }
    if (!copy_fork_from_volume_header_local(header, 272U, &catalog_fork)) {
        return 0;
    }
    if (catalog_fork.logical_size < HFSPLUS_BTREE_NODE_MIN ||
        catalog_fork.total_blocks == 0U ||
        !fork_extents_fit_volume_local(&catalog_fork, total_blocks)) {
        return 0;
    }

    memset(out_geometry, 0, sizeof(*out_geometry));
    out_geometry->source_size = source_size;
    out_geometry->container_offset = container_offset;
    out_geometry->volume_offset = volume_offset;
    out_geometry->volume_size = volume_size;
    out_geometry->catalog_logical_size = catalog_fork.logical_size;
    out_geometry->volume_uuid =
        ((uint64_t)read_u32_be_local(header + 100U) << 32) |
        (uint64_t)read_u32_be_local(header + 104U);
    out_geometry->block_size = block_size;
    out_geometry->total_blocks = total_blocks;
    out_geometry->catalog_total_blocks = catalog_fork.total_blocks;
    out_geometry->attributes = read_u32_be_local(header + 4U);
    out_geometry->journal_info_block = read_u32_be_local(header + 12U);
    out_geometry->modify_date_hfs = read_u32_be_local(header + 20U);
    out_geometry->write_count = read_u32_be_local(header + 68U);
    out_geometry->has_wrapper = has_wrapper;
    out_geometry->is_hfsx = (signature == HFSX_SIGNATURE);

    *out_catalog_fork = catalog_fork;
    return 1;
}

static int hfsplus_geometry_is_truncated_local(
    const HfsPlusBackendGeometry *geometry
)
{
    if (geometry == NULL ||
        geometry->source_size == 0U ||
        geometry->volume_size == 0U) {
        return 0;
    }
    if (geometry->volume_offset >= geometry->source_size) {
        return 1;
    }

    return geometry->volume_size > (geometry->source_size - geometry->volume_offset);
}

static int try_read_hfsplus_volume_at_local(
    FILE *input_file,
    uint64_t source_size,
    uint64_t container_offset,
    uint64_t volume_offset,
    int has_wrapper,
    HfsPlusBackendGeometry *out_geometry,
    HfsPlusForkDataLocal *out_catalog_fork
)
{
    unsigned char volume_header[HFSPLUS_VOLUME_HEADER_SIZE];

    if (source_size != 0U &&
        volume_offset + HFSPLUS_VOLUME_HEADER_OFFSET + sizeof(volume_header) > source_size) {
        return 0;
    }
    if (!read_bytes_at_local(
            input_file,
            volume_offset + HFSPLUS_VOLUME_HEADER_OFFSET,
            volume_header,
            sizeof(volume_header))) {
        return 0;
    }

    return parse_hfsplus_volume_header_local(
        volume_header,
        source_size,
        container_offset,
        volume_offset,
        has_wrapper,
        out_geometry,
        out_catalog_fork);
}

static int try_probe_candidate_offset_local(
    FILE *input_file,
    uint64_t source_size,
    uint64_t candidate_offset,
    HfsPlusBackendGeometry *out_geometry,
    HfsPlusForkDataLocal *out_catalog_fork
)
{
    unsigned char mdb[HFSPLUS_VOLUME_HEADER_SIZE];
    uint16_t wrapper_signature;
    uint16_t embedded_signature;
    uint32_t wrapper_block_size;
    uint16_t wrapper_first_block;
    uint16_t embedded_start_block;
    uint64_t embedded_volume_offset;

    if (try_read_hfsplus_volume_at_local(
            input_file,
            source_size,
            candidate_offset,
            candidate_offset,
            0,
            out_geometry,
            out_catalog_fork)) {
        return 1;
    }

    if (source_size != 0U &&
        candidate_offset + HFSPLUS_VOLUME_HEADER_OFFSET + sizeof(mdb) > source_size) {
        return 0;
    }
    if (!read_bytes_at_local(
            input_file,
            candidate_offset + HFSPLUS_VOLUME_HEADER_OFFSET,
            mdb,
            sizeof(mdb))) {
        return 0;
    }

    wrapper_signature = read_u16_be_local(mdb);
    embedded_signature = read_u16_be_local(mdb + 124U);
    wrapper_block_size = read_u32_be_local(mdb + 20U);
    wrapper_first_block = read_u16_be_local(mdb + 28U);
    embedded_start_block = read_u16_be_local(mdb + 126U);

    if (wrapper_signature != HFS_WRAPPER_SIGNATURE ||
        (embedded_signature != HFSPLUS_SIGNATURE && embedded_signature != HFSX_SIGNATURE) ||
        wrapper_block_size == 0U) {
        return 0;
    }

    embedded_volume_offset =
        candidate_offset +
        ((uint64_t)wrapper_first_block * HFSPLUS_SECTOR_SIZE) +
        ((uint64_t)embedded_start_block * (uint64_t)wrapper_block_size);

    return try_read_hfsplus_volume_at_local(
        input_file,
        source_size,
        candidate_offset,
        embedded_volume_offset,
        1,
        out_geometry,
        out_catalog_fork);
}

static int prefer_hfsplus_candidate_local(
    const HfsPlusBackendGeometry *candidate,
    const HfsPlusBackendGeometry *best
)
{
    int candidate_truncated;
    int best_truncated;

    if (candidate == NULL) {
        return 0;
    }
    if (best == NULL || best->block_size == 0U) {
        return 1;
    }
    candidate_truncated = hfsplus_geometry_is_truncated_local(candidate);
    best_truncated = hfsplus_geometry_is_truncated_local(best);
    if (candidate_truncated != best_truncated) {
        return best_truncated;
    }
    if (candidate->volume_size != best->volume_size) {
        return candidate->volume_size > best->volume_size;
    }
    if (candidate->has_wrapper != best->has_wrapper) {
        return candidate->has_wrapper < best->has_wrapper;
    }
    return candidate->volume_offset < best->volume_offset;
}

static int find_gpt_hfsplus_volume_local(
    FILE *input_file,
    uint64_t source_size,
    HfsPlusBackendGeometry *out_geometry,
    HfsPlusForkDataLocal *out_catalog_fork
)
{
    unsigned char gpt_header[HFSPLUS_SECTOR_SIZE];
    unsigned char *partition_table = NULL;
    uint64_t entries_lba;
    uint64_t entries_offset;
    uint64_t table_bytes;
    uint64_t table_read_bytes;
    uint32_t entry_count;
    uint32_t entry_size;
    uint32_t i;
    int found = 0;
    HfsPlusBackendGeometry best_geometry = {0};
    HfsPlusForkDataLocal best_catalog_fork = {0};

    if (input_file == NULL || out_geometry == NULL || out_catalog_fork == NULL) {
        return 0;
    }
    if (!read_bytes_at_local(input_file, HFSPLUS_SECTOR_SIZE, gpt_header, sizeof(gpt_header))) {
        return 0;
    }
    if (memcmp(gpt_header, "EFI PART", 8) != 0) {
        return 0;
    }

    entries_lba = read_u64_le_local(gpt_header + 72U);
    entry_count = read_u32_le_local(gpt_header + 80U);
    entry_size = read_u32_le_local(gpt_header + 84U);
    if (entries_lba == 0U || entry_count == 0U) {
        return 0;
    }
    if (entry_size < GPT_PARTITION_ENTRY_MIN || entry_size > GPT_PARTITION_ENTRY_MAX) {
        return 0;
    }
    if (entry_count > GPT_PARTITION_ENTRY_LIMIT) {
        entry_count = GPT_PARTITION_ENTRY_LIMIT;
    }

    if (entries_lba > UINT64_MAX / HFSPLUS_SECTOR_SIZE ||
        entry_count > UINT64_MAX / entry_size ||
        ((uint64_t)entry_count * (uint64_t)entry_size) >
            UINT64_MAX - (HFSPLUS_SECTOR_SIZE - 1U)) {
        return 0;
    }
    entries_offset = entries_lba * HFSPLUS_SECTOR_SIZE;
    table_bytes = (uint64_t)entry_count * (uint64_t)entry_size;
    table_read_bytes =
        (table_bytes + (HFSPLUS_SECTOR_SIZE - 1U)) &
        ~((uint64_t)HFSPLUS_SECTOR_SIZE - 1U);
    if (table_read_bytes == 0U || table_read_bytes > SIZE_MAX) {
        return 0;
    }
    partition_table = (unsigned char *)malloc((size_t)table_read_bytes);
    if (partition_table == NULL ||
        !read_bytes_at_local(
            input_file,
            entries_offset,
            partition_table,
            (size_t)table_read_bytes)) {
        free(partition_table);
        return 0;
    }

    for (i = 0U; i < entry_count; ++i) {
        const unsigned char *partition_entry =
            partition_table + ((size_t)i * (size_t)entry_size);
        HfsPlusBackendGeometry candidate_geometry = {0};
        HfsPlusForkDataLocal candidate_catalog_fork = {0};
        uint64_t first_lba;
        uint64_t last_lba;
        uint64_t candidate_offset;
        if (bytes_are_all_zero_local(partition_entry, 16U)) {
            continue;
        }

        first_lba = read_u64_le_local(partition_entry + 32U);
        last_lba = read_u64_le_local(partition_entry + 40U);
        if (first_lba == 0U || last_lba < first_lba) {
            continue;
        }

        candidate_offset = first_lba * HFSPLUS_SECTOR_SIZE;
        if (!try_probe_candidate_offset_local(
                input_file,
                source_size,
                candidate_offset,
                &candidate_geometry,
                &candidate_catalog_fork)) {
            continue;
        }

        if (!found || prefer_hfsplus_candidate_local(&candidate_geometry, &best_geometry)) {
            best_geometry = candidate_geometry;
            best_catalog_fork = candidate_catalog_fork;
            found = 1;
        }
    }

    free(partition_table);
    if (!found) {
        return 0;
    }

    *out_geometry = best_geometry;
    *out_catalog_fork = best_catalog_fork;
    return 1;
}

static int find_mbr_hfsplus_volume_local(
    FILE *input_file,
    uint64_t source_size,
    HfsPlusBackendGeometry *out_geometry,
    HfsPlusForkDataLocal *out_catalog_fork
)
{
    unsigned char mbr[HFSPLUS_SECTOR_SIZE];
    int i;
    int found = 0;
    HfsPlusBackendGeometry best_geometry = {0};
    HfsPlusForkDataLocal best_catalog_fork = {0};

    if (input_file == NULL || out_geometry == NULL || out_catalog_fork == NULL) {
        return 0;
    }
    if (!read_bytes_at_local(input_file, 0U, mbr, sizeof(mbr)) ||
        !has_valid_sector_signature_local(mbr, sizeof(mbr))) {
        return 0;
    }

    for (i = 0; i < 4; ++i) {
        const unsigned char *entry = mbr + 446U + ((size_t)i * 16U);
        uint8_t partition_type = entry[4];
        uint32_t start_lba = read_u32_le_local(entry + 8U);
        uint32_t sector_count = read_u32_le_local(entry + 12U);
        uint64_t candidate_offset;
        HfsPlusBackendGeometry candidate_geometry = {0};
        HfsPlusForkDataLocal candidate_catalog_fork = {0};

        if (partition_type == 0x00U || partition_type == 0xEEU ||
            start_lba == 0U || sector_count == 0U) {
            continue;
        }

        candidate_offset = (uint64_t)start_lba * HFSPLUS_SECTOR_SIZE;
        if (!try_probe_candidate_offset_local(
                input_file,
                source_size,
                candidate_offset,
                &candidate_geometry,
                &candidate_catalog_fork)) {
            continue;
        }

        if (!found || prefer_hfsplus_candidate_local(&candidate_geometry, &best_geometry)) {
            best_geometry = candidate_geometry;
            best_catalog_fork = candidate_catalog_fork;
            found = 1;
        }
    }

    if (!found) {
        return 0;
    }

    *out_geometry = best_geometry;
    *out_catalog_fork = best_catalog_fork;
    return 1;
}

static void free_resolved_fork_local(HfsPlusResolvedForkLocal *fork_data)
{
    if (fork_data == NULL) {
        return;
    }

    free(fork_data->extents);
    memset(fork_data, 0, sizeof(*fork_data));
}

static int append_resolved_extent_local(
    HfsPlusResolvedForkLocal *fork_data,
    uint32_t start_block,
    uint32_t block_count
)
{
    HfsPlusExtentDescriptorLocal *expanded;
    size_t new_count;

    if (fork_data == NULL || block_count == 0U) {
        return 0;
    }
    if (fork_data->extent_count >= HFSPLUS_MAX_FORK_EXTENTS) {
        return 0;
    }
    if (start_block >= g_hfsplus_geometry.total_blocks ||
        block_count > g_hfsplus_geometry.total_blocks - start_block) {
        return 0;
    }

    new_count = fork_data->extent_count + 1U;
    expanded = (HfsPlusExtentDescriptorLocal *)realloc(
        fork_data->extents,
        new_count * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    fork_data->extents = expanded;
    fork_data->extents[fork_data->extent_count].start_block = start_block;
    fork_data->extents[fork_data->extent_count].block_count = block_count;
    fork_data->extent_count = new_count;
    return 1;
}

static int hfsplus_overflow_record_compare_local(const void *left, const void *right)
{
    const HfsPlusExtentOverflowRecordLocal *a =
        (const HfsPlusExtentOverflowRecordLocal *)left;
    const HfsPlusExtentOverflowRecordLocal *b =
        (const HfsPlusExtentOverflowRecordLocal *)right;

    if (a->file_id < b->file_id) {
        return -1;
    }
    if (a->file_id > b->file_id) {
        return 1;
    }
    if (a->fork_type < b->fork_type) {
        return -1;
    }
    if (a->fork_type > b->fork_type) {
        return 1;
    }
    if (a->start_block < b->start_block) {
        return -1;
    }
    if (a->start_block > b->start_block) {
        return 1;
    }
    return 0;
}

static int ensure_overflow_record_capacity_local(size_t needed)
{
    HfsPlusExtentOverflowRecordLocal *expanded;
    size_t new_capacity =
        g_hfsplus_overflow_record_capacity == 0U ? 128U : g_hfsplus_overflow_record_capacity;

    if (needed <= g_hfsplus_overflow_record_capacity) {
        return 1;
    }
    if (needed > HFSPLUS_MAX_OVERFLOW_RECORDS) {
        return 0;
    }
    while (new_capacity < needed) {
        new_capacity *= 2U;
        if (new_capacity > HFSPLUS_MAX_OVERFLOW_RECORDS) {
            new_capacity = HFSPLUS_MAX_OVERFLOW_RECORDS;
            break;
        }
    }

    expanded = (HfsPlusExtentOverflowRecordLocal *)realloc(
        g_hfsplus_overflow_records,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_hfsplus_overflow_records = expanded;
    g_hfsplus_overflow_record_capacity = new_capacity;
    return 1;
}

static int append_overflow_record_local(const HfsPlusExtentOverflowRecordLocal *record)
{
    if (record == NULL) {
        return 0;
    }
    if (!ensure_overflow_record_capacity_local(g_hfsplus_overflow_record_count + 1U)) {
        return 0;
    }

    g_hfsplus_overflow_records[g_hfsplus_overflow_record_count] = *record;
    g_hfsplus_overflow_record_count++;
    return 1;
}

static const HfsPlusExtentOverflowRecordLocal *find_overflow_record_local(
    uint8_t fork_type,
    uint32_t file_id,
    uint32_t start_block
)
{
    HfsPlusExtentOverflowRecordLocal key;
    const HfsPlusExtentOverflowRecordLocal *match;

    if (g_hfsplus_overflow_records == NULL || g_hfsplus_overflow_record_count == 0U) {
        return NULL;
    }

    memset(&key, 0, sizeof(key));
    key.fork_type = fork_type;
    key.file_id = file_id;
    key.start_block = start_block;
    match = (const HfsPlusExtentOverflowRecordLocal *)bsearch(
        &key,
        g_hfsplus_overflow_records,
        g_hfsplus_overflow_record_count,
        sizeof(*g_hfsplus_overflow_records),
        hfsplus_overflow_record_compare_local
    );

    return match;
}

static int materialize_fork_local(
    uint8_t fork_type,
    uint32_t file_id,
    const HfsPlusForkDataLocal *fork_data,
    HfsPlusResolvedForkLocal *out_fork
)
{
    uint64_t covered_blocks = 0U;
    size_t i;

    if (fork_data == NULL || out_fork == NULL) {
        return 0;
    }

    free_resolved_fork_local(out_fork);
    out_fork->logical_size = fork_data->logical_size;
    out_fork->total_blocks = fork_data->total_blocks;

    for (i = 0U; i < HFSPLUS_EXTENT_COUNT; ++i) {
        const HfsPlusExtentDescriptorLocal *extent = &fork_data->extents[i];

        if (extent->block_count == 0U) {
            continue;
        }
        if (extent->start_block >= g_hfsplus_geometry.total_blocks ||
            extent->block_count > g_hfsplus_geometry.total_blocks - extent->start_block) {
            out_fork->truncated = 1;
            return 1;
        }
        if (covered_blocks > UINT32_MAX - extent->block_count ||
            covered_blocks + extent->block_count > (uint64_t)fork_data->total_blocks) {
            out_fork->truncated = 1;
            return 1;
        }
        if (!append_resolved_extent_local(
                out_fork,
                extent->start_block,
                extent->block_count)) {
            return 0;
        }
        covered_blocks += extent->block_count;
    }

    while (covered_blocks < (uint64_t)fork_data->total_blocks) {
        const HfsPlusExtentOverflowRecordLocal *record;
        uint64_t before_record_blocks = covered_blocks;

        if (!g_hfsplus_overflow_loaded || covered_blocks > UINT32_MAX) {
            out_fork->truncated = 1;
            break;
        }

        record = find_overflow_record_local(
            fork_type,
            file_id,
            (uint32_t)covered_blocks
        );
        if (record == NULL) {
            out_fork->truncated = 1;
            break;
        }

        out_fork->overflow_used = 1;
        for (i = 0U; i < HFSPLUS_EXTENT_COUNT; ++i) {
            const HfsPlusExtentDescriptorLocal *extent = &record->extents[i];

            if (extent->block_count == 0U) {
                continue;
            }
            if (extent->start_block >= g_hfsplus_geometry.total_blocks ||
                extent->block_count > g_hfsplus_geometry.total_blocks - extent->start_block) {
                out_fork->truncated = 1;
                break;
            }
            if (covered_blocks > UINT32_MAX - extent->block_count ||
                covered_blocks + extent->block_count > (uint64_t)fork_data->total_blocks) {
                out_fork->truncated = 1;
                break;
            }
            if (!append_resolved_extent_local(
                    out_fork,
                    extent->start_block,
                    extent->block_count)) {
                return 0;
            }
            covered_blocks += extent->block_count;
        }

        if (covered_blocks == before_record_blocks || out_fork->truncated) {
            out_fork->truncated = 1;
            break;
        }
    }

    if (out_fork->logical_size > 0U &&
        (out_fork->extent_count == 0U ||
         covered_blocks < (uint64_t)fork_data->total_blocks)) {
        out_fork->truncated = 1;
    }

    return 1;
}

static int read_extent_mapped_bytes_local(
    FILE *input_file,
    const HfsPlusBackendGeometry *geometry,
    const HfsPlusExtentDescriptorLocal *extents,
    size_t extent_count,
    uint64_t logical_size,
    uint64_t logical_offset,
    void *buffer,
    size_t buffer_size
)
{
    unsigned char *out = (unsigned char *)buffer;
    uint64_t fork_cursor = 0U;
    size_t remaining = buffer_size;
    size_t i;

    if (input_file == NULL || geometry == NULL || extents == NULL ||
        buffer == NULL || buffer_size == 0U) {
        return 0;
    }
    if (logical_offset > logical_size ||
        buffer_size > (size_t)(logical_size - logical_offset)) {
        return 0;
    }

    for (i = 0U; i < extent_count && remaining > 0U; ++i) {
        const HfsPlusExtentDescriptorLocal *extent = &extents[i];
        uint64_t extent_length;
        uint64_t extent_end;
        uint64_t within_extent;
        uint64_t read_now;
        uint64_t extent_base_offset;
        uint64_t absolute_offset;

        if (extent->block_count == 0U) {
            continue;
        }

        extent_length =
            (uint64_t)extent->block_count * (uint64_t)geometry->block_size;
        if (extent_length == 0U ||
            fork_cursor > UINT64_MAX - extent_length) {
            return 0;
        }
        extent_end = fork_cursor + extent_length;
        if (logical_offset >= extent_end) {
            fork_cursor = extent_end;
            continue;
        }

        within_extent =
            logical_offset > fork_cursor ? logical_offset - fork_cursor : 0U;
        read_now = extent_length - within_extent;
        if (read_now > (uint64_t)remaining) {
            read_now = (uint64_t)remaining;
        }

        extent_base_offset =
            (uint64_t)extent->start_block * (uint64_t)geometry->block_size;
        if (geometry->volume_offset > UINT64_MAX - extent_base_offset) {
            return 0;
        }
        absolute_offset = geometry->volume_offset + extent_base_offset;
        if (absolute_offset > UINT64_MAX - within_extent) {
            return 0;
        }
        absolute_offset += within_extent;

        if (!read_bytes_at_local(
                input_file,
                absolute_offset,
                out,
                (size_t)read_now)) {
            return 0;
        }

        out += (size_t)read_now;
        remaining -= (size_t)read_now;
        logical_offset += read_now;
        fork_cursor = extent_end;
    }

    return remaining == 0U;
}

static int read_inline_fork_bytes_local(
    FILE *input_file,
    const HfsPlusBackendGeometry *geometry,
    const HfsPlusForkDataLocal *fork_data,
    uint64_t logical_offset,
    void *buffer,
    size_t buffer_size
)
{
    if (fork_data == NULL) {
        return 0;
    }

    return read_extent_mapped_bytes_local(
        input_file,
        geometry,
        fork_data->extents,
        HFSPLUS_EXTENT_COUNT,
        fork_data->logical_size,
        logical_offset,
        buffer,
        buffer_size
    );
}

static int read_resolved_fork_bytes_local(
    FILE *input_file,
    const HfsPlusBackendGeometry *geometry,
    const HfsPlusResolvedForkLocal *fork_data,
    uint64_t logical_offset,
    void *buffer,
    size_t buffer_size
)
{
    if (fork_data == NULL || fork_data->extents == NULL || fork_data->extent_count == 0U) {
        return 0;
    }

    return read_extent_mapped_bytes_local(
        input_file,
        geometry,
        fork_data->extents,
        fork_data->extent_count,
        fork_data->logical_size,
        logical_offset,
        buffer,
        buffer_size
    );
}

static int populate_btree_header_local(
    const unsigned char *header_prefix,
    HfsPlusBTreeHeaderLocal *out_header
)
{
    uint16_t node_size;
    uint32_t total_nodes;
    int8_t node_kind;

    if (header_prefix == NULL || out_header == NULL) {
        return 0;
    }

    node_kind = (int8_t)header_prefix[8];
    node_size = read_u16_be_local(header_prefix + 32U);
    total_nodes = read_u32_be_local(header_prefix + 36U);
    if (node_kind != HFSPLUS_BT_HEADER_NODE ||
        !is_power_of_two_u32_local(node_size) ||
        node_size < HFSPLUS_BTREE_NODE_MIN ||
        node_size > HFSPLUS_BTREE_NODE_MAX ||
        total_nodes == 0U) {
        return 0;
    }

    memset(out_header, 0, sizeof(*out_header));
    out_header->first_leaf_node = read_u32_be_local(header_prefix + 24U);
    out_header->last_leaf_node = read_u32_be_local(header_prefix + 28U);
    out_header->root_node = read_u32_be_local(header_prefix + 16U);
    out_header->leaf_records = read_u32_be_local(header_prefix + 20U);
    out_header->node_size = node_size;
    out_header->total_nodes = total_nodes;
    out_header->free_nodes = read_u32_be_local(header_prefix + 40U);
    out_header->key_compare_type = header_prefix[47];
    if (out_header->free_nodes > out_header->total_nodes ||
        (out_header->root_node != 0U &&
         out_header->root_node >= out_header->total_nodes) ||
        (out_header->first_leaf_node != 0U &&
         out_header->first_leaf_node >= out_header->total_nodes) ||
        (out_header->last_leaf_node != 0U &&
         out_header->last_leaf_node >= out_header->total_nodes)) {
        return 0;
    }
    return 1;
}

static int load_btree_header_from_inline_fork_local(
    FILE *input_file,
    const HfsPlusBackendGeometry *geometry,
    const HfsPlusForkDataLocal *fork_data,
    HfsPlusBTreeHeaderLocal *out_header
)
{
    unsigned char header_prefix[128];

    if (input_file == NULL || geometry == NULL || fork_data == NULL || out_header == NULL) {
        return 0;
    }
    if (!read_inline_fork_bytes_local(
            input_file,
            geometry,
            fork_data,
            0U,
            header_prefix,
            sizeof(header_prefix))) {
        return 0;
    }

    return populate_btree_header_local(header_prefix, out_header);
}

static int load_btree_header_from_resolved_fork_local(
    FILE *input_file,
    const HfsPlusBackendGeometry *geometry,
    const HfsPlusResolvedForkLocal *fork_data,
    HfsPlusBTreeHeaderLocal *out_header
)
{
    unsigned char header_prefix[128];

    if (input_file == NULL || geometry == NULL || fork_data == NULL || out_header == NULL) {
        return 0;
    }
    if (!read_resolved_fork_bytes_local(
            input_file,
            geometry,
            fork_data,
            0U,
            header_prefix,
            sizeof(header_prefix))) {
        return 0;
    }

    return populate_btree_header_local(header_prefix, out_header);
}

static int read_btree_record_offset_local(
    const unsigned char *node,
    uint16_t node_size,
    uint16_t num_records,
    uint16_t offset_index,
    uint16_t *out_offset
)
{
    size_t byte_offset;
    size_t offset_table_bytes;

    if (node == NULL || out_offset == NULL || offset_index > num_records) {
        return 0;
    }

    offset_table_bytes = (size_t)(2U * ((size_t)offset_index + 1U));
    if (offset_table_bytes > (size_t)node_size) {
        return 0;
    }

    byte_offset = (size_t)node_size - offset_table_bytes;
    *out_offset = read_u16_be_local(node + byte_offset);
    return 1;
}

static int btree_record_bounds_local(
    const unsigned char *node,
    uint16_t node_size,
    uint16_t num_records,
    uint16_t record_index,
    uint16_t *start_out,
    uint16_t *end_out)
{
    uint16_t start;
    uint16_t end;

    if (record_index >= num_records || start_out == NULL || end_out == NULL ||
        !read_btree_record_offset_local(
            node, node_size, num_records, record_index, &start)) {
        return 0;
    }
    if (record_index + 1U < num_records) {
        if (!read_btree_record_offset_local(
                node, node_size, num_records,
                (uint16_t)(record_index + 1U), &end)) {
            return 0;
        }
    } else if (!read_btree_record_offset_local(
                   node, node_size, num_records, num_records, &end)) {
        return 0;
    }
    if (start < 14U || end <= start || end > node_size) return 0;
    *start_out = start;
    *end_out = end;
    return 1;
}

static int catalog_node_is_allocated_local(
    const unsigned char *bitmap,
    size_t bitmap_bytes,
    uint32_t node_number);

static int load_catalog_node_bitmap_local(
    FILE *input_file,
    const HfsPlusBTreeHeaderLocal *header,
    unsigned char **bitmap_out,
    size_t *bitmap_bytes_out)
{
    unsigned char *bitmap = NULL;
    unsigned char *node = NULL;
    size_t wanted_bytes;
    size_t copied = 0U;
    uint32_t map_node = 0U;
    uint32_t visited = 0U;
    uint32_t allocated_nodes = 0U;
    uint32_t node_index;
    uint16_t num_records;
    uint16_t start;
    uint16_t end;

    if (bitmap_out != NULL) *bitmap_out = NULL;
    if (bitmap_bytes_out != NULL) *bitmap_bytes_out = 0U;
    if (input_file == NULL || header == NULL || bitmap_out == NULL ||
        bitmap_bytes_out == NULL || header->total_nodes == 0U) return 0;
    wanted_bytes = ((size_t)header->total_nodes + 7U) / 8U;
    bitmap = (unsigned char *)calloc(wanted_bytes, 1U);
    node = (unsigned char *)malloc(header->node_size);
    if (bitmap == NULL || node == NULL) goto failed;
    if (!read_resolved_fork_bytes_local(
            input_file,
            &g_hfsplus_geometry,
            &g_hfsplus_catalog_resolved_fork,
            0U,
            node,
            header->node_size) ||
        (int8_t)node[8] != HFSPLUS_BT_HEADER_NODE) {
        goto failed;
    }
    num_records = read_u16_be_local(node + 10U);
    if (num_records < 3U ||
        !btree_record_bounds_local(
            node, header->node_size, num_records, 2U, &start, &end)) {
        goto failed;
    }
    {
        size_t available = (size_t)end - (size_t)start;
        size_t take = available < wanted_bytes ? available : wanted_bytes;
        memcpy(bitmap, node + start, take);
        copied = take;
    }
    map_node = read_u32_be_local(node);
    while (copied < wanted_bytes && map_node != 0U &&
           map_node < header->total_nodes && visited < header->total_nodes) {
        size_t available;
        size_t take;

        if (!read_resolved_fork_bytes_local(
                input_file,
                &g_hfsplus_geometry,
                &g_hfsplus_catalog_resolved_fork,
                (uint64_t)map_node * (uint64_t)header->node_size,
                node,
                header->node_size) ||
            (int8_t)node[8] != HFSPLUS_BT_MAP_NODE) {
            goto failed;
        }
        num_records = read_u16_be_local(node + 10U);
        if (num_records < 1U ||
            !btree_record_bounds_local(
                node, header->node_size, num_records, 0U, &start, &end)) {
            goto failed;
        }
        available = (size_t)end - (size_t)start;
        take = available < wanted_bytes - copied
            ? available : wanted_bytes - copied;
        memcpy(bitmap + copied, node + start, take);
        copied += take;
        map_node = read_u32_be_local(node);
        visited++;
    }
    free(node);
    if (copied < wanted_bytes || (bitmap[0] & 0x80U) == 0U) {
        free(bitmap);
        return 0;
    }
    for (node_index = 0U; node_index < header->total_nodes; ++node_index) {
        size_t byte_index = (size_t)node_index / 8U;
        unsigned int bit_index = (unsigned int)node_index % 8U;
        if ((bitmap[byte_index] & (unsigned char)(0x80U >> bit_index)) != 0U) {
            allocated_nodes++;
        }
    }
    if (allocated_nodes != header->total_nodes - header->free_nodes ||
        (header->root_node != 0U &&
         !catalog_node_is_allocated_local(
             bitmap, wanted_bytes, header->root_node)) ||
        (header->first_leaf_node != 0U &&
         !catalog_node_is_allocated_local(
             bitmap, wanted_bytes, header->first_leaf_node)) ||
        (header->last_leaf_node != 0U &&
         !catalog_node_is_allocated_local(
             bitmap, wanted_bytes, header->last_leaf_node))) {
        free(bitmap);
        return 0;
    }
    *bitmap_out = bitmap;
    *bitmap_bytes_out = wanted_bytes;
    return 1;

failed:
    free(node);
    free(bitmap);
    return 0;
}

static int catalog_node_is_allocated_local(
    const unsigned char *bitmap,
    size_t bitmap_bytes,
    uint32_t node_number)
{
    size_t byte_index = (size_t)node_number / 8U;
    unsigned int bit_index = (unsigned int)node_number % 8U;

    if (bitmap == NULL || byte_index >= bitmap_bytes) return 1;
    return (bitmap[byte_index] & (unsigned char)(0x80U >> bit_index)) != 0U;
}

static int read_special_fork_from_source_local(
    FILE *input_file,
    const HfsPlusBackendGeometry *geometry,
    size_t fork_offset,
    HfsPlusForkDataLocal *out_fork
)
{
    unsigned char volume_header[HFSPLUS_VOLUME_HEADER_SIZE];

    if (input_file == NULL || geometry == NULL || out_fork == NULL) {
        return 0;
    }
    if (!read_bytes_at_local(
            input_file,
            geometry->volume_offset + HFSPLUS_VOLUME_HEADER_OFFSET,
            volume_header,
            sizeof(volume_header))) {
        return 0;
    }
    if (!copy_fork_from_volume_header_local(volume_header, fork_offset, out_fork)) {
        return 0;
    }
    if (out_fork->total_blocks > 0U &&
        !fork_extents_fit_volume_local(out_fork, geometry->total_blocks)) {
        return 0;
    }

    return 1;
}

static int load_extents_overflow_records_local(FILE *input_file)
{
    HfsPlusBTreeHeaderLocal header = {0};
    unsigned char *node = NULL;
    uint32_t current_leaf_node;
    uint32_t visited_nodes = 0U;

    free(g_hfsplus_overflow_records);
    g_hfsplus_overflow_records = NULL;
    g_hfsplus_overflow_record_count = 0U;
    g_hfsplus_overflow_record_capacity = 0U;
    g_hfsplus_overflow_loaded = 0;
    memset(&g_hfsplus_extents_fork, 0, sizeof(g_hfsplus_extents_fork));

    if (input_file == NULL) {
        return 0;
    }
    if (!read_special_fork_from_source_local(
            input_file,
            &g_hfsplus_geometry,
            192U,
            &g_hfsplus_extents_fork)) {
        return 0;
    }
    if (g_hfsplus_extents_fork.logical_size < HFSPLUS_BTREE_NODE_MIN ||
        g_hfsplus_extents_fork.total_blocks == 0U) {
        return 0;
    }
    if (!load_btree_header_from_inline_fork_local(
            input_file,
            &g_hfsplus_geometry,
            &g_hfsplus_extents_fork,
            &header)) {
        return 0;
    }

    node = (unsigned char *)malloc(header.node_size);
    if (node == NULL) {
        return 0;
    }

    current_leaf_node = header.first_leaf_node;
    while (current_leaf_node != 0U && visited_nodes < header.total_nodes) {
        uint16_t num_records;
        uint16_t free_space_offset;
        uint32_t next_leaf_node;
        size_t record_index;

        if (!read_inline_fork_bytes_local(
                input_file,
                &g_hfsplus_geometry,
                &g_hfsplus_extents_fork,
                (uint64_t)current_leaf_node * (uint64_t)header.node_size,
                node,
                header.node_size)) {
            free(node);
            return 0;
        }
        if ((int8_t)node[8] != HFSPLUS_BT_LEAF_NODE) {
            free(node);
            return 0;
        }

        num_records = read_u16_be_local(node + 10U);
        if (((size_t)num_records + 1U) * 2U > (size_t)header.node_size) {
            free(node);
            return 0;
        }
        if (!read_btree_record_offset_local(
                node,
                header.node_size,
                num_records,
                num_records,
                &free_space_offset)) {
            free(node);
            return 0;
        }
        if (free_space_offset > header.node_size) {
            free(node);
            return 0;
        }
        next_leaf_node = read_u32_be_local(node);

        for (record_index = 0U; record_index < (size_t)num_records; ++record_index) {
            uint16_t record_start;
            uint16_t record_end;
            uint16_t key_length;
            size_t data_offset;
            HfsPlusExtentOverflowRecordLocal record;
            size_t extent_index;

            if (!read_btree_record_offset_local(
                    node,
                    header.node_size,
                    num_records,
                    (uint16_t)record_index,
                    &record_start)) {
                free(node);
                return 0;
            }
            if (record_index + 1U < (size_t)num_records) {
                if (!read_btree_record_offset_local(
                        node,
                        header.node_size,
                        num_records,
                        (uint16_t)(record_index + 1U),
                        &record_end)) {
                    free(node);
                    return 0;
                }
            } else {
                record_end = free_space_offset;
            }

            if (record_start < 14U ||
                record_end <= record_start ||
                record_end > header.node_size) {
                continue;
            }

            key_length = read_u16_be_local(node + record_start);
            if (key_length < 10U || record_start + 2U + key_length > record_end) {
                continue;
            }

            data_offset = (size_t)record_start + 2U + (size_t)key_length;
            if ((data_offset & 1U) != 0U) {
                ++data_offset;
            }
            if (data_offset + (HFSPLUS_EXTENT_COUNT * 8U) > (size_t)record_end) {
                continue;
            }

            memset(&record, 0, sizeof(record));
            record.fork_type = node[record_start + 2U];
            record.file_id = read_u32_be_local(node + record_start + 4U);
            record.start_block = read_u32_be_local(node + record_start + 8U);
            if (record.file_id == 0U ||
                (record.fork_type != HFSPLUS_FORK_TYPE_DATA &&
                 record.fork_type != HFSPLUS_FORK_TYPE_RESOURCE)) {
                continue;
            }

            for (extent_index = 0U; extent_index < HFSPLUS_EXTENT_COUNT; ++extent_index) {
                const unsigned char *extent = node + data_offset + (extent_index * 8U);

                record.extents[extent_index].start_block = read_u32_be_local(extent);
                record.extents[extent_index].block_count = read_u32_be_local(extent + 4U);
            }

            if (!append_overflow_record_local(&record)) {
                free(node);
                return 0;
            }
        }

        ++visited_nodes;
        if (current_leaf_node == header.last_leaf_node) {
            break;
        }
        current_leaf_node = next_leaf_node;
    }

    free(node);
    if (g_hfsplus_overflow_record_count > 1U) {
        qsort(
            g_hfsplus_overflow_records,
            g_hfsplus_overflow_record_count,
            sizeof(*g_hfsplus_overflow_records),
            hfsplus_overflow_record_compare_local
        );
    }
    g_hfsplus_overflow_loaded = 1;
    return 1;
}

static void free_catalog_metadata_local(void)
{
    size_t entry_index;

    free_resolved_fork_local(&g_hfsplus_catalog_resolved_fork);

    for (entry_index = 0U; entry_index < g_hfsplus_entry_count; ++entry_index) {
        free(g_hfsplus_entries[entry_index].extra_runs);
        g_hfsplus_entries[entry_index].extra_runs = NULL;
        g_hfsplus_entries[entry_index].extra_run_count = 0U;
    }
    free(g_hfsplus_entries);
    g_hfsplus_entries = NULL;
    g_hfsplus_entry_count = 0U;
    g_hfsplus_entry_capacity = 0U;

    free(g_hfsplus_id_index);
    g_hfsplus_id_index = NULL;
    g_hfsplus_id_index_count = 0U;

    free_lookup_index_local();

    free(g_hfsplus_overflow_records);
    g_hfsplus_overflow_records = NULL;
    g_hfsplus_overflow_record_count = 0U;
    g_hfsplus_overflow_record_capacity = 0U;
    g_hfsplus_overflow_loaded = 0;

    g_hfsplus_catalog_loaded = 0;
}

static void free_orphan_catalog_local(void)
{
    free(g_hfsplus_orphan_records);
    free(g_hfsplus_historical_folders);
    free(g_hfsplus_orphan_strings);
    g_hfsplus_orphan_records = NULL;
    g_hfsplus_orphan_record_count = 0U;
    g_hfsplus_orphan_record_capacity = 0U;
    g_hfsplus_historical_folders = NULL;
    g_hfsplus_historical_folder_count = 0U;
    g_hfsplus_historical_folder_capacity = 0U;
    g_hfsplus_orphan_strings = NULL;
    g_hfsplus_orphan_string_bytes = 0U;
    g_hfsplus_orphan_string_capacity = 0U;
    g_hfsplus_orphan_nodes_scanned = 0ULL;
    g_hfsplus_orphan_free_nodes_scanned = 0ULL;
    g_hfsplus_orphan_slack_bytes_scanned = 0ULL;
    g_hfsplus_orphan_rejected_candidates = 0ULL;
    g_hfsplus_journal_offset = 0ULL;
    g_hfsplus_journal_size = 0ULL;
    g_hfsplus_journal_bytes_read = 0ULL;
    g_hfsplus_journal_header_candidates = 0ULL;
    g_hfsplus_journal_valid_transactions = 0ULL;
    g_hfsplus_journal_active_transactions = 0ULL;
    g_hfsplus_journal_checksum_rejections = 0ULL;
    g_hfsplus_journal_catalog_blocks = 0ULL;
    g_hfsplus_journal_catalog_records = 0ULL;
    g_hfsplus_journal_folder_records = 0ULL;
    g_hfsplus_journal_sequence = 0U;
    g_hfsplus_journal_header_checksum = 0U;
    g_hfsplus_journal_header_valid = 0;
    g_hfsplus_journal_little_endian = 0;
    g_hfsplus_journal_scan_attempted = 0;
    g_hfsplus_orphan_truncated = 0;
    g_hfsplus_orphan_ready = 0;
    g_hfsplus_journal_names_recovered_current = 0ULL;
}

static void close_compact_metadata_local(void)
{
    metadata_index_sequential_meter_destroy(g_hfsplus_extent_meter);
    g_hfsplus_extent_meter = NULL;
    metadata_index_reader_close(g_hfsplus_compact_reader);
    g_hfsplus_compact_reader = NULL;
    memset(&g_hfsplus_compact_stats, 0, sizeof(g_hfsplus_compact_stats));
    g_hfsplus_extent_meter_last_publish_at = 0.0;
    g_hfsplus_extent_meter_seeded_ranges = 0ULL;
    g_hfsplus_extent_meter_seeded_bytes = 0ULL;
    g_hfsplus_extent_measurement_completed = 0;
    g_hfsplus_compact_only = 0;
    g_hfsplus_shadow_index_ready = 0;
    free(g_hfsplus_assembly_fork_bytes);
    free(g_hfsplus_assembly_extent_prefix);
    free(g_hfsplus_assembly_fork_done);
    if (g_hfsplus_assembly_journal != NULL) {
        (void)fclose(g_hfsplus_assembly_journal);
    }
    g_hfsplus_assembly_fork_bytes = NULL;
    g_hfsplus_assembly_extent_prefix = NULL;
    g_hfsplus_assembly_fork_done = NULL;
    g_hfsplus_assembly_journal = NULL;
    g_hfsplus_assembly_fork_count = 0U;
    g_hfsplus_assembly_bytes_written = 0ULL;
    g_hfsplus_assembly_intersections = 0ULL;
    g_hfsplus_assembly_files_completed = 0ULL;
    g_hfsplus_assembly_write_failures = 0ULL;
    g_hfsplus_assembly_empty_files = 0ULL;
    g_hfsplus_assembly_empty_files_deferred = 0ULL;
    g_hfsplus_assembly_directories = 0ULL;
    g_hfsplus_assembly_hardlinks = 0ULL;
    g_hfsplus_assembly_inherited_generation = 0ULL;
    g_hfsplus_assembly_disabled = 0;
    g_hfsplus_assembly_parts_ready = 0;
}

static void free_catalog_state_local(void)
{
    free_catalog_metadata_local();
    free_recovered_outputs_local();
}

static int hfsplus_metadata_ready_local(void)
{
    return g_hfsplus_geometry.block_size != 0U &&
           (hfsplus_catalog_available_local() ||
            (g_hfsplus_compact_reader != NULL &&
             g_hfsplus_compact_stats.object_count > 0U));
}

static void hfsplus_reset_metadata_local(void)
{
    close_compact_metadata_local();
    free_catalog_metadata_local();
    free_orphan_catalog_local();
    memset(&g_hfsplus_geometry, 0, sizeof(g_hfsplus_geometry));
    memset(&g_hfsplus_catalog_fork, 0, sizeof(g_hfsplus_catalog_fork));
    memset(&g_hfsplus_extents_fork, 0, sizeof(g_hfsplus_extents_fork));
    g_hfsplus_source_hint[0] = '\0';
    g_hfsplus_source_path[0] = '\0';
    g_hfsplus_sort_case_sensitive = 0;
    g_hfsplus_photos_library_signal_logged = 0;
    g_hfsplus_shadow_index_ready = 0;
}

static void hfsplus_reset_globals_local(void)
{
    close_compact_metadata_local();
    free_catalog_state_local();
    free_orphan_catalog_local();
    memset(&g_hfsplus_geometry, 0, sizeof(g_hfsplus_geometry));
    memset(&g_hfsplus_catalog_fork, 0, sizeof(g_hfsplus_catalog_fork));
    memset(&g_hfsplus_extents_fork, 0, sizeof(g_hfsplus_extents_fork));
    g_hfsplus_source_hint[0] = '\0';
    g_hfsplus_source_path[0] = '\0';
    g_hfsplus_sort_case_sensitive = 0;
    g_hfsplus_live_renamed_outputs = 0ULL;
    g_hfsplus_live_embedded_moves = 0ULL;
    g_hfsplus_live_background_conservative = 0;
    g_hfsplus_live_last_foreground_activity_at = 0.0;
    g_hfsplus_live_last_reconcile_at = 0.0;
    g_hfsplus_live_last_rewrite_at = 0.0;
    g_hfsplus_finalize_budget_seconds = 0.0;
    g_hfsplus_finalize_budget_profile[0] = '\0';
    g_hfsplus_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;
    g_hfsplus_photos_library_signal_logged = 0;
    g_hfsplus_shadow_index_ready = 0;
}

static int ensure_entry_capacity_local(size_t needed)
{
    HfsPlusCatalogEntry *expanded;
    size_t new_capacity = g_hfsplus_entry_capacity == 0U ? 512U : g_hfsplus_entry_capacity;

    if (needed <= g_hfsplus_entry_capacity) {
        return 1;
    }
    while (new_capacity < needed) {
        new_capacity *= 2U;
    }

    expanded = (HfsPlusCatalogEntry *)realloc(
        g_hfsplus_entries,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_hfsplus_entries = expanded;
    g_hfsplus_entry_capacity = new_capacity;
    return 1;
}

static int ensure_recovered_output_capacity_local(size_t needed)
{
    HfsPlusRecoveredOutput *expanded;
    size_t new_capacity =
        g_hfsplus_recovered_output_capacity == 0U ? 256U : g_hfsplus_recovered_output_capacity;

    if (needed <= g_hfsplus_recovered_output_capacity) {
        return 1;
    }
    while (new_capacity < needed) {
        new_capacity *= 2U;
    }

    expanded = (HfsPlusRecoveredOutput *)realloc(
        g_hfsplus_recovered_outputs,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_hfsplus_recovered_outputs = expanded;
    g_hfsplus_recovered_output_capacity = new_capacity;
    return 1;
}

static int ensure_pending_output_flags_capacity_local(size_t needed)
{
    unsigned char *expanded;
    size_t new_capacity =
        g_hfsplus_pending_output_flags_capacity == 0U
            ? 256U
            : g_hfsplus_pending_output_flags_capacity;

    if (needed <= g_hfsplus_pending_output_flags_capacity) {
        return 1;
    }
    while (new_capacity < needed) {
        new_capacity *= 2U;
    }

    expanded = (unsigned char *)realloc(
        g_hfsplus_pending_output_flags,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    memset(
        expanded + g_hfsplus_pending_output_flags_capacity,
        0,
        new_capacity - g_hfsplus_pending_output_flags_capacity
    );
    g_hfsplus_pending_output_flags = expanded;
    g_hfsplus_pending_output_flags_capacity = new_capacity;
    return 1;
}

static size_t pending_output_queue_depth_local(void)
{
    if (g_hfsplus_pending_output_queue_count <= g_hfsplus_pending_output_queue_head) {
        return 0U;
    }

    return g_hfsplus_pending_output_queue_count - g_hfsplus_pending_output_queue_head;
}

static void compact_pending_output_queue_local(void)
{
    size_t remaining = pending_output_queue_depth_local();

    if (g_hfsplus_pending_output_queue_head == 0U) {
        return;
    }
    if (remaining > 0U) {
        memmove(
            g_hfsplus_pending_output_queue,
            g_hfsplus_pending_output_queue + g_hfsplus_pending_output_queue_head,
            remaining * sizeof(*g_hfsplus_pending_output_queue)
        );
    }
    g_hfsplus_pending_output_queue_head = 0U;
    g_hfsplus_pending_output_queue_count = remaining;
}

static void reset_pending_output_queue_local(void)
{
    if (g_hfsplus_pending_output_flags != NULL &&
        g_hfsplus_pending_output_flags_capacity > 0U) {
        memset(
            g_hfsplus_pending_output_flags,
            0,
            g_hfsplus_pending_output_flags_capacity
        );
    }
    g_hfsplus_pending_output_queue_head = 0U;
    g_hfsplus_pending_output_queue_count = 0U;
    g_hfsplus_live_reconcile_cursor = 0U;
}

static int ensure_pending_output_queue_capacity_local(size_t extra_slots)
{
    size_t needed;
    size_t new_capacity;
    size_t *expanded;

    if (extra_slots == 0U) {
        return 1;
    }
    if (pending_output_queue_depth_local() == 0U) {
        g_hfsplus_pending_output_queue_head = 0U;
        g_hfsplus_pending_output_queue_count = 0U;
    } else if (g_hfsplus_pending_output_queue_head > 0U &&
               g_hfsplus_pending_output_queue_count + extra_slots >
                   g_hfsplus_pending_output_queue_capacity) {
        compact_pending_output_queue_local();
    }

    if (g_hfsplus_pending_output_queue_count + extra_slots <=
        g_hfsplus_pending_output_queue_capacity) {
        return 1;
    }

    needed = g_hfsplus_pending_output_queue_count + extra_slots;
    new_capacity =
        g_hfsplus_pending_output_queue_capacity == 0U
            ? 256U
            : g_hfsplus_pending_output_queue_capacity;
    while (new_capacity < needed) {
        new_capacity *= 2U;
    }

    expanded = (size_t *)realloc(
        g_hfsplus_pending_output_queue,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_hfsplus_pending_output_queue = expanded;
    g_hfsplus_pending_output_queue_capacity = new_capacity;
    return 1;
}

static int ensure_recovered_output_index_capacity_local(size_t needed)
{
    HfsPlusRecoveredOutputIndexEntry *expanded;
    size_t new_capacity =
        g_hfsplus_recovered_output_index_capacity == 0U
            ? 512U
            : g_hfsplus_recovered_output_index_capacity;

    if (needed <= g_hfsplus_recovered_output_index_capacity) {
        return 1;
    }
    while (new_capacity < needed) {
        new_capacity *= 2U;
    }

    expanded = (HfsPlusRecoveredOutputIndexEntry *)realloc(
        g_hfsplus_recovered_output_index,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_hfsplus_recovered_output_index = expanded;
    g_hfsplus_recovered_output_index_capacity = new_capacity;
    return 1;
}

static int ensure_offset_index_capacity_local(size_t needed)
{
    HfsPlusOffsetIndexEntry *expanded;
    size_t new_capacity =
        g_hfsplus_offset_index_capacity == 0U ? 1024U : g_hfsplus_offset_index_capacity;

    if (needed <= g_hfsplus_offset_index_capacity) {
        return 1;
    }
    while (new_capacity < needed) {
        new_capacity *= 2U;
    }

    expanded = (HfsPlusOffsetIndexEntry *)realloc(
        g_hfsplus_offset_index,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_hfsplus_offset_index = expanded;
    g_hfsplus_offset_index_capacity = new_capacity;
    return 1;
}

static int ensure_span_index_capacity_local(size_t needed)
{
    HfsPlusSpanIndexEntry *expanded;
    size_t new_capacity =
        g_hfsplus_span_index_capacity == 0U ? 2048U : g_hfsplus_span_index_capacity;

    if (needed <= g_hfsplus_span_index_capacity) {
        return 1;
    }
    while (new_capacity < needed) {
        new_capacity *= 2U;
    }

    expanded = (HfsPlusSpanIndexEntry *)realloc(
        g_hfsplus_span_index,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_hfsplus_span_index = expanded;
    g_hfsplus_span_index_capacity = new_capacity;
    return 1;
}

static int populate_entry_runs_from_fork_local(
    HfsPlusCatalogEntry *entry,
    uint8_t fork_type,
    const HfsPlusForkDataLocal *fork_data
)
{
    HfsPlusResolvedForkLocal resolved_fork = {0};
    uint64_t remaining;
    size_t i;

    if (entry == NULL || fork_data == NULL) {
        return 0;
    }
    if (!materialize_fork_local(fork_type, entry->file_id, fork_data, &resolved_fork)) {
        log_info(
            "HFS+ could not materialize fork runs for file id %u (%s)",
            entry->file_id,
            entry->name[0] != '\0' ? entry->name : "unnamed"
        );
        return 0;
    }

    entry->data_size = resolved_fork.logical_size;
    entry->allocated_size = 0U;
    entry->run_count = 0U;
    free(entry->extra_runs);
    entry->extra_runs = NULL;
    entry->extra_run_count = 0U;
    entry->run_truncated = 0;
    entry->abs_offset = UINT64_MAX;
    entry->has_data = 0;
    remaining = resolved_fork.logical_size;

    for (i = 0U; i < resolved_fork.extent_count; ++i) {
        const HfsPlusExtentDescriptorLocal *extent = &resolved_fork.extents[i];
        uint64_t extent_length;
        uint64_t logical_bytes;

        if (extent->block_count == 0U) {
            continue;
        }
        extent_length =
            (uint64_t)extent->block_count * (uint64_t)g_hfsplus_geometry.block_size;
        entry->allocated_size += extent_length;

        if (remaining == 0U) {
            continue;
        }

        logical_bytes = remaining < extent_length ? remaining : extent_length;
        if (entry->run_count < MFT_VIEW_MAX_RUNS) {
            entry->runs[entry->run_count].abs_offset =
                g_hfsplus_geometry.volume_offset +
                ((uint64_t)extent->start_block * (uint64_t)g_hfsplus_geometry.block_size);
            entry->runs[entry->run_count].byte_length = logical_bytes;
        } else {
            size_t extra_index = entry->run_count - MFT_VIEW_MAX_RUNS;
            MftViewRun *expanded = (MftViewRun *)realloc(
                entry->extra_runs,
                (extra_index + 1U) * sizeof(*expanded)
            );

            if (expanded == NULL) {
                entry->run_truncated = 1;
                break;
            }
            entry->extra_runs = expanded;
            entry->extra_runs[extra_index].abs_offset =
                g_hfsplus_geometry.volume_offset +
                ((uint64_t)extent->start_block * (uint64_t)g_hfsplus_geometry.block_size);
            entry->extra_runs[extra_index].byte_length = logical_bytes;
            entry->extra_run_count = extra_index + 1U;
        }
        if (entry->abs_offset == UINT64_MAX) {
            entry->abs_offset =
                g_hfsplus_geometry.volume_offset +
                ((uint64_t)extent->start_block * (uint64_t)g_hfsplus_geometry.block_size);
        }
        entry->run_count++;
        remaining -= logical_bytes;
    }

    if (remaining > 0U || resolved_fork.truncated) {
        entry->run_truncated = 1;
    }
    entry->has_data = entry->run_count > 0U && entry->data_size > 0U;
    free_resolved_fork_local(&resolved_fork);
    return 1;
}

static const MftViewRun *catalog_entry_run_local(
    const HfsPlusCatalogEntry *entry,
    size_t run_index
)
{
    size_t extra_index;

    if (entry == NULL || run_index >= entry->run_count) {
        return NULL;
    }
    if (run_index < MFT_VIEW_MAX_RUNS) {
        return &entry->runs[run_index];
    }
    extra_index = run_index - MFT_VIEW_MAX_RUNS;
    if (extra_index >= entry->extra_run_count || entry->extra_runs == NULL) {
        return NULL;
    }
    return &entry->extra_runs[extra_index];
}

/* Return one effective recovery record per visible Catalog entry.  Resolved
 * indirect nodes are skipped because their visible hard-link placeholders
 * are recovered below using the indirect node's real fork/runlist. */
static int catalog_entry_for_recovery_local(
    const HfsPlusCatalogEntry *catalog_entry,
    HfsPlusCatalogEntry *materialized,
    const HfsPlusCatalogEntry **recovery_entry_out)
{
    size_t backing_index;

    if (recovery_entry_out != NULL) *recovery_entry_out = NULL;
    if (catalog_entry == NULL || materialized == NULL ||
        recovery_entry_out == NULL) {
        return -1;
    }
    if (catalog_entry->is_hardlink_inode && catalog_entry->hardlink_resolved) {
        return 0;
    }
    if (!catalog_entry->is_hardlink_placeholder) {
        *recovery_entry_out = catalog_entry;
        return 1;
    }
    if (catalog_entry->hardlink_backing_file_id == 0U ||
        !find_entry_index_by_file_id_local(
            catalog_entry->hardlink_backing_file_id,
            &backing_index) ||
        backing_index >= g_hfsplus_entry_count ||
        !g_hfsplus_entries[backing_index].is_hardlink_inode ||
        !g_hfsplus_entries[backing_index].has_data) {
        return -1;
    }
    *materialized = g_hfsplus_entries[backing_index];
    materialized->parent_id = catalog_entry->parent_id;
    copy_text_bounded_local(
        materialized->name,
        sizeof(materialized->name),
        catalog_entry->name);
    copy_text_bounded_local(
        materialized->path,
        sizeof(materialized->path),
        catalog_entry->path);
    materialized->has_name = catalog_entry->has_name;
    materialized->path_complete = catalog_entry->path_complete;
    materialized->hardlink_resolved = 1;
    *recovery_entry_out = materialized;
    return 1;
}

static int append_catalog_entry_local(const HfsPlusCatalogEntry *entry)
{
    if (entry == NULL) {
        return 0;
    }
    if (!ensure_entry_capacity_local(g_hfsplus_entry_count + 1U)) {
        return 0;
    }

    g_hfsplus_entries[g_hfsplus_entry_count] = *entry;
    g_hfsplus_entry_count++;
    return 1;
}

static void free_lookup_index_local(void)
{
    free(g_hfsplus_offset_index);
    g_hfsplus_offset_index = NULL;
    g_hfsplus_offset_index_count = 0U;
    g_hfsplus_offset_index_capacity = 0U;

    free(g_hfsplus_span_index);
    g_hfsplus_span_index = NULL;
    g_hfsplus_span_index_count = 0U;
    g_hfsplus_span_index_capacity = 0U;

    g_hfsplus_lookup_index_entry_count = (size_t)-1;
}

static void free_recovered_output_index_local(void)
{
    free(g_hfsplus_recovered_output_index);
    g_hfsplus_recovered_output_index = NULL;
    g_hfsplus_recovered_output_index_count = 0U;
    g_hfsplus_recovered_output_index_capacity = 0U;
    g_hfsplus_recovered_output_index_sorted_count = 0U;
    g_hfsplus_recovered_output_index_output_count = (size_t)-1;
    g_hfsplus_live_reconcile_cursor = 0U;
}

static void free_pending_output_queue_local(void)
{
    free(g_hfsplus_pending_output_queue);
    g_hfsplus_pending_output_queue = NULL;
    g_hfsplus_pending_output_queue_head = 0U;
    g_hfsplus_pending_output_queue_count = 0U;
    g_hfsplus_pending_output_queue_capacity = 0U;

    free(g_hfsplus_pending_output_flags);
    g_hfsplus_pending_output_flags = NULL;
    g_hfsplus_pending_output_flags_capacity = 0U;
}

static void free_recovered_outputs_local(void)
{
    free_recovered_output_index_local();
    free_pending_output_queue_local();
    free(g_hfsplus_recovered_outputs);
    g_hfsplus_recovered_outputs = NULL;
    g_hfsplus_recovered_output_count = 0U;
    g_hfsplus_recovered_output_capacity = 0U;
    g_hfsplus_reconciled_output_count = 0U;
    g_hfsplus_embedded_output_count = 0ULL;
    g_hfsplus_recovered_outputs_log_needs_rewrite = 0;
}

static void set_recovered_output_classification_local(
    size_t output_index,
    unsigned int classification)
{
    HfsPlusRecoveredOutput *output;
    unsigned int previous;

    if (output_index >= g_hfsplus_recovered_output_count) {
        return;
    }
    output = &g_hfsplus_recovered_outputs[output_index];
    previous = output->classification;
    if (previous == classification) {
        return;
    }
    if (previous == HFSPLUS_OUTPUT_CLASS_EMBEDDED &&
        g_hfsplus_embedded_output_count > 0ULL) {
        g_hfsplus_embedded_output_count--;
    }
    output->classification = classification;
    if (classification == HFSPLUS_OUTPUT_CLASS_EMBEDDED) {
        g_hfsplus_embedded_output_count++;
    }
}

static void set_recovered_output_reconciled_local(size_t output_index, int reconciled)
{
    HfsPlusRecoveredOutput *output;
    int old_reconciled;
    int new_reconciled = reconciled ? 1 : 0;

    if (output_index >= g_hfsplus_recovered_output_count) {
        return;
    }

    output = &g_hfsplus_recovered_outputs[output_index];
    old_reconciled = output->reconciled ? 1 : 0;
    if (old_reconciled == new_reconciled) {
        output->reconciled = new_reconciled;
        return;
    }

    if (old_reconciled) {
        if (g_hfsplus_reconciled_output_count > 0U) {
            g_hfsplus_reconciled_output_count--;
        }
    } else {
        g_hfsplus_reconciled_output_count++;
    }
    output->reconciled = new_reconciled;
}

static int enqueue_pending_output_local(size_t output_index)
{
    if (output_index >= g_hfsplus_recovered_output_count) {
        return 0;
    }
    if (g_hfsplus_recovered_outputs[output_index].reconciled) {
        return 1;
    }
    if (g_hfsplus_recovered_outputs[output_index].classification ==
        HFSPLUS_OUTPUT_CLASS_EMBEDDED) {
        return 1;
    }
    if (!ensure_pending_output_flags_capacity_local(output_index + 1U)) {
        return 0;
    }
    if (g_hfsplus_pending_output_flags[output_index] != 0U) {
        return 1;
    }
    if (!ensure_pending_output_queue_capacity_local(1U)) {
        return 0;
    }

    g_hfsplus_pending_output_queue[g_hfsplus_pending_output_queue_count] = output_index;
    g_hfsplus_pending_output_queue_count++;
    g_hfsplus_pending_output_flags[output_index] = 1U;
    g_hfsplus_live_reconcile_cursor = pending_output_queue_depth_local();
    return 1;
}

static void enqueue_unreconciled_outputs_from_local(size_t start_index)
{
    size_t i;

    if (start_index > g_hfsplus_recovered_output_count) {
        start_index = 0U;
    }
    for (i = start_index; i < g_hfsplus_recovered_output_count; ++i) {
        if (!g_hfsplus_recovered_outputs[i].reconciled &&
            g_hfsplus_recovered_outputs[i].classification !=
                HFSPLUS_OUTPUT_CLASS_EMBEDDED) {
            (void)enqueue_pending_output_local(i);
        }
    }
}

static void enqueue_all_unreconciled_outputs_local(void)
{
    enqueue_unreconciled_outputs_from_local(0U);
}

static int build_id_index_local(void)
{
    size_t i;
    HfsPlusIdIndexEntry *expanded;

    free(g_hfsplus_id_index);
    g_hfsplus_id_index = NULL;
    g_hfsplus_id_index_count = 0U;

    if (g_hfsplus_entry_count == 0U) {
        return 1;
    }

    expanded = (HfsPlusIdIndexEntry *)malloc(
        g_hfsplus_entry_count * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    for (i = 0U; i < g_hfsplus_entry_count; ++i) {
        expanded[i].file_id = g_hfsplus_entries[i].file_id;
        expanded[i].entry_index = i;
    }

    qsort(
        expanded,
        g_hfsplus_entry_count,
        sizeof(*expanded),
        hfsplus_id_index_compare_local
    );

    g_hfsplus_id_index = expanded;
    g_hfsplus_id_index_count = g_hfsplus_entry_count;
    return 1;
}

static int rebuild_lookup_index_local(void)
{
    size_t i;

    free_lookup_index_local();
    if (g_hfsplus_entry_count == 0U) {
        g_hfsplus_lookup_index_entry_count = 0U;
        return 1;
    }

    for (i = 0U; i < g_hfsplus_entry_count; ++i) {
        const HfsPlusCatalogEntry *entry = &g_hfsplus_entries[i];
        size_t run_index;

        if (!entry->has_data || entry->run_count == 0U) {
            continue;
        }

        if (!ensure_offset_index_capacity_local(g_hfsplus_offset_index_count + 1U)) {
            free_lookup_index_local();
            return 0;
        }
        g_hfsplus_offset_index[g_hfsplus_offset_index_count].abs_offset = entry->abs_offset;
        g_hfsplus_offset_index[g_hfsplus_offset_index_count].entry_index = i;
        g_hfsplus_offset_index_count++;

        for (run_index = 0U; run_index < entry->run_count; ++run_index) {
            const MftViewRun *run = catalog_entry_run_local(entry, run_index);
            uint64_t start;
            uint64_t length;
            uint64_t end;

            if (run == NULL) {
                continue;
            }
            start = run->abs_offset;
            length = run->byte_length;
            if (length == 0U) {
                continue;
            }

            end = start > UINT64_MAX - length ? UINT64_MAX : start + length;
            if (end <= start) {
                continue;
            }
            if (!ensure_span_index_capacity_local(g_hfsplus_span_index_count + 1U)) {
                free_lookup_index_local();
                return 0;
            }

            g_hfsplus_span_index[g_hfsplus_span_index_count].start = start;
            g_hfsplus_span_index[g_hfsplus_span_index_count].end = end;
            g_hfsplus_span_index[g_hfsplus_span_index_count].max_end_seen = end;
            g_hfsplus_span_index[g_hfsplus_span_index_count].entry_index = i;
            g_hfsplus_span_index_count++;
        }
    }

    if (g_hfsplus_offset_index_count > 1U) {
        qsort(
            g_hfsplus_offset_index,
            g_hfsplus_offset_index_count,
            sizeof(*g_hfsplus_offset_index),
            hfsplus_offset_index_compare_local
        );
    }
    if (g_hfsplus_span_index_count > 1U) {
        uint64_t max_end_seen = 0U;

        qsort(
            g_hfsplus_span_index,
            g_hfsplus_span_index_count,
            sizeof(*g_hfsplus_span_index),
            hfsplus_span_index_compare_local
        );
        for (i = 0U; i < g_hfsplus_span_index_count; ++i) {
            if (i == 0U || g_hfsplus_span_index[i].end > max_end_seen) {
                max_end_seen = g_hfsplus_span_index[i].end;
            }
            g_hfsplus_span_index[i].max_end_seen = max_end_seen;
        }
    }

    g_hfsplus_lookup_index_entry_count = g_hfsplus_entry_count;
    return 1;
}

static int ensure_lookup_index_current_local(void)
{
    if (g_hfsplus_lookup_index_entry_count == g_hfsplus_entry_count) {
        return 1;
    }

    return rebuild_lookup_index_local();
}

static size_t offset_index_lower_bound_local(uint64_t target)
{
    size_t low = 0U;
    size_t high = g_hfsplus_offset_index_count;

    while (low < high) {
        size_t mid = low + ((high - low) / 2U);

        if (g_hfsplus_offset_index[mid].abs_offset < target) {
            low = mid + 1U;
        } else {
            high = mid;
        }
    }

    return low;
}

static int find_entry_index_by_exact_offset_local(uint64_t target, size_t *out_index)
{
    size_t index;

    if (out_index != NULL) {
        *out_index = (size_t)-1;
    }
    if (!ensure_lookup_index_current_local() || g_hfsplus_offset_index_count == 0U) {
        return 0;
    }

    index = offset_index_lower_bound_local(target);
    if (index >= g_hfsplus_offset_index_count ||
        g_hfsplus_offset_index[index].abs_offset != target) {
        return 0;
    }

    if (out_index != NULL) {
        *out_index = g_hfsplus_offset_index[index].entry_index;
    }
    return 1;
}

static int rebuild_recovered_output_index_local(void)
{
    size_t i;

    free_recovered_output_index_local();
    if (g_hfsplus_recovered_output_count == 0U) {
        g_hfsplus_recovered_output_index_output_count = 0U;
        return 1;
    }
    if (!ensure_recovered_output_index_capacity_local(g_hfsplus_recovered_output_count)) {
        free_recovered_output_index_local();
        return 0;
    }

    for (i = 0U; i < g_hfsplus_recovered_output_count; ++i) {
        g_hfsplus_recovered_output_index[i].abs_offset =
            g_hfsplus_recovered_outputs[i].abs_offset;
        g_hfsplus_recovered_output_index[i].output_index = i;
    }
    g_hfsplus_recovered_output_index_count = g_hfsplus_recovered_output_count;

    if (g_hfsplus_recovered_output_index_count > 1U) {
        qsort(
            g_hfsplus_recovered_output_index,
            g_hfsplus_recovered_output_index_count,
            sizeof(*g_hfsplus_recovered_output_index),
            hfsplus_recovered_output_index_compare_local
        );
    }

    g_hfsplus_recovered_output_index_sorted_count = g_hfsplus_recovered_output_index_count;
    g_hfsplus_recovered_output_index_output_count = g_hfsplus_recovered_output_count;
    return 1;
}

static int append_recovered_output_index_entry_local(size_t output_index)
{
    if (output_index >= g_hfsplus_recovered_output_count) {
        return 0;
    }
    if (!ensure_recovered_output_index_capacity_local(
            g_hfsplus_recovered_output_index_count + 1U)) {
        return 0;
    }

    g_hfsplus_recovered_output_index[g_hfsplus_recovered_output_index_count].abs_offset =
        g_hfsplus_recovered_outputs[output_index].abs_offset;
    g_hfsplus_recovered_output_index[g_hfsplus_recovered_output_index_count].output_index =
        output_index;
    g_hfsplus_recovered_output_index_count++;
    g_hfsplus_recovered_output_index_output_count++;
    return 1;
}

static int ensure_recovered_output_index_current_local(void)
{
    size_t pending_count;

    if (g_hfsplus_recovered_output_index_output_count == (size_t)-1 ||
        g_hfsplus_recovered_output_index_output_count > g_hfsplus_recovered_output_count ||
        g_hfsplus_recovered_output_index_output_count > g_hfsplus_recovered_output_index_count) {
        return rebuild_recovered_output_index_local();
    }

    while (g_hfsplus_recovered_output_index_output_count < g_hfsplus_recovered_output_count) {
        if (!append_recovered_output_index_entry_local(
                g_hfsplus_recovered_output_index_output_count)) {
            free_recovered_output_index_local();
            return 0;
        }
    }

    pending_count =
        g_hfsplus_recovered_output_index_count - g_hfsplus_recovered_output_index_sorted_count;
    if (pending_count > HFSPLUS_RECOVERED_OUTPUT_INDEX_PENDING_LIMIT) {
        return rebuild_recovered_output_index_local();
    }

    return 1;
}

static size_t recovered_output_index_lower_bound_local(long long abs_offset)
{
    size_t low = 0U;
    size_t high = g_hfsplus_recovered_output_index_sorted_count;

    while (low < high) {
        size_t mid = low + ((high - low) / 2U);

        if (g_hfsplus_recovered_output_index[mid].abs_offset < abs_offset) {
            low = mid + 1U;
        } else {
            high = mid;
        }
    }

    return low;
}

static size_t span_index_upper_bound_local(uint64_t target)
{
    size_t low = 0U;
    size_t high = g_hfsplus_span_index_count;

    while (low < high) {
        size_t mid = low + ((high - low) / 2U);

        if (g_hfsplus_span_index[mid].start <= target) {
            low = mid + 1U;
        } else {
            high = mid;
        }
    }

    return low;
}

static int find_entry_index_by_span_local(uint64_t target, size_t *out_index)
{
    size_t best_index = (size_t)-1;
    size_t pos;

    if (out_index != NULL) {
        *out_index = (size_t)-1;
    }
    if (!ensure_lookup_index_current_local() || g_hfsplus_span_index_count == 0U) {
        return 0;
    }

    pos = span_index_upper_bound_local(target);

    /*
     * Once max_end_seen drops below the target we know no earlier span can
     * still overlap it, so the backward walk can stop there.
     */
    while (pos > 0U) {
        const HfsPlusSpanIndexEntry *span;

        pos--;
        span = &g_hfsplus_span_index[pos];
        if (span->max_end_seen <= target) {
            break;
        }
        if (span->start <= target &&
            target < span->end &&
            (best_index == (size_t)-1 || span->entry_index < best_index)) {
            best_index = span->entry_index;
        }
    }

    if (best_index == (size_t)-1) {
        return 0;
    }

    if (out_index != NULL) {
        *out_index = best_index;
    }
    return 1;
}

static int find_entry_index_by_file_id_local(uint32_t file_id, size_t *out_index)
{
    size_t lo = 0U;
    size_t hi = g_hfsplus_id_index_count;

    if (out_index != NULL) {
        *out_index = 0U;
    }
    if (g_hfsplus_id_index == NULL || g_hfsplus_id_index_count == 0U) {
        return 0;
    }

    while (lo < hi) {
        size_t mid = lo + ((hi - lo) / 2U);

        if (g_hfsplus_id_index[mid].file_id < file_id) {
            lo = mid + 1U;
        } else {
            hi = mid;
        }
    }

    if (lo >= g_hfsplus_id_index_count ||
        g_hfsplus_id_index[lo].file_id != file_id) {
        return 0;
    }

    if (out_index != NULL) {
        *out_index = g_hfsplus_id_index[lo].entry_index;
    }
    return 1;
}

static int resolve_entry_path_recursive_local(size_t entry_index, unsigned char *state)
{
    HfsPlusCatalogEntry *entry;
    size_t parent_index = 0U;

    if (entry_index >= g_hfsplus_entry_count || state == NULL) {
        return 0;
    }
    entry = &g_hfsplus_entries[entry_index];

    if (state[entry_index] == 2U) {
        return entry->path_complete;
    }
    if (state[entry_index] == 1U) {
        return 0;
    }

    state[entry_index] = 1U;
    entry->path[0] = '\0';
    entry->path_complete = 0;

    if (entry->file_id == HFSPLUS_ROOT_FOLDER_ID) {
        snprintf(entry->path, sizeof(entry->path), "%s", "/");
        entry->path_complete = 1;
        state[entry_index] = 2U;
        return 1;
    }

    if (!entry->has_name || entry->name[0] == '\0') {
        state[entry_index] = 2U;
        return 0;
    }

    if (entry->parent_id == HFSPLUS_ROOT_FOLDER_ID) {
        if (snprintf(entry->path, sizeof(entry->path), "/%s", entry->name) <
            (int)sizeof(entry->path)) {
            entry->path_complete = 1;
        }
        state[entry_index] = 2U;
        return entry->path_complete;
    }

    if (entry->parent_id != 0U &&
        entry->parent_id != entry->file_id &&
        find_entry_index_by_file_id_local(entry->parent_id, &parent_index) &&
        resolve_entry_path_recursive_local(parent_index, state) &&
        g_hfsplus_entries[parent_index].path_complete) {
        char parent_path[HFSPLUS_PATH_MAX];

        copy_text_bounded_local(
            parent_path,
            sizeof(parent_path),
            g_hfsplus_entries[parent_index].path
        );

        if (strcmp(parent_path, "/") == 0) {
            if (snprintf(entry->path, sizeof(entry->path), "/%s", entry->name) <
                (int)sizeof(entry->path)) {
                entry->path_complete = 1;
            }
        } else if (snprintf(
                       entry->path,
                       sizeof(entry->path),
                       "%s/%s",
                       parent_path,
                       entry->name) < (int)sizeof(entry->path)) {
            entry->path_complete = 1;
        }
    } else {
        (void)snprintf(entry->path, sizeof(entry->path), "/%s", entry->name);
    }

    state[entry_index] = 2U;
    return entry->path_complete;
}

static int resolve_all_entry_paths_local(void)
{
    unsigned char *state;
    size_t i;

    if (g_hfsplus_entry_count == 0U) {
        return 1;
    }

    state = (unsigned char *)calloc(g_hfsplus_entry_count, sizeof(*state));
    if (state == NULL) {
        return 0;
    }

    for (i = 0U; i < g_hfsplus_entry_count; ++i) {
        (void)resolve_entry_path_recursive_local(i, state);
    }

    free(state);
    return 1;
}

static int parse_hardlink_inode_name_local(
    const char *name,
    int allow_extension,
    uint32_t *reference_out)
{
    const char *cursor;
    uint64_t value = 0U;
    size_t digits = 0U;

    if (reference_out != NULL) *reference_out = 0U;
    if (name == NULL || strncasecmp(name, "iNode", 5U) != 0) return 0;
    cursor = name + 5U;
    while (*cursor >= '0' && *cursor <= '9') {
        unsigned int digit = (unsigned int)(*cursor - '0');

        if (value > (UINT32_MAX - digit) / 10U) return 0;
        value = value * 10U + digit;
        cursor++;
        digits++;
    }
    if (digits == 0U || value == 0U ||
        (*cursor != '\0' && !(allow_extension && *cursor == '.'))) {
        return 0;
    }
    if (reference_out != NULL) *reference_out = (uint32_t)value;
    return 1;
}

static int build_hardlink_orphan_relative_path_local(
    char *out,
    size_t out_size,
    uint32_t reference,
    const char *extension)
{
    uint32_t group = reference / 1000U;

    if (out == NULL || out_size == 0U || reference == 0U) return 0;
    return snprintf(
               out,
               out_size,
               "%s/HFS+ Hardlink Orphans/group_%06u/iNode%u%s%s",
               APP_UNIDENT_DIR_NAME,
               group,
               reference,
               extension != NULL && extension[0] != '\0' ? "." : "",
               extension != NULL ? extension : "") < (int)out_size;
}

static int path_is_unresolved_hardlink_inode_local(
    const char *path,
    uint32_t *reference_out)
{
    const char *basename;

    if (path == NULL ||
        strstr(path, "/" HFSPLUS_HARDLINK_PRIVATE_DIR_PORTABLE "/") == NULL) {
        return 0;
    }
    basename = path_basename_local(path);
    return parse_hardlink_inode_name_local(basename, 0, reference_out);
}

static int hardlink_alias_compare_local(const void *left, const void *right)
{
    const HfsPlusHardlinkAliasLocal *a =
        (const HfsPlusHardlinkAliasLocal *)left;
    const HfsPlusHardlinkAliasLocal *b =
        (const HfsPlusHardlinkAliasLocal *)right;
    const HfsPlusCatalogEntry *a_entry;
    const HfsPlusCatalogEntry *b_entry;
    size_t a_length;
    size_t b_length;
    int a_rank;
    int b_rank;

    if (a->reference != b->reference) {
        return a->reference < b->reference ? -1 : 1;
    }
    a_entry = &g_hfsplus_entries[a->entry_index];
    b_entry = &g_hfsplus_entries[b->entry_index];
    if (a_entry->path_complete != b_entry->path_complete) {
        return a_entry->path_complete ? -1 : 1;
    }
    a_rank = strncmp(a_entry->path, "/Users/", 7U) == 0
        ? 0
        : (strncmp(a_entry->path, "/System/", 8U) == 0 ||
           strncmp(a_entry->path, "/Library/", 9U) == 0 ||
           strncmp(a_entry->path, "/private/", 9U) == 0)
            ? 2
            : 1;
    b_rank = strncmp(b_entry->path, "/Users/", 7U) == 0
        ? 0
        : (strncmp(b_entry->path, "/System/", 8U) == 0 ||
           strncmp(b_entry->path, "/Library/", 9U) == 0 ||
           strncmp(b_entry->path, "/private/", 9U) == 0)
            ? 2
            : 1;
    if (a_rank != b_rank) return a_rank < b_rank ? -1 : 1;
    a_length = strlen(a_entry->path);
    b_length = strlen(b_entry->path);
    if (a_length != b_length) return a_length < b_length ? -1 : 1;
    return strcmp(a_entry->path, b_entry->path);
}

static size_t find_hardlink_alias_local(
    const HfsPlusHardlinkAliasLocal *aliases,
    size_t alias_count,
    uint32_t reference)
{
    size_t lo = 0U;
    size_t hi = alias_count;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2U;

        if (aliases[mid].reference < reference) lo = mid + 1U;
        else hi = mid;
    }
    return lo < alias_count && aliases[lo].reference == reference
        ? aliases[lo].entry_index
        : (size_t)-1;
}

static int write_hardlink_map_local(
    const HfsPlusHardlinkAliasLocal *aliases,
    size_t alias_count)
{
    char state_dir[HFSPLUS_PATH_MAX];
    char path[HFSPLUS_PATH_MAX];
    char temp_path[HFSPLUS_PATH_MAX + 32U];
    FILE *file;
    size_t index;
    int ok = 1;

    if (g_hfsplus_output_dir[0] == '\0' ||
        snprintf(
            state_dir,
            sizeof(state_dir),
            "%s/%s",
            g_hfsplus_output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(state_dir) ||
        !ensure_directory_path_local(state_dir) ||
        snprintf(
            path,
            sizeof(path),
            "%s/hfsplus_hardlinks.tsv",
            state_dir) >= (int)sizeof(path) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >=
            (int)sizeof(temp_path) ||
        !fs_backend_output_path_write_guard_allows(temp_path)) {
        return 0;
    }
    file = fopen(temp_path, "w");
    if (file == NULL) return 0;
    (void)chmod(temp_path, 0644);
    ok = fprintf(
        file,
        "link_reference\tbacking_cnid\tresolved\tcanonical_path\talias_cnid\talias_path\n") >= 0;
    for (index = 0U; ok && index < alias_count; ++index) {
        const HfsPlusCatalogEntry *alias =
            &g_hfsplus_entries[aliases[index].entry_index];
        const HfsPlusCatalogEntry *backing = NULL;
        size_t backing_index;

        if (alias->hardlink_backing_file_id != 0U &&
            find_entry_index_by_file_id_local(
                alias->hardlink_backing_file_id,
                &backing_index) &&
            backing_index < g_hfsplus_entry_count) {
            backing = &g_hfsplus_entries[backing_index];
        }
        ok = fprintf(
            file,
            "%u\t%u\t%d\t",
            alias->hardlink_reference,
            alias->hardlink_backing_file_id,
            backing != NULL && backing->hardlink_resolved ? 1 : 0) >= 0;
        if (!ok) break;
        write_tsv_text_local(
            file,
            backing != NULL ? backing->path : "");
        ok = fprintf(file, "\t%u\t", alias->file_id) >= 0;
        if (!ok) break;
        write_tsv_text_local(file, alias->path);
        ok = fputc('\n', file) != EOF;
    }
    for (index = 0U; ok && index < g_hfsplus_entry_count; ++index) {
        const HfsPlusCatalogEntry *inode = &g_hfsplus_entries[index];

        if (!inode->is_hardlink_inode || inode->hardlink_resolved) continue;
        ok = fprintf(
            file,
            "%u\t%u\t0\t",
            inode->hardlink_reference,
            inode->file_id) >= 0;
        if (!ok) break;
        write_tsv_text_local(file, inode->path);
        ok = fprintf(file, "\t0\t\n") >= 0;
    }
    if (fclose(file) != 0) ok = 0;
    if (!ok || rename(temp_path, path) != 0) {
        (void)unlink(temp_path);
        return 0;
    }
    return mft_apply_output_owner_to_path(path);
}

static int resolve_hardlink_catalog_entries_local(void)
{
    HfsPlusHardlinkAliasLocal *aliases = NULL;
    size_t alias_count = 0U;
    size_t alias_cursor = 0U;
    size_t inode_count = 0U;
    size_t resolved_count = 0U;
    size_t orphan_count = 0U;
    size_t index;

    for (index = 0U; index < g_hfsplus_entry_count; ++index) {
        HfsPlusCatalogEntry *entry = &g_hfsplus_entries[index];
        size_t parent_index;
        uint32_t reference;

        if (entry->is_hardlink_placeholder &&
            entry->hardlink_reference != 0U && entry->path_complete) {
            alias_count++;
        }
        if (!entry->is_directory && !entry->is_hardlink_inode &&
            parse_hardlink_inode_name_local(entry->name, 0, &reference) &&
            find_entry_index_by_file_id_local(entry->parent_id, &parent_index) &&
            g_hfsplus_entries[parent_index].is_hardlink_metadata_directory) {
            entry->is_hardlink_inode = 1;
            entry->hardlink_reference = reference;
        }
    }
    if (alias_count > 0U) {
        aliases = (HfsPlusHardlinkAliasLocal *)calloc(
            alias_count,
            sizeof(*aliases));
        if (aliases == NULL) return 0;
        for (index = 0U; index < g_hfsplus_entry_count; ++index) {
            const HfsPlusCatalogEntry *entry = &g_hfsplus_entries[index];

            if (!entry->is_hardlink_placeholder ||
                entry->hardlink_reference == 0U || !entry->path_complete) {
                continue;
            }
            aliases[alias_cursor].reference = entry->hardlink_reference;
            aliases[alias_cursor].entry_index = index;
            alias_cursor++;
        }
        qsort(aliases, alias_count, sizeof(*aliases), hardlink_alias_compare_local);
    }

    for (index = 0U; index < g_hfsplus_entry_count; ++index) {
        HfsPlusCatalogEntry *inode = &g_hfsplus_entries[index];
        size_t alias_index;

        if (!inode->is_hardlink_inode || inode->hardlink_reference == 0U) continue;
        inode_count++;
        alias_index = find_hardlink_alias_local(
            aliases,
            alias_count,
            inode->hardlink_reference);
        if (alias_index == (size_t)-1) {
            inode->hardlink_resolved = 0;
            orphan_count++;
            continue;
        }
        inode->parent_id = g_hfsplus_entries[alias_index].parent_id;
        copy_text_bounded_local(
            inode->name,
            sizeof(inode->name),
            g_hfsplus_entries[alias_index].name);
        copy_text_bounded_local(
            inode->path,
            sizeof(inode->path),
            g_hfsplus_entries[alias_index].path);
        inode->has_name = g_hfsplus_entries[alias_index].has_name;
        inode->path_complete = g_hfsplus_entries[alias_index].path_complete;
        inode->hardlink_resolved = inode->path_complete ? 1 : 0;
        if (inode->hardlink_resolved) {
            size_t alias_position = 0U;

            while (alias_position < alias_count &&
                   aliases[alias_position].reference <
                       inode->hardlink_reference) {
                alias_position++;
            }
            while (alias_position < alias_count &&
                   aliases[alias_position].reference ==
                       inode->hardlink_reference) {
                g_hfsplus_entries[aliases[alias_position].entry_index]
                    .hardlink_backing_file_id = inode->file_id;
                alias_position++;
            }
            resolved_count++;
        } else {
            orphan_count++;
        }
    }
    if (!write_hardlink_map_local(aliases, alias_count)) {
        log_info(
            "HFS+ hard-link map could not be written; resolved recovery paths remain available in memory"
        );
    }
    free(aliases);
    if (inode_count > 0U || alias_count > 0U) {
        log_info(
            "HFS+ hard-link resolution: aliases=%zu indirect_nodes=%zu resolved=%zu orphan_nodes=%zu",
            alias_count,
            inode_count,
            resolved_count,
            orphan_count
        );
    }
    return 1;
}

static int catalog_component_needs_identity_suffix_local(const char *name)
{
    const unsigned char *cursor = (const unsigned char *)name;
    size_t length;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    length = strlen(name);
    if (length > 220U || name[length - 1U] == '.' || name[length - 1U] == ' ') {
        return 1;
    }
    while (*cursor != '\0') {
        if (*cursor < 32U || *cursor == '/' || *cursor == '\\' || *cursor == ':' ||
            *cursor == '$' || *cursor == '?' || *cursor == '*' || *cursor == '"' ||
            *cursor == '<' || *cursor == '>' || *cursor == '|') {
            return 1;
        }
        ++cursor;
    }
    return g_hfsplus_sort_case_sensitive ? 1 : 0;
}

static int build_portable_catalog_component_local(
    char *out,
    size_t out_size,
    const HfsPlusCatalogEntry *entry
)
{
    char sanitized[HFSPLUS_NAME_MAX];
    char suffix[48];
    const char *visible;
    const char *dot;
    size_t sanitized_length = 0U;
    size_t suffix_length;
    size_t stem_length;
    size_t extension_length;
    size_t portable_size;
    int needs_suffix;

    if (out == NULL || out_size == 0U || entry == NULL || entry->name[0] == '\0') {
        return 0;
    }
    visible = mft_visible_windows_component_name(entry->name);
    /* Leave room for the deterministic .carvpart.<CNID> sibling on exFAT. */
    portable_size = out_size < 225U ? out_size : 225U;
    append_sanitized_visible_component_local(
        sanitized,
        sizeof(sanitized),
        &sanitized_length,
        visible
    );
    while (sanitized_length > 0U &&
           (sanitized[sanitized_length - 1U] == '.' ||
            sanitized[sanitized_length - 1U] == ' ')) {
        sanitized[--sanitized_length] = '\0';
    }
    if (sanitized_length == 0U) {
        snprintf(sanitized, sizeof(sanitized), "unnamed");
        sanitized_length = strlen(sanitized);
    }

    needs_suffix = catalog_component_needs_identity_suffix_local(entry->name);
    if (!needs_suffix && sanitized_length + 1U <= portable_size) {
        memcpy(out, sanitized, sanitized_length + 1U);
        return 1;
    }

    snprintf(suffix, sizeof(suffix), "~hfs%u", entry->file_id);
    suffix_length = strlen(suffix);
    dot = strrchr(sanitized, '.');
    if (dot == sanitized || dot == NULL) {
        dot = sanitized + sanitized_length;
    }
    stem_length = (size_t)(dot - sanitized);
    extension_length = sanitized_length - stem_length;
    if (suffix_length + extension_length + 2U > portable_size) {
        return 0;
    }
    if (stem_length + suffix_length + extension_length + 1U > portable_size) {
        stem_length = portable_size - suffix_length - extension_length - 1U;
        while (stem_length > 0U &&
               ((unsigned char)sanitized[stem_length] & 0xC0U) == 0x80U) {
            --stem_length;
        }
    }
    memcpy(out, sanitized, stem_length);
    memcpy(out + stem_length, suffix, suffix_length);
    memcpy(out + stem_length + suffix_length, dot, extension_length);
    out[stem_length + suffix_length + extension_length] = '\0';
    return 1;
}

static int build_catalog_entry_output_path_local(
    char *out_path,
    size_t out_size,
    const HfsPlusCatalogEntry *entry
)
{
    const HfsPlusCatalogEntry *components[256];
    const HfsPlusCatalogEntry *cursor = entry;
    char relative[HFSPLUS_PATH_MAX];
    size_t component_count = 0U;
    size_t relative_length = 0U;

    if (out_path == NULL || out_size == 0U || entry == NULL) {
        return 0;
    }
    if (entry->is_hardlink_inode && !entry->hardlink_resolved &&
        build_hardlink_orphan_relative_path_local(
            relative,
            sizeof(relative),
            entry->hardlink_reference,
            path_extension_local(entry->name))) {
        return build_output_path_from_relative_local(out_path, out_size, relative);
    }
    while (cursor != NULL && cursor->file_id != HFSPLUS_ROOT_FOLDER_ID &&
           component_count < sizeof(components) / sizeof(components[0])) {
        size_t parent_index;

        components[component_count++] = cursor;
        if (cursor->parent_id == HFSPLUS_ROOT_FOLDER_ID) {
            break;
        }
        if (!find_entry_index_by_file_id_local(cursor->parent_id, &parent_index) ||
            parent_index >= g_hfsplus_entry_count) {
            return 0;
        }
        cursor = &g_hfsplus_entries[parent_index];
    }
    if (component_count == 0U && entry->file_id != HFSPLUS_ROOT_FOLDER_ID) {
        return 0;
    }
    relative[0] = '\0';
    while (component_count > 0U) {
        char component[HFSPLUS_NAME_MAX];
        size_t component_length;

        cursor = components[--component_count];
        if (!build_portable_catalog_component_local(
                component,
                sizeof(component),
                cursor)) {
            return 0;
        }
        component_length = strlen(component);
        if (relative_length + component_length + (relative_length > 0U ? 1U : 0U) + 1U >
            sizeof(relative)) {
            return 0;
        }
        if (relative_length > 0U) {
            relative[relative_length++] = '/';
        }
        memcpy(relative + relative_length, component, component_length + 1U);
        relative_length += component_length;
    }
    return build_output_path_from_relative_local(out_path, out_size, relative);
}

static void publish_catalog_read_progress_local(
    const HfsPlusBTreeHeaderLocal *header,
    uint32_t visited_nodes,
    uint64_t visited_records,
    uint64_t cache_reads,
    uint64_t cache_bytes,
    double started_at,
    double *last_publish_at,
    double *last_log_at,
    int force)
{
    char state_dir[HFSPLUS_PATH_MAX];
    char state_path[HFSPLUS_PATH_MAX];
    char temp_path[HFSPLUS_PATH_MAX + 48U];
    char activity[192];
    FILE *file;
    double now = monotonic_seconds_local();
    double elapsed = now - started_at;
    double percent = header != NULL && header->leaf_records > 0U
        ? (100.0 * (double)visited_records / (double)header->leaf_records)
        : 0.0;

    if (header == NULL || last_publish_at == NULL || last_log_at == NULL) return;
    if (!force && *last_publish_at > 0.0 &&
        now - *last_publish_at < HFSPLUS_CATALOG_PROGRESS_INTERVAL_SECONDS) return;

    snprintf(
        activity,
        sizeof(activity),
        "reading HFS+ Catalog: %.1f%%, %u leaf nodes, %zu entries",
        percent > 100.0 ? 100.0 : percent,
        visited_nodes,
        g_hfsplus_entry_count
    );
    log_set_working_activity(activity);
    if (force || *last_log_at <= 0.0 ||
        now - *last_log_at >= HFSPLUS_CATALOG_PROGRESS_LOG_INTERVAL_SECONDS) {
        log_info(
            "HFS+ Catalog progress: leaf_nodes=%u records=%llu/%u (%.1f%%) entries=%zu tree_nodes=%u sequential_reads=%llu sequential_io=%.2f MiB elapsed=%.1fs",
            visited_nodes,
            (unsigned long long)visited_records,
            header->leaf_records,
            percent > 100.0 ? 100.0 : percent,
            g_hfsplus_entry_count,
            header->total_nodes,
            (unsigned long long)cache_reads,
            (double)cache_bytes / (1024.0 * 1024.0),
            elapsed
        );
        *last_log_at = now;
    }

    if (g_hfsplus_output_dir[0] != '\0' &&
        snprintf(state_dir, sizeof(state_dir), "%s/%s", g_hfsplus_output_dir,
                 APP_STATE_DIR_NAME) < (int)sizeof(state_dir) &&
        ensure_directory_path_local(state_dir) &&
        snprintf(state_path, sizeof(state_path), "%s/hfsplus_catalog_progress.txt",
                 state_dir) < (int)sizeof(state_path) &&
        snprintf(temp_path, sizeof(temp_path), "%s.tmp.%ld", state_path,
                 (long)getpid()) < (int)sizeof(temp_path) &&
        fs_backend_output_path_write_guard_allows(temp_path)) {
        file = fopen(temp_path, "w");
        if (file != NULL) {
            fprintf(file, "version=1\nbackend=hfsplus\nphase=%s\n",
                    force ? "complete" : "catalog_read");
            fprintf(file, "leaf_nodes_visited=%u\ntree_nodes_total=%u\n",
                    visited_nodes, header->total_nodes);
            fprintf(file, "leaf_records_visited=%llu\nleaf_records_total=%u\n",
                    (unsigned long long)visited_records, header->leaf_records);
            fprintf(file, "leaf_progress_percent=%.6f\nentries_parsed=%zu\n",
                    percent > 100.0 ? 100.0 : percent, g_hfsplus_entry_count);
            fprintf(file, "read_ahead_reads=%llu\nread_ahead_bytes=%llu\n",
                    (unsigned long long)cache_reads,
                    (unsigned long long)cache_bytes);
            fprintf(file, "sequential_reads=%llu\nsequential_bytes=%llu\n",
                    (unsigned long long)cache_reads,
                    (unsigned long long)cache_bytes);
            fprintf(file, "elapsed_seconds=%.6f\nupdated_unix=%lld\n",
                    elapsed, (long long)time(NULL));
            if (fclose(file) == 0 && rename(temp_path, state_path) == 0) {
                (void)mft_apply_output_owner_to_path(state_path);
            } else {
                (void)unlink(temp_path);
            }
        }
    }
    *last_publish_at = now;
}

static int orphan_utf16_name_valid_local(
    const unsigned char *name_bytes,
    uint16_t char_count)
{
    uint16_t index = 0U;

    if (name_bytes == NULL || char_count == 0U || char_count > 255U) return 0;
    while (index < char_count) {
        uint16_t value = read_u16_be_local(name_bytes + (size_t)index * 2U);

        if (value == 0U || value == (uint16_t)'/') return 0;
        if (value >= 0xD800U && value <= 0xDBFFU) {
            uint16_t low;
            if (index + 1U >= char_count) return 0;
            low = read_u16_be_local(name_bytes + (size_t)(index + 1U) * 2U);
            if (low < 0xDC00U || low > 0xDFFFU) return 0;
            index += 2U;
            continue;
        }
        if (value >= 0xDC00U && value <= 0xDFFFU) return 0;
        index++;
    }
    return 1;
}

static int ensure_orphan_record_capacity_local(size_t needed)
{
    HfsPlusOrphanCatalogRecordLocal *expanded;
    size_t capacity = g_hfsplus_orphan_record_capacity == 0U
        ? 256U : g_hfsplus_orphan_record_capacity;

    if (needed <= g_hfsplus_orphan_record_capacity) return 1;
    if (needed > HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS) return 0;
    while (capacity < needed) {
        if (capacity > HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS / 2U) {
            capacity = HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS;
            break;
        }
        capacity *= 2U;
    }
    expanded = (HfsPlusOrphanCatalogRecordLocal *)realloc(
        g_hfsplus_orphan_records,
        capacity * sizeof(*expanded));
    if (expanded == NULL) return 0;
    g_hfsplus_orphan_records = expanded;
    g_hfsplus_orphan_record_capacity = capacity;
    return 1;
}

static int ensure_historical_folder_capacity_local(size_t needed)
{
    HfsPlusHistoricalFolderRecordLocal *expanded;
    size_t capacity = g_hfsplus_historical_folder_capacity == 0U
        ? 256U : g_hfsplus_historical_folder_capacity;

    if (needed <= g_hfsplus_historical_folder_capacity) return 1;
    if (needed > HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS) return 0;
    while (capacity < needed) {
        if (capacity > HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS / 2U) {
            capacity = HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS;
            break;
        }
        capacity *= 2U;
    }
    expanded = (HfsPlusHistoricalFolderRecordLocal *)realloc(
        g_hfsplus_historical_folders,
        capacity * sizeof(*expanded));
    if (expanded == NULL) return 0;
    g_hfsplus_historical_folders = expanded;
    g_hfsplus_historical_folder_capacity = capacity;
    return 1;
}

static int append_orphan_string_local(
    const char *text,
    uint64_t *offset_out,
    uint32_t *length_out)
{
    size_t length;
    size_t needed;
    size_t capacity;
    char *expanded;

    if (text == NULL || offset_out == NULL || length_out == NULL) return 0;
    length = strlen(text);
    if (length == 0U || length > UINT32_MAX ||
        g_hfsplus_orphan_string_bytes > SIZE_MAX - length - 1U) return 0;
    needed = g_hfsplus_orphan_string_bytes + length + 1U;
    if ((uint64_t)needed > HFSPLUS_MAX_ORPHAN_STRING_BYTES) return 0;
    if (needed > g_hfsplus_orphan_string_capacity) {
        capacity = g_hfsplus_orphan_string_capacity == 0U
            ? 4096U : g_hfsplus_orphan_string_capacity;
        while (capacity < needed) {
            if ((uint64_t)capacity >= HFSPLUS_MAX_ORPHAN_STRING_BYTES / 2ULL) {
                capacity = (size_t)HFSPLUS_MAX_ORPHAN_STRING_BYTES;
                break;
            }
            capacity *= 2U;
        }
        expanded = (char *)realloc(g_hfsplus_orphan_strings, capacity);
        if (expanded == NULL) return 0;
        g_hfsplus_orphan_strings = expanded;
        g_hfsplus_orphan_string_capacity = capacity;
    }
    *offset_out = (uint64_t)g_hfsplus_orphan_string_bytes;
    *length_out = (uint32_t)length;
    memcpy(g_hfsplus_orphan_strings + g_hfsplus_orphan_string_bytes,
           text, length + 1U);
    g_hfsplus_orphan_string_bytes = needed;
    return 1;
}

static const char *orphan_record_name_local(
    const HfsPlusOrphanCatalogRecordLocal *record)
{
    if (record == NULL || record->name_offset >= g_hfsplus_orphan_string_bytes ||
        record->name_length >= g_hfsplus_orphan_string_bytes -
            (size_t)record->name_offset) return "";
    return g_hfsplus_orphan_strings + (size_t)record->name_offset;
}

static const char *historical_folder_name_local(
    const HfsPlusHistoricalFolderRecordLocal *record)
{
    if (record == NULL || record->name_offset >= g_hfsplus_orphan_string_bytes ||
        record->name_length >= g_hfsplus_orphan_string_bytes -
            (size_t)record->name_offset) return "";
    return g_hfsplus_orphan_strings + (size_t)record->name_offset;
}

static int append_orphan_record_local(
    const HfsPlusOrphanCatalogRecordLocal *record,
    const char *name)
{
    HfsPlusOrphanCatalogRecordLocal stored;

    if (record == NULL || name == NULL || name[0] == '\0') return 0;
    if (g_hfsplus_orphan_record_count >= HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS ||
        !ensure_orphan_record_capacity_local(g_hfsplus_orphan_record_count + 1U)) {
        g_hfsplus_orphan_truncated = 1;
        return 0;
    }
    stored = *record;
    if (!append_orphan_string_local(
            name, &stored.name_offset, &stored.name_length)) {
        g_hfsplus_orphan_truncated = 1;
        return 0;
    }
    g_hfsplus_orphan_records[g_hfsplus_orphan_record_count++] = stored;
    return 1;
}

static int append_historical_folder_local(
    const HfsPlusHistoricalFolderRecordLocal *record,
    const char *name)
{
    HfsPlusHistoricalFolderRecordLocal stored;

    if (record == NULL || name == NULL || name[0] == '\0' ||
        g_hfsplus_historical_folder_count >=
            HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS ||
        !ensure_historical_folder_capacity_local(
            g_hfsplus_historical_folder_count + 1U)) {
        g_hfsplus_orphan_truncated = 1;
        return 0;
    }
    stored = *record;
    if (!append_orphan_string_local(
            name, &stored.name_offset, &stored.name_length)) {
        g_hfsplus_orphan_truncated = 1;
        return 0;
    }
    g_hfsplus_historical_folders[g_hfsplus_historical_folder_count++] = stored;
    return 1;
}

static int parse_historical_catalog_folder_record_local(
    const unsigned char *node,
    uint16_t node_size,
    uint32_t node_number,
    uint16_t record_start,
    uint16_t record_limit,
    uint8_t provenance,
    uint8_t confidence,
    uint32_t journal_active_rank)
{
    HfsPlusHistoricalFolderRecordLocal record = {0};
    uint16_t key_length;
    uint16_t name_char_count;
    size_t data_offset;
    char name[HFSPLUS_NAME_MAX];

    if (node == NULL || record_start < 14U || record_limit > node_size ||
        record_limit <= record_start ||
        (size_t)record_start + 8U > (size_t)record_limit) return 0;
    key_length = read_u16_be_local(node + record_start);
    name_char_count = read_u16_be_local(node + record_start + 6U);
    if (name_char_count == 0U || name_char_count > 255U ||
        key_length != (uint16_t)(6U + (uint16_t)(name_char_count * 2U)) ||
        (size_t)record_start + 2U + key_length > (size_t)record_limit ||
        !orphan_utf16_name_valid_local(
            node + record_start + 8U, name_char_count)) return 0;
    record.parent_id = read_u32_be_local(node + record_start + 2U);
    data_offset = (size_t)record_start + 2U + (size_t)key_length;
    if ((data_offset & 1U) != 0U) data_offset++;
    if (data_offset + 16U > (size_t)record_limit ||
        read_u16_be_local(node + data_offset) !=
            HFSPLUS_CATALOG_FOLDER_RECORD) return 0;
    record.folder_id = read_u32_be_local(node + data_offset + 8U);
    if (record.folder_id < HFSPLUS_ROOT_FOLDER_ID ||
        record.parent_id < 1U ||
        record.folder_id == record.parent_id) return 0;
    utf16be_to_utf8_local(
        node + record_start + 8U,
        name_char_count,
        name,
        sizeof(name));
    if (name[0] == '\0') return 0;
    record.create_date_hfs = read_u32_be_local(node + data_offset + 12U);
    record.source_node = node_number;
    record.record_offset = record_start;
    record.confidence = confidence;
    record.provenance = provenance;
    if (provenance == HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK) {
        record.journal_observations = 1U;
        if (journal_active_rank > 0U) {
            record.journal_active_observations = 1U;
            record.journal_active_first_rank = journal_active_rank;
            record.journal_active_last_rank = journal_active_rank;
        }
    }
    return append_historical_folder_local(&record, name);
}

static int parse_orphan_catalog_file_record_local(
    const unsigned char *node,
    uint16_t node_size,
    uint32_t node_number,
    uint16_t record_start,
    uint16_t record_limit,
    uint8_t provenance,
    uint8_t confidence,
    uint32_t journal_active_rank)
{
    HfsPlusOrphanCatalogRecordLocal record = {0};
    HfsPlusForkDataLocal data_fork = {0};
    uint16_t key_length;
    uint16_t name_char_count;
    uint32_t parent_id;
    uint32_t file_id;
    size_t data_offset;
    size_t extent_index;
    uint64_t allocated_size;
    uint64_t extent_blocks = 0U;
    uint64_t first_extent_base;
    char name[HFSPLUS_NAME_MAX];

    if (node == NULL || record_start < 14U || record_limit > node_size ||
        record_limit <= record_start ||
        (size_t)record_start + 8U > (size_t)record_limit) return 0;
    key_length = read_u16_be_local(node + record_start);
    name_char_count = read_u16_be_local(node + record_start + 6U);
    if (name_char_count == 0U || name_char_count > 255U ||
        key_length != (uint16_t)(6U + (uint16_t)(name_char_count * 2U)) ||
        (size_t)record_start + 2U + key_length > (size_t)record_limit ||
        !orphan_utf16_name_valid_local(
            node + record_start + 8U, name_char_count)) return 0;
    parent_id = read_u32_be_local(node + record_start + 2U);
    data_offset = (size_t)record_start + 2U + (size_t)key_length;
    if ((data_offset & 1U) != 0U) data_offset++;
    if (data_offset + 168U > (size_t)record_limit ||
        read_u16_be_local(node + data_offset) !=
            HFSPLUS_CATALOG_FILE_RECORD) return 0;
    file_id = read_u32_be_local(node + data_offset + 8U);
    if (file_id < 16U || parent_id < HFSPLUS_ROOT_FOLDER_ID ||
        file_id == parent_id) return 0;
    parse_fork_data_local(node + data_offset + 88U, &data_fork);
    if (data_fork.logical_size == 0U || data_fork.total_blocks == 0U ||
        data_fork.total_blocks > g_hfsplus_geometry.total_blocks ||
        data_fork.extents[0].block_count == 0U) return 0;
    for (extent_index = 0U; extent_index < HFSPLUS_EXTENT_COUNT; ++extent_index) {
        const HfsPlusExtentDescriptorLocal *extent = &data_fork.extents[extent_index];
        uint64_t extent_end;

        if (extent->block_count == 0U) break;
        extent_end = (uint64_t)extent->start_block + extent->block_count;
        if (extent_end > g_hfsplus_geometry.total_blocks ||
            extent_blocks > UINT64_MAX - extent->block_count) return 0;
        extent_blocks += extent->block_count;
    }
    if (extent_blocks == 0U || extent_blocks > data_fork.total_blocks ||
        (uint64_t)data_fork.total_blocks > UINT64_MAX /
            g_hfsplus_geometry.block_size) return 0;
    allocated_size = (uint64_t)data_fork.total_blocks *
        g_hfsplus_geometry.block_size;
    if (data_fork.logical_size > allocated_size ||
        data_fork.logical_size > g_hfsplus_geometry.volume_size ||
        (uint64_t)data_fork.extents[0].start_block > UINT64_MAX /
            g_hfsplus_geometry.block_size) return 0;
    first_extent_base = (uint64_t)data_fork.extents[0].start_block *
        g_hfsplus_geometry.block_size;
    if (g_hfsplus_geometry.volume_offset > UINT64_MAX - first_extent_base) return 0;
    utf16be_to_utf8_local(
        node + record_start + 8U,
        name_char_count,
        name,
        sizeof(name));
    if (name[0] == '\0') return 0;
    record.abs_offset = g_hfsplus_geometry.volume_offset + first_extent_base;
    record.data_size = data_fork.logical_size;
    record.allocated_size = allocated_size;
    record.file_id = file_id;
    record.parent_id = parent_id;
    record.create_date_hfs = read_u32_be_local(node + data_offset + 12U);
    record.source_node = node_number;
    record.record_offset = record_start;
    record.confidence = confidence;
    record.provenance = provenance;
    if (provenance == HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK) {
        record.journal_observations = 1U;
        if (journal_active_rank > 0U) {
            record.journal_active_observations = 1U;
            record.journal_active_first_rank = journal_active_rank;
            record.journal_active_last_rank = journal_active_rank;
        }
    }
    return append_orphan_record_local(&record, name);
}

static void scan_orphan_region_local(
    const unsigned char *node,
    uint16_t node_size,
    uint32_t node_number,
    uint16_t region_start,
    uint16_t region_end,
    uint8_t provenance,
    uint8_t confidence)
{
    uint32_t cursor;

    if (region_end <= region_start ||
        (uint32_t)region_end - region_start < 176U) return;
    g_hfsplus_orphan_slack_bytes_scanned +=
        (uint64_t)region_end - region_start;
    cursor = ((uint32_t)region_start + 1U) & ~1U;
    while (cursor + 176U <= region_end) {
        if (parse_orphan_catalog_file_record_local(
                node,
                node_size,
                node_number,
                (uint16_t)cursor,
                region_end,
                provenance,
                confidence,
                0U)) {
            uint16_t key_length = read_u16_be_local(node + cursor);
            size_t data_offset = cursor + 2U + key_length;
            if ((data_offset & 1U) != 0U) data_offset++;
            cursor = (uint32_t)(data_offset + 168U);
            cursor = (cursor + 1U) & ~1U;
            continue;
        }
        g_hfsplus_orphan_rejected_candidates++;
        cursor += 2U;
    }
}

static void scan_catalog_node_for_orphans_local(
    const unsigned char *node,
    const HfsPlusBTreeHeaderLocal *header,
    uint32_t node_number,
    int allocated)
{
    uint16_t num_records;
    uint16_t free_space_offset = 0U;
    uint16_t table_start;
    int valid_table = 0;
    size_t record_index;

    if (node == NULL || header == NULL || node_number == 0U) return;
    g_hfsplus_orphan_nodes_scanned++;
    if (!allocated) g_hfsplus_orphan_free_nodes_scanned++;
    num_records = read_u16_be_local(node + 10U);
    if (((size_t)num_records + 1U) * 2U <= header->node_size &&
        read_btree_record_offset_local(
            node, header->node_size, num_records, num_records,
            &free_space_offset) &&
        free_space_offset <= header->node_size) {
        table_start = (uint16_t)(header->node_size -
            (uint16_t)(((size_t)num_records + 1U) * 2U));
        valid_table = free_space_offset <= table_start;
    } else {
        table_start = header->node_size;
    }

    if (!allocated && (int8_t)node[8] == HFSPLUS_BT_LEAF_NODE && valid_table) {
        for (record_index = 0U; record_index < (size_t)num_records; ++record_index) {
            uint16_t start;
            uint16_t end;

            if (!btree_record_bounds_local(
                    node, header->node_size, num_records,
                    (uint16_t)record_index, &start, &end)) continue;
            if (!parse_orphan_catalog_file_record_local(
                    node, header->node_size, node_number, start, end,
                    HFSPLUS_ORPHAN_FREE_LEAF_TABLE, 95U, 0U)) {
                g_hfsplus_orphan_rejected_candidates++;
            }
        }
        scan_orphan_region_local(
            node, header->node_size, node_number,
            free_space_offset, table_start,
            HFSPLUS_ORPHAN_FREE_NODE_SCAN, 82U);
        return;
    }
    if (!allocated) {
        scan_orphan_region_local(
            node, header->node_size, node_number,
            14U, valid_table ? table_start : header->node_size,
            HFSPLUS_ORPHAN_FREE_NODE_SCAN, 80U);
    } else if ((int8_t)node[8] == HFSPLUS_BT_LEAF_NODE && valid_table) {
        scan_orphan_region_local(
            node, header->node_size, node_number,
            free_space_offset, table_start,
            HFSPLUS_ORPHAN_ALLOCATED_LEAF_SLACK, 75U);
    }
}

/*
 * HFS+ journals are circular redo logs.  Their byte order is independent of
 * the big-endian HFS+ volume structures, and each transaction header carries
 * Apple's 32-byte checksum.  Journal archaeology therefore accepts a Catalog
 * image only through this chain:
 *
 *   valid JournalInfoBlock -> valid journal header -> checksummed block-list
 *   header -> destination range inside the current Catalog fork -> complete
 *   Catalog leaf node -> structurally valid file record.
 *
 * This parser is deliberately measurement-only.  The recovered records join
 * the existing orphan artifact; a separate exact-identity policy may later
 * use a checksummed record to name a no-owner output without trusting its
 * historical parent chain.
 */
static uint32_t hfsplus_journal_checksum_local(
    const unsigned char *bytes,
    size_t length)
{
    uint32_t checksum = 0U;
    size_t index;

    if (bytes == NULL) return 0U;
    for (index = 0U; index < length; ++index) {
        checksum = (checksum << 8) ^ (checksum + bytes[index]);
    }
    return ~checksum;
}

static uint16_t hfsplus_journal_u16_local(
    const unsigned char *bytes,
    int little_endian)
{
    return little_endian
        ? read_u16_le_local(bytes)
        : read_u16_be_local(bytes);
}

static uint32_t hfsplus_journal_u32_local(
    const unsigned char *bytes,
    int little_endian)
{
    return little_endian
        ? read_u32_le_local(bytes)
        : read_u32_be_local(bytes);
}

static uint64_t hfsplus_journal_u64_local(
    const unsigned char *bytes,
    int little_endian)
{
    return little_endian
        ? read_u64_le_local(bytes)
        : read_u64_be_local(bytes);
}

static int hfsplus_journal_ring_read_local(
    FILE *input_file,
    uint64_t journal_absolute,
    uint64_t journal_size,
    uint32_t header_size,
    uint64_t offset,
    unsigned char *destination,
    size_t length)
{
    uint64_t data_bytes;
    size_t copied = 0U;

    if (input_file == NULL || destination == NULL || header_size == 0U ||
        journal_size <= header_size || offset < header_size ||
        offset >= journal_size) return 0;
    data_bytes = journal_size - header_size;
    if ((uint64_t)length > data_bytes) return 0;
    while (copied < length) {
        uint64_t available;
        size_t piece;

        if (offset >= journal_size) {
            offset = (uint64_t)header_size + (offset - journal_size);
        }
        available = journal_size - offset;
        piece = length - copied;
        if ((uint64_t)piece > available) piece = (size_t)available;
        if (journal_absolute > UINT64_MAX - offset ||
            !read_bytes_at_local(
                input_file,
                journal_absolute + offset,
                destination + copied,
                piece)) return 0;
        copied += piece;
        offset += piece;
        if (offset == journal_size && copied < length) offset = header_size;
    }
    return 1;
}

static uint64_t hfsplus_journal_ring_advance_local(
    uint64_t journal_size,
    uint32_t header_size,
    uint64_t offset,
    uint64_t amount)
{
    uint64_t data_bytes;
    uint64_t relative;

    if (journal_size <= header_size || offset < header_size ||
        offset >= journal_size) return 0U;
    data_bytes = journal_size - header_size;
    relative = offset - header_size;
    amount %= data_bytes;
    if (relative >= data_bytes - amount) relative -= data_bytes - amount;
    else relative += amount;
    return (uint64_t)header_size + relative;
}

static uint32_t hfsplus_journal_active_rank_local(
    uint64_t journal_size,
    uint32_t header_size,
    uint64_t start,
    uint64_t end,
    uint64_t position)
{
    uint64_t distance;
    int active;

    if (journal_size <= header_size || start < header_size ||
        start > journal_size || end < header_size || end > journal_size ||
        position < header_size || position >= journal_size) {
        return 0U;
    }
    if (start == journal_size) start = header_size;
    if (end == journal_size) end = header_size;
    if (start == end) return 0U;
    active = start < end
        ? position >= start && position < end
        : position >= start || position < end;
    if (!active) return 0U;
    if (position >= start) distance = position - start;
    else distance = journal_size - start + position - header_size;
    if (distance / header_size >= UINT32_MAX) return 0U;
    return (uint32_t)(distance / header_size) + 1U;
}

static int hfsplus_catalog_logical_for_physical_local(
    uint64_t physical_offset,
    uint64_t byte_length,
    uint64_t *logical_offset_out)
{
    uint64_t logical_base = 0U;
    size_t extent_index;

    if (logical_offset_out == NULL || byte_length == 0U ||
        g_hfsplus_catalog_resolved_fork.extents == NULL) return 0;
    for (extent_index = 0U;
         extent_index < g_hfsplus_catalog_resolved_fork.extent_count;
         ++extent_index) {
        const HfsPlusExtentDescriptorLocal *extent =
            &g_hfsplus_catalog_resolved_fork.extents[extent_index];
        uint64_t extent_start;
        uint64_t extent_bytes;
        uint64_t within;

        if (extent->block_count == 0U) continue;
        extent_start = (uint64_t)extent->start_block *
            g_hfsplus_geometry.block_size;
        extent_bytes = (uint64_t)extent->block_count *
            g_hfsplus_geometry.block_size;
        if (physical_offset >= extent_start) {
            within = physical_offset - extent_start;
            if (within <= extent_bytes && byte_length <= extent_bytes - within) {
                if (logical_base > UINT64_MAX - within ||
                    logical_base + within >=
                        g_hfsplus_catalog_resolved_fork.logical_size ||
                    byte_length >
                        g_hfsplus_catalog_resolved_fork.logical_size -
                            (logical_base + within)) return 0;
                *logical_offset_out = logical_base + within;
                return 1;
            }
        }
        if (logical_base > UINT64_MAX - extent_bytes) return 0;
        logical_base += extent_bytes;
    }
    return 0;
}

static void scan_journal_catalog_payload_local(
    const unsigned char *payload,
    uint64_t target_physical_offset,
    uint32_t payload_size,
    const HfsPlusBTreeHeaderLocal *catalog_header,
    uint32_t journal_active_rank)
{
    uint64_t catalog_logical;
    uint64_t aligned_logical;
    uint64_t leading;

    if (payload == NULL || payload_size == 0U || catalog_header == NULL ||
        catalog_header->node_size < HFSPLUS_BTREE_NODE_MIN ||
        !hfsplus_catalog_logical_for_physical_local(
            target_physical_offset, payload_size, &catalog_logical)) return;
    aligned_logical = catalog_logical;
    if (aligned_logical % catalog_header->node_size != 0U) {
        leading = catalog_header->node_size -
            (aligned_logical % catalog_header->node_size);
        if (leading >= payload_size) return;
        aligned_logical += leading;
        payload += (size_t)leading;
        payload_size -= (uint32_t)leading;
    }
    while (payload_size >= catalog_header->node_size) {
        uint32_t node_number =
            (uint32_t)(aligned_logical / catalog_header->node_size);
        uint16_t num_records;
        uint16_t free_space_offset;
        uint16_t table_start;
        size_t record_index;
        size_t candidates_before = g_hfsplus_orphan_record_count;
        size_t folders_before = g_hfsplus_historical_folder_count;

        if (node_number >= catalog_header->total_nodes ||
            (int8_t)payload[8] != HFSPLUS_BT_LEAF_NODE ||
            payload[9] != 1U) goto next_node;
        num_records = read_u16_be_local(payload + 10U);
        if (num_records == 0U ||
            ((size_t)num_records + 1U) * 2U > catalog_header->node_size ||
            !read_btree_record_offset_local(
                payload, catalog_header->node_size, num_records,
                num_records, &free_space_offset)) goto next_node;
        table_start = (uint16_t)(catalog_header->node_size -
            (uint16_t)(((size_t)num_records + 1U) * 2U));
        if (free_space_offset < 14U || free_space_offset > table_start) {
            goto next_node;
        }
        g_hfsplus_journal_catalog_blocks++;
        for (record_index = 0U; record_index < num_records; ++record_index) {
            uint16_t record_start;
            uint16_t record_end;

            if (!btree_record_bounds_local(
                    payload, catalog_header->node_size, num_records,
                    (uint16_t)record_index, &record_start, &record_end)) continue;
            (void)parse_orphan_catalog_file_record_local(
                payload,
                catalog_header->node_size,
                node_number,
                record_start,
                record_end,
                HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK,
                98U,
                journal_active_rank);
            (void)parse_historical_catalog_folder_record_local(
                payload,
                catalog_header->node_size,
                node_number,
                record_start,
                record_end,
                HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK,
                98U,
                journal_active_rank);
        }
        g_hfsplus_journal_catalog_records +=
            g_hfsplus_orphan_record_count - candidates_before;
        g_hfsplus_journal_folder_records +=
            g_hfsplus_historical_folder_count - folders_before;

next_node:
        payload += catalog_header->node_size;
        payload_size -= catalog_header->node_size;
        aligned_logical += catalog_header->node_size;
    }
}

static int scan_hfsplus_journal_catalog_local(
    FILE *input_file,
    const HfsPlusBTreeHeaderLocal *catalog_header)
{
    unsigned char journal_info[HFSPLUS_JOURNAL_INFO_SIZE];
    unsigned char journal_header[48U];
    unsigned char header_copy[HFSPLUS_JOURNAL_HEADER_CHECKSUM_SIZE];
    unsigned char block_header[HFSPLUS_JOURNAL_BLOCK_HEADER_CHECKSUM_SIZE];
    unsigned char *scan_buffer = NULL;
    unsigned char *block_list = NULL;
    unsigned char *payload = NULL;
    size_t payload_capacity = 0U;
    uint64_t info_relative;
    uint64_t info_absolute;
    uint64_t journal_relative;
    uint64_t journal_absolute;
    uint64_t journal_size;
    uint64_t declared_size;
    uint64_t start;
    uint64_t end;
    uint32_t flags;
    uint32_t header_size;
    uint32_t block_list_size;
    uint32_t stored_header_checksum;
    uint32_t calculated_header_checksum;
    uint32_t journal_magic;
    uint64_t scan_position;
    size_t scan_capacity;
    int little_endian;
    double started_at = monotonic_seconds_local();

    g_hfsplus_journal_scan_attempted = 1;
    if (input_file == NULL || catalog_header == NULL ||
        g_hfsplus_geometry.journal_info_block == 0U ||
        g_hfsplus_geometry.block_size == 0U) return 0;
    info_relative = (uint64_t)g_hfsplus_geometry.journal_info_block *
        g_hfsplus_geometry.block_size;
    if (info_relative > g_hfsplus_geometry.volume_size ||
        sizeof(journal_info) > g_hfsplus_geometry.volume_size - info_relative ||
        g_hfsplus_geometry.volume_offset > UINT64_MAX - info_relative) return 0;
    info_absolute = g_hfsplus_geometry.volume_offset + info_relative;
    if (!read_bytes_at_local(
            input_file, info_absolute, journal_info, sizeof(journal_info))) return 0;
    flags = read_u32_be_local(journal_info);
    journal_relative = read_u64_be_local(journal_info + 36U);
    journal_size = read_u64_be_local(journal_info + 44U);
    if ((flags & HFSPLUS_JOURNAL_IN_FS_MASK) == 0U ||
        (flags & HFSPLUS_JOURNAL_EXTERNAL_MASK) != 0U ||
        (flags & HFSPLUS_JOURNAL_NEED_INIT_MASK) != 0U ||
        journal_relative == 0U || journal_size < HFSPLUS_SECTOR_SIZE ||
        journal_size > HFSPLUS_JOURNAL_MAX_BYTES ||
        journal_relative > g_hfsplus_geometry.volume_size ||
        journal_size > g_hfsplus_geometry.volume_size - journal_relative ||
        g_hfsplus_geometry.volume_offset > UINT64_MAX - journal_relative) {
        return 0;
    }
    journal_absolute = g_hfsplus_geometry.volume_offset + journal_relative;
    if (journal_absolute > g_hfsplus_geometry.source_size ||
        journal_size > g_hfsplus_geometry.source_size - journal_absolute) return 0;
    if (!read_bytes_at_local(
            input_file, journal_absolute, journal_header,
            sizeof(journal_header))) return 0;
    g_hfsplus_journal_offset = journal_relative;
    g_hfsplus_journal_size = journal_size;
    g_hfsplus_journal_bytes_read = sizeof(journal_header);

    if (read_u32_le_local(journal_header + 4U) ==
            HFSPLUS_JOURNAL_ENDIAN_MAGIC) {
        little_endian = 1;
    } else if (read_u32_be_local(journal_header + 4U) ==
                   HFSPLUS_JOURNAL_ENDIAN_MAGIC) {
        little_endian = 0;
    } else {
        return 0;
    }
    journal_magic = hfsplus_journal_u32_local(
        journal_header, little_endian);
    if (journal_magic != HFSPLUS_JOURNAL_HEADER_MAGIC &&
        journal_magic != HFSPLUS_OLD_JOURNAL_HEADER_MAGIC) {
        return 0;
    }
    start = hfsplus_journal_u64_local(journal_header + 8U, little_endian);
    end = hfsplus_journal_u64_local(journal_header + 16U, little_endian);
    declared_size = hfsplus_journal_u64_local(
        journal_header + 24U, little_endian);
    block_list_size = hfsplus_journal_u32_local(
        journal_header + 32U, little_endian);
    stored_header_checksum = hfsplus_journal_u32_local(
        journal_header + 36U, little_endian);
    header_size = hfsplus_journal_u32_local(
        journal_header + 40U, little_endian);
    g_hfsplus_journal_sequence = hfsplus_journal_u32_local(
        journal_header + 44U, little_endian);
    if (declared_size != journal_size || header_size < HFSPLUS_SECTOR_SIZE ||
        header_size > journal_size || !is_power_of_two_u32_local(header_size) ||
        journal_size % header_size != 0U ||
        block_list_size < HFSPLUS_JOURNAL_BLOCK_HEADER_CHECKSUM_SIZE ||
        block_list_size > journal_size - header_size ||
        block_list_size % header_size != 0U ||
        start < header_size || start > journal_size ||
        end < header_size || end > journal_size) {
        return 0;
    }
    memcpy(header_copy, journal_header, sizeof(header_copy));
    memset(header_copy + 36U, 0, 4U);
    calculated_header_checksum = hfsplus_journal_checksum_local(
        header_copy, sizeof(header_copy));
    if (journal_magic == HFSPLUS_JOURNAL_HEADER_MAGIC &&
        calculated_header_checksum != stored_header_checksum) {
        return 0;
    }
    g_hfsplus_journal_header_checksum = stored_header_checksum;
    g_hfsplus_journal_header_valid = 1;
    g_hfsplus_journal_little_endian = little_endian;
    block_list = (unsigned char *)malloc(block_list_size);
    scan_capacity = HFSPLUS_JOURNAL_SCAN_BUFFER_BYTES;
    if ((uint64_t)scan_capacity > journal_size - header_size) {
        scan_capacity = (size_t)(journal_size - header_size);
    }
    scan_capacity -= scan_capacity % header_size;
    if (scan_capacity < header_size) scan_capacity = header_size;
    scan_buffer = (unsigned char *)malloc(scan_capacity);
    if (block_list == NULL || scan_buffer == NULL) goto scan_failed;

    log_set_working_activity("scanning checksummed HFS+ journal Catalog history");
    for (scan_position = header_size; scan_position < journal_size;) {
        uint64_t remaining = journal_size - scan_position;
        size_t scan_bytes = remaining < scan_capacity
            ? (size_t)remaining : scan_capacity;
        size_t local_position;

        scan_bytes -= scan_bytes % header_size;
        if (scan_bytes == 0U || !read_bytes_at_local(
                input_file,
                journal_absolute + scan_position,
                scan_buffer,
                scan_bytes)) goto scan_failed;
        g_hfsplus_journal_bytes_read += scan_bytes;
        for (local_position = 0U;
             local_position + sizeof(block_header) <= scan_bytes;
             local_position += header_size) {
            uint64_t position = scan_position + local_position;
            uint16_t max_blocks;
            uint16_t num_blocks;
            uint32_t bytes_used;
            uint32_t stored_checksum;
            uint32_t calculated_checksum;
            uint32_t block_flags;
            uint64_t payload_bytes = 0U;
            uint64_t payload_position;
            size_t block_index;
            int descriptors_valid = 1;
            uint32_t journal_active_rank;

            memcpy(block_header, scan_buffer + local_position,
                   sizeof(block_header));
            if (app_stop_requested()) {
                errno = ECANCELED;
                goto scan_failed;
            }
            max_blocks = hfsplus_journal_u16_local(
                block_header, little_endian);
            num_blocks = hfsplus_journal_u16_local(
                block_header + 2U, little_endian);
            bytes_used = hfsplus_journal_u32_local(
                block_header + 4U, little_endian);
            if (max_blocks == 0U || num_blocks == 0U ||
                num_blocks > max_blocks ||
                HFSPLUS_JOURNAL_BLOCK_LIST_BASE_SIZE +
                        (uint64_t)num_blocks *
                            HFSPLUS_JOURNAL_BLOCK_INFO_SIZE >
                    block_list_size ||
                bytes_used < block_list_size ||
                bytes_used > journal_size - header_size) continue;
            g_hfsplus_journal_header_candidates++;
            stored_checksum = hfsplus_journal_u32_local(
                block_header + 8U, little_endian);
            memset(block_header + 8U, 0, 4U);
            calculated_checksum = hfsplus_journal_checksum_local(
                block_header, sizeof(block_header));
            if (stored_checksum != calculated_checksum) {
                g_hfsplus_journal_checksum_rejections++;
                continue;
            }
            if (!hfsplus_journal_ring_read_local(
                    input_file, journal_absolute, journal_size, header_size,
                    position, block_list, block_list_size)) continue;
            g_hfsplus_journal_bytes_read += block_list_size;
            block_flags = hfsplus_journal_u32_local(
                block_list + 12U, little_endian);
            for (block_index = 1U; block_index < num_blocks; ++block_index) {
                const unsigned char *descriptor = block_list +
                    HFSPLUS_JOURNAL_BLOCK_LIST_BASE_SIZE +
                    block_index * HFSPLUS_JOURNAL_BLOCK_INFO_SIZE;
                uint32_t block_size = hfsplus_journal_u32_local(
                    descriptor + 8U, little_endian);

                if (block_size == 0U ||
                    payload_bytes > UINT64_MAX - block_size) {
                    descriptors_valid = 0;
                    break;
                }
                payload_bytes += block_size;
            }
            if (!descriptors_valid ||
                payload_bytes > bytes_used - block_list_size ||
                payload_bytes > journal_size - header_size) continue;
            payload_position = hfsplus_journal_ring_advance_local(
                journal_size, header_size, position, block_list_size);
            if (payload_position == 0U) continue;
            journal_active_rank = hfsplus_journal_active_rank_local(
                journal_size, header_size, start, end, position);
            g_hfsplus_journal_valid_transactions++;
            if (journal_active_rank > 0U) {
                g_hfsplus_journal_active_transactions++;
            }
            payload_bytes = 0U;
            for (block_index = 1U; block_index < num_blocks; ++block_index) {
                const unsigned char *descriptor = block_list +
                    HFSPLUS_JOURNAL_BLOCK_LIST_BASE_SIZE +
                    block_index * HFSPLUS_JOURNAL_BLOCK_INFO_SIZE;
                uint64_t block_number = hfsplus_journal_u64_local(
                    descriptor, little_endian);
                uint32_t block_size = hfsplus_journal_u32_local(
                    descriptor + 8U, little_endian);
                uint32_t block_checksum = hfsplus_journal_u32_local(
                    descriptor + 12U, little_endian);
                uint64_t target_offset;

                if (block_number == UINT64_MAX) {
                    payload_bytes += block_size;
                    continue;
                }
                if (block_number > UINT64_MAX / header_size) {
                    payload_bytes += block_size;
                    continue;
                }
                target_offset = block_number * (uint64_t)header_size;
                {
                    uint64_t ignored_logical_offset;
                    uint64_t block_payload_position;

                    if (!hfsplus_catalog_logical_for_physical_local(
                            target_offset, block_size,
                            &ignored_logical_offset)) {
                        payload_bytes += block_size;
                        continue;
                    }
                    if (block_size > payload_capacity) {
                        unsigned char *expanded = (unsigned char *)realloc(
                            payload, block_size);
                        if (expanded == NULL) goto scan_failed;
                        payload = expanded;
                        payload_capacity = block_size;
                    }
                    block_payload_position =
                        hfsplus_journal_ring_advance_local(
                            journal_size, header_size, payload_position,
                            payload_bytes);
                    if (block_payload_position == 0U ||
                        !hfsplus_journal_ring_read_local(
                            input_file, journal_absolute, journal_size,
                            header_size, block_payload_position, payload,
                            block_size)) {
                        payload_bytes += block_size;
                        continue;
                    }
                    g_hfsplus_journal_bytes_read += block_size;
                    if ((block_flags &
                            HFSPLUS_JOURNAL_CHECK_BLOCK_CHECKSUMS) != 0U &&
                        block_checksum != 0U &&
                        hfsplus_journal_checksum_local(
                            payload, block_size) != block_checksum) {
                        payload_bytes += block_size;
                        continue;
                    }
                    scan_journal_catalog_payload_local(
                        payload,
                        target_offset,
                        block_size,
                        catalog_header,
                        journal_active_rank);
                }
                payload_bytes += block_size;
            }
        }
        scan_position += scan_bytes;
    }
    free(payload);
    free(scan_buffer);
    free(block_list);
    log_info(
        "HFS+ journal Catalog archaeology: journal=%.2f MiB sequence=%u byte_order=%s header_candidates=%llu valid_transactions=%llu active_transactions=%llu checksum_rejections=%llu catalog_blocks=%llu file_records=%llu folder_records=%llu elapsed=%.2fs policy=measurement_only",
        (double)g_hfsplus_journal_size / (1024.0 * 1024.0),
        g_hfsplus_journal_sequence,
        g_hfsplus_journal_little_endian ? "little" : "big",
        (unsigned long long)g_hfsplus_journal_header_candidates,
        (unsigned long long)g_hfsplus_journal_valid_transactions,
        (unsigned long long)g_hfsplus_journal_active_transactions,
        (unsigned long long)g_hfsplus_journal_checksum_rejections,
        (unsigned long long)g_hfsplus_journal_catalog_blocks,
        (unsigned long long)g_hfsplus_journal_catalog_records,
        (unsigned long long)g_hfsplus_journal_folder_records,
        monotonic_seconds_local() - started_at);
    return 1;

scan_failed:
    free(payload);
    free(scan_buffer);
    free(block_list);
    return 0;
}

static int orphan_record_compare_local(const void *left, const void *right)
{
    const HfsPlusOrphanCatalogRecordLocal *a =
        (const HfsPlusOrphanCatalogRecordLocal *)left;
    const HfsPlusOrphanCatalogRecordLocal *b =
        (const HfsPlusOrphanCatalogRecordLocal *)right;

    if (a->abs_offset != b->abs_offset) return a->abs_offset < b->abs_offset ? -1 : 1;
    if (a->file_id != b->file_id) return a->file_id < b->file_id ? -1 : 1;
    if (a->parent_id != b->parent_id) return a->parent_id < b->parent_id ? -1 : 1;
    if (a->data_size != b->data_size) return a->data_size < b->data_size ? -1 : 1;
    if (a->allocated_size != b->allocated_size) {
        return a->allocated_size < b->allocated_size ? -1 : 1;
    }
    if (a->create_date_hfs != b->create_date_hfs) {
        return a->create_date_hfs < b->create_date_hfs ? -1 : 1;
    }
    {
        int name_order = strcmp(
            orphan_record_name_local(a), orphan_record_name_local(b));
        if (name_order != 0) return name_order;
    }
    if (a->confidence != b->confidence) return a->confidence > b->confidence ? -1 : 1;
    if (a->provenance != b->provenance) return a->provenance > b->provenance ? -1 : 1;
    if (a->source_node != b->source_node) return a->source_node < b->source_node ? -1 : 1;
    if (a->record_offset != b->record_offset) return a->record_offset < b->record_offset ? -1 : 1;
    return 0;
}

static int orphan_record_semantically_equal_local(
    const HfsPlusOrphanCatalogRecordLocal *left,
    const HfsPlusOrphanCatalogRecordLocal *right)
{
    return left != NULL && right != NULL &&
        left->abs_offset == right->abs_offset &&
        left->data_size == right->data_size &&
        left->allocated_size == right->allocated_size &&
        left->file_id == right->file_id &&
        left->parent_id == right->parent_id &&
        left->create_date_hfs == right->create_date_hfs &&
        strcmp(orphan_record_name_local(left),
               orphan_record_name_local(right)) == 0;
}

static uint32_t saturating_add_u32_local(uint32_t left, uint32_t right)
{
    return UINT32_MAX - left < right ? UINT32_MAX : left + right;
}

static void merge_orphan_journal_timeline_local(
    HfsPlusOrphanCatalogRecordLocal *target,
    const HfsPlusOrphanCatalogRecordLocal *source)
{
    if (target == NULL || source == NULL) return;
    target->journal_observations = saturating_add_u32_local(
        target->journal_observations, source->journal_observations);
    if (source->journal_active_observations > 0U) {
        if (target->journal_active_observations == 0U ||
            source->journal_active_first_rank <
                target->journal_active_first_rank) {
            target->journal_active_first_rank =
                source->journal_active_first_rank;
        }
        if (source->journal_active_last_rank >
            target->journal_active_last_rank) {
            target->journal_active_last_rank = source->journal_active_last_rank;
        }
        target->journal_active_observations = saturating_add_u32_local(
            target->journal_active_observations,
            source->journal_active_observations);
    }
}

static void deduplicate_orphan_records_local(void)
{
    size_t read_index;
    size_t write_index;

    if (g_hfsplus_orphan_record_count < 2U) return;
    write_index = 1U;
    for (read_index = 1U; read_index < g_hfsplus_orphan_record_count;
         ++read_index) {
        if (orphan_record_semantically_equal_local(
                &g_hfsplus_orphan_records[write_index - 1U],
                &g_hfsplus_orphan_records[read_index])) {
            merge_orphan_journal_timeline_local(
                &g_hfsplus_orphan_records[write_index - 1U],
                &g_hfsplus_orphan_records[read_index]);
            continue;
        }
        if (write_index != read_index) {
            g_hfsplus_orphan_records[write_index] =
                g_hfsplus_orphan_records[read_index];
        }
        write_index++;
    }
    g_hfsplus_orphan_record_count = write_index;
}

static int historical_folder_compare_local(const void *left, const void *right)
{
    const HfsPlusHistoricalFolderRecordLocal *a =
        (const HfsPlusHistoricalFolderRecordLocal *)left;
    const HfsPlusHistoricalFolderRecordLocal *b =
        (const HfsPlusHistoricalFolderRecordLocal *)right;
    int name_order;

    if (a->folder_id != b->folder_id) return a->folder_id < b->folder_id ? -1 : 1;
    if (a->parent_id != b->parent_id) return a->parent_id < b->parent_id ? -1 : 1;
    name_order = strcmp(
        historical_folder_name_local(a), historical_folder_name_local(b));
    if (name_order != 0) return name_order;
    if (a->create_date_hfs != b->create_date_hfs) {
        return a->create_date_hfs < b->create_date_hfs ? -1 : 1;
    }
    if (a->confidence != b->confidence) return a->confidence > b->confidence ? -1 : 1;
    if (a->source_node != b->source_node) return a->source_node < b->source_node ? -1 : 1;
    if (a->record_offset != b->record_offset) return a->record_offset < b->record_offset ? -1 : 1;
    return 0;
}

static int historical_folders_semantically_equal_local(
    const HfsPlusHistoricalFolderRecordLocal *left,
    const HfsPlusHistoricalFolderRecordLocal *right)
{
    return left != NULL && right != NULL &&
        left->folder_id == right->folder_id &&
        left->parent_id == right->parent_id &&
        left->create_date_hfs == right->create_date_hfs &&
        strcmp(historical_folder_name_local(left),
               historical_folder_name_local(right)) == 0;
}

static void merge_historical_folder_timeline_local(
    HfsPlusHistoricalFolderRecordLocal *target,
    const HfsPlusHistoricalFolderRecordLocal *source)
{
    if (target == NULL || source == NULL) return;
    target->journal_observations = saturating_add_u32_local(
        target->journal_observations, source->journal_observations);
    if (source->journal_active_observations > 0U) {
        if (target->journal_active_observations == 0U ||
            source->journal_active_first_rank <
                target->journal_active_first_rank) {
            target->journal_active_first_rank =
                source->journal_active_first_rank;
        }
        if (source->journal_active_last_rank >
            target->journal_active_last_rank) {
            target->journal_active_last_rank = source->journal_active_last_rank;
        }
        target->journal_active_observations = saturating_add_u32_local(
            target->journal_active_observations,
            source->journal_active_observations);
    }
}

static void deduplicate_historical_folders_local(void)
{
    size_t read_index;
    size_t write_index;

    if (g_hfsplus_historical_folder_count < 2U) return;
    write_index = 1U;
    for (read_index = 1U;
         read_index < g_hfsplus_historical_folder_count;
         ++read_index) {
        if (historical_folders_semantically_equal_local(
                &g_hfsplus_historical_folders[write_index - 1U],
                &g_hfsplus_historical_folders[read_index])) {
            merge_historical_folder_timeline_local(
                &g_hfsplus_historical_folders[write_index - 1U],
                &g_hfsplus_historical_folders[read_index]);
            continue;
        }
        if (write_index != read_index) {
            g_hfsplus_historical_folders[write_index] =
                g_hfsplus_historical_folders[read_index];
        }
        write_index++;
    }
    g_hfsplus_historical_folder_count = write_index;
}

static const char *orphan_provenance_label_local(uint8_t provenance)
{
    switch (provenance) {
        case HFSPLUS_ORPHAN_FREE_LEAF_TABLE: return "free_leaf_table";
        case HFSPLUS_ORPHAN_FREE_NODE_SCAN: return "free_node_scan";
        case HFSPLUS_ORPHAN_ALLOCATED_LEAF_SLACK: return "allocated_leaf_slack";
        case HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK:
            return "journal_catalog_block";
        default: return "unknown";
    }
}

static uint64_t orphan_fnv1a64_update_local(
    uint64_t hash,
    const void *data,
    size_t size)
{
    const unsigned char *bytes = (const unsigned char *)data;
    size_t index;

    for (index = 0U; index < size; ++index) {
        hash ^= bytes[index];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static int orphan_artifact_fingerprint_local(
    const char *path,
    uint64_t *hash_out,
    uint64_t *bytes_out)
{
    unsigned char buffer[64U * 1024U];
    uint64_t hash = 14695981039346656037ULL;
    uint64_t bytes = 0U;
    FILE *file;

    if (path == NULL || hash_out == NULL || bytes_out == NULL) return 0;
    file = fopen(path, "rb");
    if (file == NULL) return 0;
    for (;;) {
        size_t read_count = fread(buffer, 1U, sizeof(buffer), file);
        if (read_count > 0U) {
            hash = orphan_fnv1a64_update_local(hash, buffer, read_count);
            bytes += read_count;
        }
        if (read_count < sizeof(buffer)) {
            int ok = feof(file) != 0 && ferror(file) == 0;
            if (fclose(file) != 0) ok = 0;
            if (!ok) return 0;
            *hash_out = hash;
            *bytes_out = bytes;
            return 1;
        }
    }
}

static int write_orphan_catalog_artifacts_local(
    const HfsPlusBTreeHeaderLocal *header)
{
    char metadata_dir[HFSPLUS_PATH_MAX];
    char artifact_path[HFSPLUS_PATH_MAX];
    char artifact_temp[HFSPLUS_PATH_MAX + 32U];
    char folder_path[HFSPLUS_PATH_MAX];
    char folder_temp[HFSPLUS_PATH_MAX + 32U];
    char status_path[HFSPLUS_PATH_MAX];
    char status_temp[HFSPLUS_PATH_MAX + 32U];
    FILE *file;
    size_t index;
    uint64_t free_leaf_records = 0U;
    uint64_t free_scan_records = 0U;
    uint64_t allocated_slack_records = 0U;
    uint64_t journal_records = 0U;
    uint64_t artifact_hash = 0U;
    uint64_t artifact_bytes = 0U;
    uint64_t folder_hash = 0U;
    uint64_t folder_bytes = 0U;

    if (header == NULL || g_hfsplus_output_dir[0] == '\0' ||
        snprintf(metadata_dir, sizeof(metadata_dir), "%s/%s/metadata",
                 g_hfsplus_output_dir, APP_STATE_DIR_NAME) >=
            (int)sizeof(metadata_dir) ||
        !ensure_directory_path_local(metadata_dir) ||
        snprintf(artifact_path, sizeof(artifact_path),
                 "%s/hfs_orphan_catalog.tsv", metadata_dir) >=
            (int)sizeof(artifact_path) ||
        snprintf(artifact_temp, sizeof(artifact_temp), "%s.tmp", artifact_path) >=
            (int)sizeof(artifact_temp) ||
        snprintf(folder_path, sizeof(folder_path),
                 "%s/hfs_historical_folders.tsv", metadata_dir) >=
            (int)sizeof(folder_path) ||
        snprintf(folder_temp, sizeof(folder_temp), "%s.tmp", folder_path) >=
            (int)sizeof(folder_temp) ||
        snprintf(status_path, sizeof(status_path),
                 "%s/hfs_orphan_catalog_status.txt", metadata_dir) >=
            (int)sizeof(status_path) ||
        snprintf(status_temp, sizeof(status_temp), "%s.tmp", status_path) >=
            (int)sizeof(status_temp)) return 0;

    file = fopen(artifact_temp, "w");
    if (file == NULL) return 0;
    fprintf(file,
            "offset\tdata_size\tallocated_size\tfile_id\tparent_id\tcreate_date_hfs\tsource_node\trecord_offset\tconfidence\tprovenance\tjournal_observations\tjournal_active_observations\tjournal_active_first_rank\tjournal_active_last_rank\tname\n");
    for (index = 0U; index < g_hfsplus_orphan_record_count; ++index) {
        const HfsPlusOrphanCatalogRecordLocal *record =
            &g_hfsplus_orphan_records[index];

        if (record->provenance == HFSPLUS_ORPHAN_FREE_LEAF_TABLE) free_leaf_records++;
        else if (record->provenance == HFSPLUS_ORPHAN_FREE_NODE_SCAN) free_scan_records++;
        else if (record->provenance == HFSPLUS_ORPHAN_ALLOCATED_LEAF_SLACK) {
            allocated_slack_records++;
        }
        else if (record->provenance == HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK) {
            journal_records++;
        }
        fprintf(file, "%llu\t%llu\t%llu\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t",
                (unsigned long long)record->abs_offset,
                (unsigned long long)record->data_size,
                (unsigned long long)record->allocated_size,
                record->file_id,
                record->parent_id,
                record->create_date_hfs,
                record->source_node,
                (unsigned int)record->record_offset,
                (unsigned int)record->confidence,
                (unsigned int)record->provenance,
                record->journal_observations,
                record->journal_active_observations,
                record->journal_active_first_rank,
                record->journal_active_last_rank);
        write_tsv_text_local(file, orphan_record_name_local(record));
        fputc('\n', file);
    }
    {
        int failed = ferror(file) != 0;
        if (fclose(file) != 0) failed = 1;
        if (failed || rename(artifact_temp, artifact_path) != 0) {
            (void)unlink(artifact_temp);
            return 0;
        }
    }
    (void)chmod(artifact_path, 0644);
    (void)mft_apply_output_owner_to_path(artifact_path);
    if (!orphan_artifact_fingerprint_local(
            artifact_path, &artifact_hash, &artifact_bytes)) return 0;

    file = fopen(folder_temp, "w");
    if (file == NULL) return 0;
    fprintf(file,
            "folder_id\tparent_id\tcreate_date_hfs\tsource_node\trecord_offset\tconfidence\tprovenance\tjournal_observations\tjournal_active_observations\tjournal_active_first_rank\tjournal_active_last_rank\tname\n");
    for (index = 0U; index < g_hfsplus_historical_folder_count; ++index) {
        const HfsPlusHistoricalFolderRecordLocal *record =
            &g_hfsplus_historical_folders[index];

        fprintf(file, "%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t%u\t",
                record->folder_id,
                record->parent_id,
                record->create_date_hfs,
                record->source_node,
                (unsigned int)record->record_offset,
                (unsigned int)record->confidence,
                (unsigned int)record->provenance,
                record->journal_observations,
                record->journal_active_observations,
                record->journal_active_first_rank,
                record->journal_active_last_rank);
        write_tsv_text_local(file, historical_folder_name_local(record));
        fputc('\n', file);
    }
    {
        int failed = ferror(file) != 0;
        if (fclose(file) != 0) failed = 1;
        if (failed || rename(folder_temp, folder_path) != 0) {
            (void)unlink(folder_temp);
            return 0;
        }
    }
    (void)chmod(folder_path, 0644);
    (void)mft_apply_output_owner_to_path(folder_path);
    if (!orphan_artifact_fingerprint_local(
            folder_path, &folder_hash, &folder_bytes)) return 0;

    file = fopen(status_temp, "w");
    if (file == NULL) return 0;
    fprintf(file, "format_version=4\nbackend=hfsplus\nstatus=ready\n");
    fprintf(file,
            "policy_effect=none\norigin=catalog_free_nodes_slack_and_checksummed_journal\n");
    fprintf(file, "volume_uuid=%016llx\n",
            (unsigned long long)g_hfsplus_geometry.volume_uuid);
    fprintf(file, "modify_date_hfs=%u\nwrite_count=%u\njournal_info_block=%u\n",
            g_hfsplus_geometry.modify_date_hfs,
            g_hfsplus_geometry.write_count,
            g_hfsplus_geometry.journal_info_block);
    fprintf(file, "node_size=%u\ntotal_nodes=%u\nfree_nodes_header=%u\n",
            header->node_size, header->total_nodes, header->free_nodes);
    fprintf(file, "nodes_scanned=%llu\nfree_nodes_scanned=%llu\n",
            (unsigned long long)g_hfsplus_orphan_nodes_scanned,
            (unsigned long long)g_hfsplus_orphan_free_nodes_scanned);
    fprintf(file, "slack_bytes_scanned=%llu\nrejected_probes=%llu\n",
            (unsigned long long)g_hfsplus_orphan_slack_bytes_scanned,
            (unsigned long long)g_hfsplus_orphan_rejected_candidates);
    fprintf(file, "candidates=%zu\nfree_leaf_table_candidates=%llu\n",
            g_hfsplus_orphan_record_count,
            (unsigned long long)free_leaf_records);
    fprintf(file, "free_node_scan_candidates=%llu\nallocated_leaf_slack_candidates=%llu\n",
            (unsigned long long)free_scan_records,
            (unsigned long long)allocated_slack_records);
    fprintf(file, "journal_catalog_candidates=%llu\n",
            (unsigned long long)journal_records);
    fprintf(file,
            "journal_scan_attempted=%d\njournal_header_valid=%d\njournal_offset=%llu\njournal_size=%llu\njournal_bytes_read=%llu\n",
            g_hfsplus_journal_scan_attempted ? 1 : 0,
            g_hfsplus_journal_header_valid ? 1 : 0,
            (unsigned long long)g_hfsplus_journal_offset,
            (unsigned long long)g_hfsplus_journal_size,
            (unsigned long long)g_hfsplus_journal_bytes_read);
    fprintf(file,
            "journal_sequence=%u\njournal_header_checksum=%08x\njournal_byte_order=%s\njournal_header_candidates=%llu\njournal_valid_transactions=%llu\njournal_active_transactions=%llu\njournal_checksum_rejections=%llu\n",
            g_hfsplus_journal_sequence,
            g_hfsplus_journal_header_checksum,
            g_hfsplus_journal_little_endian ? "little" : "big",
            (unsigned long long)g_hfsplus_journal_header_candidates,
            (unsigned long long)g_hfsplus_journal_valid_transactions,
            (unsigned long long)g_hfsplus_journal_active_transactions,
            (unsigned long long)g_hfsplus_journal_checksum_rejections);
    fprintf(file,
            "journal_catalog_blocks=%llu\njournal_catalog_records_raw=%llu\njournal_folder_records_raw=%llu\n",
            (unsigned long long)g_hfsplus_journal_catalog_blocks,
            (unsigned long long)g_hfsplus_journal_catalog_records,
            (unsigned long long)g_hfsplus_journal_folder_records);
    fprintf(file, "truncated=%d\nstring_bytes=%zu\nartifact_bytes=%llu\n",
            g_hfsplus_orphan_truncated ? 1 : 0,
            g_hfsplus_orphan_string_bytes,
            (unsigned long long)artifact_bytes);
    fprintf(file, "artifact_fnv1a64=%016llx\n",
            (unsigned long long)artifact_hash);
    fprintf(file,
            "historical_folders=%zu\nhistorical_folder_bytes=%llu\nhistorical_folder_fnv1a64=%016llx\nhistorical_folder_artifact=hfs_historical_folders.tsv\n",
            g_hfsplus_historical_folder_count,
            (unsigned long long)folder_bytes,
            (unsigned long long)folder_hash);
    fprintf(file, "artifact=hfs_orphan_catalog.tsv\nupdated_unix=%llu\n",
            (unsigned long long)time(NULL));
    if (fclose(file) != 0 || rename(status_temp, status_path) != 0) {
        (void)unlink(status_temp);
        return 0;
    }
    (void)chmod(status_path, 0644);
    (void)mft_apply_output_owner_to_path(status_path);
    return 1;
}

static int parse_u64_text_local(const char *text, uint64_t *value_out)
{
    char *end = NULL;
    unsigned long long value;

    if (text == NULL || text[0] == '\0' || value_out == NULL) return 0;
    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') return 0;
    *value_out = (uint64_t)value;
    return 1;
}

static int read_hfsplus_journal_identity_local(
    FILE *input_file,
    uint64_t *offset_out,
    uint64_t *size_out,
    uint32_t *sequence_out,
    uint32_t *checksum_out)
{
    unsigned char journal_info[HFSPLUS_JOURNAL_INFO_SIZE];
    unsigned char journal_header[48U];
    unsigned char checksum_bytes[HFSPLUS_JOURNAL_HEADER_CHECKSUM_SIZE];
    uint64_t info_relative;
    uint64_t journal_relative;
    uint64_t journal_size;
    uint64_t journal_absolute;
    uint32_t flags;
    uint32_t magic;
    uint32_t stored_checksum;
    int little_endian;

    if (input_file == NULL || offset_out == NULL || size_out == NULL ||
        sequence_out == NULL || checksum_out == NULL ||
        g_hfsplus_geometry.journal_info_block == 0U ||
        g_hfsplus_geometry.block_size == 0U) return 0;
    info_relative = (uint64_t)g_hfsplus_geometry.journal_info_block *
        g_hfsplus_geometry.block_size;
    if (info_relative > g_hfsplus_geometry.volume_size ||
        sizeof(journal_info) > g_hfsplus_geometry.volume_size - info_relative ||
        g_hfsplus_geometry.volume_offset > UINT64_MAX - info_relative ||
        !read_bytes_at_local(
            input_file,
            g_hfsplus_geometry.volume_offset + info_relative,
            journal_info,
            sizeof(journal_info))) return 0;
    flags = read_u32_be_local(journal_info);
    journal_relative = read_u64_be_local(journal_info + 36U);
    journal_size = read_u64_be_local(journal_info + 44U);
    if ((flags & HFSPLUS_JOURNAL_IN_FS_MASK) == 0U ||
        (flags & (HFSPLUS_JOURNAL_EXTERNAL_MASK |
                  HFSPLUS_JOURNAL_NEED_INIT_MASK)) != 0U ||
        journal_relative > g_hfsplus_geometry.volume_size ||
        journal_size > g_hfsplus_geometry.volume_size - journal_relative ||
        g_hfsplus_geometry.volume_offset > UINT64_MAX - journal_relative) {
        return 0;
    }
    journal_absolute = g_hfsplus_geometry.volume_offset + journal_relative;
    if (!read_bytes_at_local(
            input_file, journal_absolute, journal_header,
            sizeof(journal_header))) return 0;
    if (read_u32_le_local(journal_header + 4U) ==
            HFSPLUS_JOURNAL_ENDIAN_MAGIC) little_endian = 1;
    else if (read_u32_be_local(journal_header + 4U) ==
                 HFSPLUS_JOURNAL_ENDIAN_MAGIC) little_endian = 0;
    else return 0;
    magic = hfsplus_journal_u32_local(journal_header, little_endian);
    if (magic != HFSPLUS_JOURNAL_HEADER_MAGIC &&
        magic != HFSPLUS_OLD_JOURNAL_HEADER_MAGIC) return 0;
    stored_checksum = hfsplus_journal_u32_local(
        journal_header + 36U, little_endian);
    memcpy(checksum_bytes, journal_header, sizeof(checksum_bytes));
    memset(checksum_bytes + 36U, 0, 4U);
    if (magic == HFSPLUS_JOURNAL_HEADER_MAGIC &&
        hfsplus_journal_checksum_local(
            checksum_bytes, sizeof(checksum_bytes)) != stored_checksum) return 0;
    *offset_out = journal_relative;
    *size_out = journal_size;
    *sequence_out = hfsplus_journal_u32_local(
        journal_header + 44U, little_endian);
    *checksum_out = stored_checksum;
    return 1;
}

static int load_orphan_catalog_artifact_local(FILE *input_file)
{
    char metadata_dir[HFSPLUS_PATH_MAX];
    char artifact_path[HFSPLUS_PATH_MAX];
    char folder_path[HFSPLUS_PATH_MAX];
    char status_path[HFSPLUS_PATH_MAX];
    char line[2048];
    FILE *file;
    uint64_t status_uuid = 0U;
    uint64_t status_modify = 0U;
    uint64_t status_write_count = 0U;
    uint64_t status_journal = 0U;
    uint64_t status_candidates = 0U;
    uint64_t status_artifact_bytes = 0U;
    uint64_t status_artifact_hash = 0U;
    uint64_t status_folder_count = 0U;
    uint64_t status_folder_bytes = 0U;
    uint64_t status_folder_hash = 0U;
    uint64_t status_journal_offset = 0U;
    uint64_t status_journal_size = 0U;
    uint64_t status_journal_sequence = 0U;
    uint64_t status_journal_checksum = 0U;
    int format_ok = 0;
    int backend_ok = 0;
    int policy_ok = 0;
    int candidates_seen = 0;
    int artifact_bytes_seen = 0;
    int artifact_hash_seen = 0;
    int folder_count_seen = 0;
    int folder_bytes_seen = 0;
    int folder_hash_seen = 0;
    int journal_offset_seen = 0;
    int journal_size_seen = 0;
    int journal_sequence_seen = 0;
    int journal_checksum_seen = 0;
    int ready = 0;

    if (g_hfsplus_output_dir[0] == '\0' ||
        snprintf(metadata_dir, sizeof(metadata_dir), "%s/%s/metadata",
                 g_hfsplus_output_dir, APP_STATE_DIR_NAME) >=
            (int)sizeof(metadata_dir) ||
        snprintf(artifact_path, sizeof(artifact_path),
                 "%s/hfs_orphan_catalog.tsv", metadata_dir) >=
            (int)sizeof(artifact_path) ||
        snprintf(folder_path, sizeof(folder_path),
                 "%s/hfs_historical_folders.tsv", metadata_dir) >=
            (int)sizeof(folder_path) ||
        snprintf(status_path, sizeof(status_path),
                 "%s/hfs_orphan_catalog_status.txt", metadata_dir) >=
            (int)sizeof(status_path)) return 0;
    file = fopen(status_path, "r");
    if (file == NULL) return 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned long long value;
        if (strcmp(line, "format_version=4\n") == 0) format_ok = 1;
        else if (strcmp(line, "backend=hfsplus\n") == 0) backend_ok = 1;
        else if (strcmp(line, "status=ready\n") == 0) ready = 1;
        else if (strcmp(line, "policy_effect=none\n") == 0) policy_ok = 1;
        else if (sscanf(line, "volume_uuid=%llx", &value) == 1) status_uuid = value;
        else if (sscanf(line, "modify_date_hfs=%llu", &value) == 1) status_modify = value;
        else if (sscanf(line, "write_count=%llu", &value) == 1) status_write_count = value;
        else if (sscanf(line, "journal_info_block=%llu", &value) == 1) status_journal = value;
        else if (sscanf(line, "candidates=%llu", &value) == 1) {
            status_candidates = value;
            candidates_seen = 1;
        }
        else if (sscanf(line, "artifact_bytes=%llu", &value) == 1) {
            status_artifact_bytes = value;
            artifact_bytes_seen = 1;
        }
        else if (sscanf(line, "artifact_fnv1a64=%llx", &value) == 1) {
            status_artifact_hash = value;
            artifact_hash_seen = 1;
        }
        else if (sscanf(line, "historical_folders=%llu", &value) == 1) {
            status_folder_count = value;
            folder_count_seen = 1;
        }
        else if (sscanf(line, "historical_folder_bytes=%llu", &value) == 1) {
            status_folder_bytes = value;
            folder_bytes_seen = 1;
        }
        else if (sscanf(line, "historical_folder_fnv1a64=%llx", &value) == 1) {
            status_folder_hash = value;
            folder_hash_seen = 1;
        }
        else if (sscanf(line, "journal_offset=%llu", &value) == 1) {
            status_journal_offset = value;
            journal_offset_seen = 1;
        }
        else if (sscanf(line, "journal_size=%llu", &value) == 1) {
            status_journal_size = value;
            journal_size_seen = 1;
        }
        else if (sscanf(line, "journal_sequence=%llu", &value) == 1) {
            status_journal_sequence = value;
            journal_sequence_seen = 1;
        }
        else if (sscanf(line, "journal_header_checksum=%llx", &value) == 1) {
            status_journal_checksum = value;
            journal_checksum_seen = 1;
        }
    }
    fclose(file);
    if (!format_ok || !backend_ok || !ready || !policy_ok || !candidates_seen ||
        !artifact_bytes_seen || !artifact_hash_seen ||
        !folder_count_seen || !folder_bytes_seen || !folder_hash_seen ||
        !journal_offset_seen || !journal_size_seen ||
        !journal_sequence_seen || !journal_checksum_seen ||
        status_candidates > HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS ||
        status_folder_count > HFSPLUS_MAX_ORPHAN_CATALOG_RECORDS ||
        status_uuid != g_hfsplus_geometry.volume_uuid ||
        status_modify != g_hfsplus_geometry.modify_date_hfs ||
        status_write_count != g_hfsplus_geometry.write_count ||
        status_journal != g_hfsplus_geometry.journal_info_block) return 0;

    if (status_journal_size > 0U) {
        uint64_t current_offset = 0U;
        uint64_t current_size = 0U;
        uint32_t current_sequence = 0U;
        uint32_t current_checksum = 0U;
        if (!read_hfsplus_journal_identity_local(
                input_file, &current_offset, &current_size,
                &current_sequence, &current_checksum) ||
            current_offset != status_journal_offset ||
            current_size != status_journal_size ||
            current_sequence != status_journal_sequence ||
            current_checksum != status_journal_checksum) return 0;
    }

    {
        uint64_t actual_hash = 0U;
        uint64_t actual_bytes = 0U;
        if (!orphan_artifact_fingerprint_local(
                artifact_path, &actual_hash, &actual_bytes) ||
            actual_hash != status_artifact_hash ||
            actual_bytes != status_artifact_bytes) return 0;
        if (!orphan_artifact_fingerprint_local(
                folder_path, &actual_hash, &actual_bytes) ||
            actual_hash != status_folder_hash ||
            actual_bytes != status_folder_bytes) return 0;
    }
    file = fopen(artifact_path, "r");
    if (file == NULL) return 0;
    free_orphan_catalog_local();
    if (fgets(line, sizeof(line), file) == NULL ||
        strcmp(line,
               "offset\tdata_size\tallocated_size\tfile_id\tparent_id\tcreate_date_hfs\tsource_node\trecord_offset\tconfidence\tprovenance\tjournal_observations\tjournal_active_observations\tjournal_active_first_rank\tjournal_active_last_rank\tname\n") != 0) {
        fclose(file);
        return 0;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        HfsPlusOrphanCatalogRecordLocal record = {0};
        char *fields[15];
        char *cursor = line;
        size_t field_count = 0U;
        uint64_t values[14];
        size_t index;

        while (field_count < 15U) {
            char *tab;
            fields[field_count++] = cursor;
            tab = strchr(cursor, '\t');
            if (tab == NULL) break;
            *tab = '\0';
            cursor = tab + 1U;
        }
        if (field_count != 15U) goto invalid_artifact;
        fields[14][strcspn(fields[14], "\r\n")] = '\0';
        for (index = 0U; index < 14U; ++index) {
            if (!parse_u64_text_local(fields[index], &values[index])) break;
        }
        if (index != 14U || values[0] < g_hfsplus_geometry.volume_offset ||
            values[0] - g_hfsplus_geometry.volume_offset >=
                g_hfsplus_geometry.volume_size ||
            values[1] == 0U || values[1] > g_hfsplus_geometry.volume_size ||
            values[2] < values[1] ||
            values[3] < 16U || values[3] > UINT32_MAX ||
            values[4] < HFSPLUS_ROOT_FOLDER_ID || values[4] > UINT32_MAX ||
            values[3] == values[4] ||
            values[5] > UINT32_MAX || values[6] > UINT32_MAX ||
            values[7] > UINT16_MAX || values[8] > UINT8_MAX ||
            values[9] < HFSPLUS_ORPHAN_FREE_LEAF_TABLE ||
            values[9] > HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK ||
            (values[9] == HFSPLUS_ORPHAN_FREE_LEAF_TABLE && values[8] != 95U) ||
            (values[9] == HFSPLUS_ORPHAN_FREE_NODE_SCAN &&
             values[8] != 80U && values[8] != 82U) ||
            (values[9] == HFSPLUS_ORPHAN_ALLOCATED_LEAF_SLACK &&
             values[8] != 75U) ||
            (values[9] == HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK &&
             values[8] != 98U) ||
            values[10] > UINT32_MAX || values[11] > values[10] ||
            values[12] > UINT32_MAX || values[13] > UINT32_MAX ||
            ((values[11] == 0U) !=
             (values[12] == 0U && values[13] == 0U)) ||
            (values[11] > 0U &&
             (values[12] == 0U || values[13] < values[12])) ||
            (values[9] == HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK &&
             values[10] == 0U) ||
            (values[9] != HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK &&
             values[10] != 0U) ||
            fields[14][0] == '\0') goto invalid_artifact;
        record.abs_offset = values[0];
        record.data_size = values[1];
        record.allocated_size = values[2];
        record.file_id = (uint32_t)values[3];
        record.parent_id = (uint32_t)values[4];
        record.create_date_hfs = (uint32_t)values[5];
        record.source_node = (uint32_t)values[6];
        record.record_offset = (uint16_t)values[7];
        record.confidence = (uint8_t)values[8];
        record.provenance = (uint8_t)values[9];
        record.journal_observations = (uint32_t)values[10];
        record.journal_active_observations = (uint32_t)values[11];
        record.journal_active_first_rank = (uint32_t)values[12];
        record.journal_active_last_rank = (uint32_t)values[13];
        if (!append_orphan_record_local(&record, fields[14])) {
            fclose(file);
            free_orphan_catalog_local();
            return 0;
        }
    }
    {
        int read_failed = ferror(file) != 0;
        int close_failed = fclose(file) != 0;
        file = NULL;
        if (read_failed || close_failed ||
            g_hfsplus_orphan_record_count != (size_t)status_candidates) {
            goto invalid_artifact;
        }
    }
    file = fopen(folder_path, "r");
    if (file == NULL) goto invalid_artifact;
    if (fgets(line, sizeof(line), file) == NULL ||
        strcmp(line,
               "folder_id\tparent_id\tcreate_date_hfs\tsource_node\trecord_offset\tconfidence\tprovenance\tjournal_observations\tjournal_active_observations\tjournal_active_first_rank\tjournal_active_last_rank\tname\n") != 0) {
        goto invalid_artifact;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        HfsPlusHistoricalFolderRecordLocal record = {0};
        char *fields[12];
        char *cursor = line;
        size_t field_count = 0U;
        uint64_t values[11];
        size_t index;

        while (field_count < 12U) {
            char *tab;
            fields[field_count++] = cursor;
            tab = strchr(cursor, '\t');
            if (tab == NULL) break;
            *tab = '\0';
            cursor = tab + 1U;
        }
        if (field_count != 12U) goto invalid_artifact;
        fields[11][strcspn(fields[11], "\r\n")] = '\0';
        for (index = 0U; index < 11U; ++index) {
            if (!parse_u64_text_local(fields[index], &values[index])) break;
        }
        if (index != 11U ||
            values[0] < HFSPLUS_ROOT_FOLDER_ID || values[0] > UINT32_MAX ||
            values[1] < 1U || values[1] > UINT32_MAX ||
            values[0] == values[1] || values[2] > UINT32_MAX ||
            values[3] > UINT32_MAX || values[4] > UINT16_MAX ||
            values[5] != 98U ||
            values[6] != HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK ||
            values[7] == 0U || values[7] > UINT32_MAX ||
            values[8] > values[7] || values[9] > UINT32_MAX ||
            values[10] > UINT32_MAX ||
            ((values[8] == 0U) !=
             (values[9] == 0U && values[10] == 0U)) ||
            (values[8] > 0U &&
             (values[9] == 0U || values[10] < values[9])) ||
            fields[11][0] == '\0') goto invalid_artifact;
        record.folder_id = (uint32_t)values[0];
        record.parent_id = (uint32_t)values[1];
        record.create_date_hfs = (uint32_t)values[2];
        record.source_node = (uint32_t)values[3];
        record.record_offset = (uint16_t)values[4];
        record.confidence = (uint8_t)values[5];
        record.provenance = (uint8_t)values[6];
        record.journal_observations = (uint32_t)values[7];
        record.journal_active_observations = (uint32_t)values[8];
        record.journal_active_first_rank = (uint32_t)values[9];
        record.journal_active_last_rank = (uint32_t)values[10];
        if (!append_historical_folder_local(&record, fields[11])) {
            goto invalid_artifact;
        }
    }
    {
        int read_failed = ferror(file) != 0;
        int close_failed = fclose(file) != 0;
        file = NULL;
        if (read_failed || close_failed ||
            g_hfsplus_historical_folder_count !=
                (size_t)status_folder_count) goto invalid_artifact;
    }
    if (g_hfsplus_orphan_record_count > 1U) {
        qsort(g_hfsplus_orphan_records, g_hfsplus_orphan_record_count,
              sizeof(*g_hfsplus_orphan_records), orphan_record_compare_local);
        deduplicate_orphan_records_local();
    }
    if (g_hfsplus_historical_folder_count > 1U) {
        qsort(
            g_hfsplus_historical_folders,
            g_hfsplus_historical_folder_count,
            sizeof(*g_hfsplus_historical_folders),
            historical_folder_compare_local);
        deduplicate_historical_folders_local();
    }
    g_hfsplus_orphan_ready = 1;
    log_info(
        "HFS+ orphan Catalog index reused: candidates=%zu historical_folders=%zu string_bytes=%zu",
        g_hfsplus_orphan_record_count,
        g_hfsplus_historical_folder_count,
        g_hfsplus_orphan_string_bytes);
    return 1;

invalid_artifact:
    if (file != NULL) fclose(file);
    free_orphan_catalog_local();
    return 0;
}

static int finish_orphan_catalog_scan_local(
    const HfsPlusBTreeHeaderLocal *header,
    const char *origin_label)
{
    if (header == NULL) return 0;
    if (g_hfsplus_orphan_record_count > 1U) {
        qsort(g_hfsplus_orphan_records, g_hfsplus_orphan_record_count,
              sizeof(*g_hfsplus_orphan_records), orphan_record_compare_local);
        deduplicate_orphan_records_local();
    }
    if (g_hfsplus_historical_folder_count > 1U) {
        qsort(
            g_hfsplus_historical_folders,
            g_hfsplus_historical_folder_count,
            sizeof(*g_hfsplus_historical_folders),
            historical_folder_compare_local);
        deduplicate_historical_folders_local();
    }
    g_hfsplus_orphan_ready = 1;
    if (!write_orphan_catalog_artifacts_local(header)) {
        log_info(
            "HFS+ orphan Catalog candidates were collected but their state artifact could not be written"
        );
    }
    log_info(
        "HFS+ orphan Catalog archaeology (%s): candidates=%zu historical_folders=%zu free_nodes=%llu slack=%.2f MiB rejected_probes=%llu truncated=%d",
        origin_label != NULL ? origin_label : "catalog_scan",
        g_hfsplus_orphan_record_count,
        g_hfsplus_historical_folder_count,
        (unsigned long long)g_hfsplus_orphan_free_nodes_scanned,
        (double)g_hfsplus_orphan_slack_bytes_scanned / (1024.0 * 1024.0),
        (unsigned long long)g_hfsplus_orphan_rejected_candidates,
        g_hfsplus_orphan_truncated ? 1 : 0);
    return 1;
}

static int parse_catalog_entries_local(FILE *input_file)
{
    HfsPlusBTreeHeaderLocal header = {0};
    unsigned char *node_bitmap = NULL;
    size_t node_bitmap_bytes = 0U;
    unsigned char *read_ahead = NULL;
    size_t read_ahead_capacity = 0U;
    uint64_t cached_logical_start = 0U;
    size_t cached_bytes = 0U;
    uint64_t cache_reads = 0U;
    uint64_t cache_bytes = 0U;
    uint32_t current_node;
    uint32_t visited_nodes = 0U;
    uint64_t visited_records = 0U;
    double catalog_started_at = monotonic_seconds_local();
    double last_progress_at = 0.0;
    double last_progress_log_at = 0.0;

    if (input_file == NULL) {
        return 0;
    }

    if (!materialize_fork_local(
            HFSPLUS_FORK_TYPE_DATA,
            HFSPLUS_CATALOG_FILE_ID,
            &g_hfsplus_catalog_fork,
            &g_hfsplus_catalog_resolved_fork)) {
        log_info("HFS+ could not materialize the catalog fork from inline + overflow extents");
        return 0;
    }
    if (!load_btree_header_from_resolved_fork_local(
            input_file,
            &g_hfsplus_geometry,
            &g_hfsplus_catalog_resolved_fork,
            &header)) {
        log_info("HFS+ catalog B-tree header could not be read from the resolved catalog fork");
        return 0;
    }
    if (!load_catalog_node_bitmap_local(
            input_file, &header, &node_bitmap, &node_bitmap_bytes)) {
        log_info(
            "HFS+ Catalog allocation bitmap was not usable; live Catalog parsing will continue, but orphan-node archaeology is disabled for this pass"
        );
    }

    read_ahead_capacity = HFSPLUS_CATALOG_READ_AHEAD_BYTES;
    if (read_ahead_capacity < header.node_size) read_ahead_capacity = header.node_size;
    if ((uint64_t)read_ahead_capacity > g_hfsplus_catalog_resolved_fork.logical_size) {
        read_ahead_capacity = (size_t)g_hfsplus_catalog_resolved_fork.logical_size;
    }
    read_ahead_capacity -= read_ahead_capacity % header.node_size;
    if (read_ahead_capacity < header.node_size) read_ahead_capacity = header.node_size;
    read_ahead = (unsigned char *)malloc(read_ahead_capacity);
    if (read_ahead == NULL) {
        free(node_bitmap);
        return 0;
    }

    g_hfsplus_sort_case_sensitive = header.key_compare_type == 0xBCU;
    /*
     * Read the Catalog B-tree in logical node order.  The leaf-chain order is
     * useful for key traversal, but it is not guaranteed to be physical (or
     * even logical-node) order.  Starting a large read-ahead window at every
     * linked leaf therefore caused massive overlap on real Catalog files.
     * A sequential node walk reads the tree once and simply ignores non-leaf
     * nodes; leaf records are still encountered in their on-disk key order
     * within each node, while path reconstruction below is ID based and does
     * not depend on leaf-chain order.
     */
    current_node = 0U;
    while (current_node < header.total_nodes) {
        uint64_t node_logical_offset =
            (uint64_t)current_node * (uint64_t)header.node_size;
        const unsigned char *node;
        int node_allocated;
        uint16_t num_records;
        uint16_t free_space_offset;
        size_t record_index;

        if (app_stop_requested()) {
            free(read_ahead);
            free(node_bitmap);
            errno = ECANCELED;
            return 0;
        }
        if (node_logical_offset < cached_logical_start ||
            node_logical_offset - cached_logical_start > cached_bytes ||
            cached_bytes - (size_t)(node_logical_offset - cached_logical_start) <
                header.node_size) {
            uint64_t remaining;
            size_t wanted;

            if (node_logical_offset >= g_hfsplus_catalog_resolved_fork.logical_size) {
                free(read_ahead);
                free(node_bitmap);
                return 0;
            }
            remaining = g_hfsplus_catalog_resolved_fork.logical_size - node_logical_offset;
            wanted = remaining < (uint64_t)read_ahead_capacity
                ? (size_t)remaining
                : read_ahead_capacity;
            wanted -= wanted % header.node_size;
            if (wanted < header.node_size) wanted = header.node_size;
            if (!read_resolved_fork_bytes_local(
                    input_file,
                    &g_hfsplus_geometry,
                    &g_hfsplus_catalog_resolved_fork,
                    node_logical_offset,
                    read_ahead,
                    wanted)) {
                wanted = header.node_size;
                if (!read_resolved_fork_bytes_local(
                        input_file,
                        &g_hfsplus_geometry,
                        &g_hfsplus_catalog_resolved_fork,
                        node_logical_offset,
                        read_ahead,
                        wanted)) {
                    free(read_ahead);
                    free(node_bitmap);
                    return 0;
                }
            }
            cached_logical_start = node_logical_offset;
            cached_bytes = wanted;
            cache_reads++;
            cache_bytes += wanted;
        }
        node = read_ahead + (size_t)(node_logical_offset - cached_logical_start);
        node_allocated = catalog_node_is_allocated_local(
            node_bitmap, node_bitmap_bytes, current_node);
        if (node_bitmap != NULL && !node_allocated) {
            scan_catalog_node_for_orphans_local(
                node, &header, current_node, 0);
            ++current_node;
            continue;
        }
        if ((int8_t)node[8] != HFSPLUS_BT_LEAF_NODE) {
            ++current_node;
            continue;
        }

        num_records = read_u16_be_local(node + 10U);
        if (((size_t)num_records + 1U) * 2U > (size_t)header.node_size) {
            free(read_ahead);
            free(node_bitmap);
            return 0;
        }
        if (!read_btree_record_offset_local(
                node,
                header.node_size,
                num_records,
                num_records,
                &free_space_offset)) {
            free(read_ahead);
            free(node_bitmap);
            return 0;
        }
        if (free_space_offset > header.node_size) {
            free(read_ahead);
            free(node_bitmap);
            return 0;
        }
        for (record_index = 0U; record_index < (size_t)num_records; ++record_index) {
            uint16_t record_start;
            uint16_t record_end;
            uint16_t key_length;
            uint16_t name_char_count;
            uint16_t record_type;
            uint32_t parent_id;
            size_t data_offset;
            HfsPlusCatalogEntry entry = {0};

            if (!read_btree_record_offset_local(
                    node,
                    header.node_size,
                    num_records,
                    (uint16_t)record_index,
                    &record_start)) {
                free(read_ahead);
                free(node_bitmap);
                return 0;
            }
            if (record_index + 1U < (size_t)num_records) {
                if (!read_btree_record_offset_local(
                        node,
                        header.node_size,
                        num_records,
                        (uint16_t)(record_index + 1U),
                        &record_end)) {
                    free(read_ahead);
                    free(node_bitmap);
                    return 0;
                }
            } else {
                record_end = free_space_offset;
            }

            if (record_start < 14U ||
                record_end <= record_start ||
                record_end > header.node_size ||
                record_start + 8U > record_end) {
                continue;
            }

            key_length = read_u16_be_local(node + record_start);
            if (key_length < 6U || record_start + 2U + key_length > record_end) {
                continue;
            }

            parent_id = read_u32_be_local(node + record_start + 2U);
            name_char_count = read_u16_be_local(node + record_start + 6U);
            data_offset = (size_t)record_start + 2U + (size_t)key_length;
            if ((data_offset & 1U) != 0U) {
                ++data_offset;
            }
            if (data_offset + 2U > (size_t)record_end) {
                continue;
            }

            record_type = read_u16_be_local(node + data_offset);
            if (record_type != HFSPLUS_CATALOG_FOLDER_RECORD &&
                record_type != HFSPLUS_CATALOG_FILE_RECORD) {
                continue;
            }
            if ((size_t)record_start + 8U + ((size_t)name_char_count * 2U) > (size_t)record_end) {
                continue;
            }

            memset(&entry, 0, sizeof(entry));
            entry.parent_id = parent_id;
            entry.has_name = name_char_count > 0U ? 1 : 0;
            entry.is_hardlink_metadata_directory =
                record_type == HFSPLUS_CATALOG_FOLDER_RECORD &&
                hfsplus_name_is_hardlink_metadata_directory_local(
                    node + record_start + 8U,
                    name_char_count);
            utf16be_to_utf8_local(
                node + record_start + 8U,
                name_char_count,
                entry.name,
                sizeof(entry.name)
            );
            if (record_type == HFSPLUS_CATALOG_FOLDER_RECORD &&
                strcmp(
                    entry.name,
                    HFSPLUS_DIRECTORY_HARDLINK_PRIVATE_DIR_PORTABLE) == 0) {
                entry.is_hardlink_metadata_directory = 1;
            }

            if (record_type == HFSPLUS_CATALOG_FOLDER_RECORD) {
                if (data_offset + 16U > (size_t)record_end) {
                    continue;
                }
                entry.is_directory = 1;
                entry.file_id = read_u32_be_local(node + data_offset + 8U);
                entry.create_date_hfs = read_u32_be_local(node + data_offset + 12U);
                entry.created_unix = hfsplus_seconds_to_unix_local(entry.create_date_hfs);
            } else {
                HfsPlusForkDataLocal data_fork = {0};

                if (data_offset + 168U > (size_t)record_end) {
                    continue;
                }
                entry.is_directory = 0;
                entry.file_id = read_u32_be_local(node + data_offset + 8U);
                entry.create_date_hfs = read_u32_be_local(node + data_offset + 12U);
                entry.created_unix = hfsplus_seconds_to_unix_local(entry.create_date_hfs);
                if (read_u32_be_local(node + data_offset + 48U) ==
                        HFSPLUS_HARDLINK_FILE_TYPE &&
                    read_u32_be_local(node + data_offset + 52U) ==
                        HFSPLUS_HARDLINK_CREATOR) {
                    entry.hardlink_reference =
                        read_u32_be_local(node + data_offset + 44U);
                    entry.is_hardlink_placeholder =
                        entry.hardlink_reference != 0U ? 1 : 0;
                }
                parse_fork_data_local(node + data_offset + 88U, &data_fork);
                if (!populate_entry_runs_from_fork_local(
                        &entry,
                        HFSPLUS_FORK_TYPE_DATA,
                        &data_fork)) {
                    continue;
                }
            }

            if (entry.file_id == 0U) {
                free(entry.extra_runs);
                continue;
            }
            if (!append_catalog_entry_local(&entry)) {
                free(entry.extra_runs);
                free(read_ahead);
                free(node_bitmap);
                return 0;
            }
        }

        if (node_bitmap != NULL) {
            scan_catalog_node_for_orphans_local(
                node, &header, current_node, 1);
        }

        ++visited_nodes;
        visited_records += num_records;
        publish_catalog_read_progress_local(
            &header,
            visited_nodes,
            visited_records,
            cache_reads,
            cache_bytes,
            catalog_started_at,
            &last_progress_at,
            &last_progress_log_at,
            0
        );
        ++current_node;
    }

    publish_catalog_read_progress_local(
        &header,
        visited_nodes,
        visited_records,
        cache_reads,
        cache_bytes,
        catalog_started_at,
        &last_progress_at,
        &last_progress_log_at,
        1
    );
    free(read_ahead);
    free(node_bitmap);
    {
        int journal_scanned = scan_hfsplus_journal_catalog_local(
            input_file, &header);
        if (node_bitmap_bytes > 0U || journal_scanned) {
        (void)finish_orphan_catalog_scan_local(&header, "primary_catalog_pass");
        }
    }
    if (!build_id_index_local() || !resolve_all_entry_paths_local() ||
        !resolve_hardlink_catalog_entries_local()) {
        return 0;
    }

    return 1;
}

static int scan_catalog_orphans_only_local(FILE *input_file)
{
    HfsPlusBTreeHeaderLocal header = {0};
    unsigned char *node_bitmap = NULL;
    size_t node_bitmap_bytes = 0U;
    unsigned char *read_ahead = NULL;
    size_t read_ahead_capacity;
    uint64_t cached_logical_start = 0U;
    size_t cached_bytes = 0U;
    uint64_t read_calls = 0U;
    uint64_t read_bytes = 0U;
    uint32_t current_node;
    double started_at = monotonic_seconds_local();

    if (input_file == NULL) return 0;
    free_orphan_catalog_local();
    if (!g_hfsplus_overflow_loaded) {
        (void)load_extents_overflow_records_local(input_file);
    }
    if (g_hfsplus_catalog_resolved_fork.extents == NULL &&
        !materialize_fork_local(
            HFSPLUS_FORK_TYPE_DATA,
            HFSPLUS_CATALOG_FILE_ID,
            &g_hfsplus_catalog_fork,
            &g_hfsplus_catalog_resolved_fork)) {
        return 0;
    }
    if (!load_btree_header_from_resolved_fork_local(
            input_file,
            &g_hfsplus_geometry,
            &g_hfsplus_catalog_resolved_fork,
            &header) ||
        !load_catalog_node_bitmap_local(
            input_file, &header, &node_bitmap, &node_bitmap_bytes)) {
        free(node_bitmap);
        return 0;
    }
    read_ahead_capacity = HFSPLUS_CATALOG_READ_AHEAD_BYTES;
    if (read_ahead_capacity < header.node_size) read_ahead_capacity = header.node_size;
    if ((uint64_t)read_ahead_capacity > g_hfsplus_catalog_resolved_fork.logical_size) {
        read_ahead_capacity = (size_t)g_hfsplus_catalog_resolved_fork.logical_size;
    }
    read_ahead_capacity -= read_ahead_capacity % header.node_size;
    if (read_ahead_capacity < header.node_size) read_ahead_capacity = header.node_size;
    read_ahead = (unsigned char *)malloc(read_ahead_capacity);
    if (read_ahead == NULL) {
        free(node_bitmap);
        return 0;
    }
    log_set_working_activity("scanning HFS+ Catalog free nodes and record slack");
    for (current_node = 1U; current_node < header.total_nodes; ++current_node) {
        uint64_t logical_offset =
            (uint64_t)current_node * (uint64_t)header.node_size;
        const unsigned char *node;
        int allocated;

        if (app_stop_requested()) {
            free(read_ahead);
            free(node_bitmap);
            errno = ECANCELED;
            return 0;
        }
        if (logical_offset < cached_logical_start ||
            logical_offset - cached_logical_start > cached_bytes ||
            cached_bytes - (size_t)(logical_offset - cached_logical_start) <
                header.node_size) {
            uint64_t remaining;
            size_t wanted;

            if (logical_offset >= g_hfsplus_catalog_resolved_fork.logical_size) break;
            remaining = g_hfsplus_catalog_resolved_fork.logical_size - logical_offset;
            wanted = remaining < read_ahead_capacity
                ? (size_t)remaining : read_ahead_capacity;
            wanted -= wanted % header.node_size;
            if (wanted < header.node_size) wanted = header.node_size;
            if (!read_resolved_fork_bytes_local(
                    input_file,
                    &g_hfsplus_geometry,
                    &g_hfsplus_catalog_resolved_fork,
                    logical_offset,
                    read_ahead,
                    wanted)) {
                free(read_ahead);
                free(node_bitmap);
                return 0;
            }
            cached_logical_start = logical_offset;
            cached_bytes = wanted;
            read_calls++;
            read_bytes += wanted;
        }
        node = read_ahead + (size_t)(logical_offset - cached_logical_start);
        allocated = catalog_node_is_allocated_local(
            node_bitmap, node_bitmap_bytes, current_node);
        scan_catalog_node_for_orphans_local(
            node, &header, current_node, allocated);
    }
    free(read_ahead);
    free(node_bitmap);
    (void)scan_hfsplus_journal_catalog_local(input_file, &header);
    if (!finish_orphan_catalog_scan_local(&header, "warm_artifact_build")) return 0;
    log_info(
        "HFS+ orphan Catalog scan timings: reads=%llu bytes=%.2f MiB elapsed=%.2fs",
        (unsigned long long)read_calls,
        (double)read_bytes / (1024.0 * 1024.0),
        monotonic_seconds_local() - started_at);
    return 1;
}

static HfsPlusCatalogEntry *find_best_entry_for_data_offset_local(long long abs_offset)
{
    size_t entry_index;
    uint64_t target;

    if (abs_offset < 0) {
        return NULL;
    }
    target = (uint64_t)abs_offset;

    if (find_entry_index_by_exact_offset_local(target, &entry_index) &&
        entry_index < g_hfsplus_entry_count) {
        return &g_hfsplus_entries[entry_index];
    }
    if (find_entry_index_by_span_local(target, &entry_index) &&
        entry_index < g_hfsplus_entry_count) {
        return &g_hfsplus_entries[entry_index];
    }
    return NULL;
}

static int populate_view_entry_local(const HfsPlusCatalogEntry *entry, MftViewEntry *out)
{
    size_t i;

    if (entry == NULL || out == NULL) {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->abs_offset = entry->abs_offset;
    out->data_size = entry->data_size;
    out->allocated_size = entry->allocated_size;
    out->run_count = entry->run_count > MFT_VIEW_MAX_RUNS
        ? MFT_VIEW_MAX_RUNS
        : entry->run_count;
    out->run_truncated =
        entry->run_truncated || entry->run_count > MFT_VIEW_MAX_RUNS;
    out->flags = entry->is_directory ? 0x0002 : 0;
    out->has_data = entry->has_data;
    out->is_resident = 0;
    copy_text_bounded_local(out->path, sizeof(out->path), entry->path);
    copy_text_bounded_local(out->name, sizeof(out->name), entry->name);

    for (i = 0U; i < out->run_count; ++i) {
        const MftViewRun *run = catalog_entry_run_local(entry, i);

        if (run != NULL) {
            out->runs[i] = *run;
        }
    }

    return 1;
}

static size_t find_recovered_output_index_local(long long abs_offset)
{
    size_t index;

    if (abs_offset < 0) {
        return (size_t)-1;
    }
    if (!ensure_recovered_output_index_current_local() ||
        g_hfsplus_recovered_output_index_count == 0U) {
        return (size_t)-1;
    }

    index = recovered_output_index_lower_bound_local(abs_offset);
    if (index < g_hfsplus_recovered_output_index_sorted_count &&
        g_hfsplus_recovered_output_index[index].abs_offset == abs_offset) {
        return g_hfsplus_recovered_output_index[index].output_index;
    }

    for (index = g_hfsplus_recovered_output_index_sorted_count;
         index < g_hfsplus_recovered_output_index_count;
         ++index) {
        if (g_hfsplus_recovered_output_index[index].abs_offset == abs_offset) {
            return g_hfsplus_recovered_output_index[index].output_index;
        }
    }

    return (size_t)-1;
}

static int path_is_under_unident_local(const char *path)
{
    return path != NULL &&
           (strstr(path, "/" APP_RECOVERED_DIR_NAME "/" APP_UNIDENT_DIR_NAME "/") != NULL ||
            strstr(path, "/" APP_RECOVERED_DIR_NAME "/" APP_LEGACY_UNIDENT_DIR_NAME "/") != NULL);
}

static int path_is_embedded_context_local(const char *path)
{
    return path != NULL &&
           (strstr(
                path,
                "/" APP_RECOVERED_DIR_NAME "/" APP_UNIDENT_DIR_NAME "/Embedded/") != NULL ||
            strstr(path, APP_UNIDENT_DIR_NAME "/Embedded/") != NULL);
}

static void prune_empty_unidentified_parents_local(const char *old_file_path)
{
    char directory[HFSPLUS_PATH_MAX];
    char unident_root[HFSPLUS_PATH_MAX];
    char legacy_root[HFSPLUS_PATH_MAX];
    const char *root = NULL;
    size_t root_length;
    char *slash;

    if (old_file_path == NULL || g_hfsplus_output_dir[0] == '\0' ||
        snprintf(
            unident_root,
            sizeof(unident_root),
            "%s/%s/%s",
            g_hfsplus_output_dir,
            APP_RECOVERED_DIR_NAME,
            APP_UNIDENT_DIR_NAME) >= (int)sizeof(unident_root) ||
        snprintf(
            legacy_root,
            sizeof(legacy_root),
            "%s/%s/%s",
            g_hfsplus_output_dir,
            APP_RECOVERED_DIR_NAME,
            APP_LEGACY_UNIDENT_DIR_NAME) >= (int)sizeof(legacy_root)) {
        return;
    }
    if (strncmp(old_file_path, unident_root, strlen(unident_root)) == 0 &&
        old_file_path[strlen(unident_root)] == '/') {
        root = unident_root;
    } else if (strncmp(old_file_path, legacy_root, strlen(legacy_root)) == 0 &&
               old_file_path[strlen(legacy_root)] == '/') {
        root = legacy_root;
    } else {
        return;
    }

    copy_text_bounded_local(directory, sizeof(directory), old_file_path);
    slash = strrchr(directory, '/');
    if (slash == NULL) return;
    *slash = '\0';
    root_length = strlen(root);
    while (strlen(directory) >= root_length &&
           strncmp(directory, root, root_length) == 0) {
        if (rmdir(directory) != 0) break;
        slash = strrchr(directory, '/');
        if (slash == NULL) break;
        *slash = '\0';
    }
}

static int recovered_output_name_requires_naming_local(const char *name)
{
    const char *digits;
    size_t digit_count = 0U;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    if (strncmp(name, "recov_", 6U) == 0) {
        return 1;
    }
    if (name[0] != 'f') {
        return 0;
    }

    digits = name + 1;
    while (*digits >= '0' && *digits <= '9') {
        digit_count++;
        digits++;
    }

    return digit_count > 0U && (*digits == '\0' || *digits == '.');
}

static int recovered_output_path_defaults_reconciled_local(const char *path)
{
    const char *basename;

    if (path == NULL || path[0] == '\0' || path_is_under_unident_local(path)) {
        return 0;
    }

    basename = path_basename_local(path);
    if (basename == NULL) {
        return 0;
    }

    return !recovered_output_name_requires_naming_local(basename);
}

static int recovered_output_is_legacy_inode_root_local(const char *path)
{
    static const char marker[] = "/" APP_RECOVERED_DIR_NAME "/";
    const char *match;
    const char *cursor;
    uint32_t ignored_reference;

    if (path == NULL) return 0;
    match = strstr(path, marker);
    if (match == NULL) return 0;
    for (cursor = match + 1U; (cursor = strstr(cursor, marker)) != NULL;
         cursor += sizeof(marker) - 1U) {
        match = cursor;
    }
    cursor = match + sizeof(marker) - 1U;
    return strchr(cursor, '/') == NULL &&
           parse_hardlink_inode_name_local(cursor, 1, &ignored_reference);
}

static int recovered_output_is_legacy_embedded_inode_local(const char *path)
{
    static const char marker[] =
        "/" APP_UNIDENT_DIR_NAME "/Embedded/iNode";
    const char *inode_name;
    uint32_t ignored_reference;

    if (path == NULL) return 0;
    inode_name = strstr(path, marker);
    if (inode_name == NULL) return 0;
    inode_name += sizeof(marker) - 1U - 5U;
    return parse_hardlink_inode_name_local(
        inode_name,
        1,
        &ignored_reference);
}

static int build_recovered_outputs_log_path_local(char *out_path, size_t out_size)
{
    if (out_path == NULL || out_size == 0U || g_hfsplus_output_dir[0] == '\0') {
        return 0;
    }

    return snprintf(
               out_path,
               out_size,
               "%s/%s/recovered_outputs.tsv",
               g_hfsplus_output_dir,
               APP_STATE_DIR_NAME) < (int)out_size;
}

static void write_tsv_text_field_local(FILE *file, const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;

    if (file == NULL) return;
    if (cursor == NULL) return;
    while (*cursor != '\0') {
        unsigned char ch = *cursor++;
        fputc((ch == '\t' || ch == '\r' || ch == '\n') ? ' ' : (int)ch, file);
    }
}

static int append_embedded_context_log_local(
    const HfsPlusRecoveredOutput *output,
    const HfsPlusEmbeddedContextLocal *context)
{
    char path[HFSPLUS_PATH_MAX];
    FILE *file;

    if (output == NULL || context == NULL || g_hfsplus_output_dir[0] == '\0' ||
        snprintf(
            path,
            sizeof(path),
            "%s/%s/hfsplus_embedded_context.tsv",
            g_hfsplus_output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(path)) {
        return 0;
    }
    file = fopen(path, "a");
    if (file == NULL) return 0;
    (void)chmod(path, 0644);
    if (ftell(file) == 0L) {
        fprintf(
            file,
            "offset\toutput_path\towner_object_key\towner_path\tlogical_position\tphysical_extent_start\tphysical_extent_end\toutput_size\tclassification\n"
        );
    }
    fprintf(file, "%lld\t", output->abs_offset);
    write_tsv_text_field_local(file, output->path);
    fprintf(file, "\t%llu\t", (unsigned long long)context->object_key);
    write_tsv_text_field_local(file, context->owner_path);
    fprintf(
        file,
        "\t%llu\t%llu\t%llu\t%llu\tembedded_in_complete_catalog_fork\n",
        (unsigned long long)context->logical_position,
        (unsigned long long)context->physical_start,
        (unsigned long long)context->physical_end,
        (unsigned long long)context->output_size
    );
    if (fclose(file) != 0) return 0;
    return mft_apply_output_owner_to_path(path);
}

static int build_metadata_snapshot_path_local(char *out_path, size_t out_size)
{
    if (out_path == NULL || out_size == 0U || g_hfsplus_output_dir[0] == '\0') {
        return 0;
    }

    return snprintf(
               out_path,
               out_size,
               "%s/%s/hfsplus_metadata_snapshot.bin",
               g_hfsplus_output_dir,
               APP_STATE_DIR_NAME) < (int)out_size;
}

static int build_finalize_status_path_local(char *out_path, size_t out_size)
{
    if (out_path == NULL || out_size == 0U || g_hfsplus_output_dir[0] == '\0') {
        return 0;
    }

    return snprintf(
               out_path,
               out_size,
               "%s/%s/hfsplus_finalize_status.txt",
               g_hfsplus_output_dir,
               APP_STATE_DIR_NAME) < (int)out_size;
}

static int build_photos_library_signal_path_local(char *out_path, size_t out_size)
{
    if (out_path == NULL || out_size == 0U || g_hfsplus_output_dir[0] == '\0') {
        return 0;
    }

    return snprintf(
               out_path,
               out_size,
               "%s/%s/photos_library_signal.txt",
               g_hfsplus_output_dir,
               APP_STATE_DIR_NAME) < (int)out_size;
}

static int path_has_photos_library_suffix_local(const char *path)
{
    static const char suffix[] = ".photoslibrary";
    size_t path_length;
    size_t suffix_length = sizeof(suffix) - 1U;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    path_length = strlen(path);
    if (path_length < suffix_length) {
        return 0;
    }

    return strcasecmp(path + (path_length - suffix_length), suffix) == 0;
}

static void write_photos_library_signal_local(void)
{
    char signal_path[HFSPLUS_PATH_MAX];
    char state_dir[HFSPLUS_PATH_MAX];
    FILE *file;
    size_t photos_library_count = 0U;
    const char *first_path = NULL;
    size_t index;

    if (g_hfsplus_output_dir[0] == '\0' ||
        snprintf(state_dir, sizeof(state_dir), "%s/%s", g_hfsplus_output_dir, APP_STATE_DIR_NAME) >=
            (int)sizeof(state_dir) ||
        !ensure_directory_path_local(state_dir) ||
        !build_photos_library_signal_path_local(signal_path, sizeof(signal_path))) {
        return;
    }

    if (g_hfsplus_catalog_loaded) {
        for (index = 0U; index < g_hfsplus_entry_count; ++index) {
            const HfsPlusCatalogEntry *entry = &g_hfsplus_entries[index];

            if (!entry->is_directory || !entry->path_complete) {
                continue;
            }
            if (!path_has_photos_library_suffix_local(entry->path)) {
                continue;
            }
            if (first_path == NULL) {
                first_path = entry->path;
            }
            photos_library_count++;
        }
    }

    file = fopen(signal_path, "w");
    if (file == NULL) {
        return;
    }

    fprintf(file, "backend=hfsplus\n");
    fprintf(file, "catalog_loaded=%d\n", g_hfsplus_catalog_loaded ? 1 : 0);
    if (!g_hfsplus_catalog_loaded) {
        fprintf(file, "photos_library_detected=unknown\n");
        fprintf(file, "photos_library_count=0\n");
    } else {
        fprintf(file, "photos_library_detected=%d\n", photos_library_count > 0U ? 1 : 0);
        fprintf(file, "photos_library_count=%zu\n", photos_library_count);
    }
    fprintf(file, "special_handling_deferred=%d\n", photos_library_count > 0U ? 1 : 0);
    if (first_path != NULL) {
        fprintf(file, "first_photos_library_path=%s\n", first_path);
    }
    fprintf(file, "generated_at_unix=%llu\n", (unsigned long long)time(NULL));

    if (fclose(file) == 0) {
        (void)mft_apply_output_owner_to_path(signal_path);
    }

    if (photos_library_count > 0U &&
        !g_hfsplus_photos_library_signal_logged) {
        g_hfsplus_photos_library_signal_logged = 1;
        log_runtime_event_info(
            "Photos Library detected in HFS+ catalog (%zu hit%s); special handling is deferred in this build. First path: %s",
            photos_library_count,
            photos_library_count == 1U ? "" : "s",
            first_path != NULL ? first_path : "(unknown)"
        );
    }
}

static size_t orphan_record_lower_bound_local(uint64_t abs_offset)
{
    size_t low = 0U;
    size_t high = g_hfsplus_orphan_record_count;

    while (low < high) {
        size_t mid = low + (high - low) / 2U;
        if (g_hfsplus_orphan_records[mid].abs_offset < abs_offset) low = mid + 1U;
        else high = mid;
    }
    return low;
}

static int orphan_records_share_file_identity_local(
    const HfsPlusOrphanCatalogRecordLocal *left,
    const HfsPlusOrphanCatalogRecordLocal *right)
{
    return left != NULL && right != NULL &&
        left->abs_offset == right->abs_offset &&
        left->data_size == right->data_size &&
        left->allocated_size == right->allocated_size &&
        left->file_id == right->file_id &&
        left->create_date_hfs == right->create_date_hfs &&
        strcmp(orphan_record_name_local(left),
               orphan_record_name_local(right)) == 0;
}

static size_t orphan_parent_variant_count_local(size_t first, size_t end)
{
    size_t variants = 0U;
    size_t index;

    for (index = first; index < end; ++index) {
        size_t prior;
        int seen = 0;

        for (prior = first; prior < index; ++prior) {
            if (g_hfsplus_orphan_records[prior].parent_id ==
                g_hfsplus_orphan_records[index].parent_id) {
                seen = 1;
                break;
            }
        }
        if (!seen) variants++;
    }
    return variants;
}

typedef struct {
    const char *status;
    uint32_t stop_cnid;
    uint32_t active_first_rank;
    uint32_t active_last_rank;
    size_t depth;
    size_t folder_versions;
    size_t active_components;
    char path[HFSPLUS_PATH_MAX];
} HfsPlusHistoricalChainLocal;

static size_t historical_folder_lower_bound_local(uint32_t folder_id)
{
    size_t low = 0U;
    size_t high = g_hfsplus_historical_folder_count;

    while (low < high) {
        size_t mid = low + (high - low) / 2U;
        if (g_hfsplus_historical_folders[mid].folder_id < folder_id) {
            low = mid + 1U;
        } else {
            high = mid;
        }
    }
    return low;
}

static void resolve_historical_parent_chain_local(
    uint32_t start_parent,
    HfsPlusHistoricalChainLocal *out)
{
    const char *components[256];
    uint32_t visited[256];
    uint32_t current = start_parent;
    size_t component_count = 0U;
    size_t visited_count = 0U;
    size_t index;
    size_t used = 0U;

    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    out->status = "missing_parent";
    out->stop_cnid = start_parent;
    if (start_parent == HFSPLUS_ROOT_FOLDER_ID) {
        out->status = "root";
        snprintf(out->path, sizeof(out->path), "/");
        return;
    }

    while (current != HFSPLUS_ROOT_FOLDER_ID) {
        size_t first;
        size_t end;
        const HfsPlusHistoricalFolderRecordLocal *folder;

        for (index = 0U; index < visited_count; ++index) {
            if (visited[index] == current) {
                out->status = "cycle";
                out->stop_cnid = current;
                goto build_path;
            }
        }
        if (visited_count >= sizeof(visited) / sizeof(visited[0]) ||
            component_count >= sizeof(components) / sizeof(components[0])) {
            out->status = "depth_limit";
            out->stop_cnid = current;
            goto build_path;
        }
        visited[visited_count++] = current;
        first = historical_folder_lower_bound_local(current);
        end = first;
        while (end < g_hfsplus_historical_folder_count &&
               g_hfsplus_historical_folders[end].folder_id == current) end++;
        if (first == end) {
            out->status = "missing_parent";
            out->stop_cnid = current;
            goto build_path;
        }
        out->folder_versions += end - first;
        if (end - first > 1U) {
            out->status = "ambiguous_folder_version";
            out->stop_cnid = current;
            goto build_path;
        }
        folder = &g_hfsplus_historical_folders[first];
        components[component_count++] = historical_folder_name_local(folder);
        if (folder->journal_active_observations > 0U) {
            if (out->active_components == 0U) {
                out->active_first_rank = folder->journal_active_first_rank;
                out->active_last_rank = folder->journal_active_last_rank;
            } else {
                if (folder->journal_active_first_rank >
                    out->active_first_rank) {
                    out->active_first_rank =
                        folder->journal_active_first_rank;
                }
                if (folder->journal_active_last_rank < out->active_last_rank) {
                    out->active_last_rank = folder->journal_active_last_rank;
                }
            }
            out->active_components++;
        }
        current = folder->parent_id;
    }
    out->status = "complete";
    out->stop_cnid = HFSPLUS_ROOT_FOLDER_ID;

build_path:
    out->depth = component_count;
    out->path[0] = '\0';
    while (component_count > 0U) {
        const char *component = components[--component_count];
        int wrote = snprintf(
            out->path + used,
            sizeof(out->path) - used,
            "/%s",
            component);

        if (wrote < 0 || (size_t)wrote >= sizeof(out->path) - used) {
            out->status = "path_too_long";
            out->path[sizeof(out->path) - 1U] = '\0';
            return;
        }
        used += (size_t)wrote;
    }
    if (out->path[0] == '\0' &&
        (strcmp(out->status, "complete") == 0 ||
         strcmp(out->status, "root") == 0)) {
        snprintf(out->path, sizeof(out->path), "/");
    }
}

static int orphan_match_has_safe_journal_name_local(
    const HfsPlusRecoveredOutput *output,
    size_t first,
    size_t end,
    const HfsPlusOrphanCatalogRecordLocal **identity_out,
    size_t *parent_variants_out,
    const char **reason_out)
{
    const HfsPlusOrphanCatalogRecordLocal *identity;
    const char *output_extension;
    const char *name_extension;
    struct stat output_stat;
    size_t index;

    if (identity_out != NULL) *identity_out = NULL;
    if (parent_variants_out != NULL) *parent_variants_out = 0U;
    if (reason_out != NULL) *reason_out = "unsafe";
    if (output == NULL || first >= end ||
        end > g_hfsplus_orphan_record_count || output->abs_offset < 0) {
        if (reason_out != NULL) *reason_out = "invalid_match_range";
        return 0;
    }

    identity = &g_hfsplus_orphan_records[first];
    for (index = first; index < end; ++index) {
        const HfsPlusOrphanCatalogRecordLocal *candidate =
            &g_hfsplus_orphan_records[index];

        if (!orphan_records_share_file_identity_local(identity, candidate)) {
            if (reason_out != NULL) *reason_out = "conflicting_file_identity";
            return 0;
        }
        if (candidate->provenance !=
                HFSPLUS_ORPHAN_JOURNAL_CATALOG_BLOCK ||
            candidate->confidence < 98U) {
            if (reason_out != NULL) *reason_out = "insufficient_provenance";
            return 0;
        }
    }

    output_extension = path_extension_local(output->path);
    name_extension = path_extension_local(orphan_record_name_local(identity));
    if (output_extension == NULL || name_extension == NULL ||
        !extensions_are_same_recovery_family_local(
            output_extension, name_extension)) {
        if (reason_out != NULL) *reason_out = "format_family_mismatch";
        return 0;
    }
    if (stat(output->path, &output_stat) != 0 ||
        !S_ISREG(output_stat.st_mode) || output_stat.st_size < 0 ||
        (uint64_t)output_stat.st_size != identity->data_size) {
        if (reason_out != NULL) *reason_out = "output_size_mismatch";
        return 0;
    }

    if (identity_out != NULL) *identity_out = identity;
    if (parent_variants_out != NULL) {
        *parent_variants_out = orphan_parent_variant_count_local(first, end);
    }
    if (reason_out != NULL) *reason_out = "safe_file_identity";
    return 1;
}

static int recover_safe_orphan_journal_name_local(
    size_t output_index,
    const HfsPlusOrphanCatalogRecordLocal *identity,
    char *destination_out,
    size_t destination_out_size)
{
    HfsPlusRecoveredOutput *output;
    char relative_path[HFSPLUS_PATH_MAX];
    char destination[HFSPLUS_PATH_MAX];
    char previous_path[HFSPLUS_PATH_MAX];
    time_t created_time;

    if (destination_out != NULL && destination_out_size > 0U) {
        destination_out[0] = '\0';
    }
    if (output_index >= g_hfsplus_recovered_output_count || identity == NULL) {
        return 0;
    }
    output = &g_hfsplus_recovered_outputs[output_index];
    if (output->reconciled) {
        if (destination_out != NULL && destination_out_size > 0U) {
            snprintf(destination_out, destination_out_size, "%s", output->path);
        }
        return 1;
    }
    if (snprintf(
            relative_path,
            sizeof(relative_path),
            "Recovered from HFS Journal/Unknown parent/%s",
            orphan_record_name_local(identity)) >= (int)sizeof(relative_path) ||
        !build_unique_contextual_output_path_local(
            destination,
            sizeof(destination),
            relative_path,
            output->path)) {
        return 0;
    }

    copy_text_bounded_local(previous_path, sizeof(previous_path), output->path);
    if (strcmp(previous_path, destination) != 0 &&
        rename(previous_path, destination) != 0) {
        return 0;
    }
    copy_text_bounded_local(output->path, sizeof(output->path), destination);
    set_recovered_output_reconciled_local(output_index, 1);
    set_recovered_output_classification_local(
        output_index, HFSPLUS_OUTPUT_CLASS_UNCLASSIFIED);
    prune_empty_unidentified_parents_local(previous_path);
    (void)mft_apply_output_owner_to_path(output->path);
    created_time = hfsplus_seconds_to_unix_local(identity->create_date_hfs);
    if (created_time > 0) {
        (void)mft_apply_created_time_value_to_path(output->path, created_time);
    }
    if (!append_recovered_output_log_entry_local(
            output->path,
            output->abs_offset,
            output->reconciled,
            output->classification)) {
        g_hfsplus_recovered_outputs_log_needs_rewrite = 1;
    }
    if (destination_out != NULL && destination_out_size > 0U) {
        snprintf(destination_out, destination_out_size, "%s", output->path);
    }
    return 1;
}

static int write_orphan_output_matches_local(const char *metadata_dir)
{
    char artifact_path[HFSPLUS_PATH_MAX];
    char artifact_temp[HFSPLUS_PATH_MAX + 32U];
    char status_path[HFSPLUS_PATH_MAX];
    char status_temp[HFSPLUS_PATH_MAX + 32U];
    char chain_path[HFSPLUS_PATH_MAX];
    char chain_temp[HFSPLUS_PATH_MAX + 32U];
    struct stat artifact_stat;
    FILE *file;
    FILE *chain_file = NULL;
    size_t output_index;
    uint64_t no_owner_examined = 0U;
    uint64_t unique_matches = 0U;
    uint64_t ambiguous_matches = 0U;
    uint64_t matched_outputs = 0U;
    uint64_t certain_identities = 0U;
    uint64_t certain_names_ambiguous_parent = 0U;
    uint64_t recovered_names = 0U;
    uint64_t recovery_failures = 0U;
    uint64_t chain_rows = 0U;
    uint64_t complete_chains = 0U;
    uint64_t ambiguous_chains = 0U;
    uint64_t missing_chains = 0U;
    uint64_t cycle_chains = 0U;

    g_hfsplus_journal_names_recovered_current = 0ULL;
    if (metadata_dir == NULL || !g_hfsplus_orphan_ready ||
        snprintf(artifact_path, sizeof(artifact_path),
                 "%s/hfs_orphan_output_matches.tsv", metadata_dir) >=
            (int)sizeof(artifact_path) ||
        snprintf(artifact_temp, sizeof(artifact_temp), "%s.tmp", artifact_path) >=
            (int)sizeof(artifact_temp) ||
        snprintf(status_path, sizeof(status_path),
                 "%s/hfs_orphan_output_match_status.txt", metadata_dir) >=
            (int)sizeof(status_path) ||
        snprintf(status_temp, sizeof(status_temp), "%s.tmp", status_path) >=
            (int)sizeof(status_temp) ||
        snprintf(chain_path, sizeof(chain_path),
                 "%s/hfs_historical_parent_chains.tsv", metadata_dir) >=
            (int)sizeof(chain_path) ||
        snprintf(chain_temp, sizeof(chain_temp), "%s.tmp", chain_path) >=
            (int)sizeof(chain_temp)) return 0;
    file = fopen(artifact_temp, "w");
    if (file == NULL) return 0;
    chain_file = fopen(chain_temp, "w");
    if (chain_file == NULL) {
        fclose(file);
        (void)unlink(artifact_temp);
        return 0;
    }
    fprintf(file,
            "output_offset\tformat\toutput_kind\tmatch_count\tparent_variants\tidentity_status\taction\tconfidence\tfile_id\tparent_id\tdata_size\tallocated_size\tcreate_date_hfs\tsource_node\trecord_offset\tprovenance\tname\tdestination\n");
    fprintf(chain_file,
            "output_offset\tfile_id\tfile_name\tstart_parent_id\tstatus\tdepth\tstop_cnid\tfolder_versions\tfile_observations\tfile_active_observations\tfile_active_first_rank\tfile_active_last_rank\tpath_active_components\tpath_active_first_rank\tpath_active_last_rank\ttimeline_status\toverlap_first_rank\toverlap_last_rank\tpath\n");
    for (output_index = 0U; output_index < g_hfsplus_recovered_output_count;
         ++output_index) {
        const HfsPlusRecoveredOutput *output =
            &g_hfsplus_recovered_outputs[output_index];
        MetadataIndexCandidateContext live_context = {0};
        size_t first;
        size_t end;
        size_t match_count;
        const HfsPlusOrphanCatalogRecordLocal *best;
        const char *extension;
        const char *output_kind;
        const char *identity_reason = "not_evaluated";
        const char *action = "evidence_only";
        const HfsPlusOrphanCatalogRecordLocal *identity = NULL;
        size_t parent_variants = 0U;
        char destination[HFSPLUS_PATH_MAX];
        int safe_identity;
        int live_result;

        if (output->abs_offset < 0) continue;
        live_result = metadata_index_reader_get_candidate_context(
            g_hfsplus_compact_reader,
            (uint64_t)output->abs_offset,
            &live_context);
        if (live_result < 0 || (live_result == 1 && live_context.has_owner)) continue;
        no_owner_examined++;
        first = orphan_record_lower_bound_local((uint64_t)output->abs_offset);
        end = first;
        while (end < g_hfsplus_orphan_record_count &&
               g_hfsplus_orphan_records[end].abs_offset ==
                   (uint64_t)output->abs_offset) end++;
        match_count = end - first;
        if (match_count == 0U) continue;
        matched_outputs++;
        if (match_count == 1U) unique_matches++;
        else ambiguous_matches++;
        best = &g_hfsplus_orphan_records[first];
        {
            size_t match_index;
            for (match_index = first + 1U; match_index < end; ++match_index) {
                if (g_hfsplus_orphan_records[match_index].confidence >
                    best->confidence) {
                    best = &g_hfsplus_orphan_records[match_index];
                }
            }
        }
        destination[0] = '\0';
        safe_identity = orphan_match_has_safe_journal_name_local(
            output,
            first,
            end,
            &identity,
            &parent_variants,
            &identity_reason);
        if (safe_identity) {
            size_t parent_index;

            certain_identities++;
            if (parent_variants > 1U) {
                certain_names_ambiguous_parent++;
                identity_reason = "certain_name_ambiguous_parent";
            } else {
                identity_reason = "certain_name_parent_unresolved";
            }
            if (output->reconciled) {
                action = "already_named";
                snprintf(destination, sizeof(destination), "%s", output->path);
            } else if (recover_safe_orphan_journal_name_local(
                           output_index,
                           identity,
                           destination,
                           sizeof(destination))) {
                action = "name_recovered";
                recovered_names++;
            } else {
                action = "name_recovery_failed";
                recovery_failures++;
            }
            for (parent_index = first; parent_index < end; ++parent_index) {
                HfsPlusHistoricalChainLocal chain;
                const HfsPlusOrphanCatalogRecordLocal *file_variant =
                    &g_hfsplus_orphan_records[parent_index];
                const char *timeline_status;
                uint32_t overlap_first = 0U;
                uint32_t overlap_last = 0U;
                size_t prior_parent;
                int parent_seen = 0;

                for (prior_parent = first;
                     prior_parent < parent_index;
                     ++prior_parent) {
                    if (g_hfsplus_orphan_records[prior_parent].parent_id ==
                        g_hfsplus_orphan_records[parent_index].parent_id) {
                        parent_seen = 1;
                        break;
                    }
                }
                if (parent_seen) continue;
                resolve_historical_parent_chain_local(
                    g_hfsplus_orphan_records[parent_index].parent_id,
                    &chain);
                chain_rows++;
                if (strcmp(chain.status, "complete") == 0 ||
                    strcmp(chain.status, "root") == 0) complete_chains++;
                else if (strcmp(chain.status, "ambiguous_folder_version") == 0) {
                    ambiguous_chains++;
                } else if (strcmp(chain.status, "cycle") == 0) {
                    cycle_chains++;
                } else {
                    missing_chains++;
                }
                if (file_variant->journal_active_observations == 0U) {
                    timeline_status = "file_stale_only";
                } else if (chain.depth == 0U &&
                           (strcmp(chain.status, "root") == 0 ||
                            strcmp(chain.status, "complete") == 0)) {
                    timeline_status = "active_root_parent";
                    overlap_first = file_variant->journal_active_first_rank;
                    overlap_last = file_variant->journal_active_last_rank;
                } else if (chain.active_components < chain.depth) {
                    timeline_status = "partial_active_path";
                } else if (chain.active_first_rank > chain.active_last_rank) {
                    timeline_status = "disjoint_path_window";
                } else {
                    overlap_first = file_variant->journal_active_first_rank >
                            chain.active_first_rank
                        ? file_variant->journal_active_first_rank
                        : chain.active_first_rank;
                    overlap_last = file_variant->journal_active_last_rank <
                            chain.active_last_rank
                        ? file_variant->journal_active_last_rank
                        : chain.active_last_rank;
                    timeline_status = overlap_first <= overlap_last
                        ? "coobserved_active_window"
                        : "ordered_nonoverlap";
                    if (overlap_first > overlap_last) {
                        overlap_first = 0U;
                        overlap_last = 0U;
                    }
                }
                fprintf(chain_file, "%lld\t%u\t",
                        output->abs_offset,
                        identity->file_id);
                write_tsv_text_local(
                    chain_file, orphan_record_name_local(identity));
                fprintf(chain_file,
                        "\t%u\t%s\t%zu\t%u\t%zu\t%u\t%u\t%u\t%u\t%zu\t%u\t%u\t%s\t%u\t%u\t",
                        file_variant->parent_id,
                        chain.status,
                        chain.depth,
                        chain.stop_cnid,
                        chain.folder_versions,
                        file_variant->journal_observations,
                        file_variant->journal_active_observations,
                        file_variant->journal_active_first_rank,
                        file_variant->journal_active_last_rank,
                        chain.active_components,
                        chain.active_first_rank,
                        chain.active_last_rank,
                        timeline_status,
                        overlap_first,
                        overlap_last);
                write_tsv_text_local(chain_file, chain.path);
                fputc('\n', chain_file);
            }
        }
        extension = path_extension_local(output->path);
        output_kind = output->classification == HFSPLUS_OUTPUT_CLASS_EMBEDDED
            ? "embedded" : (output->reconciled ? "named" : "unresolved");
        fprintf(file, "%lld\t", output->abs_offset);
        write_tsv_text_local(file, extension != NULL ? extension : "");
        fprintf(file, "\t%s\t%zu\t%zu\t%s\t%s\t%u\t%u\t%u\t%llu\t%llu\t%u\t%u\t%u\t%s\t",
                output_kind,
                match_count,
                parent_variants,
                identity_reason,
                action,
                (unsigned int)best->confidence,
                best->file_id,
                best->parent_id,
                (unsigned long long)best->data_size,
                (unsigned long long)best->allocated_size,
                best->create_date_hfs,
                best->source_node,
                (unsigned int)best->record_offset,
                orphan_provenance_label_local(best->provenance));
        write_tsv_text_local(file, orphan_record_name_local(best));
        fputc('\t', file);
        write_tsv_text_local(file, destination);
        fputc('\n', file);
    }
    /* This counter describes filesystem mutations, not whether the evidence
     * artifacts could subsequently be published. Preserve the true move
     * total even if a later state-file write fails. */
    g_hfsplus_journal_names_recovered_current = recovered_names;
    {
        int failed = ferror(file) != 0;
        if (fclose(file) != 0) failed = 1;
        if (ferror(chain_file) != 0 || fclose(chain_file) != 0) failed = 1;
        chain_file = NULL;
        if (failed || rename(artifact_temp, artifact_path) != 0 ||
            rename(chain_temp, chain_path) != 0) {
            (void)unlink(artifact_temp);
            (void)unlink(chain_temp);
            return 0;
        }
    }
    (void)chmod(artifact_path, 0644);
    (void)mft_apply_output_owner_to_path(artifact_path);
    (void)chmod(chain_path, 0644);
    (void)mft_apply_output_owner_to_path(chain_path);
    memset(&artifact_stat, 0, sizeof(artifact_stat));
    (void)stat(artifact_path, &artifact_stat);
    file = fopen(status_temp, "w");
    if (file == NULL) return 0;
    fprintf(file, "format_version=4\nbackend=hfsplus\nstatus=ready\n");
    fprintf(file,
            "policy_effect=safe_journal_name_recovery\nmatch_policy=exact_first_physical_offset_plus_stable_file_identity\n");
    fprintf(file, "orphan_candidates=%zu\nno_owner_outputs_examined=%llu\n",
            g_hfsplus_orphan_record_count,
            (unsigned long long)no_owner_examined);
    fprintf(file, "matched_outputs=%llu\nunique_matches=%llu\nambiguous_matches=%llu\n",
            (unsigned long long)matched_outputs,
            (unsigned long long)unique_matches,
            (unsigned long long)ambiguous_matches);
    fprintf(file,
            "certain_file_identities=%llu\ncertain_names_ambiguous_parent=%llu\nrecovered_names=%llu\nname_recovery_failures=%llu\n",
            (unsigned long long)certain_identities,
            (unsigned long long)certain_names_ambiguous_parent,
            (unsigned long long)recovered_names,
            (unsigned long long)recovery_failures);
    fprintf(file,
            "historical_folder_records=%zu\nparent_chain_rows=%llu\ncomplete_parent_chains=%llu\nambiguous_parent_chains=%llu\nmissing_parent_chains=%llu\ncycle_parent_chains=%llu\nparent_chain_artifact=hfs_historical_parent_chains.tsv\n",
            g_hfsplus_historical_folder_count,
            (unsigned long long)chain_rows,
            (unsigned long long)complete_chains,
            (unsigned long long)ambiguous_chains,
            (unsigned long long)missing_chains,
            (unsigned long long)cycle_chains);
    fprintf(file, "unmatched_outputs=%llu\nartifact_rows=%llu\nartifact_bytes=%llu\n",
            (unsigned long long)(no_owner_examined - matched_outputs),
            (unsigned long long)matched_outputs,
            (unsigned long long)(artifact_stat.st_size > 0
                ? artifact_stat.st_size : 0));
    fprintf(file, "artifact=hfs_orphan_output_matches.tsv\nupdated_unix=%llu\n",
            (unsigned long long)time(NULL));
    if (fclose(file) != 0 || rename(status_temp, status_path) != 0) {
        (void)unlink(status_temp);
        return 0;
    }
    (void)chmod(status_path, 0644);
    (void)mft_apply_output_owner_to_path(status_path);
    log_info(
        "HFS+ orphan Catalog/output correlation: no_owner=%llu matched=%llu unique=%llu ambiguous=%llu certain_identity=%llu parent_ambiguous=%llu names_recovered=%llu failures=%llu candidates=%zu historical_folders=%zu parent_chains=%llu complete_chains=%llu",
        (unsigned long long)no_owner_examined,
        (unsigned long long)matched_outputs,
        (unsigned long long)unique_matches,
        (unsigned long long)ambiguous_matches,
        (unsigned long long)certain_identities,
        (unsigned long long)certain_names_ambiguous_parent,
        (unsigned long long)recovered_names,
        (unsigned long long)recovery_failures,
        g_hfsplus_orphan_record_count,
        g_hfsplus_historical_folder_count,
        (unsigned long long)chain_rows,
        (unsigned long long)complete_chains);
    return 1;
}

static int write_recovered_output_metadata_outcomes_local(void)
{
    MetadataOutcomeStats stats = {0};
    MetadataOutcomeRecord *records = NULL;
    char metadata_dir[HFSPLUS_PATH_MAX];
    char path[HFSPLUS_PATH_MAX];
    size_t index;
    size_t record_count = 0U;
    int result = 0;

    g_hfsplus_journal_names_recovered_current = 0ULL;
    if (!hfsplus_compact_available_local() ||
        g_hfsplus_output_dir[0] == '\0' ||
        snprintf(metadata_dir, sizeof(metadata_dir), "%s/%s/metadata",
                 g_hfsplus_output_dir, APP_STATE_DIR_NAME) >=
            (int)sizeof(metadata_dir) ||
        !ensure_directory_path_local(metadata_dir)) {
        return 0;
    }
    /* Journal recovery can change an output from unresolved to named. Apply
     * that decision before serializing the compact outcome rows so this same
     * finalize pass never publishes stale output_kind values. */
    if (g_hfsplus_orphan_ready &&
        !write_orphan_output_matches_local(metadata_dir)) {
        log_info(
            "HFS+ orphan Catalog candidates were available, but output correlation state could not be written"
        );
    }
    if (g_hfsplus_recovered_output_count > 0U) {
        records = calloc(g_hfsplus_recovered_output_count, sizeof(*records));
        if (records == NULL) return 0;
    }
    for (index = 0U; index < g_hfsplus_recovered_output_count; ++index) {
        const HfsPlusRecoveredOutput *output = &g_hfsplus_recovered_outputs[index];
        if (output->abs_offset < 0) continue;
        records[record_count].physical_offset = (uint64_t)output->abs_offset;
        records[record_count].format = path_extension_local(output->path);
        records[record_count].output_kind =
            output->classification == HFSPLUS_OUTPUT_CLASS_EMBEDDED
                ? "embedded"
                : (output->reconciled ? "named" : "unresolved");
        record_count++;
    }
    result = metadata_outcome_write_artifacts(
        g_hfsplus_compact_reader,
        metadata_dir,
        "hfsplus",
        records,
        record_count,
        fs_backend_fopen_output_write_guarded,
        &stats) == 0;
    free(records);
    if (!result) return 0;
    if (snprintf(path, sizeof(path), "%s/recovered_output_metadata.tsv",
                 metadata_dir) < (int)sizeof(path)) {
        (void)mft_apply_output_owner_to_path(path);
    }
    if (snprintf(path, sizeof(path),
                 "%s/recovered_output_metadata_status.txt", metadata_dir) <
            (int)sizeof(path)) {
        (void)mft_apply_output_owner_to_path(path);
    }
    log_info(
        "HFS+ recovered-output metadata outcomes: outputs=%llu no_owner=%llu ambiguous=%llu non_data=%llu incomplete=%llu trusted_start=%llu trusted_interior=%llu failures=%llu artifact=%.2f MiB",
        (unsigned long long)stats.outputs,
        (unsigned long long)stats.no_owner,
        (unsigned long long)stats.ambiguous_owner,
        (unsigned long long)stats.non_data_owner,
        (unsigned long long)stats.incomplete_owner,
        (unsigned long long)stats.trusted_exact_start,
        (unsigned long long)stats.trusted_interior,
        (unsigned long long)stats.lookup_failures,
        (double)stats.artifact_bytes / (1024.0 * 1024.0));
    return 1;
}

static int write_finalize_status_local(
    const char *phase,
    const char *status,
    size_t moved,
    int snapshot_saved,
    int outputs_flushed,
    int output_metadata_written,
    size_t next_output_index,
    double reconcile_seconds,
    double snapshot_seconds,
    double rewrite_outputs_seconds,
    double total_seconds
)
{
    char status_path[HFSPLUS_PATH_MAX];
    char status_temp[HFSPLUS_PATH_MAX + 32];
    char recovered_log_path[HFSPLUS_PATH_MAX];
    char state_dir[HFSPLUS_PATH_MAX];
    FILE *file;
    struct stat recovered_log_stat;
    uint64_t metadata_generation = 0ULL;
    uint64_t recovered_log_bytes = 0ULL;
    size_t unresolved_outputs = hfsplus_backend_unreconciled_output_count();

    if (g_hfsplus_output_dir[0] == '\0' ||
        snprintf(state_dir, sizeof(state_dir), "%s/%s", g_hfsplus_output_dir, APP_STATE_DIR_NAME) >=
            (int)sizeof(state_dir) ||
        !ensure_directory_path_local(state_dir) ||
        !build_finalize_status_path_local(status_path, sizeof(status_path)) ||
        snprintf(status_temp, sizeof(status_temp), "%s.tmp", status_path) >=
            (int)sizeof(status_temp)) {
        return 0;
    }

    if (g_hfsplus_compact_reader != NULL) {
        metadata_generation =
            metadata_index_reader_generation(g_hfsplus_compact_reader);
    }
    if (build_recovered_outputs_log_path_local(
            recovered_log_path,
            sizeof(recovered_log_path)) &&
        stat(recovered_log_path, &recovered_log_stat) == 0 &&
        recovered_log_stat.st_size > 0) {
        recovered_log_bytes = (uint64_t)recovered_log_stat.st_size;
    }

    file = fopen(status_temp, "w");
    if (file == NULL) {
        return 0;
    }

    fprintf(file, "format_version=2\nbackend=hfsplus\n");
    fprintf(file, "phase=%s\n", phase != NULL ? phase : "unknown");
    fprintf(file, "status=%s\n", status != NULL ? status : "unknown");
    fprintf(file, "reconcile_complete=%d\n",
            status != NULL && strcmp(status, "ready") == 0 ? 1 : 0);
    fprintf(file, "metadata_generation=%llu\n",
            (unsigned long long)metadata_generation);
    fprintf(file, "recovered_outputs_log_bytes=%llu\n",
            (unsigned long long)recovered_log_bytes);
    fprintf(file, "next_output_index=%zu\n", next_output_index);
    fprintf(file, "finalize_budget_seconds=%.6f\n",
            g_hfsplus_finalize_budget_seconds);
    fprintf(file, "finalize_budget_profile=%s\n",
            g_hfsplus_finalize_budget_profile[0] != '\0'
                ? g_hfsplus_finalize_budget_profile
                : "unbounded");
    fprintf(file, "catalog_loaded=%d\n", g_hfsplus_catalog_loaded ? 1 : 0);
    fprintf(file, "compact_index_loaded=%d\n",
            g_hfsplus_compact_reader != NULL ? 1 : 0);
    fprintf(file, "metadata_lookup_ready=%d\n",
            hfsplus_metadata_ready_local() ? 1 : 0);
    fprintf(file, "snapshot_saved=%d\n", snapshot_saved ? 1 : 0);
    fprintf(file, "outputs_flushed=%d\n", outputs_flushed ? 1 : 0);
    fprintf(file, "output_metadata_written=%d\n",
            output_metadata_written ? 1 : 0);
    fprintf(file, "entries=%zu\n", g_hfsplus_entry_count);
    fprintf(file, "exact_offsets=%zu\n", g_hfsplus_offset_index_count);
    fprintf(file, "spans=%zu\n", g_hfsplus_span_index_count);
    fprintf(file, "recovered_outputs=%zu\n", g_hfsplus_recovered_output_count);
    fprintf(file, "named_outputs=%zu\n", g_hfsplus_reconciled_output_count);
    fprintf(file, "embedded_outputs=%llu\n",
            (unsigned long long)g_hfsplus_embedded_output_count);
    fprintf(file, "unresolved_outputs=%zu\n", unresolved_outputs);
    /* Kept for readers of the older finalize schema. Embedded context is no
     * longer pending naming work, so this now means genuinely unresolved. */
    fprintf(file, "pending_outputs=%zu\n", unresolved_outputs);
    fprintf(file, "pending_queue=%zu\n", pending_output_queue_depth_local());
    fprintf(file, "moved_outputs=%zu\n", moved);
    fprintf(file, "source_size=%llu\n",
            (unsigned long long)g_hfsplus_geometry.source_size);
    fprintf(file, "container_offset=%llu\n",
            (unsigned long long)g_hfsplus_geometry.container_offset);
    fprintf(file, "volume_offset=%llu\n",
            (unsigned long long)g_hfsplus_geometry.volume_offset);
    fprintf(file, "volume_size=%llu\n",
            (unsigned long long)g_hfsplus_geometry.volume_size);
    fprintf(file, "block_size=%u\n", g_hfsplus_geometry.block_size);
    fprintf(file, "catalog_logical_size=%llu\n",
            (unsigned long long)g_hfsplus_geometry.catalog_logical_size);
    fprintf(file, "source_path=%s\n", g_hfsplus_source_path);
    fprintf(file, "volume_uuid=%016llx\n",
            (unsigned long long)g_hfsplus_geometry.volume_uuid);
    fprintf(file, "modify_date_hfs=%u\nwrite_count=%u\njournal_info_block=%u\n",
            g_hfsplus_geometry.modify_date_hfs,
            g_hfsplus_geometry.write_count,
            g_hfsplus_geometry.journal_info_block);
    fprintf(file, "reconcile_seconds=%.6f\n", reconcile_seconds);
    fprintf(file, "snapshot_seconds=%.6f\n", snapshot_seconds);
    fprintf(file, "rewrite_outputs_seconds=%.6f\n", rewrite_outputs_seconds);
    fprintf(file, "total_seconds=%.6f\n", total_seconds);
    fprintf(file, "generated_at_unix=%llu\n", (unsigned long long)time(NULL));

    if (fclose(file) != 0) {
        (void)unlink(status_temp);
        return 0;
    }
    if (rename(status_temp, status_path) != 0) {
        (void)unlink(status_temp);
        return 0;
    }
    (void)chmod(status_path, 0644);
    return mft_apply_output_owner_to_path(status_path);
}

static int load_compact_finalize_checkpoint_local(
    size_t *out_next_output_index,
    int *out_complete
)
{
    char status_path[HFSPLUS_PATH_MAX];
    char recovered_log_path[HFSPLUS_PATH_MAX];
    char line[512];
    FILE *file;
    struct stat recovered_log_stat;
    uint64_t metadata_generation = 0ULL;
    uint64_t recovered_outputs = 0ULL;
    uint64_t named_outputs = 0ULL;
    uint64_t unresolved_outputs = 0ULL;
    uint64_t recovered_log_bytes = 0ULL;
    uint64_t volume_uuid = 0ULL;
    uint64_t modify_date_hfs = 0ULL;
    uint64_t write_count = 0ULL;
    uint64_t journal_info_block = 0ULL;
    uint64_t next_output_index = 0ULL;
    unsigned int required = 0U;
    uint64_t current_log_bytes = 0ULL;
    int status_seen = 0;
    int status_ready = 0;
    int reconcile_complete = 0;

    enum {
        FINALIZE_SEEN_FORMAT = 1U << 0,
        FINALIZE_SEEN_BACKEND = 1U << 1,
        FINALIZE_SEEN_STATUS = 1U << 2,
        FINALIZE_SEEN_COMPLETE = 1U << 3,
        FINALIZE_SEEN_GENERATION = 1U << 4,
        FINALIZE_SEEN_RECOVERED = 1U << 5,
        FINALIZE_SEEN_NAMED = 1U << 6,
        FINALIZE_SEEN_UNRESOLVED = 1U << 7,
        FINALIZE_SEEN_LOG_BYTES = 1U << 8,
        FINALIZE_SEEN_UUID = 1U << 9,
        FINALIZE_SEEN_MODIFY = 1U << 10,
        FINALIZE_SEEN_WRITE_COUNT = 1U << 11,
        FINALIZE_SEEN_JOURNAL = 1U << 12,
        FINALIZE_SEEN_NEXT_OUTPUT = 1U << 13,
        FINALIZE_REQUIRED = (1U << 14) - 1U
    };

    if (out_next_output_index != NULL) {
        *out_next_output_index = 0U;
    }
    if (out_complete != NULL) {
        *out_complete = 0;
    }

    if (!g_hfsplus_compact_only ||
        g_hfsplus_compact_reader == NULL ||
        !build_finalize_status_path_local(status_path, sizeof(status_path))) {
        return 0;
    }
    file = fopen(status_path, "r");
    if (file == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned long long value = 0ULL;

        if (strcmp(line, "format_version=2\n") == 0) {
            required |= FINALIZE_SEEN_FORMAT;
        } else if (strcmp(line, "backend=hfsplus\n") == 0) {
            required |= FINALIZE_SEEN_BACKEND;
        } else if (strcmp(line, "status=ready\n") == 0 ||
                   strcmp(line, "status=partial\n") == 0) {
            status_seen = 1;
            status_ready = strcmp(line, "status=ready\n") == 0;
            required |= FINALIZE_SEEN_STATUS;
        } else if (strcmp(line, "reconcile_complete=1\n") == 0 ||
                   strcmp(line, "reconcile_complete=0\n") == 0) {
            reconcile_complete = strcmp(line, "reconcile_complete=1\n") == 0;
            required |= FINALIZE_SEEN_COMPLETE;
        } else if (sscanf(line, "metadata_generation=%llu", &value) == 1) {
            metadata_generation = (uint64_t)value;
            required |= FINALIZE_SEEN_GENERATION;
        } else if (sscanf(line, "recovered_outputs=%llu", &value) == 1) {
            recovered_outputs = (uint64_t)value;
            required |= FINALIZE_SEEN_RECOVERED;
        } else if (sscanf(line, "named_outputs=%llu", &value) == 1) {
            named_outputs = (uint64_t)value;
            required |= FINALIZE_SEEN_NAMED;
        } else if (sscanf(line, "unresolved_outputs=%llu", &value) == 1) {
            unresolved_outputs = (uint64_t)value;
            required |= FINALIZE_SEEN_UNRESOLVED;
        } else if (sscanf(line, "recovered_outputs_log_bytes=%llu", &value) == 1) {
            recovered_log_bytes = (uint64_t)value;
            required |= FINALIZE_SEEN_LOG_BYTES;
        } else if (sscanf(line, "next_output_index=%llu", &value) == 1) {
            next_output_index = (uint64_t)value;
            required |= FINALIZE_SEEN_NEXT_OUTPUT;
        } else if (sscanf(line, "volume_uuid=%llx", &value) == 1) {
            volume_uuid = (uint64_t)value;
            required |= FINALIZE_SEEN_UUID;
        } else if (sscanf(line, "modify_date_hfs=%llu", &value) == 1) {
            modify_date_hfs = (uint64_t)value;
            required |= FINALIZE_SEEN_MODIFY;
        } else if (sscanf(line, "write_count=%llu", &value) == 1) {
            write_count = (uint64_t)value;
            required |= FINALIZE_SEEN_WRITE_COUNT;
        } else if (sscanf(line, "journal_info_block=%llu", &value) == 1) {
            journal_info_block = (uint64_t)value;
            required |= FINALIZE_SEEN_JOURNAL;
        }
    }
    if (fclose(file) != 0 || required != FINALIZE_REQUIRED || !status_seen ||
        status_ready != reconcile_complete) {
        return 0;
    }
    if (!build_recovered_outputs_log_path_local(
            recovered_log_path,
            sizeof(recovered_log_path)) ||
        stat(recovered_log_path, &recovered_log_stat) != 0 ||
        recovered_log_stat.st_size < 0) {
        return 0;
    }
    current_log_bytes = (uint64_t)recovered_log_stat.st_size;
    if (metadata_generation !=
            metadata_index_reader_generation(g_hfsplus_compact_reader) ||
        recovered_outputs != (uint64_t)g_hfsplus_recovered_output_count ||
        named_outputs != (uint64_t)g_hfsplus_reconciled_output_count ||
        unresolved_outputs !=
            (uint64_t)hfsplus_backend_unreconciled_output_count() ||
        recovered_log_bytes != current_log_bytes ||
        volume_uuid != g_hfsplus_geometry.volume_uuid ||
        modify_date_hfs != g_hfsplus_geometry.modify_date_hfs ||
        write_count != g_hfsplus_geometry.write_count ||
        journal_info_block != g_hfsplus_geometry.journal_info_block ||
        next_output_index > (uint64_t)g_hfsplus_recovered_output_count) {
        return 0;
    }
    if (out_next_output_index != NULL) {
        *out_next_output_index = (size_t)next_output_index;
    }
    if (out_complete != NULL) {
        *out_complete = reconcile_complete;
    }
    return 1;
}

static int finalize_state_local(
    const char *activity,
    const char *phase_label,
    const char *log_label
)
{
    double finalize_started_at = monotonic_seconds_local();
    double phase_started_at = finalize_started_at;
    double reconcile_seconds = 0.0;
    double snapshot_seconds = 0.0;
    double rewrite_outputs_seconds = 0.0;
    double status_seconds = 0.0;
    int exhausted = 0;
    int changed = 0;
    int snapshot_saved = 1;
    int outputs_flushed = 1;
    int output_metadata_written = 0;
    int status_written = 0;
    size_t moved = 0U;
    size_t pending_outputs = 0U;

    if (!hfsplus_catalog_available_local()) {
        return 0;
    }
    if (!ensure_lookup_index_current_local()) {
        log_error("Failed to finalize HFS+ metadata state because lookup indices are unavailable");
        return 0;
    }

    log_set_working_activity(activity);
    enqueue_all_unreconciled_outputs_local();
    g_hfsplus_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_NAMING;
    moved = reconcile_pending_output_queue_local(
        0U,
        1,
        0.0,
        &exhausted,
        &changed,
        NULL
    );
    g_hfsplus_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;
    mft_spool_publish_backend_counts(
        (uint64_t)g_hfsplus_recovered_output_count,
        (uint64_t)g_hfsplus_reconciled_output_count,
        (uint64_t)hfsplus_backend_unreconciled_output_count()
    );
    reconcile_seconds = monotonic_seconds_local() - phase_started_at;

    if (moved > 0U) {
        log_info("Reconciled %zu recovered files with HFS+ catalog context", moved);
    }
    if (hfsplus_compact_available_local() &&
        hfsplus_create_extent_meter_local()) {
        (void)hfsplus_sequential_assembly_init_local();
        (void)hfsplus_write_extent_measurement_local("checkpoint");
    }

    phase_started_at = monotonic_seconds_local();
    snapshot_saved = save_metadata_snapshot_local();
    snapshot_seconds = monotonic_seconds_local() - phase_started_at;
    write_photos_library_signal_local();

    phase_started_at = monotonic_seconds_local();
    if (changed || g_hfsplus_recovered_outputs_log_needs_rewrite) {
        outputs_flushed = rewrite_recovered_outputs_log_local();
        if (outputs_flushed) {
            g_hfsplus_live_last_rewrite_at = monotonic_seconds_local();
        }
    }
    rewrite_outputs_seconds = monotonic_seconds_local() - phase_started_at;

    output_metadata_written = write_recovered_output_metadata_outcomes_local();
    if (g_hfsplus_journal_names_recovered_current > 0ULL) {
        moved += (size_t)g_hfsplus_journal_names_recovered_current;
        log_info(
            "Included %llu safe HFS+ journal name recovery move(s) in finalize totals",
            (unsigned long long)g_hfsplus_journal_names_recovered_current);
        mft_spool_publish_backend_counts(
            (uint64_t)g_hfsplus_recovered_output_count,
            (uint64_t)g_hfsplus_reconciled_output_count,
            (uint64_t)hfsplus_backend_unreconciled_output_count());
    }
    if (!output_metadata_written) {
        log_info(
            "HFS+ finalize could not write recovered-output metadata outcomes; recovery results are unaffected"
        );
    }

    if (!write_unresolved_output_audit_local()) {
        log_info(
            "HFS+ finalize could not write unresolved-output audit; recovery results are unaffected"
        );
    }

    pending_outputs = hfsplus_backend_unreconciled_output_count();

    phase_started_at = monotonic_seconds_local();
    status_written = write_finalize_status_local(
        phase_label,
        snapshot_saved && outputs_flushed ? "ready" : "partial",
        moved,
        snapshot_saved,
        outputs_flushed,
        output_metadata_written,
        g_hfsplus_recovered_output_count,
        reconcile_seconds,
        snapshot_seconds,
        rewrite_outputs_seconds,
        monotonic_seconds_local() - finalize_started_at
    );
    status_seconds = monotonic_seconds_local() - phase_started_at;

    if (!snapshot_saved) {
        log_error(
            "HFS+ finalize could not save a fresh metadata snapshot; reruns may need to rebuild catalog metadata from the source"
        );
    }
    if (!outputs_flushed) {
        log_error(
            "HFS+ finalize could not flush recovered_outputs.tsv cleanly; reruns may have less accurate pending-output state"
        );
    }
    if (!status_written) {
        log_info(
            "HFS+ finalize could not write hfsplus_finalize_status.txt; continuing with runtime logs and saved state"
        );
    }

    log_info(
        "%s timings: reconcile=%.2fs snapshot=%.2fs rewrite_outputs=%.2fs status=%.2fs total=%.2fs recovered=%zu named=%zu embedded=%llu unresolved=%zu queue=%zu moved=%zu",
        log_label,
        reconcile_seconds,
        snapshot_seconds,
        rewrite_outputs_seconds,
        status_seconds,
        monotonic_seconds_local() - finalize_started_at,
        g_hfsplus_recovered_output_count,
        g_hfsplus_reconciled_output_count,
        (unsigned long long)g_hfsplus_embedded_output_count,
        pending_outputs,
        pending_output_queue_depth_local(),
        moved
    );

    return snapshot_saved && outputs_flushed;
}

static int save_metadata_snapshot_local(void)
{
    char snapshot_path[HFSPLUS_PATH_MAX];
    char temp_path[HFSPLUS_PATH_MAX + 32];
    char state_dir[HFSPLUS_PATH_MAX];
    FILE *file;
    size_t index;
    uint32_t snapshot_flags = 0U;

    if (!g_hfsplus_catalog_loaded ||
        g_hfsplus_entry_count == 0U ||
        g_hfsplus_output_dir[0] == '\0' ||
        g_hfsplus_entry_count > (size_t)UINT32_MAX ||
        snprintf(state_dir, sizeof(state_dir), "%s/%s", g_hfsplus_output_dir, APP_STATE_DIR_NAME) >=
            (int)sizeof(state_dir) ||
        !ensure_directory_path_local(state_dir) ||
        !build_metadata_snapshot_path_local(snapshot_path, sizeof(snapshot_path)) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", snapshot_path) >=
            (int)sizeof(temp_path)) {
        return 0;
    }

    file = fopen(temp_path, "wb");
    if (file == NULL) {
        return 0;
    }

    if (g_hfsplus_geometry.has_wrapper) {
        snapshot_flags |= HFSPLUS_SNAPSHOT_FLAG_HAS_WRAPPER;
    }
    if (g_hfsplus_geometry.is_hfsx) {
        snapshot_flags |= HFSPLUS_SNAPSHOT_FLAG_IS_HFSX;
    }
    if (g_hfsplus_sort_case_sensitive) {
        snapshot_flags |= HFSPLUS_SNAPSHOT_FLAG_SORT_CASE_SENSITIVE;
    }

    if (!write_bytes_local(file, HFSPLUS_SNAPSHOT_MAGIC, HFSPLUS_SNAPSHOT_MAGIC_SIZE) ||
        !write_u32_le_file_local(file, HFSPLUS_SNAPSHOT_VERSION) ||
        !write_u32_le_file_local(file, snapshot_flags) ||
        !write_u64_le_file_local(file, g_hfsplus_geometry.source_size) ||
        !write_u64_le_file_local(file, g_hfsplus_geometry.container_offset) ||
        !write_u64_le_file_local(file, g_hfsplus_geometry.volume_offset) ||
        !write_u64_le_file_local(file, g_hfsplus_geometry.volume_size) ||
        !write_u64_le_file_local(file, g_hfsplus_geometry.catalog_logical_size) ||
        !write_u32_le_file_local(file, g_hfsplus_geometry.block_size) ||
        !write_u32_le_file_local(file, g_hfsplus_geometry.total_blocks) ||
        !write_u32_le_file_local(file, g_hfsplus_geometry.catalog_total_blocks) ||
        !write_u64_le_file_local(file, g_hfsplus_geometry.volume_uuid) ||
        !write_u32_le_file_local(file, g_hfsplus_geometry.attributes) ||
        !write_u32_le_file_local(file, g_hfsplus_geometry.journal_info_block) ||
        !write_u32_le_file_local(file, g_hfsplus_geometry.modify_date_hfs) ||
        !write_u32_le_file_local(file, g_hfsplus_geometry.write_count) ||
        !write_u32_le_file_local(file, (uint32_t)g_hfsplus_entry_count)) {
        fclose(file);
        (void)unlink(temp_path);
        return 0;
    }

    for (index = 0U; index < g_hfsplus_entry_count; ++index) {
        const HfsPlusCatalogEntry *entry = &g_hfsplus_entries[index];
        size_t run_index;
        size_t name_length = strnlen(entry->name, sizeof(entry->name));
        size_t path_length = strnlen(entry->path, sizeof(entry->path));
        uint32_t entry_flags = 0U;

        if (entry->run_count > HFSPLUS_MAX_FORK_EXTENTS ||
            name_length > UINT16_MAX ||
            path_length > UINT16_MAX) {
            fclose(file);
            (void)unlink(temp_path);
            return 0;
        }

        if (entry->run_truncated) {
            entry_flags |= HFSPLUS_SNAPSHOT_ENTRY_FLAG_RUN_TRUNCATED;
        }
        if (entry->is_directory) {
            entry_flags |= HFSPLUS_SNAPSHOT_ENTRY_FLAG_DIRECTORY;
        }
        if (entry->has_data) {
            entry_flags |= HFSPLUS_SNAPSHOT_ENTRY_FLAG_HAS_DATA;
        }
        if (entry->has_name) {
            entry_flags |= HFSPLUS_SNAPSHOT_ENTRY_FLAG_HAS_NAME;
        }
        if (entry->path_complete) {
            entry_flags |= HFSPLUS_SNAPSHOT_ENTRY_FLAG_PATH_COMPLETE;
        }
        if (entry->is_hardlink_placeholder) {
            entry_flags |= HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_PLACEHOLDER;
        }
        if (entry->is_hardlink_inode) {
            entry_flags |= HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_INODE;
        }
        if (entry->hardlink_resolved) {
            entry_flags |= HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_RESOLVED;
        }
        if (entry->is_hardlink_metadata_directory) {
            entry_flags |= HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_METADATA_DIR;
        }

        if (!write_u32_le_file_local(file, entry->file_id) ||
            !write_u32_le_file_local(file, entry->parent_id) ||
            !write_u32_le_file_local(file, entry->create_date_hfs) ||
            !write_u64_le_file_local(file, (uint64_t)(int64_t)entry->created_unix) ||
            !write_u64_le_file_local(file, entry->abs_offset) ||
            !write_u64_le_file_local(file, entry->data_size) ||
            !write_u64_le_file_local(file, entry->allocated_size) ||
            !write_u32_le_file_local(file, (uint32_t)entry->run_count) ||
            !write_u32_le_file_local(file, entry_flags) ||
            !write_u32_le_file_local(file, entry->hardlink_reference) ||
            !write_u16_le_file_local(file, (uint16_t)name_length) ||
            !write_u16_le_file_local(file, (uint16_t)path_length)) {
            fclose(file);
            (void)unlink(temp_path);
            return 0;
        }

        for (run_index = 0U; run_index < entry->run_count; ++run_index) {
            const MftViewRun *run = catalog_entry_run_local(entry, run_index);

            if (run == NULL ||
                !write_u64_le_file_local(file, run->abs_offset) ||
                !write_u64_le_file_local(file, run->byte_length)) {
                fclose(file);
                (void)unlink(temp_path);
                return 0;
            }
        }

        if ((name_length > 0U && !write_bytes_local(file, entry->name, name_length)) ||
            (path_length > 0U && !write_bytes_local(file, entry->path, path_length))) {
            fclose(file);
            (void)unlink(temp_path);
            return 0;
        }
    }

    if (fclose(file) != 0 ||
        rename(temp_path, snapshot_path) != 0) {
        (void)unlink(temp_path);
        return 0;
    }

    return mft_apply_output_owner_to_path(snapshot_path);
}

static int load_metadata_snapshot_local(const HfsPlusBackendGeometry *expected_geometry)
{
    char snapshot_path[HFSPLUS_PATH_MAX];
    FILE *file = NULL;
    unsigned char magic[HFSPLUS_SNAPSHOT_MAGIC_SIZE];
    unsigned char buffer[8];
    uint32_t snapshot_version;
    uint32_t snapshot_flags;
    uint64_t snapshot_source_size;
    uint64_t snapshot_container_offset;
    uint64_t snapshot_volume_offset;
    uint64_t snapshot_volume_size;
    uint64_t snapshot_catalog_logical_size;
    uint32_t snapshot_block_size;
    uint32_t snapshot_total_blocks;
    uint32_t snapshot_catalog_total_blocks;
    uint64_t snapshot_volume_uuid;
    uint32_t snapshot_attributes;
    uint32_t snapshot_journal_info_block;
    uint32_t snapshot_modify_date_hfs;
    uint32_t snapshot_write_count;
    uint32_t snapshot_entry_count;
    size_t entry_index;
    int legacy_zero_source_size = 0;
    int loaded = 0;

    if (expected_geometry == NULL ||
        !build_metadata_snapshot_path_local(snapshot_path, sizeof(snapshot_path))) {
        return 0;
    }

    file = fopen(snapshot_path, "rb");
    if (file == NULL) {
        return 0;
    }

    if (!read_exact_local(file, magic, sizeof(magic)) ||
        memcmp(magic, HFSPLUS_SNAPSHOT_MAGIC, sizeof(magic)) != 0) {
        goto cleanup;
    }
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_version = read_u32_le_local(buffer);
    if (snapshot_version != HFSPLUS_SNAPSHOT_VERSION) {
        log_info(
            "Saved HFS+ metadata snapshot v%u predates parser schema v%u; rebuilding Catalog metadata from the source",
            snapshot_version,
            HFSPLUS_SNAPSHOT_VERSION
        );
        goto cleanup;
    }
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_flags = read_u32_le_local(buffer);
    if (!read_exact_local(file, buffer, 8U)) {
        goto cleanup;
    }
    snapshot_source_size = read_u64_le_local(buffer);
    if (!read_exact_local(file, buffer, 8U)) {
        goto cleanup;
    }
    snapshot_container_offset = read_u64_le_local(buffer);
    if (!read_exact_local(file, buffer, 8U)) {
        goto cleanup;
    }
    snapshot_volume_offset = read_u64_le_local(buffer);
    if (!read_exact_local(file, buffer, 8U)) {
        goto cleanup;
    }
    snapshot_volume_size = read_u64_le_local(buffer);
    if (!read_exact_local(file, buffer, 8U)) {
        goto cleanup;
    }
    snapshot_catalog_logical_size = read_u64_le_local(buffer);
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_block_size = read_u32_le_local(buffer);
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_total_blocks = read_u32_le_local(buffer);
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_catalog_total_blocks = read_u32_le_local(buffer);
    if (!read_exact_local(file, buffer, 8U)) {
        goto cleanup;
    }
    snapshot_volume_uuid = read_u64_le_local(buffer);
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_attributes = read_u32_le_local(buffer);
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_journal_info_block = read_u32_le_local(buffer);
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_modify_date_hfs = read_u32_le_local(buffer);
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_write_count = read_u32_le_local(buffer);
    if (!read_exact_local(file, buffer, 4U)) {
        goto cleanup;
    }
    snapshot_entry_count = read_u32_le_local(buffer);

    if (snapshot_source_size == 0U && expected_geometry->source_size > 0U &&
        expected_geometry->volume_offset <=
            UINT64_MAX - expected_geometry->volume_size &&
        expected_geometry->source_size >=
            expected_geometry->volume_offset + expected_geometry->volume_size) {
        legacy_zero_source_size = 1;
    }
    if ((!legacy_zero_source_size &&
         snapshot_source_size != expected_geometry->source_size) ||
        snapshot_container_offset != expected_geometry->container_offset ||
        snapshot_volume_offset != expected_geometry->volume_offset ||
        snapshot_volume_size != expected_geometry->volume_size ||
        snapshot_catalog_logical_size != expected_geometry->catalog_logical_size ||
        snapshot_block_size != expected_geometry->block_size ||
        snapshot_total_blocks != expected_geometry->total_blocks ||
        snapshot_catalog_total_blocks != expected_geometry->catalog_total_blocks ||
        snapshot_volume_uuid != expected_geometry->volume_uuid ||
        snapshot_attributes != expected_geometry->attributes ||
        snapshot_journal_info_block != expected_geometry->journal_info_block ||
        snapshot_modify_date_hfs != expected_geometry->modify_date_hfs ||
        snapshot_write_count != expected_geometry->write_count ||
        ((snapshot_flags & HFSPLUS_SNAPSHOT_FLAG_HAS_WRAPPER) != 0U) !=
            (expected_geometry->has_wrapper != 0) ||
        ((snapshot_flags & HFSPLUS_SNAPSHOT_FLAG_IS_HFSX) != 0U) !=
            (expected_geometry->is_hfsx != 0)) {
        goto cleanup;
    }

    free_catalog_state_local();
    g_hfsplus_sort_case_sensitive =
        (snapshot_flags & HFSPLUS_SNAPSHOT_FLAG_SORT_CASE_SENSITIVE) != 0U;

    for (entry_index = 0U; entry_index < (size_t)snapshot_entry_count; ++entry_index) {
        HfsPlusCatalogEntry entry = {0};
        uint32_t run_count;
        uint32_t entry_flags;
        uint16_t name_length;
        uint16_t path_length;
        size_t run_index;

        if (!read_exact_local(file, buffer, 4U)) {
            goto cleanup;
        }
        entry.file_id = read_u32_le_local(buffer);
        if (!read_exact_local(file, buffer, 4U)) {
            goto cleanup;
        }
        entry.parent_id = read_u32_le_local(buffer);
        if (!read_exact_local(file, buffer, 4U)) {
            goto cleanup;
        }
        entry.create_date_hfs = read_u32_le_local(buffer);
        if (!read_exact_local(file, buffer, 8U)) {
            goto cleanup;
        }
        entry.created_unix = (time_t)(int64_t)read_u64_le_local(buffer);
        if (!read_exact_local(file, buffer, 8U)) {
            goto cleanup;
        }
        entry.abs_offset = read_u64_le_local(buffer);
        if (!read_exact_local(file, buffer, 8U)) {
            goto cleanup;
        }
        entry.data_size = read_u64_le_local(buffer);
        if (!read_exact_local(file, buffer, 8U)) {
            goto cleanup;
        }
        entry.allocated_size = read_u64_le_local(buffer);
        if (!read_exact_local(file, buffer, 4U)) {
            goto cleanup;
        }
        run_count = read_u32_le_local(buffer);
        if (!read_exact_local(file, buffer, 4U)) {
            goto cleanup;
        }
        entry_flags = read_u32_le_local(buffer);
        if (!read_exact_local(file, buffer, 4U)) {
            goto cleanup;
        }
        entry.hardlink_reference = read_u32_le_local(buffer);
        if (!read_exact_local(file, buffer, 2U)) {
            goto cleanup;
        }
        name_length = read_u16_le_local(buffer);
        if (!read_exact_local(file, buffer, 2U)) {
            goto cleanup;
        }
        path_length = read_u16_le_local(buffer);

        if (run_count > HFSPLUS_MAX_FORK_EXTENTS ||
            name_length >= sizeof(entry.name) ||
            path_length >= sizeof(entry.path)) {
            goto cleanup;
        }

        entry.run_count = (size_t)run_count;
        if (entry.run_count > MFT_VIEW_MAX_RUNS) {
            entry.extra_run_count = entry.run_count - MFT_VIEW_MAX_RUNS;
            entry.extra_runs = (MftViewRun *)calloc(
                entry.extra_run_count,
                sizeof(*entry.extra_runs)
            );
            if (entry.extra_runs == NULL) {
                goto cleanup;
            }
        }
        entry.run_truncated =
            (entry_flags & HFSPLUS_SNAPSHOT_ENTRY_FLAG_RUN_TRUNCATED) != 0U;
        entry.is_directory =
            (entry_flags & HFSPLUS_SNAPSHOT_ENTRY_FLAG_DIRECTORY) != 0U;
        entry.has_data =
            (entry_flags & HFSPLUS_SNAPSHOT_ENTRY_FLAG_HAS_DATA) != 0U;
        entry.has_name =
            (entry_flags & HFSPLUS_SNAPSHOT_ENTRY_FLAG_HAS_NAME) != 0U;
        entry.path_complete =
            (entry_flags & HFSPLUS_SNAPSHOT_ENTRY_FLAG_PATH_COMPLETE) != 0U;
        entry.is_hardlink_placeholder =
            (entry_flags & HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_PLACEHOLDER) != 0U;
        entry.is_hardlink_inode =
            (entry_flags & HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_INODE) != 0U;
        entry.hardlink_resolved =
            (entry_flags & HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_RESOLVED) != 0U;
        entry.is_hardlink_metadata_directory =
            (entry_flags & HFSPLUS_SNAPSHOT_ENTRY_FLAG_HARDLINK_METADATA_DIR) != 0U;

        for (run_index = 0U; run_index < entry.run_count; ++run_index) {
            MftViewRun *run = run_index < MFT_VIEW_MAX_RUNS
                ? &entry.runs[run_index]
                : &entry.extra_runs[run_index - MFT_VIEW_MAX_RUNS];

            if (!read_exact_local(file, buffer, 8U)) {
                free(entry.extra_runs);
                goto cleanup;
            }
            run->abs_offset = read_u64_le_local(buffer);
            if (!read_exact_local(file, buffer, 8U)) {
                free(entry.extra_runs);
                goto cleanup;
            }
            run->byte_length = read_u64_le_local(buffer);
        }

        if ((name_length > 0U &&
             !read_exact_local(file, entry.name, name_length)) ||
            (path_length > 0U &&
             !read_exact_local(file, entry.path, path_length))) {
            free(entry.extra_runs);
            goto cleanup;
        }
        entry.name[name_length] = '\0';
        entry.path[path_length] = '\0';

        if (!append_catalog_entry_local(&entry)) {
            free(entry.extra_runs);
            goto cleanup;
        }
    }

    if (!build_id_index_local() || !resolve_hardlink_catalog_entries_local()) {
        goto cleanup;
    }
    g_hfsplus_catalog_loaded = g_hfsplus_entry_count > 0U ? 1 : 0;
    loaded = g_hfsplus_catalog_loaded;
    if (loaded && legacy_zero_source_size) {
        log_info(
            "HFS+ metadata snapshot reused through legacy source-size compatibility: saved_size=0 detected_size=%llu; all volume identity fields matched",
            (unsigned long long)expected_geometry->source_size
        );
    }

cleanup:
    if (file != NULL) {
        fclose(file);
    }
    if (!loaded) {
        free_catalog_state_local();
    }
    return loaded;
}

static int remember_recovered_output_from_state_local(
    const char *path,
    long long abs_offset,
    int reconciled,
    unsigned int classification
)
{
    size_t index;
    int needs_reconcile = reconciled ? 0 : 1;

    if (path == NULL || path[0] == '\0' || abs_offset < 0) {
        return 0;
    }

    index = find_recovered_output_index_local(abs_offset);
    if (index != (size_t)-1) {
        copy_text_bounded_local(
            g_hfsplus_recovered_outputs[index].path,
            sizeof(g_hfsplus_recovered_outputs[index].path),
            path
        );
        set_recovered_output_reconciled_local(index, reconciled);
        set_recovered_output_classification_local(index, classification);
        if (needs_reconcile) {
            (void)enqueue_pending_output_local(index);
        }
        return 1;
    }

    if (!ensure_recovered_output_capacity_local(g_hfsplus_recovered_output_count + 1U) ||
        !ensure_pending_output_flags_capacity_local(g_hfsplus_recovered_output_count + 1U)) {
        return 0;
    }

    copy_text_bounded_local(
        g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].path,
        sizeof(g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].path),
        path
    );
    g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].abs_offset = abs_offset;
    g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].reconciled = 0;
    g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].classification =
        HFSPLUS_OUTPUT_CLASS_UNCLASSIFIED;
    g_hfsplus_recovered_output_count++;
    set_recovered_output_reconciled_local(
        g_hfsplus_recovered_output_count - 1U,
        reconciled
    );
    set_recovered_output_classification_local(
        g_hfsplus_recovered_output_count - 1U,
        classification
    );
    if (needs_reconcile) {
        (void)enqueue_pending_output_local(g_hfsplus_recovered_output_count - 1U);
    }
    return 1;
}

static int resolve_recovered_output_path_for_current_run_local(
    const char *stored_path,
    char *resolved_path,
    size_t resolved_path_size
)
{
    struct stat st;
    const char *recovered_suffix;
    const char *photorec_suffix;

    if (resolved_path != NULL && resolved_path_size > 0U) {
        resolved_path[0] = '\0';
    }
    if (stored_path == NULL ||
        stored_path[0] == '\0' ||
        g_hfsplus_output_dir[0] == '\0' ||
        resolved_path == NULL ||
        resolved_path_size == 0U) {
        return 0;
    }

    if (snprintf(resolved_path, resolved_path_size, "%s", stored_path) <
            (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    recovered_suffix = strstr(stored_path, "/" APP_RECOVERED_DIR_NAME "/");
    if (recovered_suffix != NULL &&
        snprintf(
            resolved_path,
            resolved_path_size,
            "%s%s",
            g_hfsplus_output_dir,
            recovered_suffix) < (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    if (strncmp(
            stored_path,
            APP_RECOVERED_DIR_NAME "/",
            strlen(APP_RECOVERED_DIR_NAME) + 1U) == 0 &&
        snprintf(
            resolved_path,
            resolved_path_size,
            "%s/%s",
            g_hfsplus_output_dir,
            stored_path) < (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    photorec_suffix = strstr(stored_path, "/recup_dir.");
    if (photorec_suffix != NULL &&
        snprintf(
            resolved_path,
            resolved_path_size,
            "%s%s",
            g_hfsplus_output_dir,
            photorec_suffix) < (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    if (strncmp(stored_path, "recup_dir.", 10) == 0 &&
        snprintf(
            resolved_path,
            resolved_path_size,
            "%s/%s",
            g_hfsplus_output_dir,
            stored_path) < (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    resolved_path[0] = '\0';
    return 0;
}

static int load_recovered_output_state_local(void)
{
    char log_path[HFSPLUS_PATH_MAX];
    FILE *file;
    char line[HFSPLUS_PATH_MAX + 128];
    struct stat log_stat;
    int loaded = 0;
    size_t legacy_inode_outputs = 0U;
    size_t rows_seen = 0U;
    double last_progress_at = 0.0;

    if (!build_recovered_outputs_log_path_local(log_path, sizeof(log_path))) {
        return 0;
    }

    file = fopen(log_path, "r");
    if (file == NULL) {
        return 0;
    }

    memset(&log_stat, 0, sizeof(log_stat));
    (void)fstat(fileno(file), &log_stat);
    log_set_working_activity("loading saved HFS+ recovered-file ledger");
    free_recovered_outputs_local();
    while (fgets(line, sizeof(line), file) != NULL) {
        char *offset_text;
        char *path_text;
        char *reconciled_text;
        char *classification_text;
        char *saveptr = NULL;
        long long abs_offset = -1;
        char resolved_path[HFSPLUS_PATH_MAX];
        int reconciled;
        int legacy_inode_migration = 0;

        if (strncmp(line, "offset\t", 7) == 0) {
            continue;
        }
        rows_seen++;

        if ((rows_seen & 2047U) == 0U) {
            double now = monotonic_seconds_local();

            if (last_progress_at <= 0.0 || now - last_progress_at >= 0.5) {
                char activity[96];
                off_t position = ftello(file);
                unsigned int percent = 0U;

                if (position > 0 && log_stat.st_size > 0) {
                    uint64_t scaled = (uint64_t)position * 100ULL;
                    percent = (unsigned int)(scaled / (uint64_t)log_stat.st_size);
                    if (percent > 100U) percent = 100U;
                }
                snprintf(
                    activity,
                    sizeof(activity),
                    "loading saved HFS+ results: %zu rows (%u%%)",
                    rows_seen,
                    percent);
                log_set_working_activity(activity);
                last_progress_at = now;
            }
        }

        offset_text = strtok_r(line, "\t\r\n", &saveptr);
        path_text = strtok_r(NULL, "\t\r\n", &saveptr);
        reconciled_text = strtok_r(NULL, "\t\r\n", &saveptr);
        classification_text = strtok_r(NULL, "\t\r\n", &saveptr);
        if (offset_text == NULL ||
            path_text == NULL ||
            sscanf(offset_text, "%lld", &abs_offset) != 1 ||
            abs_offset < 0) {
            continue;
        }

        reconciled = recovered_output_path_defaults_reconciled_local(path_text);
        if (reconciled_text != NULL && reconciled_text[0] != '\0') {
            reconciled = (reconciled_text[0] == '1') ? 1 : 0;
        }
        if (!resolve_recovered_output_path_for_current_run_local(
                path_text,
                resolved_path,
                sizeof(resolved_path))) {
            continue;
        }
        if (recovered_output_is_legacy_inode_root_local(resolved_path) ||
            recovered_output_is_legacy_embedded_inode_local(resolved_path)) {
            reconciled = 0;
            classification_text = NULL;
            legacy_inode_migration = 1;
            legacy_inode_outputs++;
        }
        if (remember_recovered_output_from_state_local(
                resolved_path,
                abs_offset,
                reconciled,
                (!legacy_inode_migration &&
                 ((classification_text != NULL &&
                  strcmp(classification_text, "embedded") == 0) ||
                  path_is_embedded_context_local(resolved_path)))
                    ? HFSPLUS_OUTPUT_CLASS_EMBEDDED
                    : HFSPLUS_OUTPUT_CLASS_UNCLASSIFIED)) {
            loaded = 1;
        }
    }

    fclose(file);
    g_hfsplus_recovered_outputs_log_needs_rewrite = 0;
    if (legacy_inode_outputs > 0U) {
        log_info(
            "HFS+ resume queued %zu legacy iNode outputs for visible hard-link path migration",
            legacy_inode_outputs
        );
    }
    /* Loading durable output identity is a resume prerequisite.  Moving and
     * classifying every pending file is not: doing that here made one resume
     * perform the expensive reconcile before its advertised finalize phase,
     * and the app could then load the same ledger a second time.  Keep the
     * queue intact for bounded live work or the explicit finalizer. */
    g_hfsplus_live_reconcile_cursor = pending_output_queue_depth_local();
    if (loaded) {
        char activity[96];

        snprintf(
            activity,
            sizeof(activity),
            "loaded %zu saved HFS+ results; %zu await reconcile",
            g_hfsplus_recovered_output_count,
            pending_output_queue_depth_local());
        log_set_working_activity(activity);
    }
    return loaded;
}

static int append_recovered_output_log_entry_to_stream_local(
    FILE *file,
    const char *path,
    long long abs_offset,
    int reconciled,
    unsigned int classification
)
{
    if (file == NULL || path == NULL || path[0] == '\0' || abs_offset < 0) {
        return 0;
    }

    return fprintf(
               file,
               "%lld\t%s\t%d\t%s\n",
               abs_offset,
               path,
               reconciled ? 1 : 0,
               classification == HFSPLUS_OUTPUT_CLASS_EMBEDDED
                   ? "embedded"
                   : "unclassified") >= 0;
}

static int append_recovered_output_log_entry_local(
    const char *path,
    long long abs_offset,
    int reconciled,
    unsigned int classification
)
{
    char log_path[HFSPLUS_PATH_MAX];
    FILE *file;

    if (!build_recovered_outputs_log_path_local(log_path, sizeof(log_path)) ||
        path == NULL ||
        path[0] == '\0' ||
        abs_offset < 0) {
        return 0;
    }

    file = fopen(log_path, "a");
    if (file == NULL) {
        return 0;
    }
    (void)chmod(log_path, 0644);

    if (ftell(file) == 0L) {
        fprintf(file, "offset\tpath\treconciled\tclassification\n");
    }

    if (!append_recovered_output_log_entry_to_stream_local(
            file,
            path,
            abs_offset,
            reconciled,
            classification)) {
        fclose(file);
        return 0;
    }

    if (fclose(file) != 0) {
        return 0;
    }

    return mft_apply_output_owner_to_path(log_path);
}

static int reconcile_recovered_output_at_index_local(
    size_t output_index,
    int require_contextual,
    int *out_changed,
    int *out_moved
)
{
    HfsPlusRecoveredOutput *output;
    const char *extension;
    char new_path[HFSPLUS_PATH_MAX];
    char old_path[HFSPLUS_PATH_MAX];
    int contextual = 0;
    int embedded = 0;
    int changed = 0;
    int moved = 0;
    time_t created_time = (time_t)0;
    HfsPlusEmbeddedContextLocal embedded_context = {0};

    if (out_changed != NULL) {
        *out_changed = 0;
    }
    if (out_moved != NULL) {
        *out_moved = 0;
    }
    if (output_index >= g_hfsplus_recovered_output_count) {
        return 0;
    }

    output = &g_hfsplus_recovered_outputs[output_index];
    if (output->reconciled ||
        output->classification == HFSPLUS_OUTPUT_CLASS_EMBEDDED) {
        return 1;
    }

    extension = path_extension_local(output->path);
    if (extension == NULL) {
        return 0;
    }

    if (!build_recovered_output_path_internal_local(
            new_path,
            sizeof(new_path),
            output->abs_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            extension,
            output->path,
            &contextual,
            &created_time)) {
        return 0;
    }
    if (require_contextual && !contextual) {
        if (!build_embedded_output_path_local(
                new_path,
                sizeof(new_path),
                output,
                extension,
                &embedded_context)) {
            return 0;
        }
        embedded = 1;
    }

    if (strcmp(new_path, output->path) == 0) {
        int reconciled = embedded
            ? 0
            : recovered_output_path_defaults_reconciled_local(new_path);

        if (embedded) {
            set_recovered_output_classification_local(
                output_index,
                HFSPLUS_OUTPUT_CLASS_EMBEDDED);
        }
        if (reconciled != output->reconciled || embedded) {
            set_recovered_output_reconciled_local(output_index, reconciled);
            changed = 1;
            if (!append_recovered_output_log_entry_local(
                    output->path,
                    output->abs_offset,
                    output->reconciled,
                    output->classification)) {
                g_hfsplus_recovered_outputs_log_needs_rewrite = 1;
            }
            if (embedded) {
                (void)append_embedded_context_log_local(output, &embedded_context);
            }
        }
        if (out_changed != NULL) {
            *out_changed = changed;
        }
        return 1;
    }

    copy_text_bounded_local(old_path, sizeof(old_path), output->path);
    if (rename(old_path, new_path) != 0) {
        return 0;
    }

    copy_text_bounded_local(output->path, sizeof(output->path), new_path);
    prune_empty_unidentified_parents_local(old_path);
    if (embedded) {
        set_recovered_output_reconciled_local(output_index, 0);
        set_recovered_output_classification_local(
            output_index,
            HFSPLUS_OUTPUT_CLASS_EMBEDDED);
    } else {
        set_recovered_output_classification_local(
            output_index,
            HFSPLUS_OUTPUT_CLASS_UNCLASSIFIED);
        set_recovered_output_reconciled_local(
            output_index,
            recovered_output_path_defaults_reconciled_local(new_path)
        );
    }
    (void)mft_apply_output_owner_to_path(output->path);
    if (!embedded && created_time > 0) {
        (void)mft_apply_created_time_value_to_path(output->path, created_time);
    }
    if (!append_recovered_output_log_entry_local(
            output->path,
            output->abs_offset,
            output->reconciled,
            output->classification)) {
        g_hfsplus_recovered_outputs_log_needs_rewrite = 1;
    }
    changed = 1;
    moved = 1;
    if (embedded) {
        g_hfsplus_live_embedded_moves++;
        (void)append_embedded_context_log_local(output, &embedded_context);
    } else {
        g_hfsplus_live_renamed_outputs++;
    }

    if (out_changed != NULL) {
        *out_changed = changed;
    }
    if (out_moved != NULL) {
        *out_moved = moved;
    }
    return 1;
}

static size_t reconcile_pending_output_queue_local(
    size_t max_candidates,
    int require_contextual,
    double deadline_seconds,
    int *out_exhausted,
    int *out_any_change,
    size_t *out_next_output_index
)
{
    size_t candidate_count = 0U;
    size_t moved_count = 0U;
    size_t starting_depth = pending_output_queue_depth_local();
    double last_progress_at = 0.0;
    int any_change = 0;

    if (out_exhausted != NULL) {
        *out_exhausted = 1;
    }
    if (out_any_change != NULL) {
        *out_any_change = 0;
    }
    if (out_next_output_index != NULL) {
        *out_next_output_index = 0U;
    }
    if (!hfsplus_metadata_ready_local()) {
        return 0U;
    }

    if (hfsplus_catalog_available_local() && !ensure_lookup_index_current_local()) {
        return 0U;
    }

    while (pending_output_queue_depth_local() > 0U) {
        size_t output_index;
        int changed = 0;
        int moved = 0;

        if (deadline_seconds > 0.0 &&
            monotonic_seconds_local() >= deadline_seconds) {
            if (out_exhausted != NULL) {
                *out_exhausted = 0;
            }
            break;
        }
        if (max_candidates > 0U && candidate_count >= max_candidates) {
            if (out_exhausted != NULL) {
                *out_exhausted = 0;
            }
            break;
        }

        output_index =
            g_hfsplus_pending_output_queue[g_hfsplus_pending_output_queue_head];
        g_hfsplus_pending_output_queue_head++;
        if (g_hfsplus_pending_output_queue_head >=
            g_hfsplus_pending_output_queue_count) {
            g_hfsplus_pending_output_queue_head = 0U;
            g_hfsplus_pending_output_queue_count = 0U;
        } else if (g_hfsplus_pending_output_queue_head >= 64U &&
                   g_hfsplus_pending_output_queue_head * 2U >=
                       g_hfsplus_pending_output_queue_count) {
            compact_pending_output_queue_local();
        }
        if (out_next_output_index != NULL) {
            *out_next_output_index = output_index + 1U;
        }

        if (output_index >= g_hfsplus_recovered_output_count) {
            continue;
        }
        if (output_index < g_hfsplus_pending_output_flags_capacity) {
            g_hfsplus_pending_output_flags[output_index] = 0U;
        }
        if (g_hfsplus_recovered_outputs[output_index].reconciled ||
            g_hfsplus_recovered_outputs[output_index].classification ==
                HFSPLUS_OUTPUT_CLASS_EMBEDDED) {
            continue;
        }

        candidate_count++;
        if (candidate_count == 1U || (candidate_count & 255U) == 0U) {
            double now = monotonic_seconds_local();

            if (last_progress_at <= 0.0 || now - last_progress_at >= 0.5) {
                char activity[96];
                size_t remaining = pending_output_queue_depth_local();

                snprintf(
                    activity,
                    sizeof(activity),
                    "reconciling HFS+ results: %zu/%zu checked, %zu remain",
                    candidate_count,
                    starting_depth,
                    remaining);
                log_set_working_activity(activity);
                last_progress_at = now;
            }
        }
        if (reconcile_recovered_output_at_index_local(
                output_index,
                require_contextual,
                &changed,
                &moved)) {
            if (changed) {
                any_change = 1;
            }
            moved_count += (size_t)moved;
        }
    }

    g_hfsplus_live_reconcile_cursor = pending_output_queue_depth_local();
    if (candidate_count > 0U) {
        char activity[96];

        snprintf(
            activity,
            sizeof(activity),
            "HFS+ reconcile checked %zu results; %zu remain",
            candidate_count,
            pending_output_queue_depth_local());
        log_set_working_activity(activity);
    }
    if (out_any_change != NULL) {
        *out_any_change = any_change;
    }
    return moved_count;
}

static int rewrite_recovered_outputs_log_local(void)
{
    char log_path[HFSPLUS_PATH_MAX];
    FILE *file;
    size_t index;

    if (!build_recovered_outputs_log_path_local(log_path, sizeof(log_path))) {
        return 0;
    }

    file = fopen(log_path, "w");
    if (file == NULL) {
        return 0;
    }
    (void)chmod(log_path, 0644);

    fprintf(file, "offset\tpath\treconciled\tclassification\n");
    for (index = 0U; index < g_hfsplus_recovered_output_count; ++index) {
        if (!append_recovered_output_log_entry_to_stream_local(
                file,
                g_hfsplus_recovered_outputs[index].path,
                g_hfsplus_recovered_outputs[index].abs_offset,
                g_hfsplus_recovered_outputs[index].reconciled,
                g_hfsplus_recovered_outputs[index].classification)) {
            fclose(file);
            return 0;
        }
    }

    if (fclose(file) != 0) {
        return 0;
    }

    g_hfsplus_recovered_outputs_log_needs_rewrite = 0;
    return mft_apply_output_owner_to_path(log_path);
}

static void remember_recovered_output_local(
    const char *path,
    long long abs_offset
)
{
    size_t index;
    double now = monotonic_seconds_local();
    int path_reconciled;

    if (path == NULL || path[0] == '\0' || abs_offset < 0) {
        return;
    }
    path_reconciled = recovered_output_path_defaults_reconciled_local(path) ? 1 : 0;

    index = find_recovered_output_index_local(abs_offset);
    if (index != (size_t)-1) {
        if (g_hfsplus_recovered_outputs[index].classification !=
                HFSPLUS_OUTPUT_CLASS_EMBEDDED ||
            path_is_embedded_context_local(path)) {
            copy_text_bounded_local(
                g_hfsplus_recovered_outputs[index].path,
                sizeof(g_hfsplus_recovered_outputs[index].path),
                path
            );
        }
        set_recovered_output_reconciled_local(index, path_reconciled);
        g_hfsplus_recovered_outputs_log_needs_rewrite = 1;
        if (!path_reconciled &&
            hfsplus_metadata_ready_local() &&
            !hfsplus_should_defer_immediate_reconcile_local(now)) {
            (void)reconcile_recovered_output_at_index_local(index, 1, NULL, NULL);
        }
        if (!g_hfsplus_recovered_outputs[index].reconciled) {
            (void)enqueue_pending_output_local(index);
        }
        return;
    }

    if (!ensure_recovered_output_capacity_local(g_hfsplus_recovered_output_count + 1U) ||
        !ensure_pending_output_flags_capacity_local(g_hfsplus_recovered_output_count + 1U)) {
        return;
    }

    copy_text_bounded_local(
        g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].path,
        sizeof(g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].path),
        path
    );
    g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].abs_offset = abs_offset;
    g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].reconciled = 0;
    g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count].classification =
        HFSPLUS_OUTPUT_CLASS_UNCLASSIFIED;
    g_hfsplus_recovered_output_count++;
    set_recovered_output_reconciled_local(
        g_hfsplus_recovered_output_count - 1U,
        path_reconciled
    );
    app_gui_note_recovery_path(path, abs_offset);
    if (!append_recovered_output_log_entry_local(
            path,
            abs_offset,
            path_reconciled,
            HFSPLUS_OUTPUT_CLASS_UNCLASSIFIED)) {
        g_hfsplus_recovered_outputs_log_needs_rewrite = 1;
    }
    if (!path_reconciled &&
        hfsplus_metadata_ready_local() &&
        !hfsplus_should_defer_immediate_reconcile_local(now)) {
        (void)reconcile_recovered_output_at_index_local(
            g_hfsplus_recovered_output_count - 1U,
            1,
            NULL,
            NULL
        );
    }
    if (!g_hfsplus_recovered_outputs[g_hfsplus_recovered_output_count - 1U].reconciled) {
        (void)enqueue_pending_output_local(g_hfsplus_recovered_output_count - 1U);
    }
}

static const char *entry_extension_local(const HfsPlusCatalogEntry *entry)
{
    return entry != NULL ? path_extension_local(entry->name) : NULL;
}

static int build_contextual_relative_path_for_entry_local(
    const HfsPlusCatalogEntry *entry,
    const char *recovered_extension,
    char *out_relative_path,
    size_t out_size
)
{
    char stem[HFSPLUS_NAME_MAX];
    char parent_path[HFSPLUS_PATH_MAX];
    const char *basename;
    const char *dot;
    const char *entry_extension;
    size_t parent_len;

    if (out_relative_path == NULL || out_size == 0U || entry == NULL ||
        !entry->path_complete || entry->path[0] != '/') {
        return 0;
    }

    {
        uint32_t hardlink_reference = 0U;

        if (path_is_unresolved_hardlink_inode_local(
                entry->path,
                &hardlink_reference)) {
            return build_hardlink_orphan_relative_path_local(
                out_relative_path,
                out_size,
                hardlink_reference,
                recovered_extension);
        }
    }

    if (recovered_extension == NULL || recovered_extension[0] == '\0') {
        return snprintf(out_relative_path, out_size, "%s", entry->path + 1U) < (int)out_size;
    }

    entry_extension = path_extension_local(entry->path);
    if (entry_extension != NULL &&
        extensions_are_same_recovery_family_local(entry_extension, recovered_extension)) {
        return snprintf(out_relative_path, out_size, "%s", entry->path + 1U) < (int)out_size;
    }

    basename = path_basename_local(entry->path);
    if (basename == NULL || basename[0] == '\0') {
        return 0;
    }

    copy_name_without_extension_local(basename, stem, sizeof(stem));
    if (stem[0] == '\0') {
        copy_text_bounded_local(stem, sizeof(stem), basename);
    }

    dot = strrchr(entry->path, '/');
    parent_len = dot != NULL ? (size_t)(dot - entry->path) : 0U;
    if (parent_len >= sizeof(parent_path)) {
        return 0;
    }
    memcpy(parent_path, entry->path, parent_len);
    parent_path[parent_len] = '\0';

    if (parent_path[0] == '\0') {
        return snprintf(
            out_relative_path,
            out_size,
            "%s.%s",
            stem,
            recovered_extension) < (int)out_size;
    }

    return snprintf(
        out_relative_path,
        out_size,
        "%s/%s.%s",
        parent_path + 1U,
        stem,
        recovered_extension) < (int)out_size;
}

static int hfsplus_compact_match_local(
    long long abs_offset,
    MetadataIndexPhysicalMatch *match_out,
    MetadataIndexObject *object_out
)
{
    MetadataIndexPhysicalMatch match;
    size_t match_count = 0U;

    if (abs_offset < 0 || !hfsplus_compact_available_local() ||
        metadata_index_reader_lookup_physical(
            g_hfsplus_compact_reader,
            (uint64_t)abs_offset,
            &match,
            &match_count) != 1 ||
        match_count == 0U) {
        return 0;
    }
    if (object_out != NULL &&
        metadata_index_reader_get_object(
            g_hfsplus_compact_reader,
            match.object_key,
            object_out) != 0) {
        return 0;
    }
    if (match_out != NULL) {
        *match_out = match;
    }
    return 1;
}

static const char *unresolved_audit_reason_text_local(
    HfsPlusUnresolvedAuditReasonLocal reason)
{
    static const char *const labels[HFSPLUS_AUDIT_REASON_COUNT] = {
        "eligible_embedded",
        "output_unavailable",
        "compact_index_unavailable",
        "no_metadata_owner",
        "ambiguous_metadata_owner",
        "exact_catalog_start_unresolved",
        "fork_unavailable",
        "non_data_fork",
        "incomplete_data_fork",
        "crosses_physical_extent",
        "exceeds_logical_fork",
        "owner_path_unavailable"
    };

    return reason >= 0 && reason < HFSPLUS_AUDIT_REASON_COUNT
        ? labels[reason]
        : "unknown";
}

static HfsPlusUnresolvedAuditReasonLocal analyze_unresolved_output_local(
    const HfsPlusRecoveredOutput *output,
    HfsPlusUnresolvedAnalysisLocal *analysis_out)
{
    HfsPlusUnresolvedAnalysisLocal analysis;
    MetadataIndexPhysicalMatch match = {0};
    struct stat st;
    uint64_t absolute_offset;
    int lookup_result;

    memset(&analysis, 0, sizeof(analysis));
    analysis.reason = HFSPLUS_AUDIT_OUTPUT_UNAVAILABLE;
    if (output == NULL || output->abs_offset < 0 ||
        stat(output->path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        goto done;
    }
    analysis.context.output_size = (uint64_t)st.st_size;
    if (!hfsplus_compact_available_local()) {
        analysis.reason = HFSPLUS_AUDIT_COMPACT_INDEX_UNAVAILABLE;
        goto done;
    }
    absolute_offset = (uint64_t)output->abs_offset;
    lookup_result = metadata_index_reader_lookup_physical(
        g_hfsplus_compact_reader,
        absolute_offset,
        &match,
        &analysis.match_count
    );
    if (lookup_result != 1 || analysis.match_count == 0U) {
        analysis.reason = HFSPLUS_AUDIT_NO_METADATA_OWNER;
        goto done;
    }
    analysis.have_match = 1;
    analysis.context.object_key = match.object_key;
    analysis.context.fork_row = match.fork_row;
    analysis.context.logical_position = match.logical_position;
    analysis.context.physical_start = match.physical_start;
    analysis.context.physical_end = match.physical_end;
    if (analysis.match_count != 1U) {
        analysis.reason = HFSPLUS_AUDIT_AMBIGUOUS_METADATA_OWNER;
        goto done;
    }
    if (metadata_index_reader_get_fork_by_row(
            g_hfsplus_compact_reader,
            match.fork_row,
            &analysis.fork) != 0) {
        analysis.reason = HFSPLUS_AUDIT_FORK_UNAVAILABLE;
        goto done;
    }
    analysis.have_fork = 1;
    if (metadata_index_reader_reconstruct_path(
            g_hfsplus_compact_reader,
            match.object_key,
            analysis.context.owner_path,
            sizeof(analysis.context.owner_path)) == 0 &&
        analysis.context.owner_path[0] == '/') {
        analysis.have_owner_path = 1;
    }
    if (match.physical_start == absolute_offset &&
        match.logical_position == 0U) {
        analysis.reason = HFSPLUS_AUDIT_EXACT_CATALOG_START_UNRESOLVED;
        goto done;
    }
    if (analysis.fork.fork_kind != METADATA_INDEX_FORK_DATA) {
        analysis.reason = HFSPLUS_AUDIT_NON_DATA_FORK;
        goto done;
    }
    if ((analysis.fork.flags & METADATA_INDEX_FORK_FLAG_COMPLETE) == 0U) {
        analysis.reason = HFSPLUS_AUDIT_INCOMPLETE_DATA_FORK;
        goto done;
    }
    if ((uint64_t)st.st_size > UINT64_MAX - absolute_offset ||
        absolute_offset + (uint64_t)st.st_size > match.physical_end) {
        analysis.reason = HFSPLUS_AUDIT_CROSSES_PHYSICAL_EXTENT;
        goto done;
    }
    if (match.logical_position > analysis.fork.logical_size ||
        (uint64_t)st.st_size >
            analysis.fork.logical_size - match.logical_position) {
        analysis.reason = HFSPLUS_AUDIT_EXCEEDS_LOGICAL_FORK;
        goto done;
    }
    if (!analysis.have_owner_path) {
        analysis.reason = HFSPLUS_AUDIT_OWNER_PATH_UNAVAILABLE;
        goto done;
    }
    analysis.reason = HFSPLUS_AUDIT_ELIGIBLE_EMBEDDED;

done:
    if (analysis_out != NULL) *analysis_out = analysis;
    return analysis.reason;
}

static int write_unresolved_output_audit_local(void)
{
    uint64_t reason_counts[HFSPLUS_AUDIT_REASON_COUNT] = {0};
    uint64_t triage_high_priority = 0ULL;
    uint64_t triage_likely_customer = 0ULL;
    uint64_t triage_review = 0ULL;
    uint64_t triage_likely_asset = 0ULL;
    uint64_t triage_uninspected = 0ULL;
    char state_dir[HFSPLUS_PATH_MAX];
    char audit_path[HFSPLUS_PATH_MAX];
    char audit_temp_path[HFSPLUS_PATH_MAX + 32U];
    char status_path[HFSPLUS_PATH_MAX];
    char status_temp_path[HFSPLUS_PATH_MAX + 32U];
    FILE *audit_file = NULL;
    FILE *status_file = NULL;
    double started_at = monotonic_seconds_local();
    size_t unresolved_count = 0U;
    size_t audited_count = 0U;
    size_t index;
    int audit_ok = 1;
    int status_ok = 1;

    if (g_hfsplus_output_dir[0] == '\0' ||
        snprintf(
            state_dir,
            sizeof(state_dir),
            "%s/%s",
            g_hfsplus_output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(state_dir) ||
        !ensure_directory_path_local(state_dir) ||
        snprintf(
            audit_path,
            sizeof(audit_path),
            "%s/hfsplus_unresolved_audit.tsv",
            state_dir) >= (int)sizeof(audit_path) ||
        snprintf(
            audit_temp_path,
            sizeof(audit_temp_path),
            "%s.tmp",
            audit_path) >= (int)sizeof(audit_temp_path) ||
        snprintf(
            status_path,
            sizeof(status_path),
            "%s/hfsplus_unresolved_audit_status.txt",
            state_dir) >= (int)sizeof(status_path) ||
        snprintf(
            status_temp_path,
            sizeof(status_temp_path),
            "%s.tmp",
            status_path) >= (int)sizeof(status_temp_path) ||
        !fs_backend_output_path_write_guard_allows(audit_temp_path) ||
        !fs_backend_output_path_write_guard_allows(status_temp_path)) {
        return 0;
    }

    audit_file = fopen(audit_temp_path, "w");
    if (audit_file == NULL) return 0;
    (void)chmod(audit_temp_path, 0644);
    audit_ok = fprintf(
        audit_file,
        "offset\toutput_path\textension\toutput_size\treason\tmatch_count\tobject_key\towner_path\tfork_row\tlogical_position\tphysical_extent_start\tphysical_extent_end\tfork_logical_size\tfork_kind\tfork_flags\ttriage_class\ttriage_score\timage_width\timage_height\thas_exif\thas_jfif\n"
    ) >= 0;

    for (index = 0U;
         audit_ok && index < g_hfsplus_recovered_output_count;
         ++index) {
        const HfsPlusRecoveredOutput *output =
            &g_hfsplus_recovered_outputs[index];
        HfsPlusUnresolvedAnalysisLocal analysis;
        HfsPlusUnresolvedAuditReasonLocal reason;
        ImageTriageResult triage = {0};
        const char *extension;

        if (output->reconciled ||
            output->classification == HFSPLUS_OUTPUT_CLASS_EMBEDDED) {
            continue;
        }
        unresolved_count++;
        reason = analyze_unresolved_output_local(output, &analysis);
        if ((unsigned int)reason < HFSPLUS_AUDIT_REASON_COUNT) {
            reason_counts[reason]++;
        }
        extension = path_extension_local(output->path);
        triage.classification = "uninspected";
        if (analysis.context.output_size > 0U) {
            (void)image_triage_inspect_file(
                output->path,
                extension,
                analysis.context.output_size,
                &triage);
        }
        if (strcmp(triage.classification, "high_priority_photo") == 0) {
            triage_high_priority++;
        } else if (strcmp(
                       triage.classification,
                       "likely_customer_image") == 0) {
            triage_likely_customer++;
        } else if (strcmp(triage.classification, "review_image") == 0) {
            triage_review++;
        } else if (strcmp(
                       triage.classification,
                       "likely_small_asset") == 0) {
            triage_likely_asset++;
        } else {
            triage_uninspected++;
        }
        if (fprintf(audit_file, "%lld\t", output->abs_offset) < 0) {
            audit_ok = 0;
            break;
        }
        write_tsv_text_field_local(audit_file, output->path);
        if (fputc('\t', audit_file) == EOF) {
            audit_ok = 0;
            break;
        }
        write_tsv_text_field_local(
            audit_file,
            extension != NULL ? extension : "");
        if (fprintf(
                audit_file,
                "\t%llu\t%s\t%zu\t%llu\t",
                (unsigned long long)analysis.context.output_size,
                unresolved_audit_reason_text_local(reason),
                analysis.match_count,
                (unsigned long long)(analysis.have_match
                    ? analysis.context.object_key
                    : 0ULL)) < 0) {
            audit_ok = 0;
            break;
        }
        write_tsv_text_field_local(
            audit_file,
            analysis.have_owner_path ? analysis.context.owner_path : "");
        if (fprintf(
                audit_file,
                "\t%u\t%llu\t%llu\t%llu\t%llu\t%u\t%u\t%s\t%d\t%llu\t%llu\t%d\t%d\n",
                analysis.have_match ? analysis.context.fork_row : 0U,
                (unsigned long long)(analysis.have_match
                    ? analysis.context.logical_position
                    : 0ULL),
                (unsigned long long)(analysis.have_match
                    ? analysis.context.physical_start
                    : 0ULL),
                (unsigned long long)(analysis.have_match
                    ? analysis.context.physical_end
                    : 0ULL),
                (unsigned long long)(analysis.have_fork
                    ? analysis.fork.logical_size
                    : 0ULL),
                (unsigned int)(analysis.have_fork
                    ? analysis.fork.fork_kind
                    : 0U),
                (unsigned int)(analysis.have_fork
                    ? analysis.fork.flags
                    : 0U),
                triage.classification,
                triage.score,
                (unsigned long long)triage.width,
                (unsigned long long)triage.height,
                triage.has_exif,
                triage.has_jfif) < 0) {
            audit_ok = 0;
            break;
        }
        audited_count++;
    }
    if (fclose(audit_file) != 0) audit_ok = 0;
    audit_file = NULL;
    if (!audit_ok || rename(audit_temp_path, audit_path) != 0) {
        (void)unlink(audit_temp_path);
        return 0;
    }
    if (!mft_apply_output_owner_to_path(audit_path)) return 0;

    status_file = fopen(status_temp_path, "w");
    if (status_file == NULL) return 0;
    (void)chmod(status_temp_path, 0644);
    status_ok =
        fprintf(status_file, "format_version=2\n") >= 0 &&
        fprintf(status_file, "backend=hfsplus\n") >= 0 &&
        fprintf(status_file, "status=ready\n") >= 0 &&
        fprintf(status_file, "generation=%llu\n",
                (unsigned long long)(hfsplus_compact_available_local()
                    ? metadata_index_reader_generation(g_hfsplus_compact_reader)
                    : 0ULL)) >= 0 &&
        fprintf(status_file, "unresolved_outputs=%zu\n", unresolved_count) >= 0 &&
        fprintf(status_file, "audited_outputs=%zu\n", audited_count) >= 0;
    for (index = 0U;
         status_ok && index < HFSPLUS_AUDIT_REASON_COUNT;
         ++index) {
        status_ok = fprintf(
            status_file,
            "reason_%s=%llu\n",
            unresolved_audit_reason_text_local(
                (HfsPlusUnresolvedAuditReasonLocal)index),
            (unsigned long long)reason_counts[index]) >= 0;
    }
    status_ok = status_ok &&
        fprintf(status_file, "triage_high_priority_photo=%llu\n",
                (unsigned long long)triage_high_priority) >= 0 &&
        fprintf(status_file, "triage_likely_customer_image=%llu\n",
                (unsigned long long)triage_likely_customer) >= 0 &&
        fprintf(status_file, "triage_review_image=%llu\n",
                (unsigned long long)triage_review) >= 0 &&
        fprintf(status_file, "triage_likely_small_asset=%llu\n",
                (unsigned long long)triage_likely_asset) >= 0 &&
        fprintf(status_file, "triage_uninspected=%llu\n",
                (unsigned long long)triage_uninspected) >= 0;
    status_ok = status_ok &&
        fprintf(
            status_file,
            "audit_seconds=%.6f\n",
            monotonic_seconds_local() - started_at) >= 0 &&
        fprintf(
            status_file,
            "generated_at_unix=%llu\n",
            (unsigned long long)time(NULL)) >= 0;
    if (fclose(status_file) != 0) status_ok = 0;
    status_file = NULL;
    if (!status_ok || rename(status_temp_path, status_path) != 0) {
        (void)unlink(status_temp_path);
        return 0;
    }
    if (!mft_apply_output_owner_to_path(status_path)) return 0;

    log_info(
        "HFS+ unresolved-output audit: audited=%zu no_owner=%llu ambiguous=%llu incomplete_fork=%llu cross_extent=%llu exact_start=%llu eligible_but_unmoved=%llu triage(high=%llu likely=%llu review=%llu asset=%llu) time=%.2fs",
        audited_count,
        (unsigned long long)reason_counts[HFSPLUS_AUDIT_NO_METADATA_OWNER],
        (unsigned long long)reason_counts[HFSPLUS_AUDIT_AMBIGUOUS_METADATA_OWNER],
        (unsigned long long)reason_counts[HFSPLUS_AUDIT_INCOMPLETE_DATA_FORK],
        (unsigned long long)reason_counts[HFSPLUS_AUDIT_CROSSES_PHYSICAL_EXTENT],
        (unsigned long long)reason_counts[HFSPLUS_AUDIT_EXACT_CATALOG_START_UNRESOLVED],
        (unsigned long long)reason_counts[HFSPLUS_AUDIT_ELIGIBLE_EMBEDDED],
        (unsigned long long)triage_high_priority,
        (unsigned long long)triage_likely_customer,
        (unsigned long long)triage_review,
        (unsigned long long)triage_likely_asset,
        monotonic_seconds_local() - started_at
    );
    return 1;
}

static int build_embedded_output_path_local(
    char *out_path,
    size_t out_size,
    const HfsPlusRecoveredOutput *output,
    const char *extension,
    HfsPlusEmbeddedContextLocal *context_out)
{
    HfsPlusUnresolvedAnalysisLocal analysis;
    char relative[HFSPLUS_PATH_MAX];
    const char *owner_relative;
    uint64_t absolute_offset;

    if (out_path == NULL || out_size == 0U || output == NULL ||
        output->abs_offset < 0 || extension == NULL || extension[0] == '\0' ||
        analyze_unresolved_output_local(output, &analysis) !=
            HFSPLUS_AUDIT_ELIGIBLE_EMBEDDED) {
        return 0;
    }
    absolute_offset = (uint64_t)output->abs_offset;
    owner_relative = analysis.context.owner_path + 1U;
    if (snprintf(
            relative,
            sizeof(relative),
            "%s/Embedded/%s.embedded-assets/logical_%llu_abs_%llu.%s",
            APP_UNIDENT_DIR_NAME,
            owner_relative[0] != '\0' ? owner_relative : "root",
            (unsigned long long)analysis.context.logical_position,
            (unsigned long long)absolute_offset,
            extension) >= (int)sizeof(relative)) {
        if (snprintf(
                relative,
                sizeof(relative),
                "%s/Embedded/_LongPaths/object_%llu/logical_%llu_abs_%llu.%s",
                APP_UNIDENT_DIR_NAME,
                (unsigned long long)analysis.context.object_key,
                (unsigned long long)analysis.context.logical_position,
                (unsigned long long)absolute_offset,
                extension) >= (int)sizeof(relative)) {
            return 0;
        }
    }
    if (!build_unique_contextual_output_path_local(
            out_path,
            out_size,
            relative,
            output->path)) {
        return 0;
    }
    if (context_out != NULL) *context_out = analysis.context;
    return 1;
}

static int build_recovered_output_path_internal_local(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension,
    const char *current_path,
    int *out_contextual,
    time_t *out_created_time
)
{
    HfsPlusCatalogEntry *entry;
    HfsPlusCatalogEntry compact_entry;
    char resolved_default_directory[HFSPLUS_PATH_MAX];

    if (out_contextual != NULL) {
        *out_contextual = 0;
    }
    if (out_created_time != NULL) {
        *out_created_time = (time_t)0;
    }

    if (out_path == NULL || out_size == 0U ||
        default_directory == NULL || default_prefix == NULL || extension == NULL) {
        return 0;
    }

    if (strcmp(default_directory, APP_DEFAULT_UNIDENT_DIR) == 0) {
        if (!mft_build_unident_typed_bucket_dir(
                resolved_default_directory,
                sizeof(resolved_default_directory),
                extension)) {
            return 0;
        }
    } else {
        snprintf(
            resolved_default_directory,
            sizeof(resolved_default_directory),
            "%s",
            default_directory
        );
    }

    entry = find_best_entry_for_data_offset_local(abs_offset);
    if (entry == NULL && hfsplus_compact_available_local()) {
        MetadataIndexPhysicalMatch match;
        MetadataIndexObject object;

        memset(&compact_entry, 0, sizeof(compact_entry));
        if (hfsplus_compact_match_local(abs_offset, &match, &object) &&
            match.physical_start == (uint64_t)abs_offset &&
            match.logical_position == 0U &&
            metadata_index_reader_reconstruct_path(
                g_hfsplus_compact_reader,
                match.object_key,
                compact_entry.path,
                sizeof(compact_entry.path)) == 0) {
            const char *basename = path_basename_local(compact_entry.path);

            compact_entry.file_id = match.object_key <= UINT32_MAX
                ? (uint32_t)match.object_key
                : 0U;
            compact_entry.abs_offset = match.physical_start;
            compact_entry.has_data = 1;
            compact_entry.path_complete = 1;
            compact_entry.created_unix = object.create_time == METADATA_INDEX_TIME_UNKNOWN
                ? (time_t)0
                : (time_t)object.create_time;
            if (basename != NULL && basename[0] != '\0') {
                copy_text_bounded_local(
                    compact_entry.name,
                    sizeof(compact_entry.name),
                    basename);
                compact_entry.has_name = 1;
            }
            entry = &compact_entry;
        }
    }
    if (out_created_time != NULL && entry != NULL) {
        *out_created_time = entry->created_unix;
    }

    if (entry != NULL &&
        entry->has_name &&
        entry->has_data &&
        entry->abs_offset == (uint64_t)abs_offset &&
        entry->path_complete) {
        char contextual_relative[HFSPLUS_PATH_MAX];

        if (build_contextual_relative_path_for_entry_local(
                entry,
                extension,
                contextual_relative,
                sizeof(contextual_relative)) &&
            build_unique_contextual_output_path_local(
                out_path,
                out_size,
                contextual_relative,
                current_path)) {
            if (out_contextual != NULL) {
                *out_contextual = 1;
            }
            return 1;
        }
    }

    if (entry != NULL &&
        entry->has_name &&
        entry->abs_offset == (uint64_t)abs_offset) {
        const char *name_extension = entry_extension_local(entry);
        int exact_family =
            name_extension != NULL &&
            extensions_are_same_recovery_family_local(name_extension, extension);

        if (build_unique_flat_name_output_path_local(
                out_path,
                out_size,
                resolved_default_directory,
                entry->name,
                extension,
                exact_family ? 0 : 1,
                current_path)) {
            if (out_contextual != NULL) {
                *out_contextual = 1;
            }
            return 1;
        }
    }

    return build_unique_default_output_path_local(
        out_path,
        out_size,
        resolved_default_directory,
        default_prefix,
        abs_offset,
        extension,
        current_path
    );
}

static int hfsplus_catalog_available_local(void)
{
    return g_hfsplus_catalog_loaded && g_hfsplus_entry_count > 0U;
}

static int hfsplus_compact_available_local(void)
{
    return g_hfsplus_compact_reader != NULL &&
           g_hfsplus_compact_stats.object_count > 0U;
}

static int hfsplus_legacy_zero_source_identity_matches_local(
    const MetadataIndexVolumeIdentity *stored,
    const MetadataIndexVolumeIdentity *expected)
{
    uint64_t required_size;

    if (stored == NULL || expected == NULL || stored->source_size != 0U ||
        expected->source_size == 0U ||
        expected->volume_offset > UINT64_MAX - expected->volume_size) return 0;
    required_size = expected->volume_offset + expected->volume_size;
    return expected->source_size >= required_size &&
           stored->backend_kind == expected->backend_kind &&
           stored->block_size == expected->block_size &&
           stored->container_offset == expected->container_offset &&
           stored->volume_offset == expected->volume_offset &&
           stored->volume_size == expected->volume_size &&
           stored->identity_primary == expected->identity_primary &&
           stored->identity_secondary == expected->identity_secondary &&
           memcmp(stored->uuid, expected->uuid, sizeof(stored->uuid)) == 0;
}

static int hfsplus_open_compact_index_local(void)
{
    char index_dir[HFSPLUS_PATH_MAX];
    MetadataIndexVolumeIdentity identity;
    MetadataIndexReader *reader = NULL;
    MetadataIndexStats stats = {0};
    int legacy_zero_source_size = 0;

    if (g_hfsplus_output_dir[0] == '\0' ||
        snprintf(index_dir, sizeof(index_dir), "%s/%s/metadata/index",
                 g_hfsplus_output_dir, APP_STATE_DIR_NAME) >= (int)sizeof(index_dir)) {
        return 0;
    }
    hfsplus_shadow_identity_local(&identity);
    if (metadata_index_reader_open_expected(index_dir, &identity, &reader) != 0) {
        const MetadataIndexVolumeIdentity *stored_identity;

        if (metadata_index_reader_open(index_dir, &reader) != 0) return 0;
        stored_identity = metadata_index_reader_volume(reader);
        if (!hfsplus_legacy_zero_source_identity_matches_local(
                stored_identity, &identity)) {
            metadata_index_reader_close(reader);
            return 0;
        }
        legacy_zero_source_size = 1;
    }
    metadata_index_reader_get_stats(reader, &stats);
    if (stats.object_count == 0U || stats.link_count == 0U) {
        metadata_index_reader_close(reader);
        return 0;
    }
    close_compact_metadata_local();
    g_hfsplus_compact_reader = reader;
    g_hfsplus_compact_stats = stats;
    g_hfsplus_shadow_index_ready = 1;
    if (legacy_zero_source_size) {
        log_info(
            "HFS+ compact index reused through legacy source-size compatibility: saved_size=0 detected_size=%llu; all volume identity fields matched",
            (unsigned long long)identity.source_size
        );
    }
    return 1;
}

static void hfsplus_release_rich_catalog_after_export_local(void)
{
    PlatformMemoryUsage before = {0};
    PlatformMemoryUsage after = {0};
    size_t released_entries;

    if (!g_hfsplus_prefer_compact_metadata || !hfsplus_compact_available_local() ||
        !hfsplus_catalog_available_local()) return;
    released_entries = g_hfsplus_entry_count;
    (void)platform_get_process_memory_usage(&before);
    free_catalog_metadata_local();
    g_hfsplus_compact_only = 1;
    (void)platform_get_process_memory_usage(&after);
    log_info(
        "HFS+ released rich Catalog model after verified compact export: entries=%zu rss_before=%.2f MiB rss_after=%.2f MiB",
        released_entries,
        before.has_resident ? (double)before.resident_bytes / (1024.0 * 1024.0) : 0.0,
        after.has_resident ? (double)after.resident_bytes / (1024.0 * 1024.0) : 0.0
    );
}

void hfsplus_backend_reset(void)
{
    hfsplus_release_recovery_lock_local();
    hfsplus_reset_globals_local();
}

static int configure_from_source_internal_local(
    const char *input_path,
    int allow_snapshot,
    int preserve_recovery_state
)
{
    FILE *input_file = NULL;
    HfsPlusBackendGeometry geometry = {0};
    HfsPlusForkDataLocal catalog_fork = {0};
    uint64_t source_size = 0U;
    double configure_started_at = monotonic_seconds_local();
    double phase_started_at = configure_started_at;
    double probe_seconds = 0.0;
    double snapshot_seconds = 0.0;
    double overflow_seconds = 0.0;
    double catalog_seconds = 0.0;
    int ok = 0;

    if (input_path == NULL || input_path[0] == '\0') {
        return 0;
    }

    if (g_hfsplus_source_path[0] != '\0' &&
        strcmp(g_hfsplus_source_path, input_path) == 0 &&
        hfsplus_metadata_ready_local()) {
        (void)hfsplus_ensure_shadow_index_local();
        return 1;
    }

    if (preserve_recovery_state) {
        hfsplus_reset_metadata_local();
    } else {
        hfsplus_reset_globals_local();
    }
    (void)detect_source_size_local(input_path, &source_size);
    input_file = fopen(input_path, "rb");
    if (input_file == NULL) {
        return 0;
    }

    if (try_probe_candidate_offset_local(
            input_file,
            source_size,
            0U,
            &geometry,
            &catalog_fork)) {
        ok = 1;
        log_info(
            "Detected %s source volume at offset %llu%s",
            geometry.is_hfsx ? "HFSX" : "HFS+",
            (unsigned long long)geometry.volume_offset,
            geometry.has_wrapper ? " (embedded in HFS wrapper)" : ""
        );
    } else if (find_gpt_hfsplus_volume_local(
                   input_file,
                   source_size,
                   &geometry,
                   &catalog_fork)) {
        ok = 1;
        log_info(
            "Detected GPT %s partition at offset %llu",
            geometry.is_hfsx ? "HFSX" : "HFS+",
            (unsigned long long)geometry.container_offset
        );
    } else if (find_mbr_hfsplus_volume_local(
                   input_file,
                   source_size,
                   &geometry,
                   &catalog_fork)) {
        ok = 1;
        log_info(
            "Detected MBR %s partition at offset %llu",
            geometry.is_hfsx ? "HFSX" : "HFS+",
            (unsigned long long)geometry.container_offset
        );
    }
    probe_seconds = monotonic_seconds_local() - phase_started_at;

    if (!ok) {
        fclose(input_file);
        return 0;
    }

    g_hfsplus_geometry = geometry;
    g_hfsplus_catalog_fork = catalog_fork;
    snprintf(
        g_hfsplus_source_hint,
        sizeof(g_hfsplus_source_hint),
        "%s",
        geometry.is_hfsx ? "HFSX" : "HFS+"
    );
    snprintf(g_hfsplus_source_path, sizeof(g_hfsplus_source_path), "%s", input_path);
    if (hfsplus_geometry_is_truncated_local(&geometry)) {
        uint64_t readable_bytes =
            geometry.source_size > geometry.volume_offset
                ? (geometry.source_size - geometry.volume_offset)
                : 0U;
        uint64_t missing_bytes =
            geometry.volume_size > readable_bytes
                ? (geometry.volume_size - readable_bytes)
                : 0U;

        log_info(
            "HFS+ source image is shorter than the declared volume size; continuing in best-effort mode with %.2f GiB readable and %.2f GiB missing",
            (double)readable_bytes / (1024.0 * 1024.0 * 1024.0),
            (double)missing_bytes / (1024.0 * 1024.0 * 1024.0)
        );
    }

    phase_started_at = monotonic_seconds_local();
    if (allow_snapshot && g_hfsplus_prefer_compact_metadata &&
        hfsplus_open_compact_index_local()) {
        snapshot_seconds = monotonic_seconds_local() - phase_started_at;
        if (!load_orphan_catalog_artifact_local(input_file) &&
            !scan_catalog_orphans_only_local(input_file)) {
            log_info(
                "HFS+ orphan Catalog archaeology was unavailable on this warm start; live compact metadata remains usable"
            );
        }
        free_catalog_metadata_local();
        g_hfsplus_compact_only = 1;
        fclose(input_file);
        log_info(
            "HFS+ compact-only warm start: generation=%llu objects=%llu forks=%llu extents=%llu; rich Catalog snapshot was not inflated",
            (unsigned long long)metadata_index_reader_generation(
                g_hfsplus_compact_reader),
            (unsigned long long)g_hfsplus_compact_stats.object_count,
            (unsigned long long)g_hfsplus_compact_stats.fork_count,
            (unsigned long long)g_hfsplus_compact_stats.extent_count
        );
        log_info(
            "HFS+ configure timings: probe=%.2fs compact=%.2fs snapshot=0.00s overflow=0.00s catalog=0.00s total=%.2fs entries=%llu overflow_records=0",
            probe_seconds,
            snapshot_seconds,
            monotonic_seconds_local() - configure_started_at,
            (unsigned long long)g_hfsplus_compact_stats.object_count
        );
        return 1;
    }

    phase_started_at = monotonic_seconds_local();
    if (allow_snapshot && load_metadata_snapshot_local(&geometry)) {
        snapshot_seconds = monotonic_seconds_local() - phase_started_at;
        if (!load_orphan_catalog_artifact_local(input_file) &&
            !scan_catalog_orphans_only_local(input_file)) {
            log_info(
                "HFS+ orphan Catalog archaeology was unavailable while reusing the rich metadata snapshot"
            );
        }
        fclose(input_file);
        log_info(
            "Loaded %zu HFS+ catalog entr%s from saved metadata snapshot",
            g_hfsplus_entry_count,
            g_hfsplus_entry_count == 1U ? "y" : "ies"
        );
        write_photos_library_signal_local();
        (void)hfsplus_ensure_shadow_index_local();
        log_info(
            "HFS+ configure timings: probe=%.2fs snapshot=%.2fs overflow=0.00fs catalog=0.00fs total=%.2fs entries=%zu overflow_records=0",
            probe_seconds,
            snapshot_seconds,
            monotonic_seconds_local() - configure_started_at,
            g_hfsplus_entry_count
        );
        hfsplus_release_rich_catalog_after_export_local();
        return 1;
    }
    snapshot_seconds = monotonic_seconds_local() - phase_started_at;

    phase_started_at = monotonic_seconds_local();
    if (load_extents_overflow_records_local(input_file)) {
        log_info(
            "Loaded %zu HFS+ extents-overflow record%s",
            g_hfsplus_overflow_record_count,
            g_hfsplus_overflow_record_count == 1U ? "" : "s"
        );
    } else {
        log_info(
            "HFS+ extents-overflow tree was not usable on this source; continuing with inline extents only"
        );
    }
    overflow_seconds = monotonic_seconds_local() - phase_started_at;

    phase_started_at = monotonic_seconds_local();
    if (parse_catalog_entries_local(input_file)) {
        g_hfsplus_catalog_loaded = 1;
        log_info(
            "Loaded %zu HFS+ catalog entries for naming/path reconstruction%s",
            g_hfsplus_entry_count,
            g_hfsplus_catalog_resolved_fork.overflow_used
                ? " (catalog fork used extents-overflow)"
                : ""
        );
    } else {
        log_info(
            "HFS+ volume detected, but catalog parsing is not complete enough for path reconstruction on this source yet"
        );
    }
    catalog_seconds = monotonic_seconds_local() - phase_started_at;

    fclose(input_file);
    if (g_hfsplus_catalog_loaded && !save_metadata_snapshot_local()) {
        log_info(
            "HFS+ metadata snapshot could not be saved; future resumes may need to rebuild catalog metadata from the source"
        );
    }
    write_photos_library_signal_local();
    (void)hfsplus_ensure_shadow_index_local();
    log_info(
        "HFS+ configure timings: probe=%.2fs snapshot=%.2fs overflow=%.2fs catalog=%.2fs total=%.2fs entries=%zu overflow_records=%zu",
        probe_seconds,
        snapshot_seconds,
        overflow_seconds,
        catalog_seconds,
        monotonic_seconds_local() - configure_started_at,
        g_hfsplus_entry_count,
        g_hfsplus_overflow_record_count
    );
    hfsplus_release_rich_catalog_after_export_local();
    return 1;
}

int hfsplus_backend_configure_from_source(const char *input_path)
{
    return configure_from_source_internal_local(input_path, 1, 0);
}

int hfsplus_backend_has_geometry(void)
{
    return g_hfsplus_geometry.block_size != 0U;
}

const char *hfsplus_backend_source_hint(void)
{
    return g_hfsplus_source_hint;
}

const HfsPlusBackendGeometry *hfsplus_backend_current_geometry(void)
{
    return hfsplus_backend_has_geometry() ? &g_hfsplus_geometry : NULL;
}

int hfsplus_backend_should_attempt_metadata_acquisition(int phase)
{
    (void)phase;

    return g_hfsplus_source_path[0] != '\0' && !hfsplus_metadata_ready_local();
}

int hfsplus_backend_run_metadata_acquisition(int phase)
{
    const char *phase_label = "metadata revisit";
    int allow_snapshot = 1;
    int configured_ok;

    switch (phase) {
        case 1:
            phase_label = "pre-deferred revisit";
            allow_snapshot = 1;
            break;
        case 2:
            phase_label = "post-deferred revisit";
            allow_snapshot = 0;
            break;
        default:
            phase_label = "metadata revisit";
            allow_snapshot = 1;
            break;
    }

    if (g_hfsplus_source_path[0] == '\0') {
        log_info(
            "HFS+ %s skipped; no saved source path is available for metadata reacquisition",
            phase_label
        );
        return 1;
    }
    if (hfsplus_metadata_ready_local()) {
        log_info(
            "HFS+ %s skipped; volume header and catalog metadata are already attached",
            phase_label
        );
        return 1;
    }

    log_info(
        "HFS+ %s: revisiting volume header, catalog, and extents-overflow metadata%s",
        phase_label,
        allow_snapshot ? "" : " with a source-only rebuild"
    );
    configured_ok = configure_from_source_internal_local(
        g_hfsplus_source_path,
        allow_snapshot,
        1
    );
    if (!configured_ok) {
        log_info(
            "HFS+ %s could not reopen enough metadata from the source right now",
            phase_label
        );
        return 0;
    }

    if (g_hfsplus_recovered_output_count > 0U) {
        enqueue_all_unreconciled_outputs_local();
        if (hfsplus_catalog_available_local() &&
            pending_output_queue_depth_local() > 0U) {
            (void)reconcile_pending_output_queue_local(
                pending_output_queue_depth_local(),
                0,
                0.0,
                NULL,
                NULL,
                NULL
            );
            g_hfsplus_live_reconcile_cursor = pending_output_queue_depth_local();
        }
    }

    if (hfsplus_metadata_ready_local()) {
        log_info(
            "HFS+ %s attached usable volume-header and catalog metadata",
            phase_label
        );
    } else {
        log_info(
            "HFS+ %s still did not recover enough catalog metadata for strong naming",
            phase_label
        );
    }

    return 1;
}

int hfsplus_backend_supports_root_folder_preview(void)
{
    return hfsplus_catalog_available_local();
}

static int list_child_folder_names_by_parent_id_local(
    uint32_t parent_id,
    int hide_internal_root_names,
    FILE *out_stream
)
{
    char **names = NULL;
    size_t name_count = 0U;
    size_t i;
    int case_sensitive = g_hfsplus_sort_case_sensitive;

    if (out_stream == NULL) {
        out_stream = stdout;
    }

    for (i = 0U; i < g_hfsplus_entry_count; ++i) {
        HfsPlusCatalogEntry *entry = &g_hfsplus_entries[i];
        char **expanded;
        size_t j;
        int duplicate = 0;

        if (!entry->is_directory ||
            entry->is_hardlink_metadata_directory ||
            !entry->has_name ||
            entry->parent_id != parent_id ||
            entry->name[0] == '\0' ||
            (hide_internal_root_names &&
             is_internal_hfsplus_root_name_local(entry->name))) {
            continue;
        }

        for (j = 0U; j < name_count; ++j) {
            if (hfsplus_names_equal_local(names[j], entry->name, case_sensitive)) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate) {
            continue;
        }

        expanded = (char **)realloc(names, (name_count + 1U) * sizeof(*expanded));
        if (expanded == NULL) {
            break;
        }
        names = expanded;
        names[name_count] = strdup(entry->name);
        if (names[name_count] == NULL) {
            break;
        }
        ++name_count;
    }

    if (name_count > 1U) {
        g_hfsplus_sort_case_sensitive = case_sensitive;
        qsort(names, name_count, sizeof(*names), hfsplus_name_compare_local);
    }
    for (i = 0U; i < name_count; ++i) {
        fprintf(out_stream, "%s\n", names[i]);
        free(names[i]);
    }
    free(names);
    return 1;
}

static int normalize_catalog_folder_path_local(
    const char *path,
    char *out_path,
    size_t out_path_size
)
{
    size_t length;

    if (out_path == NULL || out_path_size < 2U || path == NULL) {
        return 0;
    }

    length = strlen(path);
    while (length > 1U && path[length - 1U] == '/') {
        --length;
    }

    if (length == 0U) {
        out_path[0] = '/';
        out_path[1] = '\0';
        return 1;
    }
    if (path[0] == '/') {
        if (length >= out_path_size) {
            return 0;
        }
        memcpy(out_path, path, length);
        out_path[length] = '\0';
        return 1;
    }
    if (length + 1U >= out_path_size) {
        return 0;
    }
    out_path[0] = '/';
    memcpy(out_path + 1U, path, length);
    out_path[length + 1U] = '\0';
    return 1;
}

static int find_directory_id_by_path_local(
    const char *path,
    uint32_t *out_directory_id
)
{
    size_t i;

    if (out_directory_id != NULL) {
        *out_directory_id = 0U;
    }
    if (path == NULL || out_directory_id == NULL) {
        return 0;
    }
    if (strcmp(path, "/") == 0) {
        *out_directory_id = HFSPLUS_ROOT_FOLDER_ID;
        return 1;
    }

    for (i = 0U; i < g_hfsplus_entry_count; ++i) {
        const HfsPlusCatalogEntry *entry = &g_hfsplus_entries[i];

        if (entry->is_directory &&
            entry->path_complete &&
            entry->path[0] != '\0' &&
            hfsplus_names_equal_local(
                entry->path,
                path,
                g_hfsplus_sort_case_sensitive)) {
            *out_directory_id = entry->file_id;
            return 1;
        }
    }

    return 0;
}

int hfsplus_backend_list_root_folders(const char *input_path, FILE *out_stream)
{
    if (!hfsplus_catalog_available_local() &&
        (!hfsplus_backend_configure_from_source(input_path) ||
         !hfsplus_catalog_available_local())) {
        log_error("HFS+ root-folder preview is unavailable for this source");
        return 0;
    }

    return list_child_folder_names_by_parent_id_local(
        HFSPLUS_ROOT_FOLDER_ID,
        1,
        out_stream
    );
}

int hfsplus_backend_list_child_folders(
    const char *input_path,
    const char *parent_path,
    FILE *out_stream
)
{
    char normalized_path[HFSPLUS_PATH_MAX];
    uint32_t parent_id = 0U;

    if (!hfsplus_catalog_available_local() &&
        (!hfsplus_backend_configure_from_source(input_path) ||
         !hfsplus_catalog_available_local())) {
        log_error("HFS+ child-folder preview is unavailable for this source");
        return 0;
    }
    if (!normalize_catalog_folder_path_local(
            parent_path,
            normalized_path,
            sizeof(normalized_path)) ||
        !find_directory_id_by_path_local(normalized_path, &parent_id)) {
        log_error(
            "HFS+ child-folder preview could not resolve parent path: %s",
            parent_path != NULL ? parent_path : "(null)"
        );
        return 0;
    }

    return list_child_folder_names_by_parent_id_local(
        parent_id,
        parent_id == HFSPLUS_ROOT_FOLDER_ID,
        out_stream
    );
}

static int catalog_path_has_prefix_local(
    const char *path,
    const char *prefix,
    size_t prefix_length
)
{
    if (g_hfsplus_sort_case_sensitive) {
        return strncmp(path, prefix, prefix_length) == 0;
    }
    return strncasecmp(path, prefix, prefix_length) == 0;
}

static int catalog_path_matches_scope_local(
    const char *path,
    const char *root_scope_csv
)
{
    size_t scope_offset = 0U;

    if (path == NULL || path[0] != '/') {
        return 0;
    }
    if (root_scope_csv == NULL || root_scope_csv[0] == '\0') {
        return 1;
    }

    while (1) {
        char token[HFSPLUS_PATH_MAX];
        char normalized[HFSPLUS_PATH_MAX];
        const char *token_start;
        size_t token_length;
        size_t normalized_length;
        int token_status = config_scope_next_item(
            root_scope_csv,
            &scope_offset,
            token,
            sizeof(token)
        );

        if (token_status == 0) {
            break;
        }
        if (token_status < 0) {
            log_error("Invalid or overlong encoded folder scope");
            return 0;
        }
        token_start = token;
        token_length = strlen(token_start);
        while (token_length > 1U && token_start[token_length - 1U] == '/') {
            --token_length;
        }

        if (token_length == 0U ||
            (token_length == 1U && token_start[0] == '/')) {
            return 1;
        }
        if (token_start[0] == '/') {
            if (token_length >= sizeof(normalized)) {
                return 0;
            }
            memcpy(normalized, token_start, token_length);
            normalized[token_length] = '\0';
        } else {
            if (token_length + 1U >= sizeof(normalized)) {
                return 0;
            }
            normalized[0] = '/';
            memcpy(normalized + 1U, token_start, token_length);
            normalized[token_length + 1U] = '\0';
        }

        normalized_length = strlen(normalized);
        if (catalog_path_has_prefix_local(path, normalized, normalized_length) &&
            (path[normalized_length] == '\0' || path[normalized_length] == '/')) {
            return 1;
        }
    }

    return 0;
}

static int append_ddrescue_domain_range_local(
    HfsPlusDomainRangeLocal **ranges,
    size_t *range_count,
    size_t *range_capacity,
    uint64_t start,
    uint64_t length
)
{
    HfsPlusDomainRangeLocal *expanded;

    if (ranges == NULL ||
        range_count == NULL ||
        range_capacity == NULL ||
        length == 0U ||
        start > UINT64_MAX - length) {
        return 0;
    }
    if (*range_count >= *range_capacity) {
        size_t new_capacity = *range_capacity == 0U ? 256U : *range_capacity * 2U;

        if (new_capacity <= *range_capacity) {
            return 0;
        }
        expanded = (HfsPlusDomainRangeLocal *)realloc(
            *ranges,
            new_capacity * sizeof(*expanded)
        );
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

static int append_ddrescue_domain_run_local(
    HfsPlusDomainRangeLocal **ranges,
    size_t *range_count,
    size_t *range_capacity,
    const MftViewRun *run
)
{
    if (run == NULL ||
        run->byte_length == 0U) {
        return 1;
    }
    return append_ddrescue_domain_range_local(
        ranges,
        range_count,
        range_capacity,
        (uint64_t)run->abs_offset,
        run->byte_length
    );
}

static int compare_domain_ranges_local(const void *a, const void *b)
{
    const HfsPlusDomainRangeLocal *left = (const HfsPlusDomainRangeLocal *)a;
    const HfsPlusDomainRangeLocal *right = (const HfsPlusDomainRangeLocal *)b;

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

static size_t merge_domain_ranges_local(
    HfsPlusDomainRangeLocal *ranges,
    size_t range_count,
    uint64_t max_gap_bytes
)
{
    size_t write_index = 0U;
    size_t read_index;

    if (ranges == NULL || range_count == 0U) {
        return 0U;
    }
    qsort(ranges, range_count, sizeof(*ranges), compare_domain_ranges_local);
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

static int write_ddrescue_domain_map_local(
    const char *domain_map_path,
    HfsPlusDomainRangeLocal *ranges,
    size_t range_count,
    uint64_t *out_total_bytes
)
{
    FILE *file;
    size_t i;
    uint64_t total_bytes = 0ULL;

    if (out_total_bytes != NULL) {
        *out_total_bytes = 0ULL;
    }
    if (domain_map_path == NULL ||
        domain_map_path[0] == '\0' ||
        ranges == NULL ||
        range_count == 0U ||
        !ensure_parent_dirs_for_path_local(domain_map_path)) {
        return 0;
    }

    file = fopen(domain_map_path, "wb");
    if (file == NULL) {
        return 0;
    }
    fprintf(file, "# Mapfile. Created by Carv HFS+ selected-folder domain.\n");
    fprintf(file, "# current_pos  current_status  current_pass\n");
    fprintf(file, "0x%08llX     +               1\n", 0ULL);
    fprintf(file, "#      pos        size  status\n");
    for (i = 0U; i < range_count; ++i) {
        uint64_t length;

        if (ranges[i].start >= ranges[i].end) {
            continue;
        }
        length = ranges[i].end - ranges[i].start;
        total_bytes += length;
        fprintf(
            file,
            "0x%llX  0x%llX  +\n",
            (unsigned long long)ranges[i].start,
            (unsigned long long)length
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

int hfsplus_backend_write_selected_tree_ddrescue_domain(
    const char *input_path,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
)
{
    HfsPlusDomainRangeLocal *ranges = NULL;
    size_t range_count = 0U;
    size_t range_capacity = 0U;
    size_t merged_count;
    size_t i;
    uint64_t total_bytes = 0ULL;
    int ok = 0;

    if (out_range_count != NULL) {
        *out_range_count = 0ULL;
    }
    if (out_total_bytes != NULL) {
        *out_total_bytes = 0ULL;
    }
    if (input_path == NULL ||
        input_path[0] == '\0' ||
        root_scope_csv == NULL ||
        root_scope_csv[0] == '\0' ||
        domain_map_path == NULL ||
        domain_map_path[0] == '\0' ||
        !hfsplus_backend_configure_from_source(input_path) ||
        !g_hfsplus_catalog_loaded ||
        g_hfsplus_entry_count == 0U) {
        return 0;
    }

    /* Keep the generated sparse image self-describing enough for a later
     * HFS+ metadata pass: container/GPT front matter, volume header vicinity,
     * Catalog, Extents Overflow, and then selected data forks.
     */
    {
        uint64_t source_front_length = g_hfsplus_geometry.source_size <
            (16ULL * 1024ULL * 1024ULL)
                ? g_hfsplus_geometry.source_size
                : (16ULL * 1024ULL * 1024ULL);
        uint64_t volume_front_length = 0ULL;

        if (g_hfsplus_geometry.source_size > g_hfsplus_geometry.volume_offset) {
            uint64_t available = g_hfsplus_geometry.source_size -
                g_hfsplus_geometry.volume_offset;
            volume_front_length = available < (2ULL * 1024ULL * 1024ULL)
                ? available
                : (2ULL * 1024ULL * 1024ULL);
        }
        if (source_front_length > 0ULL &&
            !append_ddrescue_domain_range_local(
                &ranges,
                &range_count,
                &range_capacity,
                0ULL,
                source_front_length)) {
            goto done;
        }
        if (volume_front_length > 0ULL &&
            !append_ddrescue_domain_range_local(
                &ranges,
                &range_count,
                &range_capacity,
                g_hfsplus_geometry.volume_offset,
                volume_front_length)) {
            goto done;
        }
    }
    for (i = 0U; i < g_hfsplus_catalog_resolved_fork.extent_count; ++i) {
        const HfsPlusExtentDescriptorLocal *extent = &g_hfsplus_catalog_resolved_fork.extents[i];
        uint64_t start = g_hfsplus_geometry.volume_offset +
            ((uint64_t)extent->start_block * (uint64_t)g_hfsplus_geometry.block_size);
        uint64_t length = (uint64_t)extent->block_count *
            (uint64_t)g_hfsplus_geometry.block_size;

        if (!append_ddrescue_domain_range_local(
                &ranges,
                &range_count,
                &range_capacity,
                start,
                length)) {
            goto done;
        }
    }
    for (i = 0U; i < HFSPLUS_EXTENT_COUNT; ++i) {
        const HfsPlusExtentDescriptorLocal *extent = &g_hfsplus_extents_fork.extents[i];
        uint64_t start;
        uint64_t length;

        if (extent->block_count == 0U) {
            continue;
        }
        start = g_hfsplus_geometry.volume_offset +
            ((uint64_t)extent->start_block * (uint64_t)g_hfsplus_geometry.block_size);
        length = (uint64_t)extent->block_count * (uint64_t)g_hfsplus_geometry.block_size;
        if (!append_ddrescue_domain_range_local(
                &ranges,
                &range_count,
                &range_capacity,
                start,
                length)) {
            goto done;
        }
    }

    for (i = 0U; i < g_hfsplus_entry_count; ++i) {
        const HfsPlusCatalogEntry *entry = &g_hfsplus_entries[i];
        size_t run_index;

        if (entry->is_directory ||
            entry->data_size == 0U ||
            !catalog_path_matches_scope_local(entry->path, root_scope_csv)) {
            continue;
        }
        for (run_index = 0U; run_index < entry->run_count; ++run_index) {
            if (!append_ddrescue_domain_run_local(
                    &ranges,
                    &range_count,
                    &range_capacity,
                    catalog_entry_run_local(entry, run_index))) {
                goto done;
            }
        }
    }

    merged_count = merge_domain_ranges_local(
        ranges,
        range_count,
        HFSPLUS_DDRESCUE_DOMAIN_COALESCE_GAP_BYTES
    );
    if (merged_count < range_count) {
        log_info(
            "HFS+ selected-folder ddrescue domain coalesced %llu raw extent range%s into %llu imaging range%s by bridging gaps up to 1 MiB",
            (unsigned long long)range_count,
            range_count == 1U ? "" : "s",
            (unsigned long long)merged_count,
            merged_count == 1U ? "" : "s"
        );
    }
    if (!write_ddrescue_domain_map_local(
            domain_map_path,
            ranges,
            merged_count,
            &total_bytes)) {
        goto done;
    }
    if (out_range_count != NULL) {
        *out_range_count = (uint64_t)merged_count;
    }
    if (out_total_bytes != NULL) {
        *out_total_bytes = total_bytes;
    }
    ok = 1;

done:
    free(ranges);
    return ok;
}

static int copy_catalog_entry_data_fork_local(
    Reader *reader,
    const HfsPlusCatalogEntry *entry,
    const char *output_path,
    HfsPlusRecoveryFailureLocal *failure
)
{
    enum { COPY_BUFFER_SIZE = 1024U * 1024U };
    unsigned char *buffer;
    FILE *output_file;
    char temporary_path[HFSPLUS_PATH_MAX + 64U];
    uint64_t total_written = 0U;
    size_t run_index;
    int ok = 1;

    if (failure != NULL) {
        memset(failure, 0, sizeof(*failure));
        failure->reason = "invalid_arguments";
    }
    if (reader == NULL || entry == NULL || output_path == NULL) {
        return 0;
    }
    if (entry->data_size > 0U &&
        (entry->run_truncated || entry->run_count == 0U)) {
        if (failure != NULL) {
            failure->reason = entry->run_truncated
                ? "incomplete_runlist"
                : "missing_runlist";
            failure->requested_bytes = entry->data_size;
        }
        return 0;
    }
    if (!ensure_parent_dirs_for_path_local(output_path)) {
        if (failure != NULL) {
            failure->reason = "create_parent_directory";
            failure->error_code = errno;
        }
        return 0;
    }

    if (snprintf(
            temporary_path,
            sizeof(temporary_path),
            "%s.carvpart.%u",
            output_path,
            entry->file_id) >= (int)sizeof(temporary_path)) {
        if (failure != NULL) {
            failure->reason = "build_temporary_output_path";
            failure->error_code = ENAMETOOLONG;
        }
        return 0;
    }

    output_file = fopen(temporary_path, "wb");
    if (output_file == NULL) {
        if (failure != NULL) {
            failure->reason = "open_output";
            failure->error_code = errno;
        }
        return 0;
    }
    buffer = (unsigned char *)malloc(COPY_BUFFER_SIZE + HFSPLUS_SECTOR_SIZE);
    if (buffer == NULL) {
        if (failure != NULL) {
            failure->reason = "allocate_copy_buffer";
            failure->error_code = errno;
        }
        fclose(output_file);
        unlink(temporary_path);
        return 0;
    }

    for (run_index = 0U;
         run_index < entry->run_count && total_written < entry->data_size;
         ++run_index) {
        const MftViewRun *run = catalog_entry_run_local(entry, run_index);
        uint64_t run_cursor;
        uint64_t run_remaining;

        if (run == NULL) {
            if (failure != NULL) {
                failure->reason = "missing_extent";
                failure->run_index = run_index;
                failure->completed_bytes = total_written;
            }
            ok = 0;
            break;
        }
        run_cursor = run->abs_offset;
        run_remaining = run->byte_length;

        while (run_remaining > 0U && total_written < entry->data_size) {
            size_t logical_bytes =
                run_remaining > COPY_BUFFER_SIZE
                    ? COPY_BUFFER_SIZE
                    : (size_t)run_remaining;
            size_t aligned_read_bytes =
                (logical_bytes + (HFSPLUS_SECTOR_SIZE - 1U)) &
                ~(HFSPLUS_SECTOR_SIZE - 1U);
            uint64_t unreadable_bytes = 0U;
            size_t bytes_read;

            if (app_stop_requested()) {
                if (failure != NULL) {
                    failure->reason = "interrupted";
                    failure->source_offset = run_cursor;
                    failure->requested_bytes = logical_bytes;
                    failure->completed_bytes = total_written;
                    failure->run_index = run_index;
                }
                ok = 0;
                break;
            }
            bytes_read = reader_read_at_resilient(
                reader,
                run_cursor,
                buffer,
                aligned_read_bytes,
                &unreadable_bytes
            );
            if (bytes_read != aligned_read_bytes || unreadable_bytes > 0U) {
                if (failure != NULL) {
                    failure->reason = unreadable_bytes > 0U
                        ? "source_read_unrecoverable"
                        : "source_read_short";
                    failure->error_code = reader_last_errno();
                    failure->source_offset = run_cursor;
                    failure->requested_bytes = aligned_read_bytes;
                    failure->completed_bytes = total_written;
                    failure->unreadable_bytes = unreadable_bytes;
                    failure->run_index = run_index;
                }
                ok = 0;
                break;
            }
            if (!write_bytes_local(output_file, buffer, logical_bytes)) {
                if (failure != NULL) {
                    failure->reason = "write_output";
                    failure->error_code = errno;
                    failure->source_offset = run_cursor;
                    failure->requested_bytes = logical_bytes;
                    failure->completed_bytes = total_written;
                    failure->run_index = run_index;
                }
                ok = 0;
                break;
            }
            run_cursor += logical_bytes;
            run_remaining -= logical_bytes;
            total_written += logical_bytes;
            g_hfsplus_recovery_progress.bytes_written = hfsplus_progress_add_local(
                g_hfsplus_recovery_progress.bytes_written,
                (uint64_t)logical_bytes
            );
            g_hfsplus_recovery_progress.bytes_copied = hfsplus_progress_add_local(
                g_hfsplus_recovery_progress.bytes_copied,
                (uint64_t)logical_bytes
            );
            g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
                g_hfsplus_recovery_progress.work_completed,
                (uint64_t)logical_bytes
            );
            g_hfsplus_recovery_progress.current_source_offset = run_cursor;
            hfsplus_progress_publish_local(0);
        }
        if (!ok) {
            break;
        }
    }

    free(buffer);
    if (fclose(output_file) != 0) {
        if (failure != NULL && ok) {
            failure->reason = "close_output";
            failure->error_code = errno;
            failure->completed_bytes = total_written;
        }
        ok = 0;
    }
    if (!ok || total_written != entry->data_size) {
        if (failure != NULL && ok && total_written != entry->data_size) {
            failure->reason = "extent_coverage_short";
            failure->completed_bytes = total_written;
            failure->requested_bytes = entry->data_size;
        }
        unlink(temporary_path);
        return 0;
    }

    if (rename(temporary_path, output_path) != 0) {
        if (failure != NULL) {
            failure->reason = "commit_output";
            failure->error_code = errno;
            failure->completed_bytes = total_written;
        }
        unlink(temporary_path);
        return 0;
    }

    (void)mft_apply_output_owner_to_path(output_path);
    (void)mft_apply_created_time_value_to_path(output_path, entry->created_unix);
    return 1;
}

static int hfsplus_catalog_entry_is_jpeg_local(const HfsPlusCatalogEntry *entry)
{
    const char *extension = entry_extension_local(entry);

    return extension != NULL &&
           (strcasecmp(extension, "jpg") == 0 ||
            strcasecmp(extension, "jpeg") == 0 ||
            strcasecmp(extension, "jpe") == 0);
}

static int hfsplus_build_metadata_test_output_path_local(
    char *out_path,
    size_t out_size,
    const char *out_dir,
    const HfsPlusCatalogEntry *entry,
    size_t ordinal
)
{
    char test_dir[HFSPLUS_PATH_MAX];
    char component[HFSPLUS_NAME_MAX];
    char leaf[HFSPLUS_NAME_MAX + 96U];
    unsigned int suffix;

    if (out_path == NULL || out_size == 0U ||
        out_dir == NULL || out_dir[0] == '\0' ||
        entry == NULL) {
        return 0;
    }
    out_path[0] = '\0';
    if (snprintf(
            test_dir,
            sizeof(test_dir),
            "%s/%s/test",
            out_dir,
            APP_RECOVERED_DIR_NAME) >= (int)sizeof(test_dir) ||
        !ensure_directory_recursive_local(test_dir) ||
        !build_portable_catalog_component_local(
            component,
            sizeof(component),
            entry)) {
        return 0;
    }

    for (suffix = 0U; suffix < 10000U; ++suffix) {
        int leaf_result;

        if (suffix == 0U) {
            leaf_result = snprintf(
                leaf,
                sizeof(leaf),
                "test_%02zu_%s",
                ordinal,
                component);
        } else {
            leaf_result = snprintf(
                leaf,
                sizeof(leaf),
                "test_%02zu_%u_%s",
                ordinal,
                suffix,
                component);
        }
        if (leaf_result < 0 || leaf_result >= (int)sizeof(leaf)) {
            const char *extension = entry_extension_local(entry);

            if (extension != NULL && extension[0] != '\0') {
                leaf_result = snprintf(
                    leaf,
                    sizeof(leaf),
                    "test_%02zu_hfs%u_%u.%s",
                    ordinal,
                    entry->file_id,
                    suffix,
                    extension);
            } else {
                leaf_result = snprintf(
                    leaf,
                    sizeof(leaf),
                    "test_%02zu_hfs%u_%u.jpg",
                    ordinal,
                    entry->file_id,
                    suffix);
            }
            if (leaf_result < 0 || leaf_result >= (int)sizeof(leaf)) {
                return 0;
            }
        }
        if (snprintf(out_path, out_size, "%s/%s", test_dir, leaf) >= (int)out_size) {
            continue;
        }
        if (!file_exists_local(out_path)) {
            return 1;
        }
    }

    out_path[0] = '\0';
    return 0;
}

int hfsplus_backend_run_metadata_jpeg_test(
    const char *input_path,
    const char *out_dir,
    size_t max_files,
    size_t *out_recovered_count
)
{
    Reader input_reader = {0};
    size_t entry_index;
    size_t matched_files = 0U;
    size_t recovered_files = 0U;
    size_t incomplete_files = 0U;
    size_t failed_files = 0U;
    char test_dir[HFSPLUS_PATH_MAX];

    if (out_recovered_count != NULL) {
        *out_recovered_count = 0U;
    }
    if (max_files == 0U) {
        return 0;
    }
    if (out_dir != NULL && out_dir[0] != '\0') {
        hfsplus_backend_set_output_dir(out_dir);
    }
    if (!hfsplus_catalog_available_local() &&
        (!hfsplus_backend_configure_from_source(input_path) ||
         !hfsplus_catalog_available_local())) {
        log_error("HFS+ JPEG test could not load Catalog metadata");
        return 0;
    }
    if (g_hfsplus_output_dir[0] == '\0') {
        log_error("HFS+ JPEG test has no output directory");
        return 0;
    }
    if (snprintf(
            test_dir,
            sizeof(test_dir),
            "%s/%s/test",
            g_hfsplus_output_dir,
            APP_RECOVERED_DIR_NAME) >= (int)sizeof(test_dir) ||
        !ensure_directory_recursive_local(test_dir)) {
        log_error("HFS+ JPEG test could not create output directory");
        return 0;
    }
    if (!hfsplus_acquire_recovery_lock_local()) {
        return 0;
    }

    memset(&g_hfsplus_recovery_progress, 0, sizeof(g_hfsplus_recovery_progress));
    g_hfsplus_recovery_progress.phase = "recovering";
    g_hfsplus_recovery_progress.activity = "Testing HFS+ Catalog JPEG recovery";
    g_hfsplus_recovery_progress.files_total = max_files;
    g_hfsplus_recovery_progress.work_total =
        (uint64_t)max_files * HFSPLUS_PROGRESS_FILE_WORK_BYTES;
    g_hfsplus_recovery_progress.started_at = monotonic_seconds_local();
    g_hfsplus_recovery_progress.work_started_at =
        g_hfsplus_recovery_progress.started_at;
    hfsplus_progress_publish_local(1);

    if (!reader_open(&input_reader, input_path, 1024U * 1024U, 0U)) {
        g_hfsplus_recovery_progress.phase = "failed";
        g_hfsplus_recovery_progress.activity = "Failed to reopen HFS+ source";
        hfsplus_progress_publish_local(1);
        log_error(
            "Failed to open resilient HFS+ source reader for JPEG test: %s (%s)",
            input_path,
            reader_last_error()
        );
        hfsplus_release_recovery_lock_local();
        return 0;
    }
    (void)reader_set_progress_reporting(&input_reader, 0);
    {
        char state_path[HFSPLUS_PATH_MAX];

        if (snprintf(state_path, sizeof(state_path), "%s/%s/read_errors.tsv",
                     g_hfsplus_output_dir, APP_STATE_DIR_NAME) < (int)sizeof(state_path)) {
            (void)reader_set_error_report_path(&input_reader, state_path);
        }
        if (snprintf(state_path, sizeof(state_path), "%s/%s/last_bad_read.txt",
                     g_hfsplus_output_dir, APP_STATE_DIR_NAME) < (int)sizeof(state_path)) {
            (void)reader_set_bad_read_state_path(&input_reader, state_path);
        }
        if (snprintf(state_path, sizeof(state_path), "%s/%s/read_trouble_map.tsv",
                     g_hfsplus_output_dir, APP_STATE_DIR_NAME) < (int)sizeof(state_path)) {
            (void)reader_set_trouble_map_path(&input_reader, state_path);
        }
    }

    log_info(
        "HFS+ metadata JPEG test: recovering up to %zu Catalog JPEG file%s into %s",
        max_files,
        max_files == 1U ? "" : "s",
        test_dir
    );
    for (entry_index = 0U;
         entry_index < g_hfsplus_entry_count &&
         recovered_files < max_files &&
         !app_stop_requested();
         ++entry_index) {
        HfsPlusCatalogEntry *entry = &g_hfsplus_entries[entry_index];
        HfsPlusRecoveryFailureLocal failure = {0};
        char output_path[HFSPLUS_PATH_MAX];

        if (entry->is_directory ||
            entry->data_size == 0U ||
            !hfsplus_catalog_entry_is_jpeg_local(entry)) {
            continue;
        }
        ++matched_files;
        hfsplus_progress_set_path_local(
            entry->path_complete && entry->path[0] != '\0'
                ? entry->path
                : entry->name,
            entry->abs_offset
        );
        hfsplus_progress_publish_local(0);
        if (entry->run_truncated || entry->run_count == 0U) {
            ++incomplete_files;
            failure.reason = entry->run_truncated
                ? "incomplete_runlist"
                : "missing_runlist";
            failure.requested_bytes = entry->data_size;
            append_hfsplus_recovery_failure_local(entry, "", &failure);
            continue;
        }
        if (!hfsplus_build_metadata_test_output_path_local(
                output_path,
                sizeof(output_path),
                g_hfsplus_output_dir,
                entry,
                recovered_files + 1U)) {
            ++failed_files;
            failure.reason = "build_test_output_path";
            failure.requested_bytes = entry->data_size;
            append_hfsplus_recovery_failure_local(entry, "", &failure);
            continue;
        }
        if (!copy_catalog_entry_data_fork_local(
                &input_reader,
                entry,
                output_path,
                &failure)) {
            if (!app_stop_requested()) {
                ++failed_files;
                append_hfsplus_recovery_failure_local(entry, output_path, &failure);
            }
            continue;
        }
        ++recovered_files;
        g_hfsplus_recovery_progress.files_completed = recovered_files;
        g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
            g_hfsplus_recovery_progress.work_completed,
            HFSPLUS_PROGRESS_FILE_WORK_BYTES
        );
        hfsplus_progress_publish_local(0);
        if (entry->abs_offset != UINT64_MAX) {
            remember_recovered_output_local(output_path, (long long)entry->abs_offset);
        }
        log_info("HFS+ JPEG test recovered: %s", output_path);
    }

    reader_close(&input_reader);
    if (out_recovered_count != NULL) {
        *out_recovered_count = recovered_files;
    }
    if (app_stop_requested()) {
        g_hfsplus_recovery_progress.phase = "interrupted";
        g_hfsplus_recovery_progress.activity = "HFS+ JPEG test interrupted";
        hfsplus_progress_publish_local(1);
        hfsplus_release_recovery_lock_local();
        return -1;
    }
    g_hfsplus_recovery_progress.phase =
        recovered_files > 0U ? "complete" : "failed";
    g_hfsplus_recovery_progress.activity =
        recovered_files > 0U
            ? "HFS+ JPEG test complete"
            : "HFS+ JPEG test found no recoverable JPEG files";
    g_hfsplus_recovery_progress.work_completed =
        g_hfsplus_recovery_progress.work_total;
    hfsplus_progress_set_path_local("", 0U);
    hfsplus_progress_publish_local(1);
    hfsplus_release_recovery_lock_local();
    log_info(
        "HFS+ metadata JPEG test finished: matched=%zu recovered=%zu incomplete_runlist=%zu failed=%zu",
        matched_files,
        recovered_files,
        incomplete_files,
        failed_files
    );
    return recovered_files > 0U ? 1 : 0;
}

int hfsplus_backend_run_selected_tree(
    const char *input_path,
    const char *root_scope_csv,
    int quick_resume,
    size_t *out_recovered_count
)
{
    Reader input_reader = {0};
    size_t entry_index;
    size_t selected_directories = 0U;
    size_t selected_files = 0U;
    size_t recovered_files = 0U;
    size_t incomplete_files = 0U;
    size_t failed_files = 0U;
    const uint64_t directory_half_work =
        HFSPLUS_PROGRESS_DIRECTORY_WORK_BYTES / 2U;

    if (out_recovered_count != NULL) {
        *out_recovered_count = 0U;
    }
    if (!hfsplus_catalog_available_local() &&
        (!hfsplus_backend_configure_from_source(input_path) ||
         !hfsplus_catalog_available_local())) {
        log_error("HFS+ selected-folder recovery could not load Catalog metadata");
        return 0;
    }
    if (g_hfsplus_output_dir[0] == '\0') {
        log_error("HFS+ selected-folder recovery has no output directory");
        return 0;
    }
    if (!hfsplus_acquire_recovery_lock_local()) {
        return 0;
    }

    memset(&g_hfsplus_recovery_progress, 0, sizeof(g_hfsplus_recovery_progress));
    g_hfsplus_recovery_progress.phase = "planning";
    g_hfsplus_recovery_progress.activity = "Inventorying selected HFS+ Catalog tree";
    g_hfsplus_recovery_progress.planning_entries_total = g_hfsplus_entry_count;
    g_hfsplus_recovery_progress.started_at = monotonic_seconds_local();
    hfsplus_progress_publish_local(1);

    for (entry_index = 0U; entry_index < g_hfsplus_entry_count; ++entry_index) {
        HfsPlusCatalogEntry *entry = &g_hfsplus_entries[entry_index];
        HfsPlusCatalogEntry materialized = {0};
        const HfsPlusCatalogEntry *recovery_entry = NULL;
        int recovery_kind = 1;

        if (app_stop_requested()) {
            g_hfsplus_recovery_progress.phase = "interrupted";
            g_hfsplus_recovery_progress.activity = "HFS+ recovery interrupted during planning";
            hfsplus_progress_publish_local(1);
            hfsplus_release_recovery_lock_local();
            return -1;
        }
        g_hfsplus_recovery_progress.planning_entries_processed = entry_index + 1U;
        if (!entry->path_complete ||
            !catalog_path_matches_scope_local(entry->path, root_scope_csv)) {
            hfsplus_progress_publish_local(0);
            continue;
        }
        if (entry->is_hardlink_metadata_directory) {
            hfsplus_progress_publish_local(0);
            continue;
        }
        if (entry->is_directory) {
            ++selected_directories;
        } else {
            recovery_kind = catalog_entry_for_recovery_local(
                entry,
                &materialized,
                &recovery_entry);
            if (recovery_kind == 0) {
                hfsplus_progress_publish_local(0);
                continue;
            }
            ++selected_files;
            g_hfsplus_recovery_progress.bytes_total = hfsplus_progress_add_local(
                g_hfsplus_recovery_progress.bytes_total,
                (recovery_kind < 0 || recovery_entry == NULL ||
                 (recovery_entry->data_size > 0U &&
                  (recovery_entry->run_truncated ||
                   recovery_entry->run_count == 0U)))
                    ? 0U
                    : recovery_entry->data_size
            );
        }
        hfsplus_progress_publish_local(0);
    }

    if (selected_directories == 0U) {
        g_hfsplus_recovery_progress.phase = "failed";
        g_hfsplus_recovery_progress.activity = "Selected HFS+ folder was not found";
        hfsplus_progress_publish_local(1);
        log_error(
            "HFS+ selected folder was not found in Catalog metadata: %s",
            root_scope_csv != NULL && root_scope_csv[0] != '\0'
                ? root_scope_csv
                : "/"
        );
        hfsplus_release_recovery_lock_local();
        return 0;
    }

    g_hfsplus_recovery_progress.files_total = selected_files;
    g_hfsplus_recovery_progress.directories_total = selected_directories;
    g_hfsplus_recovery_progress.work_total = g_hfsplus_recovery_progress.bytes_total;
    g_hfsplus_recovery_progress.work_total = hfsplus_progress_add_local(
        g_hfsplus_recovery_progress.work_total,
        (uint64_t)selected_files > UINT64_MAX / HFSPLUS_PROGRESS_FILE_WORK_BYTES
            ? UINT64_MAX
            : (uint64_t)selected_files * HFSPLUS_PROGRESS_FILE_WORK_BYTES
    );
    g_hfsplus_recovery_progress.work_total = hfsplus_progress_add_local(
        g_hfsplus_recovery_progress.work_total,
        (uint64_t)selected_directories > UINT64_MAX / HFSPLUS_PROGRESS_DIRECTORY_WORK_BYTES
            ? UINT64_MAX
            : (uint64_t)selected_directories * HFSPLUS_PROGRESS_DIRECTORY_WORK_BYTES
    );
    g_hfsplus_recovery_progress.plan_ready = 1;
    /*
     * Do not pre-create every directory before the first file.  On exFAT a
     * large HFS+ tree means tens of thousands of synchronous directory scans;
     * that delays the first recovered byte and makes a stop request appear to
     * hang.  File parents are created on demand below.  Empty directories are
     * preserved in the finalization pass once file recovery is safely done.
     */
    g_hfsplus_recovery_progress.phase = "recovering";
    g_hfsplus_recovery_progress.activity = "Preparing HFS+ file recovery";
    g_hfsplus_recovery_progress.work_started_at = monotonic_seconds_local();
    hfsplus_progress_publish_local(1);

    if (!reader_open(&input_reader, input_path, 1024U * 1024U, 0U)) {
        g_hfsplus_recovery_progress.phase = "failed";
        g_hfsplus_recovery_progress.activity = "Failed to reopen HFS+ source";
        hfsplus_progress_publish_local(1);
        log_error(
            "Failed to open resilient HFS+ source reader for selected-folder recovery: %s (%s)",
            input_path,
            reader_last_error()
        );
        hfsplus_release_recovery_lock_local();
        return 0;
    }
    (void)reader_set_progress_reporting(&input_reader, 0);
    {
        char state_path[HFSPLUS_PATH_MAX];

        if (snprintf(state_path, sizeof(state_path), "%s/%s/read_errors.tsv",
                     g_hfsplus_output_dir, APP_STATE_DIR_NAME) < (int)sizeof(state_path)) {
            (void)reader_set_error_report_path(&input_reader, state_path);
        }
        if (snprintf(state_path, sizeof(state_path), "%s/%s/last_bad_read.txt",
                     g_hfsplus_output_dir, APP_STATE_DIR_NAME) < (int)sizeof(state_path)) {
            (void)reader_set_bad_read_state_path(&input_reader, state_path);
        }
        if (snprintf(state_path, sizeof(state_path), "%s/%s/read_trouble_map.tsv",
                     g_hfsplus_output_dir, APP_STATE_DIR_NAME) < (int)sizeof(state_path)) {
            (void)reader_set_trouble_map_path(&input_reader, state_path);
        }
    }
    g_hfsplus_recovery_progress.phase = "recovering";
    g_hfsplus_recovery_progress.activity = "Recovering files from HFS+ Catalog extents";
    hfsplus_progress_set_path_local("", 0U);
    hfsplus_progress_publish_local(1);
    log_info(
        "HFS+ metadata recovery: reading every Catalog data fork under %s",
        root_scope_csv != NULL && root_scope_csv[0] != '\0' ? root_scope_csv : "/"
    );

    for (entry_index = 0U; entry_index < g_hfsplus_entry_count; ++entry_index) {
        HfsPlusCatalogEntry *catalog_entry = &g_hfsplus_entries[entry_index];
        HfsPlusCatalogEntry materialized = {0};
        const HfsPlusCatalogEntry *entry = NULL;
        char output_path[HFSPLUS_PATH_MAX];
        struct stat existing;
        int recovery_kind;

        if (app_stop_requested()) {
            break;
        }
        if (catalog_entry->is_directory || !catalog_entry->path_complete ||
            !catalog_path_matches_scope_local(
                catalog_entry->path,
                root_scope_csv)) {
            continue;
        }
        recovery_kind = catalog_entry_for_recovery_local(
            catalog_entry,
            &materialized,
            &entry);
        if (recovery_kind == 0) continue;
        if (recovery_kind < 0 || entry == NULL) {
            HfsPlusRecoveryFailureLocal failure = {0};

            ++failed_files;
            g_hfsplus_recovery_progress.files_failed = failed_files;
            g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
                g_hfsplus_recovery_progress.work_completed,
                HFSPLUS_PROGRESS_FILE_WORK_BYTES);
            failure.reason = "broken_hardlink";
            append_hfsplus_recovery_failure_local(catalog_entry, "", &failure);
            log_info(
                "HFS+ metadata recovery skipped broken hard link: %s (reference=%u)",
                catalog_entry->path,
                catalog_entry->hardlink_reference);
            hfsplus_progress_publish_local(0);
            continue;
        }
        hfsplus_progress_set_path_local(entry->path, entry->abs_offset);
        hfsplus_progress_publish_local(0);
        if (entry->data_size > 0U &&
            (entry->run_truncated || entry->run_count == 0U)) {
            HfsPlusRecoveryFailureLocal failure = {0};

            ++incomplete_files;
            g_hfsplus_recovery_progress.files_incomplete = incomplete_files;
            g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
                g_hfsplus_recovery_progress.work_completed,
                HFSPLUS_PROGRESS_FILE_WORK_BYTES
            );
            hfsplus_progress_publish_local(0);
            failure.reason = entry->run_truncated
                ? "incomplete_runlist"
                : "missing_runlist";
            failure.requested_bytes = entry->data_size;
            append_hfsplus_recovery_failure_local(entry, "", &failure);
            log_info(
                "HFS+ metadata recovery skipped incomplete data-fork runlist: %s",
                entry->path
            );
            continue;
        }
        if (!build_catalog_entry_output_path_local(
                output_path,
                sizeof(output_path),
                entry)) {
            HfsPlusRecoveryFailureLocal failure = {0};

            ++failed_files;
            g_hfsplus_recovery_progress.files_failed = failed_files;
            g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
                g_hfsplus_recovery_progress.work_completed,
                hfsplus_progress_add_local(entry->data_size,
                                           HFSPLUS_PROGRESS_FILE_WORK_BYTES)
            );
            failure.reason = "build_output_path";
            failure.requested_bytes = entry->data_size;
            append_hfsplus_recovery_failure_local(entry, "", &failure);
            log_error(
                "Failed to build portable HFS+ output path for CNID %u: %s",
                entry->file_id,
                entry->path
            );
            continue;
        }
        if (quick_resume && stat(output_path, &existing) == 0 &&
            S_ISREG(existing.st_mode) &&
            (uint64_t)existing.st_size == entry->data_size) {
            ++recovered_files;
            g_hfsplus_recovery_progress.files_completed = recovered_files;
            g_hfsplus_recovery_progress.bytes_written = hfsplus_progress_add_local(
                g_hfsplus_recovery_progress.bytes_written,
                entry->data_size
            );
            g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
                g_hfsplus_recovery_progress.work_completed,
                hfsplus_progress_add_local(entry->data_size,
                                           HFSPLUS_PROGRESS_FILE_WORK_BYTES)
            );
            hfsplus_progress_publish_local(0);
            continue;
        }
        {
            uint64_t work_before_copy = g_hfsplus_recovery_progress.work_completed;
            HfsPlusRecoveryFailureLocal failure = {0};

            if (!copy_catalog_entry_data_fork_local(
                &input_reader,
                entry,
                output_path,
                &failure)) {
                if (!app_stop_requested()) {
                    ++failed_files;
                    g_hfsplus_recovery_progress.files_failed = failed_files;
                    append_hfsplus_recovery_failure_local(entry, output_path, &failure);
                    log_error(
                        "Failed to recover HFS+ Catalog file: %s (reason=%s errno=%d source_offset=%llu requested=%llu completed=%llu unreadable=%llu run=%zu/%zu)",
                        entry->path,
                        failure.reason != NULL ? failure.reason : "unknown",
                        failure.error_code,
                        (unsigned long long)failure.source_offset,
                        (unsigned long long)failure.requested_bytes,
                        (unsigned long long)failure.completed_bytes,
                        (unsigned long long)failure.unreadable_bytes,
                        failure.run_index,
                        entry->run_count
                    );
                }
                if (!app_stop_requested()) {
                    uint64_t copied_work =
                        g_hfsplus_recovery_progress.work_completed - work_before_copy;
                    if (copied_work < entry->data_size) {
                        g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
                            g_hfsplus_recovery_progress.work_completed,
                            entry->data_size - copied_work
                        );
                    }
                    g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
                        g_hfsplus_recovery_progress.work_completed,
                        HFSPLUS_PROGRESS_FILE_WORK_BYTES
                    );
                    hfsplus_progress_publish_local(0);
                }
                continue;
            }
        }
        ++recovered_files;
        g_hfsplus_recovery_progress.files_completed = recovered_files;
        g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
            g_hfsplus_recovery_progress.work_completed,
            HFSPLUS_PROGRESS_FILE_WORK_BYTES
        );
        hfsplus_progress_publish_local(0);
        if (entry->abs_offset != UINT64_MAX) {
            remember_recovered_output_local(output_path, (long long)entry->abs_offset);
        }
    }

    reader_close(&input_reader);

    if (app_stop_requested()) {
        if (out_recovered_count != NULL) {
            *out_recovered_count = recovered_files;
        }
        g_hfsplus_recovery_progress.phase = "interrupted";
        g_hfsplus_recovery_progress.activity = "HFS+ recovery interrupted";
        hfsplus_progress_publish_local(1);
        hfsplus_release_recovery_lock_local();
        return -1;
    }

    /* Apply directory times after child creation so file writes do not replace them. */
    g_hfsplus_recovery_progress.phase = "finalizing";
    g_hfsplus_recovery_progress.activity = "Applying HFS+ directory timestamps";
    hfsplus_progress_publish_local(1);
    for (entry_index = 0U; entry_index < g_hfsplus_entry_count; ++entry_index) {
        HfsPlusCatalogEntry *entry = &g_hfsplus_entries[entry_index];
        char output_path[HFSPLUS_PATH_MAX];

        if (app_stop_requested()) {
            if (out_recovered_count != NULL) {
                *out_recovered_count = recovered_files;
            }
            g_hfsplus_recovery_progress.phase = "interrupted";
            g_hfsplus_recovery_progress.activity = "HFS+ recovery interrupted during finalization";
            hfsplus_progress_publish_local(1);
            hfsplus_release_recovery_lock_local();
            return -1;
        }
        if (!entry->is_directory || entry->is_hardlink_metadata_directory ||
            !entry->path_complete ||
            !catalog_path_matches_scope_local(entry->path, root_scope_csv)) {
            continue;
        }
        if (build_catalog_entry_output_path_local(
                output_path,
                sizeof(output_path),
                entry) &&
            ensure_directory_recursive_local(output_path)) {
            (void)mft_apply_created_time_value_to_path(output_path, entry->created_unix);
        } else {
            ++failed_files;
            g_hfsplus_recovery_progress.files_failed = failed_files;
            log_error("Failed to preserve HFS+ directory: %s", entry->path);
        }
        ++g_hfsplus_recovery_progress.directories_completed;
        g_hfsplus_recovery_progress.work_completed = hfsplus_progress_add_local(
            g_hfsplus_recovery_progress.work_completed,
            directory_half_work
        );
        hfsplus_progress_set_path_local(entry->path, entry->abs_offset);
        hfsplus_progress_publish_local(0);
    }
    if (out_recovered_count != NULL) {
        *out_recovered_count = recovered_files;
    }
    log_info(
        "HFS+ metadata recovery complete: selected=%zu recovered=%zu incomplete_runlist=%zu failed=%zu",
        selected_files,
        recovered_files,
        incomplete_files,
        failed_files
    );
    g_hfsplus_recovery_progress.work_completed = g_hfsplus_recovery_progress.work_total;
    g_hfsplus_recovery_progress.phase =
        failed_files == 0U ? "complete" : "complete_with_errors";
    g_hfsplus_recovery_progress.activity =
        failed_files == 0U
            ? "HFS+ metadata recovery complete"
            : "HFS+ metadata recovery complete with errors";
    hfsplus_progress_set_path_local("", 0U);
    hfsplus_progress_publish_local(1);
    hfsplus_release_recovery_lock_local();
    return failed_files == 0U ? 1 : 0;
}

typedef struct {
    MetadataIndexStats stats;
    uint64_t artifact_bytes;
    uint64_t path_samples;
    uint64_t path_mismatches;
    uint64_t physical_samples;
    uint64_t physical_mismatches;
    uint64_t generation;
    double build_seconds;
    double verify_seconds;
    uint64_t rss_before_bytes;
    uint64_t rss_after_bytes;
    uint64_t peak_rss_bytes;
    int reused;
    int error_code;
} HfsPlusShadowIndexResultLocal;

static int hfsplus_shadow_stop_requested_local(void *context)
{
    (void)context;
    return app_stop_requested();
}

static int hfsplus_shadow_path_allowed_local(const char *path, void *context)
{
    (void)context;
    return fs_backend_output_path_write_guard_allows(path);
}

static int hfsplus_shadow_finalize_path_local(const char *path, void *context)
{
    (void)context;
    return mft_apply_output_owner_to_path(path);
}

static void hfsplus_shadow_identity_local(MetadataIndexVolumeIdentity *identity)
{
    size_t index;

    memset(identity, 0, sizeof(*identity));
    identity->backend_kind = METADATA_INDEX_BACKEND_HFSPLUS;
    identity->block_size = g_hfsplus_geometry.block_size;
    identity->source_size = g_hfsplus_geometry.source_size;
    identity->container_offset = g_hfsplus_geometry.container_offset;
    identity->volume_offset = g_hfsplus_geometry.volume_offset;
    identity->volume_size = g_hfsplus_geometry.volume_size;
    identity->identity_primary =
        ((uint64_t)g_hfsplus_geometry.attributes << 32) |
        (uint64_t)g_hfsplus_geometry.journal_info_block;
    identity->identity_secondary =
        ((uint64_t)g_hfsplus_geometry.modify_date_hfs << 32) |
        (uint64_t)g_hfsplus_geometry.write_count;
    for (index = 0U; index < 8U; ++index) {
        identity->uuid[index] = (unsigned char)(
            g_hfsplus_geometry.volume_uuid >> (56U - (unsigned int)(index * 8U))
        );
    }
    /* Bytes 8..15 are backend-private identity salt.  Changing this value
     * invalidates only HFS+ compact indexes when parser semantics change;
     * NTFS/exFAT indexes keep their own stable identities. */
    identity->uuid[8] = 'H';
    identity->uuid[9] = 'L';
    identity->uuid[10] = 'N';
    identity->uuid[11] = 'K';
    identity->uuid[12] = (unsigned char)HFSPLUS_SHADOW_SCHEMA_VERSION;
}

static int hfsplus_shadow_expected_counts_local(MetadataIndexStats *stats)
{
    size_t index;

    if (stats == NULL || g_hfsplus_entry_count > UINT32_MAX) {
        errno = EOVERFLOW;
        return 0;
    }
    memset(stats, 0, sizeof(*stats));
    stats->object_count = g_hfsplus_entry_count;
    stats->link_count = g_hfsplus_entry_count;
    for (index = 0U; index < g_hfsplus_entry_count; ++index) {
        const HfsPlusCatalogEntry *entry = &g_hfsplus_entries[index];
        size_t name_length = entry->file_id == HFSPLUS_ROOT_FOLDER_ID
            ? 0U
            : strnlen(entry->name, sizeof(entry->name));

        if (!entry->is_directory) {
            stats->fork_count++;
            if (UINT64_MAX - stats->extent_count < entry->run_count) {
                errno = EOVERFLOW;
                return 0;
            }
            stats->extent_count += entry->run_count;
        }
        if (UINT64_MAX - stats->string_bytes < name_length) {
            errno = EOVERFLOW;
            return 0;
        }
        stats->string_bytes += name_length;
    }
    stats->physical_count = stats->extent_count;
    if (stats->fork_count > UINT32_MAX || stats->extent_count > UINT32_MAX) {
        errno = EOVERFLOW;
        return 0;
    }
    return 1;
}

static int hfsplus_shadow_stats_match_local(
    const MetadataIndexStats *actual,
    const MetadataIndexStats *expected)
{
    return actual != NULL && expected != NULL &&
           actual->object_count == expected->object_count &&
           actual->link_count == expected->link_count &&
           actual->fork_count == expected->fork_count &&
           actual->extent_count == expected->extent_count &&
           actual->physical_count == expected->physical_count &&
           actual->string_bytes == expected->string_bytes;
}

static uint64_t hfsplus_shadow_artifact_bytes_local(
    const char *index_dir,
    uint64_t generation)
{
    static const char *names[] = {
        "volume.bin", "objects.bin", "links.bin", "forks.bin",
        "extents.bin", "strings.bin", "children.idx", "physical.idx"
    };
    char generation_dir[HFSPLUS_PATH_MAX];
    uint64_t total = 0U;
    size_t index;

    if (index_dir == NULL ||
        snprintf(
            generation_dir,
            sizeof(generation_dir),
            "%s/g%06llu",
            index_dir,
            (unsigned long long)generation) >= (int)sizeof(generation_dir)) {
        return 0U;
    }
    for (index = 0U; index < sizeof(names) / sizeof(names[0]); ++index) {
        char path[HFSPLUS_PATH_MAX];
        struct stat status;

        if (snprintf(path, sizeof(path), "%s/%s", generation_dir, names[index]) >=
            (int)sizeof(path) || stat(path, &status) != 0 || status.st_size < 0) {
            continue;
        }
        if (UINT64_MAX - total < (uint64_t)status.st_size) return UINT64_MAX;
        total += (uint64_t)status.st_size;
    }
    return total;
}

static int hfsplus_verify_shadow_index_local(
    MetadataIndexReader *reader,
    const MetadataIndexStats *expected,
    HfsPlusShadowIndexResultLocal *result)
{
    size_t path_stride;
    size_t span_stride;
    size_t index;

    if (reader == NULL || expected == NULL || result == NULL) return 0;
    metadata_index_reader_get_stats(reader, &result->stats);
    if (!hfsplus_shadow_stats_match_local(&result->stats, expected)) return 0;

    path_stride = g_hfsplus_id_index_count > 2048U
        ? (g_hfsplus_id_index_count / 2048U)
        : 1U;
    for (index = 0U; index < g_hfsplus_id_index_count; index += path_stride) {
        const HfsPlusCatalogEntry *entry =
            &g_hfsplus_entries[g_hfsplus_id_index[index].entry_index];
        char rebuilt[HFSPLUS_PATH_MAX];

        if (app_stop_requested()) {
            errno = ECANCELED;
            return 0;
        }
        if (!entry->path_complete) continue;
        result->path_samples++;
        if (metadata_index_reader_reconstruct_path(
                reader,
                entry->file_id,
                rebuilt,
                sizeof(rebuilt)) != 0 || strcmp(rebuilt, entry->path) != 0) {
            result->path_mismatches++;
        }
    }

    span_stride = g_hfsplus_span_index_count > 20000U
        ? (g_hfsplus_span_index_count / 20000U)
        : 1U;
    for (index = 0U; index < g_hfsplus_span_index_count; index += span_stride) {
        const HfsPlusSpanIndexEntry *span = &g_hfsplus_span_index[index];
        const HfsPlusCatalogEntry *entry =
            span->entry_index < g_hfsplus_entry_count
                ? &g_hfsplus_entries[span->entry_index]
                : NULL;
        uint64_t offsets[3];
        size_t offset_index;

        if (app_stop_requested()) {
            errno = ECANCELED;
            return 0;
        }
        if (entry == NULL || span->end <= span->start) {
            result->physical_mismatches++;
            continue;
        }
        offsets[0] = span->start;
        offsets[1] = span->start + ((span->end - span->start) / 2U);
        offsets[2] = span->end - 1U;
        for (offset_index = 0U; offset_index < 3U; ++offset_index) {
            result->physical_samples++;
            if (metadata_index_reader_offset_has_object(
                    reader,
                    offsets[offset_index],
                    entry->file_id) != 1) {
                result->physical_mismatches++;
            }
        }
    }
    return result->path_mismatches == 0U && result->physical_mismatches == 0U;
}

static int hfsplus_write_shadow_status_local(
    const char *metadata_dir,
    const char *status,
    const char *origin,
    const HfsPlusShadowIndexResultLocal *result)
{
    char path[HFSPLUS_PATH_MAX];
    char temp_path[HFSPLUS_PATH_MAX + 32U];
    FILE *file;

    if (metadata_dir == NULL || result == NULL ||
        snprintf(path, sizeof(path), "%s/shadow_status.txt", metadata_dir) >=
            (int)sizeof(path) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >=
            (int)sizeof(temp_path) ||
        !fs_backend_output_path_write_guard_allows(temp_path)) {
        return 0;
    }
    file = fopen(temp_path, "w");
    if (file == NULL) return 0;
    fprintf(file, "format_version=%u\n", METADATA_INDEX_FORMAT_VERSION);
    fprintf(file, "backend=hfsplus\n");
    fprintf(file, "status=%s\n", status != NULL ? status : "failed");
    fprintf(file, "origin=%s\n", origin != NULL ? origin : "unknown");
    fprintf(file, "generation=%llu\n", (unsigned long long)result->generation);
    fprintf(file, "reused=%d\n", result->reused ? 1 : 0);
    fprintf(file, "objects=%llu\n", (unsigned long long)result->stats.object_count);
    fprintf(file, "links=%llu\n", (unsigned long long)result->stats.link_count);
    fprintf(file, "forks=%llu\n", (unsigned long long)result->stats.fork_count);
    fprintf(file, "extents=%llu\n", (unsigned long long)result->stats.extent_count);
    fprintf(file, "physical_rows=%llu\n", (unsigned long long)result->stats.physical_count);
    fprintf(file, "string_bytes=%llu\n", (unsigned long long)result->stats.string_bytes);
    fprintf(file, "artifact_bytes=%llu\n", (unsigned long long)result->artifact_bytes);
    fprintf(file, "path_samples=%llu\n", (unsigned long long)result->path_samples);
    fprintf(file, "path_mismatches=%llu\n", (unsigned long long)result->path_mismatches);
    fprintf(file, "physical_samples=%llu\n", (unsigned long long)result->physical_samples);
    fprintf(file, "physical_mismatches=%llu\n", (unsigned long long)result->physical_mismatches);
    fprintf(file, "build_seconds=%.6f\n", result->build_seconds);
    fprintf(file, "verify_seconds=%.6f\n", result->verify_seconds);
    fprintf(file, "rss_before_bytes=%llu\n",
            (unsigned long long)result->rss_before_bytes);
    fprintf(file, "rss_after_bytes=%llu\n",
            (unsigned long long)result->rss_after_bytes);
    fprintf(file, "peak_rss_bytes=%llu\n",
            (unsigned long long)result->peak_rss_bytes);
    fprintf(file, "error_code=%d\n", result->error_code);
    fprintf(file, "volume_uuid=%016llx\n",
            (unsigned long long)g_hfsplus_geometry.volume_uuid);
    fprintf(file, "modify_date_hfs=%u\n", g_hfsplus_geometry.modify_date_hfs);
    fprintf(file, "write_count=%u\n", g_hfsplus_geometry.write_count);
    fprintf(file, "journal_info_block=%u\n", g_hfsplus_geometry.journal_info_block);
    if (fclose(file) != 0 || rename(temp_path, path) != 0) {
        (void)unlink(temp_path);
        return 0;
    }
    return mft_apply_output_owner_to_path(path);
}

static int hfsplus_build_shadow_index_local(
    const char *index_dir,
    const MetadataIndexVolumeIdentity *identity,
    const MetadataIndexStats *expected,
    HfsPlusShadowIndexResultLocal *result)
{
    MetadataIndexWriterOptions options = {
        hfsplus_shadow_stop_requested_local,
        hfsplus_shadow_path_allowed_local,
        hfsplus_shadow_finalize_path_local,
        NULL
    };
    MetadataIndexWriter *writer = NULL;
    uint64_t fork_cursor = 0U;
    uint64_t extent_cursor = 0U;
    size_t index;

    (void)result;
    if (metadata_index_writer_create_with_options(
            index_dir,
            identity,
            &options,
            &writer) != 0) {
        return 0;
    }

    for (index = 0U; index < g_hfsplus_id_index_count; ++index) {
        const HfsPlusCatalogEntry *entry =
            &g_hfsplus_entries[g_hfsplus_id_index[index].entry_index];
        MetadataIndexObject object = {0};

        object.object_key = entry->file_id;
        object.best_link_row = (uint32_t)index;
        object.first_fork_row = entry->is_directory
            ? METADATA_INDEX_NO_ROW
            : (uint32_t)fork_cursor;
        object.fork_count = entry->is_directory ? 0U : 1U;
        object.flags = METADATA_INDEX_OBJECT_FLAG_LIVE;
        if (entry->is_directory) object.flags |= METADATA_INDEX_OBJECT_FLAG_DIRECTORY;
        if (entry->file_id == HFSPLUS_ROOT_FOLDER_ID) object.flags |= METADATA_INDEX_OBJECT_FLAG_ROOT;
        if (entry->path_complete) object.flags |= METADATA_INDEX_OBJECT_FLAG_PATH_COMPLETE;
        if (!entry->is_directory) {
            object.flags |= METADATA_INDEX_OBJECT_FLAG_RESOURCE_FORK_UNKNOWN;
            fork_cursor++;
        }
        if (entry->is_hardlink_placeholder) {
            object.flags |= METADATA_INDEX_OBJECT_FLAG_HARDLINK_PLACEHOLDER;
        }
        if (entry->is_hardlink_inode) {
            object.flags |= METADATA_INDEX_OBJECT_FLAG_HARDLINK_BACKING;
        }
        if (entry->is_hardlink_metadata_directory) {
            object.flags |= METADATA_INDEX_OBJECT_FLAG_INTERNAL_METADATA;
        }
        object.source_reference =
            entry->is_hardlink_placeholder &&
            entry->hardlink_backing_file_id != 0U
                ? entry->hardlink_backing_file_id
                : METADATA_INDEX_REFERENCE_UNKNOWN;
        object.create_time = (uint64_t)(int64_t)entry->created_unix;
        object.modify_time = METADATA_INDEX_TIME_UNKNOWN;
        if (metadata_index_writer_append_object(writer, &object) != 0) goto fail;
    }

    for (index = 0U; index < g_hfsplus_id_index_count; ++index) {
        const HfsPlusCatalogEntry *entry =
            &g_hfsplus_entries[g_hfsplus_id_index[index].entry_index];
        MetadataIndexLink link = {0};
        const char *name = entry->file_id == HFSPLUS_ROOT_FOLDER_ID ? "" : entry->name;
        size_t name_length = strlen(name);

        link.link_key = (uint64_t)index + 1U;
        link.object_key = entry->file_id;
        link.parent_object_key = entry->file_id == HFSPLUS_ROOT_FOLDER_ID
            ? 0U
            : entry->parent_id;
        link.string_length = (uint32_t)name_length;
        link.provenance = METADATA_INDEX_PROVENANCE_LIVE_HFSPLUS_CATALOG;
        link.confidence = 100U;
        if (metadata_index_writer_append_string(
                writer,
                name,
                link.string_length,
                &link.string_offset) != 0 ||
            metadata_index_writer_append_link(writer, &link) != 0) {
            goto fail;
        }
    }

    fork_cursor = 0U;
    extent_cursor = 0U;
    for (index = 0U; index < g_hfsplus_id_index_count; ++index) {
        const HfsPlusCatalogEntry *entry =
            &g_hfsplus_entries[g_hfsplus_id_index[index].entry_index];
        MetadataIndexFork fork = {0};
        uint64_t logical_total = 0U;
        size_t run_index;

        if (entry->is_directory) continue;
        for (run_index = 0U; run_index < entry->run_count; ++run_index) {
            const MftViewRun *run = catalog_entry_run_local(entry, run_index);
            if (run == NULL || UINT64_MAX - logical_total < run->byte_length) goto fail;
            logical_total += run->byte_length;
        }
        fork.object_key = entry->file_id;
        fork.logical_size = entry->data_size;
        fork.allocated_size = entry->allocated_size;
        fork.first_extent_row = extent_cursor;
        fork.extent_count = (uint32_t)entry->run_count;
        fork.fork_kind = METADATA_INDEX_FORK_DATA;
        fork.flags = !entry->run_truncated && logical_total == entry->data_size
            ? METADATA_INDEX_FORK_FLAG_COMPLETE
            : METADATA_INDEX_FORK_FLAG_TRUNCATED;
        if (metadata_index_writer_append_fork(writer, &fork) != 0) goto fail;
        extent_cursor += entry->run_count;
        fork_cursor++;
    }

    for (index = 0U; index < g_hfsplus_id_index_count; ++index) {
        const HfsPlusCatalogEntry *entry =
            &g_hfsplus_entries[g_hfsplus_id_index[index].entry_index];
        uint64_t logical_start = 0U;
        size_t run_index;

        if (entry->is_directory) continue;
        for (run_index = 0U; run_index < entry->run_count; ++run_index) {
            const MftViewRun *run = catalog_entry_run_local(entry, run_index);
            MetadataIndexExtent extent = {0};

            if (run == NULL || run->byte_length == 0U ||
                UINT64_MAX - logical_start < run->byte_length) {
                goto fail;
            }
            extent.physical_start = run->abs_offset;
            extent.logical_start = logical_start;
            extent.byte_length = run->byte_length;
            if (metadata_index_writer_append_extent(writer, &extent) != 0) goto fail;
            logical_start += run->byte_length;
        }
    }
    if (fork_cursor != expected->fork_count || extent_cursor != expected->extent_count) {
        errno = EINVAL;
        metadata_index_writer_abort(writer);
        return 0;
    }
    if (metadata_index_writer_commit(writer) != 0) return 0;
    return 1;

fail:
    metadata_index_writer_abort(writer);
    return 0;
}

static int hfsplus_ensure_shadow_index_local(void)
{
    char metadata_dir[HFSPLUS_PATH_MAX];
    char index_dir[HFSPLUS_PATH_MAX];
    MetadataIndexVolumeIdentity identity;
    MetadataIndexStats expected;
    MetadataIndexReader *reader = NULL;
    HfsPlusShadowIndexResultLocal result = {0};
    PlatformMemoryUsage memory_usage;
    double phase_started_at;
    int verified = 0;

    if (g_hfsplus_shadow_index_ready) return 1;
    if (!hfsplus_catalog_available_local() || g_hfsplus_output_dir[0] == '\0' ||
        !ensure_lookup_index_current_local() ||
        !hfsplus_shadow_expected_counts_local(&expected) ||
        snprintf(
            metadata_dir,
            sizeof(metadata_dir),
            "%s/%s/metadata",
            g_hfsplus_output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(metadata_dir) ||
        snprintf(index_dir, sizeof(index_dir), "%s/index", metadata_dir) >=
            (int)sizeof(index_dir) ||
        !ensure_directory_path_local(metadata_dir) ||
        !ensure_directory_path_local(index_dir)) {
        return 0;
    }
    hfsplus_shadow_identity_local(&identity);
    if (platform_get_process_memory_usage(&memory_usage)) {
        if (memory_usage.has_resident) {
            result.rss_before_bytes = memory_usage.resident_bytes;
        }
        if (memory_usage.has_peak_rss) {
            result.peak_rss_bytes = memory_usage.peak_rss_bytes;
        }
    }

    phase_started_at = monotonic_seconds_local();
    if (metadata_index_reader_open_expected(index_dir, &identity, &reader) == 0) {
        result.reused = 1;
    } else {
        result.reused = 0;
        phase_started_at = monotonic_seconds_local();
        if (!hfsplus_build_shadow_index_local(index_dir, &identity, &expected, &result)) {
            result.build_seconds = monotonic_seconds_local() - phase_started_at;
            result.error_code = errno;
            if (platform_get_process_memory_usage(&memory_usage)) {
                if (memory_usage.has_resident) {
                    result.rss_after_bytes = memory_usage.resident_bytes;
                }
                if (memory_usage.has_peak_rss &&
                    memory_usage.peak_rss_bytes > result.peak_rss_bytes) {
                    result.peak_rss_bytes = memory_usage.peak_rss_bytes;
                }
            }
            (void)hfsplus_write_shadow_status_local(
                metadata_dir,
                app_stop_requested() ? "interrupted" : "failed",
                "build",
                &result
            );
            log_info(
                "HFS+ compact metadata shadow index build failed softly (%s)",
                strerror(result.error_code != 0 ? result.error_code : EIO)
            );
            return 0;
        }
        result.build_seconds = monotonic_seconds_local() - phase_started_at;
        if (metadata_index_reader_open_expected(index_dir, &identity, &reader) != 0) {
            result.error_code = errno;
            (void)hfsplus_write_shadow_status_local(
                metadata_dir, "failed", "reopen", &result);
            return 0;
        }
    }

    phase_started_at = monotonic_seconds_local();
    errno = 0;
    verified = hfsplus_verify_shadow_index_local(reader, &expected, &result);
    result.verify_seconds = monotonic_seconds_local() - phase_started_at;
    result.generation = metadata_index_reader_generation(reader);
    result.artifact_bytes = hfsplus_shadow_artifact_bytes_local(
        index_dir,
        result.generation
    );
    if (platform_get_process_memory_usage(&memory_usage)) {
        if (memory_usage.has_resident) {
            result.rss_after_bytes = memory_usage.resident_bytes;
        }
        if (memory_usage.has_peak_rss &&
            memory_usage.peak_rss_bytes > result.peak_rss_bytes) {
            result.peak_rss_bytes = memory_usage.peak_rss_bytes;
        }
    }
    if (!verified) {
        metadata_index_reader_close(reader);
        reader = NULL;
        result.error_code = errno != 0 ? errno : EINVAL;
        (void)hfsplus_write_shadow_status_local(
            metadata_dir,
            app_stop_requested() ? "interrupted" : "failed",
            result.reused ? "cached_generation" : "new_generation",
            &result
        );
        log_info(
            "HFS+ compact metadata shadow index verification failed softly: path_mismatches=%llu physical_mismatches=%llu",
            (unsigned long long)result.path_mismatches,
            (unsigned long long)result.physical_mismatches
        );
        return 0;
    }
    result.error_code = 0;
    metadata_index_sequential_meter_destroy(g_hfsplus_extent_meter);
    g_hfsplus_extent_meter = NULL;
    metadata_index_reader_close(g_hfsplus_compact_reader);
    g_hfsplus_compact_reader = reader;
    reader = NULL;
    g_hfsplus_compact_stats = result.stats;
    g_hfsplus_shadow_index_ready = 1;
    (void)hfsplus_write_shadow_status_local(
        metadata_dir,
        "ready",
        result.reused ? "cached_generation" : "new_generation",
        &result
    );
    log_info(
        "HFS+ compact metadata shadow index %s: generation=%llu objects=%llu forks=%llu extents=%llu size=%.2f MiB build=%.2fs verify=%.2fs samples=%llu+%llu",
        result.reused ? "reused and verified" : "built and verified",
        (unsigned long long)result.generation,
        (unsigned long long)result.stats.object_count,
        (unsigned long long)result.stats.fork_count,
        (unsigned long long)result.stats.extent_count,
        (double)result.artifact_bytes / (1024.0 * 1024.0),
        result.build_seconds,
        result.verify_seconds,
        (unsigned long long)result.path_samples,
        (unsigned long long)result.physical_samples
    );
    return 1;
}

size_t hfsplus_backend_entry_count(void)
{
    if (g_hfsplus_entry_count > 0U) return g_hfsplus_entry_count;
    return g_hfsplus_compact_stats.object_count > (uint64_t)SIZE_MAX
        ? SIZE_MAX
        : (size_t)g_hfsplus_compact_stats.object_count;
}

int hfsplus_backend_prepare_index(void)
{
    double prepare_started_at = monotonic_seconds_local();

    if (g_hfsplus_compact_only && hfsplus_compact_available_local()) {
        if (g_hfsplus_extent_meter == NULL &&
            metadata_index_sequential_meter_create(
                g_hfsplus_compact_reader,
                &g_hfsplus_extent_meter) != 0) {
            log_error("Failed to initialize HFS+ compact extent measurement: %s",
                      strerror(errno));
            return 0;
        }
        log_info(
            "HFS+ compact index ready for sequential measurement: objects=%llu extents=%llu",
            (unsigned long long)g_hfsplus_compact_stats.object_count,
            (unsigned long long)g_hfsplus_compact_stats.physical_count);
        return 1;
    }
    if (!hfsplus_catalog_available_local()) {
        return 0;
    }
    log_set_working_activity("preparing HFS+ index");
    g_hfsplus_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_INDEX;
    if (!rebuild_lookup_index_local()) {
        g_hfsplus_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;
        log_error("Failed to prepare HFS+ offset/span lookup index");
        return 0;
    }
    (void)hfsplus_ensure_shadow_index_local();
    g_hfsplus_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;

    log_info(
        "HFS+ prepare timings: index=%.2fs entries=%zu exact_offsets=%zu spans=%zu",
        monotonic_seconds_local() - prepare_started_at,
        g_hfsplus_entry_count,
        g_hfsplus_offset_index_count,
        g_hfsplus_span_index_count
    );
    return 1;
}

int hfsplus_backend_finalize_index(void)
{
    if (g_hfsplus_compact_only && hfsplus_compact_available_local()) {
        return 1;
    }
    return finalize_state_local(
        "finalizing HFS+ metadata",
        "metadata_finalize",
        "HFS+ finalize-index"
    );
}

int hfsplus_backend_load_recovered_output_state(void)
{
    return load_recovered_output_state_local();
}

const char *hfsplus_backend_lookup_path_by_offset(long long abs_offset)
{
    HfsPlusCatalogEntry *entry = find_best_entry_for_data_offset_local(abs_offset);
    static _Thread_local char compact_path[HFSPLUS_PATH_MAX];

    if (entry != NULL && entry->path[0] != '\0') {
        return entry->path;
    }
    if (hfsplus_compact_available_local()) {
        MetadataIndexPhysicalMatch match;
        if (hfsplus_compact_match_local(abs_offset, &match, NULL) &&
            metadata_index_reader_reconstruct_path(
                g_hfsplus_compact_reader,
                match.object_key,
                compact_path,
                sizeof(compact_path)) == 0) {
            return compact_path;
        }
    }
    return NULL;
}

time_t hfsplus_backend_lookup_created_time_by_offset(long long abs_offset)
{
    HfsPlusCatalogEntry *entry = find_best_entry_for_data_offset_local(abs_offset);
    MetadataIndexObject object;

    if (entry != NULL) return entry->created_unix;
    if (hfsplus_compact_match_local(abs_offset, NULL, &object) &&
        object.create_time != METADATA_INDEX_TIME_UNKNOWN) {
        return (time_t)object.create_time;
    }
    return (time_t)0;
}

int hfsplus_backend_lookup_scan_hint(long long abs_offset, MftScanHint *out)
{
    HfsPlusCatalogEntry *entry = find_best_entry_for_data_offset_local(abs_offset);
    MetadataIndexPhysicalMatch match;

    if (out == NULL) {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->record_number = -1;
    if (entry == NULL || !entry->has_data) {
        if (!hfsplus_compact_match_local(abs_offset, &match, NULL)) return 0;
        out->inside_nonresident_run = 1;
        out->exact_data_match =
            match.physical_start == (uint64_t)abs_offset &&
            match.logical_position == 0U;
        if (match.object_key <= (uint64_t)INT_MAX) {
            out->record_number = (int)match.object_key;
        }
        return 1;
    }

    out->inside_nonresident_run = 1;
    if (entry->abs_offset == (uint64_t)abs_offset) {
        out->exact_data_match = 1;
    }
    if (entry->file_id <= (uint32_t)INT_MAX) {
        out->record_number = (int)entry->file_id;
    }

    return 1;
}

const char *hfsplus_backend_lookup_container_label_by_offset(long long abs_offset)
{
    return container_context_label_from_path(
        hfsplus_backend_lookup_path_by_offset(abs_offset)
    );
}

int hfsplus_backend_get_view_entry_by_offset(long long abs_offset, MftViewEntry *out)
{
    HfsPlusCatalogEntry *entry = find_best_entry_for_data_offset_local(abs_offset);

    if (entry == NULL ||
        !entry->has_data ||
        out == NULL ||
        abs_offset < 0 ||
        entry->abs_offset != (uint64_t)abs_offset) {
        return 0;
    }

    return populate_view_entry_local(entry, out);
}

size_t hfsplus_backend_collect_view_entries_in_range(
    long long range_start,
    long long range_end,
    MftViewEntry **out_entries
)
{
    MftViewEntry *copy = NULL;
    size_t count = 0U;
    size_t i;
    uint64_t target_start;
    uint64_t target_end;

    if (out_entries == NULL || range_end <= range_start) {
        return 0;
    }
    if (range_start < 0 || range_end < 0) {
        return 0;
    }

    target_start = (uint64_t)range_start;
    target_end = (uint64_t)range_end;
    *out_entries = NULL;
    if (!ensure_lookup_index_current_local() || g_hfsplus_offset_index_count == 0U) {
        return 0;
    }
    count = offset_index_lower_bound_local(target_end) -
            offset_index_lower_bound_local(target_start);
    if (count == 0U) {
        return 0;
    }

    copy = (MftViewEntry *)calloc(count, sizeof(*copy));
    if (copy == NULL) {
        return 0;
    }

    count = 0U;
    for (i = offset_index_lower_bound_local(target_start);
         i < g_hfsplus_offset_index_count &&
         g_hfsplus_offset_index[i].abs_offset < target_end;
         ++i) {
        HfsPlusCatalogEntry *entry =
            &g_hfsplus_entries[g_hfsplus_offset_index[i].entry_index];

        if (populate_view_entry_local(entry, &copy[count])) {
            ++count;
        }
    }

    if (count == 0U) {
        free(copy);
        return 0;
    }

    *out_entries = copy;
    return count;
}

int hfsplus_backend_build_recovered_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
)
{
    char current_path[HFSPLUS_PATH_MAX];
    const char *reuse_path = NULL;
    int current_reconciled = 0;

    current_path[0] = '\0';
    if (hfsplus_backend_get_recovered_output_info(
            abs_offset,
            current_path,
            sizeof(current_path),
            &current_reconciled) &&
        current_path[0] != '\0') {
        reuse_path = current_path;
    }

    return build_recovered_output_path_internal_local(
        out_path,
        out_size,
        abs_offset,
        default_directory,
        default_prefix,
        extension,
        reuse_path,
        NULL,
        NULL
    );
}

void hfsplus_backend_note_recovered_output(const char *path, long long abs_offset)
{
    remember_recovered_output_local(path, abs_offset);
}

int hfsplus_backend_get_recovered_output_info(
    long long abs_offset,
    char *out_path,
    size_t out_path_size,
    int *out_reconciled
)
{
    size_t index;

    if (out_path != NULL && out_path_size > 0U) {
        out_path[0] = '\0';
    }
    if (out_reconciled != NULL) {
        *out_reconciled = 0;
    }

    index = find_recovered_output_index_local(abs_offset);
    if (index == (size_t)-1) {
        return 0;
    }

    if (out_path != NULL && out_path_size > 0U) {
        snprintf(
            out_path,
            out_path_size,
            "%s",
            g_hfsplus_recovered_outputs[index].path
        );
    }
    if (out_reconciled != NULL) {
        *out_reconciled = g_hfsplus_recovered_outputs[index].reconciled;
    }
    return 1;
}

size_t hfsplus_backend_recovered_output_count(void)
{
    return g_hfsplus_recovered_output_count;
}

void hfsplus_backend_get_live_stats(MftSpoolLiveStats *out)
{
    uint64_t named_outputs;
    uint64_t total_outputs;
    uint64_t unreconciled_outputs;

    if (out == NULL) {
        return;
    }

    memset(out, 0, sizeof(*out));
    named_outputs = (uint64_t)hfsplus_backend_named_output_count();
    total_outputs = (uint64_t)g_hfsplus_recovered_output_count;
    unreconciled_outputs = (uint64_t)hfsplus_backend_unreconciled_output_count();
    out->renamed_outputs = g_hfsplus_live_renamed_outputs;
    out->recovered_outputs_current = total_outputs;
    out->named_outputs_current = named_outputs;
    out->unident_outputs_current = unreconciled_outputs;
    out->repair_pending_outputs = unreconciled_outputs;
    out->record_index_count = hfsplus_backend_entry_count();
    out->range_index_count = g_hfsplus_span_index_count > 0U
        ? g_hfsplus_span_index_count
        : (g_hfsplus_compact_stats.physical_count > (uint64_t)SIZE_MAX
            ? SIZE_MAX
            : (size_t)g_hfsplus_compact_stats.physical_count);
    out->background_phase = g_hfsplus_live_background_phase;
    out->background_conservative = g_hfsplus_live_background_conservative ? 1U : 0U;
}

size_t hfsplus_backend_named_output_count(void)
{
    return g_hfsplus_reconciled_output_count;
}

size_t hfsplus_backend_unreconciled_output_count(void)
{
    uint64_t classified = (uint64_t)g_hfsplus_reconciled_output_count +
        g_hfsplus_embedded_output_count;

    return (uint64_t)g_hfsplus_recovered_output_count >= classified
        ? (size_t)((uint64_t)g_hfsplus_recovered_output_count - classified)
        : 0U;
}

int hfsplus_backend_is_offset_fully_recovered(long long abs_offset)
{
    return find_recovered_output_index_local(abs_offset) != (size_t)-1;
}

static int hfsplus_seed_extent_meter_from_saved_coverage_local(
    MetadataIndexSequentialMeter *meter)
{
    HfsPlusDomainRangeLocal *ranges = NULL;
    size_t range_count = 0U;
    size_t range_capacity = 0U;
    size_t merged_count;
    size_t index;
    char path[HFSPLUS_PATH_MAX];
    char line[512];
    FILE *file;
    int ok = 1;

    if (meter == NULL || g_hfsplus_output_dir[0] == '\0' ||
        snprintf(
            path,
            sizeof(path),
            "%s/%s/gui_read_coverage.tsv",
            g_hfsplus_output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(path)) {
        return 0;
    }
    file = fopen(path, "r");
    if (file == NULL) return 1;
    while (fgets(line, sizeof(line), file) != NULL) {
        char pass_id[64];
        unsigned long long start;
        unsigned long long end;

        if (strncmp(line, "pass_id\t", 8U) == 0) continue;
        if (sscanf(line, "%63[^\t]\t%llu\t%llu", pass_id, &start, &end) != 3 ||
            end <= start) {
            continue;
        }
        if (!append_ddrescue_domain_range_local(
                &ranges,
                &range_count,
                &range_capacity,
                (uint64_t)start,
                (uint64_t)(end - start))) {
            ok = 0;
            break;
        }
    }
    fclose(file);
    if (!ok || range_count == 0U) {
        free(ranges);
        return ok;
    }
    merged_count = merge_domain_ranges_local(ranges, range_count, 0ULL);
    for (index = 0U; index < merged_count; ++index) {
        uint64_t length = ranges[index].end - ranges[index].start;

        if (metadata_index_sequential_meter_observe(
                meter,
                ranges[index].start,
                ranges[index].end) != 0) {
            ok = 0;
            break;
        }
        g_hfsplus_extent_meter_seeded_ranges++;
        if (UINT64_MAX - g_hfsplus_extent_meter_seeded_bytes < length) {
            g_hfsplus_extent_meter_seeded_bytes = UINT64_MAX;
        } else {
            g_hfsplus_extent_meter_seeded_bytes += length;
        }
    }
    free(ranges);
    if (ok && g_hfsplus_extent_meter_seeded_ranges > 0ULL) {
        log_info(
            "HFS+ sequential extent meter restored cumulative read coverage: ranges=%llu bytes=%.2f GiB",
            (unsigned long long)g_hfsplus_extent_meter_seeded_ranges,
            (double)g_hfsplus_extent_meter_seeded_bytes /
                (1024.0 * 1024.0 * 1024.0)
        );
    }
    return ok;
}

static int hfsplus_create_extent_meter_local(void)
{
    if (g_hfsplus_extent_meter != NULL) return 1;
    if (metadata_index_sequential_meter_create(
            g_hfsplus_compact_reader,
            &g_hfsplus_extent_meter) != 0) {
        return 0;
    }
    if (!hfsplus_seed_extent_meter_from_saved_coverage_local(
            g_hfsplus_extent_meter)) {
        metadata_index_sequential_meter_destroy(g_hfsplus_extent_meter);
        g_hfsplus_extent_meter = NULL;
        return 0;
    }
    return 1;
}

static int hfsplus_write_extent_measurement_local(const char *status)
{
    MetadataIndexSequentialStats stats;
    char path[HFSPLUS_PATH_MAX];
    char temp_path[HFSPLUS_PATH_MAX + 32U];
    FILE *file;
    int write_ok;
    int lock_fd = -1;
    char lock_path[HFSPLUS_PATH_MAX + 32U];
    struct flock lock = {0};
    const char *effective_status = status;

    if (g_hfsplus_extent_meter == NULL || g_hfsplus_output_dir[0] == '\0' ||
        snprintf(path, sizeof(path), "%s/%s/metadata/sequential_extent_measurement.txt",
                 g_hfsplus_output_dir, APP_STATE_DIR_NAME) >= (int)sizeof(path) ||
        snprintf(lock_path, sizeof(lock_path), "%s.lock", path) >=
            (int)sizeof(lock_path) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp.%ld", path,
                 (long)getpid()) >= (int)sizeof(temp_path) ||
        !fs_backend_output_path_write_guard_allows(temp_path) ||
        !fs_backend_output_path_write_guard_allows(lock_path)) {
        return 0;
    }
    lock_fd = open(lock_path, O_RDWR | O_CREAT, 0666);
    if (lock_fd < 0) return 0;
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    while (fcntl(lock_fd, F_SETLKW, &lock) != 0) {
        if (errno == EINTR) continue;
        (void)close(lock_fd);
        return 0;
    }
    /* Finalize/background helpers may publish another checkpoint after the
     * primary process completed.  Recheck persisted state while holding the
     * cross-process lock so completion can never move backwards. */
    if (!g_hfsplus_extent_measurement_completed &&
        (effective_status == NULL || strcmp(effective_status, "complete") != 0)) {
        int existing_fd = open(path, O_RDONLY);
        if (existing_fd >= 0) {
            char existing[512];
            ssize_t count = read(existing_fd, existing, sizeof(existing) - 1U);
            (void)close(existing_fd);
            if (count > 0) {
                existing[count] = '\0';
                if (strstr(existing, "\nstatus=complete\n") != NULL) {
                    effective_status = "complete";
                }
            }
        }
    } else if (g_hfsplus_extent_measurement_completed) {
        effective_status = "complete";
    }
    if (g_hfsplus_assembly_journal != NULL) {
        (void)fflush(g_hfsplus_assembly_journal);
    }
    metadata_index_sequential_meter_get_stats(g_hfsplus_extent_meter, &stats);
    file = fopen(temp_path, "w");
    if (file == NULL) {
        lock.l_type = F_UNLCK;
        (void)fcntl(lock_fd, F_SETLK, &lock);
        (void)close(lock_fd);
        return 0;
    }
    write_ok =
        fprintf(file, "format_version=1\n") >= 0 &&
        fprintf(file, "backend=hfsplus\n") >= 0 &&
        fprintf(file, "mode=measurement_and_primary_buffer_assembly\n") >= 0 &&
        fprintf(file, "status=%s\n",
                effective_status != NULL ? effective_status : "active") >= 0 &&
        fprintf(file, "generation=%llu\n",
                (unsigned long long)metadata_index_reader_generation(
                    g_hfsplus_compact_reader)) >= 0 &&
        fprintf(file, "coverage_origin=saved_union_plus_current_session\n") >= 0 &&
        fprintf(file, "coverage_seeded_ranges=%llu\n",
                (unsigned long long)g_hfsplus_extent_meter_seeded_ranges) >= 0 &&
        fprintf(file, "coverage_seeded_bytes=%llu\n",
                (unsigned long long)g_hfsplus_extent_meter_seeded_bytes) >= 0 &&
        fprintf(file, "ranges_observed=%llu\n",
                (unsigned long long)stats.ranges_observed) >= 0 &&
        fprintf(file, "source_bytes_observed=%llu\n",
                (unsigned long long)stats.source_bytes_observed) >= 0 &&
        fprintf(file, "source_gap_bytes=%llu\n",
                (unsigned long long)stats.source_gap_bytes) >= 0 &&
        fprintf(file, "duplicate_or_backward_ranges=%llu\n",
                (unsigned long long)stats.duplicate_or_backward_ranges) >= 0 &&
        fprintf(file, "extent_intersections=%llu\n",
                (unsigned long long)stats.extent_intersections) >= 0 &&
        fprintf(file, "extent_delivery_bytes=%llu\n",
                (unsigned long long)stats.extent_delivery_bytes) >= 0 &&
        fprintf(file, "extents_total=%llu\n",
                (unsigned long long)stats.extents_total) >= 0 &&
        fprintf(file, "extents_touched=%llu\n",
                (unsigned long long)stats.extents_touched) >= 0 &&
        fprintf(file, "extents_complete=%llu\n",
                (unsigned long long)stats.extents_complete) >= 0 &&
        fprintf(file, "forks_total=%llu\n",
                (unsigned long long)stats.forks_total) >= 0 &&
        fprintf(file, "forks_touched=%llu\n",
                (unsigned long long)stats.forks_touched) >= 0 &&
        fprintf(file, "forks_complete=%llu\n",
                (unsigned long long)stats.forks_complete) >= 0 &&
        fprintf(file, "forks_empty_complete=%llu\n",
                (unsigned long long)stats.forks_empty_complete) >= 0 &&
        fprintf(file, "forks_incomplete_runlist=%llu\n",
                (unsigned long long)stats.forks_incomplete_runlist) >= 0 &&
        fprintf(file, "assembly_enabled=%d\n",
                g_hfsplus_assembly_disabled ? 0 : 1) >= 0 &&
        fprintf(file, "assembly_policy=%s\n",
                g_hfsplus_assemble_all_catalog_files
                    ? "all_complete_catalog_data_forks"
                    : "selected_raw_formats") >= 0 &&
        fprintf(file, "assembly_selected_formats=%s\n",
                g_hfsplus_active_formats[0] != '\0'
                    ? g_hfsplus_active_formats
                    : "all") >= 0 &&
        fprintf(file, "assembly_intersections=%llu\n",
                (unsigned long long)g_hfsplus_assembly_intersections) >= 0 &&
        fprintf(file, "assembly_bytes_written=%llu\n",
                (unsigned long long)g_hfsplus_assembly_bytes_written) >= 0 &&
        fprintf(file, "assembly_files_completed=%llu\n",
                (unsigned long long)g_hfsplus_assembly_files_completed) >= 0 &&
        fprintf(file, "assembly_empty_files=%llu\n",
                (unsigned long long)g_hfsplus_assembly_empty_files) >= 0 &&
        fprintf(file, "assembly_empty_files_deferred=%llu\n",
                (unsigned long long)g_hfsplus_assembly_empty_files_deferred) >= 0 &&
        fprintf(file, "assembly_empty_file_policy=compact_index_only\n") >= 0 &&
        fprintf(file, "assembly_directories=%llu\n",
                (unsigned long long)g_hfsplus_assembly_directories) >= 0 &&
        fprintf(file, "assembly_hardlinks=%llu\n",
                (unsigned long long)g_hfsplus_assembly_hardlinks) >= 0 &&
        fprintf(file, "assembly_write_failures=%llu\n",
                (unsigned long long)g_hfsplus_assembly_write_failures) >= 0 &&
        fprintf(file, "assembly_inherited_generation=%llu\n",
                (unsigned long long)g_hfsplus_assembly_inherited_generation) >= 0 &&
        fprintf(file, "updated_unix=%lld\n", (long long)time(NULL)) >= 0;
    if (fclose(file) != 0) write_ok = 0;
    if (!write_ok || rename(temp_path, path) != 0) {
        (void)unlink(temp_path);
        lock.l_type = F_UNLCK;
        (void)fcntl(lock_fd, F_SETLK, &lock);
        (void)close(lock_fd);
        return 0;
    }
    write_ok = mft_apply_output_owner_to_path(path);
    lock.l_type = F_UNLCK;
    (void)fcntl(lock_fd, F_SETLK, &lock);
    (void)close(lock_fd);
    return write_ok;
}

typedef struct {
    uint64_t range_start;
    const unsigned char *bytes;
} HfsPlusSequentialDeliveryLocal;

static int hfsplus_sequential_assembly_requested_local(void)
{
    const char *value = getenv("CARV_HFS_SEQUENTIAL_ASSEMBLY");

    return value == NULL || value[0] == '\0' ||
           (strcmp(value, "0") != 0 && strcasecmp(value, "false") != 0 &&
            strcasecmp(value, "off") != 0);
}

static int hfsplus_path_matches_active_format_local(const char *path)
{
    const char *dot;
    const char *cursor;
    size_t extension_length;

    if (path == NULL || path[0] == '\0') return 0;
    if (g_hfsplus_assemble_all_catalog_files) return 1;
    if (g_hfsplus_active_formats[0] == '\0') return 1;
    dot = strrchr(path, '.');
    if (dot == NULL || dot[1] == '\0') return 0;
    dot++;
    extension_length = strlen(dot);
    cursor = g_hfsplus_active_formats;
    while (*cursor != '\0') {
        const char *start;
        size_t length;

        while (*cursor == ',' || *cursor == ';' ||
               isspace((unsigned char)*cursor)) cursor++;
        start = cursor;
        while (*cursor != '\0' && *cursor != ',' && *cursor != ';' &&
               !isspace((unsigned char)*cursor)) cursor++;
        length = (size_t)(cursor - start);
        if (length == extension_length && strncasecmp(start, dot, length) == 0) {
            return 1;
        }
        if ((extension_length == 4U && strcasecmp(dot, "jpeg") == 0 &&
             length == 3U && strncasecmp(start, "jpg", 3U) == 0) ||
            (extension_length == 3U && strcasecmp(dot, "jpg") == 0 &&
             length == 4U && strncasecmp(start, "jpeg", 4U) == 0)) {
            return 1;
        }
    }
    return 0;
}

static int hfsplus_assembly_identity_compatible_local(
    const MetadataIndexVolumeIdentity *left,
    const MetadataIndexVolumeIdentity *right)
{
    return left != NULL && right != NULL &&
           left->backend_kind == right->backend_kind &&
           left->block_size == right->block_size &&
           /* A raw device can report an unknown carrier size while its image
            * reports the exact size.  The HFS+ volume identity and layout
            * below are the safety boundary, not that transport property. */
           left->container_offset == right->container_offset &&
           left->volume_offset == right->volume_offset &&
           left->volume_size == right->volume_size &&
           left->identity_primary == right->identity_primary &&
           left->identity_secondary == right->identity_secondary &&
           memcmp(left->uuid, right->uuid, 8U) == 0;
}

static int hfsplus_assembly_layout_equal_local(
    const MetadataIndexLayoutFingerprint *left,
    const MetadataIndexLayoutFingerprint *right)
{
    return left != NULL && right != NULL &&
           left->fork_count == right->fork_count &&
           left->extent_count == right->extent_count &&
           left->physical_count == right->physical_count &&
           left->forks_crc32 == right->forks_crc32 &&
           left->extents_crc32 == right->extents_crc32 &&
           left->physical_crc32 == right->physical_crc32;
}

static int hfsplus_copy_file_local(const char *source, const char *destination)
{
    char temporary[HFSPLUS_PATH_MAX + 32U];
    unsigned char buffer[64U * 1024U];
    int source_fd = -1;
    int destination_fd = -1;
    int success = 0;

    if (source == NULL || destination == NULL ||
        snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", destination,
                 (long)getpid()) >= (int)sizeof(temporary) ||
        !fs_backend_output_path_write_guard_allows(temporary)) return 0;
    source_fd = open(source, O_RDONLY);
    destination_fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (source_fd < 0 || destination_fd < 0) goto done;
    for (;;) {
        ssize_t got = read(source_fd, buffer, sizeof(buffer));
        size_t written = 0U;

        if (got == 0) break;
        if (got < 0) {
            if (errno == EINTR) continue;
            goto done;
        }
        while (written < (size_t)got) {
            ssize_t put = write(
                destination_fd, buffer + written, (size_t)got - written);
            if (put > 0) written += (size_t)put;
            else if (put < 0 && errno == EINTR) continue;
            else goto done;
        }
    }
    if (fsync(destination_fd) != 0 || close(destination_fd) != 0) {
        destination_fd = -1;
        goto done;
    }
    destination_fd = -1;
    if (!fs_backend_output_path_write_guard_allows(destination) ||
        rename(temporary, destination) != 0) goto done;
    (void)mft_apply_output_owner_to_path(destination);
    success = 1;
done:
    if (source_fd >= 0) (void)close(source_fd);
    if (destination_fd >= 0) (void)close(destination_fd);
    if (!success) (void)unlink(temporary);
    return success;
}

static int hfsplus_inherit_assembly_generation_local(
    uint64_t current_generation,
    const char *current_journal,
    const char *current_parts)
{
    char metadata_dir[HFSPLUS_PATH_MAX];
    char index_dir[HFSPLUS_PATH_MAX];
    char previous_journal[HFSPLUS_PATH_MAX];
    char previous_parts[HFSPLUS_PATH_MAX];
    struct stat status;
    MetadataIndexLayoutFingerprint current_layout = {0};
    const MetadataIndexVolumeIdentity *current_identity;
    uint64_t candidate;

    if (current_generation <= 1U || current_journal == NULL ||
        current_parts == NULL ||
        (stat(current_journal, &status) == 0 && status.st_size > 0) ||
        snprintf(metadata_dir, sizeof(metadata_dir), "%s/%s/metadata",
                 g_hfsplus_output_dir, APP_STATE_DIR_NAME) >=
            (int)sizeof(metadata_dir) ||
        snprintf(index_dir, sizeof(index_dir), "%s/index", metadata_dir) >=
            (int)sizeof(index_dir) ||
        metadata_index_reader_get_layout_fingerprint(
            g_hfsplus_compact_reader, &current_layout) != 0) return 0;
    current_identity = metadata_index_reader_volume(g_hfsplus_compact_reader);

    for (candidate = current_generation - 1U; candidate > 0U; --candidate) {
        MetadataIndexReader *previous_reader = NULL;
        MetadataIndexLayoutFingerprint previous_layout = {0};
        const MetadataIndexVolumeIdentity *previous_identity;
        int compatible;

        if (snprintf(previous_journal, sizeof(previous_journal),
                     "%s/hfs_assembly_journal_g%06llu.tsv", metadata_dir,
                     (unsigned long long)candidate) >=
                (int)sizeof(previous_journal) ||
            snprintf(previous_parts, sizeof(previous_parts),
                     "%s/hfs_assembly_parts/g%06llu", metadata_dir,
                     (unsigned long long)candidate) >=
                (int)sizeof(previous_parts) ||
            stat(previous_journal, &status) != 0 || status.st_size <= 0 ||
            metadata_index_reader_open_generation(
                index_dir, candidate, &previous_reader) != 0) continue;
        previous_identity = metadata_index_reader_volume(previous_reader);
        compatible = hfsplus_assembly_identity_compatible_local(
                current_identity, previous_identity) &&
            metadata_index_reader_get_layout_fingerprint(
                previous_reader, &previous_layout) == 0 &&
            hfsplus_assembly_layout_equal_local(
                &current_layout, &previous_layout);
        metadata_index_reader_close(previous_reader);
        if (!compatible) continue;

        /* Completed parts have already been renamed into recovered/.  The
         * retained directory contains only partial forks and must move with
         * the row-addressed journal. */
        if (stat(previous_parts, &status) != 0 || !S_ISDIR(status.st_mode)) {
            continue;
        }
        if (rmdir(current_parts) != 0 && errno != ENOENT) continue;
        if (rename(previous_parts, current_parts) != 0) {
            (void)ensure_directory_path_local(current_parts);
            continue;
        }
        if (!hfsplus_copy_file_local(previous_journal, current_journal)) {
            if (stat(current_parts, &status) == 0 && S_ISDIR(status.st_mode)) {
                (void)rename(current_parts, previous_parts);
            }
            (void)ensure_directory_path_local(current_parts);
            return 0;
        }
        g_hfsplus_assembly_inherited_generation = candidate;
        log_info(
            "HFS+ assembly checkpoint inherited across layout-compatible compact index generation: %llu -> %llu",
            (unsigned long long)candidate,
            (unsigned long long)current_generation);
        return 1;
    }
    return 0;
}

static int hfsplus_sequential_assembly_init_local(void)
{
    char parts_dir[HFSPLUS_PATH_MAX];
    char journal_path[HFSPLUS_PATH_MAX];
    size_t fork_count;
    size_t physical_count;
    size_t index;
    uint64_t generation;
    uint64_t restored_journal_rows = 0ULL;

    if (g_hfsplus_assembly_disabled) return 0;
    if (g_hfsplus_assembly_fork_bytes != NULL) return 1;
    if (!hfsplus_sequential_assembly_requested_local() ||
        g_hfsplus_compact_reader == NULL ||
        g_hfsplus_compact_stats.fork_count == 0U ||
        g_hfsplus_compact_stats.fork_count > SIZE_MAX ||
        g_hfsplus_compact_stats.physical_count > SIZE_MAX) {
        g_hfsplus_assembly_disabled = 1;
        return 0;
    }
    fork_count = (size_t)g_hfsplus_compact_stats.fork_count;
    physical_count = (size_t)g_hfsplus_compact_stats.physical_count;
    generation = metadata_index_reader_generation(g_hfsplus_compact_reader);
    g_hfsplus_assembly_fork_bytes = (uint64_t *)calloc(
        fork_count, sizeof(*g_hfsplus_assembly_fork_bytes));
    g_hfsplus_assembly_extent_prefix = (uint64_t *)calloc(
        physical_count, sizeof(*g_hfsplus_assembly_extent_prefix));
    g_hfsplus_assembly_fork_done = (unsigned char *)calloc(
        fork_count, sizeof(*g_hfsplus_assembly_fork_done));
    if (g_hfsplus_assembly_fork_bytes == NULL ||
        g_hfsplus_assembly_extent_prefix == NULL ||
        g_hfsplus_assembly_fork_done == NULL) {
        free(g_hfsplus_assembly_fork_bytes);
        free(g_hfsplus_assembly_extent_prefix);
        free(g_hfsplus_assembly_fork_done);
        g_hfsplus_assembly_fork_bytes = NULL;
        g_hfsplus_assembly_extent_prefix = NULL;
        g_hfsplus_assembly_fork_done = NULL;
        g_hfsplus_assembly_disabled = 1;
        return 0;
    }
    g_hfsplus_assembly_fork_count = fork_count;
    if (snprintf(parts_dir, sizeof(parts_dir),
                 "%s/%s/metadata/hfs_assembly_parts/g%06llu",
                 g_hfsplus_output_dir, APP_STATE_DIR_NAME,
                 (unsigned long long)generation) >= (int)sizeof(parts_dir)) {
        free(g_hfsplus_assembly_fork_bytes);
        free(g_hfsplus_assembly_extent_prefix);
        free(g_hfsplus_assembly_fork_done);
        g_hfsplus_assembly_fork_bytes = NULL;
        g_hfsplus_assembly_extent_prefix = NULL;
        g_hfsplus_assembly_fork_done = NULL;
        g_hfsplus_assembly_fork_count = 0U;
        g_hfsplus_assembly_disabled = 1;
        return 0;
    }
    if (snprintf(journal_path, sizeof(journal_path),
                 "%s/%s/metadata/hfs_assembly_journal_g%06llu.tsv",
                 g_hfsplus_output_dir, APP_STATE_DIR_NAME,
                 (unsigned long long)generation) >=
            (int)sizeof(journal_path)) {
        g_hfsplus_assembly_disabled = 1;
        return 0;
    }
    (void)hfsplus_inherit_assembly_generation_local(
        generation, journal_path, parts_dir);
    if (!ensure_directory_path_local(parts_dir)) {
        free(g_hfsplus_assembly_fork_bytes);
        free(g_hfsplus_assembly_extent_prefix);
        free(g_hfsplus_assembly_fork_done);
        g_hfsplus_assembly_fork_bytes = NULL;
        g_hfsplus_assembly_extent_prefix = NULL;
        g_hfsplus_assembly_fork_done = NULL;
        g_hfsplus_assembly_fork_count = 0U;
        g_hfsplus_assembly_disabled = 1;
        return 0;
    }
    g_hfsplus_assembly_parts_ready = 1;
    g_hfsplus_assembly_journal = fopen(journal_path, "a+");
    if (g_hfsplus_assembly_journal == NULL) {
        g_hfsplus_assembly_disabled = 1;
        return 0;
    }
    rewind(g_hfsplus_assembly_journal);
    for (;;) {
        unsigned long long physical_row;
        unsigned int fork_row;
        unsigned long long extent_prefix;
        unsigned long long fork_bytes;
        unsigned int done;
        int parsed = fscanf(
            g_hfsplus_assembly_journal,
            "%llu\t%u\t%llu\t%llu\t%u\n",
            &physical_row,
            &fork_row,
            &extent_prefix,
            &fork_bytes,
            &done
        );

        if (parsed == EOF) break;
        if (parsed != 5) {
            int ch;
            while ((ch = fgetc(g_hfsplus_assembly_journal)) != '\n' && ch != EOF) {}
            continue;
        }
        if (physical_row < physical_count && fork_row < fork_count) {
            restored_journal_rows++;
            if ((uint64_t)extent_prefix >
                g_hfsplus_assembly_extent_prefix[physical_row]) {
                g_hfsplus_assembly_extent_prefix[physical_row] =
                    (uint64_t)extent_prefix;
            }
            if ((uint64_t)fork_bytes > g_hfsplus_assembly_fork_bytes[fork_row]) {
                g_hfsplus_assembly_fork_bytes[fork_row] = (uint64_t)fork_bytes;
            }
            if (done != 0U) g_hfsplus_assembly_fork_done[fork_row] = 1U;
        }
    }
    for (index = 0U; index < fork_count; ++index) {
        if (g_hfsplus_assembly_fork_done[index] == 1U) {
            g_hfsplus_assembly_files_completed++;
        }
        if (UINT64_MAX - g_hfsplus_assembly_bytes_written <
            g_hfsplus_assembly_fork_bytes[index]) {
            g_hfsplus_assembly_bytes_written = UINT64_MAX;
        } else {
            g_hfsplus_assembly_bytes_written +=
                g_hfsplus_assembly_fork_bytes[index];
        }
    }
    g_hfsplus_assembly_intersections = restored_journal_rows;
    (void)fseek(g_hfsplus_assembly_journal, 0L, SEEK_END);
    log_info(
        "HFS+ sequential metadata assembler enabled: policy=%s raw_selected_formats=%s forks=%zu restored_files=%llu restored_bytes=%.2f GiB journal_rows=%llu; using primary-scan bytes without source rereads",
        g_hfsplus_assemble_all_catalog_files
            ? "all complete Catalog data forks"
            : "selected raw formats",
        g_hfsplus_active_formats[0] != '\0' ? g_hfsplus_active_formats : "all",
        fork_count,
        (unsigned long long)g_hfsplus_assembly_files_completed,
        (double)g_hfsplus_assembly_bytes_written /
            (1024.0 * 1024.0 * 1024.0),
        (unsigned long long)restored_journal_rows
    );
    return 1;
}

static int hfsplus_write_all_at_local(
    int fd,
    const unsigned char *bytes,
    size_t byte_count,
    uint64_t logical_offset)
{
    size_t written = 0U;

    if (logical_offset > (uint64_t)LLONG_MAX) return 0;
    while (written < byte_count) {
        ssize_t result = pwrite(
            fd,
            bytes + written,
            byte_count - written,
            (off_t)(logical_offset + written));
        if (result > 0) {
            written += (size_t)result;
        } else if (result < 0 && errno == EINTR) {
            continue;
        } else {
            return 0;
        }
    }
    return 1;
}

static void hfsplus_sequential_journal_append_local(
    const MetadataIndexPhysicalMatch *match,
    uint64_t extent_prefix,
    uint64_t fork_bytes,
    unsigned int done)
{
    if (match == NULL || g_hfsplus_assembly_journal == NULL) return;
    (void)fprintf(
        g_hfsplus_assembly_journal,
        "%llu\t%u\t%llu\t%llu\t%u\n",
        (unsigned long long)match->physical_row,
        match->fork_row,
        (unsigned long long)extent_prefix,
        (unsigned long long)fork_bytes,
        done
    );
}

static int hfsplus_sequential_delivery_local(
    const MetadataIndexPhysicalMatch *match,
    uint64_t physical_start,
    uint64_t physical_end,
    void *context)
{
    HfsPlusSequentialDeliveryLocal *delivery =
        (HfsPlusSequentialDeliveryLocal *)context;
    MetadataIndexFork fork = {0};
    char catalog_path[HFSPLUS_PATH_MAX];
    char parts_dir[HFSPLUS_PATH_MAX];
    char part_path[HFSPLUS_PATH_MAX];
    char base_path[HFSPLUS_PATH_MAX];
    char final_path[HFSPLUS_PATH_MAX];
    uint64_t logical_offset;
    uint64_t byte_count_u64;
    uint64_t current_extent_offset;
    uint64_t previous_extent_prefix;
    uint64_t new_extent_prefix;
    uint64_t adjusted_physical_start;
    uint64_t first_physical_start;
    size_t byte_count;
    size_t buffer_offset;
    int fd;

    if (match == NULL || delivery == NULL || delivery->bytes == NULL ||
        physical_end <= physical_start ||
        physical_start < delivery->range_start ||
        match->physical_row >= g_hfsplus_compact_stats.physical_count ||
        match->fork_row >= g_hfsplus_assembly_fork_count ||
        g_hfsplus_assembly_fork_done[match->fork_row]) return 0;
    if (metadata_index_reader_get_fork_by_row(
            g_hfsplus_compact_reader, match->fork_row, &fork) != 0 ||
        fork.fork_kind != METADATA_INDEX_FORK_DATA ||
        (fork.flags & METADATA_INDEX_FORK_FLAG_COMPLETE) == 0U ||
        fork.logical_size == 0U ||
        metadata_index_reader_reconstruct_path(
            g_hfsplus_compact_reader, match->object_key,
            catalog_path, sizeof(catalog_path)) != 0 ||
        !hfsplus_path_matches_active_format_local(catalog_path)) return 0;

    current_extent_offset = physical_start - match->physical_start;
    previous_extent_prefix =
        g_hfsplus_assembly_extent_prefix[match->physical_row];
    new_extent_prefix = physical_end - match->physical_start;
    if (new_extent_prefix <= previous_extent_prefix) return 0;
    if (current_extent_offset > previous_extent_prefix) {
        /* A manual jump entered in the middle of this extent.  Keep measuring
         * it, but never present the resulting sparse part as a complete file. */
        g_hfsplus_assembly_fork_done[match->fork_row] = 2U;
        return 0;
    }
    adjusted_physical_start = match->physical_start + previous_extent_prefix;
    if (adjusted_physical_start < physical_start) {
        adjusted_physical_start = physical_start;
    }
    logical_offset = match->logical_position +
        (adjusted_physical_start - physical_start);
    if (logical_offset >= fork.logical_size) return 0;
    byte_count_u64 = physical_end - adjusted_physical_start;
    if (byte_count_u64 > fork.logical_size - logical_offset) {
        byte_count_u64 = fork.logical_size - logical_offset;
    }
    if (byte_count_u64 == 0U || byte_count_u64 > SIZE_MAX ||
        adjusted_physical_start - delivery->range_start > SIZE_MAX) return 0;
    byte_count = (size_t)byte_count_u64;
    buffer_offset =
        (size_t)(adjusted_physical_start - delivery->range_start);

    if (snprintf(parts_dir, sizeof(parts_dir),
                 "%s/%s/metadata/hfs_assembly_parts/g%06llu",
                 g_hfsplus_output_dir, APP_STATE_DIR_NAME,
                 (unsigned long long)metadata_index_reader_generation(
                     g_hfsplus_compact_reader)) >= (int)sizeof(parts_dir) ||
        !g_hfsplus_assembly_parts_ready ||
        snprintf(part_path, sizeof(part_path), "%s/f%08u.part",
                 parts_dir, match->fork_row) >= (int)sizeof(part_path)) {
        g_hfsplus_assembly_write_failures++;
        return 0;
    }
    fd = open(part_path, O_WRONLY | O_CREAT, 0666);
    if (fd < 0 || !hfsplus_write_all_at_local(
            fd, delivery->bytes + buffer_offset, byte_count, logical_offset)) {
        if (fd >= 0) (void)close(fd);
        g_hfsplus_assembly_write_failures++;
        return 0;
    }
    (void)close(fd);
    g_hfsplus_assembly_intersections++;
    g_hfsplus_assembly_bytes_written += byte_count_u64;
    g_hfsplus_assembly_extent_prefix[match->physical_row] = new_extent_prefix;
    if (UINT64_MAX - g_hfsplus_assembly_fork_bytes[match->fork_row] <
        byte_count_u64) {
        g_hfsplus_assembly_fork_bytes[match->fork_row] = UINT64_MAX;
    } else {
        g_hfsplus_assembly_fork_bytes[match->fork_row] += byte_count_u64;
    }
    if (g_hfsplus_assembly_fork_bytes[match->fork_row] < fork.logical_size) {
        hfsplus_sequential_journal_append_local(
            match,
            new_extent_prefix,
            g_hfsplus_assembly_fork_bytes[match->fork_row],
            0U
        );
        return 0;
    }

    fd = open(part_path, O_WRONLY);
    if (fd < 0 || fork.logical_size > (uint64_t)LLONG_MAX ||
        ftruncate(fd, (off_t)fork.logical_size) != 0) {
        if (fd >= 0) (void)close(fd);
        g_hfsplus_assembly_write_failures++;
        return 0;
    }
    (void)close(fd);
    if (!build_output_path_from_relative_local(
            base_path, sizeof(base_path), catalog_path) ||
        !build_unique_path_from_base_local(
            final_path, sizeof(final_path), base_path, NULL) ||
        !ensure_parent_dirs_for_path_local(final_path) ||
        rename(part_path, final_path) != 0) {
        g_hfsplus_assembly_write_failures++;
        hfsplus_sequential_journal_append_local(
            match,
            new_extent_prefix,
            g_hfsplus_assembly_fork_bytes[match->fork_row],
            0U
        );
        return 0;
    }
    (void)mft_apply_output_owner_to_path(final_path);
    g_hfsplus_assembly_fork_done[match->fork_row] = 1U;
    g_hfsplus_assembly_files_completed++;
    hfsplus_sequential_journal_append_local(
        match,
        new_extent_prefix,
        g_hfsplus_assembly_fork_bytes[match->fork_row],
        1U
    );
    hfsplus_backend_note_recovered_output(
        final_path,
        metadata_index_reader_get_fork_first_physical(
            g_hfsplus_compact_reader,
            match->fork_row,
            &first_physical_start) == 0 &&
            first_physical_start <= (uint64_t)LLONG_MAX
                ? (long long)first_physical_start
                : (long long)match->physical_start
    );
    return 0;
}

void hfsplus_backend_observe_sequential_bytes(
    uint64_t range_start,
    const unsigned char *bytes,
    size_t byte_count)
{
    double now;
    HfsPlusSequentialDeliveryLocal delivery;
    uint64_t range_end;

    if (!hfsplus_compact_available_local() || bytes == NULL || byte_count == 0U ||
        (uint64_t)byte_count > UINT64_MAX - range_start) return;
    range_end = range_start + (uint64_t)byte_count;
    if (!hfsplus_create_extent_meter_local()) {
        return;
    }
    delivery.range_start = range_start;
    delivery.bytes = bytes;
    (void)hfsplus_sequential_assembly_init_local();
    if (metadata_index_sequential_meter_observe_with_delivery(
            g_hfsplus_extent_meter,
            range_start,
            range_end,
            g_hfsplus_assembly_disabled ? NULL : hfsplus_sequential_delivery_local,
            &delivery) != 0) {
        return;
    }
    now = monotonic_seconds_local();
    if (g_hfsplus_extent_meter_last_publish_at <= 0.0 ||
        now - g_hfsplus_extent_meter_last_publish_at >=
            HFSPLUS_EXTENT_MEASUREMENT_PUBLISH_INTERVAL_SECONDS) {
        (void)hfsplus_write_extent_measurement_local("active");
        g_hfsplus_extent_meter_last_publish_at = now;
    }
}

/* Materialize Catalog objects that do not consume source bytes, then restore
 * additional hard-link names for data forks already assembled by the primary
 * scan.  This deliberately runs only for the explicit all-Catalog policy and
 * never rereads the source. */
static void hfsplus_materialize_metadata_only_objects_local(void)
{
    uint64_t row;

    if (!g_hfsplus_assemble_all_catalog_files ||
        g_hfsplus_compact_reader == NULL) return;

    for (row = 0ULL; row < g_hfsplus_compact_stats.object_count; ++row) {
        MetadataIndexObject object = {0};
        char catalog_path[HFSPLUS_PATH_MAX];
        char output_path[HFSPLUS_PATH_MAX];

        if (metadata_index_reader_get_object_by_row(
                g_hfsplus_compact_reader, row, &object) != 0 ||
            (object.flags & METADATA_INDEX_OBJECT_FLAG_PATH_COMPLETE) == 0U ||
            (object.flags & (METADATA_INDEX_OBJECT_FLAG_ROOT |
                             METADATA_INDEX_OBJECT_FLAG_INTERNAL_METADATA)) != 0U ||
            metadata_index_reader_reconstruct_path(
                g_hfsplus_compact_reader, object.object_key,
                catalog_path, sizeof(catalog_path)) != 0 ||
            !build_output_path_from_relative_local(
                output_path, sizeof(output_path), catalog_path)) {
            continue;
        }
        if ((object.flags & METADATA_INDEX_OBJECT_FLAG_DIRECTORY) != 0U) {
            struct stat status;
            int existed = stat(output_path, &status) == 0 && S_ISDIR(status.st_mode);

            if (ensure_directory_path_local(output_path) && !existed) {
                g_hfsplus_assembly_directories++;
            }
            continue;
        }
        if ((object.flags & (METADATA_INDEX_OBJECT_FLAG_HARDLINK_PLACEHOLDER |
                             METADATA_INDEX_OBJECT_FLAG_HARDLINK_BACKING)) != 0U ||
            object.fork_count == 0U ||
            object.first_fork_row == METADATA_INDEX_NO_ROW) {
            continue;
        }
        {
            MetadataIndexFork fork = {0};

            if (metadata_index_reader_get_fork_by_row(
                    g_hfsplus_compact_reader,
                    object.first_fork_row, &fork) != 0 ||
                fork.fork_kind != METADATA_INDEX_FORK_DATA ||
                (fork.flags & METADATA_INDEX_FORK_FLAG_COMPLETE) == 0U ||
                fork.logical_size != 0U) {
                continue;
            }
            /* A zero-byte Catalog object has no customer bytes to recover.
             * Keep its identity in the compact metadata index, but do not
             * explode a raw-all result tree with hundreds of thousands of
             * empty system/application files. */
            g_hfsplus_assembly_empty_files_deferred++;
        }
    }

    for (row = 0ULL; row < g_hfsplus_compact_stats.object_count; ++row) {
        MetadataIndexObject alias = {0};
        MetadataIndexObject backing = {0};
        MetadataIndexFork backing_fork = {0};
        char alias_catalog_path[HFSPLUS_PATH_MAX];
        char alias_output_path[HFSPLUS_PATH_MAX];
        char backing_output_path[HFSPLUS_PATH_MAX];
        uint64_t first_physical = 0ULL;
        int reconciled = 0;

        if (metadata_index_reader_get_object_by_row(
                g_hfsplus_compact_reader, row, &alias) != 0 ||
            (alias.flags & METADATA_INDEX_OBJECT_FLAG_HARDLINK_PLACEHOLDER) == 0U ||
            alias.source_reference == METADATA_INDEX_REFERENCE_UNKNOWN ||
            metadata_index_reader_get_object(
                g_hfsplus_compact_reader, alias.source_reference, &backing) != 0 ||
            backing.fork_count == 0U ||
            backing.first_fork_row == METADATA_INDEX_NO_ROW ||
            metadata_index_reader_get_fork_by_row(
                g_hfsplus_compact_reader,
                backing.first_fork_row, &backing_fork) != 0 ||
            backing_fork.fork_kind != METADATA_INDEX_FORK_DATA ||
            backing_fork.logical_size == 0U ||
            (backing_fork.flags & METADATA_INDEX_FORK_FLAG_COMPLETE) == 0U ||
            metadata_index_reader_reconstruct_path(
                g_hfsplus_compact_reader, alias.object_key,
                alias_catalog_path, sizeof(alias_catalog_path)) != 0 ||
            !build_output_path_from_relative_local(
                alias_output_path, sizeof(alias_output_path),
                alias_catalog_path) ||
            file_exists_local(alias_output_path) ||
            metadata_index_reader_get_fork_first_physical(
                g_hfsplus_compact_reader,
                backing.first_fork_row, &first_physical) != 0) {
            continue;
        }
        backing_output_path[0] = '\0';
        if (first_physical <= (uint64_t)LLONG_MAX) {
            (void)hfsplus_backend_get_recovered_output_info(
                (long long)first_physical,
                backing_output_path,
                sizeof(backing_output_path),
                &reconciled);
        }
        if (backing_output_path[0] == '\0' ||
            !file_exists_local(backing_output_path) ||
            !ensure_parent_dirs_for_path_local(alias_output_path)) {
            continue;
        }
        if (link(backing_output_path, alias_output_path) != 0 &&
            !hfsplus_copy_file_local(backing_output_path, alias_output_path)) {
            g_hfsplus_assembly_write_failures++;
            continue;
        }
        (void)mft_apply_output_owner_to_path(alias_output_path);
        g_hfsplus_assembly_hardlinks++;
        g_hfsplus_assembly_files_completed++;
    }
}

void hfsplus_backend_finish_sequential_measurement(int completed_full_scan)
{
    MetadataIndexSequentialStats stats;

    /* Finalize-only resume has no live scanner to lazily create the meter.
     * Rehydrate it from the compact index and saved coverage so a resumed
     * run can publish the same truthful final verdict as the original child. */
    if (g_hfsplus_extent_meter == NULL &&
        !hfsplus_create_extent_meter_local()) {
        return;
    }
    if (completed_full_scan) {
        g_hfsplus_extent_measurement_completed = 1;
        hfsplus_materialize_metadata_only_objects_local();
    }
    (void)hfsplus_write_extent_measurement_local(
        completed_full_scan ? "complete" : "checkpoint");
    metadata_index_sequential_meter_get_stats(g_hfsplus_extent_meter, &stats);
    log_info(
        "HFS+ sequential extent measurement: observed=%.2f GiB extents=%llu/%llu complete forks=%llu/%llu complete empty=%llu incomplete_runlist=%llu delivery=%.2f GiB status=%s",
        (double)stats.source_bytes_observed / (1024.0 * 1024.0 * 1024.0),
        (unsigned long long)stats.extents_complete,
        (unsigned long long)stats.extents_total,
        (unsigned long long)stats.forks_complete,
        (unsigned long long)stats.forks_total,
        (unsigned long long)stats.forks_empty_complete,
        (unsigned long long)stats.forks_incomplete_runlist,
        (double)stats.extent_delivery_bytes / (1024.0 * 1024.0 * 1024.0),
        completed_full_scan ? "complete" : "checkpoint");
    log_info(
        "HFS+ primary-buffer metadata assembly: files=%llu empty_written=%llu empty_deferred=%llu hardlinks=%llu directories=%llu bytes=%.2f GiB intersections=%llu write_failures=%llu policy=%s raw_selected_formats=%s",
        (unsigned long long)g_hfsplus_assembly_files_completed,
        (unsigned long long)g_hfsplus_assembly_empty_files,
        (unsigned long long)g_hfsplus_assembly_empty_files_deferred,
        (unsigned long long)g_hfsplus_assembly_hardlinks,
        (unsigned long long)g_hfsplus_assembly_directories,
        (double)g_hfsplus_assembly_bytes_written /
            (1024.0 * 1024.0 * 1024.0),
        (unsigned long long)g_hfsplus_assembly_intersections,
        (unsigned long long)g_hfsplus_assembly_write_failures,
        g_hfsplus_assemble_all_catalog_files
            ? "all_complete_catalog_data_forks"
            : "selected_raw_formats",
        g_hfsplus_active_formats[0] != '\0'
            ? g_hfsplus_active_formats
            : "all"
    );
}

int hfsplus_backend_range_has_trusted_metadata_owner(
    uint64_t range_start,
    uint64_t range_end)
{
    MetadataIndexPhysicalMatch match = {0};
    MetadataIndexFork fork = {0};
    size_t match_count = 0U;
    int lookup_result;

    if (g_hfsplus_compact_reader == NULL || range_end <= range_start) {
        return 0;
    }
    lookup_result = metadata_index_reader_lookup_physical(
        g_hfsplus_compact_reader,
        range_start,
        &match,
        &match_count
    );
    if (lookup_result != 1 ||
        match_count == 0U ||
        match.physical_start > range_start ||
        match.physical_end < range_end ||
        metadata_index_reader_get_fork_by_row(
            g_hfsplus_compact_reader,
            match.fork_row,
            &fork) != 0) {
        return 0;
    }
    return fork.fork_kind == METADATA_INDEX_FORK_DATA &&
           (fork.flags & METADATA_INDEX_FORK_FLAG_COMPLETE) != 0U;
}

int hfsplus_backend_get_candidate_context(
    uint64_t physical_offset,
    MetadataIndexCandidateContext *context_out)
{
    if (context_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(context_out, 0, sizeof(*context_out));
    if (g_hfsplus_compact_reader == NULL) return 0;
    return metadata_index_reader_get_candidate_context(
        g_hfsplus_compact_reader,
        physical_offset,
        context_out);
}

int hfsplus_backend_finalize_recovered_outputs(void)
{
    if (g_hfsplus_compact_only && hfsplus_compact_available_local()) {
        double started_at = monotonic_seconds_local();
        double budget_seconds =
            g_hfsplus_finalize_budget_seconds > 0.0
                ? g_hfsplus_finalize_budget_seconds
                : 90.0;
        double deadline_seconds = started_at + budget_seconds;
        int exhausted = 0;
        int changed = 0;
        int checkpoint_complete = 0;
        int reconcile_complete = 0;
        int outputs_flushed = 1;
        int output_metadata_written = 0;
        size_t resume_output_index = 0U;
        size_t next_output_index = 0U;
        size_t moved = 0U;

        if (load_compact_finalize_checkpoint_local(
                &resume_output_index,
                &checkpoint_complete)) {
            if (checkpoint_complete) {
                log_info(
                    "HFS+ compact finalize checkpoint reused: generation=%llu outputs=%zu named=%zu unresolved=%zu; no repeated reconcile needed",
                    (unsigned long long)metadata_index_reader_generation(
                        g_hfsplus_compact_reader),
                    g_hfsplus_recovered_output_count,
                    g_hfsplus_reconciled_output_count,
                    hfsplus_backend_unreconciled_output_count()
                );
                return 1;
            }
            log_info(
                "HFS+ compact finalize resuming at output %zu/%zu with %.1fs budget (%s)",
                resume_output_index,
                g_hfsplus_recovered_output_count,
                budget_seconds,
                g_hfsplus_finalize_budget_profile[0] != '\0'
                    ? g_hfsplus_finalize_budget_profile
                    : "default"
            );
        } else {
            resume_output_index = 0U;
            log_info(
                "HFS+ compact finalize starting with %.1fs budget (%s), outputs=%zu unresolved=%zu",
                budget_seconds,
                g_hfsplus_finalize_budget_profile[0] != '\0'
                    ? g_hfsplus_finalize_budget_profile
                    : "default",
                g_hfsplus_recovered_output_count,
                hfsplus_backend_unreconciled_output_count()
            );
        }

        log_set_working_activity("reconciling HFS+ results within bounded finalize budget");
        reset_pending_output_queue_local();
        enqueue_unreconciled_outputs_from_local(resume_output_index);
        next_output_index = resume_output_index;
        moved = reconcile_pending_output_queue_local(
            0U,
            1,
            deadline_seconds,
            &exhausted,
            &changed,
            &next_output_index
        );
        if (next_output_index < resume_output_index) {
            next_output_index = resume_output_index;
        }
        reconcile_complete = exhausted && pending_output_queue_depth_local() == 0U;
        mft_spool_publish_backend_counts(
            (uint64_t)g_hfsplus_recovered_output_count,
            (uint64_t)g_hfsplus_reconciled_output_count,
            (uint64_t)hfsplus_backend_unreconciled_output_count()
        );
        if (monotonic_seconds_local() < deadline_seconds &&
            hfsplus_create_extent_meter_local()) {
            (void)hfsplus_sequential_assembly_init_local();
            (void)hfsplus_write_extent_measurement_local("checkpoint");
        }
        if (g_hfsplus_recovered_outputs_log_needs_rewrite) {
            outputs_flushed = rewrite_recovered_outputs_log_local();
        }
        if (reconcile_complete &&
            monotonic_seconds_local() < deadline_seconds) {
            output_metadata_written =
                write_recovered_output_metadata_outcomes_local();
        } else if (reconcile_complete) {
            log_info(
                "HFS+ compact finalize deferred the full recovered-output metadata artifact after reaching its %.1fs budget; the next resume continues at the artifact step",
                budget_seconds
            );
        }
        if (g_hfsplus_journal_names_recovered_current > 0ULL) {
            moved += (size_t)g_hfsplus_journal_names_recovered_current;
            log_info(
                "Included %llu safe HFS+ journal name recovery move(s) in compact finalize totals",
                (unsigned long long)g_hfsplus_journal_names_recovered_current);
            mft_spool_publish_backend_counts(
                (uint64_t)g_hfsplus_recovered_output_count,
                (uint64_t)g_hfsplus_reconciled_output_count,
                (uint64_t)hfsplus_backend_unreconciled_output_count());
        }
        if (reconcile_complete && !output_metadata_written) {
            log_info(
                "HFS+ compact finalize could not write recovered-output metadata outcomes; recovery results are unaffected"
            );
        }
        if (reconcile_complete && output_metadata_written &&
            monotonic_seconds_local() < deadline_seconds &&
            !write_unresolved_output_audit_local()) {
            log_info(
                "HFS+ compact finalize could not write unresolved-output audit; recovery results are unaffected"
            );
        }
        (void)write_finalize_status_local(
            "output_reconcile",
            reconcile_complete && outputs_flushed && output_metadata_written
                ? "ready"
                : "partial",
            moved,
            1,
            outputs_flushed,
            output_metadata_written,
            reconcile_complete
                ? g_hfsplus_recovered_output_count
                : next_output_index,
            monotonic_seconds_local() - started_at,
            0.0,
            0.0,
            monotonic_seconds_local() - started_at
        );
        log_info(
            "HFS+ compact finalize: status=%s cursor=%zu/%zu recovered=%zu named=%zu embedded=%llu unresolved=%zu moved=%zu budget=%.1fs total=%.2fs",
            reconcile_complete ? "complete" : "budget_exhausted",
            reconcile_complete
                ? g_hfsplus_recovered_output_count
                : next_output_index,
            g_hfsplus_recovered_output_count,
            g_hfsplus_recovered_output_count,
            g_hfsplus_reconciled_output_count,
            (unsigned long long)g_hfsplus_embedded_output_count,
            hfsplus_backend_unreconciled_output_count(),
            moved,
            budget_seconds,
            monotonic_seconds_local() - started_at
        );
        return outputs_flushed;
    }
    return finalize_state_local(
        "reconciling HFS+ outputs",
        "output_reconcile",
        "HFS+ finalize"
    );
}

void hfsplus_backend_set_finalize_opportunistic_budget_seconds(
    double seconds,
    const char *profile_label
)
{
    g_hfsplus_finalize_budget_seconds = seconds > 0.0 ? seconds : 0.0;
    snprintf(
        g_hfsplus_finalize_budget_profile,
        sizeof(g_hfsplus_finalize_budget_profile),
        "%s",
        profile_label != NULL && profile_label[0] != '\0'
            ? profile_label
            : "default"
    );
}

void hfsplus_backend_reconcile_recovered_outputs_live(void)
{
    double reconcile_started_at;
    double deadline_seconds;
    size_t max_candidates;
    int exhausted = 0;
    int changed = 0;

    if (!hfsplus_metadata_ready_local() ||
        pending_output_queue_depth_local() == 0U) {
        return;
    }
    reconcile_started_at = monotonic_seconds_local();
    if (hfsplus_live_reconcile_should_pause_local(reconcile_started_at)) {
        return;
    }
    max_candidates = hfsplus_live_reconcile_batch_limit_local();
    deadline_seconds =
        reconcile_started_at + hfsplus_live_reconcile_budget_seconds_local();

    g_hfsplus_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_NAMING;
    (void)reconcile_pending_output_queue_local(
        max_candidates,
        1,
        deadline_seconds,
        &exhausted,
        &changed,
        NULL
    );
    g_hfsplus_live_last_reconcile_at = monotonic_seconds_local();
    if (changed &&
        g_hfsplus_recovered_outputs_log_needs_rewrite &&
        (exhausted ||
         g_hfsplus_live_last_rewrite_at <= 0.0 ||
         g_hfsplus_live_last_reconcile_at - g_hfsplus_live_last_rewrite_at >=
             HFSPLUS_LIVE_RECONCILE_REWRITE_INTERVAL_SECONDS)) {
        if (rewrite_recovered_outputs_log_local()) {
            g_hfsplus_live_last_rewrite_at = monotonic_seconds_local();
        }
    }
    g_hfsplus_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;
}

void hfsplus_backend_set_background_conservative(int enabled)
{
    g_hfsplus_live_background_conservative = enabled ? 1 : 0;
}

int hfsplus_backend_background_is_conservative(void)
{
    return g_hfsplus_live_background_conservative;
}

void hfsplus_backend_note_foreground_activity(void)
{
    g_hfsplus_live_last_foreground_activity_at = monotonic_seconds_local();
}

void hfsplus_backend_refresh_recovery_state(size_t *entry_count_snapshot)
{
    if (entry_count_snapshot != NULL) {
        *entry_count_snapshot = hfsplus_backend_entry_count();
    }
}
