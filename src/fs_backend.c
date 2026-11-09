/*
 * fs_backend.c
 * Thin filesystem-backend facade used by the rest of the app.
 *
 * Right now the active backend is NTFS/MFT-driven, but this layer keeps
 * the higher-level app code talking to one stable interface for geometry,
 * naming/finalize operations, and background worker control.
 */

#define _POSIX_C_SOURCE 200809L

#include "fs_backend.h"

#include "carver_output.h"
#include "config.h"
#include "exfat_backend.h"
#include "hfsplus_backend.h"
#include "mft_background.h"
#include "mft_engine.h"
#include "mft_probe_parser.h"
#include "mft_spool.h"
#include "scanner.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define FS_BACKEND_OUTPUT_MOUNT_GRACE_SECONDS 5U

/*
 * Keep this local declaration so fs_backend.c stays buildable even if another
 * machine is momentarily on an older hfsplus_backend.h during cross-machine
 * iteration.
 */
void exfat_backend_set_output_dir(const char *output_dir);
int exfat_backend_prepare_index(void);
int exfat_backend_load_recovered_output_state(void);
void exfat_backend_get_live_stats(MftSpoolLiveStats *out);
void exfat_backend_reconcile_recovered_outputs_live(void);
void hfsplus_backend_set_output_dir(const char *output_dir);
void mft_set_output_dir(const char *output_dir);
int hfsplus_backend_prepare_index(void);
int hfsplus_backend_load_recovered_output_state(void);
void hfsplus_backend_get_live_stats(MftSpoolLiveStats *out);
void hfsplus_backend_reconcile_recovered_outputs_live(void);
void hfsplus_backend_set_background_conservative(int enabled);
int hfsplus_backend_background_is_conservative(void);
void hfsplus_backend_note_foreground_activity(void);
int hfsplus_backend_should_attempt_metadata_acquisition(int phase);
int hfsplus_backend_run_metadata_acquisition(int phase);
int hfsplus_backend_write_selected_tree_ddrescue_domain(
    const char *input_path,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
);

#ifndef FS_BACKEND_HAVE_SALVAGE_API
typedef struct {
    size_t candidate_records;
    size_t whole_records;
    size_t partial_records;
    size_t broken_records;
} FsBackendRecordSalvageStats;

typedef struct {
    int has_entry;
    int created_time_available;
    int exact_start_match;
    int has_name;
    int contextual_complete;
    int flat_name_exact_family;
    int flat_name_preserve_extension;
} FsRecoveredNamingHint;
#endif

static FsBackendKind g_fs_backend_kind = FS_BACKEND_KIND_NTFS;
static char g_fs_backend_output_dir[PATH_MAX_LEN] = "";
static int g_fs_backend_force_ntfs_target = 0;
static int g_fs_backend_force_hfsplus_target = 0;
static FsBackendMetadataStatus g_fs_backend_last_non_ntfs_metadata_status =
    FS_BACKEND_METADATA_STATUS_NONE;
static size_t g_fs_backend_last_non_ntfs_recovered_count = 0U;

static int file_exists_local(const char *path)
{
    struct stat st;

    return path != NULL && path[0] != '\0' && stat(path, &st) == 0;
}

static int output_mount_root_from_path_local(
    const char *path,
    char *out_root,
    size_t out_root_size
)
{
    if (out_root != NULL && out_root_size > 0U) {
        out_root[0] = '\0';
    }
    if (path == NULL || path[0] == '\0' || out_root == NULL || out_root_size == 0U) {
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

static int parent_path_local(
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
    if (path == NULL || path[0] == '\0' || out_parent == NULL || out_parent_size == 0U) {
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

static int output_mount_root_is_live_local(const char *mount_root)
{
    char parent[PATH_MAX_LEN];
    struct stat mount_st;
    struct stat parent_st;

    if (mount_root == NULL ||
        mount_root[0] == '\0' ||
        stat(mount_root, &mount_st) != 0 ||
        !S_ISDIR(mount_st.st_mode) ||
        !parent_path_local(mount_root, parent, sizeof(parent)) ||
        stat(parent, &parent_st) != 0) {
        return 0;
    }

    return mount_st.st_dev != parent_st.st_dev;
}

int fs_backend_output_path_write_guard_allows(const char *path)
{
    char mount_root[PATH_MAX_LEN];
    unsigned int waited_seconds;

    if (!output_mount_root_from_path_local(path, mount_root, sizeof(mount_root))) {
        return 1;
    }
    if (output_mount_root_is_live_local(mount_root)) {
        return 1;
    }
    for (waited_seconds = 0U;
         waited_seconds < FS_BACKEND_OUTPUT_MOUNT_GRACE_SECONDS;
         waited_seconds++) {
        sleep(1);
        if (output_mount_root_is_live_local(mount_root)) {
            return 1;
        }
    }
    return 0;
}

static int fopen_mode_may_write_local(const char *mode)
{
    const char *cursor;

    if (mode == NULL || mode[0] == '\0') {
        return 0;
    }
    for (cursor = mode; *cursor != '\0'; ++cursor) {
        if (*cursor == 'w' || *cursor == 'a' || *cursor == '+') {
            return 1;
        }
    }
    return 0;
}

FILE *fs_backend_fopen_output_write_guarded(const char *path, const char *mode)
{
    if (fopen_mode_may_write_local(mode) &&
        !fs_backend_output_path_write_guard_allows(path)) {
        return NULL;
    }

    return fopen(path, mode);
}

static int build_state_child_path_local(
    char *out_path,
    size_t out_size,
    const char *name
)
{
    if (out_path == NULL ||
        out_size == 0U ||
        g_fs_backend_output_dir[0] == '\0' ||
        name == NULL ||
        name[0] == '\0') {
        return 0;
    }

    return snprintf(
               out_path,
               out_size,
               "%s/%s/%s",
               g_fs_backend_output_dir,
               APP_STATE_DIR_NAME,
               name) < (int)out_size;
}

static void query_hfsplus_artifact_state_local(
    FsBackendArtifactPhase phase,
    FsBackendArtifactState *out_state
)
{
    char snapshot_path[PATH_MAX_LEN];
    char outputs_path[PATH_MAX_LEN];
    char finalize_path[PATH_MAX_LEN];
    FILE *file = NULL;

    if (out_state == NULL) {
        return;
    }

    if (hfsplus_backend_entry_count() > 0U ||
        (build_state_child_path_local(
             snapshot_path,
             sizeof(snapshot_path),
             "hfsplus_metadata_snapshot.bin") &&
         file_exists_local(snapshot_path))) {
        out_state->metadata_snapshot_ready = 1;
    }

    if (hfsplus_backend_recovered_output_count() > 0U ||
        (build_state_child_path_local(
             outputs_path,
             sizeof(outputs_path),
             "recovered_outputs.tsv") &&
         file_exists_local(outputs_path))) {
        out_state->recovered_output_log_ready = 1;
    }

    out_state->recovered_outputs = hfsplus_backend_recovered_output_count();
    out_state->named_outputs = hfsplus_backend_named_output_count();

    if (hfsplus_backend_entry_count() > 0U) {
        out_state->pending_outputs = hfsplus_backend_unreconciled_output_count();
    }

    if (!build_state_child_path_local(
            finalize_path,
            sizeof(finalize_path),
            "hfsplus_finalize_status.txt")) {
        goto phase_ready;
    }

    file = fopen(finalize_path, "r");
    if (file != NULL) {
        char line[256];
        int status_ready = 0;
        int have_status = 0;
        size_t pending_from_file = 0U;
        size_t cursor_from_file = 0U;
        size_t recovered_from_file = 0U;
        size_t named_from_file = 0U;

        out_state->finalize_status_present = 1;
        while (fgets(line, sizeof(line), file) != NULL) {
            if (strncmp(line, "status=", 7) == 0) {
                have_status = 1;
                status_ready = strncmp(line + 7, "ready", 5) == 0;
            } else if (strncmp(line, "pending_outputs=", 16) == 0) {
                unsigned long long value = 0ULL;

                if (sscanf(line + 16, "%llu", &value) == 1) {
                    pending_from_file = (size_t)value;
                }
            } else if (strncmp(line, "next_output_index=", 18) == 0) {
                unsigned long long value = 0ULL;

                if (sscanf(line + 18, "%llu", &value) == 1) {
                    cursor_from_file = (size_t)value;
                }
            } else if (strncmp(line, "recovered_outputs=", 18) == 0) {
                unsigned long long value = 0ULL;

                if (sscanf(line + 18, "%llu", &value) == 1) {
                    recovered_from_file = (size_t)value;
                }
            } else if (strncmp(line, "named_outputs=", 14) == 0) {
                unsigned long long value = 0ULL;

                if (sscanf(line + 14, "%llu", &value) == 1) {
                    named_from_file = (size_t)value;
                }
            }
        }
        fclose(file);
        file = NULL;
        if (have_status) {
            out_state->finalize_state_ready = status_ready ? 1 : 0;
        }
        if (out_state->finalize_state_ready &&
            hfsplus_backend_recovered_output_count() > 0U &&
            (recovered_from_file != hfsplus_backend_recovered_output_count() ||
             named_from_file != hfsplus_backend_named_output_count())) {
            /* New outputs were added after this status file was written.
             * Treat the old ready marker as a checkpoint, not completion. */
            out_state->finalize_state_ready = 0;
        }
        if (out_state->pending_outputs == 0U) {
            out_state->pending_outputs = pending_from_file;
        }
        out_state->finalize_next_output_index = cursor_from_file;
        if (out_state->recovered_outputs == 0U) {
            out_state->recovered_outputs = recovered_from_file;
        }
        if (out_state->named_outputs == 0U) {
            out_state->named_outputs = named_from_file;
        }
    }

phase_ready:
    switch (phase) {
        case FS_BACKEND_ARTIFACT_PHASE_FINALIZE_RESUME:
        case FS_BACKEND_ARTIFACT_PHASE_NAME_RESUME:
            out_state->ready_for_phase =
                out_state->finalize_state_ready ||
                (out_state->metadata_snapshot_ready &&
                 out_state->recovered_output_log_ready);
            break;
        case FS_BACKEND_ARTIFACT_PHASE_SCAN_RESUME:
        default:
            out_state->ready_for_phase =
                out_state->metadata_snapshot_ready ||
                out_state->finalize_state_ready;
            break;
    }
}

static void query_exfat_artifact_state_local(
    FsBackendArtifactPhase phase,
    FsBackendArtifactState *out_state
)
{
    char outputs_path[PATH_MAX_LEN];

    (void)phase;
    if (out_state == NULL) {
        return;
    }

    if (exfat_backend_entry_count() > 0U) {
        out_state->metadata_snapshot_ready = 1;
        out_state->pending_outputs = exfat_backend_unreconciled_output_count();
    }
    if (exfat_backend_recovered_output_count() > 0U ||
        (build_state_child_path_local(
             outputs_path,
             sizeof(outputs_path),
             "recovered_outputs.tsv") &&
         file_exists_local(outputs_path))) {
        out_state->recovered_output_log_ready = 1;
    }
    out_state->ready_for_phase =
        out_state->metadata_snapshot_ready ||
        out_state->recovered_output_log_ready;
}

static void query_ntfs_artifact_state_local(
    FsBackendArtifactPhase phase,
    FsBackendArtifactState *out_state
)
{
    char outputs_path[PATH_MAX_LEN];
    MftSpoolLiveStats live_stats = {0};
    int saved_mft_ready;
    int saved_spool_ready;
    int ready_for_phase = 0;
    uint64_t pending_outputs = 0ULL;
    size_t i30_name_count = 0U;

    if (out_state == NULL) {
        return;
    }

    saved_mft_ready = mft_engine_saved_mft_map_available();
    saved_spool_ready = mft_engine_saved_spool_artifacts_available();
    i30_name_count = mft_engine_i30_name_count();
    mft_spool_get_live_stats(&live_stats);
    out_state->metadata_snapshot_ready = saved_mft_ready ? 1 : 0;
    out_state->finalize_status_present =
        (saved_mft_ready || saved_spool_ready) ? 1 : 0;
    out_state->finalize_state_ready =
        (saved_mft_ready || saved_spool_ready) ? 1 : 0;
    if (live_stats.recovered_outputs_current > 0ULL) {
        pending_outputs = live_stats.unident_outputs_current;
        if (live_stats.repair_pending_outputs > pending_outputs) {
            pending_outputs = live_stats.repair_pending_outputs;
        }
    } else {
        pending_outputs = (uint64_t)fs_backend_unreconciled_output_count();
    }
    out_state->pending_outputs = (size_t)pending_outputs;
    if (fs_backend_recovered_output_count() > 0U ||
        (build_state_child_path_local(
             outputs_path,
             sizeof(outputs_path),
             "recovered_outputs.tsv") &&
         file_exists_local(outputs_path))) {
        out_state->recovered_output_log_ready = 1;
    }
    switch (phase) {
        case FS_BACKEND_ARTIFACT_PHASE_NAME_RESUME: {
            size_t required_record_rows = 128U;
            size_t required_range_rows = 64U;
            size_t required_i30_names = 16U;
            size_t recovered_outputs =
                (size_t)live_stats.recovered_outputs_current;

            /*
             * A saved non-empty mft_map plus recovered_outputs log is enough
             * to justify a real saved-artifact naming pass even before live
             * counters or rebuilt spool indices look healthy.
             */
            if (out_state->metadata_snapshot_ready &&
                out_state->recovered_output_log_ready) {
                ready_for_phase = 1;
                break;
            }
            if (mft_entry_count() > 0U && mft_has_primary_users_root()) {
                ready_for_phase = 1;
                break;
            }
            if (live_stats.named_outputs_current > 0U) {
                ready_for_phase = 1;
                break;
            }
            if (recovered_outputs > 0U) {
                size_t scaled_record_rows = recovered_outputs / 8U;
                size_t scaled_range_rows = recovered_outputs / 16U;

                if (scaled_record_rows > required_record_rows) {
                    required_record_rows = scaled_record_rows;
                }
                if (scaled_range_rows > required_range_rows) {
                    required_range_rows = scaled_range_rows;
                }
                if (required_record_rows > 4096U) {
                    required_record_rows = 4096U;
                }
                if (required_range_rows > 2048U) {
                    required_range_rows = 2048U;
                }
            }
            if (required_range_rows > required_i30_names) {
                required_i30_names = required_range_rows;
            }
            if (live_stats.record_index_count == 0U ||
                live_stats.range_index_count == 0U) {
                ready_for_phase =
                    mft_entry_count() > 0U &&
                    i30_name_count >= required_i30_names;
                break;
            }
            ready_for_phase =
                live_stats.record_index_count >= required_record_rows &&
                live_stats.range_index_count >= required_range_rows;
            if (!ready_for_phase &&
                mft_entry_count() > 0U &&
                i30_name_count >= required_i30_names) {
                ready_for_phase = 1;
            }
            break;
        }
        case FS_BACKEND_ARTIFACT_PHASE_FINALIZE_RESUME:
            ready_for_phase =
                out_state->metadata_snapshot_ready ||
                (mft_entry_count() > 0U && mft_has_primary_users_root()) ||
                (live_stats.record_index_count > 0U &&
                 live_stats.range_index_count > 0U);
            break;
        case FS_BACKEND_ARTIFACT_PHASE_SCAN_RESUME:
        default:
            ready_for_phase =
                out_state->metadata_snapshot_ready ||
                out_state->recovered_output_log_ready ||
                saved_spool_ready;
            break;
    }
    out_state->ready_for_phase = ready_for_phase;
}

static void copy_fs_scan_hint_from_mft(FsScanHint *out, const MftScanHint *in)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }
    out->exact_data_match = in->exact_data_match;
    out->inside_nonresident_run = in->inside_nonresident_run;
    out->inside_resident_record = in->inside_resident_record;
    out->record_number = in->record_number;
}

static void copy_fs_view_entry_from_mft(FsViewEntry *out, const MftViewEntry *in)
{
    size_t run_count;
    size_t i;

    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }

    out->abs_offset = in->abs_offset;
    out->data_size = in->data_size;
    out->allocated_size = in->allocated_size;
    out->flags = in->flags;
    out->has_data = in->has_data;
    out->is_resident = in->is_resident;
    out->run_truncated = in->run_truncated ? 1 : 0;
    run_count = in->run_count;
    if (run_count > FS_VIEW_MAX_RUNS) {
        run_count = FS_VIEW_MAX_RUNS;
        out->run_truncated = 1;
    }
    out->run_count = run_count;
    for (i = 0U; i < run_count; ++i) {
        out->runs[i].abs_offset = in->runs[i].abs_offset;
        out->runs[i].byte_length = in->runs[i].byte_length;
    }
    snprintf(out->path, sizeof(out->path), "%s", in->path);
    snprintf(out->name, sizeof(out->name), "%s", in->name);
}

static void copy_fs_process_stats_from_mft(
    FsBackendProcessStats *out,
    const MftProcessStats *in
)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }
    out->parsed_metadata_units = in->parsed_records;
    out->indexed_metadata_units = in->spooled_records;
    out->built_entries = in->built_entries;
    out->stored_entries = in->stored_entries;
    out->seconds_parse = in->seconds_parse;
    out->seconds_index = in->seconds_spool;
    out->seconds_build = in->seconds_build;
    out->seconds_store = in->seconds_store;
}

static void copy_fs_record_salvage_stats_from_mft(
    FsBackendRecordSalvageStats *out,
    const MftRecordSalvageStats *in
)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }
    out->candidate_records = in->candidate_records;
    out->whole_records = in->whole_records;
    out->partial_records = in->partial_records;
    out->broken_records = in->broken_records;
}

static void copy_fs_recovered_naming_hint_from_mft(
    FsRecoveredNamingHint *out,
    const MftRecoveredNamingHint *in
)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }
    out->has_entry = in->has_entry;
    out->created_time_available = in->created_time_available;
    out->exact_start_match = in->exact_start_match;
    out->size_available = in->size_available;
    out->exact_size_match = in->exact_size_match;
    out->size_close_match = in->size_close_match;
    out->header_time_available = in->header_time_available;
    out->header_time_close_match = in->header_time_close_match;
    out->has_name = in->has_name;
    out->contextual_complete = in->contextual_complete;
    out->flat_name_exact_family = in->flat_name_exact_family;
    out->flat_name_preserve_extension = in->flat_name_preserve_extension;
}

static void copy_fs_recovered_match_signals_from_mft(
    FsRecoveredMatchSignals *out,
    const MftRecoveredMatchSignals *in
)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }
    out->direct_anchor_match = in->direct_anchor_match;
    out->candidate_found = in->candidate_found;
    out->exact_size_match = in->exact_size_match;
    out->size_close_match = in->size_close_match;
    out->header_time_close_match = in->header_time_close_match;
    out->contextual_complete = in->contextual_complete;
    out->contextual_partial = in->contextual_partial;
    out->merged_candidate = in->merged_candidate;
    out->mft_only_candidate = in->mft_only_candidate;
    out->i30_only_candidate = in->i30_only_candidate;
}

static void copy_fs_name_candidate_index_stats_from_mft(
    FsNameCandidateIndexStats *out,
    const MftNameCandidateIndexStats *in
)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }

    out->total_candidates = in->total_candidates;
    out->merged_candidates = in->merged_candidates;
    out->mft_only_candidates = in->mft_only_candidates;
    out->i30_only_candidates = in->i30_only_candidates;
    out->direct_data_anchors = in->direct_data_anchors;
    out->complete_paths = in->complete_paths;
    out->partial_paths = in->partial_paths;
    out->named_candidates = in->named_candidates;
    out->nameless_candidates = in->nameless_candidates;
    out->mft_record_seq_present = in->mft_record_seq_present;
    out->mft_record_seq_missing = in->mft_record_seq_missing;
    out->unique_missing_parents = in->unique_missing_parents;
    out->top_missing_parent_record = in->top_missing_parent_record;
    out->top_missing_parent_blocked_candidates =
        in->top_missing_parent_blocked_candidates;
}

static void copy_fs_name_match_preview_stats_from_mft(
    FsNameMatchPreviewStats *out,
    const MftNameMatchPreviewStats *in
)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }

    out->total_outputs = in->total_outputs;
    out->matched_outputs = in->matched_outputs;
    out->unmatched_outputs = in->unmatched_outputs;
    out->context_complete_matches = in->context_complete_matches;
    out->context_partial_matches = in->context_partial_matches;
    out->parent_group_matches = in->parent_group_matches;
    out->flat_name_matches = in->flat_name_matches;
    out->hint_context_complete_matches = in->hint_context_complete_matches;
    out->hint_context_partial_matches = in->hint_context_partial_matches;
    out->hint_parent_group_matches = in->hint_parent_group_matches;
    out->hint_flat_name_matches = in->hint_flat_name_matches;
}

static void copy_fs_name_uniqueness_stats_from_mft(
    FsNameUniquenessStats *out,
    const MftNameUniquenessStats *in
)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }

    out->outputs_needing_name = in->outputs_needing_name;
    out->outputs_with_size = in->outputs_with_size;
    out->outputs_with_header_time = in->outputs_with_header_time;
    out->direct_anchor_outputs = in->direct_anchor_outputs;
    out->outputs_with_any_exact_size_candidate =
        in->outputs_with_any_exact_size_candidate;
    out->unique_exact_size_outputs = in->unique_exact_size_outputs;
    out->ambiguous_exact_size_outputs = in->ambiguous_exact_size_outputs;
    out->outputs_with_any_exact_size_time_candidate =
        in->outputs_with_any_exact_size_time_candidate;
    out->unique_exact_size_time_outputs = in->unique_exact_size_time_outputs;
    out->ambiguous_exact_size_time_outputs =
        in->ambiguous_exact_size_time_outputs;
}

static FsRecoveredMatchKind fs_recovered_match_kind_from_mft(
    MftRecoveredMatchKind kind
)
{
    switch (kind) {
        case MFT_RECOVERED_MATCH_CONTEXT_COMPLETE:
            return FS_RECOVERED_MATCH_CONTEXT_COMPLETE;
        case MFT_RECOVERED_MATCH_CONTEXT_PARTIAL:
            return FS_RECOVERED_MATCH_CONTEXT_PARTIAL;
        case MFT_RECOVERED_MATCH_PARENT_GROUP:
            return FS_RECOVERED_MATCH_PARENT_GROUP;
        case MFT_RECOVERED_MATCH_FLAT_NAME:
            return FS_RECOVERED_MATCH_FLAT_NAME;
        case MFT_RECOVERED_MATCH_HINT_CONTEXT_COMPLETE:
            return FS_RECOVERED_MATCH_HINT_CONTEXT_COMPLETE;
        case MFT_RECOVERED_MATCH_HINT_CONTEXT_PARTIAL:
            return FS_RECOVERED_MATCH_HINT_CONTEXT_PARTIAL;
        case MFT_RECOVERED_MATCH_HINT_PARENT_GROUP:
            return FS_RECOVERED_MATCH_HINT_PARENT_GROUP;
        case MFT_RECOVERED_MATCH_HINT_FLAT_NAME:
            return FS_RECOVERED_MATCH_HINT_FLAT_NAME;
        case MFT_RECOVERED_MATCH_NONE:
        default:
            return FS_RECOVERED_MATCH_NONE;
    }
}

static void copy_fs_live_stats_from_mft(
    FsBackendLiveStats *out,
    const MftSpoolLiveStats *in
)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    if (in == NULL) {
        return;
    }
    out->renamed_outputs = in->renamed_outputs;
    out->repaired_outputs = in->repaired_outputs;
    out->recovered_outputs_current = in->recovered_outputs_current;
    out->named_outputs_current = in->named_outputs_current;
    out->unident_outputs_current = in->unident_outputs_current;
    out->repair_pending_outputs = in->repair_pending_outputs;
    out->repair_queue_events = in->repair_queue_events;
    out->record_index_count = in->record_index_count;
    out->range_index_count = in->range_index_count;
    out->scan_stalled_seconds = in->scan_stalled_seconds;
    out->background_phase = in->background_phase;
    out->background_conservative = in->background_conservative;
}

static size_t copy_fs_view_entries_from_mft(
    MftViewEntry *mft_entries,
    size_t count,
    FsViewEntry **out_entries
)
{
    FsViewEntry *copy;
    size_t i;

    if (out_entries == NULL) {
        free(mft_entries);
        return 0U;
    }
    *out_entries = NULL;
    if (mft_entries == NULL || count == 0U) {
        free(mft_entries);
        return 0U;
    }

    copy = (FsViewEntry *)calloc(count, sizeof(*copy));
    if (copy == NULL) {
        free(mft_entries);
        return 0U;
    }

    for (i = 0U; i < count; ++i) {
        copy_fs_view_entry_from_mft(&copy[i], &mft_entries[i]);
    }

    free(mft_entries);
    *out_entries = copy;
    return count;
}

static int current_source_supports_ntfs_metadata(void)
{
    if (g_fs_backend_force_ntfs_target) {
        return 1;
    }
    return !mft_engine_source_is_definitely_non_ntfs();
}

static FsBackendMetadataStatus fs_backend_status_from_mft_status(MftEngineStatus status)
{
    switch (status) {
        case MFT_ENGINE_STATUS_OK:
            return FS_BACKEND_METADATA_STATUS_OK;
        case MFT_ENGINE_STATUS_FAILED:
            return FS_BACKEND_METADATA_STATUS_FAILED;
        case MFT_ENGINE_STATUS_INTERRUPTED:
            return FS_BACKEND_METADATA_STATUS_INTERRUPTED;
        case MFT_ENGINE_STATUS_NONE:
        default:
            return FS_BACKEND_METADATA_STATUS_NONE;
    }
}

static void populate_mft_engine_metadata_options(
    const FsBackendMetadataOptions *options,
    MftEngineUsersOptions *out
)
{
    if (out == NULL) {
        return;
    }

    memset(out, 0, sizeof(*out));
    if (options == NULL) {
        return;
    }

    out->categories_csv = options->categories_csv;
    out->formats_csv = options->formats_csv;
    out->dev_format = options->dev_format;
    out->compare_scope_csv = options->compare_scope_csv;
    out->record_list_path = options->record_list_path;
    out->root_scope_csv = options->root_scope_csv;
    out->root_scope_defaulted = options->root_scope_defaulted;
    out->date_filter_value = options->date_filter_value;
    out->deleted_filter_value = options->deleted_filter_value;
    out->folder_levels = options->folder_levels;
    out->start_offset = options->start_offset;
    out->start_offset_explicit = options->start_offset_explicit;
    out->generic_file_targets = options->generic_file_targets;
}

static MftContextualOutputMode to_mft_contextual_mode(FsContextualOutputMode mode)
{
    return mode == FS_CONTEXTUAL_OUTPUT_FULL_TREE
        ? MFT_CONTEXTUAL_OUTPUT_FULL_TREE
        : MFT_CONTEXTUAL_OUTPUT_USERS_ONLY;
}

static void populate_mft_engine_config(
    const FsBackendConfig *config,
    MftEngineConfig *out
)
{
    if (out == NULL) {
        return;
    }

    out->output_dir = config != NULL ? config->output_dir : NULL;
    out->service_id = config != NULL ? config->service_id : NULL;
    out->active_formats_csv =
        config != NULL ? config->active_formats_csv : NULL;
    out->contextual_output_mode = to_mft_contextual_mode(
        config != NULL ? config->contextual_output_mode : FS_CONTEXTUAL_OUTPUT_SELECTED_TREE
    );
    out->reset_existing_store = config != NULL ? config->reset_existing_store : 0;
    out->recover_img = config != NULL ? config->recover_img : 0;
    out->recover_vid = config != NULL ? config->recover_vid : 0;
    out->recover_doc = config != NULL ? config->recover_doc : 0;
    out->has_deleted_filter = config != NULL ? config->has_deleted_filter : 0;
    out->deleted_value = config != NULL ? config->deleted_value : 0;
    out->include_recycle_bin_with_live_filter =
        config != NULL ? config->include_recycle_bin_with_live_filter : 0;
    out->has_date_filter = config != NULL ? config->has_date_filter : 0;
    out->date_start_yyyymmdd = config != NULL ? config->date_start_yyyymmdd : 0;
    out->date_end_yyyymmdd = config != NULL ? config->date_end_yyyymmdd : 0;
    out->force_ntfs_target = config != NULL ? config->force_ntfs_target : 0;
}

void fs_backend_configure(const FsBackendConfig *config)
{
    MftEngineConfig mft_config = {0};

    g_fs_backend_force_ntfs_target =
        config != NULL && config->force_ntfs_target ? 1 : 0;
    g_fs_backend_force_hfsplus_target =
        config != NULL && config->force_hfsplus_target ? 1 : 0;

    /*
     * Translate app-facing backend settings into the narrower MFT-engine
     * configuration and remember which backend family is active.
     */
    populate_mft_engine_config(config, &mft_config);
    if (!g_fs_backend_force_hfsplus_target) {
        mft_engine_configure(&mft_config);
    } else {
        /* HFS+ raw carvers share the generic Unidentified bucket path
         * builder with the NTFS catalogue layer.  Keep that path-only state
         * aligned with this run without configuring the inactive NTFS
         * engine (or allowing its compiled default output path to leak in). */
        mft_set_output_dir(config != NULL ? config->output_dir : NULL);
    }
    if (config != NULL && config->output_dir != NULL) {
        snprintf(
            g_fs_backend_output_dir,
            sizeof(g_fs_backend_output_dir),
            "%s",
            config->output_dir
        );
    } else {
        g_fs_backend_output_dir[0] = '\0';
    }
    exfat_backend_reset();
    exfat_backend_set_output_dir(config != NULL ? config->output_dir : NULL);
    hfsplus_backend_reset();
    hfsplus_backend_set_output_dir(config != NULL ? config->output_dir : NULL);
    hfsplus_backend_set_compact_metadata_preferred(
        config != NULL ? config->prefer_compact_metadata : 0);
    hfsplus_backend_set_active_formats(
        config != NULL ? config->active_formats_csv : NULL);
    hfsplus_backend_set_assemble_all_catalog_files(
        config != NULL ? config->hfsplus_assemble_all_catalog_files : 0);
    g_fs_backend_kind = FS_BACKEND_KIND_NTFS;
}

FsBackendKind fs_backend_current_kind(void)
{
    return g_fs_backend_kind;
}

int fs_backend_configure_from_source(const char *input_path)
{
    int ntfs_ok;

    if (g_fs_backend_force_hfsplus_target) {
        exfat_backend_reset();
        if (hfsplus_backend_configure_from_source(input_path)) {
            g_fs_backend_kind = FS_BACKEND_KIND_HFSPLUS;
            return 1;
        }
        hfsplus_backend_reset();
        g_fs_backend_kind = FS_BACKEND_KIND_NONE;
        return 0;
    }

    /*
     * Probe HFS+ before the NTFS orphan-boot fallback. On a whole HFS+ GPT
     * disk, the latter is deliberately broad and can otherwise make automatic
     * detection look like a long NTFS metadata run before HFS+ is considered.
     * An explicit NTFS target keeps the existing NTFS-first behaviour.
     */
    if (!g_fs_backend_force_ntfs_target &&
        hfsplus_backend_configure_from_source(input_path)) {
        exfat_backend_reset();
        g_fs_backend_kind = FS_BACKEND_KIND_HFSPLUS;
        return 1;
    }

    ntfs_ok = mft_engine_configure_from_source(input_path);

    /*
     * A positive NTFS probe is authoritative. Do not let a passive mounted
     * filesystem hint push us into HFS+/exFAT fallback once the source has
     * already proven to contain NTFS geometry.
     */
    if (ntfs_ok || g_fs_backend_force_ntfs_target) {
        exfat_backend_reset();
        hfsplus_backend_reset();
        g_fs_backend_kind = FS_BACKEND_KIND_NTFS;
        return 1;
    }

    if (exfat_backend_configure_from_source(input_path)) {
        hfsplus_backend_reset();
        g_fs_backend_kind = FS_BACKEND_KIND_EXFAT;
        return 1;
    }

    exfat_backend_reset();
    hfsplus_backend_reset();
    g_fs_backend_kind = FS_BACKEND_KIND_NONE;
    return 0;
}

int fs_backend_source_is_definitely_non_ntfs(void)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS ||
        g_fs_backend_kind == FS_BACKEND_KIND_EXFAT) {
        return 1;
    }
    if (g_fs_backend_force_hfsplus_target) {
        return 1;
    }
    if (g_fs_backend_force_ntfs_target) {
        return 0;
    }
    return mft_engine_source_is_definitely_non_ntfs();
}

const char *fs_backend_source_filesystem_hint(void)
{
    if (g_fs_backend_force_hfsplus_target &&
        g_fs_backend_kind != FS_BACKEND_KIND_HFSPLUS) {
        return "HFS+ (forced target)";
    }
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS &&
        g_fs_backend_force_ntfs_target &&
        !mft_has_ntfs_geometry()) {
        return "NTFS (forced target)";
    }
    if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        return hfsplus_backend_source_hint();
    }
    if (g_fs_backend_kind == FS_BACKEND_KIND_EXFAT) {
        return exfat_backend_source_hint();
    }
    return mft_engine_source_filesystem_hint();
}

const char *fs_backend_current_id(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return "ntfs";
        case FS_BACKEND_KIND_HFSPLUS:
            return "hfsplus";
        case FS_BACKEND_KIND_EXFAT:
            return "exfat";
        case FS_BACKEND_KIND_NONE:
        default:
            return "none";
    }
}

const char *fs_backend_current_name(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return "NTFS";
        case FS_BACKEND_KIND_HFSPLUS:
            return "HFS+";
        case FS_BACKEND_KIND_EXFAT:
            return "exFAT";
        case FS_BACKEND_KIND_NONE:
        default:
            return "unknown filesystem";
    }
}

const char *fs_backend_current_output_dir(void)
{
    return g_fs_backend_output_dir;
}

uint64_t fs_backend_current_volume_serial(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_get_ntfs_volume_serial()
        : 0ULL;
}

int fs_backend_is_internal_output_artifact_name(const char *name)
{
    return mft_engine_is_internal_output_artifact_name(name);
}

int fs_backend_supports_live_metadata_observation(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return current_source_supports_ntfs_metadata();
        case FS_BACKEND_KIND_HFSPLUS:
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_has_metadata_context_for_raw_scan(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_entry_count() > 0U;
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_entry_count() > 0U;
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_entry_count() > 0U;
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_translate_photorec_file_number(
    unsigned long long file_number,
    long long *out_abs_offset
)
{
    if (out_abs_offset != NULL) {
        *out_abs_offset = -1;
    }

    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_translate_photorec_file_number(
                file_number,
                out_abs_offset
            );
        case FS_BACKEND_KIND_NONE:
        case FS_BACKEND_KIND_NTFS:
        case FS_BACKEND_KIND_HFSPLUS:
        default:
            return 0;
    }
}

int fs_backend_source_path_is_direct_metadata_file(const char *path)
{
    const char *basename;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    basename = strrchr(path, '/');
    basename = basename != NULL ? basename + 1 : path;

    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return strcmp(basename, "$MFT") == 0;
    }

    return 0;
}

int fs_backend_supports_selected_tree_recovery(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return current_source_supports_ntfs_metadata();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_supports_root_folder_preview();
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_supports_root_folder_preview(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return current_source_supports_ntfs_metadata();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_supports_root_folder_preview();
        case FS_BACKEND_KIND_EXFAT:
            return 0;
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_supports_compare_mount(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return current_source_supports_ntfs_metadata();
        case FS_BACKEND_KIND_HFSPLUS:
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_has_native_geometry(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_has_ntfs_geometry();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_has_geometry();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_has_geometry();
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

size_t fs_backend_record_size(void)
{
    return mft_engine_record_size();
}

int fs_backend_write_resident_record_payload(
    FILE *out,
    const unsigned char *record,
    size_t record_length,
    uint64_t record_abs_offset,
    uint64_t expected_data_size
)
{
    MftProbeEntry probe;

    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS ||
        out == NULL ||
        record == NULL ||
        record_length < MFT_PROBE_RECORD_SIZE ||
        !mft_probe_parse_record_any(record, record_abs_offset, &probe) ||
        !probe.has_data ||
        !probe.resident ||
        probe.data_offset < 0 ||
        (uint64_t)probe.data_offset + probe.data_size > MFT_PROBE_RECORD_SIZE ||
        probe.data_size != expected_data_size) {
        return 0;
    }

    return fwrite(
        record + (size_t)probe.data_offset,
        1,
        (size_t)probe.data_size,
        out
    ) == (size_t)probe.data_size;
}

size_t fs_backend_observe_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset,
    int allow_unaligned
)
{
    size_t observed = 0U;

    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0U;
    }

    observed += mft_engine_observe_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset,
        allow_unaligned
    );
    observed += mft_engine_absorb_usn_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
    observed += mft_engine_absorb_lnk_dlt_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
    observed += mft_engine_absorb_windows_search_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
    observed += mft_engine_absorb_vss_evidence_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
    return observed;
}

size_t fs_backend_absorb_usn_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0U;
    }

    return mft_engine_absorb_usn_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
}

size_t fs_backend_absorb_lnk_dlt_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0U;
    }

    return mft_engine_absorb_lnk_dlt_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
}

size_t fs_backend_absorb_windows_search_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0U;
    }

    return mft_engine_absorb_windows_search_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
}

size_t fs_backend_absorb_vss_evidence_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0U;
    }

    return mft_engine_absorb_vss_evidence_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
}

int fs_backend_load_resume_artifacts(void)
{
    return fs_backend_load_artifacts_for_phase(
        FS_BACKEND_ARTIFACT_PHASE_SCAN_RESUME
    );
}

int fs_backend_load_finalize_resume_artifacts(void)
{
    return fs_backend_load_artifacts_for_phase(
        FS_BACKEND_ARTIFACT_PHASE_FINALIZE_RESUME
    );
}

int fs_backend_load_name_resume_artifacts(void)
{
    return fs_backend_load_artifacts_for_phase(
        FS_BACKEND_ARTIFACT_PHASE_NAME_RESUME
    );
}

int fs_backend_load_artifacts_for_phase(FsBackendArtifactPhase phase)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            switch (phase) {
                case FS_BACKEND_ARTIFACT_PHASE_FINALIZE_RESUME:
                    return mft_engine_load_finalize_resume_artifacts();
                case FS_BACKEND_ARTIFACT_PHASE_NAME_RESUME:
                    return mft_engine_load_name_resume_artifacts();
                case FS_BACKEND_ARTIFACT_PHASE_SCAN_RESUME:
                default:
                    return mft_engine_load_resume_artifacts();
            }
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_load_recovered_output_state();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_load_recovered_output_state();
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_load_recovered_output_state(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_load_recovered_output_state();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_load_recovered_output_state();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_load_recovered_output_state();
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_saved_metadata_available(void)
{
    return fs_backend_saved_metadata_available_for_phase(
        FS_BACKEND_ARTIFACT_PHASE_SCAN_RESUME
    );
}

void fs_backend_get_artifact_state(
    FsBackendArtifactPhase phase,
    FsBackendArtifactState *out_state
)
{
    if (out_state == NULL) {
        return;
    }
    memset(out_state, 0, sizeof(*out_state));

    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            query_ntfs_artifact_state_local(phase, out_state);
            break;
        case FS_BACKEND_KIND_HFSPLUS:
            query_hfsplus_artifact_state_local(phase, out_state);
            break;
        case FS_BACKEND_KIND_EXFAT:
            query_exfat_artifact_state_local(phase, out_state);
            break;
        case FS_BACKEND_KIND_NONE:
        default:
            break;
    }
}

int fs_backend_saved_metadata_available_for_phase(FsBackendArtifactPhase phase)
{
    FsBackendArtifactState state = {0};

    fs_backend_get_artifact_state(phase, &state);
    return state.ready_for_phase;
}

void fs_backend_set_partial_record_salvage(int enabled)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_set_partial_record_salvage(enabled);
    }
}

void fs_backend_set_salvage_first_sector_confirmed_bytes(size_t bytes)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_set_salvage_first_sector_confirmed_bytes(bytes);
    }
}

void fs_backend_set_catalog_first_mode(int enabled)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_set_catalog_first_mode(enabled);
    }
}

void fs_backend_set_name_trace_enabled(int enabled)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_set_name_trace_enabled(enabled);
    }
}

void fs_backend_set_finalize_opportunistic_budget_seconds(
    double seconds,
    const char *profile_label
)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_set_finalize_opportunistic_budget_seconds(
            seconds,
            profile_label
        );
    } else if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        hfsplus_backend_set_finalize_opportunistic_budget_seconds(
            seconds,
            profile_label
        );
    }
}

void fs_backend_reset_record_salvage_stats(void)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_reset_record_salvage_stats();
    }
}

void fs_backend_get_record_salvage_stats(FsBackendRecordSalvageStats *out_stats)
{
    MftRecordSalvageStats stats = {0};

    if (out_stats != NULL) {
        memset(out_stats, 0, sizeof(*out_stats));
    }
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return;
    }
    mft_engine_get_record_salvage_stats(&stats);
    copy_fs_record_salvage_stats_from_mft(out_stats, &stats);
}

void fs_backend_reset_seen_offsets(void)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_reset_seen_offsets();
    }
}

int fs_backend_prepare_index(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_prepare_index();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_prepare_index();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_prepare_index();
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_finalize_index(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_finalize_index();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_finalize_index();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_entry_count() > 0U;
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_finalize_recovered_outputs(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_finalize_recovered_outputs();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_finalize_recovered_outputs();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_finalize_recovered_outputs();
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_finalize_recovered_outputs_with_live_catalog(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_finalize_recovered_outputs_with_mft_map();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_finalize_recovered_outputs();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_finalize_recovered_outputs();
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

void fs_backend_observe_sequential_bytes(
    uint64_t range_start,
    const unsigned char *bytes,
    size_t byte_count)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        hfsplus_backend_observe_sequential_bytes(
            range_start,
            bytes,
            byte_count
        );
    }
}

void fs_backend_finish_sequential_measurement(int completed_full_scan)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        hfsplus_backend_finish_sequential_measurement(completed_full_scan);
    }
}

int fs_backend_range_has_trusted_metadata_owner(
    uint64_t range_start,
    uint64_t range_end)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        return hfsplus_backend_range_has_trusted_metadata_owner(
            range_start,
            range_end
        );
    }
    return 0;
}

int fs_backend_get_candidate_context(
    uint64_t physical_offset,
    MetadataIndexCandidateContext *context_out)
{
    if (context_out == NULL) return -1;
    memset(context_out, 0, sizeof(*context_out));
    if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        return hfsplus_backend_get_candidate_context(
            physical_offset,
            context_out);
    }
    return 0;
}

void fs_backend_set_state_writes_suppressed(int suppressed)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_set_state_writes_suppressed(suppressed);
    }
}

void fs_backend_close(void)
{
    FsBackendKind closing_kind = g_fs_backend_kind;

    exfat_backend_reset();
    hfsplus_backend_reset();
    /* An explicit HFS+ run deliberately never configures the NTFS engine.
     * Closing that inactive engine can otherwise flush stale process/default
     * NTFS state into an unrelated output path. */
    if (closing_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_close();
    }
    g_fs_backend_kind = FS_BACKEND_KIND_NONE;
    g_fs_backend_output_dir[0] = '\0';
}

size_t fs_backend_entry_count(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_entry_count();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_entry_count();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_entry_count();
        case FS_BACKEND_KIND_NONE:
        default:
            return 0U;
    }
}

size_t fs_backend_recovered_output_count(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_recovered_output_count();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_recovered_output_count();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_recovered_output_count();
        case FS_BACKEND_KIND_NONE:
            return mft_engine_recovered_output_count();
        default:
            return 0U;
    }
}

size_t fs_backend_named_output_count(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_named_output_count();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_named_output_count();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_named_output_count();
        case FS_BACKEND_KIND_NONE:
            return mft_engine_named_output_count();
        default:
            return 0U;
    }
}

size_t fs_backend_unreconciled_output_count(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_unreconciled_output_count();
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_unreconciled_output_count();
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_unreconciled_output_count();
        case FS_BACKEND_KIND_NONE:
            return mft_engine_unreconciled_output_count();
        default:
            return 0U;
    }
}

int fs_backend_is_offset_fully_recovered(long long abs_offset)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_is_offset_fully_recovered(abs_offset);
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_is_offset_fully_recovered(abs_offset);
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_is_offset_fully_recovered(abs_offset);
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_get_recovered_output_info(
    long long abs_offset,
    char *out_path,
    size_t out_path_size,
    int *out_reconciled
)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_get_recovered_output_info(
                abs_offset,
                out_path,
                out_path_size,
                out_reconciled
            );
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_get_recovered_output_info(
                abs_offset,
                out_path,
                out_path_size,
                out_reconciled
            );
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_get_recovered_output_info(
                abs_offset,
                out_path,
                out_path_size,
                out_reconciled
            );
        case FS_BACKEND_KIND_NONE:
            return mft_engine_get_recovered_output_info(
                abs_offset,
                out_path,
                out_path_size,
                out_reconciled
            );
        default:
            return 0;
    }
}

int fs_backend_build_output_path(char *out, size_t out_size, const char *relative_path)
{
    return mft_engine_build_output_path(out, out_size, relative_path);
}

int fs_backend_build_recovered_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_build_recovered_output_path(
                out_path,
                out_size,
                abs_offset,
                default_directory,
                default_prefix,
                extension
            );
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_build_recovered_output_path(
                out_path,
                out_size,
                abs_offset,
                default_directory,
                default_prefix,
                extension
            );
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_build_recovered_output_path(
                out_path,
                out_size,
                abs_offset,
                default_directory,
                default_prefix,
                extension
            );
        case FS_BACKEND_KIND_NONE:
            return mft_engine_build_recovered_output_path(
                out_path,
                out_size,
                abs_offset,
                default_directory,
                default_prefix,
                extension
            );
        default:
            return 0;
    }
}

int fs_backend_build_deferred_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_build_deferred_output_path(
                out_path,
                out_size,
                abs_offset,
                default_directory,
                default_prefix,
                extension
            );
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_build_recovered_output_path(
                out_path,
                out_size,
                abs_offset,
                default_directory,
                default_prefix,
                extension
            );
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_build_recovered_output_path(
                out_path,
                out_size,
                abs_offset,
                default_directory,
                default_prefix,
                extension
            );
        case FS_BACKEND_KIND_NONE:
            return mft_engine_build_deferred_output_path(
                out_path,
                out_size,
                abs_offset,
                default_directory,
                default_prefix,
                extension
            );
        default:
            return 0;
    }
}

int fs_backend_apply_output_owner_to_path(const char *path)
{
    return mft_engine_apply_output_owner_to_path(path);
}

int fs_backend_apply_created_time_to_path(const char *path, long long abs_offset)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_apply_created_time_to_path(path, abs_offset);
        case FS_BACKEND_KIND_HFSPLUS: {
            time_t created_time = hfsplus_backend_lookup_created_time_by_offset(abs_offset);

            if (created_time <= 0) {
                return 0;
            }
            return mft_engine_apply_created_time_value_to_path(path, created_time);
        }
        case FS_BACKEND_KIND_EXFAT: {
            time_t created_time = exfat_backend_lookup_created_time_by_offset(abs_offset);

            if (created_time <= 0) {
                return 0;
            }
            return mft_engine_apply_created_time_value_to_path(path, created_time);
        }
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_apply_created_time_value_to_path(const char *path, time_t created_time)
{
    return mft_engine_apply_created_time_value_to_path(path, created_time);
}

void fs_backend_note_recovered_output(const char *path, long long abs_offset)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            mft_engine_note_recovered_output(path, abs_offset);
            return;
        case FS_BACKEND_KIND_HFSPLUS:
            hfsplus_backend_note_recovered_output(path, abs_offset);
            return;
        case FS_BACKEND_KIND_EXFAT:
            exfat_backend_note_recovered_output(path, abs_offset);
            return;
        case FS_BACKEND_KIND_NONE:
            mft_engine_note_recovered_output(path, abs_offset);
            return;
        default:
            return;
    }
}

void fs_backend_reconcile_recovered_outputs_live(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            mft_engine_reconcile_recovered_outputs_live();
            return;
        case FS_BACKEND_KIND_HFSPLUS:
            hfsplus_backend_reconcile_recovered_outputs_live();
            return;
        case FS_BACKEND_KIND_EXFAT:
            exfat_backend_reconcile_recovered_outputs_live();
            return;
        case FS_BACKEND_KIND_NONE:
        default:
            return;
    }
}

int fs_backend_refresh_record_at(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t absolute_offset,
    size_t buffer_offset
)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return mft_engine_refresh_record_at(
            buffer,
            buffer_length,
            absolute_offset,
            buffer_offset
        );
    }
    return 0;
}

int fs_backend_record_offset_is_naming_ready(uint64_t absolute_offset)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return mft_engine_record_offset_is_naming_ready(absolute_offset);
    }
    return 0;
}

size_t fs_backend_collect_partial_metadata_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return mft_engine_collect_partial_metadata_record_offsets(
            out_offsets,
            out_capacity
        );
    }
    return 0U;
}

size_t fs_backend_collect_parent_chain_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return mft_engine_collect_parent_chain_record_offsets(
            out_offsets,
            out_capacity
        );
    }
    return 0U;
}

size_t fs_backend_collect_name_detail_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return mft_engine_collect_name_detail_record_offsets(
            out_offsets,
            out_capacity
        );
    }
    return 0U;
}

size_t fs_backend_collect_directory_index_targets(
    FsDirectoryIndexTarget *out_targets,
    size_t out_capacity,
    uint64_t max_total_bytes
)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return mft_engine_collect_i30_scan_targets(
            (MftI30ScanTarget *)out_targets,
            out_capacity,
            max_total_bytes
        );
    }
    return 0U;
}

size_t fs_backend_absorb_directory_index_buffer(
    const FsDirectoryIndexTarget *target,
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return mft_engine_absorb_i30_index_buffer(
            (const MftI30ScanTarget *)target,
            buffer,
            buffer_length,
            buffer_base_offset
        );
    }
    return 0U;
}

size_t fs_backend_refresh_directory_index_from_source(
    const char *source_path,
    uint64_t max_total_bytes,
    size_t max_target_count,
    uint64_t *out_bytes_scanned
)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return mft_engine_refresh_i30_names_from_source(
            source_path,
            max_total_bytes,
            max_target_count,
            out_bytes_scanned
        );
    }
    return 0U;
}

size_t fs_backend_directory_index_name_count(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_engine_i30_name_count()
        : 0U;
}

int fs_backend_classify_recovered_output_hint(
    long long abs_offset,
    const char *recovered_extension,
    FsRecoveredNamingHint *out_hint
)
{
    MftRecoveredNamingHint hint = {0};
    int ok = 0;

    if (out_hint != NULL) {
        memset(out_hint, 0, sizeof(*out_hint));
    }
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0;
    }
    ok = mft_engine_classify_recovered_output_hint(
        abs_offset,
        recovered_extension,
        &hint
    );
    if (ok) {
        copy_fs_recovered_naming_hint_from_mft(out_hint, &hint);
    }
    return ok;
}

int fs_backend_preview_recovered_output_match(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    FsRecoveredMatchKind *out_kind
)
{
    MftRecoveredMatchKind kind = MFT_RECOVERED_MATCH_NONE;
    int ok = 0;

    if (out_kind != NULL) {
        *out_kind = FS_RECOVERED_MATCH_NONE;
    }
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0;
    }

    ok = mft_engine_preview_recovered_output_match(
        abs_offset,
        current_path,
        recovered_extension,
        &kind
    );
    if (ok && out_kind != NULL) {
        *out_kind = fs_recovered_match_kind_from_mft(kind);
    }
    return ok;
}

int fs_backend_collect_recovered_output_match_signals(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    FsRecoveredMatchSignals *out_signals
)
{
    MftRecoveredMatchSignals signals = {0};
    int ok = 0;

    if (out_signals != NULL) {
        memset(out_signals, 0, sizeof(*out_signals));
    }
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0;
    }

    ok = mft_engine_collect_recovered_output_match_signals(
        abs_offset,
        current_path,
        recovered_extension,
        &signals
    );
    if (ok && out_signals != NULL) {
        copy_fs_recovered_match_signals_from_mft(out_signals, &signals);
    }
    return ok;
}

void fs_backend_get_name_uniqueness_stats(FsNameUniquenessStats *out_stats)
{
    MftNameUniquenessStats mft_stats = {0};

    if (out_stats != NULL) {
        memset(out_stats, 0, sizeof(*out_stats));
    }
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return;
    }

    mft_engine_get_name_uniqueness_stats(&mft_stats);
    if (out_stats != NULL) {
        copy_fs_name_uniqueness_stats_from_mft(out_stats, &mft_stats);
    }
}

int fs_backend_get_name_candidate_index_stats(FsNameCandidateIndexStats *out_stats)
{
    MftNameCandidateIndexStats mft_stats = {0};
    int ok = 0;

    if (out_stats != NULL) {
        memset(out_stats, 0, sizeof(*out_stats));
    }
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0;
    }

    ok = mft_engine_get_name_candidate_index_stats(&mft_stats);
    if (ok && out_stats != NULL) {
        copy_fs_name_candidate_index_stats_from_mft(out_stats, &mft_stats);
    }
    return ok;
}

int fs_backend_write_name_candidate_index(FsNameCandidateIndexStats *out_stats)
{
    MftNameCandidateIndexStats mft_stats = {0};
    int ok = 0;

    if (out_stats != NULL) {
        memset(out_stats, 0, sizeof(*out_stats));
    }
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0;
    }

    ok = mft_engine_write_name_candidate_index(&mft_stats);
    if (ok && out_stats != NULL) {
        copy_fs_name_candidate_index_stats_from_mft(out_stats, &mft_stats);
    }
    return ok;
}

int fs_backend_write_name_match_preview(FsNameMatchPreviewStats *out_stats)
{
    MftNameMatchPreviewStats mft_stats = {0};
    int ok = 0;

    if (out_stats != NULL) {
        memset(out_stats, 0, sizeof(*out_stats));
    }
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0;
    }

    ok = mft_engine_write_name_match_preview(&mft_stats);
    if (ok && out_stats != NULL) {
        copy_fs_name_match_preview_stats_from_mft(out_stats, &mft_stats);
    }
    return ok;
}

void fs_backend_emit_directory_index_hint_sample(size_t limit)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_emit_i30_name_trace_sample(limit);
    }
}

const char *fs_backend_lookup_path_by_offset(long long abs_offset)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_lookup_path_by_offset(abs_offset);
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_lookup_path_by_offset(abs_offset);
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_lookup_path_by_offset(abs_offset);
        case FS_BACKEND_KIND_NONE:
        default:
            return NULL;
    }
}

time_t fs_backend_lookup_created_time_by_offset(long long abs_offset)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_lookup_created_time_by_offset(abs_offset);
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_lookup_created_time_by_offset(abs_offset);
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_lookup_created_time_by_offset(abs_offset);
        case FS_BACKEND_KIND_NONE:
        default:
            return (time_t)0;
    }
}

int fs_backend_lookup_scan_hint(long long abs_offset, FsScanHint *out)
{
    MftScanHint hint = {0};
    int ok = 0;

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            ok = mft_engine_lookup_scan_hint(abs_offset, &hint);
            break;
        case FS_BACKEND_KIND_HFSPLUS:
            ok = hfsplus_backend_lookup_scan_hint(abs_offset, &hint);
            break;
        case FS_BACKEND_KIND_EXFAT:
            ok = exfat_backend_lookup_scan_hint(abs_offset, &hint);
            break;
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }

    if (ok) {
        copy_fs_scan_hint_from_mft(out, &hint);
    }
    return ok;
}

const char *fs_backend_lookup_container_label_by_offset(long long abs_offset)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_lookup_container_label_by_offset(abs_offset);
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_lookup_container_label_by_offset(abs_offset);
        case FS_BACKEND_KIND_EXFAT:
            return exfat_backend_lookup_container_label_by_offset(abs_offset);
        case FS_BACKEND_KIND_NONE:
        default:
            return NULL;
    }
}

void fs_backend_refresh_recovery_state(size_t *entry_count_snapshot)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            mft_engine_refresh_recovery_state(entry_count_snapshot);
            return;
        case FS_BACKEND_KIND_HFSPLUS:
            hfsplus_backend_refresh_recovery_state(entry_count_snapshot);
            return;
        case FS_BACKEND_KIND_EXFAT:
            exfat_backend_refresh_recovery_state(entry_count_snapshot);
            return;
        case FS_BACKEND_KIND_NONE:
        default:
            if (entry_count_snapshot != NULL) {
                *entry_count_snapshot = 0U;
            }
            return;
    }
}

size_t fs_backend_collect_view_entries_in_range(
    long long range_start,
    long long range_end,
    FsViewEntry **out_entries
)
{
    MftViewEntry *mft_entries = NULL;
    size_t count = 0U;

    if (out_entries != NULL) {
        *out_entries = NULL;
    }

    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            count = mft_engine_collect_view_entries_in_range(
                range_start,
                range_end,
                &mft_entries
            );
            return copy_fs_view_entries_from_mft(mft_entries, count, out_entries);
        case FS_BACKEND_KIND_HFSPLUS:
            count = hfsplus_backend_collect_view_entries_in_range(
                range_start,
                range_end,
                &mft_entries
            );
            return copy_fs_view_entries_from_mft(mft_entries, count, out_entries);
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            if (out_entries != NULL) {
                *out_entries = NULL;
            }
            return 0U;
    }
}

int fs_backend_get_view_entry_by_offset(long long abs_offset, FsViewEntry *out)
{
    MftViewEntry view = {0};
    int ok = 0;

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }

    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            ok = mft_engine_get_view_entry_by_offset(abs_offset, &view);
            break;
        case FS_BACKEND_KIND_HFSPLUS:
            ok = hfsplus_backend_get_view_entry_by_offset(abs_offset, &view);
            break;
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }

    if (ok) {
        copy_fs_view_entry_from_mft(out, &view);
    }
    return ok;
}

size_t fs_backend_write_missed_report(const char *path)
{
    return mft_engine_write_missed_users_report(path);
}

void fs_backend_reset_process_stats(void)
{
    mft_engine_reset_process_stats();
}

void fs_backend_get_process_stats(FsBackendProcessStats *out_stats)
{
    MftProcessStats stats = {0};

    mft_engine_get_process_stats(&stats);
    copy_fs_process_stats_from_mft(out_stats, &stats);
}

long long fs_backend_primary_scan_start_offset(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_get_primary_scan_start_offset()
        : -1LL;
}

uint64_t fs_backend_primary_total_bytes(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_get_primary_mft_total_bytes()
        : 0ULL;
}

long long fs_backend_expected_mirror_offset(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_get_expected_mft_mirror_offset()
        : -1LL;
}

uint64_t fs_backend_estimated_mirror_bytes(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_get_estimated_mft_mirror_bytes()
        : 0ULL;
}

long long fs_backend_partition_start_offset(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_get_partition_start()
        : 0LL;
}

uint32_t fs_backend_cluster_size(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_get_cluster_size()
        : 0U;
}

int fs_backend_has_primary_catalog_root(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_has_primary_users_root()
        : 0;
}

int fs_backend_run_primary_metadata_bootstrap(Reader *reader)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return scanner_run_primary_metadata_acquisition(
                reader,
                FS_BACKEND_METADATA_ACQUIRE_STARTUP
            );
        case FS_BACKEND_KIND_HFSPLUS:
            (void)reader;
            return hfsplus_backend_run_metadata_acquisition(
                FS_BACKEND_METADATA_ACQUIRE_STARTUP
            );
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 1;
    }
}

int fs_backend_should_attempt_primary_metadata_acquisition(
    FsBackendMetadataAcquirePhase phase
)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return 1;
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_should_attempt_metadata_acquisition((int)phase);
        default:
            return 0;
    }
}

int fs_backend_run_primary_metadata_acquisition(
    Reader *reader,
    FsBackendMetadataAcquirePhase phase
)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return scanner_run_primary_metadata_acquisition(reader, (int)phase);
        case FS_BACKEND_KIND_HFSPLUS:
            (void)reader;
            return hfsplus_backend_run_metadata_acquisition((int)phase);
        default:
            return 1;
    }
}

int fs_backend_bootstrap_should_disable_live_observation(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? scanner_primary_metadata_bootstrap_should_disable_live_observation()
        : 0;
}

size_t fs_backend_primary_run_count(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_get_primary_mft_run_count()
        : 0U;
}

int fs_backend_get_primary_run(
    size_t run_index,
    uint64_t *out_abs_offset,
    uint64_t *out_length
)
{
    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0;
    }
    return mft_get_primary_mft_run(run_index, out_abs_offset, out_length);
}

int fs_backend_split_run_output_dir(
    const char *run_output_dir,
    char *base_out,
    size_t base_out_size,
    char *run_id,
    size_t run_id_size
)
{
    const char *slash;
    size_t base_len;

    if (run_output_dir == NULL ||
        run_output_dir[0] == '\0' ||
        base_out == NULL ||
        base_out_size == 0U ||
        run_id == NULL ||
        run_id_size == 0U) {
        return 0;
    }

    slash = strrchr(run_output_dir, '/');
    if (slash == NULL || slash == run_output_dir || slash[1] == '\0') {
        return 0;
    }

    base_len = (size_t)(slash - run_output_dir);
    if (base_len + 1U > base_out_size ||
        strlen(slash + 1U) + 1U > run_id_size) {
        return 0;
    }

    memcpy(base_out, run_output_dir, base_len);
    base_out[base_len] = '\0';
    snprintf(run_id, run_id_size, "%s", slash + 1U);
    return 1;
}

int fs_backend_run_selected_tree_with_options(
    const char *input_path,
    const char *out_dir,
    const char *run_name,
    uint64_t limit,
    int quick_resume,
    int auto_recover_missed,
    int only_recover_missed,
    const FsBackendMetadataOptions *options
)
{
    MftEngineUsersOptions mft_options = {0};

    if (!fs_backend_configure_from_source(input_path) ||
        !fs_backend_supports_selected_tree_recovery()) {
        return 0;
    }

    g_fs_backend_last_non_ntfs_metadata_status = FS_BACKEND_METADATA_STATUS_NONE;
    g_fs_backend_last_non_ntfs_recovered_count = 0U;
    populate_mft_engine_metadata_options(options, &mft_options);
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_run_users_with_options(
                input_path,
                out_dir,
                run_name,
                limit,
                quick_resume,
                auto_recover_missed,
                only_recover_missed,
                options != NULL ? &mft_options : NULL
            );
        case FS_BACKEND_KIND_HFSPLUS: {
            int hfsplus_result = hfsplus_backend_run_selected_tree(
                input_path,
                options != NULL ? options->root_scope_csv : NULL,
                quick_resume,
                &g_fs_backend_last_non_ntfs_recovered_count
            );

            if (hfsplus_result > 0) {
                g_fs_backend_last_non_ntfs_metadata_status =
                    FS_BACKEND_METADATA_STATUS_OK;
                return 1;
            }
            g_fs_backend_last_non_ntfs_metadata_status =
                hfsplus_result < 0
                    ? FS_BACKEND_METADATA_STATUS_INTERRUPTED
                    : FS_BACKEND_METADATA_STATUS_FAILED;
            return 0;
        }
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_write_selected_tree_ddrescue_domain(
    const char *input_path,
    const char *domain_map_path,
    const FsBackendMetadataOptions *options,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
)
{
    if (out_range_count != NULL) {
        *out_range_count = 0ULL;
    }
    if (out_total_bytes != NULL) {
        *out_total_bytes = 0ULL;
    }
    if (input_path == NULL ||
        input_path[0] == '\0' ||
        domain_map_path == NULL ||
        domain_map_path[0] == '\0' ||
        options == NULL ||
        options->root_scope_csv == NULL ||
        options->root_scope_csv[0] == '\0' ||
        !fs_backend_configure_from_source(input_path) ||
        !fs_backend_supports_selected_tree_recovery()) {
        return 0;
    }

    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_write_selected_tree_ddrescue_domain(
                input_path,
                options->root_scope_csv,
                domain_map_path,
                out_range_count,
                out_total_bytes
            );
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_write_selected_tree_ddrescue_domain(
                input_path,
                options->root_scope_csv,
                domain_map_path,
                out_range_count,
                out_total_bytes
            );
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_run_filtered_recovery_with_options(
    const char *input_path,
    const char *out_dir,
    const char *run_name,
    const char *filter_csv,
    uint64_t limit,
    const FsBackendMetadataOptions *options
)
{
    MftEngineUsersOptions mft_options = {0};

    if (!fs_backend_configure_from_source(input_path) ||
        !fs_backend_supports_selected_tree_recovery()) {
        return 0;
    }

    populate_mft_engine_metadata_options(options, &mft_options);
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_run_filtered_with_options(
                input_path,
                out_dir,
                run_name,
                filter_csv,
                limit,
                options != NULL ? &mft_options : NULL
            );
        case FS_BACKEND_KIND_HFSPLUS:
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_run_metadata_jpeg_test(
    const char *input_path,
    const char *out_dir,
    size_t max_files,
    size_t *out_recovered_count
)
{
    if (out_recovered_count != NULL) {
        *out_recovered_count = 0U;
    }
    if (input_path == NULL || input_path[0] == '\0' ||
        out_dir == NULL || out_dir[0] == '\0' ||
        max_files == 0U ||
        !fs_backend_configure_from_source(input_path) ||
        !fs_backend_supports_selected_tree_recovery()) {
        return 0;
    }

    g_fs_backend_last_non_ntfs_metadata_status = FS_BACKEND_METADATA_STATUS_NONE;
    g_fs_backend_last_non_ntfs_recovered_count = 0U;
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS: {
            int ok = mft_engine_run_metadata_jpeg_test(
                input_path,
                out_dir,
                max_files,
                out_recovered_count
            );
            g_fs_backend_last_non_ntfs_recovered_count =
                out_recovered_count != NULL ? *out_recovered_count : 0U;
            return ok;
        }
        case FS_BACKEND_KIND_HFSPLUS: {
            int hfsplus_result = hfsplus_backend_run_metadata_jpeg_test(
                input_path,
                out_dir,
                max_files,
                &g_fs_backend_last_non_ntfs_recovered_count
            );

            if (out_recovered_count != NULL) {
                *out_recovered_count = g_fs_backend_last_non_ntfs_recovered_count;
            }
            if (hfsplus_result > 0) {
                g_fs_backend_last_non_ntfs_metadata_status =
                    FS_BACKEND_METADATA_STATUS_OK;
                return 1;
            }
            g_fs_backend_last_non_ntfs_metadata_status =
                hfsplus_result < 0
                    ? FS_BACKEND_METADATA_STATUS_INTERRUPTED
                    : FS_BACKEND_METADATA_STATUS_FAILED;
            return 0;
        }
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_run_compare_mount_with_options(
    const char *input_path,
    const char *out_dir,
    const char *run_name,
    const char *mount_path,
    const char *filter_csv,
    uint64_t limit,
    const FsBackendMetadataOptions *options
)
{
    MftEngineUsersOptions mft_options = {0};

    if (!fs_backend_configure_from_source(input_path) ||
        !fs_backend_supports_compare_mount()) {
        return 0;
    }

    populate_mft_engine_metadata_options(options, &mft_options);
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_run_compare_mount_with_options(
                input_path,
                out_dir,
                run_name,
                mount_path,
                filter_csv,
                limit,
                options != NULL ? &mft_options : NULL
            );
        case FS_BACKEND_KIND_HFSPLUS:
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_list_root_folders(const char *input_path, FILE *out_stream)
{
    if (g_fs_backend_force_ntfs_target) {
        g_fs_backend_kind = FS_BACKEND_KIND_NTFS;
        return mft_engine_list_root_folders(input_path, out_stream);
    }

    if (!fs_backend_configure_from_source(input_path) ||
        !fs_backend_supports_root_folder_preview()) {
        return 0;
    }

    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_list_root_folders(input_path, out_stream);
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_list_root_folders(input_path, out_stream);
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

int fs_backend_list_child_folders(
    const char *input_path,
    const char *parent_path,
    FILE *out_stream
)
{
    if (g_fs_backend_force_ntfs_target) {
        g_fs_backend_kind = FS_BACKEND_KIND_NTFS;
        return mft_engine_list_child_folders(
            input_path,
            parent_path,
            out_stream
        );
    }

    if (!fs_backend_configure_from_source(input_path) ||
        !fs_backend_supports_root_folder_preview()) {
        return 0;
    }

    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_list_child_folders(
                input_path,
                parent_path,
                out_stream
            );
        case FS_BACKEND_KIND_HFSPLUS:
            return hfsplus_backend_list_child_folders(
                input_path,
                parent_path,
                out_stream
            );
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0;
    }
}

FsBackendMetadataStatus fs_backend_last_metadata_status(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return fs_backend_status_from_mft_status(mft_engine_users_last_status());
        case FS_BACKEND_KIND_HFSPLUS:
            return g_fs_backend_last_non_ntfs_metadata_status;
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return FS_BACKEND_METADATA_STATUS_NONE;
    }
}

size_t fs_backend_last_metadata_recovered_count(void)
{
    switch (g_fs_backend_kind) {
        case FS_BACKEND_KIND_NTFS:
            return mft_engine_users_last_recovered_count();
        case FS_BACKEND_KIND_HFSPLUS:
            return g_fs_backend_last_non_ntfs_recovered_count;
        case FS_BACKEND_KIND_EXFAT:
        case FS_BACKEND_KIND_NONE:
        default:
            return 0U;
    }
}

int fs_backend_start_background_worker(const FsBackendConfig *config)
{
    MftEngineConfig mft_config = {0};

    if (g_fs_backend_kind != FS_BACKEND_KIND_NTFS) {
        return 0;
    }

    /*
     * The background worker is owned by the MFT side today, but we enter
     * it through the backend facade so the caller does not need to know
     * which filesystem-specific implementation is behind it.
     */
    populate_mft_engine_config(config, &mft_config);
    return mft_background_start(&mft_config);
}

void fs_backend_stop_background_worker(void)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_background_stop();
    }
}

int fs_backend_background_worker_running(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_background_is_running()
        : 0;
}

int fs_backend_background_worker_expected_running(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_background_expected_running()
        : 0;
}

int fs_backend_background_stop_requested(void)
{
    return g_fs_backend_kind == FS_BACKEND_KIND_NTFS
        ? mft_background_stop_requested()
        : 0;
}

void fs_backend_set_background_conservative(int enabled)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_engine_set_background_conservative(enabled);
    } else if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        hfsplus_backend_set_background_conservative(enabled);
    }
}

int fs_backend_background_is_conservative(void)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        return mft_engine_background_is_conservative();
    }
    if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        return hfsplus_backend_background_is_conservative();
    }
    return 0;
}

void fs_backend_set_output_context_skip_enabled(int enabled)
{
    carver_output_set_metadata_context_skip_enabled(enabled);
}

void fs_backend_set_metadata_stall_watch_suspended(int suspended)
{
    mft_spool_set_stall_watch_suspended(suspended);
}

void fs_backend_get_live_queue_stats(FsBackendLiveStats *out)
{
    MftSpoolLiveStats live_stats = {0};

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        size_t entry_count = mft_engine_entry_count();
        size_t i30_name_count = mft_engine_i30_name_count();

        mft_spool_get_live_stats(&live_stats);
        copy_fs_live_stats_from_mft(out, &live_stats);
        if (out != NULL) {
            /*
             * The spool/background layer may still be catching up while the
             * foreground raw-all scan has already accumulated a useful in-memory
             * NTFS picture. Reflect that best-effort state in live stats so the
             * scan is not reported as "metadata not attached" when MFT/$I30 data
             * is already available for later finalize/name stages.
             */
            if (out->record_index_count == 0U && entry_count > 0U) {
                out->record_index_count = entry_count;
            }
            if (out->range_index_count == 0U && i30_name_count > 0U) {
                out->range_index_count = i30_name_count;
            }
        }
    } else if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        hfsplus_backend_get_live_stats(&live_stats);
        copy_fs_live_stats_from_mft(out, &live_stats);
        if (out != NULL) {
            mft_spool_publish_backend_counts(
                out->recovered_outputs_current,
                out->named_outputs_current,
                out->unident_outputs_current
            );
        }
    } else if (g_fs_backend_kind == FS_BACKEND_KIND_EXFAT) {
        exfat_backend_get_live_stats(&live_stats);
        copy_fs_live_stats_from_mft(out, &live_stats);
        if (out != NULL) {
            mft_spool_publish_backend_counts(
                out->recovered_outputs_current,
                out->named_outputs_current,
                out->unident_outputs_current
            );
        }
    } else if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
}

void fs_backend_note_foreground_activity(void)
{
    if (g_fs_backend_kind == FS_BACKEND_KIND_NTFS) {
        mft_spool_note_foreground_activity();
    } else if (g_fs_backend_kind == FS_BACKEND_KIND_HFSPLUS) {
        hfsplus_backend_note_foreground_activity();
    }
}
