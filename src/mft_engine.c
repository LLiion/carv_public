/*
 * mft_engine.c
 * Mid-level bridge between the app/backend layers and the NTFS-specific
 * MFT + mftprobe machinery.
 *
 * This file mainly adapts configuration, chooses between spool-first and
 * full-MFT fallback flows, and presents a smaller API to the rest of the
 * program than the lower-level engines expose directly.
 */

#define _POSIX_C_SOURCE 200809L

#include "app.h"
#include "container_context.h"
#include "config.h"
#include "mft_engine.h"
#include "log.h"
#include "mft.h"
#include "mft_spool.h"
#include "mftprobe_engine.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define MFT_ENGINE_LARGE_FULL_LOAD_THRESHOLD_BYTES (128ULL * 1024ULL * 1024ULL)

static int text_present(const char *text)
{
    return text != NULL && text[0] != '\0';
}

static int full_mft_fallback_forced(void)
{
    const char *value = getenv("CARV_FORCE_FULL_MFT_FALLBACK");

    return value != NULL &&
           value[0] != '\0' &&
           strcmp(value, "0") != 0;
}

static int regular_nonempty_file_exists_local(const char *path)
{
    struct stat st;

    if (!text_present(path) || stat(path, &st) != 0) {
        return 0;
    }

    return S_ISREG(st.st_mode) && st.st_size > 0;
}

static int regular_file_size_local(const char *path, uint64_t *out_size)
{
    struct stat st;

    if (out_size != NULL) {
        *out_size = 0ULL;
    }
    if (!text_present(path) || stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return 0;
    }
    if (out_size != NULL && st.st_size > 0) {
        *out_size = (uint64_t)st.st_size;
    }
    return 1;
}

static int build_saved_state_artifact_path_local(
    char *out_path,
    size_t out_path_size,
    const char *artifact_name
)
{
    const char *output_dir = mft_get_output_dir();

    if (out_path == NULL ||
        out_path_size == 0U ||
        !text_present(output_dir) ||
        !text_present(artifact_name)) {
        return 0;
    }

    return snprintf(
               out_path,
               out_path_size,
               "%s/%s/%s",
               output_dir,
               APP_STATE_DIR_NAME,
               artifact_name) < (int)out_path_size;
}

static int saved_mft_map_available_on_disk_local(void)
{
    char path[1024];

    return build_saved_state_artifact_path_local(
               path,
               sizeof(path),
               "mft_map.c26mft") &&
           regular_nonempty_file_exists_local(path);
}

static uint64_t saved_mft_map_size_on_disk_local(void)
{
    char path[1024];
    uint64_t size = 0ULL;

    if (!build_saved_state_artifact_path_local(
            path,
            sizeof(path),
            "mft_map.c26mft") ||
        !regular_file_size_local(path, &size)) {
        return 0ULL;
    }

    return size;
}

static int should_prefer_spool_for_large_saved_catalog_local(void)
{
    uint64_t mft_map_size;

    if (full_mft_fallback_forced() || !mft_spool_artifacts_available()) {
        return 0;
    }

    mft_map_size = saved_mft_map_size_on_disk_local();
    return mft_map_size >= MFT_ENGINE_LARGE_FULL_LOAD_THRESHOLD_BYTES;
}

static int load_mft_resume_catalog_prefer_targeted_local(void)
{
    if (should_prefer_spool_for_large_saved_catalog_local()) {
        return mft_load_targeted_resume_artifacts();
    }
    return mft_load_resume_artifacts();
}

static int ensure_loaded_full_mft_resume_catalog_local(
    const char *label,
    int *out_loaded
)
{
    const char *resolved_label = text_present(label) ? label : "NTFS resume";
    uint64_t mft_map_size;

    if (out_loaded != NULL) {
        *out_loaded = 0;
    }

    if (mft_entry_count() > 0U) {
        return mft_apply_resume_source_rebase();
    }

    if (!saved_mft_map_available_on_disk_local()) {
        return 1;
    }

    if (should_prefer_spool_for_large_saved_catalog_local()) {
        mft_map_size = saved_mft_map_size_on_disk_local();
        log_info(
            "%s found a large saved NTFS MFT map (%llu MiB); trying targeted recovered-file MFT load before falling back to spool/index metadata",
            resolved_label,
            (unsigned long long)(mft_map_size / (1024ULL * 1024ULL))
        );
        if (mft_load_targeted_resume_artifacts()) {
            if (out_loaded != NULL) {
                *out_loaded = 1;
            }
            return 1;
        }
        log_info(
            "%s could not build a useful targeted MFT subset from the large saved map; using spool/index-backed metadata instead of loading the whole catalog into memory",
            resolved_label
        );
        return 1;
    }

    if (!mft_load_resume_artifacts()) {
        log_error(
            "%s found a saved NTFS MFT map on disk, but the full MFT resume load failed; refusing to treat thinner spool/I30 fallback artifacts as equivalent",
            resolved_label
        );
        return 0;
    }

    if (mft_entry_count() == 0U) {
        log_error(
            "%s found a saved NTFS MFT map on disk, but the full MFT resume load produced zero entries; refusing to continue as if the rich catalog were available",
            resolved_label
        );
        return 0;
    }

    if (out_loaded != NULL) {
        *out_loaded = 1;
    }
    return 1;
}

static MftEngineStatus engine_status_from_mftprobe(MftprobeEngineStatus status)
{
    switch (status) {
        case MFTPROBE_ENGINE_STATUS_OK:
            return MFT_ENGINE_STATUS_OK;
        case MFTPROBE_ENGINE_STATUS_FAILED:
            return MFT_ENGINE_STATUS_FAILED;
        case MFTPROBE_ENGINE_STATUS_INTERRUPTED:
            return MFT_ENGINE_STATUS_INTERRUPTED;
        case MFTPROBE_ENGINE_STATUS_NONE:
        default:
            return MFT_ENGINE_STATUS_NONE;
    }
}

void mft_engine_configure(const MftEngineConfig *config)
{
    MftSpoolConfig spool_config = {0};

    /*
     * Keep the catalog layer and the spool layer configured from the same
     * source of truth so later finalize/resume paths do not drift apart.
     */
    if (config == NULL) {
        return;
    }

    mft_set_output_dir(config->output_dir);
    mft_set_requested_formats_csv(config->active_formats_csv);
    mft_set_contextual_output_mode(config->contextual_output_mode);
    mft_set_reset_existing_store(config->reset_existing_store);
    mft_set_recovery_categories(
        config->recover_img,
        config->recover_vid,
        config->recover_doc
    );
    mft_set_deleted_filter(
        config->has_deleted_filter,
        config->deleted_value
    );
    mft_set_deleted_filter_recycle_policy(
        config->include_recycle_bin_with_live_filter
    );
    mft_set_date_filter(
        config->has_date_filter,
        config->date_start_yyyymmdd,
        config->date_end_yyyymmdd
    );
    mft_set_force_ntfs_target(config->force_ntfs_target);

    spool_config.output_dir = config->output_dir;
    spool_config.service_id = config->service_id;
    spool_config.contextual_output_mode = config->contextual_output_mode;
    spool_config.reset_existing_store = config->reset_existing_store;
    mft_spool_configure(&spool_config);
}

void mft_engine_prepare_background_child(void)
{
    mft_spool_prepare_background_child();
}

int mft_engine_configure_from_source(const char *input_path)
{
    int ok = mft_configure_from_source(input_path);

    mft_spool_set_geometry(
        mft_has_ntfs_geometry(),
        mft_get_partition_start(),
        mft_get_cluster_size(),
        (uint32_t)mft_get_record_size()
    );
    return ok;
}

int mft_engine_source_is_definitely_non_ntfs(void)
{
    return mft_source_is_definitely_non_ntfs();
}

const char *mft_engine_source_filesystem_hint(void)
{
    return mft_source_filesystem_hint();
}

size_t mft_engine_record_size(void)
{
    return mft_get_record_size();
}

void mft_engine_set_partial_record_salvage(int enabled)
{
    mft_set_partial_record_salvage(enabled);
}

void mft_engine_set_salvage_first_sector_confirmed_bytes(size_t bytes)
{
    mft_set_salvage_first_sector_confirmed_bytes(bytes);
}

void mft_engine_set_catalog_first_mode(int enabled)
{
    mft_set_catalog_first_mode(enabled);
}

void mft_engine_set_name_trace_enabled(int enabled)
{
    mft_set_name_trace_enabled(enabled);
}

void mft_engine_set_finalize_opportunistic_budget_seconds(
    double seconds,
    const char *profile_label
)
{
    mft_set_finalize_opportunistic_budget_seconds(seconds, profile_label);
}

void mft_engine_emit_i30_name_trace_sample(size_t limit)
{
    mft_emit_i30_name_trace_sample(limit);
}

void mft_engine_reset_record_salvage_stats(void)
{
    mft_reset_record_salvage_stats();
}

void mft_engine_get_record_salvage_stats(MftRecordSalvageStats *out_stats)
{
    mft_get_record_salvage_stats(out_stats);
}

int mft_engine_preview_recovered_output_match(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    MftRecoveredMatchKind *out_kind
)
{
    return mft_preview_recovered_output_match(
        abs_offset,
        current_path,
        recovered_extension,
        out_kind
    );
}

int mft_engine_collect_recovered_output_match_signals(
    long long abs_offset,
    const char *current_path,
    const char *recovered_extension,
    MftRecoveredMatchSignals *out_signals
)
{
    return mft_collect_recovered_output_match_signals(
        abs_offset,
        current_path,
        recovered_extension,
        out_signals
    );
}

void mft_engine_get_name_uniqueness_stats(MftNameUniquenessStats *out_stats)
{
    mft_get_name_uniqueness_stats(out_stats);
}

int mft_engine_get_name_candidate_index_stats(MftNameCandidateIndexStats *out_stats)
{
    return mft_get_name_candidate_index_stats(out_stats);
}

int mft_engine_write_name_candidate_index(MftNameCandidateIndexStats *out_stats)
{
    return mft_write_name_candidate_index(out_stats);
}

int mft_engine_write_name_match_preview(MftNameMatchPreviewStats *out_stats)
{
    return mft_write_name_match_preview(out_stats);
}

size_t mft_engine_observe_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset,
    int allow_unaligned
)
{
    size_t observed = 0;

    /*
     * Shared fast-path for foreground scans that want to feed MFT records
     * into the catalog directly from an already-read buffer. It supports
     * both aligned candidate stepping and a looser signature search mode.
     */
    if (buffer == NULL || buffer_length < 4U) {
        return 0;
    }

    if (!allow_unaligned) {
        size_t record_size = mft_engine_record_size();
        size_t absolute_start;
        size_t absolute_end;
        size_t candidate_abs;

        if (record_size == 0) {
            record_size = 1024U;
        }
        if (buffer_base_offset > (uint64_t)SIZE_MAX ||
            buffer_length > SIZE_MAX - (size_t)buffer_base_offset) {
            return 0;
        }

        absolute_start = (size_t)buffer_base_offset;
        absolute_end = absolute_start + buffer_length;
        candidate_abs = mft_next_candidate_offset(absolute_start);

        while (candidate_abs < absolute_end) {
            size_t offset = candidate_abs - absolute_start;

            if (app_stop_requested()) {
                break;
            }

            if (offset + 4U > buffer_length) {
                break;
            }
            if (buffer[offset] == 'F' &&
                buffer[offset + 1U] == 'I' &&
                buffer[offset + 2U] == 'L' &&
                buffer[offset + 3U] == 'E') {
                mft_process_record_at(
                    buffer,
                    buffer_length,
                    candidate_abs,
                    offset,
                    0
                );
                observed++;
            }

            if (record_size > SIZE_MAX - candidate_abs) {
                break;
            }
            candidate_abs += record_size;
        }

        return observed;
    }

    {
        const unsigned char *cursor = buffer;
        const unsigned char *end = buffer + buffer_length;

        while (cursor + 4U <= end) {
            const unsigned char *match;
            size_t offset;
            size_t remaining = (size_t)(end - cursor);

            if (app_stop_requested()) {
                break;
            }

            match = (const unsigned char *)memchr(cursor, 'F', remaining);
            if (match == NULL || match + 4U > end) {
                break;
            }

            offset = (size_t)(match - buffer);
            cursor = match + 1U;

            if (match[1] != 'I' || match[2] != 'L' || match[3] != 'E') {
                continue;
            }
            if (buffer_base_offset > (uint64_t)SIZE_MAX - (uint64_t)offset) {
                continue;
            }

            mft_process_record_at(
                buffer,
                buffer_length,
                (size_t)(buffer_base_offset + (uint64_t)offset),
                offset,
                allow_unaligned
            );
            observed++;
        }
    }

    return observed;
}

int mft_engine_refresh_record_at(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t absolute_offset,
    size_t buffer_offset
)
{
    if (absolute_offset > (uint64_t)SIZE_MAX) {
        return 0;
    }

    return mft_refresh_record_at(
        buffer,
        buffer_length,
        (size_t)absolute_offset,
        buffer_offset
    );
}

int mft_engine_record_offset_is_naming_ready(uint64_t absolute_offset)
{
    return mft_record_offset_is_naming_ready(absolute_offset);
}

size_t mft_engine_collect_partial_metadata_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
)
{
    return mft_collect_partial_metadata_record_offsets(out_offsets, out_capacity);
}

size_t mft_engine_collect_parent_chain_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
)
{
    return mft_collect_parent_chain_record_offsets(out_offsets, out_capacity);
}

size_t mft_engine_collect_name_detail_record_offsets(
    uint64_t *out_offsets,
    size_t out_capacity
)
{
    return mft_collect_name_detail_record_offsets(out_offsets, out_capacity);
}

size_t mft_engine_collect_i30_scan_targets(
    MftI30ScanTarget *out_targets,
    size_t out_capacity,
    uint64_t max_total_bytes
)
{
    return mft_collect_i30_scan_targets(out_targets, out_capacity, max_total_bytes);
}

size_t mft_engine_absorb_i30_index_buffer(
    const MftI30ScanTarget *target,
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    return mft_absorb_i30_index_buffer(
        target,
        buffer,
        buffer_length,
        buffer_base_offset
    );
}

size_t mft_engine_absorb_usn_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    return mft_absorb_usn_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
}

size_t mft_engine_absorb_lnk_dlt_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    return mft_absorb_lnk_dlt_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
}

size_t mft_engine_absorb_windows_search_records_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    return mft_absorb_windows_search_records_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
}

size_t mft_engine_absorb_vss_evidence_in_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    uint64_t buffer_base_offset
)
{
    return mft_absorb_vss_evidence_in_buffer(
        buffer,
        buffer_length,
        buffer_base_offset
    );
}

size_t mft_engine_refresh_i30_names_from_source(
    const char *source_path,
    uint64_t max_total_bytes,
    size_t max_target_count,
    uint64_t *out_bytes_scanned
)
{
    return mft_refresh_i30_names_from_source(
        source_path,
        max_total_bytes,
        max_target_count,
        out_bytes_scanned
    );
}

size_t mft_engine_i30_name_count(void)
{
    return mft_i30_name_count();
}

int mft_engine_load_resume_artifacts(void)
{
    int spool_loaded = 0;
    int mft_loaded = 0;

    /*
     * Spool artifacts carry helpful live counters and index sidecars, but
     * they are not a substitute for the real MFT catalog. On scan resume we
     * must still reload the saved MFT map when it exists, otherwise a
     * supervised retry wakes up with only thin spool state and then rewrites
     * the rich mft_map.c26mft from scratch as a much smaller snapshot.
     */
    if (!ensure_loaded_full_mft_resume_catalog_local(
            "NTFS scan resume",
            &mft_loaded)) {
        return 0;
    }
    spool_loaded = mft_spool_load_resume_artifacts();

    return mft_entry_count() > 0U || spool_loaded || mft_loaded;
}

int mft_engine_load_finalize_resume_artifacts(void)
{
    int spool_loaded = 0;
    int mft_loaded = 0;
    int recovered_loaded = 0;
    int i30_loaded = 0;

    if (!ensure_loaded_full_mft_resume_catalog_local(
            "NTFS finalize resume",
            &mft_loaded)) {
        return 0;
    }
    spool_loaded = mft_spool_load_resume_artifacts();

    if (mft_recovered_output_count() == 0U) {
        recovered_loaded = mft_load_recovered_outputs_resume_artifacts();
    }
    if (mft_i30_name_count() == 0U) {
        i30_loaded = mft_load_saved_i30_name_artifacts();
    }

    return mft_entry_count() > 0U ||
           spool_loaded ||
           recovered_loaded ||
           i30_loaded ||
           mft_loaded;
}

int mft_engine_load_name_resume_artifacts(void)
{
    int spool_loaded = 0;
    int recovered_loaded = 0;
    int i30_loaded = 0;
    int mft_loaded = 0;

    if (!ensure_loaded_full_mft_resume_catalog_local(
            "NTFS name resume",
            &mft_loaded)) {
        return 0;
    }
    spool_loaded = mft_spool_load_resume_artifacts();

    if (mft_recovered_output_count() == 0U) {
        recovered_loaded = mft_load_recovered_outputs_resume_artifacts();
    }
    if (mft_i30_name_count() == 0U) {
        i30_loaded = mft_load_saved_i30_name_artifacts();
    }

    return mft_entry_count() > 0U ||
           spool_loaded ||
           recovered_loaded ||
           i30_loaded ||
           mft_loaded;
}

int mft_engine_load_recovered_output_state(void)
{
    return mft_load_recovered_outputs_resume_artifacts();
}

int mft_engine_load_full_mft_resume_artifacts(void)
{
    return mft_load_resume_artifacts();
}

int mft_engine_saved_mft_map_available(void)
{
    return saved_mft_map_available_on_disk_local();
}

int mft_engine_saved_spool_artifacts_available(void)
{
    return mft_spool_artifacts_available();
}

int mft_engine_saved_metadata_available(void)
{
    return mft_engine_saved_mft_map_available();
}

static int ntfs_name_catalog_available(void)
{
    return mft_entry_count() > 0U || mft_i30_name_count() > 0U;
}

static int shared_ntfs_name_catalog_confident(void)
{
    size_t entry_count = mft_entry_count();
    size_t i30_count = mft_i30_name_count();
    size_t output_count = mft_recovered_output_count();

    if (output_count == 0U) {
        return ntfs_name_catalog_available();
    }
    if (entry_count > 0U && mft_has_primary_users_root()) {
        return 1;
    }
    if (entry_count >= 512U || i30_count >= 1024U) {
        return 1;
    }

    return 0;
}

static int refresh_spool_indices_after_shared_finalize(const char *label)
{
    if (!mft_spool_artifacts_available()) {
        return 1;
    }

    if (!mft_spool_build_indices()) {
        log_error(
            "%s could not rebuild the saved NTFS spool indices after the shared finalize path",
            text_present(label) ? label : "NTFS finalize"
        );
        return 0;
    }

    return 1;
}

static size_t visible_spool_pending_output_count(void)
{
    MftSpoolLiveStats live_stats = {0};
    size_t mft_pending = mft_unreconciled_output_count();

    mft_spool_get_live_stats(&live_stats);
    if (live_stats.recovered_outputs_current > 0ULL &&
        live_stats.unident_outputs_current < (uint64_t)mft_pending) {
        return (size_t)live_stats.unident_outputs_current;
    }

    return mft_pending;
}

static int load_name_sidecars_without_full_mft_local(void)
{
    int spool_loaded = 0;
    int recovered_loaded = 0;
    int i30_loaded = 0;

    spool_loaded = mft_spool_load_resume_artifacts();
    if (mft_recovered_output_count() == 0U) {
        recovered_loaded = mft_load_recovered_outputs_resume_artifacts();
    }
    if (mft_i30_name_count() == 0U) {
        i30_loaded = mft_load_saved_i30_name_artifacts();
    }

    return spool_loaded ||
           recovered_loaded ||
           i30_loaded ||
           ntfs_name_catalog_available();
}

static int run_shared_ntfs_name_finalize(const char *label)
{
    uint64_t mft_map_size;
    int large_targeted_failed = 0;

    if (mft_entry_count() == 0U &&
        should_prefer_spool_for_large_saved_catalog_local()) {
        mft_map_size = saved_mft_map_size_on_disk_local();
        log_info(
            "%s is using targeted recovered-file MFT loading because the saved MFT map is large (%llu MiB); set CARV_FORCE_FULL_MFT_FALLBACK=1 to force the old full-catalog path",
            text_present(label) ? label : "NTFS name finalize",
            (unsigned long long)(mft_map_size / (1024ULL * 1024ULL))
        );
        if (!mft_load_targeted_resume_artifacts()) {
            large_targeted_failed = 1;
            log_info(
                "%s could not build a targeted MFT subset from the large saved map; continuing with spool/I30 sidecars without forcing a full MFT load",
                text_present(label) ? label : "NTFS name finalize"
            );
        }
    }

    if (!ntfs_name_catalog_available()) {
        if (large_targeted_failed) {
            if (!load_name_sidecars_without_full_mft_local() ||
                !ntfs_name_catalog_available()) {
                return 0;
            }
        } else if (!mft_engine_load_name_resume_artifacts() ||
                   !ntfs_name_catalog_available()) {
            return 0;
        }

        log_info(
            "%s loaded saved NTFS name artifacts so this pass can reuse the shared name/reconcile engine instead of a separate spool-only naming path",
            text_present(label) ? label : "NTFS name finalize"
        );
    }

    if (!shared_ntfs_name_catalog_confident()) {
        log_info(
            "%s loaded saved NTFS name artifacts, but the shared catalog is still thin (mft=%zu i30=%zu outputs=%zu); letting the spool-only fallback rebuild its indices from segment records before naming",
            text_present(label) ? label : "NTFS name finalize",
            mft_entry_count(),
            mft_i30_name_count(),
            mft_recovered_output_count()
        );
        return 0;
    }

    if (!mft_finalize_recovered_outputs_name_only()) {
        return 0;
    }

    return refresh_spool_indices_after_shared_finalize(label);
}

static int run_spool_only_finalize_index_fallback(int force_full_fallback)
{
    if (mft_recovered_output_count() == 0U &&
        !mft_load_recovered_outputs_resume_artifacts()) {
        log_error("Spool-only NTFS finalize fallback could not load recovered output state");
        return 0;
    }

    if (!mft_spool_build_indices()) {
        log_error("Saved spool artifacts could not rebuild naming indices before finalize");
        return 0;
    }

    if (!mft_spool_materialize_output_directories()) {
        log_error("Spool-only NTFS finalize fallback could not prepare output directories from the saved catalog");
        return 0;
    }

    if (!mft_spool_reconcile_outputs()) {
        return 0;
    }

    if (!force_full_fallback || mft_unreconciled_output_count() == 0U) {
        log_info(
            "Spool-only NTFS finalize fallback completed with %zu pending outputs left in unident; the shared richer finalize path was unavailable in this run",
            visible_spool_pending_output_count()
        );
        return 1;
    }

    log_info(
        "Spool-only NTFS finalize fallback left %zu pending outputs; loading the full MFT fallback because CARV_FORCE_FULL_MFT_FALLBACK=1",
        mft_unreconciled_output_count()
    );
    if (!mft_load_resume_artifacts()) {
        log_error("Full MFT fallback could not be loaded after spool-only finalize fallback");
        return 0;
    }

    if (!mft_finalize_index()) {
        return 0;
    }

    return refresh_spool_indices_after_shared_finalize("NTFS finalize fallback");
}

static int run_spool_only_name_finalize_fallback(int force_full_fallback)
{
    int reconcile_ok;

    if (!mft_spool_build_indices()) {
        log_error("Saved spool artifacts were found but index rebuild failed");
        return 0;
    }
    if (!mft_spool_materialize_output_directories()) {
        log_error("Saved spool artifacts could not prepare output directories");
        return 0;
    }

    reconcile_ok = mft_spool_reconcile_outputs_naming_only();
    if (!reconcile_ok) {
        return 0;
    }

    if (force_full_fallback &&
        visible_spool_pending_output_count() > 0U) {
        if (mft_entry_count() == 0U && !mft_load_resume_artifacts()) {
            log_error("Full MFT fallback could not be loaded after spool-only naming fallback");
            return 0;
        }
        log_info(
            "Spool-only NTFS naming fallback left %zu pending outputs; loading the full MFT fallback because CARV_FORCE_FULL_MFT_FALLBACK=1",
            visible_spool_pending_output_count()
        );
        if (!mft_finalize_recovered_outputs_name_only()) {
            return 0;
        }
        return refresh_spool_indices_after_shared_finalize(
            "NTFS naming fallback"
        );
    }

    if (visible_spool_pending_output_count() > 0U) {
        log_info(
            "Spool-only NTFS naming fallback left %zu pending outputs in unident; the shared richer naming path was unavailable in this run",
            visible_spool_pending_output_count()
        );
    }
    return 1;
}

void mft_engine_reconcile_recovered_outputs_live(void)
{
    mft_reconcile_recovered_outputs_live();
}

int mft_engine_prepare_index(void)
{
    return mft_prepare_index();
}

int mft_engine_finalize_index(void)
{
    int force_full_fallback = full_mft_fallback_forced();

    /*
     * NTFS raw-all finalize should prefer the same rich catalog/reconcile
     * path that standalone name reruns rely on, so partial_tree upgrades and
     * auto-name handoffs do not drift into a separate weaker naming engine.
     * Spool-only finalize remains as a last-resort fallback when the richer
     * catalog could not be reloaded at all.
     */
    if (mft_entry_count() > 0U ||
        (mft_spool_artifacts_available() &&
         load_mft_resume_catalog_prefer_targeted_local())) {
        if (!shared_ntfs_name_catalog_confident() &&
            mft_spool_artifacts_available()) {
            log_info(
                "Shared NTFS finalize catalog is thin (mft=%zu i30=%zu outputs=%zu), so raw-all is rebuilding spool indices from segment records before naming",
                mft_entry_count(),
                mft_i30_name_count(),
                mft_recovered_output_count()
            );
            return run_spool_only_finalize_index_fallback(force_full_fallback);
        }
        if (!mft_finalize_index()) {
            return 0;
        }
        return refresh_spool_indices_after_shared_finalize("NTFS finalize");
    }

    if (mft_spool_artifacts_available()) {
        log_info(
            "Shared NTFS finalize catalog was unavailable, so raw-all is falling back to the simpler spool-only finalize path for this run"
        );
        return run_spool_only_finalize_index_fallback(force_full_fallback);
    }

    if (!mft_finalize_index()) {
        return 0;
    }

    return refresh_spool_indices_after_shared_finalize("NTFS finalize");
}

int mft_engine_finalize_recovered_outputs(void)
{
    int force_full_fallback = full_mft_fallback_forced();

    /*
     * Standalone name reruns, completed raw-all resumes, and partial_tree
     * upgrades should all funnel through the same richer NTFS reconcile path.
     * Spool-only naming stays as an emergency fallback when the shared
     * detective/catalog state could not be reloaded at all.
     */
    if (run_shared_ntfs_name_finalize("NTFS name finalize")) {
        return 1;
    }

    if (mft_spool_artifacts_available()) {
        log_info(
            "Shared NTFS name finalize state was unavailable, so this pass is falling back to the simpler spool-only naming path"
        );
        return run_spool_only_name_finalize_fallback(force_full_fallback);
    }

    return mft_finalize_recovered_outputs_name_only();
}

int mft_engine_finalize_recovered_outputs_with_mft_map(void)
{
    if (run_shared_ntfs_name_finalize("Live NTFS name finalize")) {
        return 1;
    }

    if (mft_spool_artifacts_available()) {
        log_info(
            "Live NTFS name finalize is using spool-only metadata because the shared full-MFT catalog is unavailable or intentionally skipped"
        );
        return run_spool_only_name_finalize_fallback(full_mft_fallback_forced());
    }

    return mft_finalize_recovered_outputs_name_only();
}

void mft_engine_close(void)
{
    mft_spool_close();
    mft_close();
}

void mft_engine_set_state_writes_suppressed(int suppressed)
{
    mft_set_state_writes_suppressed(suppressed);
}

size_t mft_engine_entry_count(void)
{
    return mft_entry_count();
}

size_t mft_engine_recovered_output_count(void)
{
    return mft_recovered_output_count();
}

size_t mft_engine_named_output_count(void)
{
    return mft_named_output_count();
}

size_t mft_engine_unreconciled_output_count(void)
{
    return mft_unreconciled_output_count();
}

int mft_engine_is_offset_fully_recovered(long long abs_offset)
{
    return mft_is_offset_fully_recovered(abs_offset);
}

int mft_engine_get_recovered_output_info(
    long long abs_offset,
    char *out_path,
    size_t out_path_size,
    int *out_reconciled
)
{
    return mft_get_recovered_output_info(
        abs_offset,
        out_path,
        out_path_size,
        out_reconciled
    );
}

int mft_engine_build_output_path(char *out, size_t out_size, const char *relative_path)
{
    return mft_build_output_path(out, out_size, relative_path);
}

int mft_engine_build_recovered_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
)
{
    return mft_build_recovered_output_path(
        out_path,
        out_size,
        abs_offset,
        default_directory,
        default_prefix,
        extension
    );
}

int mft_engine_build_deferred_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
)
{
    return mft_build_deferred_output_path(
        out_path,
        out_size,
        abs_offset,
        default_directory,
        default_prefix,
        extension
    );
}

int mft_engine_apply_output_owner_to_path(const char *path)
{
    return mft_apply_output_owner_to_path(path);
}

int mft_engine_apply_created_time_to_path(const char *path, long long abs_offset)
{
    return mft_apply_created_time_to_path(path, abs_offset);
}

int mft_engine_apply_created_time_value_to_path(const char *path, time_t created_time)
{
    return mft_apply_created_time_value_to_path(path, created_time);
}

void mft_engine_note_recovered_output(const char *path, long long abs_offset)
{
    mft_note_recovered_output(path, abs_offset);
}

const char *mft_engine_lookup_path_by_offset(long long abs_offset)
{
    return mft_lookup_path_by_offset(abs_offset);
}

time_t mft_engine_lookup_created_time_by_offset(long long abs_offset)
{
    return mft_lookup_created_time_by_offset(abs_offset);
}

int mft_engine_lookup_scan_hint(long long abs_offset, MftScanHint *out)
{
    return mft_lookup_scan_hint(abs_offset, out);
}

const char *mft_engine_lookup_container_label_by_offset(long long abs_offset)
{
    const char *path = mft_lookup_path_by_offset(abs_offset);

    return container_context_label_from_path(path);
}

int mft_engine_classify_recovered_output_hint(
    long long abs_offset,
    const char *recovered_extension,
    MftRecoveredNamingHint *out_hint
)
{
    return mft_classify_recovered_output_hint(
        abs_offset,
        recovered_extension,
        out_hint
    );
}

void mft_engine_refresh_recovery_state(size_t *entry_count_snapshot)
{
    size_t current_count = mft_entry_count();

    if (entry_count_snapshot != NULL && *entry_count_snapshot == current_count) {
        return;
    }

    mft_refresh_recovery_mode();
    mft_reconcile_recovered_outputs_live();
    if (entry_count_snapshot != NULL) {
        *entry_count_snapshot = current_count;
    }
}

size_t mft_engine_collect_view_entries_in_range(
    long long range_start,
    long long range_end,
    MftViewEntry **out_entries
)
{
    return mft_collect_view_entries_in_range(range_start, range_end, out_entries);
}

int mft_engine_get_view_entry_by_offset(long long abs_offset, MftViewEntry *out)
{
    return mft_get_view_entry_by_offset(abs_offset, out);
}

size_t mft_engine_write_missed_users_report(const char *path)
{
    return mft_write_missed_users_report(path);
}

void mft_engine_background_tick(int final_pass)
{
    mft_spool_background_tick(final_pass);
}

void mft_engine_set_background_conservative(int enabled)
{
    mft_spool_set_background_conservative(enabled);
}

int mft_engine_background_is_conservative(void)
{
    return mft_spool_background_is_conservative();
}

void mft_engine_reset_process_stats(void)
{
    mft_reset_process_stats();
}

void mft_engine_get_process_stats(MftProcessStats *out_stats)
{
    mft_get_process_stats(out_stats);
}

int mft_engine_artifacts_available(const char *out_dir)
{
    struct stat st;
    char mft_path[1024];
    char recovered_path[1024];

    if (!text_present(out_dir)) {
        log_error("Name-only mode needs an output directory");
        return 0;
    }

    if (stat(out_dir, &st) != 0) {
        log_error("Name-only output directory does not exist: %s", out_dir);
        return 0;
    }

    if (!S_ISDIR(st.st_mode)) {
        log_error("Name-only output path is not a directory: %s", out_dir);
        return 0;
    }

    if (mft_spool_artifacts_available()) {
        return 1;
    }

    if (snprintf(
            mft_path,
            sizeof(mft_path),
            "%s/" APP_STATE_DIR_NAME "/mft_map.c26mft",
            out_dir) >=
        (int)sizeof(mft_path)) {
        log_error("Name-only MFT map path is too long under %s", out_dir);
        return 0;
    }

    if (!regular_nonempty_file_exists_local(mft_path)) {
        log_error("Name-only requires %s, but it was not found", mft_path);
        return 0;
    }

    if (snprintf(
            recovered_path,
            sizeof(recovered_path),
            "%s/" APP_STATE_DIR_NAME "/recovered_outputs.tsv",
            out_dir) <
            (int)sizeof(recovered_path) &&
        !regular_nonempty_file_exists_local(recovered_path)) {
        log_info(
            "Name-only note: %s is missing; there may be nothing to rename",
            recovered_path
        );
    }

    return 1;
}

int mft_engine_is_internal_output_artifact_name(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return 1;
    }

    return strcmp(name, "scan_state.txt") == 0 ||
           strcmp(name, ".DS_Store") == 0 ||
           strcmp(name, "mft_map.c26mft") == 0 ||
           strcmp(name, "mft_relevant.bin") == 0 ||
           strcmp(name, "mft_i30_names.tsv") == 0 ||
           strcmp(name, "recovered_outputs.tsv") == 0 ||
           strcmp(name, "users_selected_tree.txt") == 0 ||
           strcmp(name, "missed_users_files.tsv") == 0 ||
           strcmp(name, "mapptr\303\244d") == 0 ||
           strncmp(name, "mft_map_", 8) == 0 ||
           strncmp(name, "mft_relevant_", 13) == 0;
}

int mft_engine_split_run_output_dir(
    const char *run_output_dir,
    char *base_out,
    size_t base_out_size,
    char *run_id,
    size_t run_id_size
)
{
    const char *slash;
    size_t base_len;

    if (!text_present(run_output_dir) ||
        base_out == NULL ||
        base_out_size == 0 ||
        run_id == NULL ||
        run_id_size == 0) {
        return 0;
    }

    slash = strrchr(run_output_dir, '/');
    if (slash == NULL || slash == run_output_dir || slash[1] == '\0') {
        return 0;
    }

    base_len = (size_t)(slash - run_output_dir);
    if (base_len + 1U > base_out_size ||
        strlen(slash + 1) + 1U > run_id_size) {
        return 0;
    }

    memcpy(base_out, run_output_dir, base_len);
    base_out[base_len] = '\0';
    snprintf(run_id, run_id_size, "%s", slash + 1);
    return 1;
}

int mft_engine_run_users_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    uint64_t limit,
    int quick_resume,
    int auto_recover_missed,
    int only_recover_missed,
    const MftEngineUsersOptions *options
)
{
    MftprobeEngineOptions probe_options = {0};

    /*
     * Translate the app/backend-facing "users" option struct into the
     * lower-level mftprobe option struct and reuse the same engine entry.
     */
    if (options != NULL) {
        probe_options.categories_csv = options->categories_csv;
        probe_options.formats_csv = options->formats_csv;
        probe_options.dev_format = options->dev_format;
        probe_options.compare_scope_csv = options->compare_scope_csv;
        probe_options.record_list_path = options->record_list_path;
        probe_options.root_scope_csv = options->root_scope_csv;
        probe_options.root_scope_defaulted = options->root_scope_defaulted;
        probe_options.date_filter_value = options->date_filter_value;
        probe_options.deleted_filter_value = options->deleted_filter_value;
        probe_options.folder_levels = options->folder_levels;
        probe_options.start_offset = options->start_offset;
        probe_options.start_offset_explicit = options->start_offset_explicit;
        probe_options.generic_file_targets = options->generic_file_targets;
    }

    return mftprobe_engine_run_with_options(
        image_path,
        out_dir,
        run_name,
        limit,
        quick_resume,
        auto_recover_missed,
        only_recover_missed,
        options != NULL ? &probe_options : NULL
    );
}

int mft_engine_run_filtered_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    const char *filter_csv,
    uint64_t limit,
    const MftEngineUsersOptions *options
)
{
    MftprobeEngineOptions probe_options = {0};

    /* Same adapter pattern as users-mode, but for targeted filtered work. */
    if (options != NULL) {
        probe_options.categories_csv = options->categories_csv;
        probe_options.formats_csv = options->formats_csv;
        probe_options.dev_format = options->dev_format;
        probe_options.compare_scope_csv = options->compare_scope_csv;
        probe_options.record_list_path = options->record_list_path;
        probe_options.root_scope_csv = options->root_scope_csv;
        probe_options.root_scope_defaulted = options->root_scope_defaulted;
        probe_options.date_filter_value = options->date_filter_value;
        probe_options.deleted_filter_value = options->deleted_filter_value;
        probe_options.folder_levels = options->folder_levels;
        probe_options.start_offset = options->start_offset;
        probe_options.start_offset_explicit = options->start_offset_explicit;
        probe_options.generic_file_targets = options->generic_file_targets;
    }

    return mftprobe_engine_run_filtered_recovery_with_options(
        image_path,
        out_dir,
        run_name,
        filter_csv,
        limit,
        options != NULL ? &probe_options : NULL
    );
}

int mft_engine_run_metadata_jpeg_test(
    const char *image_path,
    const char *out_dir,
    size_t max_files,
    size_t *out_recovered_count
)
{
    return mftprobe_engine_run_metadata_jpeg_test(
        image_path,
        out_dir,
        max_files,
        out_recovered_count
    );
}

int mft_engine_run_compare_mount_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    const char *mount_path,
    const char *filter_csv,
    uint64_t limit,
    const MftEngineUsersOptions *options
)
{
    MftprobeEngineOptions probe_options = {0};

    /* Compare-mode also reuses the same lower-level option packing. */
    if (options != NULL) {
        probe_options.categories_csv = options->categories_csv;
        probe_options.formats_csv = options->formats_csv;
        probe_options.dev_format = options->dev_format;
        probe_options.compare_scope_csv = options->compare_scope_csv;
        probe_options.record_list_path = options->record_list_path;
        probe_options.root_scope_csv = options->root_scope_csv;
        probe_options.root_scope_defaulted = options->root_scope_defaulted;
        probe_options.date_filter_value = options->date_filter_value;
        probe_options.deleted_filter_value = options->deleted_filter_value;
        probe_options.folder_levels = options->folder_levels;
        probe_options.start_offset = options->start_offset;
        probe_options.start_offset_explicit = options->start_offset_explicit;
        probe_options.generic_file_targets = options->generic_file_targets;
    }

    return mftprobe_engine_run_compare_mount_with_options(
        image_path,
        out_dir,
        run_name,
        mount_path,
        filter_csv,
        limit,
        options != NULL ? &probe_options : NULL
    );
}

int mft_engine_list_root_folders(const char *image_path, FILE *out_stream)
{
    return mftprobe_engine_list_root_folders(image_path, out_stream);
}

int mft_engine_list_child_folders(
    const char *image_path,
    const char *parent_path,
    FILE *out_stream
)
{
    return mftprobe_engine_list_child_folders(
        image_path,
        parent_path,
        out_stream
    );
}

int mft_engine_list_root_folders_partial(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    FILE *out_stream
)
{
    return mftprobe_engine_list_root_folders_partial(
        image_path,
        source,
        out_stream
    );
}

int mft_engine_list_child_folders_partial(
    const char *image_path,
    const char *parent_path,
    const MftprobePartialNtfsSource *source,
    FILE *out_stream
)
{
    return mftprobe_engine_list_child_folders_partial(
        image_path,
        parent_path,
        source,
        out_stream
    );
}

int mft_engine_write_selected_tree_ddrescue_domain(
    const char *image_path,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
)
{
    return mftprobe_engine_write_selected_tree_ddrescue_domain(
        image_path,
        root_scope_csv,
        domain_map_path,
        out_range_count,
        out_total_bytes
    );
}

int mft_engine_write_selected_tree_ddrescue_domain_partial(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
)
{
    return mftprobe_engine_write_selected_tree_ddrescue_domain_partial(
        image_path,
        source,
        root_scope_csv,
        domain_map_path,
        out_range_count,
        out_total_bytes
    );
}

static void mft_engine_copy_users_options_to_probe(
    const MftEngineUsersOptions *options,
    MftprobeEngineOptions *probe_options
)
{
    if (probe_options == NULL) return;
    memset(probe_options, 0, sizeof(*probe_options));
    if (options == NULL) return;
    probe_options->categories_csv = options->categories_csv;
    probe_options->formats_csv = options->formats_csv;
    probe_options->dev_format = options->dev_format;
    probe_options->compare_scope_csv = options->compare_scope_csv;
    probe_options->record_list_path = options->record_list_path;
    probe_options->root_scope_csv = options->root_scope_csv;
    probe_options->root_scope_defaulted = options->root_scope_defaulted;
    probe_options->date_filter_value = options->date_filter_value;
    probe_options->deleted_filter_value = options->deleted_filter_value;
    probe_options->folder_levels = options->folder_levels;
    probe_options->start_offset = options->start_offset;
    probe_options->start_offset_explicit = options->start_offset_explicit;
    probe_options->generic_file_targets = options->generic_file_targets;
}

int mft_engine_write_selected_tree_ddrescue_domain_partial_with_options(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    const MftEngineUsersOptions *options,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes,
    uint64_t *out_file_count
)
{
    MftprobeEngineOptions probe_options;

    if (options == NULL) return 0;
    mft_engine_copy_users_options_to_probe(options, &probe_options);
    return mftprobe_engine_write_selected_tree_ddrescue_domain_partial_with_options(
        image_path,
        source,
        &probe_options,
        domain_map_path,
        out_range_count,
        out_total_bytes,
        out_file_count
    );
}

int mft_engine_run_selected_partial_recovery(
    const char *image_path,
    const char *out_dir,
    const MftprobePartialNtfsSource *source,
    const MftEngineUsersOptions *options,
    size_t *out_recovered_count,
    size_t *out_waiting_for_coverage,
    size_t *out_already_present,
    size_t *out_failed,
    size_t *out_folders_with_complete_files
)
{
    MftprobeEngineOptions probe_options;

    if (options == NULL) return 0;
    mft_engine_copy_users_options_to_probe(options, &probe_options);
    return mftprobe_engine_run_selected_partial_recovery(
        image_path,
        out_dir,
        source,
        &probe_options,
        out_recovered_count,
        out_waiting_for_coverage,
        out_already_present,
        out_failed,
        out_folders_with_complete_files
    );
}

MftEngineStatus mft_engine_users_last_status(void)
{
    return engine_status_from_mftprobe(mftprobe_engine_last_status());
}

size_t mft_engine_users_last_recovered_count(void)
{
    return mftprobe_engine_last_recovered_count();
}
