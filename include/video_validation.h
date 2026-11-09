#ifndef VIDEO_VALIDATION_H
#define VIDEO_VALIDATION_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "config.h"
#include "fs_backend.h"
#include "run_identity.h"

typedef struct {
    const char *container;
    const char *extension;
    const char *status;
    const char *reason;
    uint64_t offset;
    uint64_t bytes;
    uint64_t payload_bytes;
    unsigned units;
    unsigned video_units;
    unsigned audio_units;
    unsigned metadata_units;
    unsigned end_markers;
    uint64_t duration_ms;
    uint64_t sample_entries;
    uint64_t chunk_offsets;
    unsigned tracks;
    const char *table_status;
    int source_exact_hint;
} CarvVideoValidationReport;

static inline const char *video_validation_nonempty_inline(
    const char *value,
    const char *fallback
)
{
    return value != NULL && value[0] != '\0' ? value : fallback;
}

static inline void video_validation_write_tsv_text_inline(
    FILE *file,
    const char *value
)
{
    const char *cursor = video_validation_nonempty_inline(value, "");

    if (file == NULL) {
        return;
    }
    while (*cursor != '\0') {
        unsigned char c = (unsigned char)*cursor;
        if (c == '\t' || c == '\r' || c == '\n') {
            fputc(' ', file);
        } else {
            fputc((int)c, file);
        }
        cursor++;
    }
}

static inline int video_validation_detail_logs_enabled_inline(void)
{
    const char *video_logs = getenv("CARV_ENABLE_VIDEO_DETAIL_LOGS");
    const char *debug_logs = getenv("CARV_DEBUG_LOGS");

    return (video_logs != NULL && video_logs[0] != '\0' && video_logs[0] != '0') ||
           (debug_logs != NULL && debug_logs[0] != '\0' && debug_logs[0] != '0');
}

static inline void video_validation_report_append(
    const AppConfig *config,
    const CarvVideoValidationReport *report
)
{
    char path[1024];
    struct stat st;
    int have_existing;
    FILE *file;

    if (!video_validation_detail_logs_enabled_inline()) {
        (void)config;
        (void)report;
        return;
    }

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0' ||
        report == NULL) {
        return;
    }

    if (snprintf(
            path,
            sizeof(path),
            "%s/%s/video_validation.tsv",
            config->output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    file = fs_backend_fopen_output_write_guarded(path, "a");
    if (file == NULL) {
        return;
    }

    if (!have_existing) {
        fprintf(
            file,
            "offset\tcontainer\textension\tstatus\treason\tbytes\tpayload_bytes\tunits\tvideo_units\taudio_units\tmetadata_units\tend_markers\tduration_ms\ttracks\tsample_entries\tchunk_offsets\ttable_status\tsource_exact_hint\n"
        );
    }

    fprintf(file, "%llu\t", (unsigned long long)report->offset);
    video_validation_write_tsv_text_inline(
        file,
        video_validation_nonempty_inline(report->container, "video")
    );
    fputc('\t', file);
    video_validation_write_tsv_text_inline(
        file,
        video_validation_nonempty_inline(report->extension, "unknown")
    );
    fputc('\t', file);
    video_validation_write_tsv_text_inline(
        file,
        video_validation_nonempty_inline(report->status, "unknown")
    );
    fputc('\t', file);
    video_validation_write_tsv_text_inline(
        file,
        video_validation_nonempty_inline(report->reason, "unknown")
    );
    fprintf(
        file,
        "\t%llu\t%llu\t%u\t%u\t%u\t%u\t%u\t%llu\t%u\t%llu\t%llu\t",
        (unsigned long long)report->bytes,
        (unsigned long long)report->payload_bytes,
        report->units,
        report->video_units,
        report->audio_units,
        report->metadata_units,
        report->end_markers,
        (unsigned long long)report->duration_ms,
        report->tracks,
        (unsigned long long)report->sample_entries,
        (unsigned long long)report->chunk_offsets
    );
    video_validation_write_tsv_text_inline(
        file,
        video_validation_nonempty_inline(report->table_status, "")
    );
    fprintf(file, "\t%d\n", report->source_exact_hint ? 1 : 0);

    fclose(file);
}

static inline void video_ftyp_probe_append(
    const AppConfig *config,
    uint64_t match_offset,
    uint64_t candidate_offset,
    uint64_t atom_size,
    const char *brand,
    const char *extension,
    const char *stage,
    const char *status,
    const char *reason,
    int active_order_present,
    uint32_t enabled_categories,
    uint64_t enabled_format_mask,
    uint64_t enabled_extension_mask,
    uint64_t resume_offset
)
{
    char path[1024];
    struct stat st;
    int have_existing;
    FILE *file;

    if (!video_validation_detail_logs_enabled_inline()) {
        (void)config;
        (void)match_offset;
        (void)candidate_offset;
        (void)atom_size;
        (void)brand;
        (void)extension;
        (void)stage;
        (void)status;
        (void)reason;
        (void)active_order_present;
        (void)enabled_categories;
        (void)enabled_format_mask;
        (void)enabled_extension_mask;
        (void)resume_offset;
        return;
    }

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0') {
        return;
    }

    if (snprintf(
            path,
            sizeof(path),
            "%s/%s/ftyp_probe.tsv",
            config->output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    carv_run_rotate_legacy_tsv_without_generation_inline(path, &have_existing);
    file = fs_backend_fopen_output_write_guarded(path, "a");
    if (file == NULL) {
        return;
    }

    if (!have_existing) {
        fprintf(
            file,
            "generation\tpass_id\tmatch_offset\tcandidate_offset\tatom_size\tbrand\textension\tstage\tstatus\treason\tactive_order_present\tenabled_categories\tenabled_format_mask\tenabled_extension_mask\tresume_offset\n"
        );
    }

    fprintf(
        file,
        "%llu\t",
        (unsigned long long)carv_run_supervisor_generation_inline()
    );
    video_validation_write_tsv_text_inline(file, carv_run_pass_id_inline());
    fprintf(
        file,
        "\t%llu\t%llu\t%llu\t",
        (unsigned long long)match_offset,
        (unsigned long long)candidate_offset,
        (unsigned long long)atom_size
    );
    video_validation_write_tsv_text_inline(file, brand);
    fputc('\t', file);
    video_validation_write_tsv_text_inline(
        file,
        video_validation_nonempty_inline(extension, "unknown")
    );
    fputc('\t', file);
    video_validation_write_tsv_text_inline(
        file,
        video_validation_nonempty_inline(stage, "dispatch")
    );
    fputc('\t', file);
    video_validation_write_tsv_text_inline(
        file,
        video_validation_nonempty_inline(status, "unknown")
    );
    fputc('\t', file);
    video_validation_write_tsv_text_inline(
        file,
        video_validation_nonempty_inline(reason, "")
    );
    fprintf(
        file,
        "\t%d\t%u\t%llu\t%llu\t%llu\n",
        active_order_present ? 1 : 0,
        enabled_categories,
        (unsigned long long)enabled_format_mask,
        (unsigned long long)enabled_extension_mask,
        (unsigned long long)resume_offset
    );

    fclose(file);
}

#endif
