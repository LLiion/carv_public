/*
 * format_pipeline.c
 * Central dispatch for format-specific recovery behavior.
 */

#include "format_pipeline.h"

#include "filtered_image_log.h"
#include "log.h"

#if !TEMP_TREE_ONLY_MODE
#include "app.h"
#include "carver_output.h"
#include "carver_archive.h"
#include "carver_audio.h"
#include "carver_bmp.h"
#include "carver_cfb.h"
#include "carver_gif.h"
#include "carver_jpeg.h"
#include "carver_jp2.h"
#include "carver_mkv.h"
#include "carver_mpeg_ps.h"
#include "carver_mov.h"
#include "carver_pdf.h"
#include "carver_png.h"
#include "carver_psd.h"
#include "carver_raw.h"
#include "carver_riff.h"
#include "carver_sqlite.h"
#include "carver_tiff.h"
#include "carver_zip.h"
#include "image_filter.h"
#include "performance_ledger.h"
#include "recovery_runner.h"
#include "video_validation.h"
#endif

#include <stddef.h>
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static FormatPipelineLiveStats g_format_pipeline_live_stats = {0};

#define FORMAT_KIND_RIFF          (1ULL << 0)
#define FORMAT_KIND_MOV           (1ULL << 1)
#define FORMAT_KIND_MKV           (1ULL << 2)
#define FORMAT_KIND_MP3           (1ULL << 3)
#define FORMAT_KIND_FLAC          (1ULL << 4)
#define FORMAT_KIND_AAC           (1ULL << 5)
#define FORMAT_KIND_RAR           (1ULL << 6)
#define FORMAT_KIND_ISO           (1ULL << 7)
#define FORMAT_KIND_MPEG_PS       (1ULL << 8)
#define FORMAT_KIND_BMP           (1ULL << 9)
#define FORMAT_KIND_TIFF          (1ULL << 10)
#define FORMAT_KIND_GIF           (1ULL << 11)
#define FORMAT_KIND_JPEG          (1ULL << 12)
#define FORMAT_KIND_JP2           (1ULL << 13)
#define FORMAT_KIND_PDF           (1ULL << 14)
#define FORMAT_KIND_PNG           (1ULL << 15)
#define FORMAT_KIND_PSD           (1ULL << 16)
#define FORMAT_KIND_ZIP_CONTAINER (1ULL << 17)
#define FORMAT_KIND_7Z            (1ULL << 18)
#define FORMAT_KIND_RAW           (1ULL << 19)
#define FORMAT_KIND_SQLITE        (1ULL << 20)
#define FORMAT_KIND_CFB           (1ULL << 21)

#define FORMAT_MOV_FTYP_MIN_ATOM_SIZE 16ULL
#define FORMAT_MOV_FTYP_MAX_ATOM_SIZE 4096ULL
#define FORMAT_VIDEO_REJECT_CACHE_SIZE 4096U
#define FORMAT_VIDEO_REJECT_KIND_MOV 1U
#define FORMAT_VIDEO_REJECT_KIND_MPEG_PS 2U

#define FORMAT_EXT_AVI   (1ULL << 0)
#define FORMAT_EXT_WAV   (1ULL << 1)
#define FORMAT_EXT_WEBP  (1ULL << 2)
#define FORMAT_EXT_RMI   (1ULL << 3)
#define FORMAT_EXT_RIFF  (1ULL << 4)
#define FORMAT_EXT_MOV   (1ULL << 5)
#define FORMAT_EXT_MP4   (1ULL << 6)
#define FORMAT_EXT_M4A   (1ULL << 7)
#define FORMAT_EXT_M4B   (1ULL << 8)
#define FORMAT_EXT_M4V   (1ULL << 9)
#define FORMAT_EXT_HEIC  (1ULL << 10)
#define FORMAT_EXT_HEIF  (1ULL << 11)
#define FORMAT_EXT_AVIF  (1ULL << 12)
#define FORMAT_EXT_MKV   (1ULL << 13)
#define FORMAT_EXT_MP3   (1ULL << 14)
#define FORMAT_EXT_FLAC  (1ULL << 15)
#define FORMAT_EXT_AAC   (1ULL << 16)
#define FORMAT_EXT_RAR   (1ULL << 17)
#define FORMAT_EXT_ISO   (1ULL << 18)
#define FORMAT_EXT_MPG   (1ULL << 19)
#define FORMAT_EXT_VOB   (1ULL << 20)
#define FORMAT_EXT_BMP   (1ULL << 21)
#define FORMAT_EXT_DIB   (1ULL << 22)
#define FORMAT_EXT_TIF   (1ULL << 23)
#define FORMAT_EXT_TIFF  (1ULL << 24)
#define FORMAT_EXT_GIF   (1ULL << 25)
#define FORMAT_EXT_JPG   (1ULL << 26)
#define FORMAT_EXT_JPEG  (1ULL << 27)
#define FORMAT_EXT_JPE   (1ULL << 28)
#define FORMAT_EXT_JP2   (1ULL << 29)
#define FORMAT_EXT_PDF   (1ULL << 30)
#define FORMAT_EXT_FDF   (1ULL << 31)
#define FORMAT_EXT_PNG   (1ULL << 32)
#define FORMAT_EXT_PSD   (1ULL << 33)
#define FORMAT_EXT_DOCX  (1ULL << 34)
#define FORMAT_EXT_XLSX  (1ULL << 35)
#define FORMAT_EXT_PPTX  (1ULL << 36)
#define FORMAT_EXT_ZIP   (1ULL << 37)
#define FORMAT_EXT_3GP   (1ULL << 38)
#define FORMAT_EXT_3G2   (1ULL << 39)
#define FORMAT_EXT_7Z    (1ULL << 40)
#define FORMAT_EXT_RAW   (1ULL << 41)
#define FORMAT_EXT_LRCAT (1ULL << 42)
#define FORMAT_EXT_SQLITE (1ULL << 43)
#define FORMAT_EXT_DB    (1ULL << 44)
#define FORMAT_EXT_DOC   (1ULL << 45)
#define FORMAT_EXT_DOT   (1ULL << 46)
#define FORMAT_EXT_XLS   (1ULL << 47)
#define FORMAT_EXT_XLA   (1ULL << 48)
#define FORMAT_EXT_PPT   (1ULL << 49)
#define FORMAT_EXT_PPS   (1ULL << 50)
#define FORMAT_EXT_WIZ   (1ULL << 51)
#define FORMAT_EXT_MSG   (1ULL << 52)
#define FORMAT_EXT_MDB   (1ULL << 53)
#define FORMAT_EXT_VSD   (1ULL << 54)
#define FORMAT_EXT_PUB   (1ULL << 55)
#define FORMAT_EXT_OLE   (1ULL << 56)
#define FORMAT_EXT_ODT   (1ULL << 57)
#define FORMAT_EXT_ODS   (1ULL << 58)
#define FORMAT_EXT_ODP   (1ULL << 59)
#define FORMAT_EXT_EPUB  (1ULL << 60)
#define FORMAT_EXT_APK   (1ULL << 61)
#define FORMAT_EXT_JAR   (1ULL << 62)
#define FORMAT_EXT_XPS   (1ULL << 63)

static uint64_t format_extension_flag_from_normalized(const char *extension);

typedef struct {
    uint64_t absolute_offset;
    unsigned char kind;
    unsigned char valid;
} FormatVideoRejectCacheEntry;

static FormatVideoRejectCacheEntry
    g_format_video_reject_cache[FORMAT_VIDEO_REJECT_CACHE_SIZE];

static const uint64_t FORMAT_KIND_IMAGE_MASK =
    FORMAT_KIND_BMP |
    FORMAT_KIND_TIFF |
    FORMAT_KIND_GIF |
    FORMAT_KIND_JPEG |
    FORMAT_KIND_JP2 |
    FORMAT_KIND_PNG |
    FORMAT_KIND_PSD |
    FORMAT_KIND_RAW;

uint32_t format_pipeline_enabled_categories(const AppConfig *config)
{
    uint32_t mask = FORMAT_PIPELINE_CATEGORY_NONE;

    if (config == NULL) {
        return FORMAT_PIPELINE_CATEGORY_IMAGE |
               FORMAT_PIPELINE_CATEGORY_VIDEO |
               FORMAT_PIPELINE_CATEGORY_DOCUMENT;
    }

    if (config->recover_img) {
        mask |= FORMAT_PIPELINE_CATEGORY_IMAGE;
    }
    if (config->recover_vid) {
        mask |= FORMAT_PIPELINE_CATEGORY_VIDEO;
    }
    if (config->recover_doc) {
        mask |= FORMAT_PIPELINE_CATEGORY_DOCUMENT;
    }

    return mask;
}

int format_pipeline_category_enabled(
    const AppConfig *config,
    uint32_t required_mask
)
{
    uint32_t enabled = format_pipeline_enabled_categories(config);

    if (required_mask == FORMAT_PIPELINE_CATEGORY_NONE) {
        return 1;
    }

    return (enabled & required_mask) == required_mask;
}

static int ascii_tolower_local(int c)
{
    return tolower((unsigned char)c);
}

static int streq_ci_local(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    while (*a != '\0' && *b != '\0') {
        if (ascii_tolower_local((unsigned char)*a) !=
            ascii_tolower_local((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static void normalize_extension_local(char *text)
{
    size_t read_pos = 0;
    size_t write_pos = 0;

    if (text == NULL) {
        return;
    }

    while (text[read_pos] == '.' || isspace((unsigned char)text[read_pos])) {
        read_pos++;
    }

    while (text[read_pos] != '\0' &&
           write_pos + 1U < FORMAT_EXTENSION_MAX) {
        if (!isspace((unsigned char)text[read_pos])) {
            text[write_pos++] =
                (char)ascii_tolower_local((unsigned char)text[read_pos]);
        }
        read_pos++;
    }

    text[write_pos] = '\0';
}

static int order_has_validator(
    const RecoveryOrder *order,
    RecoveryValidatorId validator_id
)
{
    size_t i;

    if (order == NULL) {
        return 0;
    }

    for (i = 0; i < order->count; i++) {
        if (order->formats[i].validator_id == validator_id) {
            return 1;
        }
    }

    return 0;
}

static int order_has_extension(
    const RecoveryOrder *order,
    const char *extension
)
{
    size_t i;
    size_t j;

    if (order == NULL || extension == NULL || extension[0] == '\0') {
        return 0;
    }

    for (i = 0; i < order->count; i++) {
        const RecoveryFormat *format = &order->formats[i];

        if (streq_ci_local(format->default_extension, extension)) {
            return 1;
        }

        if (format->extensions == NULL || format->extension_count == 0) {
            continue;
        }

        for (j = 0; j < format->extension_count; j++) {
            if (streq_ci_local(format->extensions[j], extension)) {
                return 1;
            }
        }
    }

    return 0;
}

static const char *path_basename_local(const char *path)
{
    const char *slash_basename;
    const char *backslash_basename;

    if (path == NULL) {
        return NULL;
    }

    slash_basename = strrchr(path, '/');
    backslash_basename = strrchr(path, '\\');
    if (slash_basename == NULL && backslash_basename == NULL) {
        return path;
    }
    if (slash_basename == NULL) {
        return backslash_basename + 1;
    }
    if (backslash_basename == NULL) {
        return slash_basename + 1;
    }

    return (slash_basename > backslash_basename)
        ? (slash_basename + 1)
        : (backslash_basename + 1);
}

static int view_entry_extension_local(
    const FsViewEntry *view,
    char *out_extension,
    size_t out_extension_size
)
{
    const char *candidate_name;
    const char *basename;
    const char *dot;

    if (out_extension == NULL || out_extension_size == 0U) {
        return 0;
    }

    out_extension[0] = '\0';
    if (view == NULL) {
        return 0;
    }

    candidate_name = view->path[0] != '\0' ? view->path : view->name;
    if (candidate_name == NULL || candidate_name[0] == '\0') {
        return 0;
    }

    basename = path_basename_local(candidate_name);
    if (basename == NULL || basename[0] == '\0') {
        return 0;
    }

    dot = strrchr(basename, '.');
    if (dot == NULL || dot[1] == '\0') {
        return 0;
    }

    snprintf(out_extension, out_extension_size, "%s", dot + 1);
    normalize_extension_local(out_extension);
    return out_extension[0] != '\0';
}

static RecoveryValidatorId metadata_stream_validator_for_extension_local(
    const char *extension
)
{
    if (extension == NULL || extension[0] == '\0') {
        return RECOVERY_VALIDATOR_NONE;
    }

    if (streq_ci_local(extension, "jpg") ||
        streq_ci_local(extension, "jpeg")) {
        return RECOVERY_VALIDATOR_JPEG;
    }
    if (streq_ci_local(extension, "pdf") ||
        streq_ci_local(extension, "fdf")) {
        return RECOVERY_VALIDATOR_PDF;
    }
    if (streq_ci_local(extension, "lrcat") ||
        streq_ci_local(extension, "sqlite") ||
        streq_ci_local(extension, "db")) {
        return RECOVERY_VALIDATOR_SQLITE;
    }
    if (streq_ci_local(extension, "avi") ||
        streq_ci_local(extension, "wav") ||
        streq_ci_local(extension, "webp") ||
        streq_ci_local(extension, "rmi") ||
        streq_ci_local(extension, "riff")) {
        return RECOVERY_VALIDATOR_RIFF;
    }
    return RECOVERY_VALIDATOR_NONE;
}

static uint32_t metadata_stream_category_for_extension_local(const char *extension)
{
    uint64_t extension_flag;

    if (extension == NULL || extension[0] == '\0') {
        return FORMAT_PIPELINE_CATEGORY_NONE;
    }

    extension_flag = format_extension_flag_from_normalized(extension);
    switch (extension_flag) {
        case FORMAT_EXT_BMP:
        case FORMAT_EXT_DIB:
        case FORMAT_EXT_TIF:
        case FORMAT_EXT_TIFF:
        case FORMAT_EXT_GIF:
        case FORMAT_EXT_JPG:
        case FORMAT_EXT_JPEG:
        case FORMAT_EXT_JPE:
        case FORMAT_EXT_JP2:
        case FORMAT_EXT_PNG:
        case FORMAT_EXT_PSD:
        case FORMAT_EXT_HEIC:
        case FORMAT_EXT_HEIF:
        case FORMAT_EXT_AVIF:
        case FORMAT_EXT_WEBP:
        case FORMAT_EXT_RAW:
            return FORMAT_PIPELINE_CATEGORY_IMAGE;
        case FORMAT_EXT_AVI:
        case FORMAT_EXT_MOV:
        case FORMAT_EXT_MP4:
        case FORMAT_EXT_M4V:
        case FORMAT_EXT_3GP:
        case FORMAT_EXT_3G2:
        case FORMAT_EXT_MKV:
        case FORMAT_EXT_MPG:
        case FORMAT_EXT_VOB:
            return FORMAT_PIPELINE_CATEGORY_VIDEO;
        case FORMAT_EXT_PDF:
        case FORMAT_EXT_FDF:
        case FORMAT_EXT_DOCX:
        case FORMAT_EXT_XLSX:
        case FORMAT_EXT_PPTX:
        case FORMAT_EXT_LRCAT:
        case FORMAT_EXT_SQLITE:
        case FORMAT_EXT_DB:
        case FORMAT_EXT_DOC:
        case FORMAT_EXT_DOT:
        case FORMAT_EXT_XLS:
        case FORMAT_EXT_XLA:
        case FORMAT_EXT_PPT:
        case FORMAT_EXT_PPS:
        case FORMAT_EXT_WIZ:
        case FORMAT_EXT_MSG:
        case FORMAT_EXT_MDB:
        case FORMAT_EXT_VSD:
        case FORMAT_EXT_PUB:
        case FORMAT_EXT_OLE:
        case FORMAT_EXT_ODT:
        case FORMAT_EXT_ODS:
        case FORMAT_EXT_ODP:
        case FORMAT_EXT_EPUB:
        case FORMAT_EXT_APK:
        case FORMAT_EXT_JAR:
        case FORMAT_EXT_XPS:
            return FORMAT_PIPELINE_CATEGORY_DOCUMENT;
        default:
            return FORMAT_PIPELINE_CATEGORY_NONE;
    }
}

static int metadata_stream_extension_enabled_local(
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const char *extension
)
{
    uint32_t required_category;

    if (extension == NULL || extension[0] == '\0') {
        return 0;
    }

    if (active_order != NULL) {
        return order_has_extension(active_order, extension);
    }

    required_category = metadata_stream_category_for_extension_local(extension);
    return required_category != FORMAT_PIPELINE_CATEGORY_NONE &&
           format_pipeline_category_enabled(config, required_category);
}

static int build_generic_recovery_target_from_view(
    const FsViewEntry *view,
    size_t absolute_offset,
    const char *output_path,
    const char *extension,
    RecoveryValidatorId validator_id,
    RecoveryTarget *out_target
)
{
    size_t run_index;

    if (view == NULL ||
        output_path == NULL ||
        output_path[0] == '\0' ||
        extension == NULL ||
        extension[0] == '\0' ||
        out_target == NULL ||
        view->run_count == 0U ||
        view->run_truncated ||
        view->data_size == 0U) {
        return 0;
    }

    memset(out_target, 0, sizeof(*out_target));
    out_target->validator_id = validator_id;
    out_target->abs_offset = (uint64_t)absolute_offset;
    out_target->size = view->data_size;
    out_target->expected_size = view->data_size;
    out_target->remaining = view->data_size;
    out_target->record = 0;
    out_target->family = 0U;
    out_target->run_truncated = view->run_truncated != 0;
    snprintf(out_target->extension, sizeof(out_target->extension), "%s", extension);
    snprintf(
        out_target->source_path,
        sizeof(out_target->source_path),
        "%s",
        (view->path[0] != '\0') ? view->path : view->name
    );
    snprintf(out_target->output_path, sizeof(out_target->output_path), "%s", output_path);

    if (validator_id == RECOVERY_VALIDATOR_JPEG) {
        out_target->blob_start[0] = 0xFFU;
        out_target->blob_start[1] = 0xD8U;
        out_target->blob_start[2] = 0xFFU;
        out_target->blob_start_length = 3U;
    } else if (validator_id == RECOVERY_VALIDATOR_RIFF) {
        out_target->blob_start[0] = 'R';
        out_target->blob_start[1] = 'I';
        out_target->blob_start[2] = 'F';
        out_target->blob_start[3] = 'F';
        out_target->blob_start_length = 4U;
    }

    for (run_index = 0; run_index < view->run_count; run_index++) {
        if (view->runs[run_index].byte_length == 0U) {
            return 0;
        }
        out_target->runs[out_target->run_count].abs_offset =
            view->runs[run_index].abs_offset;
        out_target->runs[out_target->run_count].byte_length =
            view->runs[run_index].byte_length;
        out_target->run_count++;
    }

    return out_target->run_count > 0U;
}

static int recover_metadata_target_generic_local(
    Reader *reader,
    size_t absolute_offset,
    const FsViewEntry *view,
    const char *extension,
    RecoveryValidatorId validator_id
)
{
    unsigned char *repair_buffer = NULL;
    size_t repair_buffer_size = recovery_runner_default_read_size();
    char output_path[1024];
    RecoveryTarget target;
    int ok;

    if (reader == NULL || reader->fd < 0 || view == NULL ||
        extension == NULL || extension[0] == '\0') {
        return 0;
    }
    if (validator_id == RECOVERY_VALIDATOR_NONE) {
        return 0;
    }

    if (!fs_backend_build_recovered_output_path(
            output_path,
            sizeof(output_path),
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            extension) ||
        !build_generic_recovery_target_from_view(
            view,
            absolute_offset,
            output_path,
            extension,
            validator_id,
            &target)) {
        return 0;
    }

    repair_buffer = (unsigned char *)malloc(repair_buffer_size);
    if (repair_buffer == NULL) {
        return 0;
    }

    ok = recovery_runner_recover_target_best_effort_fd(
        reader->fd,
        &target,
        repair_buffer,
        repair_buffer_size,
        app_stop_requested
    );
    free(repair_buffer);
    if (!ok) {
        return 0;
    }
    (void)fs_backend_apply_output_owner_to_path(output_path);
    (void)fs_backend_apply_created_time_to_path(output_path, (long long)absolute_offset);
    fs_backend_note_recovered_output(output_path, (long long)absolute_offset);
    return 1;
}

static int metadata_target_already_satisfied_local(
    size_t absolute_offset,
    size_t start_offset,
    const char *extension
)
{
    size_t resume_offset = 0U;

    if (!carver_output_should_skip_existing_recovered(
            (long long)absolute_offset,
            start_offset,
            &resume_offset)) {
        return 0;
    }

    return !carver_output_existing_recovered_allows_replace_attempt(
        (long long)absolute_offset,
        extension
    );
}

int format_pipeline_allows_metadata_stream_recovery(
    const AppConfig *config,
    const RecoveryOrder *active_order
)
{
    if (active_order != NULL) {
        return active_order->count > 0U;
    }
    return format_pipeline_category_enabled(config, FORMAT_PIPELINE_CATEGORY_IMAGE) ||
           format_pipeline_category_enabled(config, FORMAT_PIPELINE_CATEGORY_VIDEO) ||
           format_pipeline_category_enabled(config, FORMAT_PIPELINE_CATEGORY_DOCUMENT);
}

static int format_pipeline_recover_metadata_target_local(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    size_t start_offset,
    size_t absolute_offset,
    const FsViewEntry *view
)
{
    char extension[FORMAT_EXTENSION_MAX];
    RecoveryValidatorId validator_id;

#if !TEMP_TREE_ONLY_MODE
    if (!format_pipeline_allows_metadata_stream_recovery(config, active_order)) {
        return 0;
    }

    if (!view_entry_extension_local(view, extension, sizeof(extension)) ||
        !metadata_stream_extension_enabled_local(config, active_order, extension)) {
        return 0;
    }
    if (metadata_target_already_satisfied_local(
            absolute_offset,
            start_offset,
            extension)) {
        return 1;
    }

    validator_id = metadata_stream_validator_for_extension_local(extension);
    if (validator_id == RECOVERY_VALIDATOR_JPEG) {
        return carver_jpeg_from_mft_stream(
            reader,
            start_offset,
            absolute_offset,
            view
        );
    }
    if (validator_id == RECOVERY_VALIDATOR_NONE) {
        return 0;
    }

    return recover_metadata_target_generic_local(
        reader,
        absolute_offset,
        view,
        extension,
        validator_id
    );
#else
    (void)reader;
    (void)config;
    (void)active_order;
    (void)start_offset;
    (void)absolute_offset;
    (void)view;
    return 0;
#endif
}

int format_pipeline_recover_metadata_target(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    size_t start_offset,
    size_t absolute_offset,
    const FsViewEntry *view
)
{
    return format_pipeline_recover_metadata_target_local(
        reader,
        config,
        active_order,
        start_offset,
        absolute_offset,
        view
    );
}

void format_pipeline_reset_live_stats(void)
{
    memset(&g_format_pipeline_live_stats, 0, sizeof(g_format_pipeline_live_stats));
}

void format_pipeline_get_live_stats(FormatPipelineLiveStats *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_format_pipeline_live_stats;
}

static size_t view_entry_first_run_resume_span(
    const FsViewEntry *view,
    size_t start_offset,
    const Reader *reader
)
{
    size_t span;

    if (view == NULL || reader == NULL || view->run_count == 0U) {
        return start_offset + 1U;
    }

    span = (size_t)view->runs[0].byte_length;
    if (span == 0U) {
        return start_offset + 1U;
    }
    if (start_offset > SIZE_MAX - span) {
        return start_offset + 1U;
    }
    if (start_offset + span > reader->bytes_in_buffer) {
        return reader->bytes_in_buffer > 0U ? reader->bytes_in_buffer - 1U : start_offset + 1U;
    }
    return start_offset + span;
}

static int order_has_mov_family_extension(const RecoveryOrder *order)
{
    return order_has_extension(order, "mov") ||
           order_has_extension(order, "mp4") ||
           order_has_extension(order, "m4a") ||
           order_has_extension(order, "m4b") ||
           order_has_extension(order, "m4v") ||
           order_has_extension(order, "3gp") ||
           order_has_extension(order, "3g2") ||
           order_has_extension(order, "heic") ||
           order_has_extension(order, "heif") ||
           order_has_extension(order, "avif");
}

static int extension_is_raw_family_local(const char *extension)
{
    return streq_ci_local(extension, "raw") ||
           streq_ci_local(extension, "dng") ||
           streq_ci_local(extension, "cr2") ||
           streq_ci_local(extension, "cr3") ||
           streq_ci_local(extension, "crw") ||
           streq_ci_local(extension, "nef") ||
           streq_ci_local(extension, "nrw") ||
           streq_ci_local(extension, "arw") ||
           streq_ci_local(extension, "sr2") ||
           streq_ci_local(extension, "srf") ||
           streq_ci_local(extension, "arq") ||
           streq_ci_local(extension, "orf") ||
           streq_ci_local(extension, "ori") ||
           streq_ci_local(extension, "rw2") ||
           streq_ci_local(extension, "rwl") ||
           streq_ci_local(extension, "pef") ||
           streq_ci_local(extension, "ptx") ||
           streq_ci_local(extension, "srw") ||
           streq_ci_local(extension, "raf") ||
           streq_ci_local(extension, "x3f") ||
           streq_ci_local(extension, "3fr") ||
           streq_ci_local(extension, "fff") ||
           streq_ci_local(extension, "iiq") ||
           streq_ci_local(extension, "mos");
}

static int order_has_raw_family_extension(const RecoveryOrder *order)
{
    size_t i;
    size_t j;

    if (order == NULL) {
        return 0;
    }
    for (i = 0U; i < order->count; i++) {
        const RecoveryFormat *format = &order->formats[i];

        if (extension_is_raw_family_local(format->default_extension)) {
            return 1;
        }
        if (format->extensions == NULL) {
            continue;
        }
        for (j = 0U; j < format->extension_count; j++) {
            if (extension_is_raw_family_local(format->extensions[j])) {
                return 1;
            }
        }
    }
    return 0;
}

static uint64_t format_extension_flag_from_normalized(const char *extension)
{
    if (extension_is_raw_family_local(extension)) {
        return FORMAT_EXT_RAW;
    }
    if (streq_ci_local(extension, "avi")) {
        return FORMAT_EXT_AVI;
    }
    if (streq_ci_local(extension, "wav")) {
        return FORMAT_EXT_WAV;
    }
    if (streq_ci_local(extension, "webp")) {
        return FORMAT_EXT_WEBP;
    }
    if (streq_ci_local(extension, "rmi")) {
        return FORMAT_EXT_RMI;
    }
    if (streq_ci_local(extension, "riff")) {
        return FORMAT_EXT_RIFF;
    }
    if (streq_ci_local(extension, "mov")) {
        return FORMAT_EXT_MOV;
    }
    if (streq_ci_local(extension, "mp4")) {
        return FORMAT_EXT_MP4;
    }
    if (streq_ci_local(extension, "m4a")) {
        return FORMAT_EXT_M4A;
    }
    if (streq_ci_local(extension, "m4b")) {
        return FORMAT_EXT_M4B;
    }
    if (streq_ci_local(extension, "m4v")) {
        return FORMAT_EXT_M4V;
    }
    if (streq_ci_local(extension, "3gp")) {
        return FORMAT_EXT_3GP;
    }
    if (streq_ci_local(extension, "3g2")) {
        return FORMAT_EXT_3G2;
    }
    if (streq_ci_local(extension, "heic")) {
        return FORMAT_EXT_HEIC;
    }
    if (streq_ci_local(extension, "heif")) {
        return FORMAT_EXT_HEIF;
    }
    if (streq_ci_local(extension, "avif")) {
        return FORMAT_EXT_AVIF;
    }
    if (streq_ci_local(extension, "mkv")) {
        return FORMAT_EXT_MKV;
    }
    if (streq_ci_local(extension, "mp3")) {
        return FORMAT_EXT_MP3;
    }
    if (streq_ci_local(extension, "flac")) {
        return FORMAT_EXT_FLAC;
    }
    if (streq_ci_local(extension, "aac")) {
        return FORMAT_EXT_AAC;
    }
    if (streq_ci_local(extension, "rar")) {
        return FORMAT_EXT_RAR;
    }
    if (streq_ci_local(extension, "iso")) {
        return FORMAT_EXT_ISO;
    }
    if (streq_ci_local(extension, "mpg")) {
        return FORMAT_EXT_MPG;
    }
    if (streq_ci_local(extension, "vob")) {
        return FORMAT_EXT_VOB;
    }
    if (streq_ci_local(extension, "bmp")) {
        return FORMAT_EXT_BMP;
    }
    if (streq_ci_local(extension, "dib")) {
        return FORMAT_EXT_DIB;
    }
    if (streq_ci_local(extension, "tif")) {
        return FORMAT_EXT_TIF;
    }
    if (streq_ci_local(extension, "tiff")) {
        return FORMAT_EXT_TIFF;
    }
    if (streq_ci_local(extension, "gif")) {
        return FORMAT_EXT_GIF;
    }
    if (streq_ci_local(extension, "jpg")) {
        return FORMAT_EXT_JPG;
    }
    if (streq_ci_local(extension, "jpeg")) {
        return FORMAT_EXT_JPEG;
    }
    if (streq_ci_local(extension, "jpe")) {
        return FORMAT_EXT_JPE;
    }
    if (streq_ci_local(extension, "jp2")) {
        return FORMAT_EXT_JP2;
    }
    if (streq_ci_local(extension, "pdf")) {
        return FORMAT_EXT_PDF;
    }
    if (streq_ci_local(extension, "fdf")) {
        return FORMAT_EXT_FDF;
    }
    if (streq_ci_local(extension, "png")) {
        return FORMAT_EXT_PNG;
    }
    if (streq_ci_local(extension, "psd")) {
        return FORMAT_EXT_PSD;
    }
    if (streq_ci_local(extension, "docx")) {
        return FORMAT_EXT_DOCX;
    }
    if (streq_ci_local(extension, "xlsx")) {
        return FORMAT_EXT_XLSX;
    }
    if (streq_ci_local(extension, "pptx")) {
        return FORMAT_EXT_PPTX;
    }
    if (streq_ci_local(extension, "zip")) {
        return FORMAT_EXT_ZIP;
    }
    if (streq_ci_local(extension, "7z")) {
        return FORMAT_EXT_7Z;
    }
    if (streq_ci_local(extension, "lrcat")) {
        return FORMAT_EXT_LRCAT;
    }
    if (streq_ci_local(extension, "sqlite")) {
        return FORMAT_EXT_SQLITE;
    }
    if (streq_ci_local(extension, "db")) {
        return FORMAT_EXT_DB;
    }
    if (streq_ci_local(extension, "doc")) {
        return FORMAT_EXT_DOC;
    }
    if (streq_ci_local(extension, "dot")) {
        return FORMAT_EXT_DOT;
    }
    if (streq_ci_local(extension, "xls")) {
        return FORMAT_EXT_XLS;
    }
    if (streq_ci_local(extension, "xla")) {
        return FORMAT_EXT_XLA;
    }
    if (streq_ci_local(extension, "ppt")) {
        return FORMAT_EXT_PPT;
    }
    if (streq_ci_local(extension, "pps")) {
        return FORMAT_EXT_PPS;
    }
    if (streq_ci_local(extension, "wiz")) {
        return FORMAT_EXT_WIZ;
    }
    if (streq_ci_local(extension, "msg")) {
        return FORMAT_EXT_MSG;
    }
    if (streq_ci_local(extension, "mdb")) {
        return FORMAT_EXT_MDB;
    }
    if (streq_ci_local(extension, "vsd")) {
        return FORMAT_EXT_VSD;
    }
    if (streq_ci_local(extension, "pub")) {
        return FORMAT_EXT_PUB;
    }
    if (streq_ci_local(extension, "ole")) {
        return FORMAT_EXT_OLE;
    }
    if (streq_ci_local(extension, "odt")) {
        return FORMAT_EXT_ODT;
    }
    if (streq_ci_local(extension, "ods")) {
        return FORMAT_EXT_ODS;
    }
    if (streq_ci_local(extension, "odp")) {
        return FORMAT_EXT_ODP;
    }
    if (streq_ci_local(extension, "epub")) {
        return FORMAT_EXT_EPUB;
    }
    if (streq_ci_local(extension, "apk")) {
        return FORMAT_EXT_APK;
    }
    if (streq_ci_local(extension, "jar")) {
        return FORMAT_EXT_JAR;
    }
    if (streq_ci_local(extension, "xps")) {
        return FORMAT_EXT_XPS;
    }
    return 0U;
}

static uint64_t format_kind_mask_from_extension_mask(uint64_t extension_mask)
{
    uint64_t kind_mask = 0U;

    if ((extension_mask & (FORMAT_EXT_AVI |
                           FORMAT_EXT_WAV |
                           FORMAT_EXT_WEBP |
                           FORMAT_EXT_RMI |
                           FORMAT_EXT_RIFF)) != 0U) {
        kind_mask |= FORMAT_KIND_RIFF;
    }
    if ((extension_mask & (FORMAT_EXT_MOV |
                           FORMAT_EXT_MP4 |
                           FORMAT_EXT_M4A |
                           FORMAT_EXT_M4B |
                           FORMAT_EXT_M4V |
                           FORMAT_EXT_3GP |
                           FORMAT_EXT_3G2 |
                           FORMAT_EXT_HEIC |
                           FORMAT_EXT_HEIF |
                           FORMAT_EXT_AVIF)) != 0U) {
        kind_mask |= FORMAT_KIND_MOV;
    }
    if ((extension_mask & FORMAT_EXT_MKV) != 0U) {
        kind_mask |= FORMAT_KIND_MKV;
    }
    if ((extension_mask & FORMAT_EXT_MP3) != 0U) {
        kind_mask |= FORMAT_KIND_MP3;
    }
    if ((extension_mask & FORMAT_EXT_FLAC) != 0U) {
        kind_mask |= FORMAT_KIND_FLAC;
    }
    if ((extension_mask & FORMAT_EXT_AAC) != 0U) {
        kind_mask |= FORMAT_KIND_AAC;
    }
    if ((extension_mask & FORMAT_EXT_RAR) != 0U) {
        kind_mask |= FORMAT_KIND_RAR;
    }
    if ((extension_mask & FORMAT_EXT_ISO) != 0U) {
        kind_mask |= FORMAT_KIND_ISO;
    }
    if ((extension_mask & FORMAT_EXT_7Z) != 0U) {
        kind_mask |= FORMAT_KIND_7Z;
    }
    if ((extension_mask & (FORMAT_EXT_MPG | FORMAT_EXT_VOB)) != 0U) {
        kind_mask |= FORMAT_KIND_MPEG_PS;
    }
    if ((extension_mask & (FORMAT_EXT_BMP | FORMAT_EXT_DIB)) != 0U) {
        kind_mask |= FORMAT_KIND_BMP;
    }
    if ((extension_mask & (FORMAT_EXT_TIF | FORMAT_EXT_TIFF)) != 0U) {
        kind_mask |= FORMAT_KIND_TIFF;
    }
    if ((extension_mask & FORMAT_EXT_GIF) != 0U) {
        kind_mask |= FORMAT_KIND_GIF;
    }
    if ((extension_mask & (FORMAT_EXT_JPG | FORMAT_EXT_JPEG | FORMAT_EXT_JPE)) != 0U) {
        kind_mask |= FORMAT_KIND_JPEG;
    }
    if ((extension_mask & FORMAT_EXT_JP2) != 0U) {
        kind_mask |= FORMAT_KIND_JP2;
    }
    if ((extension_mask & (FORMAT_EXT_PDF | FORMAT_EXT_FDF)) != 0U) {
        kind_mask |= FORMAT_KIND_PDF;
    }
    if ((extension_mask & FORMAT_EXT_PNG) != 0U) {
        kind_mask |= FORMAT_KIND_PNG;
    }
    if ((extension_mask & FORMAT_EXT_PSD) != 0U) {
        kind_mask |= FORMAT_KIND_PSD;
    }
    if ((extension_mask & (FORMAT_EXT_ZIP |
                           FORMAT_EXT_DOCX |
                           FORMAT_EXT_XLSX |
                           FORMAT_EXT_PPTX |
                           FORMAT_EXT_ODT |
                           FORMAT_EXT_ODS |
                           FORMAT_EXT_ODP |
                           FORMAT_EXT_EPUB |
                           FORMAT_EXT_APK |
                           FORMAT_EXT_JAR |
                           FORMAT_EXT_XPS)) != 0U) {
        kind_mask |= FORMAT_KIND_ZIP_CONTAINER;
    }
    if ((extension_mask & (FORMAT_EXT_LRCAT |
                           FORMAT_EXT_SQLITE |
                           FORMAT_EXT_DB)) != 0U) {
        kind_mask |= FORMAT_KIND_SQLITE;
    }
    if ((extension_mask & (FORMAT_EXT_DOC |
                           FORMAT_EXT_DOT |
                           FORMAT_EXT_XLS |
                           FORMAT_EXT_XLA |
                           FORMAT_EXT_PPT |
                           FORMAT_EXT_PPS |
                           FORMAT_EXT_WIZ |
                           FORMAT_EXT_MSG |
                           FORMAT_EXT_MDB |
                           FORMAT_EXT_VSD |
                           FORMAT_EXT_PUB |
                           FORMAT_EXT_OLE)) != 0U) {
        kind_mask |= FORMAT_KIND_CFB;
    }
    if ((extension_mask & FORMAT_EXT_RAW) != 0U) {
        kind_mask |= FORMAT_KIND_RAW;
    }

    return kind_mask;
}

static uint64_t format_match_kind_mask(const MagicEntry *match)
{
    char work[256];
    char *cursor;
    uint64_t extension_mask = 0U;

    if (match == NULL || match->type == NULL) {
        return 0U;
    }

    snprintf(work, sizeof(work), "%s", match->type);
    cursor = work;
    while (*cursor != '\0') {
        char *separator = strchr(cursor, '|');

        if (separator != NULL) {
            *separator = '\0';
        }

        normalize_extension_local(cursor);
        if (cursor[0] != '\0') {
            extension_mask |= format_extension_flag_from_normalized(cursor);
        }

        if (separator == NULL) {
            break;
        }
        cursor = separator + 1;
    }

    return format_kind_mask_from_extension_mask(extension_mask);
}

static void format_match_primary_extension_local(
    const MagicEntry *match,
    char *out,
    size_t out_size
)
{
    const char *cursor;
    size_t i = 0;

    if (out == NULL || out_size == 0U) {
        return;
    }
    out[0] = '\0';
    if (match == NULL || match->type == NULL) {
        return;
    }

    cursor = match->type;
    while (*cursor != '\0' && *cursor != '|' && i + 1U < out_size) {
        out[i++] = *cursor++;
    }
    out[i] = '\0';
    normalize_extension_local(out);
}

static uint64_t order_extension_mask(const RecoveryOrder *order)
{
    uint64_t mask = 0U;

    if (order == NULL) {
        return 0U;
    }

    if (order_has_extension(order, "avi")) {
        mask |= FORMAT_EXT_AVI;
    }
    if (order_has_extension(order, "wav")) {
        mask |= FORMAT_EXT_WAV;
    }
    if (order_has_extension(order, "webp")) {
        mask |= FORMAT_EXT_WEBP;
    }
    if (order_has_extension(order, "rmi")) {
        mask |= FORMAT_EXT_RMI;
    }
    if (order_has_extension(order, "riff")) {
        mask |= FORMAT_EXT_RIFF;
    }
    if (order_has_extension(order, "mov")) {
        mask |= FORMAT_EXT_MOV;
    }
    if (order_has_extension(order, "mp4")) {
        mask |= FORMAT_EXT_MP4;
    }
    if (order_has_extension(order, "m4a")) {
        mask |= FORMAT_EXT_M4A;
    }
    if (order_has_extension(order, "m4b")) {
        mask |= FORMAT_EXT_M4B;
    }
    if (order_has_extension(order, "m4v")) {
        mask |= FORMAT_EXT_M4V;
    }
    if (order_has_extension(order, "3gp")) {
        mask |= FORMAT_EXT_3GP;
    }
    if (order_has_extension(order, "3g2")) {
        mask |= FORMAT_EXT_3G2;
    }
    if (order_has_extension(order, "heic")) {
        mask |= FORMAT_EXT_HEIC;
    }
    if (order_has_extension(order, "heif")) {
        mask |= FORMAT_EXT_HEIF;
    }
    if (order_has_extension(order, "avif")) {
        mask |= FORMAT_EXT_AVIF;
    }
    if (order_has_extension(order, "mkv")) {
        mask |= FORMAT_EXT_MKV;
    }
    if (order_has_extension(order, "mp3")) {
        mask |= FORMAT_EXT_MP3;
    }
    if (order_has_extension(order, "flac")) {
        mask |= FORMAT_EXT_FLAC;
    }
    if (order_has_extension(order, "aac")) {
        mask |= FORMAT_EXT_AAC;
    }
    if (order_has_extension(order, "rar")) {
        mask |= FORMAT_EXT_RAR;
    }
    if (order_has_extension(order, "iso")) {
        mask |= FORMAT_EXT_ISO;
    }
    if (order_has_extension(order, "mpg")) {
        mask |= FORMAT_EXT_MPG;
    }
    if (order_has_extension(order, "vob")) {
        mask |= FORMAT_EXT_VOB;
    }
    if (order_has_extension(order, "bmp")) {
        mask |= FORMAT_EXT_BMP;
    }
    if (order_has_extension(order, "dib")) {
        mask |= FORMAT_EXT_DIB;
    }
    if (order_has_extension(order, "tif")) {
        mask |= FORMAT_EXT_TIF;
    }
    if (order_has_extension(order, "tiff")) {
        mask |= FORMAT_EXT_TIFF;
    }
    if (order_has_extension(order, "gif")) {
        mask |= FORMAT_EXT_GIF;
    }
    if (order_has_extension(order, "jpg")) {
        mask |= FORMAT_EXT_JPG;
    }
    if (order_has_extension(order, "jpeg")) {
        mask |= FORMAT_EXT_JPEG;
    }
    if (order_has_extension(order, "jpe")) {
        mask |= FORMAT_EXT_JPE;
    }
    if (order_has_extension(order, "jp2")) {
        mask |= FORMAT_EXT_JP2;
    }
    if (order_has_extension(order, "pdf")) {
        mask |= FORMAT_EXT_PDF;
    }
    if (order_has_extension(order, "fdf")) {
        mask |= FORMAT_EXT_FDF;
    }
    if (order_has_extension(order, "png")) {
        mask |= FORMAT_EXT_PNG;
    }
    if (order_has_extension(order, "psd")) {
        mask |= FORMAT_EXT_PSD;
    }
    if (order_has_extension(order, "docx")) {
        mask |= FORMAT_EXT_DOCX;
    }
    if (order_has_extension(order, "xlsx")) {
        mask |= FORMAT_EXT_XLSX;
    }
    if (order_has_extension(order, "pptx")) {
        mask |= FORMAT_EXT_PPTX;
    }
    if (order_has_extension(order, "zip")) {
        mask |= FORMAT_EXT_ZIP;
    }
    if (order_has_extension(order, "odt")) {
        mask |= FORMAT_EXT_ODT;
    }
    if (order_has_extension(order, "ods")) {
        mask |= FORMAT_EXT_ODS;
    }
    if (order_has_extension(order, "odp")) {
        mask |= FORMAT_EXT_ODP;
    }
    if (order_has_extension(order, "epub")) {
        mask |= FORMAT_EXT_EPUB;
    }
    if (order_has_extension(order, "apk")) {
        mask |= FORMAT_EXT_APK;
    }
    if (order_has_extension(order, "jar")) {
        mask |= FORMAT_EXT_JAR;
    }
    if (order_has_extension(order, "xps")) {
        mask |= FORMAT_EXT_XPS;
    }
    if (order_has_extension(order, "7z")) {
        mask |= FORMAT_EXT_7Z;
    }
    if (order_has_extension(order, "lrcat")) {
        mask |= FORMAT_EXT_LRCAT;
    }
    if (order_has_extension(order, "sqlite")) {
        mask |= FORMAT_EXT_SQLITE;
    }
    if (order_has_extension(order, "db")) {
        mask |= FORMAT_EXT_DB;
    }
    if (order_has_extension(order, "doc")) {
        mask |= FORMAT_EXT_DOC;
    }
    if (order_has_extension(order, "dot")) {
        mask |= FORMAT_EXT_DOT;
    }
    if (order_has_extension(order, "xls")) {
        mask |= FORMAT_EXT_XLS;
    }
    if (order_has_extension(order, "xla")) {
        mask |= FORMAT_EXT_XLA;
    }
    if (order_has_extension(order, "ppt")) {
        mask |= FORMAT_EXT_PPT;
    }
    if (order_has_extension(order, "pps")) {
        mask |= FORMAT_EXT_PPS;
    }
    if (order_has_extension(order, "wiz")) {
        mask |= FORMAT_EXT_WIZ;
    }
    if (order_has_extension(order, "msg")) {
        mask |= FORMAT_EXT_MSG;
    }
    if (order_has_extension(order, "mdb")) {
        mask |= FORMAT_EXT_MDB;
    }
    if (order_has_extension(order, "vsd")) {
        mask |= FORMAT_EXT_VSD;
    }
    if (order_has_extension(order, "pub")) {
        mask |= FORMAT_EXT_PUB;
    }
    if (order_has_extension(order, "ole")) {
        mask |= FORMAT_EXT_OLE;
    }
    if (order_has_raw_family_extension(order)) {
        mask |= FORMAT_EXT_RAW;
    }

    return mask;
}

void format_pipeline_prepare_dispatch_context(
    FormatPipelineDispatchContext *context,
    const AppConfig *config,
    const RecoveryOrder *active_order
)
{
    uint32_t categories;

    if (context == NULL) {
        return;
    }

    memset(context, 0, sizeof(*context));
    categories = format_pipeline_enabled_categories(config);
    context->enabled_categories = categories;

    if (active_order != NULL) {
        uint64_t extension_mask = order_extension_mask(active_order);

        context->active_order_present = 1;
        context->enabled_extension_mask = extension_mask;
        context->enabled_format_mask = format_kind_mask_from_extension_mask(extension_mask);

        if (order_has_validator(active_order, RECOVERY_VALIDATOR_RIFF) ||
            (extension_mask & (FORMAT_EXT_RIFF |
                               FORMAT_EXT_AVI |
                               FORMAT_EXT_WAV |
                               FORMAT_EXT_WEBP |
                               FORMAT_EXT_RMI)) != 0U) {
            context->enabled_format_mask |= FORMAT_KIND_RIFF;
        } else {
            context->enabled_format_mask &= ~FORMAT_KIND_RIFF;
        }
        if (order_has_mov_family_extension(active_order)) {
            context->enabled_format_mask |= FORMAT_KIND_MOV;
        }
        if (order_has_raw_family_extension(active_order)) {
            context->enabled_format_mask |= FORMAT_KIND_RAW;
            context->enabled_extension_mask |= FORMAT_EXT_RAW;
        }
        if (order_has_validator(active_order, RECOVERY_VALIDATOR_JPEG) ||
            (extension_mask & (FORMAT_EXT_JPG | FORMAT_EXT_JPEG)) != 0U) {
            context->enabled_format_mask |= FORMAT_KIND_JPEG;
        } else {
            context->enabled_format_mask &= ~FORMAT_KIND_JPEG;
        }
        return;
    }

    if ((categories & (FORMAT_PIPELINE_CATEGORY_IMAGE |
                       FORMAT_PIPELINE_CATEGORY_VIDEO |
                       FORMAT_PIPELINE_CATEGORY_DOCUMENT)) != 0U) {
        context->enabled_format_mask |= FORMAT_KIND_RIFF;
        context->enabled_extension_mask |= FORMAT_EXT_RIFF |
                                           FORMAT_EXT_AVI |
                                           FORMAT_EXT_WAV |
                                           FORMAT_EXT_WEBP |
                                           FORMAT_EXT_RMI;
    }
    if ((categories & FORMAT_PIPELINE_CATEGORY_VIDEO) != 0U) {
        context->enabled_format_mask |= FORMAT_KIND_MOV |
                                        FORMAT_KIND_MKV |
                                        FORMAT_KIND_MPEG_PS;
        context->enabled_extension_mask |= FORMAT_EXT_MOV |
                                           FORMAT_EXT_MP4 |
                                           FORMAT_EXT_M4A |
                                           FORMAT_EXT_M4B |
                                           FORMAT_EXT_M4V |
                                           FORMAT_EXT_3GP |
                                           FORMAT_EXT_3G2 |
                                           FORMAT_EXT_HEIC |
                                           FORMAT_EXT_HEIF |
                                           FORMAT_EXT_AVIF |
                                           FORMAT_EXT_MKV |
                                           FORMAT_EXT_MPG |
                                           FORMAT_EXT_VOB;
    }
    if ((categories & FORMAT_PIPELINE_CATEGORY_IMAGE) != 0U) {
        context->enabled_format_mask |= FORMAT_KIND_IMAGE_MASK |
                                        FORMAT_KIND_MOV;
        context->enabled_extension_mask |= FORMAT_EXT_BMP |
                                           FORMAT_EXT_DIB |
                                           FORMAT_EXT_TIF |
                                           FORMAT_EXT_TIFF |
                                           FORMAT_EXT_GIF |
                                           FORMAT_EXT_JPG |
                                           FORMAT_EXT_JPEG |
                                           FORMAT_EXT_JPE |
                                           FORMAT_EXT_JP2 |
                                           FORMAT_EXT_PNG |
                                           FORMAT_EXT_PSD |
                                           FORMAT_EXT_HEIC |
                                           FORMAT_EXT_HEIF |
                                           FORMAT_EXT_AVIF |
                                           FORMAT_EXT_RAW;
    }
    if ((categories & FORMAT_PIPELINE_CATEGORY_DOCUMENT) != 0U) {
        context->enabled_format_mask |= FORMAT_KIND_PDF |
                                        FORMAT_KIND_ZIP_CONTAINER |
                                        FORMAT_KIND_SQLITE |
                                        FORMAT_KIND_CFB;
        context->enabled_extension_mask |= FORMAT_EXT_PDF |
                                           FORMAT_EXT_FDF |
                                           FORMAT_EXT_DOCX |
                                           FORMAT_EXT_XLSX |
                                           FORMAT_EXT_PPTX |
                                           FORMAT_EXT_ODT |
                                           FORMAT_EXT_ODS |
                                           FORMAT_EXT_ODP |
                                           FORMAT_EXT_EPUB |
                                           FORMAT_EXT_APK |
                                           FORMAT_EXT_JAR |
                                           FORMAT_EXT_XPS |
                                           FORMAT_EXT_LRCAT |
                                           FORMAT_EXT_SQLITE |
                                           FORMAT_EXT_DB |
                                           FORMAT_EXT_DOC |
                                           FORMAT_EXT_DOT |
                                           FORMAT_EXT_XLS |
                                           FORMAT_EXT_XLA |
                                           FORMAT_EXT_PPT |
                                           FORMAT_EXT_PPS |
                                           FORMAT_EXT_WIZ |
                                           FORMAT_EXT_MSG |
                                           FORMAT_EXT_MDB |
                                           FORMAT_EXT_VSD |
                                           FORMAT_EXT_PUB |
                                           FORMAT_EXT_OLE;
    }
}

int format_pipeline_dispatch_context_allows_jpeg(
    const FormatPipelineDispatchContext *context
)
{
    return context != NULL && (context->enabled_format_mask & FORMAT_KIND_JPEG) != 0U;
}

int format_pipeline_dispatch_context_allows_png(
    const FormatPipelineDispatchContext *context
)
{
    return context != NULL && (context->enabled_format_mask & FORMAT_KIND_PNG) != 0U;
}

int format_pipeline_dispatch_context_allows_pdf(
    const FormatPipelineDispatchContext *context
)
{
    return context != NULL && (context->enabled_format_mask & FORMAT_KIND_PDF) != 0U;
}

static int format_dispatch_context_allows_kind(
    const FormatPipelineDispatchContext *context,
    uint64_t kind
)
{
    return context != NULL && (context->enabled_format_mask & kind) != 0U;
}

static int format_dispatch_context_allows_extension(
    const FormatPipelineDispatchContext *context,
    const char *extension
)
{
    char normalized[FORMAT_EXTENSION_MAX];
    uint64_t flag;

    if (context == NULL || extension == NULL || extension[0] == '\0') {
        return 0;
    }

    snprintf(normalized, sizeof(normalized), "%s", extension);
    normalize_extension_local(normalized);
    flag = format_extension_flag_from_normalized(normalized);
    return flag != 0U && (context->enabled_extension_mask & flag) != 0U;
}

static int format_dispatch_context_allows_extension_flag(
    const FormatPipelineDispatchContext *context,
    uint64_t extension_flag
)
{
    return context != NULL &&
           extension_flag != 0U &&
           (context->enabled_extension_mask & extension_flag) != 0U;
}

static int format_dispatch_context_allows_riff(
    const FormatPipelineDispatchContext *context,
    const char *riff_extension
)
{
    if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_RIFF)) {
        return 0;
    }
    if (context->active_order_present &&
        riff_extension != NULL &&
        !format_dispatch_context_allows_extension(context, riff_extension) &&
        !format_dispatch_context_allows_extension(context, "riff")) {
        return 0;
    }
    return 1;
}

static const char *mov_extension_from_brand(
    const Reader *reader,
    size_t start_offset
)
{
    const unsigned char *brand;

    if (reader == NULL || reader->buffer == NULL ||
        start_offset + 12U > reader->bytes_in_buffer ||
        memcmp(reader->buffer + start_offset + 4U, "ftyp", 4) != 0) {
        return NULL;
    }

    brand = reader->buffer + start_offset + 8U;
    if (memcmp(brand, "M4A ", 4) == 0) {
        return "m4a";
    }
    if (memcmp(brand, "M4B ", 4) == 0) {
        return "m4b";
    }
    if (memcmp(brand, "M4V ", 4) == 0) {
        return "m4v";
    }
    if (memcmp(brand, "3gp4", 4) == 0 ||
        memcmp(brand, "3gp5", 4) == 0) {
        return "3gp";
    }
    if (memcmp(brand, "3g2a", 4) == 0) {
        return "3g2";
    }
    if (memcmp(brand, "heic", 4) == 0 ||
        memcmp(brand, "heix", 4) == 0 ||
        memcmp(brand, "hevc", 4) == 0 ||
        memcmp(brand, "hevx", 4) == 0) {
        return "heic";
    }
    if (memcmp(brand, "mif1", 4) == 0 ||
        memcmp(brand, "msf1", 4) == 0) {
        return "heif";
    }
    if (memcmp(brand, "avif", 4) == 0) {
        return "avif";
    }
    if (memcmp(brand, "isom", 4) == 0 ||
        memcmp(brand, "iso2", 4) == 0 ||
        memcmp(brand, "mp41", 4) == 0 ||
        memcmp(brand, "mp42", 4) == 0) {
        return "mp4";
    }
    if (memcmp(brand, "qt  ", 4) == 0) {
        return "mov";
    }
    return NULL;
}

static int mov_atom_start_from_signature_local(
    const Reader *reader,
    size_t match_offset,
    size_t *out_start_offset
)
{
    if (out_start_offset != NULL) {
        *out_start_offset = match_offset;
    }
    if (reader == NULL ||
        reader->buffer == NULL ||
        out_start_offset == NULL ||
        match_offset >= reader->bytes_in_buffer) {
        return 0;
    }

    if (match_offset + 8U <= reader->bytes_in_buffer &&
        memcmp(reader->buffer + match_offset + 4U, "ftyp", 4U) == 0) {
        *out_start_offset = match_offset;
        return 1;
    }

    if (match_offset >= 4U &&
        match_offset + 4U <= reader->bytes_in_buffer &&
        memcmp(reader->buffer + match_offset, "ftyp", 4U) == 0) {
        uint32_t atom_size =
            ((uint32_t)reader->buffer[match_offset - 4U] << 24) |
            ((uint32_t)reader->buffer[match_offset - 3U] << 16) |
            ((uint32_t)reader->buffer[match_offset - 2U] << 8) |
            (uint32_t)reader->buffer[match_offset - 1U];
        if (atom_size >= 16U) {
            *out_start_offset = match_offset - 4U;
            return 1;
        }
    }

    return 0;
}

static uint64_t mov_atom_size_from_buffer_local(
    const Reader *reader,
    size_t atom_start_offset
)
{
    if (reader == NULL ||
        reader->buffer == NULL ||
        atom_start_offset + 4U > reader->bytes_in_buffer) {
        return 0U;
    }
    return ((uint64_t)reader->buffer[atom_start_offset] << 24) |
           ((uint64_t)reader->buffer[atom_start_offset + 1U] << 16) |
           ((uint64_t)reader->buffer[atom_start_offset + 2U] << 8) |
           (uint64_t)reader->buffer[atom_start_offset + 3U];
}

static int mov_ftyp_atom_size_plausible_local(uint64_t atom_size)
{
    if (atom_size == 1U) {
        return 1;
    }
    return atom_size >= FORMAT_MOV_FTYP_MIN_ATOM_SIZE &&
           atom_size <= FORMAT_MOV_FTYP_MAX_ATOM_SIZE;
}

static void mov_brand_from_buffer_local(
    const Reader *reader,
    size_t atom_start_offset,
    char out_brand[5]
)
{
    if (out_brand == NULL) {
        return;
    }
    memcpy(out_brand, "????", 5U);
    if (reader == NULL ||
        reader->buffer == NULL ||
        atom_start_offset + 12U > reader->bytes_in_buffer ||
        memcmp(reader->buffer + atom_start_offset + 4U, "ftyp", 4U) != 0) {
        return;
    }
    memcpy(out_brand, reader->buffer + atom_start_offset + 8U, 4U);
    out_brand[4] = '\0';
}

static unsigned format_video_reject_cache_slot(
    unsigned char kind,
    uint64_t absolute_offset
)
{
    uint64_t mixed =
        (absolute_offset >> 9U) ^
        (absolute_offset >> 21U) ^
        ((uint64_t)kind * 11400714819323198485ULL);
    return (unsigned)(mixed & (FORMAT_VIDEO_REJECT_CACHE_SIZE - 1U));
}

static int format_video_reject_cache_contains(
    unsigned char kind,
    uint64_t absolute_offset
)
{
    unsigned slot = format_video_reject_cache_slot(kind, absolute_offset);
    const FormatVideoRejectCacheEntry *entry = &g_format_video_reject_cache[slot];

    return entry->valid &&
           entry->kind == kind &&
           entry->absolute_offset == absolute_offset;
}

static void format_video_reject_cache_note(
    unsigned char kind,
    uint64_t absolute_offset
)
{
    unsigned slot = format_video_reject_cache_slot(kind, absolute_offset);

    g_format_video_reject_cache[slot].absolute_offset = absolute_offset;
    g_format_video_reject_cache[slot].kind = kind;
    g_format_video_reject_cache[slot].valid = 1U;
}

typedef struct {
    uint64_t seen;
    uint64_t recovered;
    uint64_t rejected;
    uint64_t skipped;
    uint64_t detailed_rows;
    double started_at;
    double last_flush_at;
} FtypProbePerfStats;

static FtypProbePerfStats g_ftyp_probe_perf_stats = {0};

static double ftyp_probe_now_seconds_local(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (double)ts.tv_sec + ((double)ts.tv_nsec / 1000000000.0);
    }
    return 0.0;
}

static int ftyp_probe_debug_enabled_local(void)
{
    const char *value = getenv("CARV_DEBUG_FTYP");

    return value != NULL && value[0] != '\0' && value[0] != '0';
}

static int ftyp_probe_should_write_detail_local(
    const char *status,
    const char *reason
)
{
    if (ftyp_probe_debug_enabled_local()) {
        return 1;
    }
    if (status == NULL) {
        return 0;
    }
    if (strcmp(status, "recovered") == 0 ||
        strcmp(status, "rejected") == 0) {
        return 1;
    }
    return reason != NULL && strcmp(reason, "disabled_by_format_filter") == 0;
}

static void ftyp_probe_perf_note_local(
    const AppConfig *config,
    const char *status,
    const char *reason,
    uint64_t input_bytes,
    int detail_written,
    int force
)
{
    double now = ftyp_probe_now_seconds_local();
    uint64_t decisions;
    uint64_t useful;
    char note[192];

    if (g_ftyp_probe_perf_stats.started_at <= 0.0) {
        g_ftyp_probe_perf_stats.started_at = now;
    }
    if (g_ftyp_probe_perf_stats.last_flush_at <= 0.0) {
        g_ftyp_probe_perf_stats.last_flush_at = now;
    }

    if (status != NULL && strcmp(status, "recovered") == 0) {
        g_ftyp_probe_perf_stats.recovered++;
    } else if (status != NULL && strcmp(status, "rejected") == 0) {
        g_ftyp_probe_perf_stats.rejected++;
    } else if (status != NULL && strcmp(status, "skipped") == 0) {
        g_ftyp_probe_perf_stats.skipped++;
    } else {
        g_ftyp_probe_perf_stats.seen++;
    }
    if (detail_written) {
        g_ftyp_probe_perf_stats.detailed_rows++;
    }

    decisions =
        g_ftyp_probe_perf_stats.seen +
        g_ftyp_probe_perf_stats.recovered +
        g_ftyp_probe_perf_stats.rejected +
        g_ftyp_probe_perf_stats.skipped;
    useful = g_ftyp_probe_perf_stats.recovered;

    if (!force &&
        decisions % 256U != 0U &&
        (now <= 0.0 ||
         g_ftyp_probe_perf_stats.last_flush_at <= 0.0 ||
         now - g_ftyp_probe_perf_stats.last_flush_at < 30.0)) {
        return;
    }

    snprintf(
        note,
        sizeof(note),
        "seen=%llu recovered=%llu rejected=%llu skipped=%llu detail_rows=%llu last=%s/%s",
        (unsigned long long)g_ftyp_probe_perf_stats.seen,
        (unsigned long long)g_ftyp_probe_perf_stats.recovered,
        (unsigned long long)g_ftyp_probe_perf_stats.rejected,
        (unsigned long long)g_ftyp_probe_perf_stats.skipped,
        (unsigned long long)g_ftyp_probe_perf_stats.detailed_rows,
        status != NULL ? status : "unknown",
        reason != NULL ? reason : ""
    );
    performance_ledger_append(
        config,
        "video",
        "ftyp_probe",
        now > g_ftyp_probe_perf_stats.started_at
            ? now - g_ftyp_probe_perf_stats.started_at
            : 0.0,
        input_bytes,
        decisions > 0U ? decisions - 1U : 0U,
        decisions,
        useful,
        g_ftyp_probe_perf_stats.skipped + g_ftyp_probe_perf_stats.rejected,
        useful > 0U ? "productive" : "no_recovery_yet",
        note
    );
    g_ftyp_probe_perf_stats.last_flush_at = now;
}

static void log_ftyp_probe_local(
    const AppConfig *config,
    const FormatPipelineDispatchContext *context,
    size_t match_absolute_offset,
    size_t candidate_absolute_offset,
    uint64_t atom_size,
    const char *brand,
    const char *extension,
    const char *stage,
    const char *status,
    const char *reason,
    size_t resume_absolute_offset
)
{
    int write_detail =
        ftyp_probe_should_write_detail_local(status, reason);

    if (write_detail) {
        video_ftyp_probe_append(
            config,
            (uint64_t)match_absolute_offset,
            (uint64_t)candidate_absolute_offset,
            atom_size,
            brand,
            extension,
            stage,
            status,
            reason,
            context != NULL ? context->active_order_present : 0,
            context != NULL ? context->enabled_categories : 0U,
            context != NULL ? context->enabled_format_mask : 0U,
            context != NULL ? context->enabled_extension_mask : 0U,
            (uint64_t)resume_absolute_offset
        );
    }
    ftyp_probe_perf_note_local(
        config,
        status,
        reason,
        atom_size,
        write_detail,
        write_detail && status != NULL && strcmp(status, "recovered") == 0
    );
}

static int format_dispatch_context_allows_mov(
    const FormatPipelineDispatchContext *context,
    const char *mov_extension
)
{
    if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_MOV)) {
        return 0;
    }
    if (mov_extension != NULL &&
        !format_dispatch_context_allows_extension(context, mov_extension)) {
        return 0;
    }
    return 1;
}

static const char *riff_extension_from_subtype(
    const Reader *reader,
    size_t start_offset
);

typedef int (*FormatPipelineSmallSkipFn)(
    const Reader *reader,
    size_t start_offset,
    size_t absolute_offset
);

typedef int (*FormatPipelineReaderCarverFn)(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
);

static void log_early_filtered_image_local(
    const char *format,
    size_t absolute_offset,
    uint64_t detected_size,
    uint64_t width,
    uint64_t height
)
{
    filtered_image_log_append_current(
        "raw-dispatch",
        format,
        "small_image_filtered",
        (uint64_t)absolute_offset,
        0U,
        detected_size,
        width,
        height,
        NULL
    );
}

static uint16_t read_u16_le_local_fp(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint16_t read_u16_be_local_fp(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static uint32_t read_u32_le_local_fp(const uint8_t *data)
{
    return ((uint32_t)data[0]) |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint32_t read_u32_be_local_fp(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static int early_skip_small_bmp(
    const Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_span_out
)
{
    uint32_t file_size;
    int32_t width;
    int32_t height;
    uint32_t abs_width;
    uint32_t abs_height;

    if (resume_span_out != NULL) {
        *resume_span_out = 0;
    }
    if (reader == NULL || reader->buffer == NULL ||
        start_offset + 26U > reader->bytes_in_buffer) {
        return 0;
    }
    if (reader->buffer[start_offset] != 0x42U ||
        reader->buffer[start_offset + 1U] != 0x4DU) {
        return 0;
    }

    file_size = read_u32_le_local_fp(reader->buffer + start_offset + 2U);
    width = (int32_t)read_u32_le_local_fp(reader->buffer + start_offset + 18U);
    height = (int32_t)read_u32_le_local_fp(reader->buffer + start_offset + 22U);
    if (file_size == 0U || width == 0 || height == 0) {
        return 0;
    }

    abs_width = (uint32_t)(width < 0 ? -(int64_t)width : (int64_t)width);
    abs_height = (uint32_t)(height < 0 ? -(int64_t)height : (int64_t)height);
    if (!image_filter_should_skip_image(abs_width, abs_height, file_size)) {
        return 0;
    }

    log_early_filtered_image_local(
        "bmp",
        absolute_offset,
        (uint64_t)file_size,
        (uint64_t)abs_width,
        (uint64_t)abs_height
    );
    if (resume_span_out != NULL) {
        *resume_span_out = (size_t)file_size;
    }
    return 1;
}

static int early_skip_small_png(
    const Reader *reader,
    size_t start_offset,
    size_t absolute_offset
)
{
    static const uint8_t png_signature[8] =
        {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    uint32_t width;
    uint32_t height;

    if (reader == NULL || reader->buffer == NULL ||
        start_offset + 24U > reader->bytes_in_buffer) {
        return 0;
    }
    if (memcmp(reader->buffer + start_offset, png_signature, sizeof(png_signature)) != 0) {
        return 0;
    }
    if (memcmp(reader->buffer + start_offset + 12U, "IHDR", 4U) != 0) {
        return 0;
    }

    width = read_u32_be_local_fp(reader->buffer + start_offset + 16U);
    height = read_u32_be_local_fp(reader->buffer + start_offset + 20U);
    if (!image_filter_is_below_min_dimensions(width, height)) {
        return 0;
    }
    log_early_filtered_image_local(
        "png",
        absolute_offset,
        0U,
        (uint64_t)width,
        (uint64_t)height
    );
    return 1;
}

static int early_skip_small_gif(
    const Reader *reader,
    size_t start_offset,
    size_t absolute_offset
)
{
    uint16_t width;
    uint16_t height;

    if (reader == NULL || reader->buffer == NULL ||
        start_offset + 10U > reader->bytes_in_buffer) {
        return 0;
    }
    if (memcmp(reader->buffer + start_offset, "GIF87a", 6U) != 0 &&
        memcmp(reader->buffer + start_offset, "GIF89a", 6U) != 0) {
        return 0;
    }

    width = read_u16_le_local_fp(reader->buffer + start_offset + 6U);
    height = read_u16_le_local_fp(reader->buffer + start_offset + 8U);
    if (!image_filter_is_below_min_dimensions(width, height)) {
        return 0;
    }
    log_early_filtered_image_local(
        "gif",
        absolute_offset,
        0U,
        (uint64_t)width,
        (uint64_t)height
    );
    return 1;
}

static int early_skip_small_psd(
    const Reader *reader,
    size_t start_offset,
    size_t absolute_offset
)
{
    uint32_t width;
    uint32_t height;

    if (reader == NULL || reader->buffer == NULL ||
        start_offset + 26U > reader->bytes_in_buffer) {
        return 0;
    }
    if (memcmp(reader->buffer + start_offset, "8BPS", 4U) != 0) {
        return 0;
    }
    if (read_u16_be_local_fp(reader->buffer + start_offset + 4U) != 1U) {
        return 0;
    }

    height = read_u32_be_local_fp(reader->buffer + start_offset + 14U);
    width = read_u32_be_local_fp(reader->buffer + start_offset + 18U);
    if (!image_filter_is_below_min_dimensions(width, height)) {
        return 0;
    }
    log_early_filtered_image_local(
        "psd",
        absolute_offset,
        0U,
        (uint64_t)width,
        (uint64_t)height
    );
    return 1;
}

static int jpeg_marker_is_start_of_frame_local(uint8_t marker)
{
    switch (marker) {
        case 0xC0:
        case 0xC1:
        case 0xC2:
        case 0xC3:
        case 0xC5:
        case 0xC6:
        case 0xC7:
        case 0xC9:
        case 0xCA:
        case 0xCB:
        case 0xCD:
        case 0xCE:
        case 0xCF:
            return 1;
        default:
            return 0;
    }
}

static int jpeg_marker_has_length_local(uint8_t marker)
{
    if (marker == 0xD8 ||
        marker == 0xD9 ||
        marker == 0x01 ||
        (marker >= 0xD0 && marker <= 0xD7)) {
        return 0;
    }

    return 1;
}

static int buffer_contains_ascii_local(
    const uint8_t *buffer,
    size_t len,
    const char *pattern
)
{
    size_t pattern_len;
    size_t i;

    if (buffer == NULL || pattern == NULL) {
        return 0;
    }

    pattern_len = strlen(pattern);
    if (pattern_len == 0 || pattern_len > len) {
        return 0;
    }

    for (i = 0; i + pattern_len <= len; i++) {
        if (memcmp(buffer + i, pattern, pattern_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static int buffer_contains_utf16le_ascii_local(
    const uint8_t *buffer,
    size_t len,
    const char *pattern
)
{
    size_t pattern_len;
    size_t i;
    size_t j;

    if (buffer == NULL || pattern == NULL) {
        return 0;
    }

    pattern_len = strlen(pattern);
    if (pattern_len == 0 || (pattern_len * 2U) > len) {
        return 0;
    }

    for (i = 0; i + (pattern_len * 2U) <= len; i++) {
        int match = 1;

        for (j = 0; j < pattern_len; j++) {
            if (buffer[i + (j * 2U)] != (uint8_t)pattern[j] ||
                buffer[i + (j * 2U) + 1U] != 0x00U) {
                match = 0;
                break;
            }
        }

        if (match) {
            return 1;
        }
    }

    return 0;
}

static int jpeg_header_looks_kodak_embedded(
    const Reader *reader,
    size_t start_offset
)
{
    size_t available;
    size_t scan_len;
    const uint8_t *data;

    if (reader == NULL || reader->buffer == NULL ||
        start_offset >= reader->bytes_in_buffer) {
        return 0;
    }

    available = reader->bytes_in_buffer - start_offset;
    scan_len = available;
    if (scan_len > (256U * 1024U)) {
        scan_len = 256U * 1024U;
    }
    data = reader->buffer + start_offset;

    return buffer_contains_ascii_local(data, scan_len, "KODAK") ||
           buffer_contains_ascii_local(data, scan_len, "Screen Nail") ||
           buffer_contains_ascii_local(data, scan_len, "Presized image for LCD display") ||
           buffer_contains_utf16le_ascii_local(data, scan_len, "Screen Nail") ||
           buffer_contains_utf16le_ascii_local(data, scan_len, "Presized image for LCD display");
}

static int early_skip_small_jpeg(
    const Reader *reader,
    size_t start_offset,
    size_t absolute_offset
)
{
    size_t cursor;
    size_t scan_end;

    if (reader == NULL || reader->buffer == NULL ||
        start_offset + 4U > reader->bytes_in_buffer) {
        return 0;
    }
    if (reader->buffer[start_offset] != 0xFFU ||
        reader->buffer[start_offset + 1U] != 0xD8U ||
        reader->buffer[start_offset + 2U] != 0xFFU) {
        return 0;
    }

    if (jpeg_header_looks_kodak_embedded(reader, start_offset)) {
        return 0;
    }

    scan_end = start_offset + 4096U;
    if (scan_end > reader->bytes_in_buffer) {
        scan_end = reader->bytes_in_buffer;
    }

    cursor = start_offset + 2U;
    while (cursor + 1U < scan_end) {
        uint8_t marker;
        uint16_t segment_length;

        while (cursor < scan_end && reader->buffer[cursor] != 0xFFU) {
            cursor++;
        }
        if (cursor + 1U >= scan_end) {
            return 0;
        }

        while (cursor < scan_end && reader->buffer[cursor] == 0xFFU) {
            cursor++;
        }
        if (cursor >= scan_end) {
            return 0;
        }

        marker = reader->buffer[cursor++];
        if (marker == 0x00U) {
            continue;
        }
        if (marker == 0xD9U || marker == 0xDAU) {
            return 0;
        }
        if (!jpeg_marker_has_length_local(marker)) {
            continue;
        }
        if (cursor + 2U > scan_end) {
            return 0;
        }

        segment_length = read_u16_be_local_fp(reader->buffer + cursor);
        if (segment_length < 2U || cursor + segment_length > scan_end) {
            return 0;
        }

        if (jpeg_marker_is_start_of_frame_local(marker)) {
            uint16_t height;
            uint16_t width;

            if (segment_length < 7U || cursor + 7U > scan_end) {
                return 0;
            }

            height = read_u16_be_local_fp(reader->buffer + cursor + 3U);
            width = read_u16_be_local_fp(reader->buffer + cursor + 5U);
            if (!image_filter_is_below_min_dimensions(width, height)) {
                return 0;
            }
            log_early_filtered_image_local(
                "jpg",
                absolute_offset,
                0U,
                (uint64_t)width,
                (uint64_t)height
            );
            return 1;
        }

        cursor += segment_length;
    }

    return 0;
}

static const char *riff_extension_from_subtype(
    const Reader *reader,
    size_t start_offset
)
{
    const unsigned char *subtype;

    if (reader == NULL || reader->buffer == NULL ||
        start_offset + 12 > reader->bytes_in_buffer) {
        return NULL;
    }

    subtype = reader->buffer + start_offset + 8;
    if (memcmp(subtype, "AVI ", 4) == 0) {
        return "avi";
    }
    if (memcmp(subtype, "WAVE", 4) == 0) {
        return "wav";
    }
    if (memcmp(subtype, "WEBP", 4) == 0) {
        return "webp";
    }
    if (memcmp(subtype, "RMID", 4) == 0) {
        return "rmi";
    }
    return "riff";
}

static FormatPipelineDispatchResult dispatch_reader_image_carver(
    const FormatPipelineDispatchContext *context,
    uint64_t required_kind_mask,
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    FormatPipelineSmallSkipFn small_skip,
    FormatPipelineReaderCarverFn reader_carver
)
{
    size_t confirmed_span = 0;

    if (!format_dispatch_context_allows_kind(context, required_kind_mask)) {
        return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
    }

    if (small_skip != NULL && small_skip(reader, start_offset, absolute_offset)) {
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if (reader_carver != NULL &&
        reader_carver(
            reader,
            start_offset,
            absolute_offset,
            &confirmed_span) &&
        confirmed_span > 0) {
        if (resume_offset != NULL) {
            *resume_offset = start_offset + confirmed_span;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
    }

    return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
}

static int exact_mft_extension_matches_kind_local(
    const char *extension,
    uint64_t match_kind_mask
)
{
    uint64_t extension_flag;
    uint64_t extension_kind_mask;

    if (extension == NULL || extension[0] == '\0' || match_kind_mask == 0U) {
        return 0;
    }

    extension_flag = format_extension_flag_from_normalized(extension);
    extension_kind_mask = format_kind_mask_from_extension_mask(extension_flag);
    if ((extension_kind_mask & match_kind_mask) != 0U) {
        return 1;
    }

    /*
     * Camera RAW is a family, not one physical container. Some exact MFT
     * RAW files begin with TIFF-like bytes (DNG/CR2/NEF/ARW/RW2/etc.) and
     * CR3 is ISO-BMFF/QuickTime-like. Let the exact MFT path use the
     * runlist in those cases while still rejecting unrelated families.
     */
    if (extension_is_raw_family_local(extension) &&
        (match_kind_mask & (FORMAT_KIND_RAW | FORMAT_KIND_TIFF | FORMAT_KIND_MOV)) != 0U) {
        return 1;
    }

    return 0;
}

static int try_exact_mft_metadata_target_local(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    uint64_t match_kind_mask,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    FormatPipelineDispatchResult *out_result
)
{
    FsScanHint mft_hint = {0};
    FsViewEntry mft_view = {0};
    char extension[FORMAT_EXTENSION_MAX];
    int is_jpeg_candidate = (match_kind_mask & FORMAT_KIND_JPEG) != 0U;

    if (out_result != NULL) {
        *out_result = FORMAT_PIPELINE_DISPATCH_NO_HANDLER;
    }
    if (reader == NULL ||
        !fs_backend_lookup_scan_hint((long long)absolute_offset, &mft_hint) ||
        !mft_hint.exact_data_match ||
        !fs_backend_get_view_entry_by_offset((long long)absolute_offset, &mft_view) ||
        !view_entry_extension_local(&mft_view, extension, sizeof(extension)) ||
        !metadata_stream_extension_enabled_local(config, active_order, extension) ||
        !exact_mft_extension_matches_kind_local(extension, match_kind_mask)) {
        return 0;
    }

    g_format_pipeline_live_stats.metadata_exact_mft_attempts++;
    if (is_jpeg_candidate) {
        g_format_pipeline_live_stats.metadata_exact_jpeg_attempts++;
    }

    if (mft_view.run_truncated) {
        g_format_pipeline_live_stats.metadata_exact_mft_run_truncated++;
        return 0;
    }

    if (format_pipeline_recover_metadata_target_local(
            reader,
            config,
            active_order,
            start_offset,
            absolute_offset,
            &mft_view)) {
        g_format_pipeline_live_stats.metadata_exact_mft_recovered++;
        if (is_jpeg_candidate) {
            g_format_pipeline_live_stats.metadata_exact_jpeg_recovered++;
        }
        if (resume_offset != NULL) {
            *resume_offset = view_entry_first_run_resume_span(
                &mft_view,
                start_offset,
                reader
            );
        }
        if (out_result != NULL) {
            *out_result = FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return 1;
    }

    return 0;
}

FormatPipelineDispatchResult format_pipeline_dispatch_raw_match_with_context(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const FormatPipelineDispatchContext *dispatch_context,
    const MagicTable *magic_table,
    const MagicEntry *match,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
#if !TEMP_TREE_ONLY_MODE
    FormatPipelineDispatchContext local_context;
    const FormatPipelineDispatchContext *context = dispatch_context;
    uint64_t match_kind_mask;
    size_t candidate_start_offset = start_offset;
    size_t candidate_absolute_offset = absolute_offset;
    char replacement_extension[64];

    if (match == NULL) {
        return FORMAT_PIPELINE_DISPATCH_NO_HANDLER;
    }
    if (context == NULL) {
        format_pipeline_prepare_dispatch_context(&local_context, config, active_order);
        context = &local_context;
    }
    match_kind_mask = format_match_kind_mask(match);
    format_match_primary_extension_local(
        match,
        replacement_extension,
        sizeof(replacement_extension));

    if ((match_kind_mask & FORMAT_KIND_MOV) != 0U &&
        mov_atom_start_from_signature_local(
            reader,
            start_offset,
            &candidate_start_offset) &&
        candidate_start_offset <= start_offset &&
        absolute_offset >= start_offset - candidate_start_offset) {
        candidate_absolute_offset =
            absolute_offset - (start_offset - candidate_start_offset);
    }

    if (resume_offset != NULL) {
        *resume_offset = start_offset + 1;
    }

    if (carver_output_should_skip_existing_recovered(
            (long long)absolute_offset,
            start_offset,
            resume_offset)) {
        if (!carver_output_existing_recovered_allows_replace_attempt(
                (long long)absolute_offset,
                replacement_extension)) {
            if ((match_kind_mask & FORMAT_KIND_MOV) != 0U) {
                size_t mov_start_offset = start_offset;
                size_t mov_absolute_offset = absolute_offset;
                const char *mov_extension =
                    mov_extension_from_brand(reader, start_offset);
                char mov_brand[5];
                uint64_t atom_size = 0U;
                size_t resume_absolute_offset =
                    resume_offset != NULL ? *resume_offset : start_offset;

                if (mov_atom_start_from_signature_local(
                        reader,
                        start_offset,
                        &mov_start_offset)) {
                    if (mov_start_offset != start_offset) {
                        mov_extension =
                            mov_extension_from_brand(reader, mov_start_offset);
                        if (mov_start_offset <= start_offset &&
                            absolute_offset >= start_offset - mov_start_offset) {
                            mov_absolute_offset =
                                absolute_offset - (start_offset - mov_start_offset);
                        }
                    }
                    mov_brand_from_buffer_local(reader, mov_start_offset, mov_brand);
                    atom_size = mov_atom_size_from_buffer_local(reader, mov_start_offset);
                    if (resume_offset != NULL &&
                        *resume_offset >= start_offset) {
                        resume_absolute_offset =
                            mov_absolute_offset + (*resume_offset - mov_start_offset);
                    }
                    log_ftyp_probe_local(
                        config,
                        context,
                        absolute_offset,
                        mov_absolute_offset,
                        atom_size,
                        mov_brand,
                        mov_extension,
                        "dispatch",
                        "skipped",
                        "existing_recovered_output",
                        resume_absolute_offset
                    );
                }
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        if (resume_offset != NULL) {
            *resume_offset = start_offset + 1;
        }
    }

    {
        FormatPipelineDispatchResult exact_mft_result =
            FORMAT_PIPELINE_DISPATCH_NO_HANDLER;

        if (try_exact_mft_metadata_target_local(
                reader,
                config,
                active_order,
                match_kind_mask,
                candidate_start_offset,
                candidate_absolute_offset,
                resume_offset,
                &exact_mft_result)) {
            return exact_mft_result;
        }
    }

    if ((match_kind_mask & FORMAT_KIND_RAW) != 0U) {
        size_t local_resume = start_offset;
        int looks_raf =
            start_offset + 16U <= reader->bytes_in_buffer &&
            memcmp(reader->buffer + start_offset, "FUJIFILMCCD-RAW ", 16U) == 0;
        int looks_cr3 =
            (start_offset + 12U <= reader->bytes_in_buffer &&
             memcmp(reader->buffer + start_offset + 4U, "ftypcrx ", 8U) == 0) ||
            (start_offset >= 4U &&
             start_offset + 8U <= reader->bytes_in_buffer &&
             memcmp(reader->buffer + start_offset, "ftypcrx ", 8U) == 0);
        int looks_crw =
            (start_offset + 14U <= reader->bytes_in_buffer &&
             memcmp(reader->buffer + start_offset + 6U, "HEAPCCDR", 8U) == 0) ||
            (start_offset + 8U <= reader->bytes_in_buffer &&
             memcmp(reader->buffer + start_offset, "HEAPCCDR", 8U) == 0);
        int looks_x3f =
            start_offset + 4U <= reader->bytes_in_buffer &&
            memcmp(reader->buffer + start_offset, "FOVb", 4U) == 0;
        int looks_raw_tiff = carver_raw_tiff_probe_buffer(
            reader->buffer,
            reader->bytes_in_buffer,
            start_offset);

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_RAW)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (looks_raf &&
            carver_raw_raf_streaming(
                reader,
                config,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }

        if (looks_cr3 &&
            carver_raw_cr3_streaming(
                reader,
                config,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }

        if (looks_crw &&
            carver_raw_crw_streaming(
                reader,
                config,
                start_offset,
                absolute_offset,
                &local_resume,
                magic_table)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }

        if (looks_x3f &&
            carver_raw_x3f_streaming(
                reader,
                config,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }

        if (looks_raw_tiff &&
            carver_raw_tiff_streaming(
                reader,
                config,
                start_offset,
                absolute_offset,
                &local_resume,
                magic_table)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }

        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_RIFF) != 0U) {
        size_t local_resume = start_offset;
        int riff_enabled;
        const char *riff_extension = riff_extension_from_subtype(reader, start_offset);

        riff_enabled = format_dispatch_context_allows_riff(context, riff_extension);

        if (!riff_enabled) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_riff_streaming(
                reader,
                config,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_MOV) != 0U) {
        size_t local_resume = start_offset;
        size_t mov_start_offset = start_offset;
        size_t mov_absolute_offset = absolute_offset;
        const char *mov_extension =
            mov_extension_from_brand(reader, start_offset);
        char mov_brand[5];
        uint64_t atom_size;

        if (format_video_reject_cache_contains(
                FORMAT_VIDEO_REJECT_KIND_MOV,
                (uint64_t)absolute_offset)) {
            return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
        }

        if (!mov_atom_start_from_signature_local(
                reader,
                start_offset,
                &mov_start_offset)) {
            log_ftyp_probe_local(
                config,
                context,
                absolute_offset,
                absolute_offset,
                0U,
                "????",
                mov_extension,
                "dispatch",
                "skipped",
                "could_not_resolve_ftyp_atom_start",
                absolute_offset + 1U
            );
            return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
        }
        if (mov_start_offset != start_offset) {
            mov_extension = mov_extension_from_brand(reader, mov_start_offset);
            if (mov_start_offset <= start_offset &&
                absolute_offset >= start_offset - mov_start_offset) {
                mov_absolute_offset = absolute_offset - (start_offset - mov_start_offset);
            }
            local_resume = mov_start_offset;
        }
        mov_brand_from_buffer_local(reader, mov_start_offset, mov_brand);
        atom_size = mov_atom_size_from_buffer_local(reader, mov_start_offset);

        if (format_video_reject_cache_contains(
                FORMAT_VIDEO_REJECT_KIND_MOV,
                (uint64_t)mov_absolute_offset)) {
            log_ftyp_probe_local(
                config,
                context,
                absolute_offset,
                mov_absolute_offset,
                atom_size,
                mov_brand,
                mov_extension,
                "dispatch",
                "skipped",
                "cached_rejected_candidate",
                mov_absolute_offset + 1U
            );
            return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
        }

        if (!mov_ftyp_atom_size_plausible_local(atom_size)) {
            format_video_reject_cache_note(
                FORMAT_VIDEO_REJECT_KIND_MOV,
                (uint64_t)mov_absolute_offset);
            log_ftyp_probe_local(
                config,
                context,
                absolute_offset,
                mov_absolute_offset,
                atom_size,
                mov_brand,
                mov_extension,
                "dispatch",
                "skipped",
                "implausible_ftyp_atom_size",
                mov_absolute_offset + 1U
            );
            return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
        }

        log_ftyp_probe_local(
            config,
            context,
            absolute_offset,
            mov_absolute_offset,
            atom_size,
            mov_brand,
            mov_extension,
            "dispatch",
            "seen",
            "mov_kind_signature_matched",
            mov_absolute_offset + 1U
        );

        if (!format_dispatch_context_allows_mov(context, mov_extension)) {
            log_ftyp_probe_local(
                config,
                context,
                absolute_offset,
                mov_absolute_offset,
                atom_size,
                mov_brand,
                mov_extension,
                "dispatch",
                "skipped",
                "disabled_by_format_filter",
                mov_absolute_offset + 1U
            );
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (mov_start_offset != start_offset &&
            carver_output_should_skip_existing_recovered(
                (long long)mov_absolute_offset,
                mov_start_offset,
                &local_resume)) {
            if (!carver_output_existing_recovered_allows_replace_attempt(
                    (long long)mov_absolute_offset,
                    mov_extension)) {
                if (resume_offset != NULL) {
                    *resume_offset = local_resume;
                }
                log_ftyp_probe_local(
                    config,
                    context,
                    absolute_offset,
                    mov_absolute_offset,
                    atom_size,
                    mov_brand,
                    mov_extension,
                    "dispatch",
                    "skipped",
                    "existing_recovered_output_after_atom_rebase",
                    mov_absolute_offset + (local_resume - mov_start_offset)
                );
                return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
            }
            local_resume = mov_start_offset;
        }

        if (carver_mov_streaming(
                reader,
                config,
                mov_start_offset,
                mov_absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            log_ftyp_probe_local(
                config,
                context,
                absolute_offset,
                mov_absolute_offset,
                atom_size,
                mov_brand,
                mov_extension,
                "carver",
                "recovered",
                "mov_carver_completed",
                mov_absolute_offset + (local_resume - mov_start_offset)
            );
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        log_ftyp_probe_local(
            config,
            context,
            absolute_offset,
            mov_absolute_offset,
            atom_size,
            mov_brand,
            mov_extension,
            "carver",
            "rejected",
            "mov_carver_returned_no_output",
            mov_absolute_offset + 1U
        );
        format_video_reject_cache_note(
            FORMAT_VIDEO_REJECT_KIND_MOV,
            (uint64_t)mov_absolute_offset);
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_MKV) != 0U) {
        size_t local_resume = start_offset;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_MKV)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_mkv_streaming(
                reader,
                config,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_MP3) != 0U) {
        size_t local_resume = start_offset;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_MP3)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_mp3_streaming(
                reader,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        if (local_resume > start_offset + 1U) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_FLAC) != 0U) {
        size_t local_resume = start_offset;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_FLAC)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_flac_streaming(
                reader,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        if (local_resume > start_offset + 1U) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_AAC) != 0U) {
        size_t local_resume = start_offset;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_AAC)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_aac_streaming(
                reader,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        if (local_resume > start_offset + 1U) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_RAR) != 0U) {
        size_t local_resume = start_offset;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_RAR)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_rar_streaming(
                reader,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_7Z) != 0U) {
        size_t local_resume = start_offset;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_7Z)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_7z_streaming(
                reader,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_ISO) != 0U) {
        size_t local_resume = start_offset;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_ISO)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_iso_streaming(
                reader,
                start_offset,
                absolute_offset,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_MPEG_PS) != 0U) {
        size_t local_resume = start_offset;
        size_t mpeg_start_offset = start_offset;
        size_t mpeg_absolute_offset = absolute_offset;
        int allow_mpg;
        int allow_vob;
        const char *extension = "mpg";

        if (format_video_reject_cache_contains(
                FORMAT_VIDEO_REJECT_KIND_MPEG_PS,
                (uint64_t)absolute_offset)) {
            return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
        }

        allow_mpg = format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_MPG);
        allow_vob = format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_VOB);

        if (!allow_mpg && !allow_vob) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (!allow_mpg && allow_vob) {
            extension = "vob";
        }

        if (!carver_mpeg_ps_find_pack_start_near(
                reader,
                start_offset,
                &mpeg_start_offset)) {
            return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
        }
        local_resume = mpeg_start_offset;
        if (mpeg_start_offset <= start_offset &&
            absolute_offset >= start_offset - mpeg_start_offset) {
            mpeg_absolute_offset = absolute_offset - (start_offset - mpeg_start_offset);
        }

        if (format_video_reject_cache_contains(
                FORMAT_VIDEO_REJECT_KIND_MPEG_PS,
                (uint64_t)mpeg_absolute_offset)) {
            return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
        }

        if (mpeg_start_offset != start_offset &&
            carver_output_should_skip_existing_recovered(
                (long long)mpeg_absolute_offset,
                mpeg_start_offset,
                &local_resume)) {
            if (!carver_output_existing_recovered_allows_replace_attempt(
                    (long long)mpeg_absolute_offset,
                    extension)) {
                if (resume_offset != NULL) {
                    *resume_offset = local_resume;
                }
                return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
            }
            local_resume = mpeg_start_offset;
        }

        if (carver_mpeg_ps_streaming(
                reader,
                config,
                mpeg_start_offset,
                mpeg_absolute_offset,
                extension,
                &local_resume)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        format_video_reject_cache_note(
            FORMAT_VIDEO_REJECT_KIND_MPEG_PS,
            (uint64_t)mpeg_absolute_offset);
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_BMP) != 0U) {
        size_t confirmed_span = 0;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_BMP)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (early_skip_small_bmp(reader, start_offset, absolute_offset, &confirmed_span) &&
            confirmed_span > 0) {
            if (resume_offset != NULL) {
                *resume_offset = start_offset + confirmed_span;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }

        if (carver_bmp_from_buffer(
                reader->buffer,
                reader->bytes_in_buffer,
                start_offset,
                absolute_offset,
                &confirmed_span) &&
            confirmed_span > 0) {
            if (resume_offset != NULL) {
                *resume_offset = start_offset + confirmed_span;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_TIFF) != 0U) {
        size_t confirmed_span = 0;
        size_t local_resume = start_offset;

        if (format_dispatch_context_allows_kind(context, FORMAT_KIND_RAW) &&
            carver_raw_tiff_probe_buffer(
                reader->buffer,
                reader->bytes_in_buffer,
                start_offset) &&
            carver_raw_tiff_streaming(
                reader,
                config,
                start_offset,
                absolute_offset,
                &local_resume,
                magic_table)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_TIFF)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_tiff_from_buffer(
                reader->buffer,
                reader->bytes_in_buffer,
                start_offset,
                absolute_offset,
                &confirmed_span) &&
            confirmed_span > 0) {
            if (resume_offset != NULL) {
                *resume_offset = start_offset + confirmed_span;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_GIF) != 0U) {
        size_t confirmed_span = 0;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_GIF)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (early_skip_small_gif(reader, start_offset, absolute_offset)) {
            return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
        }

        if (carver_gif_from_buffer(
                reader->buffer,
                reader->bytes_in_buffer,
                start_offset,
                absolute_offset,
                &confirmed_span) &&
            confirmed_span > 0) {
            if (resume_offset != NULL) {
                *resume_offset = start_offset + confirmed_span;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_JPEG) != 0U) {
        return dispatch_reader_image_carver(
            context,
            FORMAT_KIND_JPEG,
            reader,
            start_offset,
            absolute_offset,
            resume_offset,
            early_skip_small_jpeg,
            carver_jpeg_from_reader
        );
    }

    if ((match_kind_mask & FORMAT_KIND_JP2) != 0U) {
        size_t confirmed_span = 0;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_JP2)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_jp2_from_buffer(
                reader->buffer,
                reader->bytes_in_buffer,
                start_offset,
                absolute_offset,
                &confirmed_span) &&
            confirmed_span > 0) {
            if (resume_offset != NULL) {
                *resume_offset = start_offset + confirmed_span;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_PDF) != 0U) {
        size_t confirmed_span = 0;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_PDF)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_pdf_from_reader(
                reader,
                start_offset,
                absolute_offset,
                &confirmed_span) &&
            confirmed_span > 0) {
            if (resume_offset != NULL) {
                *resume_offset = start_offset + confirmed_span;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_SQLITE) != 0U) {
        size_t local_resume = start_offset;
        int allow_lrcat;
        int allow_sqlite;
        int allow_db;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_SQLITE)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        allow_lrcat =
            format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_LRCAT);
        allow_sqlite =
            format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_SQLITE);
        allow_db =
            format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_DB);
        if (!allow_lrcat && !allow_sqlite && !allow_db) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_sqlite_streaming(
                reader,
                start_offset,
                absolute_offset,
                &local_resume,
                allow_lrcat,
                allow_sqlite,
                allow_db)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_CFB) != 0U) {
        size_t local_resume = start_offset;
        uint32_t allowed_extensions = 0U;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_CFB)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_DOC)) {
            allowed_extensions |= CARVER_CFB_ALLOW_DOC;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_DOT)) {
            allowed_extensions |= CARVER_CFB_ALLOW_DOT;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_XLS)) {
            allowed_extensions |= CARVER_CFB_ALLOW_XLS;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_XLA)) {
            allowed_extensions |= CARVER_CFB_ALLOW_XLA;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_PPT)) {
            allowed_extensions |= CARVER_CFB_ALLOW_PPT;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_PPS)) {
            allowed_extensions |= CARVER_CFB_ALLOW_PPS;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_WIZ)) {
            allowed_extensions |= CARVER_CFB_ALLOW_WIZ;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_MSG)) {
            allowed_extensions |= CARVER_CFB_ALLOW_MSG;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_MDB)) {
            allowed_extensions |= CARVER_CFB_ALLOW_MDB;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_VSD)) {
            allowed_extensions |= CARVER_CFB_ALLOW_VSD;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_PUB)) {
            allowed_extensions |= CARVER_CFB_ALLOW_PUB;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_OLE)) {
            allowed_extensions |= CARVER_CFB_ALLOW_DOC |
                                  CARVER_CFB_ALLOW_DOT |
                                  CARVER_CFB_ALLOW_XLS |
                                  CARVER_CFB_ALLOW_XLA |
                                  CARVER_CFB_ALLOW_PPT |
                                  CARVER_CFB_ALLOW_PPS |
                                  CARVER_CFB_ALLOW_WIZ |
                                  CARVER_CFB_ALLOW_MSG |
                                  CARVER_CFB_ALLOW_MDB |
                                  CARVER_CFB_ALLOW_VSD |
                                  CARVER_CFB_ALLOW_PUB;
        }
        if (allowed_extensions == 0U) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_cfb_streaming(
                reader,
                start_offset,
                absolute_offset,
                &local_resume,
                allowed_extensions)) {
            if (resume_offset != NULL) {
                *resume_offset = local_resume;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_PNG) != 0U) {
        return dispatch_reader_image_carver(
            context,
            FORMAT_KIND_PNG,
            reader,
            start_offset,
            absolute_offset,
            resume_offset,
            early_skip_small_png,
            carver_png_from_reader
        );
    }

    if ((match_kind_mask & FORMAT_KIND_PSD) != 0U) {
        size_t confirmed_span = 0;

        if (!format_dispatch_context_allows_kind(context, FORMAT_KIND_PSD)) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (early_skip_small_psd(reader, start_offset, absolute_offset)) {
            return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
        }

        if (carver_psd_from_buffer(
                reader->buffer,
                reader->bytes_in_buffer,
                start_offset,
                absolute_offset,
                &confirmed_span) &&
            confirmed_span > 0) {
            if (resume_offset != NULL) {
                *resume_offset = start_offset + confirmed_span;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    if ((match_kind_mask & FORMAT_KIND_ZIP_CONTAINER) != 0U) {
        size_t confirmed_span = 0;
        uint32_t allowed_extensions = 0U;

        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_DOCX)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_DOCX;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_XLSX)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_XLSX;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_PPTX)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_PPTX;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_ZIP)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_ZIP;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_ODT)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_ODT;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_ODS)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_ODS;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_ODP)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_ODP;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_EPUB)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_EPUB;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_APK)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_APK;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_JAR)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_JAR;
        }
        if (format_dispatch_context_allows_extension_flag(context, FORMAT_EXT_XPS)) {
            allowed_extensions |= CARVER_ZIP_ALLOW_XPS;
        }

        if (allowed_extensions == 0U) {
            return FORMAT_PIPELINE_DISPATCH_SKIPPED_DISABLED;
        }

        if (carver_zip_family_from_buffer(
                reader->buffer,
                reader->bytes_in_buffer,
                start_offset,
                absolute_offset,
                allowed_extensions,
                &confirmed_span) &&
            confirmed_span > 0) {
            if (resume_offset != NULL) {
                *resume_offset = start_offset + confirmed_span;
            }
            return FORMAT_PIPELINE_DISPATCH_HANDLED_RESUME;
        }
        return FORMAT_PIPELINE_DISPATCH_HANDLED_ADVANCE;
    }

    return FORMAT_PIPELINE_DISPATCH_NO_HANDLER;
#else
    (void)reader;
    (void)config;
    (void)active_order;
    (void)dispatch_context;
    (void)match;
    (void)start_offset;
    (void)absolute_offset;
    (void)resume_offset;
    return FORMAT_PIPELINE_DISPATCH_NO_HANDLER;
#endif
}

int format_pipeline_allows_mft_stream_recovery(
    const AppConfig *config,
    const RecoveryOrder *active_order
)
{
    return format_pipeline_allows_metadata_stream_recovery(config, active_order);
}

int format_pipeline_recover_mft_target(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    size_t start_offset,
    size_t absolute_offset,
    const FsViewEntry *view
)
{
    return format_pipeline_recover_metadata_target(
        reader,
        config,
        active_order,
        start_offset,
        absolute_offset,
        view
    );
}

FormatPipelineDispatchResult format_pipeline_dispatch_raw_match(
    Reader *reader,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    const MagicEntry *match,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    return format_pipeline_dispatch_raw_match_with_context(
        reader,
        config,
        active_order,
        NULL,
        NULL,
        match,
        start_offset,
        absolute_offset,
        resume_offset
    );
}
