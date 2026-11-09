
/*
 * carver_riff.c
 * Recovers RIFF-based files by reading the size from the RIFF header
 * and streaming the file directly to disk.
 */

#include "carver_riff.h"
#include "carver_output.h"
#include "config.h"
#include "filtered_image_log.h"
#include "image_filter.h"
#include "log.h"
#include "video_validation.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#define RIFF_MAX_REASONABLE_SIZE (512U * 1024U * 1024U)
#define RIFF_AVI_VALIDATE_MAX_CHUNKS 32768U
#define RIFF_AVI_VALIDATE_MAX_DEPTH 6U

typedef struct {
    uint64_t file_size;
    uint64_t duration_ms;
    uint64_t total_frames;
    uint64_t idx1_entries;
    unsigned chunks_seen;
    unsigned list_chunks;
    unsigned hdrl_lists;
    unsigned movi_lists;
    unsigned avih_chunks;
    unsigned strl_lists;
    unsigned strh_chunks;
    unsigned video_streams;
    unsigned audio_streams;
    unsigned idx1_chunks;
    unsigned parse_errors;
    int chunk_limit_hit;
} RiffAviValidationStats;

typedef struct {
    const AppConfig *config;
    size_t absolute_offset;
    uint64_t total_size;
} RiffAviValidationContext;

static CarverAuditReport g_riff_last_audit;

void carver_riff_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_riff_last_audit);
}

void carver_riff_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_riff_last_audit;
}

static uint32_t read_u32_le(const unsigned char *data)
{
    return ((uint32_t)data[0]) |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static int riff_file_read_at(
    FILE *file,
    uint64_t offset,
    unsigned char *buffer,
    size_t length
)
{
    if (file == NULL || buffer == NULL) {
        return 0;
    }
    if (fseeko(file, (off_t)offset, SEEK_SET) != 0) {
        return 0;
    }
    return fread(buffer, 1U, length, file) == length;
}

static int riff_fourcc_printable(const unsigned char *data)
{
    size_t i;

    if (data == NULL) {
        return 0;
    }
    for (i = 0U; i < 4U; i++) {
        if (data[i] < 32U || data[i] > 126U) {
            return 0;
        }
    }
    return 1;
}

static uint64_t riff_avi_duration_ms(uint32_t microsec_per_frame, uint32_t total_frames)
{
    uint64_t total_us;

    if (microsec_per_frame == 0U || total_frames == 0U) {
        return 0U;
    }
    total_us = (uint64_t)microsec_per_frame * (uint64_t)total_frames;
    return total_us / 1000ULL;
}

static uint16_t read_u16_le_local(const unsigned char *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t read_u24_le_local(const unsigned char *data)
{
    return ((uint32_t)data[0]) |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16);
}

static void copy_fourcc(char out[5], const unsigned char *data)
{
    out[0] = (char)data[0];
    out[1] = (char)data[1];
    out[2] = (char)data[2];
    out[3] = (char)data[3];
    out[4] = '\0';
}

static const char *extension_from_subtype(const char *subtype)
{
    if (memcmp(subtype, "AVI ", 4) == 0) {
        return "avi";
    }

    if (memcmp(subtype, "WAVE", 4) == 0) {
        return "wav";
    }

    if (memcmp(subtype, "WEBP", 4) == 0) {
        return "webp";
    }

    return "riff";
}

static int is_known_riff_subtype(const char *subtype)
{
    return memcmp(subtype, "AVI ", 4) == 0 ||
           memcmp(subtype, "WAVE", 4) == 0 ||
           memcmp(subtype, "WEBP", 4) == 0;
}

static int buffer_contains_tag(
    const unsigned char *buffer,
    size_t start,
    size_t end,
    const char *tag
)
{
    size_t i;

    if (buffer == NULL || tag == NULL || end <= start) {
        return 0;
    }

    for (i = start; i + 4 <= end; i++) {
        if (memcmp(buffer + i, tag, 4) == 0) {
            return 1;
        }
    }

    return 0;
}

static int riff_subtype_header_looks_valid(
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t start_offset,
    const char *subtype
)
{
    size_t window_end;

    if (buffer == NULL || subtype == NULL || start_offset + 12 > bytes_in_buffer) {
        return 0;
    }

    if (memcmp(subtype, "WEBP", 4) == 0) {
        if (start_offset + 16 > bytes_in_buffer) {
            return 1;
        }

        return memcmp(buffer + start_offset + 12, "VP8 ", 4) == 0 ||
               memcmp(buffer + start_offset + 12, "VP8L", 4) == 0 ||
               memcmp(buffer + start_offset + 12, "VP8X", 4) == 0;
    }

    window_end = start_offset + 256;
    if (window_end > bytes_in_buffer) {
        window_end = bytes_in_buffer;
    }

    if (memcmp(subtype, "AVI ", 4) == 0) {
        return buffer_contains_tag(buffer, start_offset + 12, window_end, "LIST") &&
               buffer_contains_tag(buffer, start_offset + 12, window_end, "hdrl");
    }

    if (memcmp(subtype, "WAVE", 4) == 0) {
        return buffer_contains_tag(buffer, start_offset + 12, window_end, "fmt ");
    }

    return 0;
}

static int webp_dimensions_from_buffer(
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t start_offset,
    uint32_t *width_out,
    uint32_t *height_out
)
{
    const unsigned char *chunk;
    uint32_t chunk_size;
    uint32_t width = 0;
    uint32_t height = 0;

    if (width_out != NULL) {
        *width_out = 0;
    }
    if (height_out != NULL) {
        *height_out = 0;
    }
    if (buffer == NULL || start_offset + 20U > bytes_in_buffer) {
        return 0;
    }

    chunk = buffer + start_offset + 12U;
    chunk_size = read_u32_le(buffer + start_offset + 16U);

    if (memcmp(chunk, "VP8X", 4) == 0) {
        if (chunk_size < 10U || start_offset + 30U > bytes_in_buffer) {
            return 0;
        }

        width = read_u24_le_local(buffer + start_offset + 24U) + 1U;
        height = read_u24_le_local(buffer + start_offset + 27U) + 1U;
    } else if (memcmp(chunk, "VP8L", 4) == 0) {
        const unsigned char *payload;

        if (chunk_size < 5U || start_offset + 25U > bytes_in_buffer) {
            return 0;
        }

        payload = buffer + start_offset + 20U;
        if (payload[0] != 0x2FU) {
            return 0;
        }

        width = 1U + (uint32_t)payload[1] +
            (((uint32_t)payload[2] & 0x3FU) << 8);
        height = 1U + (((uint32_t)payload[2] & 0xC0U) >> 6) +
            ((uint32_t)payload[3] << 2) +
            (((uint32_t)payload[4] & 0x0FU) << 10);
    } else if (memcmp(chunk, "VP8 ", 4) == 0) {
        const unsigned char *payload;

        if (chunk_size < 10U || start_offset + 30U > bytes_in_buffer) {
            return 0;
        }

        payload = buffer + start_offset + 20U;
        if (payload[3] != 0x9DU || payload[4] != 0x01U || payload[5] != 0x2AU) {
            return 0;
        }

        width = (uint32_t)read_u16_le_local(payload + 6U) & 0x3FFFU;
        height = (uint32_t)read_u16_le_local(payload + 8U) & 0x3FFFU;
    } else {
        return 0;
    }

    if (width == 0 || height == 0) {
        return 0;
    }
    if (width_out != NULL) {
        *width_out = width;
    }
    if (height_out != NULL) {
        *height_out = height;
    }
    return 1;
}

static int should_skip_small_webp(
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t start_offset,
    size_t file_size,
    uint32_t *width_out,
    uint32_t *height_out
)
{
    uint32_t width;
    uint32_t height;

    if (!webp_dimensions_from_buffer(
            buffer,
            bytes_in_buffer,
            start_offset,
            &width,
            &height)) {
        return 0;
    }

    if (width_out != NULL) {
        *width_out = width;
    }
    if (height_out != NULL) {
        *height_out = height;
    }
    return image_filter_should_skip_image(width, height, file_size);
}

static int skip_riff_streaming(
    Reader *reader,
    size_t start_offset,
    size_t total_size,
    size_t *resume_offset
)
{
    size_t available_now;
    size_t remaining;

    if (reader == NULL || reader->buffer == NULL || resume_offset == NULL ||
        start_offset >= reader->bytes_in_buffer) {
        return 0;
    }

    available_now = reader->bytes_in_buffer - start_offset;
    if (total_size <= available_now) {
        *resume_offset = start_offset + total_size;
        return 1;
    }

    remaining = total_size - available_now;
    while (remaining > 0) {
        size_t new_bytes = reader_read_next(reader);

        if (new_bytes == 0) {
            return 0;
        }

        if (remaining <= new_bytes) {
            *resume_offset = reader->overlap_bytes + remaining;
            return 1;
        }

        remaining -= new_bytes;
    }

    return 0;
}

static int write_bytes(FILE *output_file, const unsigned char *data, size_t length)
{
    return fwrite(data, 1, length, output_file) == length;
}

static void riff_avi_note_strh(
    FILE *file,
    uint64_t payload_offset,
    uint64_t payload_size,
    RiffAviValidationStats *stats
)
{
    unsigned char data[56];

    if (stats == NULL) {
        return;
    }
    stats->strh_chunks++;
    if (payload_size < 4U ||
        !riff_file_read_at(file, payload_offset, data, payload_size < sizeof(data) ? (size_t)payload_size : sizeof(data))) {
        stats->parse_errors++;
        return;
    }
    if (memcmp(data, "vids", 4U) == 0) {
        stats->video_streams++;
    } else if (memcmp(data, "auds", 4U) == 0) {
        stats->audio_streams++;
    }
}

static void riff_avi_note_avih(
    FILE *file,
    uint64_t payload_offset,
    uint64_t payload_size,
    RiffAviValidationStats *stats
)
{
    unsigned char data[56];
    uint32_t microsec_per_frame;
    uint32_t total_frames;

    if (stats == NULL) {
        return;
    }
    stats->avih_chunks++;
    if (payload_size < 24U ||
        !riff_file_read_at(file, payload_offset, data, payload_size < sizeof(data) ? (size_t)payload_size : sizeof(data))) {
        stats->parse_errors++;
        return;
    }
    microsec_per_frame = read_u32_le(data);
    total_frames = read_u32_le(data + 16U);
    stats->total_frames = total_frames;
    stats->duration_ms = riff_avi_duration_ms(microsec_per_frame, total_frames);
}

static void riff_avi_walk_chunks(
    FILE *file,
    uint64_t start,
    uint64_t end,
    unsigned depth,
    RiffAviValidationStats *stats
)
{
    uint64_t cursor = start;

    if (file == NULL || stats == NULL || start > end || depth > RIFF_AVI_VALIDATE_MAX_DEPTH) {
        return;
    }

    while (cursor + 8U >= cursor && cursor + 8U <= end) {
        unsigned char header[12];
        uint32_t chunk_size;
        uint64_t payload_offset;
        uint64_t payload_end;
        uint64_t next_offset;

        if (stats->chunks_seen >= RIFF_AVI_VALIDATE_MAX_CHUNKS) {
            stats->chunk_limit_hit = 1;
            return;
        }
        if (!riff_file_read_at(file, cursor, header, 8U) ||
            !riff_fourcc_printable(header)) {
            stats->parse_errors++;
            return;
        }

        chunk_size = read_u32_le(header + 4U);
        payload_offset = cursor + 8U;
        payload_end = payload_offset + (uint64_t)chunk_size;
        next_offset = payload_end + ((uint64_t)chunk_size & 1ULL);
        if (payload_end < payload_offset || next_offset < payload_end || payload_end > end) {
            stats->parse_errors++;
            return;
        }

        stats->chunks_seen++;
        if (memcmp(header, "LIST", 4U) == 0) {
            stats->list_chunks++;
            if (chunk_size >= 4U &&
                riff_file_read_at(file, payload_offset, header + 8U, 4U)) {
                if (memcmp(header + 8U, "hdrl", 4U) == 0) {
                    stats->hdrl_lists++;
                } else if (memcmp(header + 8U, "movi", 4U) == 0) {
                    stats->movi_lists++;
                } else if (memcmp(header + 8U, "strl", 4U) == 0) {
                    stats->strl_lists++;
                }
                if (depth < RIFF_AVI_VALIDATE_MAX_DEPTH &&
                    memcmp(header + 8U, "movi", 4U) != 0) {
                    riff_avi_walk_chunks(
                        file,
                        payload_offset + 4U,
                        payload_end,
                        depth + 1U,
                        stats
                    );
                }
            } else {
                stats->parse_errors++;
            }
        } else if (memcmp(header, "avih", 4U) == 0) {
            riff_avi_note_avih(file, payload_offset, chunk_size, stats);
        } else if (memcmp(header, "strh", 4U) == 0) {
            riff_avi_note_strh(file, payload_offset, chunk_size, stats);
        } else if (memcmp(header, "idx1", 4U) == 0) {
            stats->idx1_chunks++;
            stats->idx1_entries += (uint64_t)chunk_size / 16ULL;
        }

        if (next_offset <= cursor) {
            stats->parse_errors++;
            return;
        }
        cursor = next_offset;
    }
}

static int riff_avi_collect_stats(const char *path, RiffAviValidationStats *stats)
{
    struct stat st;
    FILE *file;
    unsigned char header[12];

    if (path == NULL || stats == NULL) {
        return 0;
    }
    memset(stats, 0, sizeof(*stats));
    if (stat(path, &st) != 0 || st.st_size < 12) {
        return 0;
    }
    stats->file_size = (uint64_t)st.st_size;
    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    if (!riff_file_read_at(file, 0U, header, sizeof(header)) ||
        memcmp(header, "RIFF", 4U) != 0 ||
        memcmp(header + 8U, "AVI ", 4U) != 0) {
        fclose(file);
        return 0;
    }
    riff_avi_walk_chunks(file, 12U, stats->file_size, 0U, stats);
    fclose(file);
    return stats->chunks_seen > 0U;
}

static const char *riff_avi_decide(
    const RiffAviValidationStats *stats,
    char *reason,
    size_t reason_size,
    char *table_status,
    size_t table_status_size,
    int *hard_reject
)
{
    unsigned missing = 0U;

    if (reason != NULL && reason_size > 0U) {
        reason[0] = '\0';
    }
    if (table_status != NULL && table_status_size > 0U) {
        table_status[0] = '\0';
    }
    if (hard_reject != NULL) {
        *hard_reject = 0;
    }
    if (stats == NULL) {
        if (reason != NULL && reason_size > 0U) {
            snprintf(reason, reason_size, "AVI finalize parser had no stats");
        }
        if (table_status != NULL && table_status_size > 0U) {
            snprintf(table_status, table_status_size, "parse_failed");
        }
        return "accepted_suspicious";
    }

    if (stats->hdrl_lists == 0U) {
        missing++;
    }
    if (stats->avih_chunks == 0U) {
        missing++;
    }
    if (stats->movi_lists == 0U) {
        missing++;
    }
    if (stats->strh_chunks == 0U || stats->video_streams == 0U) {
        missing++;
    }

    if (missing >= 2U) {
        if (reason != NULL && reason_size > 0U) {
            snprintf(reason, reason_size, "AVI structure is too incomplete");
        }
        if (table_status != NULL && table_status_size > 0U) {
            snprintf(table_status, table_status_size, "avi_structure_missing");
        }
        if (hard_reject != NULL) {
            *hard_reject = 1;
        }
        return "rejected";
    }

    if (missing > 0U || stats->parse_errors > 0U || stats->idx1_entries == 0U) {
        if (reason != NULL && reason_size > 0U) {
            snprintf(
                reason,
                reason_size,
                "AVI kept with caution: missing=%u parse_errors=%u idx1=%llu",
                missing,
                stats->parse_errors,
                (unsigned long long)stats->idx1_entries
            );
        }
        if (table_status != NULL && table_status_size > 0U) {
            snprintf(table_status, table_status_size, "avi_index_partial");
        }
        return "accepted_suspicious";
    }

    if (reason != NULL && reason_size > 0U) {
        snprintf(reason, reason_size, "AVI header, stream, movi and idx1 confirmed");
    }
    if (table_status != NULL && table_status_size > 0U) {
        snprintf(table_status, table_status_size, "avi_index_present");
    }
    return "accepted";
}

static void riff_avi_report_validation(
    const RiffAviValidationContext *ctx,
    const RiffAviValidationStats *stats,
    const char *status,
    const char *reason,
    const char *table_status
)
{
    CarvVideoValidationReport report;

    if (ctx == NULL) {
        return;
    }
    memset(&report, 0, sizeof(report));
    report.container = "riff_avi";
    report.extension = "avi";
    report.status = status;
    report.reason = reason;
    report.offset = (uint64_t)ctx->absolute_offset;
    report.bytes = ctx->total_size;
    report.table_status = table_status;
    if (stats != NULL) {
        report.payload_bytes = ctx->total_size;
        report.units = stats->chunks_seen;
        report.video_units = stats->video_streams;
        report.audio_units = stats->audio_streams;
        report.metadata_units = stats->hdrl_lists + stats->avih_chunks + stats->strh_chunks;
        report.duration_ms = stats->duration_ms;
        report.tracks = stats->strh_chunks;
        report.sample_entries = stats->total_frames;
        report.chunk_offsets = stats->idx1_entries;
    }
    video_validation_report_append(ctx->config, &report);
}

static int riff_avi_output_validator(const char *path, void *opaque)
{
    RiffAviValidationContext *ctx = (RiffAviValidationContext *)opaque;
    RiffAviValidationStats stats;
    char reason[160];
    char table_status[80];
    const char *status;
    int hard_reject = 0;

    if (ctx == NULL) {
        return 1;
    }
    if (!riff_avi_collect_stats(path, &stats)) {
        snprintf(reason, sizeof(reason), "AVI finalize parser could not parse completed candidate");
        snprintf(table_status, sizeof(table_status), "parse_failed");
        riff_avi_report_validation(ctx, NULL, "accepted_suspicious", reason, table_status);
        return 1;
    }

    status = riff_avi_decide(
        &stats,
        reason,
        sizeof(reason),
        table_status,
        sizeof(table_status),
        &hard_reject
    );
    riff_avi_report_validation(ctx, &stats, status, reason, table_status);
    if (hard_reject) {
        log_info(
            "AVI candidate at byte %zu rejected after finalize validation: %s (table=%s frames=%llu idx1=%llu)",
            ctx->absolute_offset,
            reason,
            table_status,
            (unsigned long long)stats.total_frames,
            (unsigned long long)stats.idx1_entries
        );
        return 0;
    }
    if (strcmp(status, "accepted_suspicious") == 0) {
        log_info(
            "AVI candidate at byte %zu kept with finalize caution: %s (table=%s frames=%llu idx1=%llu)",
            ctx->absolute_offset,
            reason,
            table_status,
            (unsigned long long)stats.total_frames,
            (unsigned long long)stats.idx1_entries
        );
    }
    return 1;
}

int carver_riff_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    char subtype[5];
    CarverOutput output = {0};
    const char *extension;
    const char *default_directory;
    uint32_t riff_size;
    size_t total_size;
    size_t available_now;
    size_t remaining;
    size_t new_bytes;
    uint32_t webp_width = 0;
    uint32_t webp_height = 0;
    int is_avi = 0;

    if (reader == NULL || reader->buffer == NULL || resume_offset == NULL) {
        return 0;
    }

    carver_riff_reset_last_audit();
    *resume_offset = start_offset;

    if (start_offset + 12 > reader->bytes_in_buffer) {
        carver_audit_set_inline(&g_riff_last_audit, "rejected", "short_riff_header", 0U);
        return 0;
    }

    if (memcmp(reader->buffer + start_offset, "RIFF", 4) != 0) {
        carver_audit_set_inline(&g_riff_last_audit, "rejected", "missing_riff_signature", 0U);
        return 0;
    }

    riff_size = read_u32_le(reader->buffer + start_offset + 4);
    total_size = (size_t)riff_size + 8;

    copy_fourcc(subtype, reader->buffer + start_offset + 8);
    extension = extension_from_subtype(subtype);
    default_directory = APP_DEFAULT_UNIDENT_DIR;
    is_avi = memcmp(subtype, "AVI ", 4) == 0;

/*     log_info(
        "RIFF candidate at offset %zu: subtype=%s riff_size=%u total_size=%zu",
        absolute_offset,
        subtype,
        riff_size,
        total_size
    ); */

    /*
     * Basic sanity checks.
     */
    if (total_size < 12) {
        carver_audit_set_inline(&g_riff_last_audit, "rejected", "implausible_riff_size", total_size);
        return 0;
    }

    if (total_size > RIFF_MAX_REASONABLE_SIZE) {
        carver_audit_set_inline(&g_riff_last_audit, "rejected", "riff_size_over_cap", total_size);
        return 0;
    }

    /*
     * Avoid trying to recover obviously bogus RIFF-like hits.
     */
    if (!is_known_riff_subtype(subtype)) {
        carver_audit_set_inline(&g_riff_last_audit, "rejected", "unknown_riff_subtype", total_size);
        return 0;
    }

    if (!riff_subtype_header_looks_valid(
            reader->buffer,
            reader->bytes_in_buffer,
            start_offset,
            subtype)) {
        carver_audit_set_inline(&g_riff_last_audit, "rejected", "invalid_riff_subtype_header", total_size);
        return 0;
    }

    if (memcmp(subtype, "WEBP", 4) == 0 &&
        should_skip_small_webp(
            reader->buffer,
            reader->bytes_in_buffer,
            start_offset,
            total_size,
            &webp_width,
            &webp_height)) {
        filtered_image_log_append_current(
            "raw-carver",
            "webp",
            "small_image_filtered",
            (uint64_t)absolute_offset,
            0U,
            (uint64_t)total_size,
            (uint64_t)webp_width,
            (uint64_t)webp_height,
            NULL
        );
        carver_audit_set_inline(&g_riff_last_audit, "skipped", "small_webp_filtered", total_size);
        return skip_riff_streaming(reader, start_offset, total_size, resume_offset);
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            default_directory,
            "recov",
            extension)) {
        log_error("Failed to prepare RIFF output");
        carver_audit_set_inline(&g_riff_last_audit, "rejected", "output_open_failed", total_size);
        return 0;
    }

    available_now = reader->bytes_in_buffer - start_offset;

    /*
     * Case 1: the entire file already fits in the current buffer.
     */
    if (total_size <= available_now) {
        if (!write_bytes(output.file, reader->buffer + start_offset, total_size)) {
            carver_output_abort(&output);
            carver_audit_set_inline(&g_riff_last_audit, "rejected", "write_failed", total_size);
            return 0;
        }

        if (is_avi) {
            RiffAviValidationContext validation_ctx;

            memset(&validation_ctx, 0, sizeof(validation_ctx));
            validation_ctx.config = config;
            validation_ctx.absolute_offset = absolute_offset;
            validation_ctx.total_size = total_size;
            if (!carver_output_finish_validated(
                    &output,
                    riff_avi_output_validator,
                    &validation_ctx)) {
                carver_audit_set_inline(&g_riff_last_audit, "rejected", "finalize_validation_rejected_or_write_failed", total_size);
                return 0;
            }
        } else if (!carver_output_finish(&output)) {
            carver_audit_set_inline(&g_riff_last_audit, "rejected", "finish_failed", total_size);
            return 0;
        }

        *resume_offset = start_offset + total_size;
        carver_audit_set_inline(&g_riff_last_audit, "recovered", "riff_declared_size_confirmed", total_size);
        carver_audit_set_trailing_reason_inline(&g_riff_last_audit, "riff_after_declared_size");
        return 1;
    }

    /*
     * Case 2: write what remains in the current buffer, then keep streaming
     * additional chunks until the RIFF file is complete.
     */
    {
        if (!write_bytes(output.file, reader->buffer + start_offset, available_now)) {
            carver_output_abort(&output);
            carver_audit_set_inline(&g_riff_last_audit, "rejected", "write_failed", total_size);
            return 0;
        }
    }

    remaining = total_size - available_now;

    while (remaining > 0) {
        new_bytes = reader_read_next(reader);
        if (new_bytes == 0) {
            carver_output_abort(&output);
            log_error(
                "RIFF recovery hit EOF before completion at offset %zu",
                absolute_offset
            );
            carver_audit_set_inline(&g_riff_last_audit, "rejected", "source_eof_before_riff_end", total_size);
            return 0;
        }

        /*
         * Only write the newly read bytes.
         * The overlap region at the start of the buffer is duplicated data.
         */
        if (remaining <= new_bytes) {
            if (!write_bytes(
                    output.file,
                    reader->buffer + reader->overlap_bytes,
                    remaining)) {
                carver_output_abort(&output);
                carver_audit_set_inline(&g_riff_last_audit, "rejected", "write_failed", total_size);
                return 0;
            }

            if (is_avi) {
                RiffAviValidationContext validation_ctx;

                memset(&validation_ctx, 0, sizeof(validation_ctx));
                validation_ctx.config = config;
                validation_ctx.absolute_offset = absolute_offset;
                validation_ctx.total_size = total_size;
                if (!carver_output_finish_validated(
                        &output,
                        riff_avi_output_validator,
                        &validation_ctx)) {
                    carver_audit_set_inline(&g_riff_last_audit, "rejected", "finalize_validation_rejected_or_write_failed", total_size);
                    return 0;
                }
            } else if (!carver_output_finish(&output)) {
                carver_audit_set_inline(&g_riff_last_audit, "rejected", "finish_failed", total_size);
                return 0;
            }

            *resume_offset = reader->overlap_bytes + remaining;
            carver_audit_set_inline(&g_riff_last_audit, "recovered", "riff_declared_size_confirmed", total_size);
            carver_audit_set_trailing_reason_inline(&g_riff_last_audit, "riff_after_declared_size");
            return 1;
        }

        if (!write_bytes(
                output.file,
                reader->buffer + reader->overlap_bytes,
                new_bytes)) {
            carver_output_abort(&output);
            carver_audit_set_inline(&g_riff_last_audit, "rejected", "write_failed", total_size);
            return 0;
        }

        remaining -= new_bytes;
    }

    if (is_avi) {
        RiffAviValidationContext validation_ctx;

        memset(&validation_ctx, 0, sizeof(validation_ctx));
        validation_ctx.config = config;
        validation_ctx.absolute_offset = absolute_offset;
        validation_ctx.total_size = total_size;
        return carver_output_finish_validated(
            &output,
            riff_avi_output_validator,
            &validation_ctx
        )
            ? (carver_audit_set_inline(&g_riff_last_audit, "recovered", "riff_declared_size_confirmed", total_size),
               carver_audit_set_trailing_reason_inline(&g_riff_last_audit, "riff_after_declared_size"),
               1)
            : (carver_audit_set_inline(&g_riff_last_audit, "rejected", "finalize_validation_rejected_or_write_failed", total_size),
               0);
    }

    if (!carver_output_finish(&output)) {
        carver_audit_set_inline(&g_riff_last_audit, "rejected", "finish_failed", total_size);
        return 0;
    }
    carver_audit_set_inline(&g_riff_last_audit, "recovered", "riff_declared_size_confirmed", total_size);
    carver_audit_set_trailing_reason_inline(&g_riff_last_audit, "riff_after_declared_size");
    return 1;
}
