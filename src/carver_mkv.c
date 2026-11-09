#include "carver_mkv.h"

#include "carver_output.h"
#include "config.h"
#include "log.h"
#include "video_validation.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MKV_EBML_HEADER_ID 0x1A45DFA3U
#define MKV_SEGMENT_ID 0x18538067U
#define MKV_VOID_ID 0xECU
#define MKV_CRC32_ID 0xBFU
#define MKV_DOCTYPE_ID 0x4282U
#define MKV_INFO_ID 0x1549A966U
#define MKV_TRACKS_ID 0x1654AE6BU
#define MKV_TRACK_ENTRY_ID 0xAEU
#define MKV_TRACK_TYPE_ID 0x83U
#define MKV_DURATION_ID 0x4489U
#define MKV_TIMECODE_SCALE_ID 0x2AD7B1U
#define MKV_CLUSTER_ID 0x1F43B675U
#define MKV_CUES_ID 0x1C53BB6BU
#define MKV_SIMPLE_BLOCK_ID 0xA3U
#define MKV_BLOCK_GROUP_ID 0xA0U
#define MKV_MAX_EBML_HEADER_SIZE 4096U
#define MKV_MAX_REASONABLE_FILE_SIZE (64ULL * 1024ULL * 1024ULL * 1024ULL)
#define MKV_VALIDATE_MAX_ELEMENTS 32768U
#define MKV_VALIDATE_MAX_DEPTH 8U

typedef struct {
    uint64_t file_size;
    uint64_t segment_bytes;
    uint64_t timecode_scale_ns;
    uint64_t duration_ms;
    unsigned elements_seen;
    unsigned segment_children;
    unsigned info_elements;
    unsigned track_entries;
    unsigned video_tracks;
    unsigned audio_tracks;
    unsigned clusters;
    unsigned cues;
    unsigned simple_blocks;
    unsigned block_groups;
    unsigned parse_errors;
    int element_limit_hit;
    int has_duration;
} MkvValidationStats;

typedef struct {
    const AppConfig *config;
    size_t absolute_offset;
    uint64_t total_size;
} MkvValidationContext;

static CarverAuditReport g_mkv_last_audit;

void carver_mkv_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_mkv_last_audit);
}

void carver_mkv_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_mkv_last_audit;
}

static uint64_t mkv_budget_adjusted_file_cap(void)
{
    switch (log_get_validator_budget_state()) {
        case LOG_TROUBLE_BUDGET_RED:
            return 16ULL * 1024ULL * 1024ULL * 1024ULL;
        case LOG_TROUBLE_BUDGET_YELLOW:
            return 32ULL * 1024ULL * 1024ULL * 1024ULL;
        case LOG_TROUBLE_BUDGET_GREEN:
        case LOG_TROUBLE_BUDGET_UNKNOWN:
        default:
            return MKV_MAX_REASONABLE_FILE_SIZE;
    }
}

typedef struct {
    uint64_t value;
    size_t length;
    int unknown_size;
} EbmlVint;

static int read_bytes_at(
    Reader *reader,
    size_t offset,
    unsigned char *dst,
    size_t needed
)
{
    size_t copied = 0;

    if (reader == NULL || reader->buffer == NULL || dst == NULL) {
        return 0;
    }

    while (copied < needed) {
        size_t available = offset < reader->bytes_in_buffer
            ? reader->bytes_in_buffer - offset
            : 0U;

        if (available == 0U) {
            if (reader_read_next(reader) == 0) {
                return 0;
            }
            offset = reader->overlap_bytes;
            continue;
        }

        if (available > needed - copied) {
            available = needed - copied;
        }

        memcpy(dst + copied, reader->buffer + offset, available);
        copied += available;
        offset += available;
    }

    return 1;
}

static int ebml_vint_length(uint8_t first_byte)
{
    int length;

    for (length = 1; length <= 8; length++) {
        if ((first_byte & (0x80U >> (length - 1))) != 0U) {
            return length;
        }
    }

    return 0;
}

static int ebml_read_id(
    const uint8_t *data,
    size_t available,
    EbmlVint *out
)
{
    int length;
    size_t i;
    uint64_t value = 0;

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (data == NULL || out == NULL || available == 0U) {
        return 0;
    }

    length = ebml_vint_length(data[0]);
    if (length == 0 || (size_t)length > available) {
        return 0;
    }

    for (i = 0; i < (size_t)length; i++) {
        value = (value << 8) | (uint64_t)data[i];
    }

    out->value = value;
    out->length = (size_t)length;
    out->unknown_size = 0;
    return 1;
}

static int ebml_read_size(
    const uint8_t *data,
    size_t available,
    EbmlVint *out
)
{
    int length;
    size_t i;
    uint64_t value;
    uint8_t mask;
    int unknown = 1;

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (data == NULL || out == NULL || available == 0U) {
        return 0;
    }

    length = ebml_vint_length(data[0]);
    if (length == 0 || (size_t)length > available) {
        return 0;
    }

    mask = (uint8_t)(0xFFU >> length);
    value = (uint64_t)(data[0] & mask);
    if ((data[0] & mask) != mask) {
        unknown = 0;
    }

    for (i = 1; i < (size_t)length; i++) {
        value = (value << 8) | (uint64_t)data[i];
        if (data[i] != 0xFFU) {
            unknown = 0;
        }
    }

    out->value = value;
    out->length = (size_t)length;
    out->unknown_size = unknown;
    return 1;
}

static int mkv_file_read_at(
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

static int mkv_file_read_vints(
    FILE *file,
    uint64_t offset,
    uint64_t end,
    EbmlVint *id,
    EbmlVint *size_field
)
{
    unsigned char header[16];
    size_t header_size;

    if (offset + 2U < offset || offset + 2U > end) {
        return 0;
    }
    header_size = (size_t)(end - offset);
    if (header_size > sizeof(header)) {
        header_size = sizeof(header);
    }
    if (header_size < 2U ||
        !mkv_file_read_at(file, offset, header, header_size)) {
        return 0;
    }
    if (!ebml_read_id(header, header_size, id)) {
        return 0;
    }
    if (offset + id->length + 1U < offset ||
        offset + id->length + 1U > end) {
        return 0;
    }
    if (id->length >= header_size ||
        !ebml_read_size(header + id->length, header_size - id->length, size_field)) {
        return 0;
    }
    return 1;
}

static uint64_t mkv_read_uint_be_local(const unsigned char *data, size_t length)
{
    uint64_t value = 0U;
    size_t i;

    if (data == NULL || length > 8U) {
        return 0U;
    }
    for (i = 0U; i < length; i++) {
        value = (value << 8) | (uint64_t)data[i];
    }
    return value;
}

static double mkv_read_float_be_local(const unsigned char *data, size_t length)
{
    if (data == NULL) {
        return 0.0;
    }
    if (length == 4U) {
        uint32_t bits =
            ((uint32_t)data[0] << 24) |
            ((uint32_t)data[1] << 16) |
            ((uint32_t)data[2] << 8) |
            (uint32_t)data[3];
        float value;
        memcpy(&value, &bits, sizeof(value));
        return (double)value;
    }
    if (length == 8U) {
        uint64_t bits =
            ((uint64_t)data[0] << 56) |
            ((uint64_t)data[1] << 48) |
            ((uint64_t)data[2] << 40) |
            ((uint64_t)data[3] << 32) |
            ((uint64_t)data[4] << 24) |
            ((uint64_t)data[5] << 16) |
            ((uint64_t)data[6] << 8) |
            (uint64_t)data[7];
        double value;
        memcpy(&value, &bits, sizeof(value));
        return value;
    }
    return 0.0;
}

static int mkv_element_is_master(uint64_t id)
{
    return id == MKV_SEGMENT_ID ||
           id == MKV_INFO_ID ||
           id == MKV_TRACKS_ID ||
           id == MKV_TRACK_ENTRY_ID ||
           id == MKV_CLUSTER_ID ||
           id == MKV_CUES_ID ||
           id == MKV_BLOCK_GROUP_ID;
}

static void mkv_validate_parse_leaf(
    FILE *file,
    uint64_t id,
    uint64_t payload_offset,
    uint64_t payload_size,
    MkvValidationStats *stats
)
{
    unsigned char data[16];

    if (file == NULL || stats == NULL) {
        return;
    }
    if (id == MKV_TIMECODE_SCALE_ID) {
        if (payload_size == 0U || payload_size > 8U ||
            !mkv_file_read_at(file, payload_offset, data, (size_t)payload_size)) {
            stats->parse_errors++;
            return;
        }
        stats->timecode_scale_ns = mkv_read_uint_be_local(data, (size_t)payload_size);
    } else if (id == MKV_DURATION_ID) {
        double duration_units;
        double duration_ms;

        if ((payload_size != 4U && payload_size != 8U) ||
            !mkv_file_read_at(file, payload_offset, data, (size_t)payload_size)) {
            stats->parse_errors++;
            return;
        }
        duration_units = mkv_read_float_be_local(data, (size_t)payload_size);
        if (duration_units > 0.0) {
            duration_ms =
                duration_units *
                (double)(stats->timecode_scale_ns > 0U
                    ? stats->timecode_scale_ns
                    : 1000000ULL) /
                1000000.0;
            if (duration_ms > 0.0 && duration_ms < 315576000000.0) {
                stats->duration_ms = (uint64_t)duration_ms;
                stats->has_duration = 1;
            }
        }
    } else if (id == MKV_TRACK_TYPE_ID) {
        uint64_t track_type;

        if (payload_size == 0U || payload_size > 8U ||
            !mkv_file_read_at(file, payload_offset, data, (size_t)payload_size)) {
            stats->parse_errors++;
            return;
        }
        track_type = mkv_read_uint_be_local(data, (size_t)payload_size);
        if (track_type == 1U) {
            stats->video_tracks++;
        } else if (track_type == 2U) {
            stats->audio_tracks++;
        }
    }
}

static void mkv_validate_walk(
    FILE *file,
    uint64_t start,
    uint64_t end,
    unsigned depth,
    MkvValidationStats *stats
)
{
    uint64_t cursor = start;

    if (file == NULL || stats == NULL || start > end || depth > MKV_VALIDATE_MAX_DEPTH) {
        return;
    }
    while (cursor + 2U >= cursor && cursor + 2U <= end) {
        EbmlVint id;
        EbmlVint size_field;
        uint64_t payload_offset;
        uint64_t payload_end;

        if (stats->elements_seen >= MKV_VALIDATE_MAX_ELEMENTS) {
            stats->element_limit_hit = 1;
            return;
        }
        if (!mkv_file_read_vints(file, cursor, end, &id, &size_field)) {
            stats->parse_errors++;
            return;
        }
        payload_offset = cursor + id.length + size_field.length;
        if (payload_offset < cursor) {
            stats->parse_errors++;
            return;
        }
        if (size_field.unknown_size) {
            payload_end = end;
        } else {
            payload_end = payload_offset + size_field.value;
            if (payload_end < payload_offset || payload_end > end) {
                stats->parse_errors++;
                return;
            }
        }

        stats->elements_seen++;
        if (depth == 1U) {
            stats->segment_children++;
        }
        if (id.value == MKV_INFO_ID) {
            stats->info_elements++;
        } else if (id.value == MKV_TRACK_ENTRY_ID) {
            stats->track_entries++;
        } else if (id.value == MKV_CLUSTER_ID) {
            stats->clusters++;
        } else if (id.value == MKV_CUES_ID) {
            stats->cues++;
        } else if (id.value == MKV_SIMPLE_BLOCK_ID) {
            stats->simple_blocks++;
        } else if (id.value == MKV_BLOCK_GROUP_ID) {
            stats->block_groups++;
        }

        if (depth < MKV_VALIDATE_MAX_DEPTH &&
            mkv_element_is_master(id.value) &&
            id.value != MKV_CLUSTER_ID &&
            id.value != MKV_CUES_ID &&
            id.value != MKV_VOID_ID &&
            id.value != MKV_CRC32_ID) {
            mkv_validate_walk(file, payload_offset, payload_end, depth + 1U, stats);
        } else {
            mkv_validate_parse_leaf(file, id.value, payload_offset, size_field.value, stats);
        }

        if (size_field.unknown_size || payload_end <= cursor) {
            return;
        }
        cursor = payload_end;
    }
}

static int mkv_validate_collect_stats(const char *path, MkvValidationStats *stats)
{
    struct stat st;
    FILE *file;
    unsigned char header[16];
    EbmlVint ebml_size;
    EbmlVint id;
    EbmlVint size_field;
    uint64_t cursor;
    uint64_t segment_payload_offset;
    uint64_t segment_payload_end;

    if (path == NULL || stats == NULL) {
        return 0;
    }
    memset(stats, 0, sizeof(*stats));
    stats->timecode_scale_ns = 1000000ULL;
    if (stat(path, &st) != 0 || st.st_size < 32) {
        return 0;
    }
    stats->file_size = (uint64_t)st.st_size;
    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    if (!mkv_file_read_at(file, 0U, header, sizeof(header)) ||
        ((uint32_t)header[0] << 24 |
         (uint32_t)header[1] << 16 |
         (uint32_t)header[2] << 8 |
         (uint32_t)header[3]) != MKV_EBML_HEADER_ID ||
        !ebml_read_size(header + 4U, sizeof(header) - 4U, &ebml_size) ||
        ebml_size.unknown_size) {
        fclose(file);
        return 0;
    }
    cursor = 4U + ebml_size.length + ebml_size.value;
    while (cursor + 2U <= stats->file_size) {
        if (!mkv_file_read_vints(file, cursor, stats->file_size, &id, &size_field)) {
            fclose(file);
            return 0;
        }
        segment_payload_offset = cursor + id.length + size_field.length;
        if (id.value == MKV_SEGMENT_ID) {
            segment_payload_end = size_field.unknown_size
                ? stats->file_size
                : segment_payload_offset + size_field.value;
            if (segment_payload_end > stats->file_size ||
                segment_payload_end < segment_payload_offset) {
                fclose(file);
                return 0;
            }
            stats->segment_bytes = segment_payload_end - segment_payload_offset;
            mkv_validate_walk(
                file,
                segment_payload_offset,
                segment_payload_end,
                1U,
                stats
            );
            fclose(file);
            return stats->segment_children > 0U;
        }
        if (size_field.unknown_size) {
            fclose(file);
            return 0;
        }
        cursor = segment_payload_offset + size_field.value;
    }
    fclose(file);
    return 0;
}

static const char *mkv_validate_decide(
    const MkvValidationStats *stats,
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
            snprintf(reason, reason_size, "MKV finalize parser had no stats");
        }
        if (table_status != NULL && table_status_size > 0U) {
            snprintf(table_status, table_status_size, "parse_failed");
        }
        return "accepted_suspicious";
    }

    if (stats->info_elements == 0U) {
        missing++;
    }
    if (stats->track_entries == 0U || stats->video_tracks == 0U) {
        missing++;
    }
    if (stats->clusters == 0U) {
        missing++;
    }

    if (missing >= 2U) {
        if (reason != NULL && reason_size > 0U) {
            snprintf(reason, reason_size, "MKV/WebM structure is too incomplete");
        }
        if (table_status != NULL && table_status_size > 0U) {
            snprintf(table_status, table_status_size, "mkv_structure_missing");
        }
        if (hard_reject != NULL) {
            *hard_reject = 1;
        }
        return "rejected";
    }
    if (missing > 0U || !stats->has_duration || stats->parse_errors > 0U) {
        if (reason != NULL && reason_size > 0U) {
            snprintf(
                reason,
                reason_size,
                "MKV/WebM kept with caution: missing=%u duration=%d parse_errors=%u",
                missing,
                stats->has_duration,
                stats->parse_errors
            );
        }
        if (table_status != NULL && table_status_size > 0U) {
            snprintf(table_status, table_status_size, "mkv_metadata_partial");
        }
        return "accepted_suspicious";
    }

    if (reason != NULL && reason_size > 0U) {
        snprintf(reason, reason_size, "MKV/WebM tracks, duration and clusters confirmed");
    }
    if (table_status != NULL && table_status_size > 0U) {
        snprintf(table_status, table_status_size, "mkv_metadata_complete");
    }
    return "accepted";
}

static void mkv_report_validation(
    const MkvValidationContext *ctx,
    const MkvValidationStats *stats,
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
    report.container = "matroska";
    report.extension = "mkv";
    report.status = status;
    report.reason = reason;
    report.offset = (uint64_t)ctx->absolute_offset;
    report.bytes = ctx->total_size;
    report.table_status = table_status;
    if (stats != NULL) {
        report.payload_bytes = stats->segment_bytes;
        report.units = stats->elements_seen;
        report.video_units = stats->video_tracks;
        report.audio_units = stats->audio_tracks;
        report.metadata_units =
            stats->info_elements +
            stats->track_entries +
            stats->cues;
        report.duration_ms = stats->duration_ms;
        report.tracks = stats->track_entries;
        report.sample_entries = stats->simple_blocks + stats->block_groups;
        report.chunk_offsets = stats->cues;
    }
    video_validation_report_append(ctx->config, &report);
}

static int mkv_output_validator(const char *path, void *opaque)
{
    MkvValidationContext *ctx = (MkvValidationContext *)opaque;
    MkvValidationStats stats;
    char reason[160];
    char table_status[80];
    const char *status;
    int hard_reject = 0;

    if (ctx == NULL) {
        return 1;
    }
    if (!mkv_validate_collect_stats(path, &stats)) {
        snprintf(reason, sizeof(reason), "MKV/WebM finalize parser could not parse completed candidate");
        snprintf(table_status, sizeof(table_status), "parse_failed");
        mkv_report_validation(ctx, NULL, "accepted_suspicious", reason, table_status);
        return 1;
    }
    status = mkv_validate_decide(
        &stats,
        reason,
        sizeof(reason),
        table_status,
        sizeof(table_status),
        &hard_reject
    );
    mkv_report_validation(ctx, &stats, status, reason, table_status);
    if (hard_reject) {
        log_info(
            "MKV/WebM candidate at byte %zu rejected after finalize validation: %s (table=%s tracks=%u clusters=%u)",
            ctx->absolute_offset,
            reason,
            table_status,
            stats.track_entries,
            stats.clusters
        );
        return 0;
    }
    if (strcmp(status, "accepted_suspicious") == 0) {
        log_info(
            "MKV/WebM candidate at byte %zu kept with finalize caution: %s (table=%s tracks=%u clusters=%u)",
            ctx->absolute_offset,
            reason,
            table_status,
            stats.track_entries,
            stats.clusters
        );
    }
    return 1;
}

static int mkv_stream_exact_size(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    uint64_t total_size,
    size_t *resume_offset
)
{
    CarverOutput output = {0};
    size_t last_resume = start_offset;
    uint64_t remaining = total_size;
    size_t current_offset = start_offset;

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "mkv")) {
        return 0;
    }

    while (remaining > 0U) {
        size_t available;

        if (current_offset >= reader->bytes_in_buffer) {
            if (reader_read_next(reader) == 0) {
                carver_output_abort(&output);
                return 0;
            }
            current_offset = reader->overlap_bytes;
        }

        available = reader->bytes_in_buffer - current_offset;
        if (available == 0U) {
            carver_output_abort(&output);
            return 0;
        }

        if ((uint64_t)available > remaining) {
            available = (size_t)remaining;
        }

        if (fwrite(reader->buffer + current_offset, 1, available, output.file) != available) {
            carver_output_abort(&output);
            return 0;
        }

        current_offset += available;
        last_resume = current_offset;
        remaining -= (uint64_t)available;
    }

    {
        MkvValidationContext validation_ctx;

        memset(&validation_ctx, 0, sizeof(validation_ctx));
        validation_ctx.config = config;
        validation_ctx.absolute_offset = absolute_offset;
        validation_ctx.total_size = total_size;
        if (!carver_output_finish_validated(
                &output,
                mkv_output_validator,
                &validation_ctx)) {
            return 0;
        }
    }

    *resume_offset = last_resume;
    return 1;
}

static int mkv_doctype_is_known(const uint8_t *data, size_t length)
{
    return (length == 8U && memcmp(data, "matroska", 8U) == 0) ||
           (length == 4U && memcmp(data, "webm", 4U) == 0);
}

static int mkv_header_has_known_doctype(const uint8_t *header, size_t header_size)
{
    size_t cursor;
    size_t end;

    if (header == NULL || header_size < 5U) {
        return 0;
    }

    {
        EbmlVint size_field;

        if (!ebml_read_size(header + 4U, header_size - 4U, &size_field) ||
            size_field.unknown_size) {
            return 0;
        }

        cursor = 4U + size_field.length;
        end = cursor + (size_t)size_field.value;
        if (end > header_size) {
            return 0;
        }
    }

    while (cursor < end) {
        EbmlVint id;
        EbmlVint size_field;
        size_t value_offset;

        if (!ebml_read_id(header + cursor, end - cursor, &id)) {
            return 0;
        }
        cursor += id.length;
        if (!ebml_read_size(header + cursor, end - cursor, &size_field) ||
            size_field.unknown_size) {
            return 0;
        }
        cursor += size_field.length;
        value_offset = cursor;

        if (size_field.value > (uint64_t)(end - cursor)) {
            return 0;
        }

        if (id.value == MKV_DOCTYPE_ID &&
            mkv_doctype_is_known(header + value_offset, (size_t)size_field.value)) {
            return 1;
        }

        cursor += (size_t)size_field.value;
    }

    return 0;
}

static int mkv_first_segment_child_known(
    Reader *reader,
    size_t offset
)
{
    unsigned char header[8];
    EbmlVint id;
    EbmlVint size_field;
    size_t attempts = 0;

    while (attempts < 4U) {
        if (!read_bytes_at(reader, offset, header, sizeof(header))) {
            return 0;
        }
        if (!ebml_read_id(header, sizeof(header), &id)) {
            return 0;
        }
        if (!ebml_read_size(header + id.length, sizeof(header) - id.length, &size_field)) {
            return 0;
        }

        if (id.value == MKV_VOID_ID || id.value == MKV_CRC32_ID) {
            if (size_field.unknown_size) {
                return 0;
            }
            offset += id.length + size_field.length + (size_t)size_field.value;
            attempts++;
            continue;
        }

        return id.value == 0x114D9B74U ||
               id.value == 0x1549A966U ||
               id.value == 0x1654AE6BU ||
               id.value == 0x1F43B675U ||
               id.value == 0x1C53BB6BU ||
               id.value == 0x1941A469U ||
               id.value == 0x1043A770U ||
               id.value == 0x1254C367U;
    }

    return 0;
}

int carver_mkv_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    unsigned char header[16];
    unsigned char *ebml_header = NULL;
    uint32_t ebml_header_id;
    EbmlVint size_field;
    EbmlVint top_id;
    EbmlVint top_size;
    size_t ebml_total_size;
    size_t cursor;
    uint64_t segment_size;
    size_t segment_offset;
    size_t segment_header_size;
    uint64_t total_file_size;
    uint64_t effective_file_cap = mkv_budget_adjusted_file_cap();
    int success = 0;
    const char *reject_reason = "unknown";

    if (resume_offset != NULL) {
        *resume_offset = start_offset;
    }
    if (reader == NULL || reader->buffer == NULL || resume_offset == NULL) {
        return 0;
    }

    carver_mkv_reset_last_audit();
    if (!read_bytes_at(reader, start_offset, header, sizeof(header))) {
        carver_audit_set_inline(&g_mkv_last_audit, "rejected", "short_ebml_header", 0U);
        return 0;
    }

    ebml_header_id = ((uint32_t)header[0] << 24) |
                     ((uint32_t)header[1] << 16) |
                     ((uint32_t)header[2] << 8) |
                     (uint32_t)header[3];
    if (ebml_header_id != MKV_EBML_HEADER_ID) {
        carver_audit_set_inline(&g_mkv_last_audit, "rejected", "missing_ebml_header", 0U);
        return 0;
    }

    if (!ebml_read_size(header + 4U, sizeof(header) - 4U, &size_field) ||
        size_field.unknown_size ||
        size_field.value > MKV_MAX_EBML_HEADER_SIZE) {
        carver_audit_set_inline(&g_mkv_last_audit, "rejected", "invalid_ebml_header_size", 0U);
        return 0;
    }

    ebml_total_size = 4U + size_field.length + (size_t)size_field.value;
    if (ebml_total_size > MKV_MAX_EBML_HEADER_SIZE) {
        carver_audit_set_inline(&g_mkv_last_audit, "rejected", "ebml_header_over_cap", ebml_total_size);
        return 0;
    }

    ebml_header = (unsigned char *)malloc(ebml_total_size);
    if (ebml_header == NULL) {
        carver_audit_set_inline(&g_mkv_last_audit, "rejected", "memory_allocation_failed", ebml_total_size);
        return 0;
    }

    if (!read_bytes_at(reader, start_offset, ebml_header, ebml_total_size)) {
        reject_reason = "could_not_read_full_ebml_header";
        goto cleanup;
    }
    if (!mkv_header_has_known_doctype(ebml_header, ebml_total_size)) {
        reject_reason = "unknown_mkv_doctype";
        goto cleanup;
    }

    cursor = start_offset + ebml_total_size;
    while (1) {
        if (!read_bytes_at(reader, cursor, header, sizeof(header))) {
            reject_reason = "could_not_read_top_level_element";
            goto cleanup;
        }

        if (!ebml_read_id(header, sizeof(header), &top_id) ||
            !ebml_read_size(
                header + top_id.length,
                sizeof(header) - top_id.length,
                &top_size)) {
            reject_reason = "invalid_top_level_element";
            goto cleanup;
        }

        if (top_id.value == MKV_SEGMENT_ID) {
            break;
        }

        if ((top_id.value != MKV_VOID_ID && top_id.value != MKV_CRC32_ID) ||
            top_size.unknown_size) {
            reject_reason = "unexpected_top_level_element_before_segment";
            goto cleanup;
        }

        cursor += top_id.length + top_size.length + (size_t)top_size.value;
    }

    if (top_size.unknown_size) {
        reject_reason = "unknown_segment_size";
        goto cleanup;
    }

    segment_offset = cursor;
    segment_header_size = top_id.length + top_size.length;
    segment_size = top_size.value;
    total_file_size = (uint64_t)segment_offset +
                      (uint64_t)segment_header_size +
                      segment_size;

    if (total_file_size < (uint64_t)segment_offset ||
        total_file_size > effective_file_cap) {
        if (total_file_size > effective_file_cap) {
            log_info(
                "MKV candidate at byte %zu was capped at %.1f MiB (budget=%s); treating it as misleadingly large and moving on",
                absolute_offset,
                (double)effective_file_cap / (1024.0 * 1024.0),
                log_trouble_budget_state_label(log_get_trouble_budget_state())
            );
        }
        reject_reason = total_file_size < (uint64_t)segment_offset
            ? "mkv_size_overflow"
            : "mkv_file_size_over_cap";
        goto cleanup;
    }

    if (!mkv_first_segment_child_known(reader, segment_offset + segment_header_size)) {
        reject_reason = "segment_first_child_unknown";
        goto cleanup;
    }

    success = mkv_stream_exact_size(
        reader,
        config,
        start_offset,
        absolute_offset,
        total_file_size,
        resume_offset
    );
    if (success) {
        carver_audit_set_inline(
            &g_mkv_last_audit,
            "recovered",
            "ebml_segment_size_confirmed",
            (size_t)total_file_size);
        carver_audit_set_trailing_reason_inline(
            &g_mkv_last_audit,
            "mkv_after_segment");
    } else {
        reject_reason = "stream_exact_size_failed";
    }

cleanup:
    if (!success &&
        strcmp(g_mkv_last_audit.status, "not_run") == 0) {
        carver_audit_set_inline(&g_mkv_last_audit, "rejected", reject_reason, 0U);
    }
    free(ebml_header);
    return success;
}
