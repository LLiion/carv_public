#include "carver_mpeg_ps.h"

#include "carver_output.h"
#include "config.h"
#include "fs_backend.h"
#include "log.h"
#include "video_validation.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#if defined(_WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#define MPEG_PACK_HEADER_SIZE 14U
#define MPEG_MIN_PROBE_BYTES 64U
#define MPEG_STRUCTURE_PROBE_BYTES (2U * 1024U * 1024U)
#define MPEG_PACK_BACKTRACK_BYTES (2U * 1024U * 1024U)
#define MPEG_MAX_PACKET_WALK_UNITS 4096U
#define MPEG_MAX_REASONABLE_FILE_SIZE (32ULL * 1024ULL * 1024ULL * 1024ULL)
#define MPEG_MAX_UNANCHORED_FILE_SIZE (512ULL * 1024ULL * 1024ULL)
#define MPEG_STRUCTURAL_TAIL_GRACE_BYTES (8ULL * 1024ULL * 1024ULL)
#define MPEG_MIN_FRAGMENT_ACCEPT_BYTES 4096ULL

typedef struct {
    unsigned pack_headers;
    unsigned system_headers;
    unsigned pes_packets;
    unsigned video_packets;
    unsigned audio_packets;
    unsigned private_packets;
    unsigned padding_packets;
    unsigned metadata_units;
    unsigned end_codes;
    unsigned bad_units;
    unsigned scanned_units;
    uint64_t payload_bytes;
    uint64_t min_pts_90khz;
    uint64_t max_pts_90khz;
    int have_pts;
    size_t max_gap;
} MpegPsValidationStats;

static CarverAuditReport g_mpeg_ps_last_audit;

void carver_mpeg_ps_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_mpeg_ps_last_audit);
}

void carver_mpeg_ps_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_mpeg_ps_last_audit;
}

static int mpeg_output_truncate_to(CarverOutput *output, uint64_t byte_length)
{
    if (output == NULL || output->file == NULL) {
        return 0;
    }
    if (fflush(output->file) != 0) {
        return 0;
    }
#if defined(_WIN32)
    if (_chsize_s(_fileno(output->file), byte_length) != 0) {
        return 0;
    }
    return _fseeki64(output->file, (__int64)byte_length, SEEK_SET) == 0;
#else
    if (ftruncate(fileno(output->file), (off_t)byte_length) != 0) {
        return 0;
    }
    return fseeko(output->file, (off_t)byte_length, SEEK_SET) == 0;
#endif
}

static uint64_t mpeg_reader_buffer_base_absolute(const Reader *reader)
{
    if (reader == NULL) {
        return 0ULL;
    }
    if ((uint64_t)reader->bytes_in_buffer > (uint64_t)reader->total_bytes_read) {
        return 0ULL;
    }
    return (uint64_t)reader->total_bytes_read -
           (uint64_t)reader->bytes_in_buffer;
}

static int mpeg_compute_resume_offset_local(
    const Reader *reader,
    uint64_t resume_abs,
    size_t fallback_offset,
    size_t *resume_offset_out
)
{
    uint64_t base_abs;

    if (reader == NULL || resume_offset_out == NULL) {
        return 0;
    }

    base_abs = mpeg_reader_buffer_base_absolute(reader);
    if (resume_abs < base_abs ||
        resume_abs >= base_abs + (uint64_t)reader->bytes_in_buffer) {
        *resume_offset_out = fallback_offset + 1U;
        return 1;
    }

    *resume_offset_out = (size_t)(resume_abs - base_abs);
    return 1;
}

static uint16_t read_u16_be_local(const unsigned char *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static int is_start_code_at(
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t offset
)
{
    return buffer != NULL &&
           offset + 4U <= bytes_in_buffer &&
           buffer[offset] == 0x00U &&
           buffer[offset + 1U] == 0x00U &&
           buffer[offset + 2U] == 0x01U;
}

static size_t find_next_start_code(
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t offset,
    size_t limit
)
{
    size_t cursor = offset;
    size_t end = limit < bytes_in_buffer ? limit : bytes_in_buffer;

    while (cursor + 4U <= end) {
        if (is_start_code_at(buffer, bytes_in_buffer, cursor)) {
            return cursor;
        }
        cursor++;
    }

    return bytes_in_buffer;
}

static size_t mpeg_pack_header_length(
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t start_offset
)
{
    unsigned char control;

    if (buffer == NULL || start_offset + MPEG_PACK_HEADER_SIZE > bytes_in_buffer) {
        return 0;
    }

    if (buffer[start_offset] != 0x00 ||
        buffer[start_offset + 1] != 0x00 ||
        buffer[start_offset + 2] != 0x01 ||
        buffer[start_offset + 3] != 0xBA) {
        return 0;
    }

    control = buffer[start_offset + 4];

    if ((control & 0xC4U) == 0x44U &&
        (buffer[start_offset + 6U] & 0x04U) != 0U &&
        (buffer[start_offset + 8U] & 0x04U) != 0U &&
        (buffer[start_offset + 9U] & 0x01U) != 0U &&
        (buffer[start_offset + 12U] & 0x01U) != 0U &&
        (buffer[start_offset + 13U] & 0xF8U) == 0xF8U) {
        size_t stuffing = (size_t)(buffer[start_offset + 13U] & 0x07U);
        size_t header_length = 14U + stuffing;
        if (start_offset + header_length <= bytes_in_buffer) {
            return header_length;
        }
        return 0;
    }

    if ((control & 0xF0U) == 0x20U &&
        start_offset + 12U <= bytes_in_buffer) {
        return 12U;
    }

    return 0;
}

static int looks_like_mpeg_pack_header(
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t start_offset
)
{
    return mpeg_pack_header_length(buffer, bytes_in_buffer, start_offset) > 0U;
}

int carver_mpeg_ps_find_pack_start_near(
    const Reader *reader,
    size_t match_offset,
    size_t *out_start_offset
)
{
    size_t min_offset;
    size_t cursor;

    if (out_start_offset != NULL) {
        *out_start_offset = match_offset;
    }
    if (reader == NULL ||
        reader->buffer == NULL ||
        out_start_offset == NULL ||
        match_offset >= reader->bytes_in_buffer) {
        return 0;
    }

    if (looks_like_mpeg_pack_header(reader->buffer, reader->bytes_in_buffer, match_offset)) {
        *out_start_offset = match_offset;
        return 1;
    }

    min_offset = match_offset > MPEG_PACK_BACKTRACK_BYTES
        ? match_offset - MPEG_PACK_BACKTRACK_BYTES
        : 0U;
    cursor = match_offset;
    while (cursor > min_offset) {
        cursor--;
        if (looks_like_mpeg_pack_header(reader->buffer, reader->bytes_in_buffer, cursor)) {
            *out_start_offset = cursor;
            return 1;
        }
    }

    return 0;
}

static int mpeg_stream_id_has_packet_length(unsigned char stream_id)
{
    return stream_id != 0xBAU && stream_id != 0xB9U;
}

static int mpeg_stream_id_is_pes_like(unsigned char stream_id)
{
    return stream_id == 0xBCU ||
           stream_id == 0xBDU ||
           stream_id == 0xBEU ||
           stream_id == 0xBFU ||
           stream_id >= 0xC0U;
}

static int mpeg_stream_id_can_be_lengthless_pes(unsigned char stream_id)
{
    return stream_id >= 0xE0U && stream_id <= 0xEFU;
}

static int mpeg_known_unit_end_in_buffer(
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t packet_start,
    size_t *out_unit_end,
    int *out_lengthless_pes
)
{
    unsigned char stream_id;

    if (out_unit_end != NULL) {
        *out_unit_end = packet_start;
    }
    if (out_lengthless_pes != NULL) {
        *out_lengthless_pes = 0;
    }

    if (buffer == NULL ||
        out_unit_end == NULL ||
        packet_start + 4U > bytes_in_buffer ||
        !is_start_code_at(buffer, bytes_in_buffer, packet_start)) {
        return 0;
    }

    stream_id = buffer[packet_start + 3U];
    if (stream_id == 0xBAU) {
        size_t length = mpeg_pack_header_length(buffer, bytes_in_buffer, packet_start);
        if (length == 0U || packet_start + length > bytes_in_buffer) {
            return 0;
        }
        *out_unit_end = packet_start + length;
        return 1;
    }
    if (stream_id == 0xB9U) {
        *out_unit_end = packet_start + 4U;
        return 1;
    }
    if (mpeg_stream_id_has_packet_length(stream_id) &&
        packet_start + 6U <= bytes_in_buffer) {
        uint16_t packet_length = read_u16_be_local(buffer + packet_start + 4U);

        if (packet_length > 0U) {
            size_t unit_length = 6U + (size_t)packet_length;
            if (packet_start + unit_length <= packet_start ||
                packet_start + unit_length > bytes_in_buffer) {
                return 0;
            }
            *out_unit_end = packet_start + unit_length;
            return 1;
        }
        if (mpeg_stream_id_can_be_lengthless_pes(stream_id)) {
            if (out_lengthless_pes != NULL) {
                *out_lengthless_pes = 1;
            }
        }
    }

    return 0;
}

static int mpeg_read_pts_90khz(
    const unsigned char *data,
    size_t length,
    uint64_t *out_pts
)
{
    uint64_t pts;

    if (out_pts != NULL) {
        *out_pts = 0U;
    }
    if (data == NULL || length < 5U || out_pts == NULL) {
        return 0;
    }
    if ((data[0] & 0xF0U) != 0x20U &&
        (data[0] & 0xF0U) != 0x30U) {
        return 0;
    }
    if ((data[0] & 0x01U) == 0U ||
        (data[2] & 0x01U) == 0U ||
        (data[4] & 0x01U) == 0U) {
        return 0;
    }

    pts = ((uint64_t)((data[0] >> 1U) & 0x07U) << 30U) |
          ((uint64_t)data[1] << 22U) |
          ((uint64_t)((data[2] >> 1U) & 0x7FU) << 15U) |
          ((uint64_t)data[3] << 7U) |
          (uint64_t)((data[4] >> 1U) & 0x7FU);
    *out_pts = pts;
    return 1;
}

static void mpeg_note_pts(MpegPsValidationStats *stats, uint64_t pts_90khz)
{
    if (stats == NULL) {
        return;
    }
    if (!stats->have_pts) {
        stats->min_pts_90khz = pts_90khz;
        stats->max_pts_90khz = pts_90khz;
        stats->have_pts = 1;
        return;
    }
    if (pts_90khz < stats->min_pts_90khz) {
        stats->min_pts_90khz = pts_90khz;
    }
    if (pts_90khz > stats->max_pts_90khz) {
        stats->max_pts_90khz = pts_90khz;
    }
}

static void mpeg_note_pes_timing(
    MpegPsValidationStats *stats,
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t packet_start
)
{
    unsigned char stream_id;
    uint16_t packet_length;
    size_t packet_end;

    if (stats == NULL ||
        buffer == NULL ||
        packet_start + 9U > bytes_in_buffer ||
        !is_start_code_at(buffer, bytes_in_buffer, packet_start)) {
        return;
    }

    stream_id = buffer[packet_start + 3U];
    if (stream_id == 0xBAU ||
        stream_id == 0xB9U ||
        stream_id == 0xBBU ||
        stream_id == 0xBCU ||
        stream_id == 0xBEU ||
        !mpeg_stream_id_is_pes_like(stream_id)) {
        return;
    }

    packet_length = read_u16_be_local(buffer + packet_start + 4U);
    packet_end = packet_length > 0U
        ? packet_start + 6U + (size_t)packet_length
        : bytes_in_buffer;
    if (packet_end < packet_start || packet_end > bytes_in_buffer) {
        packet_end = bytes_in_buffer;
    }

    if (packet_start + 14U <= packet_end &&
        (buffer[packet_start + 6U] & 0xC0U) == 0x80U) {
        unsigned char pts_dts_flags = (unsigned char)(buffer[packet_start + 7U] & 0xC0U);
        unsigned char header_data_length = buffer[packet_start + 8U];
        size_t pts_offset = packet_start + 9U;

        if ((pts_dts_flags == 0x80U || pts_dts_flags == 0xC0U) &&
            header_data_length >= 5U &&
            pts_offset + 5U <= packet_end) {
            uint64_t pts;
            if (mpeg_read_pts_90khz(buffer + pts_offset, packet_end - pts_offset, &pts)) {
                mpeg_note_pts(stats, pts);
            }
        }
        return;
    }

    {
        size_t cursor = packet_start + 6U;

        while (cursor < packet_end && buffer[cursor] == 0xFFU) {
            cursor++;
        }
        if (cursor + 2U <= packet_end &&
            (buffer[cursor] & 0xC0U) == 0x40U) {
            cursor += 2U;
        }
        if (cursor + 5U <= packet_end &&
            ((buffer[cursor] & 0xF0U) == 0x20U ||
             (buffer[cursor] & 0xF0U) == 0x30U)) {
            uint64_t pts;
            if (mpeg_read_pts_90khz(buffer + cursor, packet_end - cursor, &pts)) {
                mpeg_note_pts(stats, pts);
            }
        }
    }
}

static uint64_t mpeg_duration_ms_from_stats(const MpegPsValidationStats *stats)
{
    uint64_t delta;

    if (stats == NULL || !stats->have_pts ||
        stats->max_pts_90khz <= stats->min_pts_90khz) {
        return 0U;
    }

    delta = stats->max_pts_90khz - stats->min_pts_90khz;
    return (delta + 45U) / 90U;
}

static int mpeg_stats_support_fragment_acceptance(
    const MpegPsValidationStats *stats,
    uint64_t total_written
)
{
    uint64_t duration_ms;

    if (stats == NULL ||
        total_written < MPEG_MIN_FRAGMENT_ACCEPT_BYTES ||
        stats->pack_headers == 0U ||
        stats->video_packets == 0U ||
        stats->pes_packets == 0U) {
        return 0;
    }

    duration_ms = mpeg_duration_ms_from_stats(stats);
    if (duration_ms >= 250U) {
        return 1;
    }
    if (stats->video_packets >= 2U &&
        stats->pes_packets >= 2U &&
        stats->bad_units <= stats->video_packets + stats->audio_packets + 2U) {
        return 1;
    }
    if (stats->video_packets >= 1U &&
        stats->audio_packets >= 1U &&
        stats->pes_packets >= 2U &&
        stats->bad_units <= stats->video_packets + stats->audio_packets + 2U) {
        return 1;
    }

    return 0;
}

static void mpeg_note_stream_id(
    MpegPsValidationStats *stats,
    unsigned char stream_id,
    uint16_t packet_length
)
{
    if (stats == NULL) {
        return;
    }

    if (stream_id == 0xBAU) {
        stats->pack_headers++;
        return;
    }
    if (stream_id == 0xB9U) {
        stats->end_codes++;
        return;
    }
    if (stream_id == 0xBBU) {
        stats->system_headers++;
        stats->metadata_units++;
        return;
    }
    if (!mpeg_stream_id_is_pes_like(stream_id)) {
        stats->bad_units++;
        return;
    }

    stats->pes_packets++;
    if (stream_id >= 0xE0U && stream_id <= 0xEFU) {
        stats->video_packets++;
    } else if (stream_id >= 0xC0U && stream_id <= 0xDFU) {
        stats->audio_packets++;
    } else if (stream_id == 0xBDU || stream_id == 0xBFU) {
        stats->private_packets++;
    } else if (stream_id == 0xBEU) {
        stats->padding_packets++;
    } else {
        stats->metadata_units++;
    }
    stats->payload_bytes += packet_length;
}

static int mpeg_probe_initial_structure(
    const unsigned char *buffer,
    size_t bytes_in_buffer,
    size_t start_offset,
    MpegPsValidationStats *stats,
    char *reason_out,
    size_t reason_out_size
)
{
    size_t cursor;
    size_t limit;

    if (reason_out != NULL && reason_out_size > 0U) {
        reason_out[0] = '\0';
    }
    if (stats != NULL) {
        memset(stats, 0, sizeof(*stats));
    }

    if (buffer == NULL ||
        stats == NULL ||
        start_offset + MPEG_MIN_PROBE_BYTES > bytes_in_buffer ||
        !looks_like_mpeg_pack_header(buffer, bytes_in_buffer, start_offset)) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "initial pack header was not plausible");
        }
        return 0;
    }

    cursor = start_offset;
    limit = start_offset + MPEG_STRUCTURE_PROBE_BYTES;
    if (limit < start_offset || limit > bytes_in_buffer) {
        limit = bytes_in_buffer;
    }

    while (cursor + 4U <= limit &&
           stats->scanned_units < MPEG_MAX_PACKET_WALK_UNITS) {
        unsigned char stream_id;
        size_t unit_start = cursor;
        size_t unit_length = 4U;

        if (!is_start_code_at(buffer, bytes_in_buffer, cursor)) {
            size_t next = find_next_start_code(buffer, bytes_in_buffer, cursor + 1U, limit);
            size_t gap = next < bytes_in_buffer ? next - cursor : limit - cursor;
            if (gap > stats->max_gap) {
                stats->max_gap = gap;
            }
            if (next >= bytes_in_buffer || next >= limit) {
                break;
            }
            if (gap > 64U) {
                stats->bad_units++;
            }
            cursor = next;
        }

        stream_id = buffer[cursor + 3U];
        stats->scanned_units++;

        if (stream_id == 0xBAU) {
            unit_length = mpeg_pack_header_length(buffer, bytes_in_buffer, cursor);
            if (unit_length == 0U) {
                stats->bad_units++;
                break;
            }
            mpeg_note_stream_id(stats, stream_id, 0U);
            cursor += unit_length;
            continue;
        }

        if (stream_id == 0xB9U) {
            mpeg_note_stream_id(stats, stream_id, 0U);
            cursor += 4U;
            break;
        }

        if (mpeg_stream_id_has_packet_length(stream_id)) {
            uint16_t packet_length;

            if (cursor + 6U > limit) {
                break;
            }
            packet_length = read_u16_be_local(buffer + cursor + 4U);
            mpeg_note_stream_id(stats, stream_id, packet_length);
            mpeg_note_pes_timing(stats, buffer, bytes_in_buffer, cursor);
            if (packet_length > 0U) {
                unit_length = 6U + (size_t)packet_length;
                if (unit_start + unit_length <= cursor ||
                    unit_start + unit_length > limit) {
                    break;
                }
                cursor = unit_start + unit_length;
                continue;
            }
        } else {
            mpeg_note_stream_id(stats, stream_id, 0U);
        }

        {
            size_t next = find_next_start_code(buffer, bytes_in_buffer, cursor + 4U, limit);
            if (next >= bytes_in_buffer || next >= limit || next <= cursor) {
                break;
            }
            cursor = next;
        }
    }

    if (stats->pack_headers == 0U) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "no plausible pack header in packet walk");
        }
        return 0;
    }
    if (stats->video_packets == 0U) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "no early video PES packet");
        }
        return 0;
    }
    if (stats->pes_packets == 0U) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "no PES payload packet");
        }
        return 0;
    }
    if (stats->bad_units > 3U && stats->bad_units > stats->video_packets + stats->audio_packets) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "packet walk had too many invalid units");
        }
        return 0;
    }

    if (reason_out != NULL && reason_out_size > 0U) {
        snprintf(reason_out, reason_out_size, "pack/PES walk found video payload");
    }
    return 1;
}

static void report_mpeg_validation(
    const AppConfig *config,
    size_t absolute_offset,
    const char *extension,
    const char *status,
    const char *reason,
    uint64_t total_written,
    const MpegPsValidationStats *stats,
    int exact_hint
)
{
    CarvVideoValidationReport report;

    memset(&report, 0, sizeof(report));
    report.container = "mpeg_ps";
    report.extension = extension != NULL && extension[0] != '\0' ? extension : "mpg";
    report.status = status;
    report.reason = reason;
    report.offset = (uint64_t)absolute_offset;
    report.bytes = total_written;
    report.table_status = "packet_walk";
    report.source_exact_hint = exact_hint;
    if (stats != NULL) {
        report.payload_bytes = stats->payload_bytes;
        report.units = stats->pack_headers + stats->pes_packets + stats->system_headers;
        report.video_units = stats->video_packets;
        report.audio_units = stats->audio_packets;
        report.metadata_units = stats->system_headers + stats->private_packets;
        report.end_markers = stats->end_codes;
        report.duration_ms = mpeg_duration_ms_from_stats(stats);
        report.tracks = (stats->video_packets > 0U ? 1U : 0U) +
                        (stats->audio_packets > 0U ? 1U : 0U);
    }
    video_validation_report_append(config, &report);
}

static void mpeg_merge_probe_stats_for_report(
    MpegPsValidationStats *dst,
    const MpegPsValidationStats *probe
)
{
    if (dst == NULL || probe == NULL) {
        return;
    }

    if (dst->pack_headers < probe->pack_headers) {
        dst->pack_headers = probe->pack_headers;
    }
    if (dst->system_headers < probe->system_headers) {
        dst->system_headers = probe->system_headers;
    }
    if (dst->pes_packets < probe->pes_packets) {
        dst->pes_packets = probe->pes_packets;
    }
    if (dst->video_packets < probe->video_packets) {
        dst->video_packets = probe->video_packets;
    }
    if (dst->audio_packets < probe->audio_packets) {
        dst->audio_packets = probe->audio_packets;
    }
    if (dst->private_packets < probe->private_packets) {
        dst->private_packets = probe->private_packets;
    }
    if (dst->padding_packets < probe->padding_packets) {
        dst->padding_packets = probe->padding_packets;
    }
    if (dst->metadata_units < probe->metadata_units) {
        dst->metadata_units = probe->metadata_units;
    }
    if (dst->end_codes < probe->end_codes) {
        dst->end_codes = probe->end_codes;
    }
    if (dst->bad_units < probe->bad_units) {
        dst->bad_units = probe->bad_units;
    }
    if (dst->scanned_units < probe->scanned_units) {
        dst->scanned_units = probe->scanned_units;
    }
    if (dst->payload_bytes < probe->payload_bytes) {
        dst->payload_bytes = probe->payload_bytes;
    }
    if (probe->have_pts) {
        if (!dst->have_pts) {
            dst->min_pts_90khz = probe->min_pts_90khz;
            dst->max_pts_90khz = probe->max_pts_90khz;
            dst->have_pts = 1;
        } else {
            if (dst->min_pts_90khz > probe->min_pts_90khz) {
                dst->min_pts_90khz = probe->min_pts_90khz;
            }
            if (dst->max_pts_90khz < probe->max_pts_90khz) {
                dst->max_pts_90khz = probe->max_pts_90khz;
            }
        }
    }
    if (dst->max_gap < probe->max_gap) {
        dst->max_gap = probe->max_gap;
    }
}

int carver_mpeg_ps_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    const char *extension,
    size_t *resume_offset
)
{
    CarverOutput output = {0};
    uint32_t rolling = 0xFFFFFFFFU;
    size_t current_offset;
    size_t last_resume;
    uint64_t total_written = 0;
    uint64_t last_resume_abs;
    uint64_t max_file_size = MPEG_MAX_UNANCHORED_FILE_SIZE;
    int saw_stream_packet = 0;
    int saw_end_code = 0;
    int structural_tail_cut = 0;
    FsScanHint mft_hint = {0};
    int exact_hint = 0;
    int hit_source_eof = 0;
    int have_pending_lengthless_pes = 0;
    MpegPsValidationStats probe_stats;
    MpegPsValidationStats stream_stats;
    char probe_reason[96];
    uint64_t last_structural_end = 0ULL;
    uint64_t pending_lengthless_pes_start = 0ULL;
    const char *output_extension =
        extension != NULL && extension[0] != '\0' ? extension : "mpg";

    if (reader == NULL || reader->buffer == NULL || resume_offset == NULL) {
        return 0;
    }

    carver_mpeg_ps_reset_last_audit();
    *resume_offset = start_offset;

    if (!looks_like_mpeg_pack_header(reader->buffer, reader->bytes_in_buffer, start_offset)) {
        carver_audit_set_inline(&g_mpeg_ps_last_audit, "rejected", "missing_mpeg_pack_header", 0U);
        return 0;
    }

    if (fs_backend_lookup_scan_hint((long long)absolute_offset, &mft_hint) &&
        mft_hint.exact_data_match) {
        exact_hint = 1;
        max_file_size = MPEG_MAX_REASONABLE_FILE_SIZE;
    }

    if (!mpeg_probe_initial_structure(
            reader->buffer,
            reader->bytes_in_buffer,
            start_offset,
            &probe_stats,
            probe_reason,
            sizeof(probe_reason))) {
        report_mpeg_validation(
            config,
            absolute_offset,
            output_extension,
            "rejected",
            probe_reason,
            0U,
            &probe_stats,
            exact_hint);
        carver_audit_set_inline(&g_mpeg_ps_last_audit, "rejected", probe_reason, 0U);
        return 0;
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            output_extension)) {
        carver_audit_set_inline(&g_mpeg_ps_last_audit, "rejected", "output_open_failed", 0U);
        return 0;
    }

    memset(&stream_stats, 0, sizeof(stream_stats));
    current_offset = start_offset;
    last_resume = start_offset;
    last_resume_abs = (uint64_t)absolute_offset;

    while (1) {
        size_t available;
        size_t i;
        size_t write_count = 0;

        if (current_offset >= reader->bytes_in_buffer) {
            if (reader_read_next(reader) == 0) {
                hit_source_eof = 1;
                break;
            }
            current_offset = reader->overlap_bytes;
        }

        available = reader->bytes_in_buffer - current_offset;
        if (available == 0) {
            break;
        }

        if (total_written + available > max_file_size) {
            carver_output_abort(&output);
            carver_audit_set_inline(&g_mpeg_ps_last_audit, "rejected", "mpeg_file_size_over_cap", (size_t)total_written);
            return 0;
        }

        for (i = 0; i < available; i++) {
            rolling = (rolling << 8) | (uint32_t)reader->buffer[current_offset + i];

            if ((rolling & 0xFFFFFF00U) == 0x00000100U) {
                uint8_t stream_id = (uint8_t)(rolling & 0xFFU);

                if (i >= 3U) {
                    size_t packet_start = current_offset + i - 3U;
                    uint64_t packet_start_written =
                        total_written + (uint64_t)(packet_start - current_offset);
                    size_t unit_end = packet_start;
                    int lengthless_pes = 0;

                    if (have_pending_lengthless_pes &&
                        packet_start_written > pending_lengthless_pes_start) {
                        last_structural_end = packet_start_written;
                        have_pending_lengthless_pes = 0;
                    }
                    if (mpeg_known_unit_end_in_buffer(
                            reader->buffer,
                            reader->bytes_in_buffer,
                            packet_start,
                            &unit_end,
                            &lengthless_pes)) {
                        uint64_t unit_end_written =
                            total_written + (uint64_t)(unit_end - current_offset);
                        if (unit_end_written > last_structural_end) {
                            last_structural_end = unit_end_written;
                        }
                    } else if (lengthless_pes) {
                        have_pending_lengthless_pes = 1;
                        pending_lengthless_pes_start = packet_start_written;
                    }
                }

                if (stream_id == 0xBAU) {
                    stream_stats.pack_headers++;
                }
                if (stream_id == 0xBBU) {
                    stream_stats.system_headers++;
                }
                if (stream_id == 0xBDU || stream_id == 0xBFU) {
                    stream_stats.private_packets++;
                }
                if (stream_id == 0xBEU) {
                    stream_stats.padding_packets++;
                }
                if (stream_id >= 0xC0U && stream_id <= 0xDFU) {
                    stream_stats.audio_packets++;
                }
                if (stream_id >= 0xE0U && stream_id <= 0xEFU) {
                    stream_stats.video_packets++;
                }
                if (i >= 3U) {
                    mpeg_note_pes_timing(
                        &stream_stats,
                        reader->buffer,
                        reader->bytes_in_buffer,
                        current_offset + i - 3U);
                }
                if (stream_id == 0xBBU ||
                    stream_id == 0xBCU ||
                    stream_id == 0xBDU ||
                    stream_id == 0xBEU ||
                    stream_id == 0xBFU ||
                    stream_id >= 0xC0U) {
                    saw_stream_packet = 1;
                    stream_stats.pes_packets++;
                }
            }

            if (rolling == 0x000001B9U) {
                saw_end_code = 1;
                stream_stats.end_codes++;
                write_count = i + 1U;
                break;
            }
        }

        if (!saw_end_code) {
            write_count = available;
        }

        if (fwrite(reader->buffer + current_offset, 1, write_count, output.file) != write_count) {
            carver_output_abort(&output);
            return 0;
        }

        total_written += (uint64_t)write_count;
        current_offset += write_count;
        last_resume = current_offset;
        last_resume_abs = (uint64_t)absolute_offset + total_written;

        if (saw_end_code) {
            break;
        }
        if (!have_pending_lengthless_pes &&
            last_structural_end > 0ULL &&
            total_written > last_structural_end + MPEG_STRUCTURAL_TAIL_GRACE_BYTES) {
            MpegPsValidationStats merged_stats = stream_stats;

            mpeg_merge_probe_stats_for_report(&merged_stats, &probe_stats);
            if (mpeg_stats_support_fragment_acceptance(
                    &merged_stats,
                    last_structural_end)) {
                if (!mpeg_output_truncate_to(&output, last_structural_end)) {
                    carver_output_abort(&output);
                    carver_audit_set_inline(&g_mpeg_ps_last_audit, "rejected", "mpeg_tail_truncate_failed", (size_t)total_written);
                    return 0;
                }
                total_written = last_structural_end;
                last_resume_abs = (uint64_t)absolute_offset + total_written;
                structural_tail_cut = 1;
                break;
            }
        }
    }

    {
        MpegPsValidationStats report_stats = stream_stats;
        int fragment_ok;

        mpeg_merge_probe_stats_for_report(&report_stats, &probe_stats);
        fragment_ok =
            structural_tail_cut &&
            mpeg_stats_support_fragment_acceptance(&report_stats, total_written);

        if ((!saw_end_code && !(hit_source_eof || exact_hint || fragment_ok)) ||
            !saw_stream_packet ||
            report_stats.video_packets == 0U ||
            report_stats.pack_headers == 0U ||
            total_written < MPEG_PACK_HEADER_SIZE) {
            const char *reason = "mpeg stream did not finish cleanly";

            if (!saw_end_code) {
                reason = "missing MPEG program end code";
            } else if (report_stats.video_packets == 0U) {
                reason = "no video PES packet in recovered stream";
            } else if (report_stats.pack_headers == 0U) {
                reason = "no pack header in recovered stream";
            }
            report_mpeg_validation(
                config,
                absolute_offset,
                output_extension,
                "rejected",
                reason,
                total_written,
                &report_stats,
                exact_hint);
            carver_output_abort(&output);
            carver_audit_set_inline(&g_mpeg_ps_last_audit, "rejected", reason, (size_t)total_written);
            return 0;
        }
    }

    if (!carver_output_finish(&output)) {
        carver_audit_set_inline(&g_mpeg_ps_last_audit, "rejected", "finish_failed", (size_t)total_written);
        return 0;
    }

    {
        MpegPsValidationStats report_stats = stream_stats;
        mpeg_merge_probe_stats_for_report(&report_stats, &probe_stats);
        report_mpeg_validation(
            config,
            absolute_offset,
            output_extension,
            saw_end_code ? "accepted" : "accepted_suspicious",
            saw_end_code
                ? "packet walk, video PES and end code confirmed"
                : structural_tail_cut
                    ? "packet walk and video PES confirmed; trimmed at structural boundary before junk tail"
                    : "packet walk and video PES confirmed at clean source boundary",
            total_written,
            &report_stats,
            exact_hint);
        if (total_written < 1024ULL * 1024ULL) {
            log_info(
                "MPG candidate at byte %zu accepted as a short but structurally complete clip: %.1f KiB, video_pes=%u audio_pes=%u packs=%u",
                absolute_offset,
                (double)total_written / 1024.0,
                report_stats.video_packets,
                report_stats.audio_packets,
                report_stats.pack_headers
            );
        }
        carver_audit_set_inline(
            &g_mpeg_ps_last_audit,
            saw_end_code ? "recovered" : "recovered_suspicious",
            saw_end_code
                ? "packet walk, video PES and end code confirmed"
                : structural_tail_cut
                    ? "packet walk and video PES confirmed; trimmed at structural boundary before junk tail"
                    : "packet walk and video PES confirmed at clean source boundary",
            (size_t)total_written);
        carver_audit_set_trailing_reason_inline(
            &g_mpeg_ps_last_audit,
            structural_tail_cut ? "mpeg_after_structural_tail" : "mpeg_after_valid_span");
    }
    (void)mpeg_compute_resume_offset_local(
        reader,
        last_resume_abs,
        last_resume,
        resume_offset
    );
    return 1;
}
