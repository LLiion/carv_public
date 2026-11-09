/*
 * carver_mov.c
 * Streams MOV/MP4-style recovery by parsing top-level atoms starting from
 * an ftyp atom.
 */

#include "carver_mov.h"
#include "app.h"
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
#include <time.h>

#define MOV_MIN_ATOM_SIZE 8
#define MOV_MAX_REASONABLE_ATOM_SIZE (1024ULL * 1024ULL * 1024ULL * 8ULL)
#define MOV_MAX_REASONABLE_FILE_SIZE (1024ULL * 1024ULL * 1024ULL * 16ULL)
#define MOV_EXPLORATORY_CAP_GREEN_BYTES (512ULL * 1024ULL * 1024ULL)
#define MOV_EXPLORATORY_CAP_YELLOW_BYTES (256ULL * 1024ULL * 1024ULL)
#define MOV_EXPLORATORY_CAP_RED_BYTES (128ULL * 1024ULL * 1024ULL)
#define MOV_STRUCTURE_PROBE_BYTES (256U * 1024U)
#define MOV_STRUCTURE_RECURSION_DEPTH 4U
#define MOV_FLAG_MVHD (1U << 0)
#define MOV_FLAG_TRAK (1U << 1)
#define MOV_FLAG_MDIA (1U << 2)
#define MOV_FLAG_STBL (1U << 3)
#define MOV_FLAG_MFHD (1U << 4)
#define MOV_FLAG_TRAF (1U << 5)
#define MOV_FLAG_TFHD (1U << 6)
#define MOV_FLAG_TRUN (1U << 7)
#define MOV_FLAG_HDLR (1U << 8)
#define MOV_FLAG_IINF (1U << 9)
#define MOV_FLAG_ILOC (1U << 10)
#define MOV_FLAG_PITM (1U << 11)
#define MOV_FLAG_IPRP (1U << 12)
#define MOV_FLAG_IPCO (1U << 13)
#define MOV_FINALIZE_MAX_BOXES 32768U
#define MOV_FINALIZE_MAX_DEPTH 8U
#define MOV_FINALIZE_MAX_MDAT_RANGES 16U
#define MOV_FINALIZE_MAX_CHUNK_SAMPLES 256U
#define MOV_CTX_TRAK (1U << 0)
#define MOV_CTX_MDIA (1U << 1)
#define MOV_CTX_STBL (1U << 2)
#define MOV_CTX_MOOF (1U << 3)
#define MOV_CTX_TRAF (1U << 4)

#define MOV_PROGRESS_TIMEOUT_GREEN_SECONDS 90.0
#define MOV_PROGRESS_TIMEOUT_YELLOW_SECONDS 60.0
#define MOV_PROGRESS_TIMEOUT_RED_SECONDS 45.0

typedef struct {
    double last_progress_at;
    double timeout_seconds;
    uint64_t progress_units;
    int timed_out;
    int cancelled;
} MovCandidateProgressGuard;

typedef struct {
    uint64_t offset;
    uint64_t size;
    uint64_t header_size;
    uint64_t payload_offset;
    uint64_t payload_size;
    char type[5];
} MovBoxHeader;

typedef struct {
    uint64_t file_size;
    uint64_t mdat_bytes;
    uint64_t mdat_start[MOV_FINALIZE_MAX_MDAT_RANGES];
    uint64_t mdat_end[MOV_FINALIZE_MAX_MDAT_RANGES];
    uint64_t chunk_samples[MOV_FINALIZE_MAX_CHUNK_SAMPLES];
    uint64_t duration_ms;
    uint64_t movie_duration_ms;
    uint64_t max_media_duration_ms;
    uint64_t sample_count;
    uint64_t fragmented_sample_count;
    uint64_t chunk_offsets;
    uint64_t stts_entries;
    uint64_t stsc_entries;
    uint64_t sampled_chunk_offsets;
    uint64_t invalid_chunk_offsets;
    uint64_t sampled_chunks_outside_mdat;
    unsigned box_count;
    unsigned top_level_atoms;
    unsigned mdat_count;
    unsigned mdat_range_count;
    unsigned moov_count;
    unsigned moof_count;
    unsigned trak_count;
    unsigned media_track_count;
    unsigned video_tracks;
    unsigned audio_tracks;
    unsigned mvhd_count;
    unsigned mdhd_count;
    unsigned hdlr_count;
    unsigned stbl_count;
    unsigned stts_count;
    unsigned stsz_count;
    unsigned stz2_count;
    unsigned stsc_count;
    unsigned stco_count;
    unsigned co64_count;
    unsigned trun_count;
    unsigned tfhd_count;
    unsigned parse_errors;
    int box_limit_hit;
    MovCandidateProgressGuard *progress_guard;
} MovFinalizeStats;

typedef struct {
    const AppConfig *config;
    size_t absolute_offset;
    char extension[16];
    uint64_t total_written;
    int atom_count;
    int image_brand;
    int has_media_payload;
    int has_movie_metadata;
    int has_fragment_metadata;
    int has_strong_movie_metadata;
    int has_strong_fragment_metadata;
    int has_strong_image_metadata;
    char structural_reason[96];
    MovCandidateProgressGuard *progress_guard;
} MovOutputValidationContext;

static CarverAuditReport g_mov_last_audit;

static double mov_monotonic_seconds(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return 0.0;
    }
    return (double)now.tv_sec + ((double)now.tv_nsec / 1000000000.0);
}

static double mov_progress_timeout_seconds(void)
{
    switch (log_get_validator_budget_state()) {
        case LOG_TROUBLE_BUDGET_RED:
            return MOV_PROGRESS_TIMEOUT_RED_SECONDS;
        case LOG_TROUBLE_BUDGET_YELLOW:
            return MOV_PROGRESS_TIMEOUT_YELLOW_SECONDS;
        case LOG_TROUBLE_BUDGET_GREEN:
        case LOG_TROUBLE_BUDGET_UNKNOWN:
        default:
            return MOV_PROGRESS_TIMEOUT_GREEN_SECONDS;
    }
}

static void mov_progress_guard_init(MovCandidateProgressGuard *guard)
{
    if (guard == NULL) {
        return;
    }
    memset(guard, 0, sizeof(*guard));
    guard->timeout_seconds = mov_progress_timeout_seconds();
    guard->last_progress_at = mov_monotonic_seconds();
}

static void mov_progress_guard_touch(
    MovCandidateProgressGuard *guard,
    uint64_t progress_units
)
{
    if (guard == NULL || guard->timed_out) {
        return;
    }
    guard->progress_units = progress_units;
    guard->last_progress_at = mov_monotonic_seconds();
}

static int mov_progress_guard_should_abort(MovCandidateProgressGuard *guard)
{
    double now;

    if (app_stop_requested() || app_supervisor_generation_stale()) {
        if (guard != NULL) {
            guard->cancelled = 1;
        }
        return 1;
    }
    if (guard == NULL || guard->timed_out || guard->timeout_seconds <= 0.0) {
        return guard != NULL && guard->timed_out;
    }
    now = mov_monotonic_seconds();
    if (now > 0.0 && guard->last_progress_at > 0.0 &&
        now - guard->last_progress_at >= guard->timeout_seconds) {
        guard->timed_out = 1;
        return 1;
    }
    return 0;
}

static void mov_copy_audit_text(
    char *out,
    size_t out_size,
    const char *value,
    const char *fallback
)
{
    const char *src = (value != NULL && value[0] != '\0') ? value : fallback;
    size_t i = 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }
    if (src == NULL) {
        src = "";
    }

    while (i + 1U < out_size && src[i] != '\0') {
        out[i] = src[i];
        i++;
    }
    out[i] = '\0';
}

static void mov_reset_last_audit(void)
{
    memset(&g_mov_last_audit, 0, sizeof(g_mov_last_audit));
    mov_copy_audit_text(g_mov_last_audit.status, sizeof(g_mov_last_audit.status), "not_run", "not_run");
    mov_copy_audit_text(
        g_mov_last_audit.reject_reason,
        sizeof(g_mov_last_audit.reject_reason),
        "not_run",
        "not_run"
    );
}

void carver_mov_reset_last_audit(void)
{
    mov_reset_last_audit();
}

static void mov_set_last_audit(
    const char *status,
    const char *reason,
    uint64_t confirmed_span
)
{
    g_mov_last_audit.confirmed_span = (size_t)confirmed_span;
    mov_copy_audit_text(
        g_mov_last_audit.status,
        sizeof(g_mov_last_audit.status),
        status,
        "unknown"
    );
    mov_copy_audit_text(
        g_mov_last_audit.reject_reason,
        sizeof(g_mov_last_audit.reject_reason),
        reason,
        ""
    );
}

static void mov_set_last_audit_trailing_reason(const char *reason)
{
    mov_copy_audit_text(
        g_mov_last_audit.trailing_child_reason,
        sizeof(g_mov_last_audit.trailing_child_reason),
        reason,
        ""
    );
}

void carver_mov_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_mov_last_audit;
}

static int is_likely_printable_fourcc(const char *type);
static int mov_type_is_container_box(const char *type);

static uint64_t mov_budget_adjusted_file_cap(void)
{
    switch (log_get_validator_budget_state()) {
        case LOG_TROUBLE_BUDGET_RED:
            return 4ULL * 1024ULL * 1024ULL * 1024ULL;
        case LOG_TROUBLE_BUDGET_YELLOW:
            return 8ULL * 1024ULL * 1024ULL * 1024ULL;
        case LOG_TROUBLE_BUDGET_GREEN:
        case LOG_TROUBLE_BUDGET_UNKNOWN:
        default:
            return MOV_MAX_REASONABLE_FILE_SIZE;
    }
}

static uint64_t mov_budget_adjusted_exploratory_cap(void)
{
    switch (log_get_validator_budget_state()) {
        case LOG_TROUBLE_BUDGET_RED:
            return MOV_EXPLORATORY_CAP_RED_BYTES;
        case LOG_TROUBLE_BUDGET_YELLOW:
            return MOV_EXPLORATORY_CAP_YELLOW_BYTES;
        case LOG_TROUBLE_BUDGET_GREEN:
        case LOG_TROUBLE_BUDGET_UNKNOWN:
        default:
            return MOV_EXPLORATORY_CAP_GREEN_BYTES;
    }
}

/* ========================= UTIL ========================= */

static uint32_t read_u32_be(const unsigned char *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           ((uint32_t)data[3]);
}

static uint64_t read_u64_be(const unsigned char *data)
{
    return ((uint64_t)data[0] << 56) |
           ((uint64_t)data[1] << 48) |
           ((uint64_t)data[2] << 40) |
           ((uint64_t)data[3] << 32) |
           ((uint64_t)data[4] << 24) |
           ((uint64_t)data[5] << 16) |
           ((uint64_t)data[6] << 8) |
           ((uint64_t)data[7]);
}

static void copy_fourcc(char out[5], const unsigned char *data)
{
    out[0] = (char)data[0];
    out[1] = (char)data[1];
    out[2] = (char)data[2];
    out[3] = (char)data[3];
    out[4] = '\0';
}

static int mov_file_read_at(
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

static uint64_t mov_duration_to_ms(uint64_t duration, uint32_t timescale)
{
    if (duration == 0U || timescale == 0U) {
        return 0U;
    }
    if (duration <= UINT64_MAX / 1000ULL) {
        return (duration * 1000ULL) / (uint64_t)timescale;
    }
    return (duration / (uint64_t)timescale) * 1000ULL;
}

static int mov_file_read_box_header(
    FILE *file,
    uint64_t offset,
    uint64_t parent_end,
    MovBoxHeader *box
)
{
    unsigned char header[16];
    uint64_t size;
    uint64_t header_size = 8U;

    if (file == NULL || box == NULL || offset + 8U < offset || offset + 8U > parent_end) {
        return 0;
    }
    if (!mov_file_read_at(file, offset, header, 8U)) {
        return 0;
    }

    memset(box, 0, sizeof(*box));
    size = read_u32_be(header);
    copy_fourcc(box->type, header + 4U);

    if (size == 1U) {
        if (offset + 16U < offset || offset + 16U > parent_end ||
            !mov_file_read_at(file, offset, header, 16U)) {
            return 0;
        }
        size = read_u64_be(header + 8U);
        header_size = 16U;
    } else if (size == 0U) {
        size = parent_end - offset;
    }

    if (size < header_size ||
        offset + size < offset ||
        offset + size > parent_end ||
        !is_likely_printable_fourcc(box->type)) {
        return 0;
    }

    box->offset = offset;
    box->size = size;
    box->header_size = header_size;
    box->payload_offset = offset + header_size;
    box->payload_size = size - header_size;
    return 1;
}

static int mov_file_read_payload_prefix(
    FILE *file,
    const MovBoxHeader *box,
    unsigned char *buffer,
    size_t length
)
{
    if (box == NULL || box->payload_size < length) {
        return 0;
    }
    return mov_file_read_at(file, box->payload_offset, buffer, length);
}

static void mov_finalize_note_mdat(MovFinalizeStats *stats, const MovBoxHeader *box)
{
    uint64_t payload_end;

    if (stats == NULL || box == NULL) {
        return;
    }

    stats->mdat_count++;
    stats->mdat_bytes += box->payload_size;
    payload_end = box->payload_offset + box->payload_size;
    if (stats->mdat_range_count < MOV_FINALIZE_MAX_MDAT_RANGES) {
        unsigned index = stats->mdat_range_count++;
        stats->mdat_start[index] = box->payload_offset;
        stats->mdat_end[index] = payload_end;
    }
}

static int mov_finalize_offset_inside_mdat(
    const MovFinalizeStats *stats,
    uint64_t offset
)
{
    unsigned i;

    if (stats == NULL) {
        return 0;
    }
    for (i = 0U; i < stats->mdat_range_count; i++) {
        if (offset >= stats->mdat_start[i] && offset < stats->mdat_end[i]) {
            return 1;
        }
    }
    return 0;
}

static void mov_finalize_note_duration(
    MovFinalizeStats *stats,
    uint64_t duration_ms,
    int movie_duration
)
{
    if (stats == NULL || duration_ms == 0U) {
        return;
    }
    if (movie_duration) {
        stats->movie_duration_ms = duration_ms;
    } else if (duration_ms > stats->max_media_duration_ms) {
        stats->max_media_duration_ms = duration_ms;
    }
    if (duration_ms > stats->duration_ms) {
        stats->duration_ms = duration_ms;
    }
}

static void mov_finalize_parse_mvhd(
    FILE *file,
    const MovBoxHeader *box,
    MovFinalizeStats *stats
)
{
    unsigned char data[32];
    size_t read_len;
    unsigned version;
    uint32_t timescale;
    uint64_t duration;

    if (stats == NULL) {
        return;
    }
    stats->mvhd_count++;
    read_len = box != NULL && box->payload_size < sizeof(data)
        ? (size_t)box->payload_size
        : sizeof(data);
    if (read_len < 20U || !mov_file_read_at(file, box->payload_offset, data, read_len)) {
        stats->parse_errors++;
        return;
    }
    version = data[0];
    if (version == 1U) {
        if (read_len < 32U) {
            stats->parse_errors++;
            return;
        }
        timescale = read_u32_be(data + 20U);
        duration = read_u64_be(data + 24U);
    } else {
        timescale = read_u32_be(data + 12U);
        duration = read_u32_be(data + 16U);
    }
    mov_finalize_note_duration(stats, mov_duration_to_ms(duration, timescale), 1);
}

static void mov_finalize_parse_mdhd(
    FILE *file,
    const MovBoxHeader *box,
    MovFinalizeStats *stats
)
{
    unsigned char data[32];
    size_t read_len;
    unsigned version;
    uint32_t timescale;
    uint64_t duration;

    if (stats == NULL) {
        return;
    }
    stats->mdhd_count++;
    read_len = box != NULL && box->payload_size < sizeof(data)
        ? (size_t)box->payload_size
        : sizeof(data);
    if (read_len < 20U || !mov_file_read_at(file, box->payload_offset, data, read_len)) {
        stats->parse_errors++;
        return;
    }
    version = data[0];
    if (version == 1U) {
        if (read_len < 32U) {
            stats->parse_errors++;
            return;
        }
        timescale = read_u32_be(data + 20U);
        duration = read_u64_be(data + 24U);
    } else {
        timescale = read_u32_be(data + 12U);
        duration = read_u32_be(data + 16U);
    }
    mov_finalize_note_duration(stats, mov_duration_to_ms(duration, timescale), 0);
}

static void mov_finalize_parse_hdlr(
    FILE *file,
    const MovBoxHeader *box,
    unsigned context,
    MovFinalizeStats *stats
)
{
    unsigned char data[12];
    char handler[5];

    if (stats == NULL) {
        return;
    }
    stats->hdlr_count++;
    if ((context & MOV_CTX_MDIA) == 0U) {
        return;
    }
    if (!mov_file_read_payload_prefix(file, box, data, sizeof(data))) {
        stats->parse_errors++;
        return;
    }
    copy_fourcc(handler, data + 8U);
    if (memcmp(handler, "vide", 4U) == 0) {
        stats->video_tracks++;
        stats->media_track_count++;
    } else if (memcmp(handler, "soun", 4U) == 0) {
        stats->audio_tracks++;
        stats->media_track_count++;
    }
}

static uint32_t mov_finalize_read_entry_count(
    FILE *file,
    const MovBoxHeader *box
)
{
    unsigned char data[8];

    if (!mov_file_read_payload_prefix(file, box, data, sizeof(data))) {
        return 0U;
    }
    return read_u32_be(data + 4U);
}

static void mov_finalize_parse_stsz_or_stz2(
    FILE *file,
    const MovBoxHeader *box,
    MovFinalizeStats *stats
)
{
    unsigned char data[12];
    uint32_t sample_count;

    if (stats == NULL) {
        return;
    }
    if (memcmp(box->type, "stsz", 4U) == 0) {
        stats->stsz_count++;
    } else {
        stats->stz2_count++;
    }
    if (!mov_file_read_payload_prefix(file, box, data, sizeof(data))) {
        stats->parse_errors++;
        return;
    }
    sample_count = read_u32_be(data + 8U);
    stats->sample_count += sample_count;
}

static void mov_finalize_note_chunk_sample(
    MovFinalizeStats *stats,
    uint64_t chunk_offset
)
{
    if (stats == NULL) {
        return;
    }
    if (chunk_offset >= stats->file_size) {
        stats->invalid_chunk_offsets++;
    }
    if (stats->sampled_chunk_offsets < MOV_FINALIZE_MAX_CHUNK_SAMPLES) {
        stats->chunk_samples[stats->sampled_chunk_offsets++] = chunk_offset;
    }
}

static void mov_finalize_parse_chunk_offsets(
    FILE *file,
    const MovBoxHeader *box,
    MovFinalizeStats *stats
)
{
    unsigned char data[12];
    uint32_t entry_count;
    uint32_t i;
    uint32_t sample_tail_start = 0U;
    int use_64;

    if (stats == NULL) {
        return;
    }
    use_64 = memcmp(box->type, "co64", 4U) == 0;
    if (use_64) {
        stats->co64_count++;
    } else {
        stats->stco_count++;
    }
    if (!mov_file_read_payload_prefix(file, box, data, 8U)) {
        stats->parse_errors++;
        return;
    }
    entry_count = read_u32_be(data + 4U);
    stats->chunk_offsets += entry_count;

    if (entry_count > 128U) {
        sample_tail_start = entry_count > 128U ? entry_count - 128U : 0U;
    }
    for (i = 0U; i < entry_count; i++) {
        uint64_t entry_offset;
        uint64_t chunk_offset;
        size_t width = use_64 ? 8U : 4U;

        if (entry_count > MOV_FINALIZE_MAX_CHUNK_SAMPLES &&
            i >= 128U &&
            i < sample_tail_start) {
            i = sample_tail_start - 1U;
            continue;
        }
        if (mov_progress_guard_should_abort(stats->progress_guard)) {
            return;
        }

        entry_offset = box->payload_offset + 8U + (uint64_t)i * (uint64_t)width;
        if (entry_offset + width < entry_offset ||
            entry_offset + width > box->payload_offset + box->payload_size) {
            stats->parse_errors++;
            break;
        }
        if (!mov_file_read_at(file, entry_offset, data, width)) {
            stats->parse_errors++;
            break;
        }
        chunk_offset = use_64 ? read_u64_be(data) : (uint64_t)read_u32_be(data);
        mov_finalize_note_chunk_sample(stats, chunk_offset);
        mov_progress_guard_touch(
            stats->progress_guard,
            (uint64_t)stats->box_count + (uint64_t)i + 1ULL
        );
    }
}

static void mov_finalize_parse_trun(
    FILE *file,
    const MovBoxHeader *box,
    MovFinalizeStats *stats
)
{
    unsigned char data[8];
    uint32_t sample_count;

    if (stats == NULL) {
        return;
    }
    stats->trun_count++;
    if (!mov_file_read_payload_prefix(file, box, data, sizeof(data))) {
        stats->parse_errors++;
        return;
    }
    sample_count = read_u32_be(data + 4U);
    stats->fragmented_sample_count += sample_count;
}

static unsigned mov_finalize_child_context(
    const MovBoxHeader *box,
    unsigned context,
    MovFinalizeStats *stats
)
{
    if (box == NULL) {
        return context;
    }

    if (memcmp(box->type, "moov", 4U) == 0) {
        if (stats != NULL) {
            stats->moov_count++;
        }
        return 0U;
    }
    if (memcmp(box->type, "trak", 4U) == 0) {
        if (stats != NULL) {
            stats->trak_count++;
        }
        return MOV_CTX_TRAK;
    }
    if (memcmp(box->type, "mdia", 4U) == 0) {
        return (context | MOV_CTX_MDIA) & ~MOV_CTX_STBL;
    }
    if (memcmp(box->type, "stbl", 4U) == 0) {
        if (stats != NULL) {
            stats->stbl_count++;
        }
        return context | MOV_CTX_STBL;
    }
    if (memcmp(box->type, "moof", 4U) == 0) {
        if (stats != NULL) {
            stats->moof_count++;
        }
        return MOV_CTX_MOOF;
    }
    if (memcmp(box->type, "traf", 4U) == 0) {
        return context | MOV_CTX_TRAF;
    }

    return context;
}

static void mov_finalize_parse_leaf(
    FILE *file,
    const MovBoxHeader *box,
    unsigned context,
    MovFinalizeStats *stats
)
{
    uint32_t entry_count;

    if (file == NULL || box == NULL || stats == NULL) {
        return;
    }

    if (memcmp(box->type, "mvhd", 4U) == 0) {
        mov_finalize_parse_mvhd(file, box, stats);
    } else if (memcmp(box->type, "mdhd", 4U) == 0) {
        mov_finalize_parse_mdhd(file, box, stats);
    } else if (memcmp(box->type, "hdlr", 4U) == 0) {
        mov_finalize_parse_hdlr(file, box, context, stats);
    } else if (memcmp(box->type, "stts", 4U) == 0) {
        stats->stts_count++;
        entry_count = mov_finalize_read_entry_count(file, box);
        if (entry_count == 0U) {
            stats->parse_errors++;
        }
        stats->stts_entries += entry_count;
    } else if (memcmp(box->type, "stsc", 4U) == 0) {
        stats->stsc_count++;
        entry_count = mov_finalize_read_entry_count(file, box);
        if (entry_count == 0U) {
            stats->parse_errors++;
        }
        stats->stsc_entries += entry_count;
    } else if (memcmp(box->type, "stsz", 4U) == 0 ||
               memcmp(box->type, "stz2", 4U) == 0) {
        mov_finalize_parse_stsz_or_stz2(file, box, stats);
    } else if (memcmp(box->type, "stco", 4U) == 0 ||
               memcmp(box->type, "co64", 4U) == 0) {
        mov_finalize_parse_chunk_offsets(file, box, stats);
    } else if (memcmp(box->type, "trun", 4U) == 0) {
        mov_finalize_parse_trun(file, box, stats);
    } else if (memcmp(box->type, "tfhd", 4U) == 0) {
        stats->tfhd_count++;
    }
}

static int mov_finalize_box_is_container(const MovBoxHeader *box)
{
    return box != NULL && mov_type_is_container_box(box->type);
}

static void mov_finalize_walk_boxes(
    FILE *file,
    uint64_t start,
    uint64_t end,
    unsigned depth,
    unsigned context,
    MovFinalizeStats *stats
)
{
    uint64_t cursor = start;

    if (file == NULL || stats == NULL || start > end || depth > MOV_FINALIZE_MAX_DEPTH) {
        return;
    }

    while (cursor + 8U >= cursor && cursor + 8U <= end) {
        MovBoxHeader box;
        unsigned child_context;
        uint64_t child_start;
        uint64_t child_end;

        if (mov_progress_guard_should_abort(stats->progress_guard)) {
            return;
        }
        if (stats->box_count >= MOV_FINALIZE_MAX_BOXES) {
            stats->box_limit_hit = 1;
            return;
        }
        if (!mov_file_read_box_header(file, cursor, end, &box)) {
            stats->parse_errors++;
            return;
        }

        stats->box_count++;
        mov_progress_guard_touch(
            stats->progress_guard,
            (uint64_t)stats->box_count
        );
        if (depth == 0U) {
            stats->top_level_atoms++;
        }

        if (memcmp(box.type, "mdat", 4U) == 0) {
            mov_finalize_note_mdat(stats, &box);
        } else {
            mov_finalize_parse_leaf(file, &box, context, stats);
        }

        child_context = mov_finalize_child_context(&box, context, stats);
        child_start = box.payload_offset;
        child_end = box.payload_offset + box.payload_size;
        if (memcmp(box.type, "meta", 4U) == 0 && child_start + 4U <= child_end) {
            child_start += 4U;
        }
        if (depth < MOV_FINALIZE_MAX_DEPTH &&
            mov_finalize_box_is_container(&box) &&
            child_start + 8U >= child_start &&
            child_start + 8U <= child_end) {
            mov_finalize_walk_boxes(
                file,
                child_start,
                child_end,
                depth + 1U,
                child_context,
                stats
            );
        }

        if (box.size == 0U || cursor + box.size <= cursor) {
            stats->parse_errors++;
            return;
        }
        cursor += box.size;
    }
}

static void mov_finalize_validate_chunk_samples(MovFinalizeStats *stats)
{
    uint64_t i;

    if (stats == NULL) {
        return;
    }
    for (i = 0U; i < stats->sampled_chunk_offsets; i++) {
        if (!mov_finalize_offset_inside_mdat(stats, stats->chunk_samples[i])) {
            stats->sampled_chunks_outside_mdat++;
        }
    }
}

static int mov_finalize_collect_stats(
    const char *path,
    MovFinalizeStats *stats,
    MovCandidateProgressGuard *progress_guard
)
{
    struct stat st;
    FILE *file;

    if (path == NULL || stats == NULL) {
        return 0;
    }
    memset(stats, 0, sizeof(*stats));
    stats->progress_guard = progress_guard;
    if (stat(path, &st) != 0 || st.st_size <= 0) {
        return 0;
    }
    stats->file_size = (uint64_t)st.st_size;
    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    mov_finalize_walk_boxes(file, 0U, stats->file_size, 0U, 0U, stats);
    fclose(file);
    if (progress_guard != NULL &&
        (progress_guard->timed_out || progress_guard->cancelled)) {
        return 0;
    }
    mov_finalize_validate_chunk_samples(stats);
    return stats->top_level_atoms > 0U;
}

static const char *mov_finalize_decide(
    const MovFinalizeStats *stats,
    int image_brand,
    char *reason_out,
    size_t reason_out_size,
    char *table_status_out,
    size_t table_status_out_size,
    int *hard_reject_out
)
{
    unsigned missing_essentials = 0U;
    int has_sample_size_table;

    if (reason_out != NULL && reason_out_size > 0U) {
        reason_out[0] = '\0';
    }
    if (table_status_out != NULL && table_status_out_size > 0U) {
        table_status_out[0] = '\0';
    }
    if (hard_reject_out != NULL) {
        *hard_reject_out = 0;
    }
    if (stats == NULL) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "finalize parser had no stats");
        }
        if (table_status_out != NULL && table_status_out_size > 0U) {
            snprintf(table_status_out, table_status_out_size, "parse_failed");
        }
        return "accepted_suspicious";
    }

    if (stats->mdat_count == 0U || stats->mdat_bytes == 0U) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "finalize parser found no mdat payload");
        }
        if (table_status_out != NULL && table_status_out_size > 0U) {
            snprintf(table_status_out, table_status_out_size, "no_mdat");
        }
        if (hard_reject_out != NULL) {
            *hard_reject_out = 1;
        }
        return "rejected";
    }

    if (image_brand) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "image-family MOV/ISO BMFF structure kept");
        }
        if (table_status_out != NULL && table_status_out_size > 0U) {
            snprintf(table_status_out, table_status_out_size, "image_family");
        }
        return "accepted";
    }

    if (stats->moof_count > 0U || stats->trun_count > 0U) {
        if (stats->fragmented_sample_count > 0U && stats->mdat_bytes > 0U) {
            if (reason_out != NULL && reason_out_size > 0U) {
                snprintf(reason_out, reason_out_size, "fragmented MP4 has trun samples and mdat payload");
            }
            if (table_status_out != NULL && table_status_out_size > 0U) {
                snprintf(table_status_out, table_status_out_size, "fragmented_samples");
            }
            return "accepted";
        }
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "fragmented MP4 metadata has no trun samples");
        }
        if (table_status_out != NULL && table_status_out_size > 0U) {
            snprintf(table_status_out, table_status_out_size, "fragmented_no_samples");
        }
        return "accepted_suspicious";
    }

    has_sample_size_table = stats->stsz_count > 0U || stats->stz2_count > 0U;
    if (stats->stts_count == 0U || stats->stts_entries == 0U) {
        missing_essentials++;
    }
    if (!has_sample_size_table || stats->sample_count == 0U) {
        missing_essentials++;
    }
    if (stats->stsc_count == 0U || stats->stsc_entries == 0U) {
        missing_essentials++;
    }
    if (stats->chunk_offsets == 0U) {
        missing_essentials++;
    }

    if (missing_essentials >= 2U) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(
                reason_out,
                reason_out_size,
                "classic MP4 sample tables are too incomplete"
            );
        }
        if (table_status_out != NULL && table_status_out_size > 0U) {
            snprintf(table_status_out, table_status_out_size, "sample_tables_missing");
        }
        if (hard_reject_out != NULL) {
            *hard_reject_out = 1;
        }
        return "rejected";
    }

    if (stats->sampled_chunk_offsets > 0U &&
        stats->invalid_chunk_offsets >= stats->sampled_chunk_offsets) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "all sampled chunk offsets point beyond EOF");
        }
        if (table_status_out != NULL && table_status_out_size > 0U) {
            snprintf(table_status_out, table_status_out_size, "chunk_offsets_beyond_eof");
        }
        if (hard_reject_out != NULL) {
            *hard_reject_out = 1;
        }
        return "rejected";
    }

    if (stats->sampled_chunk_offsets > 0U &&
        stats->sampled_chunks_outside_mdat >= stats->sampled_chunk_offsets) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "sampled chunk offsets do not point into mdat");
        }
        if (table_status_out != NULL && table_status_out_size > 0U) {
            snprintf(table_status_out, table_status_out_size, "chunks_outside_mdat");
        }
        return "accepted_suspicious";
    }

    if (missing_essentials > 0U || stats->duration_ms == 0U || stats->parse_errors > 0U) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(
                reason_out,
                reason_out_size,
                "classic MP4 kept with caution: missing=%u duration_ms=%llu parse_errors=%u",
                missing_essentials,
                (unsigned long long)stats->duration_ms,
                stats->parse_errors
            );
        }
        if (table_status_out != NULL && table_status_out_size > 0U) {
            snprintf(table_status_out, table_status_out_size, "sample_tables_partial");
        }
        return "accepted_suspicious";
    }

    if (reason_out != NULL && reason_out_size > 0U) {
        snprintf(reason_out, reason_out_size, "duration and classic sample tables confirmed");
    }
    if (table_status_out != NULL && table_status_out_size > 0U) {
        snprintf(table_status_out, table_status_out_size, "sample_tables_complete");
    }
    return "accepted";
}

/* ========================= ATOM ========================= */

static int read_atom_header(
    Reader *reader,
    size_t offset,
    unsigned char header[16],
    MovCandidateProgressGuard *progress_guard
)
{
    size_t needed = 16;
    size_t copied = 0;

    if (reader == NULL || reader->buffer == NULL || header == NULL) {
        return 0;
    }

    while (1) {
        size_t available = (offset < reader->bytes_in_buffer)
                         ? reader->bytes_in_buffer - offset
                         : 0;

        if (mov_progress_guard_should_abort(progress_guard)) {
            return 0;
        }
        if (available >= needed) {
            memcpy(header + copied, reader->buffer + offset, needed);
            return 1;
        }

        if (available > 0) {
            memcpy(header + copied, reader->buffer + offset, available);
            copied += available;
            needed -= available;
        }

        if (reader_read_next(reader) == 0) {
            return 0;
        }
        mov_progress_guard_touch(
            progress_guard,
            (uint64_t)reader->total_bytes_read
        );

        offset = reader->overlap_bytes;
    }
}

static int is_likely_printable_fourcc(const char *type)
{
    size_t i;

    if (type == NULL) {
        return 0;
    }

    for (i = 0; i < 4; i++) {
        unsigned char c = (unsigned char)type[i];

        if (c < 32 || c > 126) {
            return 0;
        }
    }

    return 1;
}

static int is_known_mov_brand(const char *brand)
{
    if (brand == NULL) {
        return 0;
    }

    return memcmp(brand, "isom", 4) == 0 ||
           memcmp(brand, "iso2", 4) == 0 ||
           memcmp(brand, "mp41", 4) == 0 ||
           memcmp(brand, "mp42", 4) == 0 ||
           memcmp(brand, "M4A ", 4) == 0 ||
           memcmp(brand, "M4B ", 4) == 0 ||
           memcmp(brand, "M4V ", 4) == 0 ||
           memcmp(brand, "3gp4", 4) == 0 ||
           memcmp(brand, "3gp5", 4) == 0 ||
           memcmp(brand, "3g2a", 4) == 0 ||
           memcmp(brand, "qt  ", 4) == 0 ||
           memcmp(brand, "avif", 4) == 0 ||
           memcmp(brand, "heic", 4) == 0 ||
           memcmp(brand, "heix", 4) == 0 ||
           memcmp(brand, "hevc", 4) == 0 ||
           memcmp(brand, "hevx", 4) == 0 ||
           memcmp(brand, "mif1", 4) == 0 ||
           memcmp(brand, "msf1", 4) == 0;
}

static int mov_brand_is_image_family(const char *brand)
{
    if (brand == NULL) {
        return 0;
    }

    return memcmp(brand, "heic", 4) == 0 ||
           memcmp(brand, "heix", 4) == 0 ||
           memcmp(brand, "hevc", 4) == 0 ||
           memcmp(brand, "hevx", 4) == 0 ||
           memcmp(brand, "mif1", 4) == 0 ||
           memcmp(brand, "msf1", 4) == 0 ||
           memcmp(brand, "avif", 4) == 0;
}

static const char *extension_from_brand(const char *brand)
{
    if (brand == NULL) {
        return "mov";
    }

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

    return "mov";
}

static int is_known_top_level_atom(const char *type)
{
    if (type == NULL) {
        return 0;
    }

    return memcmp(type, "ftyp", 4) == 0 ||
           memcmp(type, "moov", 4) == 0 ||
           memcmp(type, "mdat", 4) == 0 ||
           memcmp(type, "free", 4) == 0 ||
           memcmp(type, "skip", 4) == 0 ||
           memcmp(type, "wide", 4) == 0 ||
           memcmp(type, "uuid", 4) == 0 ||
           memcmp(type, "pnot", 4) == 0 ||
           memcmp(type, "meta", 4) == 0 ||
           memcmp(type, "pdin", 4) == 0 ||
           memcmp(type, "moof", 4) == 0 ||
           memcmp(type, "mfra", 4) == 0;
}

static uint32_t mov_structure_flag_for_type(const char *type)
{
    if (type == NULL) {
        return 0U;
    }

    if (memcmp(type, "mvhd", 4) == 0) {
        return MOV_FLAG_MVHD;
    }
    if (memcmp(type, "trak", 4) == 0) {
        return MOV_FLAG_TRAK;
    }
    if (memcmp(type, "mdia", 4) == 0) {
        return MOV_FLAG_MDIA;
    }
    if (memcmp(type, "stbl", 4) == 0) {
        return MOV_FLAG_STBL;
    }
    if (memcmp(type, "mfhd", 4) == 0) {
        return MOV_FLAG_MFHD;
    }
    if (memcmp(type, "traf", 4) == 0) {
        return MOV_FLAG_TRAF;
    }
    if (memcmp(type, "tfhd", 4) == 0) {
        return MOV_FLAG_TFHD;
    }
    if (memcmp(type, "trun", 4) == 0) {
        return MOV_FLAG_TRUN;
    }
    if (memcmp(type, "hdlr", 4) == 0) {
        return MOV_FLAG_HDLR;
    }
    if (memcmp(type, "iinf", 4) == 0) {
        return MOV_FLAG_IINF;
    }
    if (memcmp(type, "iloc", 4) == 0) {
        return MOV_FLAG_ILOC;
    }
    if (memcmp(type, "pitm", 4) == 0) {
        return MOV_FLAG_PITM;
    }
    if (memcmp(type, "iprp", 4) == 0) {
        return MOV_FLAG_IPRP;
    }
    if (memcmp(type, "ipco", 4) == 0) {
        return MOV_FLAG_IPCO;
    }

    return 0U;
}

static int mov_type_is_container_box(const char *type)
{
    if (type == NULL) {
        return 0;
    }

    return memcmp(type, "moov", 4) == 0 ||
           memcmp(type, "trak", 4) == 0 ||
           memcmp(type, "mdia", 4) == 0 ||
           memcmp(type, "minf", 4) == 0 ||
           memcmp(type, "stbl", 4) == 0 ||
           memcmp(type, "moof", 4) == 0 ||
           memcmp(type, "traf", 4) == 0 ||
           memcmp(type, "meta", 4) == 0 ||
           memcmp(type, "iprp", 4) == 0 ||
           memcmp(type, "ipco", 4) == 0 ||
           memcmp(type, "iinf", 4) == 0;
}

static void mov_collect_structure_flags_from_buffer(
    const unsigned char *buffer,
    size_t length,
    size_t initial_skip,
    unsigned depth_remaining,
    uint32_t *flags_out,
    unsigned *parsed_box_count_out
)
{
    size_t cursor = initial_skip;

    if (buffer == NULL || flags_out == NULL || parsed_box_count_out == NULL) {
        return;
    }

    while (cursor + 8U <= length) {
        uint64_t child_size = read_u32_be(buffer + cursor);
        uint64_t child_header_size = 8U;
        char child_type[5];

        copy_fourcc(child_type, buffer + cursor + 4U);
        if (!is_likely_printable_fourcc(child_type)) {
            break;
        }

        if (child_size == 1U) {
            if (cursor + 16U > length) {
                break;
            }
            child_size = read_u64_be(buffer + cursor + 8U);
            child_header_size = 16U;
        } else if (child_size == 0U) {
            child_size = (uint64_t)(length - cursor);
        }

        if (child_size < child_header_size) {
            break;
        }

        (*parsed_box_count_out)++;
        *flags_out |= mov_structure_flag_for_type(child_type);

        if (depth_remaining > 0U &&
            mov_type_is_container_box(child_type) &&
            child_size > child_header_size) {
            size_t child_initial_skip = 0U;
            size_t available_child_size =
                child_size > (uint64_t)(length - cursor)
                    ? length - cursor
                    : (size_t)child_size;
            size_t child_payload_size =
                available_child_size > child_header_size
                    ? available_child_size - (size_t)child_header_size
                    : 0U;

            if (memcmp(child_type, "meta", 4) == 0) {
                child_initial_skip = 4U;
            }
            if (child_payload_size > child_initial_skip) {
                mov_collect_structure_flags_from_buffer(
                    buffer + cursor + (size_t)child_header_size,
                    child_payload_size,
                    child_initial_skip,
                    depth_remaining - 1U,
                    flags_out,
                    parsed_box_count_out
                );
            }
        }

        if (child_size > (uint64_t)(length - cursor)) {
            break;
        }
        cursor += (size_t)child_size;
    }
}

static int mov_probe_structure_flags(
    Reader *reader,
    size_t payload_offset,
    uint64_t payload_bytes,
    size_t initial_skip,
    uint32_t *flags_out,
    unsigned *parsed_box_count_out
)
{
    unsigned char probe[MOV_STRUCTURE_PROBE_BYTES];
    size_t probe_bytes;

    if (flags_out != NULL) {
        *flags_out = 0U;
    }
    if (parsed_box_count_out != NULL) {
        *parsed_box_count_out = 0U;
    }
    if (reader == NULL || reader->buffer == NULL ||
        flags_out == NULL || parsed_box_count_out == NULL ||
        payload_bytes <= initial_skip ||
        payload_offset >= reader->bytes_in_buffer) {
        return 0;
    }

    probe_bytes = (size_t)payload_bytes;
    if (probe_bytes > sizeof(probe)) {
        probe_bytes = sizeof(probe);
    }
    if (probe_bytes > reader->bytes_in_buffer - payload_offset) {
        probe_bytes = reader->bytes_in_buffer - payload_offset;
    }
    if (probe_bytes <= initial_skip || probe_bytes < initial_skip + 8U) {
        return 0;
    }

    memcpy(probe, reader->buffer + payload_offset, probe_bytes);
    mov_collect_structure_flags_from_buffer(
        probe,
        probe_bytes,
        initial_skip,
        MOV_STRUCTURE_RECURSION_DEPTH,
        flags_out,
        parsed_box_count_out
    );
    return *parsed_box_count_out > 0U;
}

static int mov_meta_structure_flag_count(uint32_t flags)
{
    int count = 0;

    if ((flags & MOV_FLAG_HDLR) != 0U) {
        count++;
    }
    if ((flags & MOV_FLAG_IINF) != 0U) {
        count++;
    }
    if ((flags & MOV_FLAG_ILOC) != 0U) {
        count++;
    }
    if ((flags & MOV_FLAG_PITM) != 0U) {
        count++;
    }
    if ((flags & MOV_FLAG_IPRP) != 0U) {
        count++;
    }
    if ((flags & MOV_FLAG_IPCO) != 0U) {
        count++;
    }

    return count;
}

static int mov_moov_structure_is_strong(
    uint32_t flags,
    unsigned parsed_box_count,
    char *reason_out,
    size_t reason_out_size
)
{
    int has_mvhd = (flags & MOV_FLAG_MVHD) != 0U;
    int has_trak = (flags & MOV_FLAG_TRAK) != 0U;
    int has_mdia = (flags & MOV_FLAG_MDIA) != 0U;
    int has_stbl = (flags & MOV_FLAG_STBL) != 0U;

    if (reason_out != NULL && reason_out_size > 0U) {
        reason_out[0] = '\0';
    }
    if (parsed_box_count < 2U) {
        return 0;
    }
    if (has_mvhd && has_trak && (has_mdia || has_stbl)) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "moov child chain mvhd+trak+mdia/stbl");
        }
        return 1;
    }
    if (has_mvhd && has_trak && parsed_box_count >= 3U) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "moov child chain mvhd+trak");
        }
        return 1;
    }

    return 0;
}

static int mov_moof_structure_is_strong(
    uint32_t flags,
    unsigned parsed_box_count,
    char *reason_out,
    size_t reason_out_size
)
{
    int has_mfhd = (flags & MOV_FLAG_MFHD) != 0U;
    int has_traf = (flags & MOV_FLAG_TRAF) != 0U;
    int has_tfhd = (flags & MOV_FLAG_TFHD) != 0U;
    int has_trun = (flags & MOV_FLAG_TRUN) != 0U;

    if (reason_out != NULL && reason_out_size > 0U) {
        reason_out[0] = '\0';
    }
    if (parsed_box_count < 2U) {
        return 0;
    }
    if (has_mfhd && has_traf && (has_tfhd || has_trun)) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "moof child chain mfhd+traf+tfhd/trun");
        }
        return 1;
    }

    return 0;
}

static int mov_meta_structure_is_strong(
    uint32_t flags,
    unsigned parsed_box_count,
    char *reason_out,
    size_t reason_out_size
)
{
    int meta_flag_count = mov_meta_structure_flag_count(flags);
    int has_hdlr = (flags & MOV_FLAG_HDLR) != 0U;
    int has_locator = (flags & (MOV_FLAG_ILOC | MOV_FLAG_IINF | MOV_FLAG_PITM)) != 0U;

    if (reason_out != NULL && reason_out_size > 0U) {
        reason_out[0] = '\0';
    }
    if (parsed_box_count < 2U) {
        return 0;
    }
    if (has_hdlr && has_locator && meta_flag_count >= 2) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "meta child chain hdlr+iloc/iinf/pitm");
        }
        return 1;
    }
    if (has_hdlr && (flags & (MOV_FLAG_IPRP | MOV_FLAG_IPCO)) != 0U && meta_flag_count >= 2) {
        if (reason_out != NULL && reason_out_size > 0U) {
            snprintf(reason_out, reason_out_size, "meta child chain hdlr+iprp/ipco");
        }
        return 1;
    }

    return 0;
}

static void log_mov_low_confidence_cap_hit(
    size_t absolute_offset,
    const char *major_brand,
    int atom_count,
    uint64_t bytes_examined,
    uint64_t exploratory_cap_bytes
)
{
    log_info(
        "MOV/MP4 candidate at byte %zu stayed plausible on only low-confidence structure (brand=%4.4s atoms=%d) and hit the exploratory cap at %.1f MiB after %.1f MiB; moving on until stronger container structure proves it is real",
        absolute_offset,
        major_brand != NULL ? major_brand : "????",
        atom_count,
        (double)exploratory_cap_bytes / (1024.0 * 1024.0),
        (double)bytes_examined / (1024.0 * 1024.0)
    );
}

static void log_mov_confidence_gain(
    size_t absolute_offset,
    const char *major_brand,
    int atom_count,
    const char *reason
)
{
    log_info(
        "MOV/MP4 candidate at byte %zu gained strong confidence from %s (brand=%4.4s atoms=%d)",
        absolute_offset,
        reason != NULL ? reason : "strong container structure",
        major_brand != NULL ? major_brand : "????",
        atom_count
    );
}

static void log_mov_structure_reject(
    size_t absolute_offset,
    const char *major_brand,
    int atom_count,
    int image_brand,
    int has_media_payload,
    int saw_movie_metadata,
    int saw_fragment_metadata,
    int has_strong_movie_metadata,
    int has_strong_fragment_metadata,
    int has_strong_image_metadata
)
{
    const char *reason = "container structure stayed shallow";

    if (!has_media_payload) {
        reason = "no mdat payload was found";
    } else if (image_brand && !has_strong_image_metadata) {
        reason = "image-family metadata stayed shallow";
    } else if (!image_brand &&
               saw_fragment_metadata &&
               !has_strong_fragment_metadata &&
               !has_strong_movie_metadata) {
        reason = "fragment metadata stayed shallow";
    } else if (!image_brand &&
               saw_movie_metadata &&
               !has_strong_movie_metadata &&
               !has_strong_fragment_metadata) {
        reason = "movie metadata stayed shallow";
    } else if (!saw_movie_metadata && !saw_fragment_metadata) {
        reason = "no semantic metadata atoms were found";
    }

    log_info(
        "MOV/MP4 candidate at byte %zu was rejected because %s (brand=%4.4s atoms=%d)",
        absolute_offset,
        reason,
        major_brand != NULL ? major_brand : "????",
        atom_count
    );
}

static void report_mov_validation(
    const AppConfig *config,
    size_t absolute_offset,
    const char *extension,
    const char *status,
    const char *reason,
    uint64_t total_written,
    int atom_count,
    int has_media_payload,
    int has_movie_metadata,
    int has_fragment_metadata,
    int has_strong_movie_metadata,
    int has_strong_fragment_metadata,
    int has_strong_image_metadata
)
{
    CarvVideoValidationReport report;

    memset(&report, 0, sizeof(report));
    report.container = "mov_mp4";
    report.extension = extension != NULL && extension[0] != '\0' ? extension : "mov";
    report.status = status;
    report.reason = reason;
    report.offset = (uint64_t)absolute_offset;
    report.bytes = total_written;
    report.payload_bytes = has_media_payload ? total_written : 0U;
    report.units = atom_count > 0 ? (unsigned)atom_count : 0U;
    report.video_units = has_media_payload ? 1U : 0U;
    report.metadata_units =
        (has_movie_metadata ? 1U : 0U) +
        (has_fragment_metadata ? 1U : 0U) +
        (has_strong_movie_metadata ? 1U : 0U) +
        (has_strong_fragment_metadata ? 1U : 0U) +
        (has_strong_image_metadata ? 1U : 0U);
    video_validation_report_append(config, &report);
}

static void report_mov_finalize_validation(
    const MovOutputValidationContext *ctx,
    const MovFinalizeStats *stats,
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
    report.container = "mov_mp4";
    report.extension = ctx->extension[0] != '\0' ? ctx->extension : "mov";
    report.status = status;
    report.reason = reason;
    report.offset = (uint64_t)ctx->absolute_offset;
    report.bytes = ctx->total_written;
    report.units = ctx->atom_count > 0 ? (unsigned)ctx->atom_count : 0U;
    report.video_units = ctx->has_media_payload ? 1U : 0U;
    report.metadata_units =
        (ctx->has_movie_metadata ? 1U : 0U) +
        (ctx->has_fragment_metadata ? 1U : 0U) +
        (ctx->has_strong_movie_metadata ? 1U : 0U) +
        (ctx->has_strong_fragment_metadata ? 1U : 0U) +
        (ctx->has_strong_image_metadata ? 1U : 0U);
    report.table_status = table_status;
    if (stats != NULL) {
        report.payload_bytes = stats->mdat_bytes;
        report.units = stats->box_count;
        report.video_units = stats->video_tracks;
        report.audio_units = stats->audio_tracks;
        report.metadata_units =
            stats->mvhd_count +
            stats->mdhd_count +
            stats->hdlr_count +
            stats->stbl_count +
            stats->moof_count;
        report.duration_ms = stats->duration_ms;
        report.tracks = stats->trak_count;
        report.sample_entries =
            stats->sample_count > 0U
                ? stats->sample_count
                : stats->fragmented_sample_count;
        report.chunk_offsets = stats->chunk_offsets;
    } else {
        report.payload_bytes = ctx->has_media_payload ? ctx->total_written : 0U;
    }
    video_validation_report_append(ctx->config, &report);
}

static int mov_output_finalize_validator(const char *path, void *opaque)
{
    MovOutputValidationContext *ctx = (MovOutputValidationContext *)opaque;
    MovFinalizeStats stats;
    char reason[160];
    char table_status[80];
    const char *status;
    int hard_reject = 0;

    if (ctx == NULL) {
        return 1;
    }

    if (!mov_finalize_collect_stats(path, &stats, ctx->progress_guard)) {
        if (ctx->progress_guard != NULL && ctx->progress_guard->cancelled) {
            return 0;
        }
        if (ctx->progress_guard != NULL && ctx->progress_guard->timed_out) {
            snprintf(
                reason,
                sizeof(reason),
                "finalize parser made no progress for %.0f seconds",
                ctx->progress_guard->timeout_seconds
            );
            snprintf(table_status, sizeof(table_status), "candidate_watchdog_timeout");
            report_mov_finalize_validation(
                ctx,
                NULL,
                "rejected",
                reason,
                table_status
            );
            log_info(
                "MOV/MP4 candidate at byte %zu was abandoned by its validator watchdog after %.0f seconds without parser progress",
                ctx->absolute_offset,
                ctx->progress_guard->timeout_seconds
            );
            return 0;
        }
        snprintf(
            reason,
            sizeof(reason),
            "finalize parser could not reopen or parse the completed candidate"
        );
        snprintf(table_status, sizeof(table_status), "finalize_parse_failed");
        report_mov_finalize_validation(
            ctx,
            NULL,
            "accepted_suspicious",
            reason,
            table_status
        );
        return 1;
    }

    status = mov_finalize_decide(
        &stats,
        ctx->image_brand,
        reason,
        sizeof(reason),
        table_status,
        sizeof(table_status),
        &hard_reject
    );
    report_mov_finalize_validation(ctx, &stats, status, reason, table_status);

    if (hard_reject) {
        log_info(
            "MOV/MP4 candidate at byte %zu rejected after finalize validation: %s (table=%s duration_ms=%llu samples=%llu chunks=%llu)",
            ctx->absolute_offset,
            reason,
            table_status,
            (unsigned long long)stats.duration_ms,
            (unsigned long long)(stats.sample_count > 0U ? stats.sample_count : stats.fragmented_sample_count),
            (unsigned long long)stats.chunk_offsets
        );
        return 0;
    }
    if (strcmp(status, "accepted_suspicious") == 0) {
        log_info(
            "MOV/MP4 candidate at byte %zu kept with finalize caution: %s (table=%s duration_ms=%llu samples=%llu chunks=%llu)",
            ctx->absolute_offset,
            reason,
            table_status,
            (unsigned long long)stats.duration_ms,
            (unsigned long long)(stats.sample_count > 0U ? stats.sample_count : stats.fragmented_sample_count),
            (unsigned long long)stats.chunk_offsets
        );
    }

    return 1;
}

/* ========================= MAIN ========================= */

int carver_mov_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    unsigned char header[16];
    char atom_type[5];
    char major_brand[5];
    const char *output_extension;
    CarverOutput output = {0};

    FILE *output_file = NULL;
    size_t current_offset;
    size_t write_offset;
    size_t last_resume;

    uint64_t total_written = 0;
    uint64_t effective_file_cap = mov_budget_adjusted_file_cap();
    uint64_t exploratory_cap_bytes = mov_budget_adjusted_exploratory_cap();
    int atom_count = 0;
    int has_media_payload = 0;
    int has_movie_metadata = 0;
    int has_fragment_metadata = 0;
    int has_strong_movie_metadata = 0;
    int has_strong_fragment_metadata = 0;
    int has_strong_image_metadata = 0;
    int high_confidence = 0;
    int image_brand = 0;
    char metadata_reason[96];
    char trailing_child_reason[32];
    MovCandidateProgressGuard progress_guard;

    metadata_reason[0] = '\0';
    trailing_child_reason[0] = '\0';
    mov_reset_last_audit();
    mov_progress_guard_init(&progress_guard);

    if (reader == NULL || reader->buffer == NULL || resume_offset == NULL) {
        log_error("MOV carver: invalid input pointers");
        mov_set_last_audit("rejected", "invalid_input", 0U);
        return 0;
    }

    *resume_offset = start_offset;

    if (!read_atom_header(reader, start_offset, header, &progress_guard)) {
        if (progress_guard.timed_out) {
            log_info(
                "MOV/MP4 candidate at byte %zu was abandoned after %.0f seconds without source/parser progress",
                absolute_offset,
                progress_guard.timeout_seconds
            );
            mov_set_last_audit("rejected", "candidate_watchdog_timeout", 0U);
            return 0;
        }
        mov_set_last_audit("rejected", "could_not_read_atom_header", 0U);
        return 0;
    }

    if (read_u32_be(header) < MOV_MIN_ATOM_SIZE) {
        mov_set_last_audit("rejected", "first_atom_too_small", 0U);
        return 0;
    }

    copy_fourcc(atom_type, header + 4);
    if (memcmp(atom_type, "ftyp", 4) != 0) {
        mov_set_last_audit("rejected", "first_atom_not_ftyp", 0U);
        return 0;
    }

    copy_fourcc(major_brand, header + 8);
    if (!is_known_mov_brand(major_brand)) {
        mov_set_last_audit("rejected", "unknown_brand", 0U);
        return 0;
    }
    image_brand = mov_brand_is_image_family(major_brand);
    output_extension = extension_from_brand(major_brand);

/*     log_info(
        "MOV candidate at offset %zu: first_atom=%s major_brand=%s",
        absolute_offset,
        atom_type,
        major_brand
    ); */

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            output_extension)) {
        log_error("MOV carver: failed to prepare output");
        mov_set_last_audit("rejected", "output_prepare_failed", 0U);
        return 0;
    }

    output_file = output.file;
    current_offset = start_offset;
    write_offset = start_offset;
    last_resume = start_offset;

    while (1) {
        uint64_t atom_size;
        uint64_t atom_header_size = 8;

        if (mov_progress_guard_should_abort(&progress_guard)) {
            if (progress_guard.timed_out) {
                log_info(
                    "MOV/MP4 candidate at byte %zu was abandoned after %.0f seconds without source/parser progress (written=%.1f MiB atoms=%d)",
                    absolute_offset,
                    progress_guard.timeout_seconds,
                    (double)total_written / (1024.0 * 1024.0),
                    atom_count
                );
                mov_set_last_audit(
                    "rejected",
                    "candidate_watchdog_timeout",
                    total_written
                );
            }
            goto candidate_abort;
        }
        if (!read_atom_header(reader, current_offset, header, &progress_guard)) {
            if (progress_guard.timed_out) {
                log_info(
                    "MOV/MP4 candidate at byte %zu was abandoned after %.0f seconds without source/parser progress while reading an atom header",
                    absolute_offset,
                    progress_guard.timeout_seconds
                );
                mov_set_last_audit(
                    "rejected",
                    "candidate_watchdog_timeout",
                    total_written
                );
                goto candidate_abort;
            }
            mov_copy_audit_text(
                trailing_child_reason,
                sizeof(trailing_child_reason),
                "mov_after_last_atom",
                "");
            break;
        }

        atom_size = read_u32_be(header);
        copy_fourcc(atom_type, header + 4);

        if (atom_size == 1) {
            atom_size = read_u64_be(header + 8);
            atom_header_size = 16;
        }

        if (!is_likely_printable_fourcc(atom_type)) {
            mov_copy_audit_text(
                trailing_child_reason,
                sizeof(trailing_child_reason),
                "mov_trailing_non_atom",
                "");
            break;
        }

        if (!is_known_top_level_atom(atom_type)) {
            mov_copy_audit_text(
                trailing_child_reason,
                sizeof(trailing_child_reason),
                "mov_unknown_top_level_atom",
                "");
            break;
        }

        if (!high_confidence &&
            total_written + atom_size > exploratory_cap_bytes) {
            log_mov_low_confidence_cap_hit(
                absolute_offset,
                major_brand,
                atom_count,
                total_written + atom_size,
                exploratory_cap_bytes
            );
            mov_copy_audit_text(
                trailing_child_reason,
                sizeof(trailing_child_reason),
                "mov_low_confidence_cap",
                "");
            break;
        }

        if (atom_size == 0 ||
            atom_size < atom_header_size ||
            atom_size > MOV_MAX_REASONABLE_ATOM_SIZE ||
            total_written + atom_size > effective_file_cap) {
            mov_copy_audit_text(
                trailing_child_reason,
                sizeof(trailing_child_reason),
                total_written + atom_size > effective_file_cap
                    ? "mov_file_cap"
                    : "mov_invalid_atom_size",
                "");
            if (total_written + atom_size > effective_file_cap) {
                log_info(
                    "MOV candidate at byte %zu was capped at %.1f MiB (budget=%s); treating it as misleadingly large and moving on",
                    absolute_offset,
                    (double)effective_file_cap / (1024.0 * 1024.0),
                    log_trouble_budget_state_label(log_get_trouble_budget_state())
                );
            }
            break;
        }

        if (memcmp(atom_type, "moov", 4) == 0 ||
            memcmp(atom_type, "meta", 4) == 0) {
            uint32_t structure_flags = 0U;
            unsigned parsed_box_count = 0U;
            char structure_reason[64];

            has_movie_metadata = 1;
            structure_reason[0] = '\0';
            if (mov_probe_structure_flags(
                    reader,
                    current_offset + (size_t)atom_header_size,
                    atom_size - atom_header_size,
                    memcmp(atom_type, "meta", 4) == 0 ? 4U : 0U,
                    &structure_flags,
                    &parsed_box_count)) {
                if (memcmp(atom_type, "moov", 4) == 0 &&
                    mov_moov_structure_is_strong(
                        structure_flags,
                        parsed_box_count,
                        structure_reason,
                        sizeof(structure_reason))) {
                    has_strong_movie_metadata = 1;
                    if (metadata_reason[0] == '\0') {
                        snprintf(metadata_reason, sizeof(metadata_reason), "%s", structure_reason);
                    }
                } else if (memcmp(atom_type, "meta", 4) == 0 &&
                           image_brand &&
                           mov_meta_structure_is_strong(
                               structure_flags,
                               parsed_box_count,
                               structure_reason,
                               sizeof(structure_reason))) {
                    has_strong_image_metadata = 1;
                    if (metadata_reason[0] == '\0') {
                        snprintf(metadata_reason, sizeof(metadata_reason), "%s", structure_reason);
                    }
                }
            }
        }

        if (memcmp(atom_type, "moof", 4) == 0) {
            uint32_t structure_flags = 0U;
            unsigned parsed_box_count = 0U;
            char structure_reason[64];

            has_fragment_metadata = 1;
            structure_reason[0] = '\0';
            if (mov_probe_structure_flags(
                    reader,
                    current_offset + (size_t)atom_header_size,
                    atom_size - atom_header_size,
                    0U,
                    &structure_flags,
                    &parsed_box_count) &&
                mov_moof_structure_is_strong(
                    structure_flags,
                    parsed_box_count,
                    structure_reason,
                    sizeof(structure_reason))) {
                has_strong_fragment_metadata = 1;
                if (metadata_reason[0] == '\0') {
                    snprintf(metadata_reason, sizeof(metadata_reason), "%s", structure_reason);
                }
            }
        }

        if (memcmp(atom_type, "mdat", 4) == 0) {
            has_media_payload = 1;
        }

        if (!high_confidence) {
            int next_high_confidence = 0;

            if (image_brand) {
                next_high_confidence = has_media_payload && has_strong_image_metadata;
            } else {
                next_high_confidence = has_media_payload &&
                    (has_strong_movie_metadata || has_strong_fragment_metadata);
            }
            if (next_high_confidence) {
                char confidence_reason[128];

                if (metadata_reason[0] != '\0') {
                    snprintf(
                        confidence_reason,
                        sizeof(confidence_reason),
                        "mdat payload plus %s",
                        metadata_reason
                    );
                } else {
                    snprintf(
                        confidence_reason,
                        sizeof(confidence_reason),
                        "mdat payload plus strong container structure"
                    );
                }
                log_mov_confidence_gain(
                    absolute_offset,
                    major_brand,
                    atom_count + 1,
                    confidence_reason
                );
                high_confidence = 1;
            }
        }

        {
            uint64_t remaining = atom_size;

            while (remaining > 0) {
                size_t available;

                if (mov_progress_guard_should_abort(&progress_guard)) {
                    if (progress_guard.timed_out) {
                        log_info(
                            "MOV/MP4 candidate at byte %zu was abandoned after %.0f seconds without streaming progress (written=%.1f MiB atoms=%d)",
                            absolute_offset,
                            progress_guard.timeout_seconds,
                            (double)total_written / (1024.0 * 1024.0),
                            atom_count
                        );
                        mov_set_last_audit(
                            "rejected",
                            "candidate_watchdog_timeout",
                            total_written
                        );
                    }
                    goto candidate_abort;
                }
                if (write_offset >= reader->bytes_in_buffer) {
                    if (reader_read_next(reader) == 0) {
                        log_error("MOV carver: EOF while streaming atom %d", atom_count);
                        goto done;
                    }

                    write_offset = reader->overlap_bytes;
                    mov_progress_guard_touch(
                        &progress_guard,
                        (uint64_t)reader->total_bytes_read
                    );
                }

                available = reader->bytes_in_buffer - write_offset;
                if (available > remaining) {
                    available = (size_t)remaining;
                }

                if (fwrite(reader->buffer + write_offset, 1, available, output_file) != available) {
                    log_error("MOV carver: fwrite failed");
                    goto done;
                }

                write_offset += available;
                remaining -= available;
                total_written += available;
                mov_progress_guard_touch(&progress_guard, total_written);
            }
        }

        current_offset = write_offset;
        last_resume = write_offset;
        atom_count++;
    }

done:
    if (atom_count == 0 || total_written == 0) {
        carver_output_abort(&output);
        mov_set_last_audit("rejected", "no_complete_atoms", total_written);
        return 0;
    }

    if (!has_media_payload ||
        (image_brand && !has_strong_image_metadata) ||
        (!image_brand && !(has_strong_movie_metadata || has_strong_fragment_metadata))) {
        const char *reject_reason = "container structure stayed shallow";
        int should_try_finalize_validation =
            !image_brand &&
            has_media_payload &&
            (has_movie_metadata || has_fragment_metadata);
        if (!has_media_payload) {
            reject_reason = "no mdat payload was found";
        } else if (image_brand && !has_strong_image_metadata) {
            reject_reason = "image-family metadata stayed shallow";
        } else if (!image_brand &&
                   has_fragment_metadata &&
                   !has_strong_fragment_metadata &&
                   !has_strong_movie_metadata) {
            reject_reason = "fragment metadata stayed shallow";
        } else if (!image_brand &&
                   has_movie_metadata &&
                   !has_strong_movie_metadata &&
                   !has_strong_fragment_metadata) {
            reject_reason = "movie metadata stayed shallow";
        } else if (!has_movie_metadata && !has_fragment_metadata) {
            reject_reason = "no semantic metadata atoms were found";
        }

        if (should_try_finalize_validation) {
            MovOutputValidationContext validation_ctx;
            MovCandidateProgressGuard finalize_guard;

            memset(&validation_ctx, 0, sizeof(validation_ctx));
            mov_progress_guard_init(&finalize_guard);
            validation_ctx.config = config;
            validation_ctx.absolute_offset = absolute_offset;
            snprintf(
                validation_ctx.extension,
                sizeof(validation_ctx.extension),
                "%s",
                output_extension != NULL ? output_extension : "mov"
            );
            validation_ctx.total_written = total_written;
            validation_ctx.atom_count = atom_count;
            validation_ctx.image_brand = image_brand;
            validation_ctx.has_media_payload = has_media_payload;
            validation_ctx.has_movie_metadata = has_movie_metadata;
            validation_ctx.has_fragment_metadata = has_fragment_metadata;
            validation_ctx.has_strong_movie_metadata = has_strong_movie_metadata;
            validation_ctx.has_strong_fragment_metadata = has_strong_fragment_metadata;
            validation_ctx.has_strong_image_metadata = has_strong_image_metadata;
            validation_ctx.progress_guard = &finalize_guard;
            snprintf(
                validation_ctx.structural_reason,
                sizeof(validation_ctx.structural_reason),
                "%s",
                metadata_reason[0] != '\0'
                    ? metadata_reason
                    : reject_reason
            );
            if (!carver_output_finish_validated(
                    &output,
                    mov_output_finalize_validator,
                    &validation_ctx)) {
                mov_set_last_audit(
                    "rejected",
                    "finalize_validation_rejected_or_write_failed",
                    total_written);
                return 0;
            }
            *resume_offset = last_resume;
            mov_set_last_audit("recovered", validation_ctx.structural_reason, total_written);
            mov_set_last_audit_trailing_reason(
                trailing_child_reason[0] != '\0'
                    ? trailing_child_reason
                    : "mov_after_last_atom");
            return 1;
        }

        log_mov_structure_reject(
            absolute_offset,
            major_brand,
            atom_count,
            image_brand,
            has_media_payload,
            has_movie_metadata,
            has_fragment_metadata,
            has_strong_movie_metadata,
            has_strong_fragment_metadata,
            has_strong_image_metadata
        );
        report_mov_validation(
            config,
            absolute_offset,
            output_extension,
            "rejected",
            reject_reason,
            total_written,
            atom_count,
            has_media_payload,
            has_movie_metadata,
            has_fragment_metadata,
            has_strong_movie_metadata,
            has_strong_fragment_metadata,
            has_strong_image_metadata);
        carver_output_abort(&output);
        mov_set_last_audit("rejected", reject_reason, total_written);
        return 0;
    }

    {
        MovOutputValidationContext validation_ctx;
        MovCandidateProgressGuard finalize_guard;

        memset(&validation_ctx, 0, sizeof(validation_ctx));
        mov_progress_guard_init(&finalize_guard);
        validation_ctx.config = config;
        validation_ctx.absolute_offset = absolute_offset;
        snprintf(
            validation_ctx.extension,
            sizeof(validation_ctx.extension),
            "%s",
            output_extension != NULL ? output_extension : "mov"
        );
        validation_ctx.total_written = total_written;
        validation_ctx.atom_count = atom_count;
        validation_ctx.image_brand = image_brand;
        validation_ctx.has_media_payload = has_media_payload;
        validation_ctx.has_movie_metadata = has_movie_metadata;
        validation_ctx.has_fragment_metadata = has_fragment_metadata;
        validation_ctx.has_strong_movie_metadata = has_strong_movie_metadata;
        validation_ctx.has_strong_fragment_metadata = has_strong_fragment_metadata;
        validation_ctx.has_strong_image_metadata = has_strong_image_metadata;
        validation_ctx.progress_guard = &finalize_guard;
        snprintf(
            validation_ctx.structural_reason,
            sizeof(validation_ctx.structural_reason),
            "%s",
            metadata_reason[0] != '\0'
                ? metadata_reason
                : "mdat plus strong container structure"
        );
        if (!carver_output_finish_validated(
                &output,
                mov_output_finalize_validator,
                &validation_ctx)) {
            mov_set_last_audit(
                "rejected",
                "finalize_validation_rejected_or_write_failed",
                total_written);
            return 0;
        }
        mov_set_last_audit("recovered", validation_ctx.structural_reason, total_written);
        mov_set_last_audit_trailing_reason(
            trailing_child_reason[0] != '\0'
                ? trailing_child_reason
                : "mov_after_last_atom");
    }

    *resume_offset = last_resume;
    return 1;

candidate_abort:
    carver_output_abort(&output);
    return 0;
}
