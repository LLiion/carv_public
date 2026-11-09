#include "carver_raw.h"

#include "carver_output.h"
#include "log.h"
#include "matcher.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define RAW_TIFF_MIN_FILE_SIZE 1024U
#define RAW_TIFF_MAX_IFD_VISITS 128U
#define RAW_TIFF_INITIAL_META_BYTES (1024U * 1024U)
#define RAW_TIFF_MAX_META_BYTES (64U * 1024U * 1024U)
#define RAW_TIFF_BOUNDARY_SCAN_CHUNK (1024U * 1024U)
#define RAW_TIFF_BOUNDARY_SCAN_OVERLAP 64U
#define RAW_TIFF_BOUNDARY_SCAN_MAX_BYTES (512ULL * 1024ULL * 1024ULL)
#define RAW_TIFF_BOUNDARY_MIN_PAYLOAD_BYTES (1024ULL * 1024ULL)
#define RAW_TIFF_BOUNDARY_ALIGNMENT 512ULL
#define RAW_MAX_REASONABLE_FILE_SIZE (2ULL * 1024ULL * 1024ULL * 1024ULL)
#define RAW_RAF_HEADER_BYTES 108U
#define RAW_CRW_HEADER_MIN_BYTES 26U
#define RAW_CRW_MIN_VALID_SPAN (1024ULL * 1024ULL)
#define RAW_CRW_BOUNDARY_SCAN_MAX_BYTES (1024ULL * 1024ULL * 1024ULL)
#define RAW_CRW_BOUNDARY_TRIM_MAX_BYTES (8ULL * 1024ULL)
#define RAW_CRW_DIR_MAX_ENTRIES 4096U
#define RAW_CR3_MAX_BOXES 8192U

typedef enum {
    RAW_TIFF_PARSE_INVALID = 0,
    RAW_TIFF_PARSE_OK = 1,
    RAW_TIFF_PARSE_NEED_MORE = 2
} RawTiffParseStatus;

typedef enum {
    RAW_TIFF_ENDIAN_LITTLE = 0,
    RAW_TIFF_ENDIAN_BIG = 1
} RawTiffEndian;

typedef enum {
    RAW_TIFF_KIND_CLASSIC = 0,
    RAW_TIFF_KIND_BIG = 1
} RawTiffKind;

typedef struct {
    const uint8_t *data;
    uint16_t type;
    uint64_t count;
} RawTiffValueArray;

typedef struct {
    const uint8_t *buffer;
    size_t length;
    RawTiffEndian endian;
    RawTiffKind kind;
    uint16_t version;
    size_t visited_ifd_offsets[RAW_TIFF_MAX_IFD_VISITS];
    size_t visited_ifd_count;
    uint64_t needed_end;
    uint64_t max_end;
    uint64_t max_width;
    uint64_t max_height;
    uint64_t raw_data_offset;
    int saw_ifd;
    int saw_image_payload;
    int saw_raw_indicator;
    int saw_dng;
    int saw_cr2;
    int saw_orf;
    int saw_rw2;
    char make[64];
    char model[96];
    char unique_model[96];
    char extension[8];
} RawTiffContext;

static CarverAuditReport g_raw_last_audit;

static int raw_ascii_contains_ci(const char *haystack, const char *needle);

void carver_raw_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_raw_last_audit);
}

void carver_raw_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_raw_last_audit;
}

static uint64_t reader_buffer_base_absolute(const Reader *reader)
{
    if (reader == NULL ||
        (uint64_t)reader->bytes_in_buffer > (uint64_t)reader->total_bytes_read) {
        return 0U;
    }
    return (uint64_t)reader->total_bytes_read - (uint64_t)reader->bytes_in_buffer;
}

static int read_stream_bytes(
    Reader *reader,
    uint64_t start_abs,
    uint8_t *dst,
    size_t byte_count
)
{
    uint64_t current_abs = start_abs;
    size_t copied = 0U;

    if (reader == NULL || dst == NULL) {
        return 0;
    }

    while (copied < byte_count) {
        uint64_t base_abs;
        size_t buffer_offset;
        size_t available;
        size_t copy_now;

        base_abs = reader_buffer_base_absolute(reader);
        if (current_abs < base_abs) {
            return 0;
        }

        while (current_abs >= base_abs + (uint64_t)reader->bytes_in_buffer) {
            if (reader_read_next(reader) == 0U) {
                return 0;
            }
            base_abs = reader_buffer_base_absolute(reader);
            if (current_abs < base_abs) {
                return 0;
            }
        }

        buffer_offset = (size_t)(current_abs - base_abs);
        available = reader->bytes_in_buffer - buffer_offset;
        copy_now = available;
        if (copy_now > byte_count - copied) {
            copy_now = byte_count - copied;
        }

        memcpy(dst + copied, reader->buffer + buffer_offset, copy_now);
        current_abs += (uint64_t)copy_now;
        copied += copy_now;
    }

    return 1;
}

static int copy_stream_bytes(
    Reader *reader,
    FILE *output_file,
    uint64_t start_abs,
    uint64_t byte_count
)
{
    uint64_t current_abs = start_abs;
    uint64_t remaining = byte_count;

    if (reader == NULL || output_file == NULL) {
        return 0;
    }

    while (remaining > 0U) {
        uint64_t base_abs;
        size_t buffer_offset;
        size_t available;
        size_t write_now;

        base_abs = reader_buffer_base_absolute(reader);
        if (current_abs < base_abs) {
            return 0;
        }

        while (current_abs >= base_abs + (uint64_t)reader->bytes_in_buffer) {
            if (reader_read_next(reader) == 0U) {
                return 0;
            }
            base_abs = reader_buffer_base_absolute(reader);
            if (current_abs < base_abs) {
                return 0;
            }
        }

        buffer_offset = (size_t)(current_abs - base_abs);
        available = reader->bytes_in_buffer - buffer_offset;
        write_now = available;
        if ((uint64_t)write_now > remaining) {
            write_now = (size_t)remaining;
        }

        if (fwrite(reader->buffer + buffer_offset, 1U, write_now, output_file) != write_now) {
            return 0;
        }

        current_abs += (uint64_t)write_now;
        remaining -= (uint64_t)write_now;
    }

    return 1;
}

static int compute_resume_offset_local(
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

    base_abs = reader_buffer_base_absolute(reader);
    if (resume_abs < base_abs) {
        *resume_offset_out = fallback_offset + 1U;
        return 1;
    }
    if (resume_abs >= base_abs + (uint64_t)reader->bytes_in_buffer) {
        *resume_offset_out = reader->bytes_in_buffer;
        return 1;
    }

    *resume_offset_out = (size_t)(resume_abs - base_abs);
    return 1;
}

static uint16_t read_u16_le(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t read_u32_le(const uint8_t *data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *data)
{
    uint64_t value = 0U;
    size_t i;

    for (i = 0U; i < 8U; i++) {
        value |= (uint64_t)data[i] << (i * 8U);
    }
    return value;
}

static uint16_t read_u16_be(const uint8_t *data)
{
    return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}

static uint32_t read_u32_be(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static uint64_t read_u64_be(const uint8_t *data)
{
    uint64_t value = 0U;
    size_t i;

    for (i = 0U; i < 8U; i++) {
        value = (value << 8) | (uint64_t)data[i];
    }
    return value;
}

static uint16_t raw_tiff_read_u16(const uint8_t *data, RawTiffEndian endian)
{
    return endian == RAW_TIFF_ENDIAN_LITTLE ? read_u16_le(data) : read_u16_be(data);
}

static uint32_t raw_tiff_read_u32(const uint8_t *data, RawTiffEndian endian)
{
    return endian == RAW_TIFF_ENDIAN_LITTLE ? read_u32_le(data) : read_u32_be(data);
}

static uint64_t raw_tiff_read_u64(const uint8_t *data, RawTiffEndian endian)
{
    return endian == RAW_TIFF_ENDIAN_LITTLE ? read_u64_le(data) : read_u64_be(data);
}

static size_t raw_tiff_type_width(uint16_t type)
{
    switch (type) {
        case 1:
        case 2:
        case 6:
        case 7:
            return 1U;
        case 3:
        case 8:
            return 2U;
        case 4:
        case 9:
        case 11:
        case 13:
            return 4U;
        case 5:
        case 10:
        case 12:
        case 16:
        case 17:
        case 18:
            return 8U;
        default:
            return 0U;
    }
}

static int raw_tiff_mul_size(uint64_t count, size_t width, size_t *out)
{
    if (out == NULL) {
        return 0;
    }
    if (count == 0U || width == 0U) {
        *out = 0U;
        return 1;
    }
    if (count > (uint64_t)SIZE_MAX / (uint64_t)width) {
        return 0;
    }
    *out = (size_t)(count * (uint64_t)width);
    return 1;
}

static void raw_tiff_need(RawTiffContext *ctx, uint64_t end)
{
    if (ctx != NULL && end > ctx->needed_end) {
        ctx->needed_end = end;
    }
}

static RawTiffParseStatus raw_tiff_require(
    RawTiffContext *ctx,
    uint64_t offset,
    uint64_t length
)
{
    if (ctx == NULL) {
        return RAW_TIFF_PARSE_INVALID;
    }
    if (length == 0U) {
        return RAW_TIFF_PARSE_OK;
    }
    if (offset > RAW_MAX_REASONABLE_FILE_SIZE ||
        length > RAW_MAX_REASONABLE_FILE_SIZE - offset) {
        return RAW_TIFF_PARSE_INVALID;
    }
    if (offset + length > (uint64_t)ctx->length) {
        raw_tiff_need(ctx, offset + length);
        return RAW_TIFF_PARSE_NEED_MORE;
    }
    return RAW_TIFF_PARSE_OK;
}

static RawTiffParseStatus raw_tiff_note_region(
    RawTiffContext *ctx,
    uint64_t offset,
    uint64_t length
)
{
    if (ctx == NULL) {
        return RAW_TIFF_PARSE_INVALID;
    }
    if (length == 0U) {
        return RAW_TIFF_PARSE_OK;
    }
    if (offset > RAW_MAX_REASONABLE_FILE_SIZE ||
        length > RAW_MAX_REASONABLE_FILE_SIZE - offset) {
        return RAW_TIFF_PARSE_INVALID;
    }
    if (offset + length > ctx->max_end) {
        ctx->max_end = offset + length;
    }
    return RAW_TIFF_PARSE_OK;
}

static uint64_t raw_tiff_numeric_value(
    const uint8_t *data,
    uint16_t type,
    RawTiffEndian endian
)
{
    if (data == NULL) {
        return 0U;
    }

    switch (type) {
        case 1:
        case 2:
        case 6:
        case 7:
            return (uint64_t)data[0];
        case 3:
        case 8:
            return (uint64_t)raw_tiff_read_u16(data, endian);
        case 4:
        case 9:
        case 13:
            return (uint64_t)raw_tiff_read_u32(data, endian);
        case 16:
        case 17:
        case 18:
            return raw_tiff_read_u64(data, endian);
        default:
            return 0U;
    }
}

static size_t raw_tiff_numeric_stride(uint16_t type)
{
    size_t width = raw_tiff_type_width(type);

    if (type == 5U || type == 10U || type == 11U || type == 12U) {
        return 0U;
    }
    return width;
}

static int raw_tiff_array_value(
    const RawTiffContext *ctx,
    const RawTiffValueArray *array,
    size_t index,
    uint64_t *out
)
{
    size_t stride;

    if (out != NULL) {
        *out = 0U;
    }
    if (ctx == NULL || array == NULL || out == NULL ||
        array->data == NULL || index >= array->count) {
        return 0;
    }
    stride = raw_tiff_numeric_stride(array->type);
    if (stride == 0U) {
        return 0;
    }
    *out = raw_tiff_numeric_value(array->data + index * stride, array->type, ctx->endian);
    return 1;
}

static int raw_magic_type_contains_ci(const MagicEntry *match, const char *needle)
{
    if (match == NULL || needle == NULL || needle[0] == '\0') {
        return 0;
    }
    return raw_ascii_contains_ci(match->type, needle) ||
           raw_ascii_contains_ci(match->type_name, needle) ||
           raw_ascii_contains_ci(match->category, needle);
}

static int raw_tiff_magic_match_is_strong_boundary(const MagicEntry *match)
{
    const uint8_t *index_pattern;
    size_t index_length;

    if (match == NULL) {
        return 0;
    }
    index_pattern =
        match->start_pattern != NULL && match->start_pattern_length > 0U
            ? match->start_pattern
            : match->pattern;
    index_length =
        match->start_pattern != NULL && match->start_pattern_length > 0U
            ? match->start_pattern_length
            : match->pattern_length;
    if (index_pattern == NULL || index_length == 0U) {
        return 0;
    }
    if (match->pattern_length >= 4U || index_length >= 4U) {
        return 1;
    }
    if (raw_magic_type_contains_ci(match, "jpg") ||
        raw_magic_type_contains_ci(match, "jpeg")) {
        return 1;
    }
    return 0;
}

static int raw_tiff_find_next_strong_boundary(
    const Reader *reader,
    const MagicTable *table,
    uint64_t absolute_offset,
    uint64_t scan_start_span,
    uint64_t max_scan_span,
    uint64_t *boundary_span_out
)
{
    uint8_t *buffer;
    uint64_t source_end;
    uint64_t scan_abs;
    uint64_t scan_end;
    size_t chunk_capacity;
    ssize_t bytes_read;

    if (boundary_span_out != NULL) {
        *boundary_span_out = 0U;
    }
    if (reader == NULL ||
        table == NULL ||
        boundary_span_out == NULL ||
        reader->fd < 0 ||
        scan_start_span == 0U ||
        max_scan_span == 0U) {
        return 0;
    }
    if (reader->source_size > 0U) {
        if (absolute_offset >= reader->source_size) {
            return 0;
        }
        source_end = reader->source_size;
    } else {
        source_end = absolute_offset + max_scan_span;
    }
    if (scan_start_span > source_end - absolute_offset) {
        return 0;
    }
    scan_abs = absolute_offset + scan_start_span;
    scan_end = absolute_offset + max_scan_span;
    if (scan_end < absolute_offset || scan_end > source_end) {
        scan_end = source_end;
    }
    if (scan_abs >= scan_end) {
        return 0;
    }

    chunk_capacity = RAW_TIFF_BOUNDARY_SCAN_CHUNK + RAW_TIFF_BOUNDARY_SCAN_OVERLAP;
    buffer = (uint8_t *)malloc(chunk_capacity);
    if (buffer == NULL) {
        return 0;
    }
    while (scan_abs < scan_end) {
        size_t request = RAW_TIFF_BOUNDARY_SCAN_CHUNK;
        size_t i;

        if ((uint64_t)request > scan_end - scan_abs) {
            request = (size_t)(scan_end - scan_abs);
        }
        if (request == 0U) {
            break;
        }
        bytes_read = pread(reader->fd, buffer, request, (off_t)scan_abs);
        if (bytes_read <= 0) {
            break;
        }
        for (i = 0U; i < (size_t)bytes_read; i++) {
            uint64_t candidate_abs = scan_abs + (uint64_t)i;
            const MagicEntry *match;

            if ((candidate_abs % RAW_TIFF_BOUNDARY_ALIGNMENT) != 0U) {
                continue;
            }
            match = matcher_match_at(table, buffer, (size_t)bytes_read, i);
            if (!raw_tiff_magic_match_is_strong_boundary(match)) {
                continue;
            }
            if (candidate_abs <= absolute_offset) {
                continue;
            }
            *boundary_span_out = candidate_abs - absolute_offset;
            free(buffer);
            return 1;
        }
        if ((size_t)bytes_read < request) {
            break;
        }
        scan_abs += (uint64_t)bytes_read;
    }
    free(buffer);
    return 0;
}

static RawTiffParseStatus raw_tiff_entry_value_ptr(
    RawTiffContext *ctx,
    const uint8_t *entry,
    uint16_t type,
    uint64_t count,
    const uint8_t **data_out,
    size_t *data_size_out,
    size_t *inline_capacity_out
)
{
    size_t value_size;
    size_t inline_capacity;
    size_t value_field_offset;
    uint64_t value_offset;
    RawTiffParseStatus status;

    if (data_out != NULL) {
        *data_out = NULL;
    }
    if (data_size_out != NULL) {
        *data_size_out = 0U;
    }
    if (inline_capacity_out != NULL) {
        *inline_capacity_out = 0U;
    }
    if (ctx == NULL || entry == NULL || data_out == NULL || data_size_out == NULL) {
        return RAW_TIFF_PARSE_INVALID;
    }
    if (!raw_tiff_mul_size(count, raw_tiff_type_width(type), &value_size)) {
        return RAW_TIFF_PARSE_INVALID;
    }

    inline_capacity = ctx->kind == RAW_TIFF_KIND_BIG ? 8U : 4U;
    value_field_offset = ctx->kind == RAW_TIFF_KIND_BIG ? 12U : 8U;
    if (inline_capacity_out != NULL) {
        *inline_capacity_out = inline_capacity;
    }

    if (value_size <= inline_capacity) {
        *data_out = entry + value_field_offset;
        *data_size_out = value_size;
        return RAW_TIFF_PARSE_OK;
    }

    value_offset = ctx->kind == RAW_TIFF_KIND_BIG
        ? raw_tiff_read_u64(entry + value_field_offset, ctx->endian)
        : (uint64_t)raw_tiff_read_u32(entry + value_field_offset, ctx->endian);

    status = raw_tiff_require(ctx, value_offset, (uint64_t)value_size);
    if (status != RAW_TIFF_PARSE_OK) {
        return status;
    }

    *data_out = ctx->buffer + (size_t)value_offset;
    *data_size_out = value_size;
    return RAW_TIFF_PARSE_OK;
}

static int raw_ascii_contains_ci(const char *haystack, const char *needle)
{
    size_t i;
    size_t j;
    size_t hay_len;
    size_t needle_len;

    if (haystack == NULL || needle == NULL || needle[0] == '\0') {
        return 0;
    }
    hay_len = strlen(haystack);
    needle_len = strlen(needle);
    if (needle_len > hay_len) {
        return 0;
    }
    for (i = 0U; i + needle_len <= hay_len; i++) {
        for (j = 0U; j < needle_len; j++) {
            unsigned char a = (unsigned char)haystack[i + j];
            unsigned char b = (unsigned char)needle[j];
            if (a >= 'A' && a <= 'Z') {
                a = (unsigned char)(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = (unsigned char)(b - 'A' + 'a');
            }
            if (a != b) {
                break;
            }
        }
        if (j == needle_len) {
            return 1;
        }
    }
    return 0;
}

static void raw_tiff_copy_ascii(char *out, size_t out_size, const uint8_t *data, size_t size)
{
    size_t i;
    size_t write_pos = 0U;

    if (out == NULL || out_size == 0U || data == NULL || size == 0U) {
        return;
    }
    if (out[0] != '\0') {
        return;
    }
    for (i = 0U; i < size && write_pos + 1U < out_size; i++) {
        unsigned char ch = data[i];
        if (ch == '\0') {
            if (write_pos > 0U) {
                break;
            }
            continue;
        }
        if (ch >= 32U && ch < 127U) {
            out[write_pos++] = (char)ch;
        }
    }
    out[write_pos] = '\0';
}

static int raw_tiff_ifd_already_visited(const RawTiffContext *ctx, size_t ifd_offset)
{
    size_t i;

    if (ctx == NULL) {
        return 0;
    }
    for (i = 0U; i < ctx->visited_ifd_count; i++) {
        if (ctx->visited_ifd_offsets[i] == ifd_offset) {
            return 1;
        }
    }
    return 0;
}

static int raw_tiff_mark_ifd_visited(RawTiffContext *ctx, size_t ifd_offset)
{
    if (ctx == NULL) {
        return 0;
    }
    if (raw_tiff_ifd_already_visited(ctx, ifd_offset)) {
        return 1;
    }
    if (ctx->visited_ifd_count >= RAW_TIFF_MAX_IFD_VISITS) {
        return 0;
    }
    ctx->visited_ifd_offsets[ctx->visited_ifd_count++] = ifd_offset;
    return 1;
}

static RawTiffParseStatus raw_tiff_parse_ifd(RawTiffContext *ctx, size_t ifd_offset);

static RawTiffParseStatus raw_tiff_parse_subifds(
    RawTiffContext *ctx,
    const RawTiffValueArray *array
)
{
    size_t i;

    if (ctx == NULL || array == NULL) {
        return RAW_TIFF_PARSE_INVALID;
    }
    for (i = 0U; i < array->count; i++) {
        uint64_t child = 0U;
        RawTiffParseStatus status;

        if (!raw_tiff_array_value(ctx, array, i, &child)) {
            return RAW_TIFF_PARSE_INVALID;
        }
        if (child == 0U) {
            continue;
        }
        status = raw_tiff_parse_ifd(ctx, (size_t)child);
        if (status != RAW_TIFF_PARSE_OK) {
            return status;
        }
    }
    return RAW_TIFF_PARSE_OK;
}

static RawTiffParseStatus raw_tiff_note_image_ranges(
    RawTiffContext *ctx,
    const RawTiffValueArray *offsets,
    const RawTiffValueArray *byte_counts
)
{
    size_t count;
    size_t i;

    if (ctx == NULL || offsets == NULL || byte_counts == NULL) {
        return RAW_TIFF_PARSE_OK;
    }
    if (offsets->data == NULL || byte_counts->data == NULL) {
        return RAW_TIFF_PARSE_OK;
    }

    count = offsets->count < byte_counts->count
        ? (size_t)offsets->count
        : (size_t)byte_counts->count;

    for (i = 0U; i < count; i++) {
        uint64_t offset_value = 0U;
        uint64_t count_value = 0U;
        RawTiffParseStatus status;

        if (!raw_tiff_array_value(ctx, offsets, i, &offset_value) ||
            !raw_tiff_array_value(ctx, byte_counts, i, &count_value)) {
            return RAW_TIFF_PARSE_INVALID;
        }
        if (offset_value == 0U || count_value == 0U) {
            continue;
        }
        status = raw_tiff_note_region(ctx, offset_value, count_value);
        if (status != RAW_TIFF_PARSE_OK) {
            return status;
        }
        ctx->saw_image_payload = 1;
    }
    return RAW_TIFF_PARSE_OK;
}

static RawTiffParseStatus raw_tiff_parse_ifd(RawTiffContext *ctx, size_t ifd_offset)
{
    size_t entry_count_field_size;
    size_t entry_size;
    size_t next_ifd_size;
    uint64_t entry_count_u64;
    size_t entry_count;
    size_t entries_bytes;
    size_t table_end;
    size_t i;
    RawTiffValueArray strip_offsets = {0};
    RawTiffValueArray strip_counts = {0};
    RawTiffValueArray tile_offsets = {0};
    RawTiffValueArray tile_counts = {0};
    RawTiffValueArray jpeg_offsets = {0};
    RawTiffValueArray jpeg_lengths = {0};

    if (ctx == NULL) {
        return RAW_TIFF_PARSE_INVALID;
    }
    if (raw_tiff_ifd_already_visited(ctx, ifd_offset)) {
        return RAW_TIFF_PARSE_OK;
    }
    if (!raw_tiff_mark_ifd_visited(ctx, ifd_offset)) {
        return RAW_TIFF_PARSE_INVALID;
    }

    entry_count_field_size = ctx->kind == RAW_TIFF_KIND_BIG ? 8U : 2U;
    entry_size = ctx->kind == RAW_TIFF_KIND_BIG ? 20U : 12U;
    next_ifd_size = ctx->kind == RAW_TIFF_KIND_BIG ? 8U : 4U;

    {
        RawTiffParseStatus status =
            raw_tiff_require(ctx, (uint64_t)ifd_offset, (uint64_t)entry_count_field_size);
        if (status != RAW_TIFF_PARSE_OK) {
            return status;
        }
    }

    entry_count_u64 = ctx->kind == RAW_TIFF_KIND_BIG
        ? raw_tiff_read_u64(ctx->buffer + ifd_offset, ctx->endian)
        : (uint64_t)raw_tiff_read_u16(ctx->buffer + ifd_offset, ctx->endian);
    if (entry_count_u64 > 4096U ||
        entry_count_u64 > (uint64_t)(SIZE_MAX / entry_size)) {
        return RAW_TIFF_PARSE_INVALID;
    }

    entry_count = (size_t)entry_count_u64;
    entries_bytes = entry_count * entry_size;
    table_end = ifd_offset + entry_count_field_size + entries_bytes + next_ifd_size;
    if (table_end < ifd_offset) {
        return RAW_TIFF_PARSE_INVALID;
    }
    {
        RawTiffParseStatus status =
            raw_tiff_require(ctx, (uint64_t)ifd_offset, (uint64_t)(table_end - ifd_offset));
        if (status != RAW_TIFF_PARSE_OK) {
            return status;
        }
    }

    ctx->saw_ifd = 1;
    if ((uint64_t)table_end > ctx->max_end) {
        ctx->max_end = (uint64_t)table_end;
    }

    for (i = 0U; i < entry_count; i++) {
        const uint8_t *entry =
            ctx->buffer + ifd_offset + entry_count_field_size + i * entry_size;
        uint16_t tag = raw_tiff_read_u16(entry, ctx->endian);
        uint16_t type = raw_tiff_read_u16(entry + 2U, ctx->endian);
        uint64_t count = ctx->kind == RAW_TIFF_KIND_BIG
            ? raw_tiff_read_u64(entry + 4U, ctx->endian)
            : (uint64_t)raw_tiff_read_u32(entry + 4U, ctx->endian);
        const uint8_t *value_data = NULL;
        size_t value_size = 0U;
        size_t inline_capacity = 0U;
        RawTiffValueArray array = {0};
        RawTiffParseStatus status;

        if (raw_tiff_type_width(type) == 0U) {
            /*
             * Camera RAW files often carry proprietary maker-note tags.
             * Unknown TIFF field types should not invalidate otherwise
             * usable Strip/Tile/JPEG offset evidence.
             */
            continue;
        }
        status = raw_tiff_entry_value_ptr(
            ctx,
            entry,
            type,
            count,
            &value_data,
            &value_size,
            &inline_capacity);
        if (status != RAW_TIFF_PARSE_OK) {
            return status;
        }
        if (value_size > inline_capacity) {
            uint64_t value_offset = ctx->kind == RAW_TIFF_KIND_BIG
                ? raw_tiff_read_u64(entry + 12U, ctx->endian)
                : (uint64_t)raw_tiff_read_u32(entry + 8U, ctx->endian);
            status = raw_tiff_note_region(ctx, value_offset, (uint64_t)value_size);
            if (status != RAW_TIFF_PARSE_OK) {
                return status;
            }
        }

        array.data = value_data;
        array.type = type;
        array.count = count;

        switch (tag) {
            case 256:
            case 257:
            {
                uint64_t dimension = 0U;
                if (array.count > 0U &&
                    raw_tiff_array_value(ctx, &array, 0U, &dimension)) {
                    if (tag == 256U && dimension > ctx->max_width) {
                        ctx->max_width = dimension;
                    } else if (tag == 257U && dimension > ctx->max_height) {
                        ctx->max_height = dimension;
                    }
                }
                break;
            }
            case 271:
                raw_tiff_copy_ascii(ctx->make, sizeof(ctx->make), value_data, value_size);
                break;
            case 272:
                raw_tiff_copy_ascii(ctx->model, sizeof(ctx->model), value_data, value_size);
                break;
            case 273:
                strip_offsets = array;
                break;
            case 280:
            {
                uint64_t raw_offset = 0U;
                if (array.count > 0U &&
                    raw_tiff_array_value(ctx, &array, 0U, &raw_offset) &&
                    raw_offset > 0U) {
                    ctx->raw_data_offset = raw_offset;
                }
                break;
            }
            case 279:
                strip_counts = array;
                break;
            case 324:
                tile_offsets = array;
                break;
            case 325:
                tile_counts = array;
                break;
            case 330:
                status = raw_tiff_parse_subifds(ctx, &array);
                if (status != RAW_TIFF_PARSE_OK) {
                    return status;
                }
                break;
            case 513:
                jpeg_offsets = array;
                break;
            case 514:
                jpeg_lengths = array;
                break;
            case 34665:
            case 34853:
            case 40965:
            {
                uint64_t child_offset = 0U;
                if (array.count == 0U ||
                    !raw_tiff_array_value(ctx, &array, 0U, &child_offset) ||
                    child_offset == 0U) {
                    break;
                }
                status = raw_tiff_parse_ifd(ctx, (size_t)child_offset);
                if (status != RAW_TIFF_PARSE_OK) {
                    return status;
                }
                break;
            }
            case 50706:
            case 50707:
                ctx->saw_dng = 1;
                ctx->saw_raw_indicator = 1;
                break;
            case 50708:
            case 50709:
                raw_tiff_copy_ascii(
                    ctx->unique_model,
                    sizeof(ctx->unique_model),
                    value_data,
                    value_size);
                ctx->saw_raw_indicator = 1;
                break;
            case 50717:
            case 50721:
            case 50723:
            case 50724:
            case 50725:
            case 50778:
                ctx->saw_raw_indicator = 1;
                break;
            default:
                break;
        }
    }

    {
        RawTiffParseStatus status;
        status = raw_tiff_note_image_ranges(ctx, &strip_offsets, &strip_counts);
        if (status != RAW_TIFF_PARSE_OK) {
            return status;
        }
        status = raw_tiff_note_image_ranges(ctx, &tile_offsets, &tile_counts);
        if (status != RAW_TIFF_PARSE_OK) {
            return status;
        }
        status = raw_tiff_note_image_ranges(ctx, &jpeg_offsets, &jpeg_lengths);
        if (status != RAW_TIFF_PARSE_OK) {
            return status;
        }
    }

    {
        size_t next_pos = ifd_offset + entry_count_field_size + entries_bytes;
        uint64_t next_ifd = ctx->kind == RAW_TIFF_KIND_BIG
            ? raw_tiff_read_u64(ctx->buffer + next_pos, ctx->endian)
            : (uint64_t)raw_tiff_read_u32(ctx->buffer + next_pos, ctx->endian);
        if (next_ifd != 0U) {
            RawTiffParseStatus status =
                raw_tiff_parse_ifd(ctx, (size_t)next_ifd);
            if (status != RAW_TIFF_PARSE_OK) {
                return status;
            }
        }
    }

    return RAW_TIFF_PARSE_OK;
}

static void raw_tiff_select_extension(RawTiffContext *ctx)
{
    const char *make;
    const char *model;
    const char *unique_model;

    if (ctx == NULL || ctx->extension[0] != '\0') {
        return;
    }

    make = ctx->make;
    model = ctx->model;
    unique_model = ctx->unique_model;

    if (ctx->saw_dng) {
        snprintf(ctx->extension, sizeof(ctx->extension), "dng");
        return;
    }
    if (ctx->saw_cr2) {
        snprintf(ctx->extension, sizeof(ctx->extension), "cr2");
        return;
    }
    if (ctx->saw_orf) {
        snprintf(ctx->extension, sizeof(ctx->extension), "orf");
        return;
    }
    if (ctx->saw_rw2) {
        if (raw_ascii_contains_ci(make, "leica") ||
            raw_ascii_contains_ci(model, "leica")) {
            snprintf(ctx->extension, sizeof(ctx->extension), "rwl");
        } else {
            snprintf(ctx->extension, sizeof(ctx->extension), "rw2");
        }
        return;
    }
    if (raw_ascii_contains_ci(make, "nikon") ||
        raw_ascii_contains_ci(unique_model, "nikon")) {
        if (raw_ascii_contains_ci(model, "coolpix") ||
            raw_ascii_contains_ci(unique_model, "coolpix")) {
            snprintf(ctx->extension, sizeof(ctx->extension), "nrw");
        } else {
            snprintf(ctx->extension, sizeof(ctx->extension), "nef");
        }
        return;
    }
    if (raw_ascii_contains_ci(make, "sony") ||
        raw_ascii_contains_ci(unique_model, "sony")) {
        snprintf(ctx->extension, sizeof(ctx->extension), "arw");
        return;
    }
    if (raw_ascii_contains_ci(make, "olympus") ||
        raw_ascii_contains_ci(make, "om digital") ||
        raw_ascii_contains_ci(unique_model, "olympus")) {
        snprintf(ctx->extension, sizeof(ctx->extension), "orf");
        return;
    }
    if (raw_ascii_contains_ci(make, "panasonic")) {
        snprintf(ctx->extension, sizeof(ctx->extension), "rw2");
        return;
    }
    if (raw_ascii_contains_ci(make, "leica")) {
        snprintf(ctx->extension, sizeof(ctx->extension), "rwl");
        return;
    }
    if (raw_ascii_contains_ci(make, "pentax") ||
        raw_ascii_contains_ci(model, "pentax") ||
        raw_ascii_contains_ci(model, "gx-")) {
        snprintf(ctx->extension, sizeof(ctx->extension), "pef");
        return;
    }
    if (raw_ascii_contains_ci(make, "samsung")) {
        snprintf(ctx->extension, sizeof(ctx->extension), "srw");
        return;
    }
    if (raw_ascii_contains_ci(make, "hasselblad")) {
        snprintf(ctx->extension, sizeof(ctx->extension), "3fr");
        return;
    }
    if (raw_ascii_contains_ci(make, "leaf")) {
        snprintf(ctx->extension, sizeof(ctx->extension), "mos");
        return;
    }
}

static RawTiffParseStatus raw_tiff_parse_prefix(
    const uint8_t *buffer,
    size_t length,
    RawTiffContext *ctx
)
{
    uint64_t first_ifd = 0U;

    if (ctx == NULL) {
        return RAW_TIFF_PARSE_INVALID;
    }
    memset(ctx, 0, sizeof(*ctx));
    ctx->buffer = buffer;
    ctx->length = length;

    if (buffer == NULL || length < 8U) {
        raw_tiff_need(ctx, 8U);
        return RAW_TIFF_PARSE_NEED_MORE;
    }

    if (buffer[0] == 'I' && buffer[1] == 'I') {
        ctx->endian = RAW_TIFF_ENDIAN_LITTLE;
    } else if (buffer[0] == 'M' && buffer[1] == 'M') {
        ctx->endian = RAW_TIFF_ENDIAN_BIG;
    } else {
        return RAW_TIFF_PARSE_INVALID;
    }

    ctx->version = raw_tiff_read_u16(buffer + 2U, ctx->endian);
    if (ctx->version == 42U || ctx->version == 85U ||
        ctx->version == 0x4f52U || ctx->version == 0x5352U) {
        ctx->kind = RAW_TIFF_KIND_CLASSIC;
        first_ifd = (uint64_t)raw_tiff_read_u32(buffer + 4U, ctx->endian);
        ctx->max_end = 8U;
        if (ctx->version == 85U) {
            ctx->saw_rw2 = 1;
            ctx->saw_raw_indicator = 1;
        } else if (ctx->version == 0x4f52U || ctx->version == 0x5352U) {
            ctx->saw_orf = 1;
            ctx->saw_raw_indicator = 1;
        }
    } else if (ctx->version == 43U) {
        if (length < 16U) {
            raw_tiff_need(ctx, 16U);
            return RAW_TIFF_PARSE_NEED_MORE;
        }
        if (raw_tiff_read_u16(buffer + 4U, ctx->endian) != 8U ||
            raw_tiff_read_u16(buffer + 6U, ctx->endian) != 0U) {
            return RAW_TIFF_PARSE_INVALID;
        }
        ctx->kind = RAW_TIFF_KIND_BIG;
        first_ifd = raw_tiff_read_u64(buffer + 8U, ctx->endian);
        ctx->max_end = 16U;
    } else {
        return RAW_TIFF_PARSE_INVALID;
    }

    if (length >= 12U &&
        memcmp(buffer, "II\x2a\x00", 4U) == 0 &&
        memcmp(buffer + 8U, "CR\x02\x00", 4U) == 0) {
        ctx->saw_cr2 = 1;
        ctx->saw_raw_indicator = 1;
    }

    if (first_ifd == 0U || first_ifd > RAW_TIFF_MAX_META_BYTES) {
        return RAW_TIFF_PARSE_INVALID;
    }

    {
        RawTiffParseStatus status = raw_tiff_parse_ifd(ctx, (size_t)first_ifd);
        if (status != RAW_TIFF_PARSE_OK) {
            return status;
        }
    }

    raw_tiff_select_extension(ctx);

    if (ctx->extension[0] == '\0' && ctx->saw_raw_indicator) {
        snprintf(ctx->extension, sizeof(ctx->extension), "dng");
    }

    return RAW_TIFF_PARSE_OK;
}

int carver_raw_tiff_probe_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    size_t start_offset
)
{
    RawTiffContext ctx;
    RawTiffParseStatus status;

    if (buffer == NULL || start_offset + 8U > buffer_length) {
        return 0;
    }
    status = raw_tiff_parse_prefix(
        buffer + start_offset,
        buffer_length - start_offset,
        &ctx);
    return status == RAW_TIFF_PARSE_OK &&
           ctx.extension[0] != '\0' &&
           (ctx.saw_image_payload ||
            (ctx.saw_rw2 && ctx.raw_data_offset > 0U));
}

static int raw_read_prefix(
    Reader *reader,
    uint64_t absolute_offset,
    uint8_t **buffer_io,
    size_t *length_io,
    size_t target_length
)
{
    uint8_t *grown;
    size_t old_length;

    if (reader == NULL || buffer_io == NULL || length_io == NULL ||
        target_length == 0U || target_length > RAW_TIFF_MAX_META_BYTES) {
        return 0;
    }
    old_length = *length_io;
    if (old_length >= target_length) {
        return 1;
    }
    grown = (uint8_t *)realloc(*buffer_io, target_length);
    if (grown == NULL) {
        return 0;
    }
    *buffer_io = grown;
    if (!read_stream_bytes(
            reader,
            absolute_offset + (uint64_t)old_length,
            grown + old_length,
            target_length - old_length)) {
        return 0;
    }
    *length_io = target_length;
    return 1;
}

int carver_raw_tiff_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    const MagicTable *boundary_table
)
{
    uint8_t *prefix = NULL;
    size_t prefix_length = 0U;
    size_t target_length = RAW_TIFF_INITIAL_META_BYTES;
    RawTiffContext ctx;
    RawTiffParseStatus status;
    CarverOutput output = {0};

#define RAW_TIFF_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_raw_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        free(prefix); \
        return 0; \
    } while (0)

    (void)config;
    carver_raw_reset_last_audit();
    if (resume_offset != NULL) {
        *resume_offset = start_offset + 1U;
    }
    if (reader == NULL || resume_offset == NULL) {
        RAW_TIFF_REJECT("invalid_input", 0U);
    }
    if (reader->source_size > 0U &&
        (uint64_t)absolute_offset >= reader->source_size) {
        RAW_TIFF_REJECT("source_eof_before_start", 0U);
    }

    while (1) {
        if (!raw_read_prefix(
                reader,
                (uint64_t)absolute_offset,
                &prefix,
                &prefix_length,
                target_length)) {
            RAW_TIFF_REJECT("source_eof_before_metadata", 0U);
        }

        status = raw_tiff_parse_prefix(prefix, prefix_length, &ctx);
        if (status == RAW_TIFF_PARSE_OK) {
            break;
        }
        if (status == RAW_TIFF_PARSE_INVALID) {
            RAW_TIFF_REJECT("not_supported_raw_tiff", 0U);
        }
        if (ctx.needed_end <= prefix_length ||
            ctx.needed_end > RAW_TIFF_MAX_META_BYTES) {
            RAW_TIFF_REJECT("metadata_over_cap", ctx.needed_end);
        }
        target_length = (size_t)ctx.needed_end;
        if (target_length < prefix_length + (64U * 1024U)) {
            target_length = prefix_length + (64U * 1024U);
        }
        if (target_length > RAW_TIFF_MAX_META_BYTES) {
            target_length = RAW_TIFF_MAX_META_BYTES;
        }
    }

    if (ctx.extension[0] == '\0' || !ctx.saw_image_payload) {
        if (ctx.saw_rw2 &&
            ctx.raw_data_offset > 0U &&
            boundary_table != NULL) {
            uint64_t scan_start_span =
                ctx.raw_data_offset + RAW_TIFF_BOUNDARY_MIN_PAYLOAD_BYTES;
            uint64_t max_scan_span = RAW_TIFF_BOUNDARY_SCAN_MAX_BYTES;
            uint64_t boundary_span = 0U;

            if (scan_start_span < RAW_TIFF_BOUNDARY_MIN_PAYLOAD_BYTES) {
                scan_start_span = RAW_TIFF_BOUNDARY_MIN_PAYLOAD_BYTES;
            }
            if (reader->source_size > 0U &&
                (uint64_t)absolute_offset < reader->source_size &&
                max_scan_span > reader->source_size - (uint64_t)absolute_offset) {
                max_scan_span = reader->source_size - (uint64_t)absolute_offset;
            }
            if (raw_tiff_find_next_strong_boundary(
                    reader,
                    boundary_table,
                    (uint64_t)absolute_offset,
                    scan_start_span,
                    max_scan_span,
                    &boundary_span)) {
                ctx.max_end = boundary_span;
                ctx.saw_image_payload = 1;
                carver_audit_set_trailing_reason_inline(
                    &g_raw_last_audit,
                    "next_strong_signature");
            }
        }
        if (!ctx.saw_image_payload &&
            ctx.saw_rw2 &&
            ctx.raw_data_offset > 0U &&
            absolute_offset == 0U &&
            reader->source_size > 0U &&
            reader->source_size <= RAW_MAX_REASONABLE_FILE_SIZE) {
            ctx.max_end = reader->source_size;
            ctx.saw_image_payload = 1;
        }
    }
    if (ctx.extension[0] == '\0' || !ctx.saw_image_payload) {
        if (ctx.saw_rw2 && ctx.raw_data_offset > 0U) {
            RAW_TIFF_REJECT("missing_raw_boundary", ctx.max_end);
        }
        RAW_TIFF_REJECT("unclassified_raw_tiff", ctx.max_end);
    }
    if (ctx.max_end < RAW_TIFF_MIN_FILE_SIZE) {
        RAW_TIFF_REJECT("too_small", ctx.max_end);
    }
    if (ctx.max_end > RAW_MAX_REASONABLE_FILE_SIZE) {
        RAW_TIFF_REJECT("size_over_cap", ctx.max_end);
    }
    if (reader->source_size > 0U &&
        (ctx.max_end > reader->source_size - (uint64_t)absolute_offset)) {
        RAW_TIFF_REJECT("source_eof_before_end", ctx.max_end);
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            ctx.extension)) {
        RAW_TIFF_REJECT("output_open_failed", ctx.max_end);
    }
    {
        uint64_t buffered_write =
            ctx.max_end < (uint64_t)prefix_length ? ctx.max_end : (uint64_t)prefix_length;
        if (buffered_write > 0U &&
            fwrite(prefix, 1U, (size_t)buffered_write, output.file) != (size_t)buffered_write) {
            carver_output_abort(&output);
            RAW_TIFF_REJECT("write_failed", ctx.max_end);
        }
        if (ctx.max_end > buffered_write &&
            !copy_stream_bytes(
                reader,
                output.file,
                (uint64_t)absolute_offset + buffered_write,
                ctx.max_end - buffered_write)) {
            carver_output_abort(&output);
            RAW_TIFF_REJECT("write_failed", ctx.max_end);
        }
    }
    if (!carver_output_finish(&output)) {
        RAW_TIFF_REJECT("finish_failed", ctx.max_end);
    }

    compute_resume_offset_local(
        reader,
        (uint64_t)absolute_offset + ctx.max_end,
        start_offset,
        resume_offset);
    carver_audit_set_inline(
        &g_raw_last_audit,
        "recovered",
        ctx.extension,
        carver_audit_span_from_u64(ctx.max_end));
    free(prefix);
#undef RAW_TIFF_REJECT
    return 1;
}

int carver_raw_raf_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    uint8_t header[RAW_RAF_HEADER_BYTES];
    uint32_t jpeg_offset;
    uint32_t jpeg_length;
    uint32_t cfa_header_offset;
    uint32_t cfa_header_length;
    uint32_t raw_offset;
    uint32_t raw_length;
    uint64_t confirmed_span;
    CarverOutput output = {0};

#define RAW_RAF_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_raw_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    (void)config;
    carver_raw_reset_last_audit();
    if (resume_offset != NULL) {
        *resume_offset = start_offset + 1U;
    }
    if (reader == NULL || resume_offset == NULL) {
        RAW_RAF_REJECT("invalid_input", 0U);
    }
    if (!read_stream_bytes(reader, (uint64_t)absolute_offset, header, sizeof(header))) {
        RAW_RAF_REJECT("source_eof_before_header", 0U);
    }
    if (memcmp(header, "FUJIFILMCCD-RAW ", 16U) != 0) {
        RAW_RAF_REJECT("missing_raf_header", 0U);
    }

    jpeg_offset = read_u32_be(header + 84U);
    jpeg_length = read_u32_be(header + 88U);
    cfa_header_offset = read_u32_be(header + 92U);
    cfa_header_length = read_u32_be(header + 96U);
    raw_offset = read_u32_be(header + 100U);
    raw_length = read_u32_be(header + 104U);

    confirmed_span = RAW_RAF_HEADER_BYTES;
    if (jpeg_offset > 0U && jpeg_length > 0U &&
        (uint64_t)jpeg_offset + (uint64_t)jpeg_length > confirmed_span) {
        confirmed_span = (uint64_t)jpeg_offset + (uint64_t)jpeg_length;
    }
    if (cfa_header_offset > 0U && cfa_header_length > 0U &&
        (uint64_t)cfa_header_offset + (uint64_t)cfa_header_length > confirmed_span) {
        confirmed_span = (uint64_t)cfa_header_offset + (uint64_t)cfa_header_length;
    }
    if (raw_offset > 0U && raw_length > 0U &&
        (uint64_t)raw_offset + (uint64_t)raw_length > confirmed_span) {
        confirmed_span = (uint64_t)raw_offset + (uint64_t)raw_length;
    }

    if (confirmed_span < 1024U * 1024U) {
        RAW_RAF_REJECT("raf_payload_too_small", confirmed_span);
    }
    if (confirmed_span > RAW_MAX_REASONABLE_FILE_SIZE) {
        RAW_RAF_REJECT("size_over_cap", confirmed_span);
    }
    if (reader->source_size > 0U &&
        confirmed_span > reader->source_size - (uint64_t)absolute_offset) {
        RAW_RAF_REJECT("source_eof_before_end", confirmed_span);
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "raf")) {
        RAW_RAF_REJECT("output_open_failed", confirmed_span);
    }
    if (!copy_stream_bytes(reader, output.file, (uint64_t)absolute_offset, confirmed_span)) {
        carver_output_abort(&output);
        RAW_RAF_REJECT("write_failed", confirmed_span);
    }
    if (!carver_output_finish(&output)) {
        RAW_RAF_REJECT("finish_failed", confirmed_span);
    }
    compute_resume_offset_local(
        reader,
        (uint64_t)absolute_offset + confirmed_span,
        start_offset,
        resume_offset);
    carver_audit_set_inline(
        &g_raw_last_audit,
        "recovered",
        "raf",
        carver_audit_span_from_u64(confirmed_span));
#undef RAW_RAF_REJECT
    return 1;
}

static int raw_pread_exact(
    const Reader *reader,
    uint64_t absolute_offset,
    uint8_t *dst,
    size_t byte_count
)
{
    size_t done = 0U;

    if (reader == NULL || dst == NULL || reader->fd < 0) {
        return 0;
    }
    while (done < byte_count) {
        ssize_t got = pread(
            reader->fd,
            dst + done,
            byte_count - done,
            (off_t)(absolute_offset + (uint64_t)done));
        if (got <= 0) {
            return 0;
        }
        done += (size_t)got;
    }
    return 1;
}

static uint16_t raw_crw_read_u16(const uint8_t *data, int little_endian)
{
    return little_endian ? read_u16_le(data) : read_u16_be(data);
}

static uint32_t raw_crw_read_u32(const uint8_t *data, int little_endian)
{
    return little_endian ? read_u32_le(data) : read_u32_be(data);
}

static int raw_crw_header_valid(
    const uint8_t *header,
    size_t header_size,
    int *little_endian_out,
    uint32_t *header_length_out
)
{
    int little_endian;
    uint32_t header_length;
    uint32_t version;
    uint32_t major;

    if (little_endian_out != NULL) {
        *little_endian_out = 0;
    }
    if (header_length_out != NULL) {
        *header_length_out = 0U;
    }
    if (header == NULL || header_size < RAW_CRW_HEADER_MIN_BYTES) {
        return 0;
    }
    if (header[0] == 'I' && header[1] == 'I') {
        little_endian = 1;
    } else if (header[0] == 'M' && header[1] == 'M') {
        little_endian = 0;
    } else {
        return 0;
    }
    header_length = raw_crw_read_u32(header + 2U, little_endian);
    if (header_length < RAW_CRW_HEADER_MIN_BYTES ||
        header_length > 4096U) {
        return 0;
    }
    if (memcmp(header + 6U, "HEAPCCDR", 8U) != 0) {
        return 0;
    }
    version = raw_crw_read_u32(header + 14U, little_endian);
    major = version >> 16U;
    if (major == 0U || major > 10U) {
        return 0;
    }
    if (little_endian_out != NULL) {
        *little_endian_out = little_endian;
    }
    if (header_length_out != NULL) {
        *header_length_out = header_length;
    }
    return 1;
}

static int raw_crw_locate_start(
    Reader *reader,
    size_t match_offset,
    size_t match_absolute_offset,
    size_t *crw_start_offset_out,
    size_t *crw_absolute_offset_out
)
{
    uint8_t header[RAW_CRW_HEADER_MIN_BYTES];

    if (crw_start_offset_out != NULL) {
        *crw_start_offset_out = match_offset;
    }
    if (crw_absolute_offset_out != NULL) {
        *crw_absolute_offset_out = match_absolute_offset;
    }
    if (reader == NULL ||
        crw_start_offset_out == NULL ||
        crw_absolute_offset_out == NULL) {
        return 0;
    }

    if (read_stream_bytes(
            reader,
            (uint64_t)match_absolute_offset,
            header,
            sizeof(header)) &&
        raw_crw_header_valid(header, sizeof(header), NULL, NULL)) {
        return 1;
    }

    if (match_offset < 6U || match_absolute_offset < 6U) {
        return 0;
    }
    if (!read_stream_bytes(
            reader,
            (uint64_t)match_absolute_offset - 6ULL,
            header,
            sizeof(header))) {
        return 0;
    }
    if (!raw_crw_header_valid(header, sizeof(header), NULL, NULL)) {
        return 0;
    }

    *crw_start_offset_out = match_offset - 6U;
    *crw_absolute_offset_out = match_absolute_offset - 6U;
    return 1;
}

static int raw_crw_validate_span(
    const Reader *reader,
    uint64_t crw_absolute_offset,
    uint64_t confirmed_span,
    uint64_t *payload_end_out
)
{
    uint8_t header[RAW_CRW_HEADER_MIN_BYTES];
    uint8_t trailer[4];
    uint8_t count_buf[2];
    uint8_t *entries = NULL;
    uint32_t header_length = 0U;
    uint32_t dir_start;
    uint16_t dir_count;
    uint64_t block_size;
    uint64_t entries_start;
    uint64_t entries_bytes;
    uint64_t entries_abs;
    size_t i;
    int little_endian = 0;
    int saw_raw_data = 0;
    int saw_valid_reference = 0;
    uint64_t payload_end = 0U;

    if (payload_end_out != NULL) {
        *payload_end_out = 0U;
    }
    if (reader == NULL ||
        confirmed_span < RAW_CRW_MIN_VALID_SPAN ||
        confirmed_span > RAW_MAX_REASONABLE_FILE_SIZE ||
        reader->fd < 0) {
        return 0;
    }
    if (!raw_pread_exact(
            reader,
            crw_absolute_offset,
            header,
            sizeof(header)) ||
        !raw_crw_header_valid(
            header,
            sizeof(header),
            &little_endian,
            &header_length)) {
        return 0;
    }
    if (confirmed_span <= (uint64_t)header_length + 6ULL) {
        return 0;
    }

    block_size = confirmed_span - (uint64_t)header_length;
    if (block_size > UINT32_MAX) {
        return 0;
    }
    if (!raw_pread_exact(
            reader,
            crw_absolute_offset + confirmed_span - 4ULL,
            trailer,
            sizeof(trailer))) {
        return 0;
    }
    dir_start = raw_crw_read_u32(trailer, little_endian);
    if ((uint64_t)dir_start + 2ULL > block_size ||
        (uint64_t)dir_start + 2ULL > block_size - 4ULL) {
        return 0;
    }
    if (!raw_pread_exact(
            reader,
            crw_absolute_offset + (uint64_t)header_length + (uint64_t)dir_start,
            count_buf,
            sizeof(count_buf))) {
        return 0;
    }
    dir_count = raw_crw_read_u16(count_buf, little_endian);
    if (dir_count == 0U || dir_count > RAW_CRW_DIR_MAX_ENTRIES) {
        return 0;
    }

    entries_start = (uint64_t)dir_start + 2ULL;
    entries_bytes = (uint64_t)dir_count * 10ULL;
    if (entries_start + entries_bytes < entries_start ||
        entries_start + entries_bytes > block_size - 4ULL ||
        entries_bytes > SIZE_MAX) {
        return 0;
    }
    entries = (uint8_t *)malloc((size_t)entries_bytes);
    if (entries == NULL) {
        return 0;
    }
    entries_abs =
        crw_absolute_offset + (uint64_t)header_length + entries_start;
    if (!raw_pread_exact(reader, entries_abs, entries, (size_t)entries_bytes)) {
        free(entries);
        return 0;
    }

    for (i = 0U; i < (size_t)dir_count; i++) {
        const uint8_t *entry = entries + i * 10U;
        uint16_t tag = raw_crw_read_u16(entry, little_endian);
        uint32_t size = raw_crw_read_u32(entry + 2U, little_endian);
        uint32_t offset = raw_crw_read_u32(entry + 6U, little_endian);
        uint16_t data_location = (uint16_t)(tag & 0xc000U);
        uint16_t tag_id = (uint16_t)(tag & 0x3fffU);

        if (tag == 0U) {
            continue;
        }
        if (data_location == 0x4000U) {
            if (size <= 8U) {
                saw_valid_reference = 1;
            }
            continue;
        }
        if (data_location != 0U) {
            continue;
        }
        if ((uint64_t)offset > (uint64_t)dir_start ||
            (uint64_t)size > (uint64_t)dir_start - (uint64_t)offset) {
            free(entries);
            return 0;
        }
        if (size > 0U) {
            uint64_t end = (uint64_t)header_length +
                           (uint64_t)offset +
                           (uint64_t)size;
            saw_valid_reference = 1;
            if (end > payload_end) {
                payload_end = end;
            }
        }
        if (tag_id == 0x2005U && size >= 512U * 1024U) {
            saw_raw_data = 1;
        }
    }

    free(entries);
    if (!saw_valid_reference || !saw_raw_data) {
        return 0;
    }
    if (payload_end_out != NULL) {
        *payload_end_out = payload_end;
    }
    return 1;
}

static int raw_crw_validate_span_near_boundary(
    const Reader *reader,
    uint64_t crw_absolute_offset,
    uint64_t candidate_span,
    uint64_t *valid_span_out
)
{
    uint64_t max_trim;
    uint64_t trim;

    if (valid_span_out != NULL) {
        *valid_span_out = 0U;
    }
    if (reader == NULL || valid_span_out == NULL ||
        candidate_span < RAW_CRW_MIN_VALID_SPAN) {
        return 0;
    }
    if (raw_crw_validate_span(
            reader,
            crw_absolute_offset,
            candidate_span,
            NULL)) {
        *valid_span_out = candidate_span;
        return 1;
    }

    max_trim = RAW_CRW_BOUNDARY_TRIM_MAX_BYTES;
    if (candidate_span - RAW_CRW_MIN_VALID_SPAN < max_trim) {
        max_trim = candidate_span - RAW_CRW_MIN_VALID_SPAN;
    }
    for (trim = 2U; trim <= max_trim; trim += 2U) {
        uint64_t trimmed_span = candidate_span - trim;
        if (raw_crw_validate_span(
                reader,
                crw_absolute_offset,
                trimmed_span,
                NULL)) {
            *valid_span_out = trimmed_span;
            return 1;
        }
    }
    return 0;
}

static int raw_crw_find_valid_boundary(
    const Reader *reader,
    const MagicTable *table,
    uint64_t crw_absolute_offset,
    uint64_t *boundary_span_out
)
{
    uint8_t *buffer;
    uint64_t source_end;
    uint64_t scan_abs;
    uint64_t scan_end;
    size_t chunk_capacity;

    if (boundary_span_out != NULL) {
        *boundary_span_out = 0U;
    }
    if (reader == NULL ||
        table == NULL ||
        boundary_span_out == NULL ||
        reader->fd < 0) {
        return 0;
    }
    if (reader->source_size > 0U) {
        if (crw_absolute_offset >= reader->source_size) {
            return 0;
        }
        source_end = reader->source_size;
    } else {
        source_end = crw_absolute_offset + RAW_CRW_BOUNDARY_SCAN_MAX_BYTES;
    }

    scan_abs = crw_absolute_offset + RAW_CRW_MIN_VALID_SPAN;
    scan_end = crw_absolute_offset + RAW_CRW_BOUNDARY_SCAN_MAX_BYTES;
    if (scan_end < crw_absolute_offset || scan_end > source_end) {
        scan_end = source_end;
    }
    if (scan_abs >= scan_end) {
        return 0;
    }

    chunk_capacity = RAW_TIFF_BOUNDARY_SCAN_CHUNK + RAW_TIFF_BOUNDARY_SCAN_OVERLAP;
    buffer = (uint8_t *)malloc(chunk_capacity);
    if (buffer == NULL) {
        return 0;
    }
    while (scan_abs < scan_end) {
        size_t request = RAW_TIFF_BOUNDARY_SCAN_CHUNK;
        ssize_t bytes_read;
        size_t i;

        if ((uint64_t)request > scan_end - scan_abs) {
            request = (size_t)(scan_end - scan_abs);
        }
        if (request == 0U) {
            break;
        }
        bytes_read = pread(reader->fd, buffer, request, (off_t)scan_abs);
        if (bytes_read <= 0) {
            break;
        }
        for (i = 0U; i < (size_t)bytes_read; i++) {
            uint64_t candidate_abs = scan_abs + (uint64_t)i;
            uint64_t candidate_span;
            const MagicEntry *match;

            if ((candidate_abs % RAW_TIFF_BOUNDARY_ALIGNMENT) != 0U) {
                continue;
            }
            match = matcher_match_at(table, buffer, (size_t)bytes_read, i);
            if (!raw_tiff_magic_match_is_strong_boundary(match)) {
                continue;
            }
            if (candidate_abs <= crw_absolute_offset) {
                continue;
            }
            candidate_span = candidate_abs - crw_absolute_offset;
            if (raw_crw_validate_span_near_boundary(
                    reader,
                    crw_absolute_offset,
                    candidate_span,
                    boundary_span_out)) {
                free(buffer);
                return 1;
            }
        }
        if ((size_t)bytes_read < request) {
            break;
        }
        scan_abs += (uint64_t)bytes_read;
    }
    free(buffer);
    return 0;
}

int carver_raw_crw_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    const MagicTable *boundary_table
)
{
    size_t crw_start_offset = start_offset;
    size_t crw_absolute_offset = absolute_offset;
    uint64_t confirmed_span = 0U;
    uint64_t payload_end = 0U;
    CarverOutput output = {0};

#define RAW_CRW_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_raw_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    (void)config;
    carver_raw_reset_last_audit();
    if (resume_offset != NULL) {
        *resume_offset = start_offset + 1U;
    }
    if (reader == NULL || resume_offset == NULL) {
        RAW_CRW_REJECT("invalid_input", 0U);
    }
    if (!raw_crw_locate_start(
            reader,
            start_offset,
            absolute_offset,
            &crw_start_offset,
            &crw_absolute_offset)) {
        RAW_CRW_REJECT("missing_crw_header", 0U);
    }
    if (reader->source_size > 0U &&
        (uint64_t)crw_absolute_offset >= reader->source_size) {
        RAW_CRW_REJECT("source_eof_before_start", 0U);
    }

    if (crw_absolute_offset == 0U &&
        reader->source_size > 0U &&
        reader->source_size <= RAW_MAX_REASONABLE_FILE_SIZE &&
        raw_crw_validate_span(
            reader,
            (uint64_t)crw_absolute_offset,
            reader->source_size,
            &payload_end)) {
        confirmed_span = reader->source_size;
    }
    if (confirmed_span == 0U &&
        raw_crw_find_valid_boundary(
            reader,
            boundary_table,
            (uint64_t)crw_absolute_offset,
            &confirmed_span)) {
        carver_audit_set_trailing_reason_inline(
            &g_raw_last_audit,
            "next_strong_signature");
    }
    if (confirmed_span == 0U) {
        RAW_CRW_REJECT("missing_crw_boundary", 0U);
    }
    if (!raw_crw_validate_span(
            reader,
            (uint64_t)crw_absolute_offset,
            confirmed_span,
            &payload_end)) {
        RAW_CRW_REJECT("invalid_crw_directory", confirmed_span);
    }
    if (payload_end > confirmed_span) {
        RAW_CRW_REJECT("crw_payload_out_of_span", confirmed_span);
    }
    if (reader->source_size > 0U &&
        confirmed_span > reader->source_size - (uint64_t)crw_absolute_offset) {
        RAW_CRW_REJECT("source_eof_before_end", confirmed_span);
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)crw_absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "crw")) {
        RAW_CRW_REJECT("output_open_failed", confirmed_span);
    }
    if (!copy_stream_bytes(
            reader,
            output.file,
            (uint64_t)crw_absolute_offset,
            confirmed_span)) {
        carver_output_abort(&output);
        RAW_CRW_REJECT("write_failed", confirmed_span);
    }
    if (!carver_output_finish(&output)) {
        RAW_CRW_REJECT("finish_failed", confirmed_span);
    }

    compute_resume_offset_local(
        reader,
        (uint64_t)crw_absolute_offset + confirmed_span,
        crw_start_offset,
        resume_offset);
    carver_audit_set_inline(
        &g_raw_last_audit,
        "recovered",
        "crw",
        carver_audit_span_from_u64(confirmed_span));
#undef RAW_CRW_REJECT
    return 1;
}

static int raw_cr3_atom_start(
    Reader *reader,
    size_t match_offset,
    size_t absolute_offset,
    size_t *start_offset_out,
    size_t *absolute_offset_out
)
{
    uint8_t prefix[12];

    if (start_offset_out != NULL) {
        *start_offset_out = match_offset;
    }
    if (absolute_offset_out != NULL) {
        *absolute_offset_out = absolute_offset;
    }
    if (reader == NULL || start_offset_out == NULL || absolute_offset_out == NULL) {
        return 0;
    }
    if (read_stream_bytes(reader, (uint64_t)absolute_offset, prefix, 12U) &&
        memcmp(prefix + 4U, "ftyp", 4U) == 0) {
        return 1;
    }
    if (absolute_offset >= 4U &&
        match_offset >= 4U &&
        read_stream_bytes(reader, (uint64_t)absolute_offset - 4U, prefix, 12U) &&
        memcmp(prefix + 4U, "ftyp", 4U) == 0) {
        *start_offset_out = match_offset - 4U;
        *absolute_offset_out = absolute_offset - 4U;
        return 1;
    }
    return 0;
}

static int raw_cr3_box_type_known(const char *type)
{
    return type != NULL &&
           (memcmp(type, "ftyp", 4U) == 0 ||
            memcmp(type, "moov", 4U) == 0 ||
            memcmp(type, "mdat", 4U) == 0 ||
            memcmp(type, "uuid", 4U) == 0 ||
            memcmp(type, "free", 4U) == 0 ||
            memcmp(type, "skip", 4U) == 0 ||
            memcmp(type, "wide", 4U) == 0);
}

int carver_raw_cr3_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    size_t cr3_start_offset = start_offset;
    size_t cr3_absolute_offset = absolute_offset;
    uint64_t cursor_abs;
    uint64_t confirmed_span = 0U;
    unsigned boxes = 0U;
    int saw_moov = 0;
    int saw_payload = 0;
    int output_open = 0;
    CarverOutput output = {0};

#define RAW_CR3_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_raw_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    (void)config;
    carver_raw_reset_last_audit();
    if (resume_offset != NULL) {
        *resume_offset = start_offset + 1U;
    }
    if (reader == NULL || resume_offset == NULL) {
        RAW_CR3_REJECT("invalid_input", 0U);
    }
    if (!raw_cr3_atom_start(
            reader,
            start_offset,
            absolute_offset,
            &cr3_start_offset,
            &cr3_absolute_offset)) {
        RAW_CR3_REJECT("missing_ftyp", 0U);
    }

    {
        uint8_t ftyp[24];
        if (!read_stream_bytes(reader, (uint64_t)cr3_absolute_offset, ftyp, sizeof(ftyp))) {
            RAW_CR3_REJECT("source_eof_before_ftyp", 0U);
        }
        if (memcmp(ftyp + 4U, "ftyp", 4U) != 0 ||
            memcmp(ftyp + 8U, "crx ", 4U) != 0) {
            RAW_CR3_REJECT("not_cr3_brand", 0U);
        }
    }
    if (!carver_output_open_deferred(
            &output,
            (long long)cr3_absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "cr3")) {
        RAW_CR3_REJECT("output_open_failed", 0U);
    }
    output_open = 1;

    cursor_abs = (uint64_t)cr3_absolute_offset;
    while (boxes < RAW_CR3_MAX_BOXES) {
        uint8_t header[16];
        uint64_t box_size;
        uint64_t header_size = 8U;
        char type[5];

        if (!read_stream_bytes(reader, cursor_abs, header, 8U)) {
            break;
        }
        box_size = (uint64_t)read_u32_be(header);
        memcpy(type, header + 4U, 4U);
        type[4] = '\0';
        if (box_size == 1U) {
            if (!read_stream_bytes(reader, cursor_abs, header, 16U)) {
                break;
            }
            box_size = read_u64_be(header + 8U);
            header_size = 16U;
        }
        if (box_size == 0U) {
            break;
        }
        if (box_size < header_size ||
            box_size > RAW_MAX_REASONABLE_FILE_SIZE ||
            cursor_abs + box_size <= cursor_abs) {
            break;
        }
        if (!raw_cr3_box_type_known(type)) {
            break;
        }
        if (!copy_stream_bytes(reader, output.file, cursor_abs, box_size)) {
            carver_output_abort(&output);
            output_open = 0;
            RAW_CR3_REJECT("write_failed", confirmed_span);
        }
        boxes++;
        if (memcmp(type, "moov", 4U) == 0) {
            saw_moov = 1;
        } else if (memcmp(type, "mdat", 4U) == 0 ||
                   memcmp(type, "uuid", 4U) == 0) {
            saw_payload = 1;
        }
        confirmed_span = (cursor_abs - (uint64_t)cr3_absolute_offset) + box_size;
        if (confirmed_span > RAW_MAX_REASONABLE_FILE_SIZE) {
            RAW_CR3_REJECT("size_over_cap", confirmed_span);
        }
        cursor_abs += box_size;
    }

    if (!saw_moov || !saw_payload || confirmed_span < 1024U) {
        if (output_open) {
            carver_output_abort(&output);
            output_open = 0;
        }
        RAW_CR3_REJECT("weak_cr3_structure", confirmed_span);
    }
    if (reader->source_size > 0U &&
        confirmed_span > reader->source_size - (uint64_t)cr3_absolute_offset) {
        if (output_open) {
            carver_output_abort(&output);
            output_open = 0;
        }
        RAW_CR3_REJECT("source_eof_before_end", confirmed_span);
    }
    if (!carver_output_finish(&output)) {
        RAW_CR3_REJECT("finish_failed", confirmed_span);
    }
    output_open = 0;
    compute_resume_offset_local(
        reader,
        (uint64_t)cr3_absolute_offset + confirmed_span,
        cr3_start_offset,
        resume_offset);
    carver_audit_set_inline(
        &g_raw_last_audit,
        "recovered",
        "cr3",
        carver_audit_span_from_u64(confirmed_span));
#undef RAW_CR3_REJECT
    return 1;
}

static int raw_x3f_directory_span(
    const uint8_t *buffer,
    size_t length,
    uint64_t *span_out
)
{
    size_t i;

    if (span_out != NULL) {
        *span_out = 0U;
    }
    if (buffer == NULL || span_out == NULL || length < 256U ||
        memcmp(buffer, "FOVb", 4U) != 0) {
        return 0;
    }
    for (i = 232U; i + 12U <= length; i += 4U) {
        uint32_t version;
        uint32_t entry_count;
        uint64_t directory_end;
        uint64_t file_end;
        uint32_t directory_pointer;
        uint32_t image_columns;
        uint32_t image_rows;
        size_t j;
        int saw_useful_section = 0;

        if (memcmp(buffer + i, "SECd", 4U) != 0) {
            continue;
        }
        version = read_u32_le(buffer + i + 4U);
        entry_count = read_u32_le(buffer + i + 8U);
        if ((version >> 16U) != 2U ||
            entry_count == 0U ||
            entry_count > 4096U) {
            continue;
        }
        directory_end = (uint64_t)i + 12ULL + (uint64_t)entry_count * 12ULL;
        file_end = directory_end + 4ULL;
        if (file_end > (uint64_t)length ||
            file_end > RAW_MAX_REASONABLE_FILE_SIZE) {
            continue;
        }
        directory_pointer = read_u32_le(buffer + (size_t)file_end - 4U);
        if ((uint64_t)directory_pointer != (uint64_t)i) {
            continue;
        }
        image_columns = read_u32_le(buffer + 28U);
        image_rows = read_u32_le(buffer + 32U);
        if (image_columns == 0U ||
            image_rows == 0U ||
            image_columns > 200000U ||
            image_rows > 200000U) {
            continue;
        }
        for (j = 0U; j < (size_t)entry_count; j++) {
            const uint8_t *entry = buffer + i + 12U + j * 12U;
            uint32_t section_offset = read_u32_le(entry);
            uint32_t section_length = read_u32_le(entry + 4U);
            const uint8_t *section_type = entry + 8U;
            uint64_t section_end =
                (uint64_t)section_offset + (uint64_t)section_length;

            if ((section_offset & 3U) != 0U ||
                section_length == 0U ||
                section_offset < 232U ||
                section_end > (uint64_t)i) {
                saw_useful_section = 0;
                break;
            }
            if (memcmp(section_type, "IMAG", 4U) == 0 ||
                memcmp(section_type, "IMA2", 4U) == 0 ||
                memcmp(section_type, "PROP", 4U) == 0) {
                saw_useful_section = 1;
            }
        }
        if (!saw_useful_section) {
            continue;
        }
        *span_out = file_end;
        return 1;
    }
    return 0;
}

int carver_raw_x3f_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    uint8_t *prefix = NULL;
    size_t prefix_length = 0U;
    size_t target_length = RAW_TIFF_INITIAL_META_BYTES;
    uint64_t confirmed_span = 0U;
    CarverOutput output = {0};

#define RAW_X3F_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_raw_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        free(prefix); \
        return 0; \
    } while (0)

    (void)config;
    carver_raw_reset_last_audit();
    if (resume_offset != NULL) {
        *resume_offset = start_offset + 1U;
    }
    if (reader == NULL || resume_offset == NULL) {
        RAW_X3F_REJECT("invalid_input", 0U);
    }
    if (start_offset + 4U > reader->bytes_in_buffer ||
        memcmp(reader->buffer + start_offset, "FOVb", 4U) != 0) {
        RAW_X3F_REJECT("missing_header", 0U);
    }
    if (reader->source_size > 0U &&
        (uint64_t)absolute_offset >= reader->source_size) {
        RAW_X3F_REJECT("source_eof_before_start", 0U);
    }
    while (target_length <= RAW_TIFF_MAX_META_BYTES) {
        if (reader->source_size > 0U) {
            uint64_t remaining = reader->source_size - (uint64_t)absolute_offset;
            if (remaining < (uint64_t)target_length) {
                target_length = (size_t)remaining;
            }
        }
        if (target_length == 0U) {
            RAW_X3F_REJECT("source_eof_before_directory", 0U);
        }
        if (!raw_read_prefix(
                reader,
                (uint64_t)absolute_offset,
                &prefix,
                &prefix_length,
                target_length)) {
            RAW_X3F_REJECT("source_eof_before_directory", 0U);
        }
        if (raw_x3f_directory_span(prefix, prefix_length, &confirmed_span)) {
            break;
        }
        if (reader->source_size > 0U &&
            (uint64_t)prefix_length >=
                reader->source_size - (uint64_t)absolute_offset) {
            RAW_X3F_REJECT("missing_directory", 0U);
        }
        if (target_length >= RAW_TIFF_MAX_META_BYTES) {
            RAW_X3F_REJECT("metadata_over_cap", 0U);
        }
        target_length *= 2U;
        if (target_length < prefix_length + RAW_TIFF_INITIAL_META_BYTES) {
            target_length = prefix_length + RAW_TIFF_INITIAL_META_BYTES;
        }
        if (target_length > RAW_TIFF_MAX_META_BYTES) {
            target_length = RAW_TIFF_MAX_META_BYTES;
        }
    }

    if (confirmed_span < 256U) {
        RAW_X3F_REJECT("weak_x3f_structure", confirmed_span);
    }
    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "x3f")) {
        RAW_X3F_REJECT("output_open_failed", confirmed_span);
    }
    if (fwrite(prefix, 1U, (size_t)confirmed_span, output.file) !=
        (size_t)confirmed_span) {
        carver_output_abort(&output);
        RAW_X3F_REJECT("write_failed", confirmed_span);
    }
    if (!carver_output_finish(&output)) {
        RAW_X3F_REJECT("finish_failed", confirmed_span);
    }
    compute_resume_offset_local(
        reader,
        (uint64_t)absolute_offset + confirmed_span,
        start_offset,
        resume_offset);
    carver_audit_set_inline(
        &g_raw_last_audit,
        "recovered",
        "x3f",
        carver_audit_span_from_u64(confirmed_span));
    free(prefix);
#undef RAW_X3F_REJECT
    return 1;
}
