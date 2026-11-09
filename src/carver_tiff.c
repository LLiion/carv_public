#include "carver_tiff.h"

#include "carver_output.h"
#include "config.h"
#include "filtered_image_log.h"
#include "image_filter.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TIFF_MIN_FILE_SIZE 64U
#define TIFF_MAX_IFD_VISITS 64U

typedef enum {
    TIFF_ENDIAN_LITTLE = 0,
    TIFF_ENDIAN_BIG = 1
} TiffEndian;

typedef enum {
    TIFF_KIND_CLASSIC = 0,
    TIFF_KIND_BIG = 1
} TiffKind;

typedef struct {
    const uint8_t *buffer;
    size_t length;
    TiffEndian endian;
    TiffKind kind;
    size_t visited_ifd_offsets[TIFF_MAX_IFD_VISITS];
    size_t visited_ifd_count;
    size_t max_end;
    int saw_ifd;
    int saw_image_payload;
    uint64_t max_width;
    uint64_t max_height;
} TiffContext;

static CarverAuditReport g_tiff_last_audit;

void carver_tiff_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_tiff_last_audit);
}

void carver_tiff_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_tiff_last_audit;
}

typedef struct {
    const uint8_t *data;
    uint16_t type;
    uint64_t count;
} TiffValueArray;

static uint16_t read_u16_tiff(const uint8_t *data, TiffEndian endian)
{
    if (endian == TIFF_ENDIAN_LITTLE) {
        return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
    }

    return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}

static uint32_t read_u32_tiff(const uint8_t *data, TiffEndian endian)
{
    if (endian == TIFF_ENDIAN_LITTLE) {
        return (uint32_t)data[0] |
               ((uint32_t)data[1] << 8) |
               ((uint32_t)data[2] << 16) |
               ((uint32_t)data[3] << 24);
    }

    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static uint64_t read_u64_tiff(const uint8_t *data, TiffEndian endian)
{
    uint64_t value = 0;
    size_t i;

    if (endian == TIFF_ENDIAN_LITTLE) {
        for (i = 0; i < 8; i++) {
            value |= (uint64_t)data[i] << (i * 8U);
        }
        return value;
    }

    for (i = 0; i < 8; i++) {
        value = (value << 8) | (uint64_t)data[i];
    }
    return value;
}

static size_t tiff_type_width(uint16_t type)
{
    switch (type) {
        case 1:  /* BYTE */
        case 2:  /* ASCII */
        case 6:  /* SBYTE */
        case 7:  /* UNDEFINED */
            return 1;
        case 3:  /* SHORT */
        case 8:  /* SSHORT */
            return 2;
        case 4:  /* LONG */
        case 9:  /* SLONG */
        case 11: /* FLOAT */
        case 13: /* IFD */
            return 4;
        case 5:  /* RATIONAL */
        case 10: /* SRATIONAL */
        case 12: /* DOUBLE */
        case 16: /* LONG8 */
        case 17: /* SLONG8 */
        case 18: /* IFD8 */
            return 8;
        default:
            return 0;
    }
}

static int tiff_mul_size(uint64_t a, size_t b, size_t *out)
{
    if (out == NULL) {
        return 0;
    }

    if (a == 0 || b == 0) {
        *out = 0;
        return 1;
    }

    if (a > (uint64_t)SIZE_MAX / (uint64_t)b) {
        return 0;
    }

    *out = (size_t)(a * (uint64_t)b);
    return 1;
}

static int tiff_note_region(TiffContext *ctx, uint64_t offset, uint64_t length)
{
    size_t end;

    if (ctx == NULL) {
        return 0;
    }
    if (length == 0) {
        return 1;
    }
    if (offset > (uint64_t)ctx->length) {
        return 0;
    }
    if (length > (uint64_t)ctx->length - offset) {
        return 0;
    }

    end = (size_t)(offset + length);
    if (end > ctx->max_end) {
        ctx->max_end = end;
    }
    return 1;
}

static int tiff_ifd_already_visited(const TiffContext *ctx, size_t ifd_offset)
{
    size_t i;

    if (ctx == NULL) {
        return 0;
    }

    for (i = 0; i < ctx->visited_ifd_count; i++) {
        if (ctx->visited_ifd_offsets[i] == ifd_offset) {
            return 1;
        }
    }

    return 0;
}

static int tiff_mark_ifd_visited(TiffContext *ctx, size_t ifd_offset)
{
    if (ctx == NULL) {
        return 0;
    }
    if (tiff_ifd_already_visited(ctx, ifd_offset)) {
        return 1;
    }
    if (ctx->visited_ifd_count >= TIFF_MAX_IFD_VISITS) {
        return 0;
    }

    ctx->visited_ifd_offsets[ctx->visited_ifd_count++] = ifd_offset;
    return 1;
}

static uint64_t tiff_numeric_value(
    const uint8_t *data,
    uint16_t type,
    TiffEndian endian
)
{
    if (data == NULL) {
        return 0;
    }

    switch (type) {
        case 1:
        case 2:
        case 6:
        case 7:
            return (uint64_t)data[0];
        case 3:
        case 8:
            return (uint64_t)read_u16_tiff(data, endian);
        case 4:
        case 9:
        case 13:
            return (uint64_t)read_u32_tiff(data, endian);
        case 16:
        case 17:
        case 18:
            return read_u64_tiff(data, endian);
        default:
            return 0;
    }
}

static size_t tiff_numeric_stride(uint16_t type)
{
    size_t width = tiff_type_width(type);

    if (type == 5 || type == 10 || type == 11 || type == 12) {
        return 0;
    }

    return width;
}

static int tiff_array_value(
    const TiffContext *ctx,
    const TiffValueArray *array,
    size_t index,
    uint64_t *value_out
)
{
    size_t stride;

    if (value_out != NULL) {
        *value_out = 0;
    }
    if (ctx == NULL || array == NULL || value_out == NULL) {
        return 0;
    }
    if (array->data == NULL || index >= array->count) {
        return 0;
    }

    stride = tiff_numeric_stride(array->type);
    if (stride == 0) {
        return 0;
    }

    *value_out = tiff_numeric_value(array->data + index * stride, array->type, ctx->endian);
    return 1;
}

static int tiff_entry_value_ptr(
    const TiffContext *ctx,
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

    if (data_out != NULL) {
        *data_out = NULL;
    }
    if (data_size_out != NULL) {
        *data_size_out = 0;
    }
    if (inline_capacity_out != NULL) {
        *inline_capacity_out = 0;
    }
    if (ctx == NULL || entry == NULL || data_out == NULL || data_size_out == NULL) {
        return 0;
    }

    if (!tiff_mul_size(count, tiff_type_width(type), &value_size)) {
        return 0;
    }

    inline_capacity = ctx->kind == TIFF_KIND_BIG ? 8U : 4U;
    value_field_offset = ctx->kind == TIFF_KIND_BIG ? 12U : 8U;

    if (inline_capacity_out != NULL) {
        *inline_capacity_out = inline_capacity;
    }

    if (value_size == 0) {
        *data_out = entry + value_field_offset;
        *data_size_out = 0;
        return 1;
    }

    if (value_size <= inline_capacity) {
        *data_out = entry + value_field_offset;
        *data_size_out = value_size;
        return 1;
    }

    value_offset = ctx->kind == TIFF_KIND_BIG
        ? read_u64_tiff(entry + value_field_offset, ctx->endian)
        : (uint64_t)read_u32_tiff(entry + value_field_offset, ctx->endian);

    if (value_offset > (uint64_t)ctx->length) {
        return 0;
    }
    if (value_size > ctx->length - (size_t)value_offset) {
        return 0;
    }

    *data_out = ctx->buffer + (size_t)value_offset;
    *data_size_out = value_size;
    return 1;
}

static int tiff_note_image_ranges(
    TiffContext *ctx,
    const TiffValueArray *offsets,
    const TiffValueArray *byte_counts
)
{
    size_t count;
    size_t i;

    if (ctx == NULL || offsets == NULL || byte_counts == NULL) {
        return 0;
    }

    count = offsets->count < byte_counts->count
        ? (size_t)offsets->count
        : (size_t)byte_counts->count;

    for (i = 0; i < count; i++) {
        uint64_t offset_value;
        uint64_t count_value;

        if (!tiff_array_value(ctx, offsets, i, &offset_value) ||
            !tiff_array_value(ctx, byte_counts, i, &count_value)) {
            return 0;
        }

        if (offset_value == 0 || count_value == 0) {
            continue;
        }

        if (!tiff_note_region(ctx, offset_value, count_value)) {
            return 0;
        }
        ctx->saw_image_payload = 1;
    }

    return 1;
}

static int tiff_parse_ifd(TiffContext *ctx, size_t ifd_offset);

static void tiff_note_dimension(uint64_t *target, uint64_t value)
{
    if (target == NULL || value == 0) {
        return;
    }

    if (value > *target) {
        *target = value;
    }
}

static int tiff_parse_subifd_array(TiffContext *ctx, const TiffValueArray *offsets)
{
    size_t i;

    if (ctx == NULL || offsets == NULL) {
        return 0;
    }

    for (i = 0; i < offsets->count; i++) {
        uint64_t child_offset;

        if (!tiff_array_value(ctx, offsets, i, &child_offset)) {
            return 0;
        }

        if (child_offset == 0) {
            continue;
        }

        if (!tiff_parse_ifd(ctx, (size_t)child_offset)) {
            return 0;
        }
    }

    return 1;
}

static int tiff_parse_ifd(TiffContext *ctx, size_t ifd_offset)
{
    size_t entry_count_field_size;
    size_t entry_size;
    size_t next_ifd_size;
    uint64_t entry_count_u64;
    size_t entry_count;
    size_t entries_bytes;
    size_t table_end;
    size_t i;
    TiffValueArray strip_offsets = {0};
    TiffValueArray strip_counts = {0};
    TiffValueArray tile_offsets = {0};
    TiffValueArray tile_counts = {0};
    TiffValueArray jpeg_offsets = {0};
    TiffValueArray jpeg_lengths = {0};
    TiffValueArray free_offsets = {0};
    TiffValueArray free_counts = {0};

    if (ctx == NULL || ifd_offset >= ctx->length) {
        return 0;
    }
    if (tiff_ifd_already_visited(ctx, ifd_offset)) {
        return 1;
    }
    if (!tiff_mark_ifd_visited(ctx, ifd_offset)) {
        return 0;
    }

    entry_count_field_size = ctx->kind == TIFF_KIND_BIG ? 8U : 2U;
    entry_size = ctx->kind == TIFF_KIND_BIG ? 20U : 12U;
    next_ifd_size = ctx->kind == TIFF_KIND_BIG ? 8U : 4U;

    if (ifd_offset + entry_count_field_size > ctx->length) {
        return 0;
    }

    entry_count_u64 = ctx->kind == TIFF_KIND_BIG
        ? read_u64_tiff(ctx->buffer + ifd_offset, ctx->endian)
        : (uint64_t)read_u16_tiff(ctx->buffer + ifd_offset, ctx->endian);

    if (entry_count_u64 > (uint64_t)(SIZE_MAX / entry_size)) {
        return 0;
    }

    entry_count = (size_t)entry_count_u64;
    entries_bytes = entry_count * entry_size;
    table_end = ifd_offset + entry_count_field_size + entries_bytes + next_ifd_size;

    if (table_end < ifd_offset || table_end > ctx->length) {
        return 0;
    }

    ctx->saw_ifd = 1;
    if (table_end > ctx->max_end) {
        ctx->max_end = table_end;
    }

    for (i = 0; i < entry_count; i++) {
        const uint8_t *entry =
            ctx->buffer + ifd_offset + entry_count_field_size + i * entry_size;
        uint16_t tag = read_u16_tiff(entry, ctx->endian);
        uint16_t type = read_u16_tiff(entry + 2, ctx->endian);
        uint64_t count = ctx->kind == TIFF_KIND_BIG
            ? read_u64_tiff(entry + 4, ctx->endian)
            : (uint64_t)read_u32_tiff(entry + 4, ctx->endian);
        const uint8_t *value_data = NULL;
        size_t value_size = 0;
        size_t inline_capacity = 0;
        TiffValueArray array = {0};

        if (tiff_type_width(type) == 0) {
            return 0;
        }

        if (!tiff_entry_value_ptr(
                ctx,
                entry,
                type,
                count,
                &value_data,
                &value_size,
                &inline_capacity)) {
            return 0;
        }

        if (value_size > inline_capacity) {
            uint64_t value_offset = ctx->kind == TIFF_KIND_BIG
                ? read_u64_tiff(entry + 12, ctx->endian)
                : (uint64_t)read_u32_tiff(entry + 8, ctx->endian);

            if (!tiff_note_region(ctx, value_offset, value_size)) {
                return 0;
            }
        }

        array.data = value_data;
        array.type = type;
        array.count = count;

        switch (tag) {
            case 256:
            {
                uint64_t width = 0;

                if (array.count > 0 &&
                    tiff_array_value(ctx, &array, 0, &width)) {
                    tiff_note_dimension(&ctx->max_width, width);
                }
                break;
            }
            case 257:
            {
                uint64_t height = 0;

                if (array.count > 0 &&
                    tiff_array_value(ctx, &array, 0, &height)) {
                    tiff_note_dimension(&ctx->max_height, height);
                }
                break;
            }
            case 273:
                strip_offsets = array;
                break;
            case 279:
                strip_counts = array;
                break;
            case 324:
                tile_offsets = array;
                break;
            case 325:
                tile_counts = array;
                break;
            case 513:
                jpeg_offsets = array;
                break;
            case 514:
                jpeg_lengths = array;
                break;
            case 288:
                free_offsets = array;
                break;
            case 289:
                free_counts = array;
                break;
            case 330:
                if (!tiff_parse_subifd_array(ctx, &array)) {
                    return 0;
                }
                break;
            case 34665:
            case 34853:
            case 40965:
            {
                uint64_t child_offset = 0;

                if (array.count == 0 ||
                    !tiff_array_value(ctx, &array, 0, &child_offset) ||
                    child_offset == 0) {
                    break;
                }

                if (!tiff_parse_ifd(ctx, (size_t)child_offset)) {
                    return 0;
                }
                break;
            }
            default:
                break;
        }
    }

    if (!tiff_note_image_ranges(ctx, &strip_offsets, &strip_counts) ||
        !tiff_note_image_ranges(ctx, &tile_offsets, &tile_counts) ||
        !tiff_note_image_ranges(ctx, &jpeg_offsets, &jpeg_lengths) ||
        !tiff_note_image_ranges(ctx, &free_offsets, &free_counts)) {
        return 0;
    }

    {
        size_t next_offset_pos = ifd_offset + entry_count_field_size + entries_bytes;
        uint64_t next_ifd = ctx->kind == TIFF_KIND_BIG
            ? read_u64_tiff(ctx->buffer + next_offset_pos, ctx->endian)
            : (uint64_t)read_u32_tiff(ctx->buffer + next_offset_pos, ctx->endian);

        if (next_ifd != 0 && !tiff_parse_ifd(ctx, (size_t)next_ifd)) {
            return 0;
        }
    }

    return 1;
}

static int should_skip_small_tiff(const TiffContext *ctx)
{
    if (ctx == NULL) {
        return 0;
    }

    return image_filter_should_skip_image(
        ctx->max_width,
        ctx->max_height,
        ctx->max_end
    );
}

static void log_filtered_tiff_local(
    size_t absolute_offset,
    const TiffContext *ctx
)
{
    if (ctx == NULL) {
        return;
    }
    filtered_image_log_append_current(
        "raw-carver",
        "tif",
        "small_image_filtered",
        (uint64_t)absolute_offset,
        0U,
        ctx->max_end,
        ctx->max_width,
        ctx->max_height,
        NULL
    );
}

static int write_tiff_file(
    const uint8_t *buffer,
    size_t start_offset,
    size_t file_size,
    size_t absolute_offset
)
{
    return carver_output_write_buffer(
        (long long)absolute_offset,
        APP_DEFAULT_UNIDENT_DIR,
        "recov",
        "tif",
        buffer + start_offset,
        file_size
    );
}

int carver_tiff_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    TiffContext ctx;
    uint16_t version;
    uint64_t first_ifd;
    size_t available_length;

    carver_tiff_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0;
    }
    if (buffer == NULL || start_offset >= buffer_length) {
        carver_audit_set_inline(&g_tiff_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    available_length = buffer_length - start_offset;
    if (available_length < TIFF_MIN_FILE_SIZE) {
        carver_audit_set_inline(&g_tiff_last_audit, "rejected", "too_small", 0U);
        return 0;
    }

    memset(&ctx, 0, sizeof(ctx));
    ctx.buffer = buffer + start_offset;
    ctx.length = available_length;

    if (ctx.buffer[0] == 'I' && ctx.buffer[1] == 'I') {
        ctx.endian = TIFF_ENDIAN_LITTLE;
    } else if (ctx.buffer[0] == 'M' && ctx.buffer[1] == 'M') {
        ctx.endian = TIFF_ENDIAN_BIG;
    } else {
        carver_audit_set_inline(&g_tiff_last_audit, "rejected", "missing_tiff_byte_order", 0U);
        return 0;
    }

    version = read_u16_tiff(ctx.buffer + 2, ctx.endian);
    if (version == 42U) {
        ctx.kind = TIFF_KIND_CLASSIC;
        first_ifd = (uint64_t)read_u32_tiff(ctx.buffer + 4, ctx.endian);
        ctx.max_end = 8U;
    } else if (version == 43U) {
        if (ctx.length < 16U ||
            read_u16_tiff(ctx.buffer + 4, ctx.endian) != 8U ||
            read_u16_tiff(ctx.buffer + 6, ctx.endian) != 0U) {
            carver_audit_set_inline(&g_tiff_last_audit, "rejected", "invalid_bigtiff_header", 0U);
            return 0;
        }
        ctx.kind = TIFF_KIND_BIG;
        first_ifd = read_u64_tiff(ctx.buffer + 8, ctx.endian);
        ctx.max_end = 16U;
    } else {
        carver_audit_set_inline(&g_tiff_last_audit, "rejected", "unsupported_tiff_version", 0U);
        return 0;
    }

    if (first_ifd == 0 || first_ifd >= (uint64_t)ctx.length) {
        carver_audit_set_inline(&g_tiff_last_audit, "rejected", "invalid_first_ifd", 0U);
        return 0;
    }

    if (!tiff_parse_ifd(&ctx, (size_t)first_ifd)) {
        carver_audit_set_inline(&g_tiff_last_audit, "rejected", "invalid_ifd_tree", 0U);
        return 0;
    }

    if (!ctx.saw_ifd || !ctx.saw_image_payload || ctx.max_end < TIFF_MIN_FILE_SIZE) {
        carver_audit_set_inline(&g_tiff_last_audit, "rejected", "missing_image_payload", 0U);
        return 0;
    }

    if (should_skip_small_tiff(&ctx)) {
        if (confirmed_span_out != NULL) {
            *confirmed_span_out = ctx.max_end;
        }
        log_filtered_tiff_local(absolute_offset, &ctx);
        carver_audit_set_inline(
            &g_tiff_last_audit,
            "skipped",
            "small_image_filtered",
            ctx.max_end);
        return 1;
    }

    if (!write_tiff_file(
            buffer,
            start_offset,
            ctx.max_end,
            absolute_offset)) {
        carver_audit_set_inline(
            &g_tiff_last_audit,
            "rejected",
            "write_failed",
            ctx.max_end);
        return 0;
    }

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = ctx.max_end;
    }
    carver_audit_set_inline(
        &g_tiff_last_audit,
        "recovered",
        "accepted",
        ctx.max_end);
    return 1;
}
