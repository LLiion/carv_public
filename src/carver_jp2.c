#include "carver_jp2.h"

#include "carver_output.h"
#include "config.h"
#include "filtered_image_log.h"
#include "image_filter.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define JP2_SIGNATURE_SIZE 12U
#define JP2_MIN_FILE_SIZE 64U
#define JP2_MAX_DIMENSION 200000U

typedef struct {
    int valid_signature;
    int saw_ftyp;
    int saw_jp2h;
    int saw_ihdr;
    int saw_jp2c;
    uint32_t width;
    uint32_t height;
    size_t file_size;
    size_t consumed_prefix;
} Jp2Analysis;

static CarverAuditReport g_jp2_last_audit;

void carver_jp2_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_jp2_last_audit);
}

void carver_jp2_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_jp2_last_audit;
}

static uint32_t read_u32_be_local(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static uint64_t read_u64_be_local(const uint8_t *data)
{
    uint64_t value = 0;
    size_t i;

    for (i = 0; i < 8U; i++) {
        value = (value << 8) | (uint64_t)data[i];
    }

    return value;
}

static int is_known_top_level_box_type(const uint8_t *type)
{
    static const char *known_types[] = {
        "ftyp", "jp2h", "jp2c", "jp2i", "xml ", "uuid",
        "uinf", "ulst", "url ", "res ", "resc", "resd"
    };
    size_t i;

    if (type == NULL) {
        return 0;
    }

    for (i = 0; i < sizeof(known_types) / sizeof(known_types[0]); i++) {
        if (memcmp(type, known_types[i], 4U) == 0) {
            return 1;
        }
    }

    return 0;
}

static int is_known_jp2h_box_type(const uint8_t *type)
{
    static const char *known_types[] = {
        "ihdr", "bpcc", "colr", "pclr", "cmap", "cdef",
        "res ", "resc", "resd"
    };
    size_t i;

    if (type == NULL) {
        return 0;
    }

    for (i = 0; i < sizeof(known_types) / sizeof(known_types[0]); i++) {
        if (memcmp(type, known_types[i], 4U) == 0) {
            return 1;
        }
    }

    return 0;
}

static int parse_jp2h_box(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t box_offset,
    size_t box_size,
    Jp2Analysis *analysis
)
{
    size_t cursor;
    size_t box_end;

    if (buffer == NULL || analysis == NULL) {
        return 0;
    }
    if (box_size < 8U || box_offset + box_size > buffer_length) {
        return 0;
    }

    analysis->saw_jp2h = 1;
    cursor = box_offset + 8U;
    box_end = box_offset + box_size;

    while (cursor + 8U <= box_end) {
        uint64_t child_size = (uint64_t)read_u32_be_local(buffer + cursor);
        const uint8_t *child_type = buffer + cursor + 4U;
        size_t child_header_size = 8U;
        uint64_t actual_child_size;

        if (child_size == 1U) {
            if (cursor + 16U > box_end) {
                return 0;
            }
            actual_child_size = read_u64_be_local(buffer + cursor + 8U);
            child_header_size = 16U;
        } else if (child_size == 0U) {
            actual_child_size = (uint64_t)(box_end - cursor);
        } else {
            actual_child_size = child_size;
        }

        if (actual_child_size < child_header_size ||
            actual_child_size > (uint64_t)(box_end - cursor) ||
            !is_known_jp2h_box_type(child_type)) {
            return 0;
        }

        if (memcmp(child_type, "ihdr", 4U) == 0) {
            if (actual_child_size < child_header_size + 14U) {
                return 0;
            }

            analysis->height = read_u32_be_local(buffer + cursor + child_header_size);
            analysis->width = read_u32_be_local(buffer + cursor + child_header_size + 4U);
            if (analysis->width == 0U || analysis->height == 0U ||
                analysis->width > JP2_MAX_DIMENSION ||
                analysis->height > JP2_MAX_DIMENSION) {
                return 0;
            }
            analysis->saw_ihdr = 1;
        }

        cursor += (size_t)actual_child_size;
    }

    return cursor == box_end;
}

static int has_full_signature_at(const uint8_t *buffer, size_t buffer_length, size_t offset)
{
    static const uint8_t signature[JP2_SIGNATURE_SIZE] = {
        0x00, 0x00, 0x00, 0x0C,
        0x6A, 0x50, 0x20, 0x20,
        0x0D, 0x0A, 0x87, 0x0A
    };

    if (buffer == NULL || offset + JP2_SIGNATURE_SIZE > buffer_length) {
        return 0;
    }

    return memcmp(buffer + offset, signature, sizeof(signature)) == 0;
}

static Jp2Analysis analyze_jp2_candidate(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset
)
{
    Jp2Analysis result = {0};
    size_t actual_start = start_offset;
    size_t cursor;
    size_t last_valid_end = 0;

    if (buffer == NULL || start_offset >= buffer_length) {
        return result;
    }

    if (has_full_signature_at(buffer, buffer_length, start_offset)) {
        actual_start = start_offset;
    } else if (start_offset >= 3U &&
               has_full_signature_at(buffer, buffer_length, start_offset - 3U)) {
        actual_start = start_offset - 3U;
    } else {
        return result;
    }

    result.valid_signature = 1;
    result.consumed_prefix = start_offset - actual_start;
    cursor = actual_start + JP2_SIGNATURE_SIZE;
    last_valid_end = cursor;

    while (cursor + 8U <= buffer_length) {
        uint64_t box_size = (uint64_t)read_u32_be_local(buffer + cursor);
        const uint8_t *box_type = buffer + cursor + 4U;
        size_t box_header_size = 8U;
        uint64_t actual_box_size;

        if (box_size == 1U) {
            if (cursor + 16U > buffer_length) {
                break;
            }
            actual_box_size = read_u64_be_local(buffer + cursor + 8U);
            box_header_size = 16U;
        } else if (box_size == 0U) {
            actual_box_size = (uint64_t)(buffer_length - cursor);
        } else {
            actual_box_size = box_size;
        }

        if (actual_box_size < box_header_size ||
            actual_box_size > (uint64_t)(buffer_length - cursor) ||
            !is_known_top_level_box_type(box_type)) {
            break;
        }

        if (memcmp(box_type, "ftyp", 4U) == 0) {
            if (actual_box_size < box_header_size + 8U) {
                return (Jp2Analysis){0};
            }
            result.saw_ftyp = 1;
        } else if (memcmp(box_type, "jp2h", 4U) == 0) {
            if (!parse_jp2h_box(
                    buffer,
                    buffer_length,
                    cursor,
                    (size_t)actual_box_size,
                    &result)) {
                return (Jp2Analysis){0};
            }
        } else if (memcmp(box_type, "jp2c", 4U) == 0) {
            if (actual_box_size <= box_header_size) {
                return (Jp2Analysis){0};
            }
            result.saw_jp2c = 1;
        }

        cursor += (size_t)actual_box_size;
        last_valid_end = cursor;

        if (box_size == 0U) {
            break;
        }
    }

    if (!result.valid_signature ||
        !result.saw_ftyp ||
        !result.saw_jp2h ||
        !result.saw_ihdr ||
        !result.saw_jp2c ||
        last_valid_end <= actual_start) {
        return (Jp2Analysis){0};
    }

    result.file_size = last_valid_end - actual_start;
    return result;
}

static int should_skip_small_jp2(const Jp2Analysis *analysis)
{
    if (analysis == NULL) {
        return 0;
    }

    return image_filter_should_skip_image(
        analysis->width,
        analysis->height,
        analysis->file_size
    );
}

static void log_filtered_jp2_local(
    size_t absolute_offset,
    const Jp2Analysis *analysis
)
{
    if (analysis == NULL) {
        return;
    }
    filtered_image_log_append_current(
        "raw-carver",
        "jp2",
        "small_image_filtered",
        (uint64_t)absolute_offset,
        0U,
        (uint64_t)analysis->file_size,
        (uint64_t)analysis->width,
        (uint64_t)analysis->height,
        NULL
    );
}

static int write_jp2_file(
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
        "jp2",
        buffer + start_offset,
        file_size
    );
}

int carver_jp2_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    Jp2Analysis analysis;
    size_t actual_start;
    size_t actual_absolute_offset;

    carver_jp2_reset_last_audit();
    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0;
    }
    if (buffer == NULL || start_offset >= buffer_length) {
        carver_audit_set_inline(&g_jp2_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }

    analysis = analyze_jp2_candidate(buffer, buffer_length, start_offset);
    if (!analysis.valid_signature || analysis.file_size < JP2_MIN_FILE_SIZE) {
        carver_audit_set_inline(&g_jp2_last_audit, "rejected", "invalid_jp2_structure", 0U);
        return 0;
    }

    actual_start = start_offset - analysis.consumed_prefix;
    actual_absolute_offset = absolute_offset - analysis.consumed_prefix;

    if (should_skip_small_jp2(&analysis)) {
        if (confirmed_span_out != NULL) {
            *confirmed_span_out = analysis.file_size - analysis.consumed_prefix;
        }
        log_filtered_jp2_local(actual_absolute_offset, &analysis);
        carver_audit_set_inline(
            &g_jp2_last_audit,
            "skipped",
            "small_image_filtered",
            analysis.file_size - analysis.consumed_prefix);
        return 1;
    }

    if (!write_jp2_file(
            buffer,
            actual_start,
            analysis.file_size,
            actual_absolute_offset)) {
        carver_audit_set_inline(
            &g_jp2_last_audit,
            "rejected",
            "write_failed",
            analysis.file_size - analysis.consumed_prefix);
        return 0;
    }

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = analysis.file_size - analysis.consumed_prefix;
    }
    carver_audit_set_inline(
        &g_jp2_last_audit,
        "recovered",
        "accepted",
        analysis.file_size - analysis.consumed_prefix);
    return 1;
}
