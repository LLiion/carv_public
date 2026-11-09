#include "carver_archive.h"

#include "carver_output.h"
#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define RAR4_MARKER_SIZE 7U
#define RAR4_BLOCK_BASE_SIZE 7U
#define RAR4_LONG_BLOCK_FLAG 0x8000U
#define RAR5_MARKER_SIZE 8U
#define RAR5_HEADER_CRC_SIZE 4U
#define RAR5_MAX_HEADER_SIZE (2U * 1024U * 1024U)
#define RAR5_PEEK_BYTES 64U
#define RAR5_BLOCK_FLAG_EXTRA 0x0001U
#define RAR5_BLOCK_FLAG_DATA 0x0002U
#define RAR_MAX_REASONABLE_FILE_SIZE (64ULL * 1024ULL * 1024ULL * 1024ULL)
#define SEVEN_Z_SIGNATURE_SIZE 6U
#define SEVEN_Z_SIGNATURE_HEADER_SIZE 32U
#define SEVEN_Z_START_HEADER_SIZE 20U
#define SEVEN_Z_MAX_REASONABLE_FILE_SIZE (64ULL * 1024ULL * 1024ULL * 1024ULL)
#define ISO_SECTOR_SIZE 2048U
#define ISO_PVD_SECTOR_INDEX 16U
#define ISO_PVD_ID_OFFSET 1U
#define ISO_PVD_ID_SIZE 5U
#define ISO_PVD_VERSION_OFFSET 6U
#define ISO_PVD_VOLUME_SPACE_SIZE_OFFSET 80U
#define ISO_PVD_LOGICAL_BLOCK_SIZE_OFFSET 128U
#define ISO_MAX_DESCRIPTOR_SCAN 64U
#define ISO_MAX_REASONABLE_FILE_SIZE (64ULL * 1024ULL * 1024ULL * 1024ULL)

static CarverAuditReport g_rar_last_audit;
static CarverAuditReport g_7z_last_audit;
static CarverAuditReport g_iso_last_audit;

void carver_rar_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_rar_last_audit);
}

void carver_rar_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_rar_last_audit;
}

void carver_7z_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_7z_last_audit);
}

void carver_7z_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_7z_last_audit;
}

void carver_iso_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_iso_last_audit);
}

void carver_iso_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_iso_last_audit;
}

static uint64_t reader_buffer_base_absolute(const Reader *reader)
{
    if (reader == NULL) {
        return 0;
    }
    if ((uint64_t)reader->bytes_in_buffer > (uint64_t)reader->total_bytes_read) {
        return 0;
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
    size_t copied = 0;

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
            if (reader_read_next(reader) == 0) {
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
            if (reader_read_next(reader) == 0) {
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

        if (fwrite(reader->buffer + buffer_offset, 1, write_now, output_file) != write_now) {
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
    if (resume_abs < base_abs ||
        resume_abs >= base_abs + (uint64_t)reader->bytes_in_buffer) {
        *resume_offset_out = fallback_offset + 1U;
        return 1;
    }

    *resume_offset_out = (size_t)(resume_abs - base_abs);
    return 1;
}

static uint16_t read_u16_le_local(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t read_u32_le_local(const uint8_t *data)
{
    return ((uint32_t)data[0]) |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint64_t read_u64_le_local(const uint8_t *data)
{
    return ((uint64_t)data[0]) |
           ((uint64_t)data[1] << 8) |
           ((uint64_t)data[2] << 16) |
           ((uint64_t)data[3] << 24) |
           ((uint64_t)data[4] << 32) |
           ((uint64_t)data[5] << 40) |
           ((uint64_t)data[6] << 48) |
           ((uint64_t)data[7] << 56);
}

static uint32_t g_crc32_table_local[256];
static int g_crc32_ready_local = 0;

static void crc32_init_local(void)
{
    uint32_t i;

    if (g_crc32_ready_local) {
        return;
    }

    for (i = 0; i < 256U; i++) {
        uint32_t value = i;
        unsigned bit;

        for (bit = 0; bit < 8U; bit++) {
            if ((value & 1U) != 0U) {
                value = (value >> 1) ^ 0xEDB88320U;
            } else {
                value >>= 1;
            }
        }

        g_crc32_table_local[i] = value;
    }

    g_crc32_ready_local = 1;
}

static uint32_t crc32_update_local(
    uint32_t crc,
    const uint8_t *buffer,
    size_t length
)
{
    size_t i;

    if (buffer == NULL || length == 0U) {
        return crc;
    }

    crc32_init_local();
    for (i = 0; i < length; i++) {
        crc = (crc >> 8) ^ g_crc32_table_local[(crc ^ buffer[i]) & 0xFFU];
    }

    return crc;
}

static uint32_t crc32_compute_local(const void *buffer, size_t length)
{
    uint32_t crc = 0xFFFFFFFFU;

    crc = crc32_update_local(crc, (const uint8_t *)buffer, length);
    return crc ^ 0xFFFFFFFFU;
}

static int copy_stream_bytes_with_crc32_window(
    Reader *reader,
    FILE *output_file,
    uint64_t start_abs,
    uint64_t byte_count,
    uint64_t crc_window_start_abs,
    uint64_t crc_window_length,
    uint32_t *crc_out
)
{
    uint64_t current_abs = start_abs;
    uint64_t remaining = byte_count;
    uint64_t crc_window_end_abs;
    uint32_t crc = 0xFFFFFFFFU;

    if (reader == NULL || output_file == NULL || crc_out == NULL) {
        return 0;
    }

    if (crc_window_start_abs > UINT64_MAX - crc_window_length) {
        return 0;
    }
    crc_window_end_abs = crc_window_start_abs + crc_window_length;

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
            if (reader_read_next(reader) == 0) {
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

        if (fwrite(reader->buffer + buffer_offset, 1, write_now, output_file) != write_now) {
            return 0;
        }

        if (current_abs < crc_window_end_abs &&
            current_abs + (uint64_t)write_now > crc_window_start_abs) {
            uint64_t overlap_start_abs =
                current_abs > crc_window_start_abs ? current_abs : crc_window_start_abs;
            uint64_t overlap_end_abs =
                current_abs + (uint64_t)write_now < crc_window_end_abs
                    ? current_abs + (uint64_t)write_now
                    : crc_window_end_abs;
            size_t crc_offset = (size_t)(overlap_start_abs - current_abs);
            size_t crc_len = (size_t)(overlap_end_abs - overlap_start_abs);

            crc = crc32_update_local(
                crc,
                reader->buffer + buffer_offset + crc_offset,
                crc_len
            );
        }

        current_abs += (uint64_t)write_now;
        remaining -= (uint64_t)write_now;
    }

    *crc_out = crc ^ 0xFFFFFFFFU;
    return 1;
}

static int rar4_head_type_valid(uint8_t head_type)
{
    return head_type >= 0x73U && head_type <= 0x7BU;
}

static int rar5_head_type_valid(uint64_t head_type)
{
    return head_type >= 1U && head_type <= 5U;
}

static int rar5_read_vint_local(
    const uint8_t *data,
    size_t available,
    uint64_t *value_out,
    size_t *used_out
)
{
    uint64_t value = 0U;
    unsigned shift = 0U;
    size_t used = 0U;

    if (data == NULL || value_out == NULL || used_out == NULL) {
        return 0;
    }

    while (used < available && used < 10U) {
        uint8_t byte = data[used++];

        value |= (uint64_t)(byte & 0x7FU) << shift;
        if ((byte & 0x80U) == 0U) {
            *value_out = value;
            *used_out = used;
            return 1;
        }
        shift += 7U;
    }

    return 0;
}

static int carver_rar4_streaming_local(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    static const uint8_t rar4_marker[RAR4_MARKER_SIZE] =
        {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
    uint8_t marker[RAR4_MARKER_SIZE];
    uint64_t start_abs = (uint64_t)absolute_offset;
    uint64_t cursor_abs = start_abs + RAR4_MARKER_SIZE;
    uint64_t last_resume_abs = start_abs;
    CarverOutput output = {0};
    int saw_main = 0;
    int saw_end = 0;
    unsigned block_count = 0;

    if (reader == NULL || resume_offset == NULL) {
        return 0;
    }
    *resume_offset = start_offset + 1U;

    if (!read_stream_bytes(reader, start_abs, marker, sizeof(marker))) {
        return 0;
    }
    if (memcmp(marker, rar4_marker, sizeof(marker)) != 0) {
        return 0;
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "rar")) {
        return 0;
    }

    if (!copy_stream_bytes(reader, output.file, start_abs, RAR4_MARKER_SIZE)) {
        carver_output_abort(&output);
        return 0;
    }
    last_resume_abs = cursor_abs;

    while (1) {
        uint8_t header[11];
        uint16_t flags;
        uint16_t head_size;
        uint32_t add_size = 0;
        uint64_t total_block_size;
        uint8_t head_type;

        if (!read_stream_bytes(reader, cursor_abs, header, RAR4_BLOCK_BASE_SIZE)) {
            break;
        }

        head_type = header[2];
        flags = read_u16_le_local(header + 3);
        head_size = read_u16_le_local(header + 5);

        if (!rar4_head_type_valid(head_type) ||
            head_size < RAR4_BLOCK_BASE_SIZE) {
            break;
        }

        if ((flags & RAR4_LONG_BLOCK_FLAG) != 0U) {
            if (!read_stream_bytes(reader, cursor_abs, header, sizeof(header))) {
                break;
            }
            if (head_size < sizeof(header)) {
                break;
            }
            add_size = read_u32_le_local(header + 7);
        }

        total_block_size = (uint64_t)head_size + (uint64_t)add_size;
        if (total_block_size < (uint64_t)head_size ||
            total_block_size == 0U ||
            total_block_size > RAR_MAX_REASONABLE_FILE_SIZE) {
            break;
        }
        if (cursor_abs - start_abs + total_block_size > RAR_MAX_REASONABLE_FILE_SIZE) {
            carver_output_abort(&output);
            return 0;
        }

        if (!copy_stream_bytes(reader, output.file, cursor_abs, total_block_size)) {
            carver_output_abort(&output);
            return 0;
        }

        if (head_type == 0x73U) {
            saw_main = 1;
        } else if (head_type == 0x7BU) {
            saw_end = 1;
        }

        cursor_abs += total_block_size;
        last_resume_abs = cursor_abs;
        block_count++;

        if (saw_end) {
            break;
        }
    }

    if (!saw_main || !saw_end || block_count < 2U) {
        carver_output_abort(&output);
        return 0;
    }

    if (!carver_output_finish(&output)) {
        return 0;
    }

    compute_resume_offset_local(reader, last_resume_abs, start_offset, resume_offset);
    return 1;
}

static int carver_rar5_streaming_local(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    static const uint8_t rar5_marker[RAR5_MARKER_SIZE] =
        {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};
    uint8_t marker[RAR5_MARKER_SIZE];
    uint8_t prefix[RAR5_HEADER_CRC_SIZE + 10U];
    uint8_t header_peek[RAR5_PEEK_BYTES];
    uint64_t start_abs = (uint64_t)absolute_offset;
    uint64_t cursor_abs = start_abs + RAR5_MARKER_SIZE;
    uint64_t last_resume_abs = start_abs;
    CarverOutput output = {0};
    int saw_main = 0;
    int saw_end = 0;
    unsigned block_count = 0;

    if (reader == NULL || resume_offset == NULL) {
        return 0;
    }
    *resume_offset = start_offset + 1U;

    if (!read_stream_bytes(reader, start_abs, marker, sizeof(marker))) {
        return 0;
    }
    if (memcmp(marker, rar5_marker, sizeof(marker)) != 0) {
        return 0;
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "rar")) {
        return 0;
    }

    if (!copy_stream_bytes(reader, output.file, start_abs, RAR5_MARKER_SIZE)) {
        carver_output_abort(&output);
        return 0;
    }
    last_resume_abs = cursor_abs;

    while (1) {
        uint64_t header_size;
        uint64_t header_flags;
        uint64_t header_type;
        uint64_t data_size = 0U;
        uint64_t total_block_size;
        size_t header_size_used;
        size_t header_peek_len;
        size_t used;
        size_t pos;

        if (!read_stream_bytes(reader, cursor_abs, prefix, sizeof(prefix))) {
            break;
        }
        if (!rar5_read_vint_local(
                prefix + RAR5_HEADER_CRC_SIZE,
                sizeof(prefix) - RAR5_HEADER_CRC_SIZE,
                &header_size,
                &header_size_used)) {
            break;
        }
        if (header_size == 0U || header_size > RAR5_MAX_HEADER_SIZE) {
            break;
        }

        header_peek_len = (size_t)header_size;
        if (header_peek_len > sizeof(header_peek)) {
            header_peek_len = sizeof(header_peek);
        }
        if (!read_stream_bytes(
                reader,
                cursor_abs + RAR5_HEADER_CRC_SIZE + (uint64_t)header_size_used,
                header_peek,
                header_peek_len)) {
            break;
        }

        pos = 0U;
        if (!rar5_read_vint_local(header_peek + pos, header_peek_len - pos, &header_type, &used)) {
            break;
        }
        pos += used;
        if (!rar5_read_vint_local(header_peek + pos, header_peek_len - pos, &header_flags, &used)) {
            break;
        }
        pos += used;

        if (!rar5_head_type_valid(header_type)) {
            break;
        }
        if ((header_flags & RAR5_BLOCK_FLAG_EXTRA) != 0U) {
            uint64_t extra_size;

            if (!rar5_read_vint_local(header_peek + pos, header_peek_len - pos, &extra_size, &used)) {
                break;
            }
            pos += used;
        }
        if ((header_flags & RAR5_BLOCK_FLAG_DATA) != 0U) {
            if (!rar5_read_vint_local(header_peek + pos, header_peek_len - pos, &data_size, &used)) {
                break;
            }
            pos += used;
        }

        total_block_size =
            (uint64_t)RAR5_HEADER_CRC_SIZE +
            (uint64_t)header_size_used +
            header_size +
            data_size;
        if (total_block_size == 0U ||
            total_block_size > RAR_MAX_REASONABLE_FILE_SIZE ||
            cursor_abs - start_abs + total_block_size > RAR_MAX_REASONABLE_FILE_SIZE) {
            break;
        }

        if (!copy_stream_bytes(reader, output.file, cursor_abs, total_block_size)) {
            carver_output_abort(&output);
            return 0;
        }

        if (header_type == 1U) {
            saw_main = 1;
        } else if (header_type == 5U) {
            saw_end = 1;
        }

        cursor_abs += total_block_size;
        last_resume_abs = cursor_abs;
        block_count++;

        if (saw_end) {
            break;
        }
    }

    if (!saw_main || !saw_end || block_count < 2U) {
        carver_output_abort(&output);
        return 0;
    }

    if (!carver_output_finish(&output)) {
        return 0;
    }

    compute_resume_offset_local(reader, last_resume_abs, start_offset, resume_offset);
    return 1;
}

int carver_rar_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    static const uint8_t rar4_marker[RAR4_MARKER_SIZE] =
        {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00};
    static const uint8_t rar5_marker[RAR5_MARKER_SIZE] =
        {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00};
    uint8_t marker[RAR5_MARKER_SIZE];
    uint64_t start_abs = (uint64_t)absolute_offset;
    int ok;

    carver_rar_reset_last_audit();
    if (reader == NULL || resume_offset == NULL) {
        carver_audit_set_inline(&g_rar_last_audit, "rejected", "invalid_input", 0U);
        return 0;
    }
    *resume_offset = start_offset + 1U;

    if (!read_stream_bytes(reader, start_abs, marker, sizeof(marker))) {
        carver_audit_set_inline(&g_rar_last_audit, "rejected", "read_header_failed", 0U);
        return 0;
    }
    if (memcmp(marker, rar5_marker, sizeof(marker)) == 0) {
        ok = carver_rar5_streaming_local(reader, start_offset, absolute_offset, resume_offset);
        carver_audit_set_inline(
            &g_rar_last_audit,
            ok ? "recovered" : "rejected",
            ok ? "accepted_rar5" : "rar5_parser_rejected",
            ok && *resume_offset > start_offset ? *resume_offset - start_offset : 0U);
        return ok;
    }
    if (memcmp(marker, rar4_marker, sizeof(rar4_marker)) == 0) {
        ok = carver_rar4_streaming_local(reader, start_offset, absolute_offset, resume_offset);
        carver_audit_set_inline(
            &g_rar_last_audit,
            ok ? "recovered" : "rejected",
            ok ? "accepted_rar4" : "rar4_parser_rejected",
            ok && *resume_offset > start_offset ? *resume_offset - start_offset : 0U);
        return ok;
    }

    carver_audit_set_inline(&g_rar_last_audit, "rejected", "missing_rar_marker", 0U);
    return 0;
}

int carver_7z_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    static const uint8_t seven_z_signature[SEVEN_Z_SIGNATURE_SIZE] =
        {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
    uint8_t header[SEVEN_Z_SIGNATURE_HEADER_SIZE];
    uint64_t start_abs = (uint64_t)absolute_offset;
    uint64_t next_header_offset;
    uint64_t next_header_size;
    uint64_t next_header_abs;
    uint64_t total_size;
    uint32_t stored_start_header_crc;
    uint32_t stored_next_header_crc;
    uint32_t computed_next_header_crc = 0U;
    CarverOutput output = {0};

#define SEVEN_Z_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_7z_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    carver_7z_reset_last_audit();
    if (reader == NULL || resume_offset == NULL) {
        SEVEN_Z_REJECT("invalid_input", 0U);
    }
    *resume_offset = start_offset + 1U;

    if (!read_stream_bytes(reader, start_abs, header, sizeof(header))) {
        SEVEN_Z_REJECT("read_header_failed", 0U);
    }
    if (memcmp(header, seven_z_signature, sizeof(seven_z_signature)) != 0) {
        SEVEN_Z_REJECT("missing_7z_signature", 0U);
    }

    stored_start_header_crc = read_u32_le_local(header + 8U);
    if (stored_start_header_crc !=
        crc32_compute_local(header + 12U, SEVEN_Z_START_HEADER_SIZE)) {
        SEVEN_Z_REJECT("start_header_crc_mismatch", 0U);
    }

    next_header_offset = read_u64_le_local(header + 12U);
    next_header_size = read_u64_le_local(header + 20U);
    stored_next_header_crc = read_u32_le_local(header + 28U);

    if (next_header_size == 0U) {
        SEVEN_Z_REJECT("empty_next_header", 0U);
    }
    if (next_header_offset > UINT64_MAX - SEVEN_Z_SIGNATURE_HEADER_SIZE ||
        next_header_offset > SEVEN_Z_MAX_REASONABLE_FILE_SIZE ||
        next_header_size > SEVEN_Z_MAX_REASONABLE_FILE_SIZE ||
        next_header_offset > UINT64_MAX - next_header_size - SEVEN_Z_SIGNATURE_HEADER_SIZE) {
        SEVEN_Z_REJECT("size_over_cap", 0U);
    }

    next_header_abs = start_abs + SEVEN_Z_SIGNATURE_HEADER_SIZE + next_header_offset;
    total_size = SEVEN_Z_SIGNATURE_HEADER_SIZE + next_header_offset + next_header_size;
    if (next_header_abs < start_abs ||
        total_size < SEVEN_Z_SIGNATURE_HEADER_SIZE ||
        total_size > SEVEN_Z_MAX_REASONABLE_FILE_SIZE) {
        SEVEN_Z_REJECT("invalid_total_size", 0U);
    }
    if (reader->source_size > 0U &&
        (start_abs >= reader->source_size ||
         total_size > reader->source_size - start_abs)) {
        SEVEN_Z_REJECT("source_eof_before_end", 0U);
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "7z")) {
        SEVEN_Z_REJECT("output_open_failed", 0U);
    }

    if (!copy_stream_bytes_with_crc32_window(
            reader,
            output.file,
            start_abs,
            total_size,
            next_header_abs,
            next_header_size,
            &computed_next_header_crc)) {
        carver_output_abort(&output);
        SEVEN_Z_REJECT("write_failed", 0U);
    }

    if (computed_next_header_crc != stored_next_header_crc) {
        carver_output_abort(&output);
        SEVEN_Z_REJECT("next_header_crc_mismatch", total_size);
    }

    if (!carver_output_finish(&output)) {
        SEVEN_Z_REJECT("finish_failed", total_size);
    }

    compute_resume_offset_local(
        reader,
        start_abs + total_size,
        start_offset,
        resume_offset
    );
    carver_audit_set_inline(
        &g_7z_last_audit,
        "recovered",
        "accepted",
        carver_audit_span_from_u64(total_size));
#undef SEVEN_Z_REJECT
    return 1;
}

static int iso_read_pvd(
    Reader *reader,
    uint64_t iso_start_abs,
    uint8_t pvd[ISO_SECTOR_SIZE]
)
{
    uint64_t pvd_abs = iso_start_abs + ((uint64_t)ISO_PVD_SECTOR_INDEX * ISO_SECTOR_SIZE);

    if (reader == NULL || pvd == NULL) {
        return 0;
    }

    return read_stream_bytes(reader, pvd_abs, pvd, ISO_SECTOR_SIZE);
}

static int iso_has_terminator_descriptor(
    Reader *reader,
    uint64_t iso_start_abs
)
{
    uint8_t descriptor[7];
    uint64_t sector_index;

    if (reader == NULL) {
        return 0;
    }

    for (sector_index = ISO_PVD_SECTOR_INDEX + 1U;
         sector_index <= ISO_PVD_SECTOR_INDEX + ISO_MAX_DESCRIPTOR_SCAN;
         sector_index++) {
        uint64_t abs = iso_start_abs + sector_index * ISO_SECTOR_SIZE;

        if (!read_stream_bytes(reader, abs, descriptor, sizeof(descriptor))) {
            return 0;
        }
        if (descriptor[0] == 255U &&
            memcmp(descriptor + 1, "CD001", 5) == 0 &&
            descriptor[6] == 1U) {
            return 1;
        }
    }

    return 0;
}

int carver_iso_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    uint8_t pvd[ISO_SECTOR_SIZE];
    uint64_t iso_start_abs;
    uint64_t volume_space_size;
    uint64_t logical_block_size;
    uint64_t total_size;
    CarverOutput output = {0};

#define ISO_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_iso_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    carver_iso_reset_last_audit();
    if (reader == NULL || resume_offset == NULL) {
        ISO_REJECT("invalid_input", 0U);
    }
    *resume_offset = start_offset + 1U;

    if (absolute_offset < (ISO_PVD_SECTOR_INDEX * ISO_SECTOR_SIZE) + ISO_PVD_ID_OFFSET) {
        ISO_REJECT("invalid_pvd_offset", 0U);
    }

    iso_start_abs = (uint64_t)absolute_offset -
                    ((uint64_t)ISO_PVD_SECTOR_INDEX * ISO_SECTOR_SIZE) -
                    ISO_PVD_ID_OFFSET;

    if (!iso_read_pvd(reader, iso_start_abs, pvd)) {
        ISO_REJECT("read_pvd_failed", 0U);
    }

    if (pvd[0] != 1U ||
        memcmp(pvd + ISO_PVD_ID_OFFSET, "CD001", ISO_PVD_ID_SIZE) != 0 ||
        pvd[ISO_PVD_VERSION_OFFSET] != 1U) {
        ISO_REJECT("invalid_pvd", 0U);
    }

    logical_block_size = (uint64_t)read_u16_le_local(pvd + ISO_PVD_LOGICAL_BLOCK_SIZE_OFFSET);
    volume_space_size = (uint64_t)read_u32_le_local(pvd + ISO_PVD_VOLUME_SPACE_SIZE_OFFSET);

    if ((logical_block_size != 512U &&
         logical_block_size != 1024U &&
         logical_block_size != 2048U &&
        logical_block_size != 4096U) ||
        volume_space_size < 17U) {
        ISO_REJECT("invalid_volume_geometry", 0U);
    }

    total_size = logical_block_size * volume_space_size;
    if (total_size < 17U * logical_block_size ||
        total_size > ISO_MAX_REASONABLE_FILE_SIZE) {
        ISO_REJECT("size_over_cap", 0U);
    }
    if (reader->source_size > 0U &&
        (iso_start_abs >= reader->source_size ||
         total_size > reader->source_size - iso_start_abs)) {
        ISO_REJECT("source_eof_before_end", 0U);
    }
    if (!iso_has_terminator_descriptor(reader, iso_start_abs)) {
        ISO_REJECT("missing_terminator_descriptor", 0U);
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)iso_start_abs,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "iso")) {
        ISO_REJECT("output_open_failed", 0U);
    }

    if (!copy_stream_bytes(reader, output.file, iso_start_abs, total_size)) {
        carver_output_abort(&output);
        ISO_REJECT("write_failed", 0U);
    }

    if (!carver_output_finish(&output)) {
        ISO_REJECT("finish_failed", total_size);
    }

    compute_resume_offset_local(
        reader,
        iso_start_abs + total_size,
        start_offset,
        resume_offset
    );
    carver_audit_set_inline(
        &g_iso_last_audit,
        "recovered",
        "accepted",
        carver_audit_span_from_u64(total_size));
#undef ISO_REJECT
    return 1;
}
