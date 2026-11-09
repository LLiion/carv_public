#include "jpeg_mpf_parser.h"

#include <limits.h>
#include <stdint.h>
#include <string.h>

static uint16_t jpeg_mpf_read_u16(const unsigned char *p, int big_endian)
{
    if (big_endian) {
        return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
    }
    return (uint16_t)(((uint16_t)p[1] << 8) | (uint16_t)p[0]);
}

static uint32_t jpeg_mpf_read_u32(const unsigned char *p, int big_endian)
{
    if (big_endian) {
        return ((uint32_t)p[0] << 24) |
               ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) |
               (uint32_t)p[3];
    }
    return ((uint32_t)p[3] << 24) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[1] << 8) |
           (uint32_t)p[0];
}

static int jpeg_mpf_marker_has_length(uint8_t marker)
{
    if (marker == 0xD8 ||
        marker == 0xD9 ||
        marker == 0x01 ||
        (marker >= 0xD0 && marker <= 0xD7)) {
        return 0;
    }
    return 1;
}

void jpeg_mpf_info_init(JpegMpfInfo *info)
{
    if (info == NULL) {
        return;
    }
    memset(info, 0, sizeof(*info));
}

int jpeg_mpf_parse(const unsigned char *buffer, size_t length, JpegMpfInfo *out_info)
{
    JpegMpfInfo local;
    size_t cursor;
    size_t app2_offset = 0U;
    size_t app2_length = 0U;
    size_t payload_offset = 0U;
    size_t mp_endian_offset = 0U;
    int big_endian = 1;
    uint32_t ifd0_offset = 0U;
    size_t ifd0_pos;
    uint16_t entry_count;
    size_t mp_list_value_or_offset = 0U;
    uint32_t mp_list_count = 0U;
    uint32_t number_of_images = 0U;
    size_t i;
    int found = 0;

    jpeg_mpf_info_init(&local);
    if (buffer == NULL || length < 16U) {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }
    if (!(buffer[0] == 0xFFU && buffer[1] == 0xD8U)) {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }

    cursor = 2U;
    while (cursor + 3U < length) {
        uint8_t marker;
        uint16_t segment_length;
        size_t segment_data;

        while (cursor < length && buffer[cursor] == 0xFFU) {
            cursor++;
        }
        if (cursor >= length) {
            break;
        }

        marker = buffer[cursor++];
        if (marker == 0xDAU || marker == 0xD9U) {
            break;
        }
        if (!jpeg_mpf_marker_has_length(marker)) {
            continue;
        }
        if (cursor + 2U > length) {
            break;
        }

        segment_length = (uint16_t)(((uint16_t)buffer[cursor] << 8) | buffer[cursor + 1U]);
        if (segment_length < 2U) {
            break;
        }
        segment_data = cursor + 2U;
        if (segment_data + (size_t)segment_length - 2U > length) {
            break;
        }

        if (marker == 0xE2U &&
            segment_length >= 8U &&
            memcmp(buffer + segment_data, "MPF\0", 4U) == 0) {
            app2_offset = cursor - 1U;
            app2_length = (size_t)segment_length - 2U;
            payload_offset = segment_data;
            mp_endian_offset = payload_offset + 4U;
            found = 1;
            break;
        }

        cursor = segment_data + (size_t)segment_length - 2U;
    }

    if (!found || mp_endian_offset + 8U > length) {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }

    if (buffer[mp_endian_offset] == 'M' && buffer[mp_endian_offset + 1U] == 'M') {
        big_endian = 1;
    } else if (buffer[mp_endian_offset] == 'I' && buffer[mp_endian_offset + 1U] == 'I') {
        big_endian = 0;
    } else {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }

    if (jpeg_mpf_read_u16(buffer + mp_endian_offset + 2U, big_endian) != 0x002AU) {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }

    ifd0_offset = jpeg_mpf_read_u32(buffer + mp_endian_offset + 4U, big_endian);
    ifd0_pos = mp_endian_offset + (size_t)ifd0_offset;
    if (ifd0_pos + 2U > length || ifd0_pos < mp_endian_offset) {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }

    entry_count = jpeg_mpf_read_u16(buffer + ifd0_pos, big_endian);
    if (ifd0_pos + 2U + (size_t)entry_count * 12U > length) {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }

    for (i = 0U; i < (size_t)entry_count; i++) {
        size_t entry_pos = ifd0_pos + 2U + (i * 12U);
        uint16_t tag = jpeg_mpf_read_u16(buffer + entry_pos, big_endian);
        uint16_t type = jpeg_mpf_read_u16(buffer + entry_pos + 2U, big_endian);
        uint32_t count = jpeg_mpf_read_u32(buffer + entry_pos + 4U, big_endian);
        uint32_t value_or_offset = jpeg_mpf_read_u32(buffer + entry_pos + 8U, big_endian);

        if (tag == 0xB001U && type == 4U && count == 1U) {
            number_of_images = value_or_offset;
        } else if (tag == 0xB002U) {
            mp_list_count = count;
            mp_list_value_or_offset = (size_t)value_or_offset;
        }
    }

    if (number_of_images == 0U ||
        mp_list_count < number_of_images * 16U ||
        mp_list_value_or_offset == 0U) {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }

    local.big_endian = big_endian;
    local.app2_offset = app2_offset;
    local.mp_endian_offset = mp_endian_offset;
    local.number_of_images = number_of_images;
    local.image_count = number_of_images > JPEG_MPF_MAX_IMAGES
        ? JPEG_MPF_MAX_IMAGES
        : (unsigned int)number_of_images;

    for (i = 0U; i < local.image_count; i++) {
        size_t entry_pos = mp_endian_offset + mp_list_value_or_offset + (i * 16U);
        JpegMpfImageEntry *entry;
        uint64_t soi_offset;
        uint64_t end_offset;

        if (entry_pos + 16U > length || entry_pos < mp_endian_offset) {
            if (out_info != NULL) {
                *out_info = local;
            }
            return 0;
        }

        entry = &local.images[i];
        entry->attributes = jpeg_mpf_read_u32(buffer + entry_pos, big_endian);
        entry->image_size = jpeg_mpf_read_u32(buffer + entry_pos + 4U, big_endian);
        entry->data_offset = jpeg_mpf_read_u32(buffer + entry_pos + 8U, big_endian);
        entry->dependent_image1 = jpeg_mpf_read_u16(buffer + entry_pos + 12U, big_endian);
        entry->dependent_image2 = jpeg_mpf_read_u16(buffer + entry_pos + 14U, big_endian);

        if (entry->image_size == 0U) {
            continue;
        }

        if (i == 0U && entry->data_offset == 0U) {
            soi_offset = 0U;
        } else {
            soi_offset = (uint64_t)mp_endian_offset + (uint64_t)entry->data_offset;
        }
        end_offset = soi_offset + (uint64_t)entry->image_size;
        if (soi_offset > SIZE_MAX || end_offset > SIZE_MAX) {
            continue;
        }
        entry->soi_offset = (size_t)soi_offset;
        entry->end_offset = (size_t)end_offset;
        if (entry->end_offset > local.wrapper_end_offset) {
            local.wrapper_end_offset = entry->end_offset;
        }
    }

    if (local.wrapper_end_offset == 0U) {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }

    local.valid = 1;
    if (out_info != NULL) {
        *out_info = local;
    }
    (void)app2_length;
    return 1;
}
