#include "jpeg_wrapper_classifier.h"
#include "jpeg_mpf_parser.h"

#include <stdint.h>
#include <string.h>

#define JPEG_WRAPPER_LARGE_EXIF_MIN (16U * 1024U)

static uint16_t jpeg_wrapper_read_u16_be(const unsigned char *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static size_t jpeg_wrapper_leading_exif_span(
    const unsigned char *buffer,
    size_t length
)
{
    size_t cursor;
    uint8_t marker;
    uint16_t segment_length;

    if (buffer == NULL || length < 12U) {
        return 0U;
    }
    if (!(buffer[0] == 0xFFU && buffer[1] == 0xD8U && buffer[2] == 0xFFU)) {
        return 0U;
    }

    cursor = 2U;
    while (cursor < length && buffer[cursor] == 0xFFU) {
        cursor++;
    }
    if (cursor >= length) {
        return 0U;
    }

    marker = buffer[cursor++];
    if (marker != 0xE1U || cursor + 2U > length) {
        return 0U;
    }

    segment_length = jpeg_wrapper_read_u16_be(buffer + cursor);
    if (segment_length < 8U || cursor + 8U > length) {
        return 0U;
    }
    if (memcmp(buffer + cursor + 2U, "Exif\0\0", 6U) != 0) {
        return 0U;
    }

    return 2U + (size_t)segment_length;
}

void jpeg_wrapper_info_init(JpegWrapperInfo *info)
{
    if (info == NULL) {
        return;
    }
    memset(info, 0, sizeof(*info));
    info->wrapper_class = JPEG_WRAPPER_CLASS_UNKNOWN;
    info->mpf_offset = SIZE_MAX;
    info->second_soi_offset = SIZE_MAX;
}

int jpeg_wrapper_classify(
    const unsigned char *buffer,
    size_t length,
    JpegWrapperInfo *out_info
)
{
    size_t i;
    JpegWrapperInfo local;
    JpegMpfInfo mpf_info;

    jpeg_wrapper_info_init(&local);
    jpeg_mpf_info_init(&mpf_info);
    if (buffer == NULL || length < 4U) {
        if (out_info != NULL) {
            *out_info = local;
        }
        return 0;
    }

    local.leading_exif_span = jpeg_wrapper_leading_exif_span(buffer, length);
    if (local.leading_exif_span >= JPEG_WRAPPER_LARGE_EXIF_MIN) {
        local.has_large_leading_exif = 1;
    }

    (void)jpeg_mpf_parse(buffer, length, &mpf_info);

    for (i = 0U; i + 3U < length; i++) {
        if (buffer[i] == 0xFFU && buffer[i + 1U] == 0xD8U &&
            buffer[i + 2U] == 0xFFU) {
            local.soi_count++;
            if (local.soi_count == 2U) {
                local.second_soi_offset = i;
            }
        }
        if (buffer[i] == 0xFFU && buffer[i + 1U] == 0xDAU) {
            local.sos_count++;
            if (local.first_sos_offset == 0U) {
                local.first_sos_offset = i;
            }
        }
        if (buffer[i] == 0xFFU && buffer[i + 1U] == 0xD9U) {
            local.eoi_count++;
            if (local.first_eoi_offset == 0U) {
                local.first_eoi_offset = i;
            }
            local.last_eoi_offset = i;
        }
        if (i + 8U < length &&
            buffer[i] == 0xFFU && buffer[i + 1U] == 0xE2U &&
            memcmp(buffer + i + 4U, "MPF\0", 4U) == 0) {
            local.has_mpf_app2 = 1;
            local.mpf_offset = i;
        }
    }

    if (local.second_soi_offset != SIZE_MAX &&
        local.first_eoi_offset > 0U &&
        local.second_soi_offset > local.first_eoi_offset) {
        local.has_nested_soi_after_primary = 1;
    }

    if (mpf_info.valid) {
        local.has_mpf_app2 = 1;
        if (mpf_info.image_count >= 2U) {
            local.soi_count = mpf_info.image_count;
        }
        if (mpf_info.wrapper_end_offset > 0U &&
            mpf_info.wrapper_end_offset <= length) {
            local.last_eoi_offset = mpf_info.wrapper_end_offset - 2U;
        }
        local.wrapper_class = JPEG_WRAPPER_CLASS_MPF_MULTI_IMAGE;
    } else if (local.has_mpf_app2 &&
        local.soi_count >= 2U &&
        local.eoi_count >= 2U) {
        local.wrapper_class = JPEG_WRAPPER_CLASS_MPF_MULTI_IMAGE;
    } else if (local.has_nested_soi_after_primary &&
               local.eoi_count >= 2U) {
        local.wrapper_class = JPEG_WRAPPER_CLASS_NESTED_JPEG;
    } else if (local.has_large_leading_exif) {
        local.wrapper_class = JPEG_WRAPPER_CLASS_LARGE_EXIF;
    } else if (local.soi_count >= 1U && local.eoi_count >= 1U) {
        local.wrapper_class = JPEG_WRAPPER_CLASS_SIMPLE;
    } else {
        local.wrapper_class = JPEG_WRAPPER_CLASS_UNKNOWN;
    }

    if (out_info != NULL) {
        *out_info = local;
    }
    return 1;
}

const char *jpeg_wrapper_class_name(JpegWrapperClass wrapper_class)
{
    switch (wrapper_class) {
        case JPEG_WRAPPER_CLASS_SIMPLE:
            return "simple";
        case JPEG_WRAPPER_CLASS_LARGE_EXIF:
            return "large_exif";
        case JPEG_WRAPPER_CLASS_NESTED_JPEG:
            return "nested_jpeg";
        case JPEG_WRAPPER_CLASS_MPF_MULTI_IMAGE:
            return "mpf_multi_image";
        case JPEG_WRAPPER_CLASS_UNKNOWN:
        default:
            return "unknown";
    }
}
