#define _POSIX_C_SOURCE 200809L

#include "image_triage.h"

#include "image_filter.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define IMAGE_TRIAGE_PREFIX_MAX (1024U * 1024U)
#define IMAGE_TRIAGE_PREFIX_INITIAL (64U * 1024U)

static uint16_t triage_be16(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t triage_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static uint16_t triage_le16(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t triage_le32(const unsigned char *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static int triage_jpeg_sof(unsigned char marker)
{
    return (marker >= 0xc0U && marker <= 0xcfU &&
            marker != 0xc4U && marker != 0xc8U && marker != 0xccU);
}

static int triage_parse_jpeg(
    const unsigned char *data,
    size_t size,
    ImageTriageResult *result)
{
    size_t cursor = 2U;

    if (size < 4U || data[0] != 0xffU || data[1] != 0xd8U) return 0;
    result->recognized = 1;
    while (cursor + 1U < size) {
        unsigned char marker;
        uint16_t segment_size;

        while (cursor < size && data[cursor] != 0xffU) cursor++;
        while (cursor < size && data[cursor] == 0xffU) cursor++;
        if (cursor >= size) break;
        marker = data[cursor++];
        if (marker == 0U || marker == 0xd8U) continue;
        if (marker == 0xd9U || marker == 0xdaU) break;
        if (marker >= 0xd0U && marker <= 0xd7U) continue;
        if (cursor + 2U > size) break;
        segment_size = triage_be16(data + cursor);
        if (segment_size < 2U) break;
        if (marker == 0xe0U && segment_size >= 7U && cursor + 7U <= size &&
            memcmp(data + cursor + 2U, "JFIF\0", 5U) == 0) {
            result->has_jfif = 1;
        } else if (marker == 0xe1U && segment_size >= 8U &&
                   cursor + 8U <= size &&
                   memcmp(data + cursor + 2U, "Exif\0\0", 6U) == 0) {
            result->has_exif = 1;
        }
        if (cursor + segment_size > size) break;
        if (triage_jpeg_sof(marker) && segment_size >= 8U) {
            result->height = triage_be16(data + cursor + 3U);
            result->width = triage_be16(data + cursor + 5U);
        }
        cursor += segment_size;
    }
    return 1;
}

static uint16_t triage_tiff16(const unsigned char *p, int little)
{
    return little ? triage_le16(p) : triage_be16(p);
}

static uint32_t triage_tiff32(const unsigned char *p, int little)
{
    return little ? triage_le32(p) : triage_be32(p);
}

static int triage_parse_tiff(
    const unsigned char *data,
    size_t size,
    ImageTriageResult *result)
{
    uint32_t ifd_offset;
    uint16_t entries;
    size_t index;
    int little;

    if (size < 8U) return 0;
    if (data[0] == 'I' && data[1] == 'I') little = 1;
    else if (data[0] == 'M' && data[1] == 'M') little = 0;
    else return 0;
    if (triage_tiff16(data + 2U, little) != 42U) return 0;
    result->recognized = 1;
    ifd_offset = triage_tiff32(data + 4U, little);
    if ((uint64_t)ifd_offset + 2U > size) return 1;
    entries = triage_tiff16(data + ifd_offset, little);
    for (index = 0U; index < entries; ++index) {
        size_t row = (size_t)ifd_offset + 2U + index * 12U;
        uint16_t tag;
        uint16_t type;
        uint32_t count;
        uint64_t value;

        if (row + 12U > size) break;
        tag = triage_tiff16(data + row, little);
        if (tag != 256U && tag != 257U) continue;
        type = triage_tiff16(data + row + 2U, little);
        count = triage_tiff32(data + row + 4U, little);
        if (count != 1U || (type != 3U && type != 4U)) continue;
        value = type == 3U
            ? triage_tiff16(data + row + 8U, little)
            : triage_tiff32(data + row + 8U, little);
        if (tag == 256U) result->width = value;
        else result->height = value;
    }
    return 1;
}

static int triage_parse_image(
    const unsigned char *data,
    size_t size,
    const char *extension,
    ImageTriageResult *result)
{
    if ((extension != NULL &&
         (strcasecmp(extension, "jpg") == 0 ||
          strcasecmp(extension, "jpeg") == 0)) ||
        (size >= 2U && data[0] == 0xffU && data[1] == 0xd8U)) {
        return triage_parse_jpeg(data, size, result);
    }
    if (size >= 24U &&
        memcmp(data, "\x89PNG\r\n\x1a\n", 8U) == 0) {
        result->recognized = 1;
        result->width = triage_be32(data + 16U);
        result->height = triage_be32(data + 20U);
        return 1;
    }
    if (size >= 10U &&
        (memcmp(data, "GIF87a", 6U) == 0 ||
         memcmp(data, "GIF89a", 6U) == 0)) {
        result->recognized = 1;
        result->width = triage_le16(data + 6U);
        result->height = triage_le16(data + 8U);
        return 1;
    }
    if (size >= 26U && data[0] == 'B' && data[1] == 'M') {
        int32_t signed_height;
        result->recognized = 1;
        result->width = triage_le32(data + 18U);
        signed_height = (int32_t)triage_le32(data + 22U);
        result->height = signed_height < 0
            ? (uint64_t)(-(int64_t)signed_height)
            : (uint64_t)signed_height;
        return 1;
    }
    return triage_parse_tiff(data, size, result);
}

static void triage_score(const char *extension, ImageTriageResult *result)
{
    uint64_t pixels = 0U;
    int is_jpeg = extension != NULL &&
        (strcasecmp(extension, "jpg") == 0 ||
         strcasecmp(extension, "jpeg") == 0);
    int is_png = extension != NULL && strcasecmp(extension, "png") == 0;

    if (result->recognized) result->score += 5;
    if (result->width > 0U && result->height > 0U) {
        result->score += 10;
        if (image_filter_is_below_min_dimensions(
                result->width, result->height)) {
            result->score -= 20;
        } else {
            result->score += 25;
        }
        if (result->height <= UINT64_MAX / result->width) {
            pixels = result->width * result->height;
            if (pixels >= 2000000U) result->score += 10;
            if (pixels >= 6000000U) result->score += 5;
        }
    }
    if (result->file_size >= IMAGE_FILTER_MIN_FILE_SIZE_BYTES) result->score += 5;
    if (result->file_size >= 256U * 1024U) result->score += 10;
    if (result->file_size >= 1024U * 1024U) result->score += 5;
    if (is_jpeg) result->score += 5;
    if (result->has_jfif) result->score += 5;
    if (result->has_exif) result->score += 30;
    if (is_png && !result->has_exif &&
        result->file_size < 256U * 1024U) result->score -= 10;

    if (result->score >= 70) result->classification = "high_priority_photo";
    else if (result->score >= 45) result->classification = "likely_customer_image";
    else if (result->score >= 20) result->classification = "review_image";
    else result->classification = "likely_small_asset";
}

int image_triage_inspect_file(
    const char *path,
    const char *extension,
    uint64_t file_size,
    ImageTriageResult *result)
{
    unsigned char *buffer = NULL;
    size_t wanted;
    size_t have = 0U;
    int fd = -1;
    int parsed = 0;

    if (result == NULL) { errno = EINVAL; return 0; }
    memset(result, 0, sizeof(*result));
    result->file_size = file_size;
    result->classification = "uninspected";
    if (path == NULL || path[0] == '\0' || file_size == 0U) return 0;
    wanted = file_size < IMAGE_TRIAGE_PREFIX_INITIAL
        ? (size_t)file_size
        : IMAGE_TRIAGE_PREFIX_INITIAL;
    buffer = (unsigned char *)malloc(wanted);
    if (buffer == NULL) return 0;
    fd = open(path, O_RDONLY);
    if (fd < 0) goto done;
    while (have < wanted) {
        ssize_t got = read(fd, buffer + have, wanted - have);
        if (got > 0) have += (size_t)got;
        else if (got < 0 && errno == EINTR) continue;
        else break;
    }
    parsed = triage_parse_image(buffer, have, extension, result);
    if (parsed && result->recognized && result->width == 0U &&
        file_size > have && have < IMAGE_TRIAGE_PREFIX_MAX) {
        size_t expanded_wanted = file_size < IMAGE_TRIAGE_PREFIX_MAX
            ? (size_t)file_size
            : IMAGE_TRIAGE_PREFIX_MAX;
        unsigned char *expanded = (unsigned char *)realloc(
            buffer, expanded_wanted);
        if (expanded != NULL) {
            buffer = expanded;
            while (have < expanded_wanted) {
                ssize_t got = read(fd, buffer + have, expanded_wanted - have);
                if (got > 0) have += (size_t)got;
                else if (got < 0 && errno == EINTR) continue;
                else break;
            }
            result->width = 0U;
            result->height = 0U;
            (void)triage_parse_image(buffer, have, extension, result);
        }
    }
    if (parsed && result->recognized) triage_score(extension, result);
done:
    if (fd >= 0) (void)close(fd);
    free(buffer);
    return parsed;
}
