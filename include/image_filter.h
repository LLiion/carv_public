#ifndef IMAGE_FILTER_H
#define IMAGE_FILTER_H

#include <stdint.h>

#define IMAGE_FILTER_MIN_LONG_SIDE 640U
#define IMAGE_FILTER_MIN_SHORT_SIDE 480U
#define IMAGE_FILTER_MIN_FILE_SIZE_BYTES (50U * 1024U)
#define IMAGE_FILTER_NAMED_MIN_LONG_SIDE 128U
#define IMAGE_FILTER_NAMED_MIN_SHORT_SIDE 96U

static inline int image_filter_is_below_min_dimensions(uint64_t width, uint64_t height)
{
    uint64_t long_side;
    uint64_t short_side;

    if (width == 0 || height == 0) {
        return 0;
    }

    if (width >= height) {
        long_side = width;
        short_side = height;
    } else {
        long_side = height;
        short_side = width;
    }

    return long_side < IMAGE_FILTER_MIN_LONG_SIDE ||
           short_side < IMAGE_FILTER_MIN_SHORT_SIDE;
}

static inline int image_filter_is_below_named_dimensions(uint64_t width, uint64_t height)
{
    uint64_t long_side;
    uint64_t short_side;

    if (width == 0 || height == 0) {
        return 0;
    }

    if (width >= height) {
        long_side = width;
        short_side = height;
    } else {
        long_side = height;
        short_side = width;
    }

    return long_side < IMAGE_FILTER_NAMED_MIN_LONG_SIDE ||
           short_side < IMAGE_FILTER_NAMED_MIN_SHORT_SIDE;
}

static inline int image_filter_is_below_min_file_size(uint64_t file_size)
{
    return file_size > 0 && file_size < IMAGE_FILTER_MIN_FILE_SIZE_BYTES;
}

static inline int image_filter_should_skip_image(
    uint64_t width,
    uint64_t height,
    uint64_t file_size
)
{
    return image_filter_is_below_min_dimensions(width, height) ||
           image_filter_is_below_min_file_size(file_size);
}

#endif
