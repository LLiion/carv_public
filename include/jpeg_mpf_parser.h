#ifndef JPEG_MPF_PARSER_H
#define JPEG_MPF_PARSER_H

#include <stddef.h>
#include <stdint.h>

#define JPEG_MPF_MAX_IMAGES 16U

typedef struct {
    uint32_t attributes;
    uint32_t image_size;
    uint32_t data_offset;
    uint16_t dependent_image1;
    uint16_t dependent_image2;
    size_t soi_offset;
    size_t end_offset;
} JpegMpfImageEntry;

typedef struct {
    int valid;
    int big_endian;
    size_t app2_offset;
    size_t mp_endian_offset;
    uint32_t number_of_images;
    unsigned int image_count;
    size_t wrapper_end_offset;
    JpegMpfImageEntry images[JPEG_MPF_MAX_IMAGES];
} JpegMpfInfo;

void jpeg_mpf_info_init(JpegMpfInfo *info);
int jpeg_mpf_parse(const unsigned char *buffer, size_t length, JpegMpfInfo *out_info);

#endif
