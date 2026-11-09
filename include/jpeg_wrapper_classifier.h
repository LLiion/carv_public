#ifndef JPEG_WRAPPER_CLASSIFIER_H
#define JPEG_WRAPPER_CLASSIFIER_H

#include <stddef.h>

typedef enum {
    JPEG_WRAPPER_CLASS_UNKNOWN = 0,
    JPEG_WRAPPER_CLASS_SIMPLE = 1,
    JPEG_WRAPPER_CLASS_LARGE_EXIF = 2,
    JPEG_WRAPPER_CLASS_NESTED_JPEG = 3,
    JPEG_WRAPPER_CLASS_MPF_MULTI_IMAGE = 4
} JpegWrapperClass;

typedef struct {
    JpegWrapperClass wrapper_class;
    size_t leading_exif_span;
    size_t first_sos_offset;
    size_t first_eoi_offset;
    size_t mpf_offset;
    size_t second_soi_offset;
    size_t last_eoi_offset;
    unsigned int soi_count;
    unsigned int sos_count;
    unsigned int eoi_count;
    int has_large_leading_exif;
    int has_mpf_app2;
    int has_nested_soi_after_primary;
} JpegWrapperInfo;

void jpeg_wrapper_info_init(JpegWrapperInfo *info);
int jpeg_wrapper_classify(
    const unsigned char *buffer,
    size_t length,
    JpegWrapperInfo *out_info
);
const char *jpeg_wrapper_class_name(JpegWrapperClass wrapper_class);

#endif
