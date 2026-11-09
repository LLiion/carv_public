#ifndef JPEG_STREAM_PROBE_H
#define JPEG_STREAM_PROBE_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    JPEG_STREAM_PROBE_NEED_MORE = 0,
    JPEG_STREAM_PROBE_COMPLETE = 1,
    JPEG_STREAM_PROBE_INVALID = 2
} JpegStreamProbeStatus;

typedef enum {
    JPEG_STREAM_BREAKPOINT_NONE = 0,
    JPEG_STREAM_BREAKPOINT_PREFIX_EARLY_EOI = 1,
    JPEG_STREAM_BREAKPOINT_PREFIX_SOF_WITHOUT_SUPPORT = 2,
    JPEG_STREAM_BREAKPOINT_PREFIX_SOS_WITHOUT_SUPPORT = 3,
    JPEG_STREAM_BREAKPOINT_PREFIX_INVALID_SEGMENT = 4,
    JPEG_STREAM_BREAKPOINT_ENTROPY_MARKER = 5
} JpegStreamBreakpointKind;

typedef struct {
    int saw_soi;
    int saw_jfif;
    int saw_exif;
    int saw_sof;
    int saw_sos;
    int saw_eoi;
    int saw_prefix_support_segment;
    int saw_prefix_app_segment;
    int saw_prefix_table_segment;
    int saw_restart_marker;
    int saw_entropy_marker_anomaly;
    uint16_t width;
    uint16_t height;
    uint8_t first_marker_after_soi;
    uint8_t breakpoint_marker;
    uint8_t breakpoint_kind;
    size_t total_size;
    size_t eoi_offset;
    size_t error_offset;
    size_t entropy_data_bytes;
} JpegStreamProbeResult;

typedef struct {
    unsigned char *data;
    size_t size;
    size_t capacity;
    size_t entropy_start_offset;
    size_t entropy_scan_offset;
    int entropy_prev_ff;
    JpegStreamProbeStatus status;
    JpegStreamProbeResult result;
} JpegStreamProbe;

void jpeg_stream_probe_init(JpegStreamProbe *probe);
void jpeg_stream_probe_free(JpegStreamProbe *probe);
int jpeg_stream_probe_append(
    JpegStreamProbe *probe,
    const unsigned char *data,
    size_t length
);
JpegStreamProbeStatus jpeg_stream_probe_status(const JpegStreamProbe *probe);
const JpegStreamProbeResult *jpeg_stream_probe_result(const JpegStreamProbe *probe);
const unsigned char *jpeg_stream_probe_data(
    const JpegStreamProbe *probe,
    size_t *out_length
);

#endif
