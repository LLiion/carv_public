#include "carver_audio.h"

#include "carver_output.h"
#include "config.h"
#include "log.h"

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define MP3_MAX_REASONABLE_FILE_SIZE (1024ULL * 1024ULL * 1024ULL)
#define AAC_MAX_REASONABLE_FILE_SIZE (512ULL * 1024ULL * 1024ULL)
#define FLAC_MAX_REASONABLE_FILE_SIZE (4ULL * 1024ULL * 1024ULL * 1024ULL)
#define AUDIO_REJECT_RESUME_MIN_BYTES (16ULL * 1024ULL * 1024ULL)
#define MP3_MIN_VALID_FRAMES 2U
#define AAC_MIN_VALID_FRAMES 3U
#define MP3_LOW_CONFIDENCE_MIN_FRAMES 12U
#define AAC_LOW_CONFIDENCE_MIN_FRAMES 24U
#define MP3_LOW_CONFIDENCE_MIN_DURATION_SECONDS 0.5
#define AAC_LOW_CONFIDENCE_MIN_DURATION_SECONDS 0.75
#define MP3_ID3V1_TAG_SIZE 128U
#define FLAC_MIN_BOUNDED_FRAMES 1U
#define FLAC_MAX_METADATA_BYTES (4U * 1024U * 1024U)
#define FLAC_DEFAULT_FRAME_SEARCH_WINDOW (256U * 1024U)

typedef struct {
    uint32_t frame_size;
    uint8_t version_id;
    uint8_t layer_id;
    uint8_t channel_mode;
    uint8_t protection_absent;
    uint32_t sample_rate;
    uint16_t samples_per_frame;
    uint16_t bitrate_kbps;
} Mp3FrameInfo;

typedef struct {
    uint32_t frame_size;
    uint8_t profile;
    uint8_t sample_rate_index;
    uint8_t channel_config;
    uint32_t sample_rate;
    uint16_t samples_per_frame;
} AacFrameInfo;

typedef struct {
    uint32_t min_frame_size;
    uint32_t max_frame_size;
    uint64_t audio_start_abs;
} FlacStreamInfo;

typedef struct {
    size_t header_size;
} FlacFrameHeaderInfo;

static CarverAuditReport g_mp3_last_audit;
static CarverAuditReport g_aac_last_audit;
static CarverAuditReport g_flac_last_audit;

void carver_mp3_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_mp3_last_audit);
}

void carver_mp3_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_mp3_last_audit;
}

void carver_aac_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_aac_last_audit);
}

void carver_aac_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_aac_last_audit;
}

void carver_flac_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_flac_last_audit);
}

void carver_flac_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_flac_last_audit;
}

static uint64_t audio_budget_adjusted_cap(
    uint64_t green_cap,
    uint64_t yellow_cap,
    uint64_t red_cap
)
{
    switch (log_get_validator_budget_state()) {
        case LOG_TROUBLE_BUDGET_RED:
            return red_cap;
        case LOG_TROUBLE_BUDGET_YELLOW:
            return yellow_cap;
        case LOG_TROUBLE_BUDGET_GREEN:
        case LOG_TROUBLE_BUDGET_UNKNOWN:
        default:
            return green_cap;
    }
}

static int buffer_contains_ascii_local(
    const uint8_t *data,
    size_t data_len,
    const char *needle
)
{
    size_t needle_len;
    size_t i;

    if (data == NULL || needle == NULL) {
        return 0;
    }

    needle_len = strlen(needle);
    if (needle_len == 0U || data_len < needle_len) {
        return 0;
    }

    for (i = 0U; i + needle_len <= data_len; i++) {
        if (memcmp(data + i, needle, needle_len) == 0) {
            return 1;
        }
    }

    return 0;
}

static void log_audio_budget_cap_hit(
    const char *format_name,
    uint64_t start_abs,
    unsigned frame_count,
    uint64_t last_resume_abs,
    uint64_t effective_cap_bytes
)
{
    LogTroubleBudgetState budget_state = log_get_validator_budget_state();

    log_info(
        "%s candidate at byte %llu was capped after %u frames and %.1f MiB (budget=%s cap=%.1f MiB); treating it as misleadingly large and moving on",
        format_name != NULL ? format_name : "Audio",
        (unsigned long long)start_abs,
        frame_count,
        (double)(last_resume_abs - start_abs) / (1024.0 * 1024.0),
        log_trouble_budget_state_label(budget_state),
        (double)effective_cap_bytes / (1024.0 * 1024.0)
    );
}

static void log_audio_low_confidence_cap_hit(
    const char *format_name,
    uint64_t start_abs,
    unsigned frame_count,
    double duration_seconds,
    uint64_t last_resume_abs,
    uint64_t confidence_cap_bytes
)
{
    LogTroubleBudgetState budget_state = log_get_validator_budget_state();

    log_info(
        "%s candidate at byte %llu stayed structurally plausible on only low-confidence evidence (%u frames, %.0fs) and hit the exploratory cap at %.1f MiB after %.1f MiB of stream data (budget=%s); moving on until stronger metadata proves it is real",
        format_name != NULL ? format_name : "Audio",
        (unsigned long long)start_abs,
        frame_count,
        duration_seconds,
        (double)confidence_cap_bytes / (1024.0 * 1024.0),
        (double)(last_resume_abs - start_abs) / (1024.0 * 1024.0),
        log_trouble_budget_state_label(budget_state)
    );
}

static void log_audio_confidence_gain(
    const char *format_name,
    uint64_t start_abs,
    unsigned frame_count,
    double duration_seconds,
    const char *reason
)
{
    log_info(
        "%s candidate at byte %llu gained strong confidence from %s (%u frames, %.2fs)",
        format_name != NULL ? format_name : "Audio",
        (unsigned long long)start_abs,
        reason != NULL ? reason : "format-specific metadata",
        frame_count,
        duration_seconds
    );
}

static void log_audio_low_confidence_reject(
    const char *format_name,
    uint64_t start_abs,
    unsigned frame_count,
    double duration_seconds,
    const char *reason
)
{
    log_info(
        "%s candidate at byte %llu was rejected because it ended on only low-confidence evidence (%u frames, %.2fs): %s",
        format_name != NULL ? format_name : "Audio",
        (unsigned long long)start_abs,
        frame_count,
        duration_seconds,
        reason != NULL ? reason : "stable frame train stayed too shallow to trust"
    );
}

static void log_audio_low_confidence_accept(
    const char *format_name,
    uint64_t start_abs,
    unsigned frame_count,
    double duration_seconds,
    const char *reason
)
{
    log_info(
        "%s candidate at byte %llu was accepted on an extended low-confidence frame train (%u frames, %.2fs): %s",
        format_name != NULL ? format_name : "Audio",
        (unsigned long long)start_abs,
        frame_count,
        duration_seconds,
        reason != NULL ? reason : "no stronger metadata anchor was present"
    );
}

static void audio_mark_high_confidence(
    const char *format_name,
    uint64_t start_abs,
    unsigned frame_count,
    double duration_seconds,
    int *high_confidence,
    const char **confidence_reason_out,
    const char *reason
)
{
    if (high_confidence == NULL) {
        return;
    }
    if (!*high_confidence) {
        log_audio_confidence_gain(
            format_name,
            start_abs,
            frame_count,
            duration_seconds,
            reason
        );
    }
    *high_confidence = 1;
    if (confidence_reason_out != NULL) {
        *confidence_reason_out = reason;
    }
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

static int copy_stream_bytes(
    Reader *reader,
    FILE *output_file,
    uint64_t start_abs,
    uint64_t byte_count
)
{
    uint64_t current_abs = start_abs;
    uint64_t remaining = byte_count;
    uint64_t source_size;

    if (reader == NULL || output_file == NULL) {
        return 0;
    }
    source_size = reader_get_source_size(reader);
    if (start_abs > source_size || byte_count > source_size - start_abs) {
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

static int read_stream_bytes(
    Reader *reader,
    uint64_t start_abs,
    uint8_t *dst,
    size_t byte_count
)
{
    uint64_t current_abs = start_abs;
    size_t copied = 0;
    uint64_t source_size;

    if (reader == NULL || dst == NULL) {
        return 0;
    }
    source_size = reader_get_source_size(reader);
    if (start_abs > source_size || (uint64_t)byte_count > source_size - start_abs) {
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

static int compute_resume_offset_local(
    const Reader *reader,
    uint64_t resume_abs,
    size_t fallback_offset,
    size_t *resume_offset_out
)
{
    uint64_t base_abs;

    if (resume_offset_out == NULL || reader == NULL) {
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

static void audio_resume_after_reject_if_useful(
    Reader *reader,
    uint64_t start_abs,
    uint64_t last_resume_abs,
    size_t fallback_offset,
    size_t *resume_offset_out
)
{
    if (reader == NULL || resume_offset_out == NULL) {
        return;
    }
    if (last_resume_abs <= start_abs ||
        last_resume_abs - start_abs < AUDIO_REJECT_RESUME_MIN_BYTES) {
        return;
    }
    (void)compute_resume_offset_local(
        reader,
        last_resume_abs,
        fallback_offset,
        resume_offset_out
    );
}

static int parse_synchsafe_u32(const uint8_t *data, uint32_t *value_out)
{
    if (data == NULL || value_out == NULL) {
        return 0;
    }

    if ((data[0] & 0x80U) != 0U ||
        (data[1] & 0x80U) != 0U ||
        (data[2] & 0x80U) != 0U ||
        (data[3] & 0x80U) != 0U) {
        return 0;
    }

    *value_out = ((uint32_t)data[0] << 21) |
                 ((uint32_t)data[1] << 14) |
                 ((uint32_t)data[2] << 7) |
                 (uint32_t)data[3];
    return 1;
}

static int parse_id3v2_tag_size(
    const uint8_t header[10],
    uint32_t *tag_total_size_out
)
{
    uint32_t tag_payload_size;
    uint32_t total_size;

    if (header == NULL || tag_total_size_out == NULL) {
        return 0;
    }

    if (memcmp(header, "ID3", 3) != 0) {
        return 0;
    }
    if ((header[5] & 0x0FU) != 0U) {
        return 0;
    }
    if (!parse_synchsafe_u32(header + 6, &tag_payload_size)) {
        return 0;
    }

    total_size = 10U + tag_payload_size;
    if ((header[5] & 0x10U) != 0U) {
        total_size += 10U;
    }

    *tag_total_size_out = total_size;
    return 1;
}

static int parse_mp3_frame_header(
    const uint8_t header[4],
    Mp3FrameInfo *info_out
)
{
    static const int bitrate_v1_l1[16] =
        {0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448, 0};
    static const int bitrate_v1_l2[16] =
        {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0};
    static const int bitrate_v1_l3[16] =
        {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0};
    static const int bitrate_v2_l1[16] =
        {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0};
    static const int bitrate_v2_l23[16] =
        {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0};
    static const int sample_rates[3] = {44100, 48000, 32000};
    int version_id;
    int layer_id;
    int bitrate_index;
    int sample_rate_index;
    int padding;
    int sample_rate;
    int bitrate_kbps;
    int channel_mode;
    int protection_absent;
    uint16_t samples_per_frame;
    uint32_t frame_size;

    if (header == NULL || info_out == NULL) {
        return 0;
    }

    if (header[0] != 0xFFU || (header[1] & 0xE0U) != 0xE0U) {
        return 0;
    }

    version_id = (header[1] >> 3) & 0x03;
    layer_id = (header[1] >> 1) & 0x03;
    bitrate_index = (header[2] >> 4) & 0x0F;
    sample_rate_index = (header[2] >> 2) & 0x03;
    padding = (header[2] >> 1) & 0x01;
    protection_absent = header[1] & 0x01;
    channel_mode = (header[3] >> 6) & 0x03;

    if (version_id == 1 || layer_id == 0 ||
        bitrate_index == 0 || bitrate_index == 15 ||
        sample_rate_index == 3) {
        return 0;
    }

    sample_rate = sample_rates[sample_rate_index];
    if (version_id == 2) {
        sample_rate /= 2;
    } else if (version_id == 0) {
        sample_rate /= 4;
    }
    if (sample_rate <= 0) {
        return 0;
    }

    if (version_id == 3) {
        if (layer_id == 3) {
            bitrate_kbps = bitrate_v1_l1[bitrate_index];
        } else if (layer_id == 2) {
            bitrate_kbps = bitrate_v1_l2[bitrate_index];
        } else {
            bitrate_kbps = bitrate_v1_l3[bitrate_index];
        }
    } else {
        if (layer_id == 3) {
            bitrate_kbps = bitrate_v2_l1[bitrate_index];
        } else {
            bitrate_kbps = bitrate_v2_l23[bitrate_index];
        }
    }

    if (bitrate_kbps <= 0) {
        return 0;
    }

    if (layer_id == 3) {
        frame_size = (uint32_t)(((12U * (uint32_t)bitrate_kbps * 1000U) / (uint32_t)sample_rate) +
                                (uint32_t)padding) * 4U;
    } else if (layer_id == 1 && version_id != 3) {
        frame_size = (uint32_t)((72U * (uint32_t)bitrate_kbps * 1000U) / (uint32_t)sample_rate) +
                     (uint32_t)padding;
    } else {
        frame_size = (uint32_t)((144U * (uint32_t)bitrate_kbps * 1000U) / (uint32_t)sample_rate) +
                     (uint32_t)padding;
    }

    if (frame_size < 4U) {
        return 0;
    }

    if (layer_id == 3) {
        samples_per_frame = 384U;
    } else if (layer_id == 2) {
        samples_per_frame = 1152U;
    } else if (version_id == 3) {
        samples_per_frame = 1152U;
    } else {
        samples_per_frame = 576U;
    }

    info_out->frame_size = frame_size;
    info_out->version_id = (uint8_t)version_id;
    info_out->layer_id = (uint8_t)layer_id;
    info_out->channel_mode = (uint8_t)channel_mode;
    info_out->protection_absent = (uint8_t)protection_absent;
    info_out->sample_rate = (uint32_t)sample_rate;
    info_out->samples_per_frame = samples_per_frame;
    info_out->bitrate_kbps = (uint16_t)bitrate_kbps;
    return 1;
}

static int parse_aac_frame_header(
    const uint8_t header[7],
    AacFrameInfo *info_out
)
{
    static const uint32_t sample_rates[13] = {
        96000U, 88200U, 64000U, 48000U, 44100U, 32000U,
        24000U, 22050U, 16000U, 12000U, 11025U, 8000U, 7350U
    };
    uint8_t profile;
    uint8_t sample_rate_index;
    uint8_t channel_config;
    uint32_t frame_length;

    if (header == NULL || info_out == NULL) {
        return 0;
    }

    if (header[0] != 0xFFU || (header[1] & 0xF6U) != 0xF0U) {
        return 0;
    }

    profile = (header[2] >> 6) & 0x03U;
    sample_rate_index = (header[2] >> 2) & 0x0FU;
    channel_config = (uint8_t)(((header[2] & 0x01U) << 2) | ((header[3] >> 6) & 0x03U));
    frame_length = ((uint32_t)(header[3] & 0x03U) << 11) |
                   ((uint32_t)header[4] << 3) |
                   ((uint32_t)header[5] >> 5);

    if (profile == 3U ||
        sample_rate_index == 0x0FU ||
        sample_rate_index >= 13U ||
        channel_config == 0U ||
        channel_config > 7U) {
        return 0;
    }

    if (frame_length < (((header[1] & 0x01U) != 0U) ? 7U : 9U)) {
        return 0;
    }

    info_out->frame_size = frame_length;
    info_out->profile = profile;
    info_out->sample_rate_index = sample_rate_index;
    info_out->channel_config = channel_config;
    info_out->sample_rate = sample_rates[sample_rate_index];
    info_out->samples_per_frame = 1024U;
    return 1;
}

static double mp3_frame_duration_seconds(const Mp3FrameInfo *info)
{
    if (info == NULL || info->sample_rate == 0U || info->samples_per_frame == 0U) {
        return 0.0;
    }

    return (double)info->samples_per_frame / (double)info->sample_rate;
}

static double aac_frame_duration_seconds(const AacFrameInfo *info)
{
    if (info == NULL || info->sample_rate == 0U || info->samples_per_frame == 0U) {
        return 0.0;
    }

    return (double)info->samples_per_frame / (double)info->sample_rate;
}

static int mp3_frame_has_auxiliary_tag(
    Reader *reader,
    uint64_t frame_abs,
    const Mp3FrameInfo *info
)
{
    uint8_t probe[512];
    size_t payload_offset;
    size_t probe_size;

    if (reader == NULL || info == NULL || info->frame_size <= 4U) {
        return 0;
    }

    payload_offset = 4U;
    if (!info->protection_absent) {
        payload_offset += 2U;
    }
    if (payload_offset >= info->frame_size) {
        return 0;
    }

    probe_size = (size_t)(info->frame_size - payload_offset);
    if (probe_size > sizeof(probe)) {
        probe_size = sizeof(probe);
    }
    if (probe_size < 16U) {
        return 0;
    }

    if (!read_stream_bytes(reader, frame_abs + (uint64_t)payload_offset, probe, probe_size)) {
        return 0;
    }

    return buffer_contains_ascii_local(probe, probe_size, "Xing") ||
           buffer_contains_ascii_local(probe, probe_size, "Info") ||
           buffer_contains_ascii_local(probe, probe_size, "VBRI") ||
           buffer_contains_ascii_local(probe, probe_size, "LAME");
}

static int mp3_stream_has_id3v1_tag(Reader *reader, uint64_t tag_abs)
{
    uint64_t source_size;
    uint8_t header[3];

    if (reader == NULL) {
        return 0;
    }

    source_size = reader_get_source_size(reader);
    if (tag_abs > source_size || source_size - tag_abs < MP3_ID3V1_TAG_SIZE) {
        return 0;
    }
    if (!read_stream_bytes(reader, tag_abs, header, sizeof(header))) {
        return 0;
    }

    return memcmp(header, "TAG", sizeof(header)) == 0;
}

static int is_valid_flac_frame_header_start(const uint8_t header[4])
{
    uint8_t block_size_code;
    uint8_t sample_rate_code;
    uint8_t channel_assignment;
    uint8_t bits_per_sample_code;

    if (header == NULL) {
        return 0;
    }

    if (header[0] != 0xFFU || (header[1] & 0xFEU) != 0xF8U) {
        return 0;
    }

    block_size_code = (header[2] >> 4) & 0x0FU;
    sample_rate_code = header[2] & 0x0FU;
    channel_assignment = (header[3] >> 4) & 0x0FU;
    bits_per_sample_code = (header[3] >> 1) & 0x07U;

    if (block_size_code == 0U || sample_rate_code == 0x0FU) {
        return 0;
    }
    if (channel_assignment > 10U) {
        return 0;
    }
    if (bits_per_sample_code == 0x03U || bits_per_sample_code == 0x07U) {
        return 0;
    }

    return 1;
}

static uint8_t crc8_update_local(uint8_t crc, uint8_t value)
{
    unsigned bit_index;

    crc ^= value;
    for (bit_index = 0U; bit_index < 8U; bit_index++) {
        if ((crc & 0x80U) != 0U) {
            crc = (uint8_t)((crc << 1) ^ 0x07U);
        } else {
            crc <<= 1;
        }
    }

    return crc;
}

static uint16_t crc16_update_local(uint16_t crc, uint8_t value)
{
    unsigned bit_index;

    crc ^= (uint16_t)value << 8;
    for (bit_index = 0U; bit_index < 8U; bit_index++) {
        if ((crc & 0x8000U) != 0U) {
            crc = (uint16_t)((crc << 1) ^ 0x8005U);
        } else {
            crc <<= 1;
        }
    }

    return crc;
}

static int flac_utf8_code_length(uint8_t first_byte, size_t *length_out)
{
    unsigned leading_ones = 0U;
    uint8_t mask = 0x80U;

    if (length_out == NULL) {
        return 0;
    }

    if ((first_byte & 0x80U) == 0U) {
        *length_out = 1U;
        return 1;
    }

    while ((first_byte & mask) != 0U && mask != 0U) {
        leading_ones++;
        mask >>= 1;
    }

    if (leading_ones < 2U || leading_ones > 7U) {
        return 0;
    }

    *length_out = (size_t)leading_ones;
    return 1;
}

static int parse_flac_frame_header(
    Reader *reader,
    uint64_t frame_abs,
    FlacFrameHeaderInfo *info_out
)
{
    uint8_t prefix[16];
    size_t utf8_length;
    size_t extra_bytes = 0U;
    size_t header_size;
    size_t index;
    uint8_t crc = 0U;
    uint8_t block_size_code;
    uint8_t sample_rate_code;
    uint8_t channel_assignment;
    uint8_t bits_per_sample_code;

    if (reader == NULL || info_out == NULL) {
        return 0;
    }

    if (!read_stream_bytes(reader, frame_abs, prefix, sizeof(prefix))) {
        return 0;
    }
    if (!is_valid_flac_frame_header_start(prefix)) {
        return 0;
    }

    if ((prefix[3] & 0x01U) != 0U) {
        return 0;
    }

    block_size_code = (prefix[2] >> 4) & 0x0FU;
    sample_rate_code = prefix[2] & 0x0FU;
    channel_assignment = (prefix[3] >> 4) & 0x0FU;
    bits_per_sample_code = (prefix[3] >> 1) & 0x07U;

    if (block_size_code == 0U || sample_rate_code == 0x0FU) {
        return 0;
    }
    if (channel_assignment > 10U) {
        return 0;
    }
    if (bits_per_sample_code == 0x03U || bits_per_sample_code == 0x07U) {
        return 0;
    }

    if (!flac_utf8_code_length(prefix[4], &utf8_length)) {
        return 0;
    }

    if (block_size_code == 6U) {
        extra_bytes += 1U;
    } else if (block_size_code == 7U) {
        extra_bytes += 2U;
    }

    if (sample_rate_code == 0x0CU) {
        extra_bytes += 1U;
    } else if (sample_rate_code == 0x0DU || sample_rate_code == 0x0EU) {
        extra_bytes += 2U;
    }

    header_size = 4U + utf8_length + extra_bytes + 1U;
    if (header_size > sizeof(prefix) || header_size < 6U) {
        return 0;
    }

    for (index = 1U; index < utf8_length; index++) {
        if ((prefix[4U + index] & 0xC0U) != 0x80U) {
            return 0;
        }
    }

    for (index = 0U; index + 1U < header_size; index++) {
        crc = crc8_update_local(crc, prefix[index]);
    }
    if (crc != prefix[header_size - 1U]) {
        return 0;
    }

    info_out->header_size = header_size;
    return 1;
}

static int parse_flac_streaminfo(
    const uint8_t data[34],
    FlacStreamInfo *info_out
)
{
    uint32_t min_frame_size;
    uint32_t max_frame_size;

    if (data == NULL || info_out == NULL) {
        return 0;
    }

    min_frame_size = ((uint32_t)data[4] << 16) |
                     ((uint32_t)data[5] << 8) |
                     (uint32_t)data[6];
    max_frame_size = ((uint32_t)data[7] << 16) |
                     ((uint32_t)data[8] << 8) |
                     (uint32_t)data[9];
    info_out->min_frame_size = min_frame_size;
    info_out->max_frame_size = max_frame_size;
    return 1;
}

static int find_next_flac_frame_sync(
    Reader *reader,
    uint64_t start_abs,
    uint64_t search_window,
    uint64_t *sync_abs_out
)
{
    uint64_t cursor = start_abs;
    uint64_t limit = start_abs + search_window;
    uint64_t source_size;
    uint8_t header[4];

    if (reader == NULL || sync_abs_out == NULL) {
        return 0;
    }
    source_size = reader_get_source_size(reader);
    if (source_size < 4U || start_abs > source_size - 4U) {
        return 0;
    }
    if (limit > source_size - 4U) {
        limit = source_size - 4U;
    }

    while (cursor + 4U <= limit) {
        FlacFrameHeaderInfo header_info;

        if (!read_stream_bytes(reader, cursor, header, sizeof(header))) {
            return 0;
        }
        if (is_valid_flac_frame_header_start(header) &&
            parse_flac_frame_header(reader, cursor, &header_info)) {
            *sync_abs_out = cursor;
            return 1;
        }
        cursor++;
    }

    return 0;
}

static int find_flac_frame_end_by_crc16(
    Reader *reader,
    uint64_t frame_abs,
    uint64_t search_window,
    const FlacStreamInfo *streaminfo,
    uint64_t *frame_end_abs_out
)
{
    uint64_t source_size;
    uint64_t available_u64;
    size_t available;
    uint8_t *buffer = NULL;
    uint16_t *prefix_crc = NULL;
    size_t min_candidate;
    size_t i;
    size_t best_end = 0U;
    FlacFrameHeaderInfo header_info;
    int ok = 0;

    if (reader == NULL || frame_end_abs_out == NULL) {
        return 0;
    }
    if (!parse_flac_frame_header(reader, frame_abs, &header_info)) {
        return 0;
    }

    source_size = reader_get_source_size(reader);
    if (frame_abs >= source_size) {
        return 0;
    }

    available_u64 = source_size - frame_abs;
    if (available_u64 > search_window) {
        available_u64 = search_window;
    }
    if (available_u64 > (uint64_t)SIZE_MAX) {
        return 0;
    }
    available = (size_t)available_u64;
    if (available < header_info.header_size + 2U) {
        return 0;
    }

    buffer = (uint8_t *)malloc(available);
    prefix_crc = (uint16_t *)malloc((available + 1U) * sizeof(uint16_t));
    if (buffer == NULL || prefix_crc == NULL) {
        goto cleanup;
    }
    if (!read_stream_bytes(reader, frame_abs, buffer, available)) {
        goto cleanup;
    }

    prefix_crc[0] = 0U;
    for (i = 0U; i < available; i++) {
        prefix_crc[i + 1U] = crc16_update_local(prefix_crc[i], buffer[i]);
    }

    min_candidate = header_info.header_size + 2U;
    if (streaminfo != NULL &&
        streaminfo->min_frame_size != 0U &&
        (size_t)streaminfo->min_frame_size > min_candidate) {
        min_candidate = (size_t)streaminfo->min_frame_size;
    }

    for (i = min_candidate; i <= available; i++) {
        uint16_t stored_crc;

        if (i < 2U) {
            continue;
        }
        stored_crc = (uint16_t)((uint16_t)buffer[i - 2U] << 8) |
                     (uint16_t)buffer[i - 1U];
        if (prefix_crc[i - 2U] == stored_crc) {
            best_end = i;
            break;
        }
    }

    if (best_end == 0U) {
        goto cleanup;
    }

    *frame_end_abs_out = frame_abs + (uint64_t)best_end;
    ok = 1;

cleanup:
    free(buffer);
    free(prefix_crc);
    return ok;
}

int carver_mp3_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    uint8_t header[10];
    uint64_t start_abs = (uint64_t)absolute_offset;
    uint64_t cursor_abs = start_abs;
    uint64_t last_resume_abs = start_abs;
    uint64_t effective_cap_bytes = audio_budget_adjusted_cap(
        MP3_MAX_REASONABLE_FILE_SIZE,
        512ULL * 1024ULL * 1024ULL,
        256ULL * 1024ULL * 1024ULL
    );
    uint64_t exploratory_cap_bytes = audio_budget_adjusted_cap(
        64ULL * 1024ULL * 1024ULL,
        32ULL * 1024ULL * 1024ULL,
        16ULL * 1024ULL * 1024ULL
    );
    uint32_t id3_total_size = 0;
    unsigned frame_count = 0;
    double duration_seconds = 0.0;
    Mp3FrameInfo stream_shape = {0};
    int have_stream_shape = 0;
    int high_confidence = 0;
    const char *confidence_reason = NULL;
    CarverOutput output = {0};

#define MP3_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_mp3_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    carver_mp3_reset_last_audit();
    if (reader == NULL || resume_offset == NULL) {
        MP3_REJECT("invalid_input", 0U);
    }
    *resume_offset = start_offset + 1U;

    if (!read_stream_bytes(reader, start_abs, header, sizeof(header))) {
        MP3_REJECT("read_header_failed", 0U);
    }

    if (memcmp(header, "ID3", 3) == 0) {
        if (!parse_id3v2_tag_size(header, &id3_total_size)) {
            MP3_REJECT("invalid_id3v2_header", 0U);
        }
        cursor_abs += (uint64_t)id3_total_size;
        audio_mark_high_confidence(
            "MP3",
            start_abs,
            frame_count,
            duration_seconds,
            &high_confidence,
            &confidence_reason,
            "leading ID3v2 tag"
        );
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "mp3")) {
        MP3_REJECT("output_open_failed", 0U);
    }

    if (id3_total_size > 0U) {
        if (!copy_stream_bytes(reader, output.file, start_abs, (uint64_t)id3_total_size)) {
            carver_output_abort(&output);
            MP3_REJECT("write_failed", cursor_abs - start_abs);
        }
        last_resume_abs = cursor_abs;
    }

    while (1) {
        Mp3FrameInfo info;
        uint8_t frame_header[4];

        if (!read_stream_bytes(reader, cursor_abs, frame_header, sizeof(frame_header))) {
            break;
        }

        if (!parse_mp3_frame_header(frame_header, &info)) {
            break;
        }

        if (!have_stream_shape) {
            stream_shape = info;
            have_stream_shape = 1;
            if (mp3_frame_has_auxiliary_tag(reader, cursor_abs, &info)) {
                audio_mark_high_confidence(
                    "MP3",
                    start_abs,
                    frame_count,
                    duration_seconds,
                    &high_confidence,
                    &confidence_reason,
                    "Xing/Info/VBRI/LAME auxiliary tag"
                );
            }
        } else if (info.version_id != stream_shape.version_id ||
                   info.layer_id != stream_shape.layer_id ||
                   info.sample_rate != stream_shape.sample_rate) {
            break;
        }

        if (!high_confidence &&
            cursor_abs - start_abs + (uint64_t)info.frame_size > exploratory_cap_bytes) {
            audio_resume_after_reject_if_useful(
                reader,
                start_abs,
                last_resume_abs,
                start_offset,
                resume_offset
            );
            carver_output_abort(&output);
            log_audio_low_confidence_cap_hit(
                "MP3",
                start_abs,
                frame_count,
                duration_seconds,
                last_resume_abs,
                exploratory_cap_bytes
            );
            MP3_REJECT("low_confidence_cap", last_resume_abs - start_abs);
        }

        if (cursor_abs - start_abs + (uint64_t)info.frame_size > effective_cap_bytes) {
            audio_resume_after_reject_if_useful(
                reader,
                start_abs,
                last_resume_abs,
                start_offset,
                resume_offset
            );
            carver_output_abort(&output);
            log_audio_budget_cap_hit(
                "MP3",
                start_abs,
                frame_count,
                last_resume_abs,
                effective_cap_bytes
            );
            MP3_REJECT("size_over_cap", last_resume_abs - start_abs);
        }

        if (!copy_stream_bytes(reader, output.file, cursor_abs, (uint64_t)info.frame_size)) {
            carver_output_abort(&output);
            MP3_REJECT("write_failed", last_resume_abs - start_abs);
        }

        cursor_abs += (uint64_t)info.frame_size;
        last_resume_abs = cursor_abs;
        frame_count++;
        duration_seconds += mp3_frame_duration_seconds(&info);
        if (!high_confidence &&
            duration_seconds >= 600.0 &&
            frame_count >= 16U) {
            audio_mark_high_confidence(
                "MP3",
                start_abs,
                frame_count,
                duration_seconds,
                &high_confidence,
                &confidence_reason,
                "very long stable MPEG frame train"
            );
        }
    }

    if (frame_count >= MP3_MIN_VALID_FRAMES &&
        mp3_stream_has_id3v1_tag(reader, cursor_abs)) {
        if (!copy_stream_bytes(reader, output.file, cursor_abs, MP3_ID3V1_TAG_SIZE)) {
            carver_output_abort(&output);
            MP3_REJECT("write_failed", last_resume_abs - start_abs);
        }
        audio_mark_high_confidence(
            "MP3",
            start_abs,
            frame_count,
            duration_seconds,
            &high_confidence,
            &confidence_reason,
            "trailing ID3v1 tag"
        );
        cursor_abs += MP3_ID3V1_TAG_SIZE;
        last_resume_abs = cursor_abs;
    }

    if (frame_count < MP3_MIN_VALID_FRAMES) {
        carver_output_abort(&output);
        MP3_REJECT("too_few_frames", last_resume_abs - start_abs);
    }

    if (!high_confidence &&
        (frame_count < MP3_LOW_CONFIDENCE_MIN_FRAMES ||
         duration_seconds < MP3_LOW_CONFIDENCE_MIN_DURATION_SECONDS)) {
        audio_resume_after_reject_if_useful(
            reader,
            start_abs,
            last_resume_abs,
            start_offset,
            resume_offset
        );
        carver_output_abort(&output);
        log_audio_low_confidence_reject(
            "MP3",
            start_abs,
            frame_count,
            duration_seconds,
            "only a short stable frame train was found and no ID3/Xing-style anchor appeared"
        );
        MP3_REJECT("low_confidence", last_resume_abs - start_abs);
    }

    if (!high_confidence) {
        log_audio_low_confidence_accept(
            "MP3",
            start_abs,
            frame_count,
            duration_seconds,
            "stable MPEG frames persisted long enough even though no metadata anchor was found"
        );
    } else {
        (void)confidence_reason;
    }

    if (!carver_output_finish(&output)) {
        MP3_REJECT("finish_failed", last_resume_abs - start_abs);
    }

    compute_resume_offset_local(reader, last_resume_abs, start_offset, resume_offset);
    carver_audit_set_inline(
        &g_mp3_last_audit,
        high_confidence ? "recovered" : "recovered_suspicious",
        high_confidence ? "accepted" : "low_confidence_accepted",
        carver_audit_span_from_u64(last_resume_abs - start_abs));
#undef MP3_REJECT
    return 1;
}

int carver_aac_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    uint64_t start_abs = (uint64_t)absolute_offset;
    uint64_t cursor_abs = start_abs;
    uint64_t last_resume_abs = start_abs;
    uint64_t effective_cap_bytes = audio_budget_adjusted_cap(
        AAC_MAX_REASONABLE_FILE_SIZE,
        256ULL * 1024ULL * 1024ULL,
        128ULL * 1024ULL * 1024ULL
    );
    uint64_t exploratory_cap_bytes = audio_budget_adjusted_cap(
        32ULL * 1024ULL * 1024ULL,
        16ULL * 1024ULL * 1024ULL,
        8ULL * 1024ULL * 1024ULL
    );
    unsigned frame_count = 0;
    double duration_seconds = 0.0;
    AacFrameInfo stream_shape = {0};
    int have_stream_shape = 0;
    int high_confidence = 0;
    const char *confidence_reason = NULL;
    CarverOutput output = {0};

#define AAC_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_aac_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    carver_aac_reset_last_audit();
    if (reader == NULL || resume_offset == NULL) {
        AAC_REJECT("invalid_input", 0U);
    }
    *resume_offset = start_offset + 1U;

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "aac")) {
        AAC_REJECT("output_open_failed", 0U);
    }

    while (1) {
        AacFrameInfo info;
        uint8_t frame_header[7];

        if (!read_stream_bytes(reader, cursor_abs, frame_header, sizeof(frame_header))) {
            break;
        }

        if (!parse_aac_frame_header(frame_header, &info)) {
            break;
        }

        if (!have_stream_shape) {
            stream_shape = info;
            have_stream_shape = 1;
        } else if (info.profile != stream_shape.profile ||
                   info.sample_rate_index != stream_shape.sample_rate_index ||
                   info.channel_config != stream_shape.channel_config) {
            break;
        }

        if (!high_confidence &&
            cursor_abs - start_abs + (uint64_t)info.frame_size > exploratory_cap_bytes) {
            audio_resume_after_reject_if_useful(
                reader,
                start_abs,
                last_resume_abs,
                start_offset,
                resume_offset
            );
            carver_output_abort(&output);
            log_audio_low_confidence_cap_hit(
                "AAC",
                start_abs,
                frame_count,
                duration_seconds,
                last_resume_abs,
                exploratory_cap_bytes
            );
            AAC_REJECT("low_confidence_cap", last_resume_abs - start_abs);
        }

        if (cursor_abs - start_abs + (uint64_t)info.frame_size > effective_cap_bytes) {
            audio_resume_after_reject_if_useful(
                reader,
                start_abs,
                last_resume_abs,
                start_offset,
                resume_offset
            );
            carver_output_abort(&output);
            log_audio_budget_cap_hit(
                "AAC",
                start_abs,
                frame_count,
                last_resume_abs,
                effective_cap_bytes
            );
            AAC_REJECT("size_over_cap", last_resume_abs - start_abs);
        }

        if (!copy_stream_bytes(reader, output.file, cursor_abs, (uint64_t)info.frame_size)) {
            carver_output_abort(&output);
            AAC_REJECT("write_failed", last_resume_abs - start_abs);
        }

        cursor_abs += (uint64_t)info.frame_size;
        last_resume_abs = cursor_abs;
        frame_count++;
        duration_seconds += aac_frame_duration_seconds(&info);
        if (!high_confidence &&
            duration_seconds >= 300.0 &&
            frame_count >= 32U) {
            audio_mark_high_confidence(
                "AAC",
                start_abs,
                frame_count,
                duration_seconds,
                &high_confidence,
                &confidence_reason,
                "very long stable ADTS frame train"
            );
        }
    }

    if (frame_count < AAC_MIN_VALID_FRAMES) {
        carver_output_abort(&output);
        AAC_REJECT("too_few_frames", last_resume_abs - start_abs);
    }

    if (!high_confidence &&
        (frame_count < AAC_LOW_CONFIDENCE_MIN_FRAMES ||
         duration_seconds < AAC_LOW_CONFIDENCE_MIN_DURATION_SECONDS)) {
        audio_resume_after_reject_if_useful(
            reader,
            start_abs,
            last_resume_abs,
            start_offset,
            resume_offset
        );
        carver_output_abort(&output);
        log_audio_low_confidence_reject(
            "AAC",
            start_abs,
            frame_count,
            duration_seconds,
            "only a short stable ADTS frame train was found and AAC offered no stronger metadata anchor"
        );
        AAC_REJECT("low_confidence", last_resume_abs - start_abs);
    }

    if (!high_confidence) {
        log_audio_low_confidence_accept(
            "AAC",
            start_abs,
            frame_count,
            duration_seconds,
            "stable ADTS frames persisted long enough even though the stream never gained richer metadata evidence"
        );
    } else {
        (void)confidence_reason;
    }

    if (!carver_output_finish(&output)) {
        AAC_REJECT("finish_failed", last_resume_abs - start_abs);
    }

    compute_resume_offset_local(reader, last_resume_abs, start_offset, resume_offset);
    carver_audit_set_inline(
        &g_aac_last_audit,
        high_confidence ? "recovered" : "recovered_suspicious",
        high_confidence ? "accepted" : "low_confidence_accepted",
        carver_audit_span_from_u64(last_resume_abs - start_abs));
#undef AAC_REJECT
    return 1;
}

int carver_flac_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
)
{
    uint8_t marker[4];
    uint64_t start_abs = (uint64_t)absolute_offset;
    uint64_t cursor_abs = start_abs + 4U;
    uint64_t effective_cap_bytes = audio_budget_adjusted_cap(
        FLAC_MAX_REASONABLE_FILE_SIZE,
        FLAC_MAX_REASONABLE_FILE_SIZE,
        2ULL * 1024ULL * 1024ULL * 1024ULL
    );
    uint64_t metadata_bytes = 4U;
    uint64_t audio_start_abs;
    uint64_t frame_abs;
    uint64_t last_resume_abs = start_abs;
    FlacStreamInfo streaminfo = {0};
    unsigned bounded_frames = 0;
    CarverOutput output = {0};
    int first_block = 1;
    int saw_last_metadata = 0;

#define FLAC_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_flac_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    carver_flac_reset_last_audit();
    if (reader == NULL || resume_offset == NULL) {
        FLAC_REJECT("invalid_input", 0U);
    }
    *resume_offset = start_offset + 1U;

    if (!read_stream_bytes(reader, start_abs, marker, sizeof(marker))) {
        FLAC_REJECT("read_header_failed", 0U);
    }
    if (memcmp(marker, "fLaC", 4) != 0) {
        FLAC_REJECT("missing_flac_marker", 0U);
    }

    while (!saw_last_metadata) {
        uint8_t block_header[4];
        uint8_t block_data[34];
        uint32_t block_length;
        uint8_t block_type;

        if (!read_stream_bytes(reader, cursor_abs, block_header, sizeof(block_header))) {
            FLAC_REJECT("read_metadata_header_failed", cursor_abs - start_abs);
        }

        saw_last_metadata = (block_header[0] & 0x80U) != 0U;
        block_type = block_header[0] & 0x7FU;
        block_length = ((uint32_t)block_header[1] << 16) |
                       ((uint32_t)block_header[2] << 8) |
                       (uint32_t)block_header[3];

        if (metadata_bytes + 4U + (uint64_t)block_length > FLAC_MAX_METADATA_BYTES) {
            FLAC_REJECT("metadata_over_cap", metadata_bytes);
        }
        if (first_block && (block_type != 0U || block_length != 34U)) {
            FLAC_REJECT("missing_streaminfo", metadata_bytes);
        }

        cursor_abs += 4U;
        metadata_bytes += 4U + (uint64_t)block_length;

        if (block_type == 0U) {
            if (!read_stream_bytes(reader, cursor_abs, block_data, sizeof(block_data))) {
                FLAC_REJECT("read_streaminfo_failed", metadata_bytes);
            }
            if (!parse_flac_streaminfo(block_data, &streaminfo)) {
                FLAC_REJECT("invalid_streaminfo", metadata_bytes);
            }
        }

        cursor_abs += (uint64_t)block_length;
        first_block = 0;
    }

    audio_start_abs = cursor_abs;
    frame_abs = audio_start_abs;

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "flac")) {
        FLAC_REJECT("output_open_failed", 0U);
    }

    if (!copy_stream_bytes(reader, output.file, start_abs, audio_start_abs - start_abs)) {
        carver_output_abort(&output);
        FLAC_REJECT("write_failed", last_resume_abs - start_abs);
    }
    last_resume_abs = audio_start_abs;

    while (1) {
        FlacFrameHeaderInfo header_info;
        uint64_t next_frame_abs;
        uint64_t search_window = streaminfo.max_frame_size != 0U
            ? (uint64_t)streaminfo.max_frame_size + 16U
            : (uint64_t)FLAC_DEFAULT_FRAME_SEARCH_WINDOW;
        uint64_t frame_end_abs;

        if (!parse_flac_frame_header(reader, frame_abs, &header_info)) {
            break;
        }
        if (!find_next_flac_frame_sync(
                reader,
                frame_abs + header_info.header_size,
                search_window,
                &next_frame_abs)) {
            if (!find_flac_frame_end_by_crc16(
                    reader,
                    frame_abs,
                    search_window,
                    &streaminfo,
                    &frame_end_abs)) {
                break;
            }
            if (frame_end_abs <= frame_abs) {
                break;
            }
            if (frame_end_abs - start_abs > effective_cap_bytes) {
                audio_resume_after_reject_if_useful(
                    reader,
                    start_abs,
                    last_resume_abs,
                    start_offset,
                    resume_offset
                );
                carver_output_abort(&output);
                log_audio_budget_cap_hit(
                    "FLAC",
                    start_abs,
                    bounded_frames,
                    last_resume_abs,
                    effective_cap_bytes
                );
                FLAC_REJECT("size_over_cap", last_resume_abs - start_abs);
            }
            if (!copy_stream_bytes(reader, output.file, frame_abs, frame_end_abs - frame_abs)) {
                carver_output_abort(&output);
                FLAC_REJECT("write_failed", last_resume_abs - start_abs);
            }
            bounded_frames++;
            last_resume_abs = frame_end_abs;
            frame_abs = frame_end_abs;
            break;
        }
        if (next_frame_abs <= frame_abs) {
            break;
        }
        if (next_frame_abs - start_abs > effective_cap_bytes) {
            audio_resume_after_reject_if_useful(
                reader,
                start_abs,
                last_resume_abs,
                start_offset,
                resume_offset
            );
            carver_output_abort(&output);
            log_audio_budget_cap_hit(
                "FLAC",
                start_abs,
                bounded_frames,
                last_resume_abs,
                effective_cap_bytes
            );
            FLAC_REJECT("size_over_cap", last_resume_abs - start_abs);
        }

        if (!copy_stream_bytes(reader, output.file, frame_abs, next_frame_abs - frame_abs)) {
            carver_output_abort(&output);
            FLAC_REJECT("write_failed", last_resume_abs - start_abs);
        }

        bounded_frames++;
        frame_abs = next_frame_abs;
        last_resume_abs = frame_abs;
    }

    {
        uint64_t source_size = reader_get_source_size(reader);
        uint64_t remaining_bytes = frame_abs < source_size
            ? source_size - frame_abs
            : 0U;
        uint64_t search_window = streaminfo.max_frame_size != 0U
            ? (uint64_t)streaminfo.max_frame_size + 16U
            : (uint64_t)FLAC_DEFAULT_FRAME_SEARCH_WINDOW;
        uint64_t frame_end_abs;

        if (remaining_bytes >= 2U &&
            remaining_bytes <= search_window &&
            find_flac_frame_end_by_crc16(
                reader,
                frame_abs,
                search_window,
                &streaminfo,
                &frame_end_abs) &&
            frame_end_abs > frame_abs) {
            if (frame_end_abs - start_abs > effective_cap_bytes) {
                audio_resume_after_reject_if_useful(
                    reader,
                    start_abs,
                    last_resume_abs,
                    start_offset,
                    resume_offset
                );
                carver_output_abort(&output);
                log_audio_budget_cap_hit(
                    "FLAC",
                    start_abs,
                    bounded_frames,
                    last_resume_abs,
                    effective_cap_bytes
                );
                FLAC_REJECT("size_over_cap", last_resume_abs - start_abs);
            }
            if (!copy_stream_bytes(reader, output.file, frame_abs, frame_end_abs - frame_abs)) {
                carver_output_abort(&output);
                FLAC_REJECT("write_failed", last_resume_abs - start_abs);
            }
            bounded_frames++;
            last_resume_abs = frame_end_abs;
        }
    }

    if (bounded_frames < FLAC_MIN_BOUNDED_FRAMES) {
        carver_output_abort(&output);
        FLAC_REJECT("too_few_bounded_frames", last_resume_abs - start_abs);
    }

    if (!carver_output_finish(&output)) {
        FLAC_REJECT("finish_failed", last_resume_abs - start_abs);
    }

    compute_resume_offset_local(reader, last_resume_abs, start_offset, resume_offset);
    carver_audit_set_inline(
        &g_flac_last_audit,
        "recovered",
        "accepted",
        carver_audit_span_from_u64(last_resume_abs - start_abs));
#undef FLAC_REJECT
    return 1;
}
