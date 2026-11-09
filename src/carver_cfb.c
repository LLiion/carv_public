#include "carver_cfb.h"

#include "carver_output.h"
#include "config.h"
#include "recovery_runner.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CFB_HEADER_SIZE 512U
#define CFB_SIGNATURE_SIZE 8U
#define CFB_DIFAT_HEADER_COUNT 109U
#define CFB_DIR_ENTRY_SIZE 128U
#define CFB_MINI_STREAM_CUTOFF_DEFAULT 4096U
#define CFB_MAX_FAT_BYTES (64ULL * 1024ULL * 1024ULL)
#define CFB_MAX_DIRECTORY_BYTES (32ULL * 1024ULL * 1024ULL)
#define CFB_MAX_REASONABLE_SPAN (16ULL * 1024ULL * 1024ULL * 1024ULL)
#define CFB_COPY_CHUNK_SIZE (1024U * 1024U)

#define CFB_FREESECT 0xFFFFFFFFU
#define CFB_ENDOFCHAIN 0xFFFFFFFEU
#define CFB_FATSECT 0xFFFFFFFDU
#define CFB_DIFSECT 0xFFFFFFFCU
#define CFB_MAXREGSECT 0xFFFFFFFAU

typedef struct {
    uint16_t major_version;
    uint16_t sector_shift;
    uint16_t mini_sector_shift;
    uint32_t sector_size;
    uint32_t mini_cutoff;
    uint32_t first_directory_sector;
    uint32_t first_mini_fat_sector;
    uint32_t mini_fat_sector_count;
    uint32_t first_difat_sector;
    uint32_t difat_sector_count;
    uint32_t fat_sector_count;
    uint32_t header_difat[CFB_DIFAT_HEADER_COUNT];
} CfbHeader;

typedef struct {
    int word_score;
    int excel_score;
    int powerpoint_score;
    int msg_score;
    int access_score;
    int visio_score;
    int publisher_score;
} CfbClassification;

typedef struct {
    uint64_t confirmed_span;
    const char *extension;
} CfbAnalysis;

static CarverAuditReport g_cfb_last_audit;

void carver_cfb_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_cfb_last_audit);
}

void carver_cfb_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_cfb_last_audit;
}

static uint16_t read_u16_le_local(const uint8_t *data)
{
    return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static uint32_t read_u32_le_local(const uint8_t *data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint64_t read_u64_le_local(const uint8_t *data)
{
    uint64_t lo = read_u32_le_local(data);
    uint64_t hi = read_u32_le_local(data + 4);

    return lo | (hi << 32);
}

static int cfb_sector_regular(uint32_t sector)
{
    return sector <= CFB_MAXREGSECT;
}

static uint64_t reader_buffer_base_absolute_local(const Reader *reader)
{
    if (reader == NULL ||
        (uint64_t)reader->bytes_in_buffer > (uint64_t)reader->total_bytes_read) {
        return 0U;
    }
    return (uint64_t)reader->total_bytes_read - (uint64_t)reader->bytes_in_buffer;
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

    base_abs = reader_buffer_base_absolute_local(reader);
    if (resume_abs < base_abs) {
        *resume_offset_out = fallback_offset + 1U;
        return 1;
    }
    if (resume_abs >= base_abs + (uint64_t)reader->bytes_in_buffer) {
        *resume_offset_out = reader->bytes_in_buffer;
        return 1;
    }

    *resume_offset_out = (size_t)(resume_abs - base_abs);
    return 1;
}

static int cfb_read_exact_fd(
    const Reader *reader,
    uint64_t absolute_offset,
    uint8_t *buffer,
    size_t byte_count
)
{
    uint64_t failed_at = 0U;
    size_t got;

    if (reader == NULL || reader->fd < 0 || buffer == NULL || byte_count == 0U) {
        return 0;
    }
    if (reader->source_size > 0U &&
        ((uint64_t)absolute_offset >= reader->source_size ||
         (uint64_t)byte_count > reader->source_size - absolute_offset)) {
        return 0;
    }

    got = recovery_runner_read_with_fallback(
        reader->fd,
        buffer,
        absolute_offset,
        byte_count,
        &failed_at);
    return got == byte_count;
}

static int cfb_sector_abs_offset(
    uint64_t base_abs,
    uint32_t sector_size,
    uint32_t sector,
    uint64_t *out_abs
)
{
    uint64_t sector_index;
    uint64_t relative;

    if (out_abs == NULL || !cfb_sector_regular(sector)) {
        return 0;
    }
    sector_index = (uint64_t)sector + 1ULL;
    if (sector_index > UINT64_MAX / (uint64_t)sector_size) {
        return 0;
    }
    relative = sector_index * (uint64_t)sector_size;
    if (base_abs > UINT64_MAX - relative) {
        return 0;
    }
    *out_abs = base_abs + relative;
    return 1;
}

static int cfb_parse_header(
    const uint8_t *header,
    CfbHeader *out,
    const char **reject_reason
)
{
    static const uint8_t signature[CFB_SIGNATURE_SIZE] = {
        0xd0U, 0xcfU, 0x11U, 0xe0U, 0xa1U, 0xb1U, 0x1aU, 0xe1U
    };
    size_t i;
    uint16_t byte_order;

    if (header == NULL || out == NULL) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_input";
        }
        return 0;
    }
    if (memcmp(header, signature, sizeof(signature)) != 0) {
        if (reject_reason != NULL) {
            *reject_reason = "missing_cfb_header";
        }
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->major_version = read_u16_le_local(header + 0x1aU);
    byte_order = read_u16_le_local(header + 0x1cU);
    out->sector_shift = read_u16_le_local(header + 0x1eU);
    out->mini_sector_shift = read_u16_le_local(header + 0x20U);
    out->fat_sector_count = read_u32_le_local(header + 0x2cU);
    out->first_directory_sector = read_u32_le_local(header + 0x30U);
    out->mini_cutoff = read_u32_le_local(header + 0x38U);
    out->first_mini_fat_sector = read_u32_le_local(header + 0x3cU);
    out->mini_fat_sector_count = read_u32_le_local(header + 0x40U);
    out->first_difat_sector = read_u32_le_local(header + 0x44U);
    out->difat_sector_count = read_u32_le_local(header + 0x48U);

    if (byte_order != 0xfffeU) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_byte_order";
        }
        return 0;
    }
    if (out->sector_shift != 9U && out->sector_shift != 12U) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_sector_shift";
        }
        return 0;
    }
    if (out->mini_sector_shift != 6U) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_mini_sector_shift";
        }
        return 0;
    }
    out->sector_size = 1U << out->sector_shift;
    if (out->mini_cutoff == 0U) {
        out->mini_cutoff = CFB_MINI_STREAM_CUTOFF_DEFAULT;
    }
    if (out->fat_sector_count == 0U ||
        (uint64_t)out->fat_sector_count * (uint64_t)out->sector_size >
            CFB_MAX_FAT_BYTES) {
        if (reject_reason != NULL) {
            *reject_reason = "fat_too_large";
        }
        return 0;
    }
    if (!cfb_sector_regular(out->first_directory_sector)) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_directory_start";
        }
        return 0;
    }

    for (i = 0U; i < CFB_DIFAT_HEADER_COUNT; i++) {
        out->header_difat[i] =
            read_u32_le_local(header + 0x4cU + (i * sizeof(uint32_t)));
    }

    return 1;
}

static int cfb_collect_fat_sector_ids(
    const Reader *reader,
    uint64_t base_abs,
    const CfbHeader *header,
    uint32_t **ids_out,
    size_t *count_out,
    uint64_t *max_sector_out,
    const char **reject_reason
)
{
    uint32_t *ids = NULL;
    uint8_t *sector_data = NULL;
    size_t count = 0U;
    size_t i;
    uint32_t difat_sector;
    size_t difat_steps = 0U;
    size_t difat_limit;
    size_t entries_per_difat_sector;

    if (reader == NULL || header == NULL || ids_out == NULL || count_out == NULL) {
        return 0;
    }

    ids = (uint32_t *)calloc(header->fat_sector_count, sizeof(*ids));
    if (ids == NULL) {
        if (reject_reason != NULL) {
            *reject_reason = "out_of_memory";
        }
        return 0;
    }

    for (i = 0U; i < CFB_DIFAT_HEADER_COUNT && count < header->fat_sector_count; i++) {
        uint32_t sector = header->header_difat[i];

        if (cfb_sector_regular(sector)) {
            ids[count++] = sector;
            if (max_sector_out != NULL && sector > *max_sector_out) {
                *max_sector_out = sector;
            }
        }
    }

    if (count >= header->fat_sector_count) {
        *ids_out = ids;
        *count_out = count;
        return 1;
    }
    if (!cfb_sector_regular(header->first_difat_sector)) {
        free(ids);
        if (reject_reason != NULL) {
            *reject_reason = "missing_difat";
        }
        return 0;
    }

    sector_data = (uint8_t *)malloc(header->sector_size);
    if (sector_data == NULL) {
        free(ids);
        if (reject_reason != NULL) {
            *reject_reason = "out_of_memory";
        }
        return 0;
    }

    entries_per_difat_sector = (header->sector_size / sizeof(uint32_t)) - 1U;
    difat_limit = header->difat_sector_count + 1U;
    difat_sector = header->first_difat_sector;
    while (count < header->fat_sector_count && cfb_sector_regular(difat_sector)) {
        uint64_t sector_abs;
        uint32_t next_difat;

        if (difat_steps++ > difat_limit) {
            free(sector_data);
            free(ids);
            if (reject_reason != NULL) {
                *reject_reason = "difat_loop";
            }
            return 0;
        }
        if (!cfb_sector_abs_offset(base_abs, header->sector_size, difat_sector, &sector_abs) ||
            !cfb_read_exact_fd(reader, sector_abs, sector_data, header->sector_size)) {
            free(sector_data);
            free(ids);
            if (reject_reason != NULL) {
                *reject_reason = "source_eof_before_difat";
            }
            return 0;
        }
        if (max_sector_out != NULL && difat_sector > *max_sector_out) {
            *max_sector_out = difat_sector;
        }

        for (i = 0U; i < entries_per_difat_sector && count < header->fat_sector_count; i++) {
            uint32_t sector = read_u32_le_local(sector_data + (i * sizeof(uint32_t)));

            if (cfb_sector_regular(sector)) {
                ids[count++] = sector;
                if (max_sector_out != NULL && sector > *max_sector_out) {
                    *max_sector_out = sector;
                }
            }
        }
        next_difat = read_u32_le_local(
            sector_data + (entries_per_difat_sector * sizeof(uint32_t)));
        difat_sector = next_difat;
    }

    free(sector_data);
    if (count < header->fat_sector_count) {
        free(ids);
        if (reject_reason != NULL) {
            *reject_reason = "incomplete_difat";
        }
        return 0;
    }

    *ids_out = ids;
    *count_out = count;
    return 1;
}

static int cfb_load_fat(
    const Reader *reader,
    uint64_t base_abs,
    const CfbHeader *header,
    const uint32_t *fat_sector_ids,
    size_t fat_sector_id_count,
    uint32_t **fat_out,
    size_t *fat_count_out,
    const char **reject_reason
)
{
    uint32_t *fat = NULL;
    uint8_t *sector_data = NULL;
    size_t entries_per_sector;
    size_t total_entries;
    size_t out_index = 0U;
    size_t i;

    if (reader == NULL ||
        header == NULL ||
        fat_sector_ids == NULL ||
        fat_out == NULL ||
        fat_count_out == NULL) {
        return 0;
    }

    entries_per_sector = header->sector_size / sizeof(uint32_t);
    if (fat_sector_id_count > SIZE_MAX / entries_per_sector) {
        if (reject_reason != NULL) {
            *reject_reason = "fat_too_large";
        }
        return 0;
    }
    total_entries = fat_sector_id_count * entries_per_sector;
    if (total_entries == 0U ||
        total_entries > SIZE_MAX / sizeof(uint32_t)) {
        if (reject_reason != NULL) {
            *reject_reason = "fat_too_large";
        }
        return 0;
    }

    fat = (uint32_t *)malloc(total_entries * sizeof(*fat));
    sector_data = (uint8_t *)malloc(header->sector_size);
    if (fat == NULL || sector_data == NULL) {
        free(fat);
        free(sector_data);
        if (reject_reason != NULL) {
            *reject_reason = "out_of_memory";
        }
        return 0;
    }

    for (i = 0U; i < fat_sector_id_count; i++) {
        uint64_t sector_abs;
        size_t j;

        if (!cfb_sector_abs_offset(
                base_abs,
                header->sector_size,
                fat_sector_ids[i],
                &sector_abs) ||
            !cfb_read_exact_fd(reader, sector_abs, sector_data, header->sector_size)) {
            free(fat);
            free(sector_data);
            if (reject_reason != NULL) {
                *reject_reason = "source_eof_before_fat";
            }
            return 0;
        }
        for (j = 0U; j < entries_per_sector; j++) {
            fat[out_index++] =
                read_u32_le_local(sector_data + (j * sizeof(uint32_t)));
        }
    }

    free(sector_data);
    *fat_out = fat;
    *fat_count_out = total_entries;
    return 1;
}

static int cfb_append_sector_id(
    uint32_t **items,
    size_t *count,
    size_t *capacity,
    uint32_t value
)
{
    uint32_t *new_items;
    size_t new_capacity;

    if (items == NULL || count == NULL || capacity == NULL) {
        return 0;
    }
    if (*count < *capacity) {
        (*items)[(*count)++] = value;
        return 1;
    }

    new_capacity = (*capacity == 0U) ? 32U : (*capacity * 2U);
    if (new_capacity <= *capacity ||
        new_capacity > SIZE_MAX / sizeof(uint32_t)) {
        return 0;
    }
    new_items = (uint32_t *)realloc(*items, new_capacity * sizeof(*new_items));
    if (new_items == NULL) {
        return 0;
    }
    *items = new_items;
    *capacity = new_capacity;
    (*items)[(*count)++] = value;
    return 1;
}

static int cfb_collect_chain(
    const uint32_t *fat,
    size_t fat_count,
    uint32_t start_sector,
    uint32_t **sectors_out,
    size_t *sector_count_out,
    uint64_t *max_sector_out,
    const char **reject_reason
)
{
    uint32_t *items = NULL;
    size_t count = 0U;
    size_t capacity = 0U;
    uint32_t sector = start_sector;
    size_t steps = 0U;

    if (fat == NULL || sectors_out == NULL || sector_count_out == NULL) {
        return 0;
    }
    if (!cfb_sector_regular(sector)) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_chain_start";
        }
        return 0;
    }

    while (cfb_sector_regular(sector)) {
        uint32_t next_sector;

        if ((size_t)sector >= fat_count || steps++ > fat_count) {
            free(items);
            if (reject_reason != NULL) {
                *reject_reason = "fat_chain_invalid";
            }
            return 0;
        }
        if (!cfb_append_sector_id(&items, &count, &capacity, sector)) {
            free(items);
            if (reject_reason != NULL) {
                *reject_reason = "out_of_memory";
            }
            return 0;
        }
        if (max_sector_out != NULL && sector > *max_sector_out) {
            *max_sector_out = sector;
        }
        next_sector = fat[sector];
        if (next_sector == CFB_ENDOFCHAIN) {
            *sectors_out = items;
            *sector_count_out = count;
            return 1;
        }
        if (!cfb_sector_regular(next_sector)) {
            free(items);
            if (reject_reason != NULL) {
                *reject_reason = "fat_chain_special_sector";
            }
            return 0;
        }
        sector = next_sector;
    }

    free(items);
    if (reject_reason != NULL) {
        *reject_reason = "fat_chain_invalid";
    }
    return 0;
}

static int cfb_walk_chain_for_max(
    const uint32_t *fat,
    size_t fat_count,
    uint32_t start_sector,
    uint64_t *max_sector_out
)
{
    uint32_t sector = start_sector;
    size_t steps = 0U;

    if (fat == NULL || !cfb_sector_regular(sector)) {
        return 0;
    }
    while (cfb_sector_regular(sector)) {
        uint32_t next_sector;

        if ((size_t)sector >= fat_count || steps++ > fat_count) {
            return 0;
        }
        if (max_sector_out != NULL && sector > *max_sector_out) {
            *max_sector_out = sector;
        }
        next_sector = fat[sector];
        if (next_sector == CFB_ENDOFCHAIN) {
            return 1;
        }
        if (!cfb_sector_regular(next_sector)) {
            return 0;
        }
        sector = next_sector;
    }
    return 0;
}

static void cfb_utf16le_name_to_ascii(
    const uint8_t *entry,
    char *out,
    size_t out_size
)
{
    uint16_t name_len_bytes;
    size_t chars;
    size_t i;
    size_t write_pos = 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }
    out[0] = '\0';
    if (entry == NULL) {
        return;
    }

    name_len_bytes = read_u16_le_local(entry + 0x40U);
    if (name_len_bytes < 2U || name_len_bytes > 64U) {
        return;
    }
    chars = (size_t)(name_len_bytes / 2U);
    if (chars > 0U) {
        chars--;
    }

    for (i = 0U; i < chars && write_pos + 1U < out_size; i++) {
        uint16_t ch = read_u16_le_local(entry + (i * 2U));

        if (ch >= 32U && ch < 127U) {
            out[write_pos++] = (char)ch;
        } else if (ch == 0x0005U) {
            out[write_pos++] = '_';
        }
    }
    out[write_pos] = '\0';
}

static int ascii_tolower_local(int c)
{
    return c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c;
}

static int streq_ci_local(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }
    while (*a != '\0' && *b != '\0') {
        if (ascii_tolower_local((unsigned char)*a) !=
            ascii_tolower_local((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int starts_with_ci_local(const char *text, const char *prefix)
{
    if (text == NULL || prefix == NULL) {
        return 0;
    }
    while (*prefix != '\0') {
        if (*text == '\0' ||
            ascii_tolower_local((unsigned char)*text) !=
                ascii_tolower_local((unsigned char)*prefix)) {
            return 0;
        }
        text++;
        prefix++;
    }
    return 1;
}

static int contains_ci_local(const char *text, const char *needle)
{
    size_t needle_len;
    const char *cursor;

    if (text == NULL || needle == NULL || needle[0] == '\0') {
        return 0;
    }
    needle_len = strlen(needle);
    for (cursor = text; *cursor != '\0'; cursor++) {
        size_t i;

        for (i = 0U; i < needle_len; i++) {
            if (cursor[i] == '\0' ||
                ascii_tolower_local((unsigned char)cursor[i]) !=
                    ascii_tolower_local((unsigned char)needle[i])) {
                break;
            }
        }
        if (i == needle_len) {
            return 1;
        }
    }
    return 0;
}

static void cfb_classify_stream_name(
    const char *name,
    uint8_t object_type,
    CfbClassification *classification
)
{
    if (name == NULL || classification == NULL || name[0] == '\0') {
        return;
    }
    if (object_type != 1U && object_type != 2U && object_type != 5U) {
        return;
    }

    if (streq_ci_local(name, "WordDocument")) {
        classification->word_score += 10;
    }
    if (streq_ci_local(name, "Workbook") ||
        streq_ci_local(name, "Book")) {
        classification->excel_score += 10;
    }
    if (streq_ci_local(name, "PowerPoint Document") ||
        streq_ci_local(name, "Pictures")) {
        classification->powerpoint_score += 8;
    }
    if (starts_with_ci_local(name, "__substg1.0_") ||
        starts_with_ci_local(name, "__nameid_version1.0")) {
        classification->msg_score += 4;
    }
    if (streq_ci_local(name, "VisioDocument") ||
        starts_with_ci_local(name, "Visio")) {
        classification->visio_score += 10;
    }
    if (streq_ci_local(name, "AccessObjSiteData") ||
        streq_ci_local(name, "MSysObjects") ||
        contains_ci_local(name, "Access")) {
        classification->access_score += 6;
    }
    if (streq_ci_local(name, "Quill") ||
        streq_ci_local(name, "Escher") ||
        streq_ci_local(name, "Contents") ||
        streq_ci_local(name, "Contents2") ||
        contains_ci_local(name, "Publisher")) {
        classification->publisher_score += 4;
    }
}

static const char *cfb_choose_extension(
    const CfbClassification *classification,
    uint32_t allowed_extensions
)
{
    int best_score = 0;
    const char *best_extension = NULL;

#define CFB_CONSIDER(score_value, ext_name, allow_bit) \
    do { \
        int local_score = (score_value); \
        if (local_score > best_score && ((allowed_extensions) & (allow_bit)) != 0U) { \
            best_score = local_score; \
            best_extension = (ext_name); \
        } \
    } while (0)

    if (classification == NULL) {
        return NULL;
    }

    CFB_CONSIDER(classification->msg_score, "msg", CARVER_CFB_ALLOW_MSG);
    CFB_CONSIDER(classification->visio_score, "vsd", CARVER_CFB_ALLOW_VSD);
    CFB_CONSIDER(classification->access_score, "mdb", CARVER_CFB_ALLOW_MDB);
    CFB_CONSIDER(classification->publisher_score, "pub", CARVER_CFB_ALLOW_PUB);

    if ((allowed_extensions & CARVER_CFB_ALLOW_DOC) != 0U) {
        CFB_CONSIDER(classification->word_score, "doc", CARVER_CFB_ALLOW_DOC);
    } else {
        CFB_CONSIDER(classification->word_score, "dot", CARVER_CFB_ALLOW_DOT);
        CFB_CONSIDER(classification->word_score, "wiz", CARVER_CFB_ALLOW_WIZ);
    }

    if ((allowed_extensions & CARVER_CFB_ALLOW_XLS) != 0U) {
        CFB_CONSIDER(classification->excel_score, "xls", CARVER_CFB_ALLOW_XLS);
    } else {
        CFB_CONSIDER(classification->excel_score, "xla", CARVER_CFB_ALLOW_XLA);
    }

    if ((allowed_extensions & CARVER_CFB_ALLOW_PPT) != 0U) {
        CFB_CONSIDER(
            classification->powerpoint_score,
            "ppt",
            CARVER_CFB_ALLOW_PPT);
    } else {
        CFB_CONSIDER(
            classification->powerpoint_score,
            "pps",
            CARVER_CFB_ALLOW_PPS);
    }

#undef CFB_CONSIDER

    return best_score > 0 ? best_extension : NULL;
}

static int cfb_analyze_directory(
    const Reader *reader,
    uint64_t base_abs,
    const CfbHeader *header,
    const uint32_t *fat,
    size_t fat_count,
    uint64_t *max_sector_out,
    CfbClassification *classification,
    const char **reject_reason
)
{
    uint32_t *dir_sectors = NULL;
    size_t dir_sector_count = 0U;
    uint8_t *dir_data = NULL;
    size_t dir_bytes;
    size_t i;

    if (reader == NULL ||
        header == NULL ||
        fat == NULL ||
        classification == NULL) {
        return 0;
    }

    if (!cfb_collect_chain(
            fat,
            fat_count,
            header->first_directory_sector,
            &dir_sectors,
            &dir_sector_count,
            max_sector_out,
            reject_reason)) {
        return 0;
    }
    if (dir_sector_count == 0U ||
        (uint64_t)dir_sector_count * (uint64_t)header->sector_size >
            CFB_MAX_DIRECTORY_BYTES) {
        free(dir_sectors);
        if (reject_reason != NULL) {
            *reject_reason = "directory_too_large";
        }
        return 0;
    }
    dir_bytes = dir_sector_count * (size_t)header->sector_size;
    dir_data = (uint8_t *)malloc(dir_bytes);
    if (dir_data == NULL) {
        free(dir_sectors);
        if (reject_reason != NULL) {
            *reject_reason = "out_of_memory";
        }
        return 0;
    }

    for (i = 0U; i < dir_sector_count; i++) {
        uint64_t sector_abs;

        if (!cfb_sector_abs_offset(
                base_abs,
                header->sector_size,
                dir_sectors[i],
                &sector_abs) ||
            !cfb_read_exact_fd(
                reader,
                sector_abs,
                dir_data + (i * (size_t)header->sector_size),
                header->sector_size)) {
            free(dir_data);
            free(dir_sectors);
            if (reject_reason != NULL) {
                *reject_reason = "source_eof_before_directory";
            }
            return 0;
        }
    }
    free(dir_sectors);

    for (i = 0U; i + CFB_DIR_ENTRY_SIZE <= dir_bytes; i += CFB_DIR_ENTRY_SIZE) {
        const uint8_t *entry = dir_data + i;
        uint8_t object_type = entry[0x42U];
        uint32_t stream_start_sector = read_u32_le_local(entry + 0x74U);
        uint64_t stream_size;
        char name[80];

        cfb_utf16le_name_to_ascii(entry, name, sizeof(name));
        cfb_classify_stream_name(name, object_type, classification);

        if (object_type != 2U && object_type != 5U) {
            continue;
        }

        if (header->major_version >= 4U) {
            stream_size = read_u64_le_local(entry + 0x78U);
        } else {
            stream_size = read_u32_le_local(entry + 0x78U);
        }

        if (stream_size == 0U || !cfb_sector_regular(stream_start_sector)) {
            continue;
        }
        if (object_type == 5U || stream_size >= header->mini_cutoff) {
            (void)cfb_walk_chain_for_max(
                fat,
                fat_count,
                stream_start_sector,
                max_sector_out);
        }
    }

    free(dir_data);
    return 1;
}

static int cfb_analyze(
    const Reader *reader,
    uint64_t base_abs,
    uint32_t allowed_extensions,
    CfbAnalysis *analysis,
    const char **reject_reason
)
{
    uint8_t header_bytes[CFB_HEADER_SIZE];
    CfbHeader header;
    uint32_t *fat_sector_ids = NULL;
    size_t fat_sector_id_count = 0U;
    uint32_t *fat = NULL;
    size_t fat_count = 0U;
    uint64_t max_sector = 0U;
    CfbClassification classification;
    const char *extension;
    uint64_t confirmed_span;

    if (reader == NULL || analysis == NULL) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_input";
        }
        return 0;
    }
    if (!cfb_read_exact_fd(reader, base_abs, header_bytes, sizeof(header_bytes))) {
        if (reject_reason != NULL) {
            *reject_reason = "source_eof_before_header";
        }
        return 0;
    }
    if (!cfb_parse_header(header_bytes, &header, reject_reason)) {
        return 0;
    }
    if (!cfb_collect_fat_sector_ids(
            reader,
            base_abs,
            &header,
            &fat_sector_ids,
            &fat_sector_id_count,
            &max_sector,
            reject_reason)) {
        return 0;
    }
    if (!cfb_load_fat(
            reader,
            base_abs,
            &header,
            fat_sector_ids,
            fat_sector_id_count,
            &fat,
            &fat_count,
            reject_reason)) {
        free(fat_sector_ids);
        return 0;
    }
    free(fat_sector_ids);

    memset(&classification, 0, sizeof(classification));
    if (!cfb_analyze_directory(
            reader,
            base_abs,
            &header,
            fat,
            fat_count,
            &max_sector,
            &classification,
            reject_reason)) {
        free(fat);
        return 0;
    }
    free(fat);

    extension = cfb_choose_extension(&classification, allowed_extensions);
    if (extension == NULL) {
        if (reject_reason != NULL) {
            *reject_reason = "unclassified_cfb";
        }
        return 0;
    }

    if (max_sector > (UINT64_MAX / (uint64_t)header.sector_size) - 2ULL) {
        if (reject_reason != NULL) {
            *reject_reason = "span_overflow";
        }
        return 0;
    }
    confirmed_span = (max_sector + 2ULL) * (uint64_t)header.sector_size;
    if (confirmed_span < CFB_HEADER_SIZE ||
        confirmed_span > CFB_MAX_REASONABLE_SPAN) {
        if (reject_reason != NULL) {
            *reject_reason = "span_not_reasonable";
        }
        return 0;
    }
    if (reader->source_size > 0U &&
        (base_abs >= reader->source_size ||
         confirmed_span > reader->source_size - base_abs)) {
        if (reject_reason != NULL) {
            *reject_reason = "source_eof_before_end";
        }
        return 0;
    }

    analysis->confirmed_span = confirmed_span;
    analysis->extension = extension;
    return 1;
}

static int cfb_copy_fd_to_output(
    const Reader *reader,
    FILE *output_file,
    uint64_t start_abs,
    uint64_t byte_count
)
{
    uint8_t *buffer = NULL;
    uint64_t copied = 0U;
    int result = 0;

    if (reader == NULL || output_file == NULL || byte_count == 0U) {
        return 0;
    }

    buffer = (uint8_t *)malloc(CFB_COPY_CHUNK_SIZE);
    if (buffer == NULL) {
        return 0;
    }

    while (copied < byte_count) {
        uint64_t remaining = byte_count - copied;
        size_t want = remaining > CFB_COPY_CHUNK_SIZE
            ? CFB_COPY_CHUNK_SIZE
            : (size_t)remaining;

        if (!cfb_read_exact_fd(reader, start_abs + copied, buffer, want)) {
            goto cleanup;
        }
        if (fwrite(buffer, 1U, want, output_file) != want) {
            goto cleanup;
        }
        copied += (uint64_t)want;
    }

    result = 1;

cleanup:
    free(buffer);
    return result;
}

int carver_cfb_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    uint32_t allowed_extensions
)
{
    CfbAnalysis analysis;
    const char *reject_reason = "unknown";
    CarverOutput output = {0};

#define CFB_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_cfb_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    carver_cfb_reset_last_audit();
    if (resume_offset != NULL) {
        *resume_offset = start_offset + 1U;
    }
    if (reader == NULL || resume_offset == NULL) {
        CFB_REJECT("invalid_input", 0U);
    }
    if (allowed_extensions == 0U) {
        CFB_REJECT("disabled_by_filter", 0U);
    }

    memset(&analysis, 0, sizeof(analysis));
    if (!cfb_analyze(
            reader,
            (uint64_t)absolute_offset,
            allowed_extensions,
            &analysis,
            &reject_reason)) {
        CFB_REJECT(reject_reason, analysis.confirmed_span);
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            analysis.extension)) {
        CFB_REJECT("output_open_failed", analysis.confirmed_span);
    }
    if (!cfb_copy_fd_to_output(
            reader,
            output.file,
            (uint64_t)absolute_offset,
            analysis.confirmed_span)) {
        carver_output_abort(&output);
        CFB_REJECT("write_failed", analysis.confirmed_span);
    }
    if (fflush(output.file) != 0) {
        carver_output_abort(&output);
        CFB_REJECT("write_failed", analysis.confirmed_span);
    }
    if (!carver_output_finish(&output)) {
        CFB_REJECT("finish_failed", analysis.confirmed_span);
    }

    compute_resume_offset_local(
        reader,
        (uint64_t)absolute_offset + analysis.confirmed_span,
        start_offset,
        resume_offset);
    carver_audit_set_inline(
        &g_cfb_last_audit,
        "recovered",
        analysis.extension,
        carver_audit_span_from_u64(analysis.confirmed_span));
    return 1;

#undef CFB_REJECT
}
