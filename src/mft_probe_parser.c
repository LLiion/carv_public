#define _POSIX_C_SOURCE 200809L

#include "mft_probe_parser.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define ATTR_FILE_NAME 0x30U
#define ATTR_INDEX_ROOT 0x90U
#define ATTR_INDEX_ALLOCATION 0xA0U
#define ATTR_DATA 0x80U
#define ATTR_END 0xFFFFFFFFU
#define MFT_PROBE_SECTOR_SIZE 512U
#define MFT_PROBE_SALVAGE_MIN_FIRST_SECTOR_BYTES 128U
#define INDEX_ENTRY_HEADER_SIZE 16U
#define INDEX_ENTRY_MIN_SIZE 0x52U
#define INDEX_ENTRY_FLAG_NODE 0x0001U
#define INDEX_ENTRY_FLAG_END 0x0002U
#define DEFAULT_I30_INDEX_BLOCK_SIZE 4096U

static size_t g_salvage_first_sector_confirmed_bytes = 0U;

static uint16_t rd16(const unsigned char *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const unsigned char *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const unsigned char *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static int apply_update_sequence_fixup(
    const unsigned char *record,
    unsigned char *fixed_record,
    size_t record_size
)
{
    uint16_t usa_offset;
    uint16_t usa_count;
    uint16_t usa_value;
    size_t i;

    if (record == NULL || fixed_record == NULL || record_size < MFT_PROBE_SECTOR_SIZE) {
        return 0;
    }

    memcpy(fixed_record, record, record_size);
    usa_offset = rd16(record + 4);
    usa_count = rd16(record + 6);

    if (usa_offset < 0x28U ||
        usa_count < 2U ||
        usa_offset + ((size_t)usa_count * 2U) > record_size ||
        (((size_t)usa_count - 1U) * MFT_PROBE_SECTOR_SIZE) > record_size) {
        return 0;
    }

    usa_value = rd16(record + usa_offset);
    if (usa_value == 0U) {
        return 0;
    }

    for (i = 1U; i < usa_count; i++) {
        size_t sector_end_offset = (i * MFT_PROBE_SECTOR_SIZE) - 2U;
        uint16_t expected = rd16(record + usa_offset + (i * 2U));

        if (sector_end_offset + 2U > record_size ||
            rd16(record + sector_end_offset) != usa_value) {
            return 0;
        }

        fixed_record[sector_end_offset] = (unsigned char)(expected & 0xFFU);
        fixed_record[sector_end_offset + 1U] = (unsigned char)(expected >> 8);
    }

    return 1;
}

static int apply_update_sequence_fixup_salvage(
    const unsigned char *record,
    unsigned char *fixed_record,
    size_t record_size
)
{
    uint16_t usa_offset;
    uint16_t usa_count;
    uint16_t usa_value;
    size_t i;

    if (record == NULL || fixed_record == NULL || record_size < MFT_PROBE_SECTOR_SIZE) {
        return 0;
    }

    memcpy(fixed_record, record, record_size);
    usa_offset = rd16(record + 4);
    usa_count = rd16(record + 6);

    if (usa_offset < 0x28U ||
        usa_count < 2U ||
        usa_offset + ((size_t)usa_count * 2U) > record_size ||
        (((size_t)usa_count - 1U) * MFT_PROBE_SECTOR_SIZE) > record_size) {
        return 0;
    }

    usa_value = rd16(record + usa_offset);
    if (usa_value == 0U) {
        return 0;
    }

    for (i = 1U; i < usa_count; i++) {
        size_t sector_end_offset = (i * MFT_PROBE_SECTOR_SIZE) - 2U;
        size_t sector_start_offset = (i - 1U) * MFT_PROBE_SECTOR_SIZE;
        size_t sector_length = MFT_PROBE_SECTOR_SIZE;
        uint16_t expected;

        if (sector_start_offset >= record_size) {
            break;
        }
        if (sector_start_offset + sector_length > record_size) {
            sector_length = record_size - sector_start_offset;
        }
        if (sector_end_offset + 2U > record_size) {
            return 0;
        }

        expected = rd16(record + usa_offset + (i * 2U));
        if (rd16(record + sector_end_offset) != usa_value) {
            if (i == 1U) {
                if (g_salvage_first_sector_confirmed_bytes <
                    MFT_PROBE_SALVAGE_MIN_FIRST_SECTOR_BYTES) {
                    return 0;
                }
                if (g_salvage_first_sector_confirmed_bytes < sector_length) {
                    memset(
                        fixed_record + sector_start_offset + g_salvage_first_sector_confirmed_bytes,
                        0,
                        sector_length - g_salvage_first_sector_confirmed_bytes
                    );
                }
                continue;
            }
            memset(fixed_record + sector_start_offset, 0, sector_length);
            continue;
        }

        fixed_record[sector_end_offset] = (unsigned char)(expected & 0xFFU);
        fixed_record[sector_end_offset + 1U] = (unsigned char)(expected >> 8);
    }

    return 1;
}

static void filetime_to_text(uint64_t filetime, char *out, size_t out_size)
{
    int64_t unix_seconds;
    time_t t;
    struct tm tm_value;

    if (out_size == 0) {
        return;
    }
    if (filetime == 0) {
        snprintf(out, out_size, "UNKNOWN");
        return;
    }

    unix_seconds = (int64_t)(filetime / 10000000ULL) - 11644473600LL;
    if (unix_seconds <= 0) {
        snprintf(out, out_size, "INVALID");
        return;
    }

    t = (time_t)unix_seconds;
    if (gmtime_r(&t, &tm_value) == NULL ||
        strftime(out, out_size, "%Y-%m-%d %H:%M:%S", &tm_value) == 0) {
        snprintf(out, out_size, "INVALID");
    }
}

static size_t append_utf8_codepoint_local(char *out, size_t out_size, size_t pos, uint32_t codepoint)
{
    if (out == NULL || out_size == 0 || pos >= out_size - 1U) {
        return pos;
    }

    if (codepoint <= 0x7FU) {
        out[pos++] = (char)codepoint;
    } else if (codepoint <= 0x7FFU && pos + 2U < out_size) {
        out[pos++] = (char)(0xC0U | (codepoint >> 6));
        out[pos++] = (char)(0x80U | (codepoint & 0x3FU));
    } else if (codepoint <= 0xFFFFU && pos + 3U < out_size) {
        out[pos++] = (char)(0xE0U | (codepoint >> 12));
        out[pos++] = (char)(0x80U | ((codepoint >> 6) & 0x3FU));
        out[pos++] = (char)(0x80U | (codepoint & 0x3FU));
    } else {
        out[pos++] = '_';
    }

    return pos;
}

static void utf16le_to_utf8(
    const unsigned char *p,
    size_t chars,
    char *out,
    size_t out_size
)
{
    size_t i;
    size_t j = 0;

    if (out_size == 0) {
        return;
    }

    for (i = 0; i < chars && j + 1 < out_size; i++) {
        uint16_t ch = rd16(p + i * 2U);

        if (ch == 0) {
            break;
        }
        if (ch < 32U) {
            out[j++] = '_';
        } else if (ch >= 0xD800U && ch <= 0xDBFFU) {
            if (i + 1U < chars) {
                uint16_t low = rd16(p + (i + 1U) * 2U);

                if (low >= 0xDC00U && low <= 0xDFFFU) {
                    uint32_t codepoint =
                        0x10000U +
                        (((uint32_t)(ch - 0xD800U) << 10) |
                         (uint32_t)(low - 0xDC00U));
                    j = append_utf8_codepoint_local(out, out_size, j, codepoint);
                    i++;
                } else {
                    out[j++] = '_';
                }
            } else {
                out[j++] = '_';
            }
        } else if (ch >= 0xDC00U && ch <= 0xDFFFU) {
            out[j++] = '_';
        } else if (ch == 0) {
            break;
        } else {
            j = append_utf8_codepoint_local(out, out_size, j, ch);
        }
    }
    out[j] = '\0';
}

static void parse_file_name_attr(
    const unsigned char *attr,
    uint32_t attr_len,
    MftProbeEntry *entry
)
{
    uint32_t content_len;
    uint16_t content_off;
    const unsigned char *content;
    uint8_t name_len;
    uint8_t namespace_id;
    uint64_t parent_ref_raw;
    uint64_t created_filetime;
    uint64_t candidate_allocated_size;
    uint64_t candidate_data_size;
    char candidate[MFT_PROBE_NAME_MAX];
    uint8_t current_rank;
    uint8_t candidate_rank;

    if (attr_len < 24U) {
        return;
    }

    content_len = rd32(attr + 16);
    content_off = rd16(attr + 20);
    if ((uint32_t)content_off + content_len > attr_len || content_len < 66U) {
        return;
    }

    content = attr + content_off;
    candidate_allocated_size = rd64(content + 40U);
    candidate_data_size = rd64(content + 48U);
    name_len = content[64];
    namespace_id = content[65];
    if (name_len == 0 || 66U + (uint32_t)name_len * 2U > content_len) {
        return;
    }

    utf16le_to_utf8(content + 66, name_len, candidate, sizeof(candidate));
    if (candidate[0] == '\0') {
        return;
    }

    if (candidate_allocated_size > entry->allocated_size) {
        entry->allocated_size = candidate_allocated_size;
    }
    if (candidate_data_size > entry->data_size) {
        entry->data_size = candidate_data_size;
    }

    current_rank = entry->name[0] == '\0' ? 0U :
        (entry->name_namespace == 3U ? 4U :
         entry->name_namespace == 1U ? 3U :
         entry->name_namespace == 0U ? 2U :
         entry->name_namespace == 2U ? 1U : 0U);
    candidate_rank = namespace_id == 3U ? 4U :
        namespace_id == 1U ? 3U :
        namespace_id == 0U ? 2U :
        namespace_id == 2U ? 1U : 0U;

    if (entry->name[0] == '\0' ||
        candidate_rank > current_rank ||
        (candidate_rank == current_rank &&
         strlen(candidate) > strlen(entry->name))) {
        parent_ref_raw = rd64(content);
        created_filetime = rd64(content + 8);
        entry->parent = parent_ref_raw & 0x0000FFFFFFFFFFFFULL;
        entry->parent_seq = (uint16_t)(parent_ref_raw >> 48);
        entry->created_filetime = created_filetime;
        filetime_to_text(created_filetime, entry->created, sizeof(entry->created));
        snprintf(entry->name, sizeof(entry->name), "%s", candidate);
        entry->name_namespace = namespace_id;
    }
}

static int parse_file_name_key(
    const unsigned char *content,
    uint32_t content_len,
    uint64_t *out_parent_record,
    uint16_t *out_parent_seq,
    char *out_name,
    size_t out_name_size,
    uint8_t *out_namespace,
    uint32_t *out_file_attributes,
    uint64_t *out_created_filetime,
    uint64_t *out_data_size,
    uint64_t *out_allocated_size
)
{
    uint8_t name_len;
    uint8_t namespace_id;
    uint64_t parent_ref_raw;

    if (content == NULL || content_len < 66U ||
        out_name == NULL || out_name_size == 0U) {
        return 0;
    }

    name_len = content[64];
    namespace_id = content[65];
    if (name_len == 0U || 66U + (uint32_t)name_len * 2U > content_len) {
        return 0;
    }

    utf16le_to_utf8(content + 66U, name_len, out_name, out_name_size);
    if (out_name[0] == '\0') {
        return 0;
    }

    parent_ref_raw = rd64(content);
    if (out_parent_record != NULL) {
        *out_parent_record = parent_ref_raw & 0x0000FFFFFFFFFFFFULL;
    }
    if (out_parent_seq != NULL) {
        *out_parent_seq = (uint16_t)(parent_ref_raw >> 48);
    }
    if (out_namespace != NULL) {
        *out_namespace = namespace_id;
    }
    if (out_file_attributes != NULL) {
        *out_file_attributes = rd32(content + 56U);
    }
    if (out_created_filetime != NULL) {
        *out_created_filetime = rd64(content + 8U);
    }
    if (out_allocated_size != NULL) {
        *out_allocated_size = rd64(content + 40U);
    }
    if (out_data_size != NULL) {
        *out_data_size = rd64(content + 48U);
    }

    return 1;
}

static void note_i30_child(
    MftProbeEntry *entry,
    uint64_t child_record_ref,
    uint16_t child_seq,
    uint32_t file_attributes,
    uint64_t created_filetime,
    uint64_t data_size,
    uint64_t allocated_size,
    const char *name,
    uint8_t name_namespace
)
{
    if (entry == NULL ||
        child_record_ref == 0U ||
        name == NULL ||
        name[0] == '\0') {
        return;
    }

    if (entry->i30_child_count < MFT_PROBE_I30_CHILDREN_MAX) {
        entry->i30_children[entry->i30_child_count].child_record_ref =
            child_record_ref;
        entry->i30_children[entry->i30_child_count].child_seq = child_seq;
        entry->i30_children[entry->i30_child_count].file_attributes =
            file_attributes;
        entry->i30_children[entry->i30_child_count].created_filetime =
            created_filetime;
        entry->i30_children[entry->i30_child_count].data_size = data_size;
        entry->i30_children[entry->i30_child_count].allocated_size =
            allocated_size;
        entry->i30_children[entry->i30_child_count].name_namespace =
            name_namespace;
        snprintf(
            entry->i30_children[entry->i30_child_count].name,
            sizeof(entry->i30_children[entry->i30_child_count].name),
            "%s",
            name
        );
        entry->i30_child_count++;
    } else {
        entry->i30_child_truncated = 1;
    }
}

static int parse_index_entry_candidate(
    const unsigned char *entry_ptr,
    const unsigned char *entries_end,
    uint64_t *out_child_record_ref,
    uint16_t *out_child_seq,
    uint16_t *out_entry_len,
    uint16_t *out_flags,
    uint32_t *out_file_attributes,
    uint64_t *out_created_filetime,
    uint64_t *out_data_size,
    uint64_t *out_allocated_size,
    char *out_name,
    size_t out_name_size,
    uint8_t *out_name_namespace
)
{
    uint64_t child_ref_raw;
    uint16_t child_seq;
    uint16_t entry_len;
    uint16_t key_len;
    uint16_t flags;

    if (entry_ptr == NULL ||
        entries_end == NULL ||
        entry_ptr + INDEX_ENTRY_MIN_SIZE > entries_end ||
        out_name == NULL ||
        out_name_size == 0U) {
        return 0;
    }

    child_ref_raw = rd64(entry_ptr);
    entry_len = rd16(entry_ptr + 8U);
    key_len = rd16(entry_ptr + 10U);
    flags = rd16(entry_ptr + 12U);

    if (entry_len < INDEX_ENTRY_MIN_SIZE ||
        entry_ptr + entry_len > entries_end ||
        key_len < 66U ||
        key_len > entry_len - INDEX_ENTRY_HEADER_SIZE ||
        !parse_file_name_key(
            entry_ptr + INDEX_ENTRY_HEADER_SIZE,
            key_len,
            NULL,
            NULL,
            out_name,
            out_name_size,
            out_name_namespace,
            out_file_attributes,
            out_created_filetime,
            out_data_size,
            out_allocated_size)) {
        return 0;
    }

    child_seq = (uint16_t)(child_ref_raw >> 48);
    if (out_child_record_ref != NULL) {
        *out_child_record_ref = child_ref_raw & 0x0000FFFFFFFFFFFFULL;
    }
    if (out_child_seq != NULL) {
        *out_child_seq = child_seq;
    }
    if (out_entry_len != NULL) {
        *out_entry_len = entry_len;
    }
    if (out_flags != NULL) {
        *out_flags = flags;
    }

    return 1;
}

static void parse_index_entry_slack_region(
    const unsigned char *slack_start,
    const unsigned char *slack_end,
    MftProbeEntry *entry
)
{
    const unsigned char *cursor = slack_start;

    if (slack_start == NULL ||
        slack_end == NULL ||
        entry == NULL ||
        slack_start >= slack_end) {
        return;
    }

    while (cursor + INDEX_ENTRY_MIN_SIZE <= slack_end) {
        uint64_t child_record_ref = 0U;
        uint16_t child_seq = 0U;
        uint16_t entry_len = 0U;
        uint16_t flags = 0U;
        uint32_t file_attributes = 0U;
        uint64_t created_filetime = 0U;
        uint64_t data_size = 0U;
        uint64_t allocated_size = 0U;
        char candidate_name[MFT_PROBE_NAME_MAX];
        uint8_t candidate_namespace = 0U;

        if (parse_index_entry_candidate(
                cursor,
                slack_end,
                &child_record_ref,
                &child_seq,
                &entry_len,
                &flags,
                &file_attributes,
                &created_filetime,
                &data_size,
                &allocated_size,
                candidate_name,
                sizeof(candidate_name),
                &candidate_namespace)) {
            note_i30_child(
                entry,
                child_record_ref,
                child_seq,
                file_attributes,
                created_filetime,
                data_size,
                allocated_size,
                candidate_name,
                candidate_namespace
            );
            cursor += (entry_len > 0U) ? entry_len : 1U;
        } else {
            cursor++;
        }
        (void)flags;
    }
}

static void parse_index_root_attr(
    const unsigned char *attr,
    uint32_t attr_len,
    MftProbeEntry *entry
)
{
    uint32_t content_len;
    uint16_t content_off;
    const unsigned char *content;
    const unsigned char *index_header;
    const unsigned char *entry_ptr;
    uint32_t indexed_attr_type;
    uint32_t allocated_size;
    uint32_t index_record_size_bytes;
    uint32_t entries_offset;
    uint32_t entries_size;
    const unsigned char *entries_end;
    const unsigned char *allocation_end;

    if (attr == NULL || entry == NULL || attr_len < 32U) {
        return;
    }

    if (!(entry->flags & 0x0002U) || attr[8] != 0U) {
        return;
    }

    content_len = rd32(attr + 16U);
    content_off = rd16(attr + 20U);
    if ((uint32_t)content_off + content_len > attr_len || content_len < 32U) {
        return;
    }

    content = attr + content_off;
    indexed_attr_type = rd32(content);
    if (indexed_attr_type != ATTR_FILE_NAME) {
        return;
    }
    index_record_size_bytes = rd32(content + 8U);
    if (index_record_size_bytes >= 512U &&
        index_record_size_bytes <= 65536U &&
        (entry->i30_index_block_size == 0U ||
         entry->i30_index_block_size == DEFAULT_I30_INDEX_BLOCK_SIZE)) {
        entry->i30_index_block_size = index_record_size_bytes;
    }

    index_header = content + 16U;
    entries_offset = rd32(index_header);
    entries_size = rd32(index_header + 4U);
    allocated_size = rd32(index_header + 8U);
    if (entries_offset < 16U ||
        entries_offset > content_len - 16U ||
        entries_size == 0U ||
        allocated_size < entries_size ||
        allocated_size > content_len - 16U ||
        entries_offset + entries_size > content_len - 16U ||
        entries_offset + allocated_size > content_len - 16U) {
        return;
    }

    entry_ptr = index_header + entries_offset;
    entries_end = index_header + entries_size;
    allocation_end = index_header + allocated_size;
    while (entry_ptr + INDEX_ENTRY_HEADER_SIZE <= entries_end) {
        uint64_t child_record_ref = 0U;
        uint16_t child_seq = 0U;
        uint16_t entry_len = 0U;
        uint16_t flags;
        uint32_t file_attributes = 0U;
        uint64_t created_filetime = 0U;
        uint64_t data_size = 0U;
        uint64_t child_allocated_size = 0U;
        char candidate_name[MFT_PROBE_NAME_MAX];
        uint8_t candidate_namespace = 0U;

        if (!parse_index_entry_candidate(
                entry_ptr,
                entries_end,
                &child_record_ref,
                &child_seq,
                &entry_len,
                &flags,
                &file_attributes,
                &created_filetime,
                &data_size,
                &child_allocated_size,
                candidate_name,
                sizeof(candidate_name),
                &candidate_namespace)) {
            break;
        }

        note_i30_child(
            entry,
            child_record_ref,
            child_seq,
            file_attributes,
            created_filetime,
            data_size,
            child_allocated_size,
            candidate_name,
            candidate_namespace
        );

        if (flags & INDEX_ENTRY_FLAG_END) {
            break;
        }

        if (flags & INDEX_ENTRY_FLAG_NODE) {
            /* Resident INDEX_ROOT gives filenames already; child-node VCN can wait. */
        }

        entry_ptr += entry_len;
    }

    if (entries_end + INDEX_ENTRY_MIN_SIZE <= allocation_end) {
        parse_index_entry_slack_region(entries_end, allocation_end, entry);
    }
}

size_t mft_probe_visit_i30_index_block_children(
    const unsigned char *block,
    size_t block_size,
    MftProbeI30ChildVisitor visitor,
    void *user_data,
    int *out_truncated
)
{
    unsigned char *fixed = NULL;
    const unsigned char *index_header;
    const unsigned char *entry_ptr;
    const unsigned char *entries_end;
    uint32_t entries_offset;
    uint32_t entries_size;
    uint32_t allocated_size;
    uint32_t index_payload_limit;
    size_t visited = 0U;

    if (out_truncated != NULL) {
        *out_truncated = 0;
    }
    if (block == NULL ||
        visitor == NULL ||
        block_size < MFT_PROBE_SECTOR_SIZE ||
        block_size > 65536U ||
        memcmp(block, "INDX", 4U) != 0) {
        return 0U;
    }

    fixed = (unsigned char *)malloc(block_size);
    if (fixed == NULL) {
        if (out_truncated != NULL) {
            *out_truncated = 1;
        }
        return 0U;
    }
    if (!apply_update_sequence_fixup(block, fixed, block_size)) {
        free(fixed);
        return 0U;
    }

    index_header = fixed + 24U;
    entries_offset = rd32(index_header);
    entries_size = rd32(index_header + 4U);
    allocated_size = rd32(index_header + 8U);
    index_payload_limit = (uint32_t)(block_size - 24U);
    if (entries_offset < 16U ||
        entries_offset > index_payload_limit ||
        entries_size == 0U ||
        entries_size < entries_offset ||
        entries_size > index_payload_limit ||
        allocated_size < entries_size ||
        allocated_size > index_payload_limit) {
        free(fixed);
        return 0U;
    }

    entry_ptr = index_header + entries_offset;
    entries_end = index_header + entries_size;
    while (entry_ptr + INDEX_ENTRY_HEADER_SIZE <= entries_end) {
        MftProbeI30Child child;
        uint64_t child_ref_raw;
        uint16_t entry_len;
        uint16_t key_len;
        uint16_t flags;

        child_ref_raw = rd64(entry_ptr);
        entry_len = rd16(entry_ptr + 8U);
        key_len = rd16(entry_ptr + 10U);
        flags = rd16(entry_ptr + 12U);
        if (entry_len < INDEX_ENTRY_HEADER_SIZE ||
            entry_ptr + entry_len > entries_end) {
            break;
        }

        if (key_len >= 66U && key_len <= entry_len - INDEX_ENTRY_HEADER_SIZE) {
            memset(&child, 0, sizeof(child));
            child.child_record_ref = child_ref_raw & 0x0000FFFFFFFFFFFFULL;
            child.child_seq = (uint16_t)(child_ref_raw >> 48);
            if (parse_file_name_key(
                    entry_ptr + INDEX_ENTRY_HEADER_SIZE,
                    key_len,
                    NULL,
                    NULL,
                    child.name,
                    sizeof(child.name),
                    &child.name_namespace,
                    &child.file_attributes,
                    &child.created_filetime,
                    &child.data_size,
                    &child.allocated_size)) {
                if (!visitor(&child, user_data)) {
                    if (out_truncated != NULL) {
                        *out_truncated = 1;
                    }
                    break;
                }
                visited++;
            }
        }

        if (flags & INDEX_ENTRY_FLAG_END) {
            break;
        }
        entry_ptr += entry_len;
    }

    free(fixed);
    return visited;
}

static void parse_index_allocation_attr(
    const unsigned char *attr,
    uint32_t attr_len,
    MftProbeEntry *entry
)
{
    uint64_t candidate_first_lcn = 0;
    uint64_t candidate_run_clusters = 0;
    uint64_t candidate_run_total_clusters = 0;
    uint64_t candidate_max_lcn_end = 0;
    uint32_t candidate_run_count = 0;
    uint32_t candidate_stored_run_count = 0;
    int candidate_run_truncated = 0;
    MftRunlistInfo runlist_info;

    if (attr == NULL || entry == NULL || attr_len < 64U) {
        return;
    }
    if (!(entry->flags & 0x0002U) || attr[8] == 0U) {
        return;
    }

    if (entry->i30_index_block_size < 512U ||
        entry->i30_index_block_size > 65536U) {
        entry->i30_index_block_size = DEFAULT_I30_INDEX_BLOCK_SIZE;
    }
    {
        uint16_t run_off = rd16(attr + 32U);

        if (run_off >= attr_len) {
            return;
        }
        mft_runlist_info_clear(&runlist_info);
        if (!mft_runlist_parse(attr + run_off, attr_len - run_off, &runlist_info)) {
            return;
        }
        candidate_first_lcn = runlist_info.first_lcn;
        candidate_run_clusters = runlist_info.run_clusters;
        candidate_run_count = runlist_info.run_count;
        candidate_run_total_clusters = runlist_info.run_total_clusters;
        candidate_max_lcn_end = runlist_info.max_lcn_end;
        candidate_stored_run_count = runlist_info.stored_run_count;
        candidate_run_truncated = runlist_info.run_truncated;
    }

    entry->has_i30_allocation = 1;
    if (entry->i30_first_lcn == 0U && candidate_first_lcn > 0U) {
        entry->i30_first_lcn = candidate_first_lcn;
        entry->i30_run_clusters = candidate_run_clusters;
    }
    entry->i30_run_count += candidate_run_count;
    entry->i30_run_total_clusters += candidate_run_total_clusters;
    if (candidate_max_lcn_end > entry->i30_max_lcn_end) {
        entry->i30_max_lcn_end = candidate_max_lcn_end;
    }
    if (candidate_run_truncated) {
        entry->i30_run_truncated = 1;
    }
    if (candidate_stored_run_count > 0U) {
        size_t i;

        for (i = 0U; i < candidate_stored_run_count; i++) {
            if (runlist_info.runs[i].clusters == 0U) {
                continue;
            }
            if (entry->i30_stored_run_count < MFT_ENTRY_MAX_RUNS) {
                entry->i30_runs[entry->i30_stored_run_count++] = runlist_info.runs[i];
            } else {
                entry->i30_run_truncated = 1;
            }
        }
    }
}

static void parse_data_attr(
    const unsigned char *attr,
    uint32_t attr_len,
    uint32_t attr_record_offset,
    MftProbeEntry *entry,
    int catalog_only
)
{
    uint8_t attr_name_len;
    uint8_t non_resident;
    uint64_t candidate_data_size = 0;
    uint64_t candidate_allocated_size = 0;
    uint64_t candidate_low_vcn = 0;
    uint64_t candidate_first_lcn = 0;
    uint64_t candidate_run_clusters = 0;
    uint64_t candidate_run_total_clusters = 0;
    uint64_t candidate_max_lcn_end = 0;
    uint32_t candidate_run_count = 0;
    uint32_t candidate_stored_run_count = 0;
    int candidate_run_truncated = 0;
    int should_replace = 0;
    MftRunlistInfo runlist_info;

    if (attr_len < 24U) {
        return;
    }

    attr_name_len = attr[9];
    if (attr_name_len != 0U) {
        return;
    }

    non_resident = attr[8];
    if (non_resident == 0) {
        uint32_t content_len = rd32(attr + 16);
        uint16_t content_off = rd16(attr + 20);
        uint32_t resident_record_offset = attr_record_offset + (uint32_t)content_off;

        candidate_data_size = content_len;
        should_replace =
            !entry->has_data ||
            (entry->data_size == 0 && candidate_data_size > 0);
        if (!should_replace) {
            return;
        }
        entry->has_data = 1;
        entry->resident = 1;
        entry->data_size = candidate_data_size;
        entry->allocated_size = candidate_data_size;
        entry->data_offset =
            (content_off < attr_len && resident_record_offset < MFT_PROBE_RECORD_SIZE)
                ? (int64_t)resident_record_offset
                : -1;
        entry->data_low_vcn = 0;
        entry->first_lcn = 0;
        entry->run_clusters = 0;
        entry->run_count = 0;
        entry->run_total_clusters = 0;
        entry->max_lcn_end = 0;
        entry->stored_run_count = 0;
        entry->run_truncated = 0;
        memset(entry->runs, 0, sizeof(entry->runs));
        return;
    }

    if (attr_len >= 64U) {
        uint16_t run_off = rd16(attr + 32);

        candidate_low_vcn = rd64(attr + 16);
        candidate_allocated_size = rd64(attr + 40);
        candidate_data_size = rd64(attr + 56);
        if (run_off < attr_len) {
            mft_runlist_info_clear(&runlist_info);
            if ((catalog_only
                    ? mft_runlist_parse_first(attr + run_off, attr_len - run_off, &runlist_info)
                    : mft_runlist_parse(attr + run_off, attr_len - run_off, &runlist_info))) {
                candidate_first_lcn = runlist_info.first_lcn;
                candidate_run_clusters = runlist_info.run_clusters;
                candidate_run_count = runlist_info.run_count;
                candidate_run_total_clusters = runlist_info.run_total_clusters;
                candidate_max_lcn_end = runlist_info.max_lcn_end;
                candidate_stored_run_count = runlist_info.stored_run_count;
                candidate_run_truncated = runlist_info.run_truncated;
            }
        }
    }

    if (!entry->has_data || entry->resident) {
        entry->has_data = 1;
        entry->resident = 0;
        entry->data_offset = -1;
        entry->data_size = 0;
        entry->allocated_size = 0;
        entry->data_low_vcn = candidate_low_vcn;
        entry->first_lcn = 0;
        entry->run_clusters = 0;
        entry->run_count = 0;
        entry->run_total_clusters = 0;
        entry->max_lcn_end = 0;
        entry->stored_run_count = 0;
        entry->run_truncated = 0;
        memset(entry->runs, 0, sizeof(entry->runs));
    } else if (candidate_low_vcn < entry->data_low_vcn) {
        entry->data_low_vcn = candidate_low_vcn;
    }

    if (candidate_data_size > entry->data_size) {
        entry->data_size = candidate_data_size;
    }
    if (candidate_allocated_size > entry->allocated_size) {
        entry->allocated_size = candidate_allocated_size;
    }
    if (entry->first_lcn == 0 && candidate_first_lcn > 0) {
        entry->first_lcn = candidate_first_lcn;
        entry->run_clusters = candidate_run_clusters;
    }
    entry->run_count += candidate_run_count;
    entry->run_total_clusters += candidate_run_total_clusters;
    if (candidate_max_lcn_end > entry->max_lcn_end) {
        entry->max_lcn_end = candidate_max_lcn_end;
    }
    if (candidate_run_truncated) {
        entry->run_truncated = 1;
    }

    if (candidate_stored_run_count > 0) {
        size_t i;

        for (i = 0; i < candidate_stored_run_count; i++) {
            if (runlist_info.runs[i].clusters == 0) {
                continue;
            }
            if (entry->stored_run_count < MFT_ENTRY_MAX_RUNS) {
                entry->runs[entry->stored_run_count++] = runlist_info.runs[i];
            } else {
                entry->run_truncated = 1;
            }
        }
    }
}

static int parse_record_internal(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry,
    int require_name,
    int allow_salvage_fixup,
    int catalog_only
)
{
    unsigned char fixed_record[MFT_PROBE_RECORD_SIZE];
    const unsigned char *parsed_record = fixed_record;
    uint16_t first_attr;
    uint32_t used_size;
    uint32_t pos;

    if (record == NULL || entry == NULL || memcmp(record, "FILE", 4) != 0) {
        return 0;
    }
    if (allow_salvage_fixup) {
        if (!apply_update_sequence_fixup_salvage(
                record,
                fixed_record,
                sizeof(fixed_record))) {
            return 0;
        }
    } else if (!apply_update_sequence_fixup(record, fixed_record, sizeof(fixed_record))) {
        return 0;
    }

    memset(entry, 0, sizeof(*entry));
    entry->offset = offset;
    entry->record_seq = rd16(parsed_record + 16);
    entry->record = (int)rd32(parsed_record + 44);
    entry->raw_record = entry->record;
    entry->base_record_ref = rd64(parsed_record + 32) & 0x0000FFFFFFFFFFFFULL;
    entry->base_record_seq = (uint16_t)(rd64(parsed_record + 32) >> 48);
    entry->parent = UINT64_MAX;
    entry->data_offset = -1;
    snprintf(entry->created, sizeof(entry->created), "UNKNOWN");

    first_attr = rd16(parsed_record + 20);
    entry->flags = rd16(parsed_record + 22);
    used_size = rd32(parsed_record + 24);
    entry->record_used_size = used_size;
    entry->record_allocated_size = rd32(parsed_record + 28);

    if (first_attr < 0x30U || first_attr >= MFT_PROBE_RECORD_SIZE) {
        return 0;
    }
    if (used_size == 0 || used_size > MFT_PROBE_RECORD_SIZE) {
        return 0;
    }

    pos = first_attr;
    while (pos + 8U < MFT_PROBE_RECORD_SIZE) {
        uint32_t type = rd32(parsed_record + pos);
        uint32_t len = rd32(parsed_record + pos + 4);

        if (type == ATTR_END) {
            break;
        }
        if (len == 0 || pos + len > MFT_PROBE_RECORD_SIZE) {
            break;
        }

        if (type == ATTR_FILE_NAME) {
            parse_file_name_attr(parsed_record + pos, len, entry);
        } else if (type == ATTR_INDEX_ROOT) {
            parse_index_root_attr(parsed_record + pos, len, entry);
        } else if (type == ATTR_INDEX_ALLOCATION) {
            parse_index_allocation_attr(parsed_record + pos, len, entry);
        } else if (type == ATTR_DATA) {
            parse_data_attr(parsed_record + pos, len, pos, entry, catalog_only);
            if (catalog_only &&
                entry->name[0] != '\0' &&
                entry->has_data) {
                break;
            }
        }

        pos += len;
    }

    return require_name ? entry->name[0] != '\0' : 1;
}

int mft_probe_parse_record_any(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
)
{
    return parse_record_internal(record, offset, entry, 0, 0, 0);
}

int mft_probe_parse_record(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
)
{
    return parse_record_internal(record, offset, entry, 1, 0, 0);
}

int mft_probe_parse_record_catalog(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
)
{
    return parse_record_internal(record, offset, entry, 1, 0, 1);
}

int mft_probe_parse_record_salvage(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
)
{
    return parse_record_internal(record, offset, entry, 1, 1, 0);
}

int mft_probe_parse_record_salvage_catalog(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
)
{
    return parse_record_internal(record, offset, entry, 1, 1, 1);
}

int mft_probe_parse_record_salvage_any(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
)
{
    return parse_record_internal(record, offset, entry, 0, 1, 0);
}

void mft_probe_set_salvage_first_sector_confirmed_bytes(size_t bytes)
{
    g_salvage_first_sector_confirmed_bytes = bytes;
}
