#include "mft_runlist.h"

#include <string.h>

static int64_t sign_extend_le(const unsigned char *bytes, int byte_count)
{
    int64_t value = 0;
    int i;

    for (i = 0; i < byte_count; i++) {
        value |= ((int64_t)bytes[i]) << (i * 8);
    }
    if (byte_count > 0 && (bytes[byte_count - 1] & 0x80U) != 0U) {
        value |= -((int64_t)1 << (byte_count * 8));
    }
    return value;
}

void mft_runlist_info_clear(MftRunlistInfo *info)
{
    if (info == NULL) {
        return;
    }
    memset(info, 0, sizeof(*info));
}

int mft_runlist_parse(
    const unsigned char *runlist,
    size_t runlist_len,
    MftRunlistInfo *info
)
{
    size_t pos = 0;
    int64_t current_lcn = 0;
    int found = 0;

    if (runlist == NULL || info == NULL) {
        return 0;
    }

    mft_runlist_info_clear(info);

    while (pos < runlist_len && runlist[pos] != 0) {
        uint8_t header = runlist[pos++];
        int len_bytes = header & 0x0F;
        int off_bytes = (header >> 4) & 0x0F;
        uint64_t length = 0;
        int64_t delta;
        int sparse_run;
        int i;

        if (len_bytes == 0 || len_bytes > 8 || off_bytes > 8 ||
            pos + (size_t)len_bytes + (size_t)off_bytes > runlist_len) {
            return found;
        }

        for (i = 0; i < len_bytes; i++) {
            length |= ((uint64_t)runlist[pos + (size_t)i]) << (i * 8);
        }
        pos += (size_t)len_bytes;

        sparse_run = off_bytes == 0;
        delta = sign_extend_le(runlist + pos, off_bytes);
        pos += (size_t)off_bytes;
        if (!sparse_run) {
            current_lcn += delta;
        }

        info->run_count++;
        info->run_total_clusters += length;
        if (!sparse_run && current_lcn >= 0 &&
            (uint64_t)current_lcn + length > info->max_lcn_end) {
            info->max_lcn_end = (uint64_t)current_lcn + length;
        }
        if (sparse_run) {
            info->run_truncated = 1;
        }
        if (!sparse_run && current_lcn >= 0 && length > 0) {
            if (info->stored_run_count < MFT_ENTRY_MAX_RUNS) {
                info->runs[info->stored_run_count].lcn = (uint64_t)current_lcn;
                info->runs[info->stored_run_count].clusters = length;
                info->stored_run_count++;
            } else {
                info->run_truncated = 1;
            }
        }

        if (!sparse_run && !found && current_lcn >= 0) {
            info->first_lcn = (uint64_t)current_lcn;
            info->run_clusters = length;
            found = 1;
        }
    }

    return found;
}

int mft_runlist_parse_first(
    const unsigned char *runlist,
    size_t runlist_len,
    MftRunlistInfo *info
)
{
    size_t pos = 0;
    int64_t current_lcn = 0;

    if (runlist == NULL || info == NULL) {
        return 0;
    }

    mft_runlist_info_clear(info);

    while (pos < runlist_len && runlist[pos] != 0) {
        uint8_t header = runlist[pos++];
        int len_bytes = header & 0x0F;
        int off_bytes = (header >> 4) & 0x0F;
        uint64_t length = 0;
        int64_t delta;
        int sparse_run;
        int i;

        if (len_bytes == 0 || len_bytes > 8 || off_bytes > 8 ||
            pos + (size_t)len_bytes + (size_t)off_bytes > runlist_len) {
            return 0;
        }

        for (i = 0; i < len_bytes; i++) {
            length |= ((uint64_t)runlist[pos + (size_t)i]) << (i * 8);
        }
        pos += (size_t)len_bytes;

        sparse_run = off_bytes == 0;
        delta = sign_extend_le(runlist + pos, off_bytes);
        pos += (size_t)off_bytes;
        if (!sparse_run) {
            current_lcn += delta;
        }

        if (!sparse_run && current_lcn >= 0 && length > 0) {
            info->first_lcn = (uint64_t)current_lcn;
            info->run_clusters = length;
            info->run_count = 1U;
            info->run_total_clusters = length;
            info->max_lcn_end = (uint64_t)current_lcn + length;
            info->stored_run_count = 1U;
            info->runs[0].lcn = (uint64_t)current_lcn;
            info->runs[0].clusters = length;
            if (pos < runlist_len && runlist[pos] != 0) {
                info->run_truncated = 1;
            }
            return 1;
        }
    }

    return 0;
}
