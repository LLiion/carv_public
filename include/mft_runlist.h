#ifndef MFT_RUNLIST_H
#define MFT_RUNLIST_H

#include <stddef.h>
#include <stdint.h>

#define MFT_ENTRY_MAX_RUNS 64U

typedef struct MftDataRun {
    uint64_t lcn;
    uint64_t clusters;
} MftDataRun;

typedef struct {
    uint64_t first_lcn;
    uint64_t run_clusters;
    uint64_t run_count;
    uint64_t run_total_clusters;
    uint64_t max_lcn_end;
    size_t stored_run_count;
    int run_truncated;
    MftDataRun runs[MFT_ENTRY_MAX_RUNS];
} MftRunlistInfo;

void mft_runlist_info_clear(MftRunlistInfo *info);

int mft_runlist_parse(
    const unsigned char *runlist,
    size_t runlist_len,
    MftRunlistInfo *info
);

int mft_runlist_parse_first(
    const unsigned char *runlist,
    size_t runlist_len,
    MftRunlistInfo *info
);

#endif
