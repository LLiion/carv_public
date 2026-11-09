#ifndef MFT_TYPES_H
#define MFT_TYPES_H

#include "mft_runlist.h"

#include <stddef.h>
#include <stdint.h>

#define MFT_VIEW_MAX_RUNS MFT_ENTRY_MAX_RUNS

typedef struct {
    uint64_t abs_offset;
    uint64_t byte_length;
} MftViewRun;

typedef struct {
    long long abs_offset;
    uint64_t data_size;
    uint64_t allocated_size;
    size_t run_count;
    int run_truncated;
    MftViewRun runs[MFT_VIEW_MAX_RUNS];
    int flags;
    int has_data;
    int is_resident;
    char path[1024];
    char name[256];
} MftViewEntry;

typedef struct {
    int exact_data_match;
    int inside_nonresident_run;
    int inside_resident_record;
    int record_number;
} MftScanHint;

typedef enum {
    MFT_CONTEXTUAL_OUTPUT_USERS_ONLY = 0,
    MFT_CONTEXTUAL_OUTPUT_FULL_TREE = 1
} MftContextualOutputMode;

#endif
