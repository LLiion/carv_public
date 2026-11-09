#ifndef MFT_PROBE_PARSER_H
#define MFT_PROBE_PARSER_H

#include "mft_runlist.h"

#include <stddef.h>
#include <stdint.h>

#define MFT_PROBE_RECORD_SIZE 1024U
#define MFT_PROBE_NAME_MAX 256U
#define MFT_PROBE_CREATED_TEXT_MAX 32U
#define MFT_PROBE_I30_CHILDREN_MAX 32U
#define MFT_PROBE_PARSER_HAVE_EXTENDED_HINTS 1

typedef struct {
    uint64_t child_record_ref;
    uint16_t child_seq;
    uint32_t file_attributes;
    uint64_t created_filetime;
    uint64_t data_size;
    uint64_t allocated_size;
    char name[MFT_PROBE_NAME_MAX];
    uint8_t name_namespace;
} MftProbeI30Child;

typedef struct {
    uint64_t offset;
    int record;
    int raw_record;
    uint16_t record_seq;
    uint64_t base_record_ref;
    uint16_t base_record_seq;
    uint64_t parent;
    uint16_t parent_seq;
    uint32_t family;
    uint16_t flags;
    uint32_t record_used_size;
    uint32_t record_allocated_size;
    char name[MFT_PROBE_NAME_MAX];
    uint8_t name_namespace;
    char created[MFT_PROBE_CREATED_TEXT_MAX];
    uint64_t created_filetime;
    int has_data;
    int resident;
    int64_t data_offset;
    uint64_t data_size;
    uint64_t allocated_size;
    uint64_t data_low_vcn;
    uint64_t first_lcn;
    uint64_t run_clusters;
    uint64_t run_count;
    uint64_t run_total_clusters;
    uint64_t max_lcn_end;
    size_t stored_run_count;
    int run_truncated;
    int has_i30_allocation;
    uint32_t i30_index_block_size;
    uint64_t i30_first_lcn;
    uint64_t i30_run_clusters;
    uint64_t i30_run_count;
    uint64_t i30_run_total_clusters;
    uint64_t i30_max_lcn_end;
    size_t i30_stored_run_count;
    int i30_run_truncated;
    size_t i30_child_count;
    int i30_child_truncated;
    MftProbeI30Child i30_children[MFT_PROBE_I30_CHILDREN_MAX];
    MftDataRun i30_runs[MFT_ENTRY_MAX_RUNS];
    MftDataRun runs[MFT_ENTRY_MAX_RUNS];
} MftProbeEntry;

typedef int (*MftProbeI30ChildVisitor)(
    const MftProbeI30Child *child,
    void *user_data
);

int mft_probe_parse_record(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
);

int mft_probe_parse_record_catalog(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
);

int mft_probe_parse_record_any(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
);

int mft_probe_parse_record_salvage(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
);

int mft_probe_parse_record_salvage_catalog(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
);

int mft_probe_parse_record_salvage_any(
    const unsigned char *record,
    uint64_t offset,
    MftProbeEntry *entry
);

void mft_probe_set_salvage_first_sector_confirmed_bytes(size_t bytes);

size_t mft_probe_visit_i30_index_block_children(
    const unsigned char *block,
    size_t block_size,
    MftProbeI30ChildVisitor visitor,
    void *user_data,
    int *out_truncated
);

#endif
