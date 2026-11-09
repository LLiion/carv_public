#ifndef MFTPROBE_USERS_TREE_H
#define MFTPROBE_USERS_TREE_H

#include "mftprobe_engine_types.h"

typedef struct MftprobeUsersTreeOps {
    int (*snapshot_entries)(MftTable *table, MftEntry **out_items, size_t *out_count);
    int (*stop_requested)(void);
    RecordIndex *(*build_record_index)(const MftEntry *items, size_t count);
    int (*is_users_root_entry)(const MftEntry *entry);
    int (*build_path_if_under_users_root)(
        const MftEntry *items,
        const RecordIndex *index,
        size_t count,
        const MftEntry *entry,
        char *out,
        size_t out_size
    );
    void (*append_parent_dirs)(PathList *dirs, const char *file_path);
    int (*append_path)(PathList *list, const char *path);
    uint64_t (*mft_data_offset_for_entry)(const Config *config, const MftEntry *entry);
    void (*write_ascii_tree)(FILE *tree, PathList *paths);
    void (*free_paths)(PathList *list);
    void (*join_path)(char *out, size_t out_size, const char *dir, const char *name);
    const RecoveryFormat *(*entry_selected_format)(const Config *config, const MftEntry *entry);
} MftprobeUsersTreeOps;

int mftprobe_path_has_skipped_users_segment(const char *path);

int mftprobe_write_users_selected_tree(
    const Config *config,
    MftTable *table,
    const MftprobeUsersTreeOps *ops
);

#endif
