#include "mftprobe_users_tree.h"

#include "config.h"
#include "fs_backend.h"
#include "log.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if defined(__GNUC__) || defined(__clang__)
#define TREE_MAYBE_UNUSED __attribute__((unused))
#else
#define TREE_MAYBE_UNUSED
#endif

#if defined(__GNUC__) && !defined(__clang__)
#define GCC_ICE_WORKAROUND_O0 __attribute__((optimize("O0")))
#else
#define GCC_ICE_WORKAROUND_O0
#endif

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

static int TREE_MAYBE_UNUSED ensure_parent_dirs_local(const char *path)
{
    char temp[1024];
    char *cursor;

    if (path == NULL || path[0] == '\0' || strlen(path) >= sizeof(temp)) {
        return 0;
    }
    if (!fs_backend_output_path_write_guard_allows(path)) {
        return 0;
    }

    snprintf(temp, sizeof(temp), "%s", path);
    cursor = temp;

    while ((cursor = strchr(cursor + 1, '/')) != NULL) {
        *cursor = '\0';
        if (!fs_backend_output_path_write_guard_allows(temp)) {
            return 0;
        }
        if (mkdir(temp, 0777) != 0 && errno != EEXIST) {
            return 0;
        }
        *cursor = '/';
    }

    return 1;
}

static int ascii_tolower_local(int c)
{
    return tolower((unsigned char)c);
}

static int GCC_ICE_WORKAROUND_O0 segment_equals_ci_local(
    const char *segment,
    size_t segment_len,
    const char *text
)
{
    size_t i;
    size_t text_len;

    if (segment == NULL || text == NULL) {
        return 0;
    }

    text_len = strlen(text);
    if (segment_len != text_len) {
        return 0;
    }

    for (i = 0; i < segment_len; i++) {
        if (ascii_tolower_local((unsigned char)segment[i]) !=
            ascii_tolower_local((unsigned char)text[i])) {
            return 0;
        }
    }

    return 1;
}

int mftprobe_path_has_skipped_users_segment(const char *path)
{
    const char *segment;

    if (path == NULL || path[0] != '\\') {
        return 0;
    }

    segment = path + 1;
    while (*segment != '\0') {
        const char *next = strchr(segment, '\\');
        size_t len = next != NULL ? (size_t)(next - segment) : strlen(segment);

        if (segment_equals_ci_local(segment, len, "AppData") ||
            segment_equals_ci_local(segment, len, "Application Data") ||
            segment_equals_ci_local(segment, len, "Local Settings")) {
            return 1;
        }

        if (next == NULL) {
            break;
        }
        segment = next + 1;
    }

    return 0;
}

typedef struct ExtensionCount {
    char extension[FORMAT_EXTENSION_MAX];
    size_t count;
} ExtensionCount;

static int TREE_MAYBE_UNUSED extract_extension_local(
    const char *name,
    char *out,
    size_t out_size
)
{
    const char *dot;
    size_t i = 0;

    if (out == NULL || out_size == 0) {
        return 0;
    }
    out[0] = '\0';

    if (name == NULL || name[0] == '\0') {
        return 0;
    }

    dot = strrchr(name, '.');
    if (dot == NULL || dot[1] == '\0') {
        return 0;
    }

    dot++;
    while (dot[i] != '\0' && i + 1 < out_size) {
        out[i] = (char)ascii_tolower_local((unsigned char)dot[i]);
        i++;
    }
    out[i] = '\0';
    return i > 0;
}

static int TREE_MAYBE_UNUSED increment_extension_count_local(
    ExtensionCount **counts,
    size_t *count,
    size_t *capacity,
    const char *extension
)
{
    size_t i;
    ExtensionCount *new_counts;

    if (counts == NULL || count == NULL || capacity == NULL ||
        extension == NULL || extension[0] == '\0') {
        return 0;
    }

    for (i = 0; i < *count; i++) {
        if (strcmp((*counts)[i].extension, extension) == 0) {
            (*counts)[i].count++;
            return 1;
        }
    }

    if (*count == *capacity) {
        size_t new_capacity = *capacity == 0 ? 16U : (*capacity * 2U);
        new_counts = (ExtensionCount *)realloc(*counts, new_capacity * sizeof(*new_counts));
        if (new_counts == NULL) {
            return 0;
        }
        *counts = new_counts;
        *capacity = new_capacity;
    }

    snprintf((*counts)[*count].extension, sizeof((*counts)[*count].extension), "%s", extension);
    (*counts)[*count].count = 1;
    (*count)++;
    return 1;
}

static void TREE_MAYBE_UNUSED write_active_formats_local(FILE *tree, const Config *config)
{
    const RecoveryOrder *order;
    size_t i;

    if (tree == NULL || config == NULL) {
        return;
    }

    order = config->recovery_order;
    if (order == NULL || order->count == 0) {
        fprintf(tree, "selected_formats: (none)\n");
        return;
    }

    fprintf(tree, "selected_formats: ");
    for (i = 0; i < order->count; i++) {
        const char *ext = order->formats[i].default_extension;
        fprintf(tree, "%s%s", i == 0 ? "" : ",", ext != NULL ? ext : "?");
    }
    fprintf(tree, "\n");
}

int mftprobe_write_users_selected_tree(
    const Config *config,
    MftTable *table,
    const MftprobeUsersTreeOps *ops
)
{
    (void)config;
    (void)table;
    (void)ops;
    return 1;
#if 0
    char path[PATH_MAX_LEN];
    FILE *tree;
    MftEntry *items = NULL;
    RecordIndex *index = NULL;
    PathList paths = {0};
    size_t count = 0;
    size_t users_roots = 0;
    size_t selected_files = 0;
    ExtensionCount *extension_counts = NULL;
    size_t extension_count = 0;
    size_t extension_capacity = 0;
    size_t i;

    if (config == NULL || table == NULL || ops == NULL ||
        ops->snapshot_entries == NULL ||
        ops->stop_requested == NULL ||
        ops->build_record_index == NULL ||
        ops->is_users_root_entry == NULL ||
        ops->build_path_if_under_users_root == NULL ||
        ops->append_parent_dirs == NULL ||
        ops->append_path == NULL ||
        ops->mft_data_offset_for_entry == NULL ||
        ops->write_ascii_tree == NULL ||
        ops->free_paths == NULL ||
        ops->join_path == NULL ||
        ops->entry_selected_format == NULL) {
        return 0;
    }

    if (!ops->snapshot_entries(table, &items, &count)) {
        return 0;
    }

    if (ops->stop_requested()) {
        free(items);
        return 0;
    }
    index = ops->build_record_index(items, count);
    if (count > 0 && index == NULL) {
        free(items);
        return 0;
    }

    log_info("Writing Users selected-format tree: entries=%zu", count);
    ops->join_path(
        path,
        sizeof(path),
        config->out_dir,
        APP_STATE_DIR_NAME "/users_selected_tree.txt");
    if (!ensure_parent_dirs_local(path)) {
        free(index);
        free(items);
        return 0;
    }
    tree = fopen(path, "w");

    if (tree == NULL) {
        free(index);
        free(items);
        if (tree != NULL) fclose(tree);
        return 0;
    }

    for (i = 0; i < count && !ops->stop_requested(); i++) {
        if (ops->is_users_root_entry(&items[i])) {
            users_roots++;
        }
    }

    for (i = 0; i < count && !ops->stop_requested(); i++) {
        char full_path[PATH_MAX_LEN];

        if (ops->entry_selected_format(config, &items[i]) == NULL) {
            continue;
        }
        if (!ops->build_path_if_under_users_root(items, index, count, &items[i], full_path, sizeof(full_path))) {
            continue;
        }
        ops->append_parent_dirs(&paths, full_path);
        selected_files++;
        {
            char extension[FORMAT_EXTENSION_MAX];
            if (extract_extension_local(items[i].name, extension, sizeof(extension))) {
                if (!increment_extension_count_local(
                        &extension_counts,
                        &extension_count,
                        &extension_capacity,
                        extension)) {
                    fclose(tree);
                    ops->free_paths(&paths);
                    free(index);
                    free(items);
                    free(extension_counts);
                    return 0;
                }
            }
        }
    }

    fprintf(tree, "mftprobe Users selected-format tree\n");
    fprintf(tree, "image: %s\n", config->image_path);
    write_active_formats_local(tree, config);
    fprintf(tree, "live_index_records: %zu\n", count);
    fprintf(tree, "users_roots_parent_5: %zu\n", users_roots);
    fprintf(tree, "selected_files_under_users: %zu\n", selected_files);
    fprintf(tree, "format_count: %zu\n", extension_count);
    if (config->ntfs.valid) {
        size_t v;

        fprintf(tree,
                "ntfs_geometry: preferred_volume_offset=%llu cluster_size=%llu serial=%016llx bytes_per_sector=%u sectors_per_cluster=%u volumes=%zu\n",
                (unsigned long long)config->ntfs.volume_offset,
                (unsigned long long)config->ntfs.cluster_size,
                (unsigned long long)config->ntfs.volume_serial,
                (unsigned int)config->ntfs.bytes_per_sector,
                (unsigned int)config->ntfs.sectors_per_cluster,
                config->ntfs_volume_count);
        for (v = 0; v < config->ntfs_volume_count; v++) {
            fprintf(tree,
                    "ntfs_volume[%zu]: offset=%llu size=%llu cluster_size=%llu serial=%016llx mft_abs=%llu basic_data=%d\n",
                    v,
                    (unsigned long long)config->ntfs_volumes[v].volume_offset,
                    (unsigned long long)config->ntfs_volumes[v].volume_size,
                    (unsigned long long)config->ntfs_volumes[v].cluster_size,
                    (unsigned long long)config->ntfs_volumes[v].volume_serial,
                    (unsigned long long)config->ntfs_volumes[v].mft_abs_offset,
                    config->ntfs_volumes[v].is_basic_data);
        }
        fprintf(tree, "\n");
    } else {
        fprintf(tree,
                "ntfs_geometry: unavailable; data_byte_offset=UNKNOWN for entries that cannot be tied to an NTFS volume\n\n");
    }

    fprintf(tree, "Users roots:\n");
    for (i = 0; i < count; i++) {
        if (ops->is_users_root_entry(&items[i])) {
            fprintf(tree,
                    "- %s record=%d raw_record=%d parent=%llu mft_offset=%llu created=%s\n",
                    items[i].name,
                    items[i].record,
                    items[i].raw_record,
                    (unsigned long long)items[i].parent,
                    (unsigned long long)items[i].offset,
                    items[i].created);
        }
    }
    fprintf(tree, "\nFormat summary:\n");
    if (extension_count == 0) {
        fprintf(tree, "(no matching selected-format files below strict Users root)\n");
    } else {
        for (i = 0; i < extension_count; i++) {
            fprintf(tree, "- .%s: %zu\n", extension_counts[i].extension, extension_counts[i].count);
        }
    }

    fprintf(tree, "\nUsers tree (directories only):\n");

    if (ops->stop_requested()) {
        fprintf(tree, "(interrupted while building Users selected-format tree)\n");
    } else if (users_roots == 0) {
        fprintf(tree, "(no strict Users root with parent 5 found)\n");
    } else if (selected_files == 0) {
        fprintf(tree, "(no selected-format files currently mapped below strict Users root)\n");
    } else {
        ops->write_ascii_tree(tree, &paths);
    }

    fclose(tree);
    ops->free_paths(&paths);
    free(index);
    free(items);
    free(extension_counts);
    return 1;
#endif
}
