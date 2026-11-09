#ifndef MFTPROBE_ENGINE_H
#define MFTPROBE_ENGINE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum {
    MFTPROBE_ENGINE_STATUS_NONE = 0,
    MFTPROBE_ENGINE_STATUS_OK,
    MFTPROBE_ENGINE_STATUS_FAILED,
    MFTPROBE_ENGINE_STATUS_INTERRUPTED
} MftprobeEngineStatus;

typedef struct MftprobePartialNtfsSource {
    const char *coverage_map_path;
    uint64_t source_size;
    uint64_t volume_offset;
    uint64_t volume_size;
    uint64_t cluster_size;
    uint64_t volume_serial;
    uint64_t mft_abs_offset;
    uint64_t mft_mirror_abs_offset;
    uint32_t mft_record_size;
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    int is_basic_data;
} MftprobePartialNtfsSource;

typedef struct MftprobeEngineOptions {
    const char *categories_csv;
    const char *formats_csv;
    const char *dev_format;
    const char *compare_scope_csv;
    const char *record_list_path;
    const char *root_scope_csv;
    int root_scope_defaulted;
    const char *date_filter_value;
    const char *deleted_filter_value;
    int folder_levels;
    uint64_t start_offset;
    int start_offset_explicit;
    int generic_file_targets;
} MftprobeEngineOptions;

int mftprobe_engine_run(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    uint64_t limit,
    int quick_resume,
    int auto_recover_missed,
    int only_recover_missed
);

int mftprobe_engine_run_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    uint64_t limit,
    int quick_resume,
    int auto_recover_missed,
    int only_recover_missed,
    const MftprobeEngineOptions *options
);

int mftprobe_engine_run_filtered_recovery_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    const char *filter_csv,
    uint64_t limit,
    const MftprobeEngineOptions *options
);
int mftprobe_engine_run_metadata_jpeg_test(
    const char *image_path,
    const char *out_dir,
    size_t max_files,
    size_t *out_recovered_count
);
int mftprobe_engine_run_compare_mount_with_options(
    const char *image_path,
    const char *out_dir,
    const char *run_name,
    const char *mount_path,
    const char *filter_csv,
    uint64_t limit,
    const MftprobeEngineOptions *options
);
int mftprobe_engine_list_root_folders(const char *image_path, FILE *out_stream);
int mftprobe_engine_list_child_folders(
    const char *image_path,
    const char *parent_path,
    FILE *out_stream
);
int mftprobe_engine_list_root_folders_partial(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    FILE *out_stream
);
int mftprobe_engine_list_child_folders_partial(
    const char *image_path,
    const char *parent_path,
    const MftprobePartialNtfsSource *source,
    FILE *out_stream
);
int mftprobe_engine_write_selected_tree_ddrescue_domain(
    const char *image_path,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
);
int mftprobe_engine_write_selected_tree_ddrescue_domain_partial(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    const char *root_scope_csv,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes
);
int mftprobe_engine_write_selected_tree_ddrescue_domain_partial_with_options(
    const char *image_path,
    const MftprobePartialNtfsSource *source,
    const MftprobeEngineOptions *options,
    const char *domain_map_path,
    uint64_t *out_range_count,
    uint64_t *out_total_bytes,
    uint64_t *out_file_count
);
int mftprobe_engine_run_selected_partial_recovery(
    const char *image_path,
    const char *out_dir,
    const MftprobePartialNtfsSource *source,
    const MftprobeEngineOptions *options,
    size_t *out_recovered_count,
    size_t *out_waiting_for_coverage,
    size_t *out_already_present,
    size_t *out_failed,
    size_t *out_folders_with_complete_files
);

MftprobeEngineStatus mftprobe_engine_last_status(void);
size_t mftprobe_engine_last_recovered_count(void);

#endif
