#ifndef EXFAT_BACKEND_H
#define EXFAT_BACKEND_H

#include "mft_spool.h"
#include "mft_types.h"

#include <stdint.h>
#include <time.h>

typedef struct {
    uint64_t source_size;
    uint64_t volume_offset;
    uint64_t volume_size;
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint32_t fat_offset_sectors;
    uint32_t fat_length_sectors;
    uint32_t cluster_heap_offset_sectors;
    uint32_t cluster_count;
    uint32_t root_directory_cluster;
    uint8_t number_of_fats;
    uint16_t volume_flags;
} ExfatBackendGeometry;

void exfat_backend_reset(void);
void exfat_backend_set_output_dir(const char *output_dir);
int exfat_backend_configure_from_source(const char *input_path);
int exfat_backend_has_geometry(void);
int exfat_backend_translate_photorec_file_number(
    unsigned long long file_number,
    long long *out_abs_offset
);
const char *exfat_backend_source_hint(void);
const ExfatBackendGeometry *exfat_backend_current_geometry(void);
size_t exfat_backend_entry_count(void);
int exfat_backend_prepare_index(void);
int exfat_backend_load_recovered_output_state(void);
const char *exfat_backend_lookup_path_by_offset(long long abs_offset);
time_t exfat_backend_lookup_created_time_by_offset(long long abs_offset);
int exfat_backend_lookup_scan_hint(long long abs_offset, MftScanHint *out);
const char *exfat_backend_lookup_container_label_by_offset(long long abs_offset);
int exfat_backend_build_recovered_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
void exfat_backend_note_recovered_output(const char *path, long long abs_offset);
int exfat_backend_get_recovered_output_info(
    long long abs_offset,
    char *out_path,
    size_t out_path_size,
    int *out_reconciled
);
void exfat_backend_get_live_stats(MftSpoolLiveStats *out);
size_t exfat_backend_recovered_output_count(void);
size_t exfat_backend_named_output_count(void);
size_t exfat_backend_unreconciled_output_count(void);
int exfat_backend_is_offset_fully_recovered(long long abs_offset);
int exfat_backend_finalize_recovered_outputs(void);
void exfat_backend_refresh_recovery_state(size_t *entry_count_snapshot);
void exfat_backend_reconcile_recovered_outputs_live(void);

#endif
