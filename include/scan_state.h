/*
 * scan_state.h
 * Shared scan state persistence for resumable scans.
 */

#ifndef SCAN_STATE_H
#define SCAN_STATE_H

#include <stddef.h>
#include <stdint.h>

#define SCAN_STATE_MAX_ACCEPTED_NTFS_SERIALS 8U

typedef struct {
    char source_path[1024];
    char source_device_name[128];
    char scan_mode[32];
    uint64_t source_size;
    uint64_t scan_offset;
    uint64_t source_ntfs_serial;
    uint64_t accepted_ntfs_serials[SCAN_STATE_MAX_ACCEPTED_NTFS_SERIALS];
    size_t accepted_ntfs_serial_count;
    int source_is_internal;
    int scan_completed;
    int completed;
} ScanState;

int scan_state_write(
    const char *path,
    const char *source_path,
    const char *scan_mode,
    uint64_t source_size,
    uint64_t scan_offset,
    int scan_completed,
    int completed
);

int scan_state_load(const char *path, ScanState *out);
int scan_state_load_emergency_mirror(const char *path, ScanState *out);
int scan_state_remove_emergency_mirror(const char *path);
int scan_state_emergency_mirror_is_older_than_path(
    const char *path,
    const char *reference_path
);
void scan_state_identity_reset(void);
void scan_state_identity_seed_from_loaded(const ScanState *state);
void scan_state_identity_set_current_ntfs_serial(uint64_t serial);
void scan_state_identity_note_confirmed_ntfs_serial(uint64_t serial);
void scan_state_identity_set_source_device_info(const char *device_name, int is_internal);
int scan_state_has_ntfs_serial_match(const ScanState *state, uint64_t serial);
void scan_state_format_ntfs_serial(uint64_t serial, char *out, size_t out_size);

#endif
