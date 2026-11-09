/*
 * reader.h
 * Opens an input file and reads it sequentially in fixed-size chunks with overlap.
 */

#ifndef READER_H
#define READER_H

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>

typedef void (*ReaderSequentialChunkObserver)(
    uint64_t absolute_offset,
    const uint8_t *bytes,
    size_t byte_count,
    void *context
);

typedef struct {
    FILE *file;
    int fd;
    const char *path;
    uint8_t *buffer;
    uint8_t *io_buffer;
    size_t io_buffer_size;
    size_t direct_read_alignment;
    int use_stdio_device_reads;
    int source_is_regular_file;
    dev_t source_open_dev;
    ino_t source_open_ino;
    uint64_t source_size;
    int sequential_advice_enabled;
    size_t sequential_prefetch_bytes;
    size_t sequential_release_bytes;
    uint64_t sequential_last_read_offset;
    uint64_t sequential_last_read_end_offset;
    uint64_t sequential_prefetch_end_offset;
    uint64_t sequential_release_end_offset;
    size_t chunk_size;
    size_t overlap_size;
    size_t bytes_in_buffer;
    size_t overlap_bytes;
    size_t total_bytes_read;
    uint64_t progress_bytes_read;
    uint64_t read_error_count;
    uint64_t read_error_range_count;
    uint64_t read_error_bytes;
    uint64_t last_read_error_offset;
    uint64_t last_read_error_length;
    uint64_t pending_read_error_offset;
    uint64_t pending_read_error_end_offset;
    uint64_t pending_read_error_bytes;
    uint64_t pending_read_error_spans;
    int pending_read_error_errno;
    char bad_read_state_path[1024];
    char trouble_map_path[1024];
    char error_report_path[1024];
    char error_cluster_report_path[1024];
    char error_report_run_id[256];
    int error_report_detail_suppressed;
    uint64_t pending_cluster_error_offset;
    uint64_t pending_cluster_error_end_offset;
    uint64_t pending_cluster_error_bytes;
    uint64_t pending_cluster_error_spans;
    int pending_cluster_error_errno;
    int report_progress;
    int is_first_chunk;
    int precise_record_mode;
    int precise_record_first_sector_only;
    size_t precise_record_probe_bytes;
    size_t precise_record_first_sector_cap_bytes;
    int last_precise_record_first_sector_failed;
    int last_precise_record_later_sector_failed;
    int last_precise_record_first_sector_partial;
    size_t last_precise_record_failed_sectors;
    size_t last_precise_record_skipped_sectors;
    size_t last_precise_record_first_sector_bytes_read;
    size_t precise_record_sector_size;
    uint64_t precise_record_total_failed_sectors;
    uint64_t precise_record_total_skipped_sectors;
    uint64_t precise_record_total_partial_first_sectors;
    ReaderSequentialChunkObserver sequential_chunk_observer;
    void *sequential_chunk_observer_context;
} Reader;

int reader_open(Reader *reader, const char *path, size_t chunk_size, size_t overlap_size);
size_t reader_read_next(Reader *reader);
size_t reader_read_at_resilient(
    Reader *reader,
    uint64_t absolute_offset,
    void *buffer,
    size_t length,
    uint64_t *out_new_error_bytes
);
int reader_seek_absolute(Reader *reader, uint64_t absolute_offset);
int reader_set_progress_reporting(Reader *reader, int enabled);
void reader_set_sequential_chunk_observer(
    Reader *reader,
    ReaderSequentialChunkObserver observer,
    void *context
);
int reader_set_error_report_path(Reader *reader, const char *path);
int reader_set_error_report_run_id(Reader *reader, const char *run_id);
int reader_set_bad_read_state_path(Reader *reader, const char *path);
int reader_set_trouble_map_path(Reader *reader, const char *path);
int reader_set_precise_record_mode(Reader *reader, int enabled);
int reader_set_precise_record_first_sector_only(Reader *reader, int enabled);
int reader_set_precise_record_probe_bytes(Reader *reader, size_t bytes);
int reader_set_precise_record_first_sector_cap_bytes(Reader *reader, size_t bytes);
uint64_t reader_get_read_error_count(const Reader *reader);
uint64_t reader_get_last_read_error_offset(const Reader *reader);
uint64_t reader_get_last_read_error_length(const Reader *reader);
uint64_t reader_get_precise_record_total_failed_sectors(const Reader *reader);
uint64_t reader_get_precise_record_total_skipped_sectors(const Reader *reader);
uint64_t reader_get_precise_record_total_partial_first_sectors(const Reader *reader);
int reader_error_is_fatal_device_error(int error_code);
int reader_last_errno(void);
void reader_close(Reader *reader);
const char *reader_last_error(void);
int reader_path_is_block_device(const char *path);
int reader_resolve_mounted_source_device(const char *path, char *out, size_t out_size);
int reader_path_is_mounted(const char *path);
int reader_unmount_path(const char *path);
int reader_block_device_is_read_only(const char *path);
int reader_set_block_device_read_only(const char *path);
uint64_t reader_get_source_size(const Reader *reader);
/* Read-only size probe shared by filesystem backends. Handles regular files,
 * Linux block devices, and macOS block/raw character devices. */
uint64_t reader_detect_source_size(const char *path);

#endif
