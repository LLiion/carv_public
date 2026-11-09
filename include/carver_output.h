#ifndef CARVER_OUTPUT_H
#define CARVER_OUTPUT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "fs_backend.h"

typedef struct {
    FILE *file;
    char path[1024];
    char replacement_existing_path[1024];
    char extension[32];
    size_t replacement_existing_size;
    long long abs_offset;
    int deferred_capture;
    int replacement_candidate;
    int replacement_existing_reconciled;
} CarverOutput;

typedef struct {
    size_t queue_count;
    size_t queue_capacity;
    size_t active_jobs;
    uint64_t outstanding_bytes;
    int running;
} AsyncOutputLiveStats;

typedef int (*CarverOutputValidator)(const char *path, void *ctx);

int carver_output_open(
    CarverOutput *out,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
int carver_output_open_deferred(
    CarverOutput *out,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
);
void carver_output_set_metadata_context_skip_enabled(int enabled);
int carver_output_should_skip_by_metadata_context(long long abs_offset);
int carver_output_should_skip_small_derivative_image_view(
    const FsViewEntry *view
);

/* Compatibility shims while the rest of the tree finishes the rename. */
void carver_output_set_mft_context_skip_enabled(int enabled);
int carver_output_should_skip_by_mft_context(long long abs_offset);
int carver_output_should_skip_existing_recovered(
    long long abs_offset,
    size_t start_offset,
    size_t *resume_offset
);
int carver_output_existing_recovered_allows_replace_attempt(
    long long abs_offset,
    const char *extension
);
int carver_output_write_buffer(
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension,
    const uint8_t *data,
    size_t data_size
);
int carver_output_replace_existing_buffer_if_better(
    long long abs_offset,
    const char *extension,
    const uint8_t *data,
    size_t data_size
);
int carver_output_note_deferred_completion(const char *path, long long abs_offset);
int carver_output_async_start(void);
void carver_output_async_drain_completions(void);
void carver_output_async_flush(void);
void carver_output_async_stop(void);
void carver_output_async_get_live_stats(AsyncOutputLiveStats *out);
int carver_output_finish(CarverOutput *out);
int carver_output_finish_validated(
    CarverOutput *out,
    CarverOutputValidator validator,
    void *ctx
);
void carver_output_abort(CarverOutput *out);

#endif
