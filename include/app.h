/*
 * app.h
 * High-level application entry point.
 */

#ifndef APP_H
#define APP_H

#include <stddef.h>
#include <stdint.h>

int app_run(int argc, char *argv[]);
int app_stop_requested(void);
int app_supervisor_generation_stale(void);
int app_supervisor_generation_enabled(void);
void app_note_shutdown_progress(const char *context);
void app_request_source_reconnect(const char *context, int errno_code);
int app_source_reconnect_requested(void);
int app_source_reconnect_errno(void);
void app_gui_note_trouble(uint64_t start_offset, uint64_t end_offset, const char *kind);
void app_gui_note_recovery(long long abs_offset);
void app_gui_note_recovery_path(const char *path, long long abs_offset);
void app_gui_note_read_coverage(uint64_t start_offset, uint64_t end_offset);
size_t app_best_effort_recovered_count_for_run(const char *output_dir);
size_t app_best_effort_named_count_for_run(const char *output_dir);
size_t app_best_effort_unident_count_for_run(const char *output_dir);

#endif
