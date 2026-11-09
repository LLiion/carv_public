#ifndef APP_RESUME_STATE_H
#define APP_RESUME_STATE_H

#include "config.h"
#include "scan_state.h"

#include <stdint.h>

void app_set_resume_state(
    AppConfig *config,
    int quick_resume,
    int additive_pass,
    uint64_t resume_offset,
    int resume_completed,
    int resume_scan_completed,
    int resume_active
);

void app_set_additive_resume_state(AppConfig *config, int quick_resume);
void app_set_scan_completed_resume_state(AppConfig *config, const ScanState *scan_state);
void app_set_completed_resume_state(AppConfig *config, const ScanState *scan_state);
void app_set_loaded_scan_resume_state(AppConfig *config, const ScanState *scan_state);

int app_additive_request_can_start_now(
    const AppConfig *config,
    int supervised_retry
);

int app_write_loaded_scan_state(
    const char *scan_state_path,
    const ScanState *state,
    int scan_completed,
    int completed
);

int app_write_current_or_loaded_scan_state(
    const AppConfig *config,
    const char *scan_state_path,
    const ScanState *state,
    int scan_completed,
    int completed
);

#endif
