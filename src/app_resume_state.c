#include "app_resume_state.h"

#include "config.h"
#include "scan_state.h"

void app_set_resume_state(
    AppConfig *config,
    int quick_resume,
    int additive_pass,
    uint64_t resume_offset,
    int resume_completed,
    int resume_scan_completed,
    int resume_active
)
{
    if (config == NULL) {
        return;
    }

    config->quick_resume = quick_resume;
    config->additive_pass = additive_pass;
    config->resume_offset = resume_offset;
    config->resume_completed = resume_completed;
    config->resume_scan_completed = resume_scan_completed;
    config->resume_active = resume_active;
}

void app_set_additive_resume_state(AppConfig *config, int quick_resume)
{
    app_set_resume_state(config, quick_resume, 1, 0ULL, 0, 0, 0);
}

void app_set_scan_completed_resume_state(
    AppConfig *config,
    const ScanState *scan_state
)
{
    if (scan_state == NULL) {
        return;
    }
    app_set_resume_state(config, 1, 0, scan_state->scan_offset, 0, 1, 0);
}

void app_set_completed_resume_state(
    AppConfig *config,
    const ScanState *scan_state
)
{
    if (scan_state == NULL) {
        return;
    }
    app_set_resume_state(config, 1, 0, scan_state->scan_offset, 1, 0, 0);
}

void app_set_loaded_scan_resume_state(
    AppConfig *config,
    const ScanState *scan_state
)
{
    if (scan_state == NULL) {
        return;
    }
    app_set_resume_state(
        config,
        1,
        0,
        scan_state->scan_offset,
        scan_state->completed,
        0,
        !scan_state->completed
    );
}

int app_additive_request_can_start_now(
    const AppConfig *config,
    int supervised_retry
)
{
    return config != NULL &&
           config->additive_requested &&
           (!supervised_retry || config->additive_auto_selection);
}

int app_write_loaded_scan_state(
    const char *scan_state_path,
    const ScanState *state,
    int scan_completed,
    int completed
)
{
    if (scan_state_path == NULL || state == NULL) {
        return 0;
    }

    return scan_state_write(
        scan_state_path,
        state->source_path,
        state->scan_mode,
        state->source_size,
        state->scan_offset,
        scan_completed,
        completed
    );
}

int app_write_current_or_loaded_scan_state(
    const AppConfig *config,
    const char *scan_state_path,
    const ScanState *state,
    int scan_completed,
    int completed
)
{
    if (config == NULL || scan_state_path == NULL || state == NULL) {
        return 0;
    }

    return scan_state_write(
        scan_state_path,
        state->source_path[0] != '\0'
            ? state->source_path
            : config->input_path,
        state->scan_mode[0] != '\0'
            ? state->scan_mode
            : config_scan_mode_label(config),
        state->source_size,
        state->scan_offset,
        scan_completed,
        completed
    );
}
