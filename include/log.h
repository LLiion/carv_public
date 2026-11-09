/*
 * log.h
 * Small logging helpers for terminal output.
 */

#ifndef LOG_H
#define LOG_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    LOG_TROUBLE_BUDGET_UNKNOWN = 0,
    LOG_TROUBLE_BUDGET_GREEN = 1,
    LOG_TROUBLE_BUDGET_YELLOW = 2,
    LOG_TROUBLE_BUDGET_RED = 3
} LogTroubleBudgetState;

typedef struct {
    uint64_t processed_bytes;
    uint64_t total_bytes;
    uint64_t speed_base_bytes;
    uint64_t budget_base_bytes;
    uint64_t budget_penalty_bytes;
    size_t recovered_files;
    size_t named_files;
    size_t unident_files;
    size_t repair_pending_files;
    size_t repair_queue_files;
    size_t record_index_count;
    size_t range_index_count;
    unsigned long long stalled_seconds;
    unsigned long long eta_seconds;
    double elapsed_seconds;
    double budget_elapsed_seconds;
    double recent_mib_per_sec;
    double target_mib_per_sec;
    int eta_phase;
    int load_eta_done;
    int working_running;
    int working_has_started;
    unsigned long long nominal_total_seconds;
    unsigned long long nominal_remaining_seconds;
    unsigned long long budget_eta_seconds;
    long long schedule_delta_seconds;
    int trouble_budget_state;
    int validator_budget_state;
    char activity[96];
    char background_activity[32];
} LogWorkingSnapshot;

void log_info(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_set_runtime_event_path(const char *path);
void log_runtime_event_info(const char *fmt, ...);
void log_runtime_event_verbose(const char *fmt, ...);
void log_runtime_event_error(const char *fmt, ...);
void log_set_verbose(int enabled);
int log_is_verbose(void);
void log_verbose(const char *fmt, ...);
void log_set_working_suffix(const char *suffix);
void log_set_working_activity(const char *activity);
void log_set_working_position_detail(const char *detail);
void log_set_working_progress(uint64_t processed_bytes, uint64_t total_bytes);
void log_set_working_speed_base(uint64_t base_bytes);
void log_set_working_budget_base(uint64_t base_bytes);
void log_set_working_budget_penalty(uint64_t penalty_bytes);
void log_set_working_elapsed_bias(double seconds);
void log_set_working_recovered_files(size_t recovered_files);
void log_set_working_named_files(size_t named_files);
void log_set_working_queue_stats(
    size_t unident_files,
    size_t repair_pending_files,
    size_t repair_queue_files,
    size_t record_index_count,
    size_t range_index_count,
    unsigned long long stalled_seconds,
    const char *background_activity
);
void log_set_eta_phase_load(void);
void log_set_eta_phase_scan(void);
void log_mark_load_eta_done(void);
int log_get_working_snapshot(LogWorkingSnapshot *out_snapshot);
double log_get_target_throughput_mib_per_sec(void);
void log_set_target_throughput_mib_per_sec(double mib_per_sec);
const char *log_target_throughput_profile_label(double target_mib_per_sec);
const char *log_target_throughput_profile_ui_label(double target_mib_per_sec);
LogTroubleBudgetState log_get_trouble_budget_state(void);
LogTroubleBudgetState log_get_validator_budget_state(void);
const char *log_trouble_budget_state_label(LogTroubleBudgetState state);
void log_calculate_budget_metrics_for_values(
    uint64_t processed_bytes,
    uint64_t total_bytes,
    uint64_t budget_base_bytes,
    uint64_t budget_penalty_bytes,
    double elapsed_seconds,
    double recent_mib_per_sec,
    unsigned long long *out_nominal_total_seconds,
    unsigned long long *out_nominal_remaining_seconds,
    unsigned long long *out_budget_eta_seconds,
    long long *out_schedule_delta_seconds,
    LogTroubleBudgetState *out_state,
    LogTroubleBudgetState *out_validator_state
);
void log_set_running_mode(void);
void log_set_done_mode(void);
void log_reset_terminal_mode(void);
void log_disable_blink(void);
void log_start_working_indicator(void);
void log_stop_working_indicator(void);

#endif
