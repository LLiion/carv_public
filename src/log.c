#define _POSIX_C_SOURCE 200809L

/*
 * log.c
 */

#include "log.h"
#include "fs_backend.h"

#include <stdio.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <limits.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))


/* ANSI */
#define LOG_BLUE_HEX "#0000aa"
#define ANSI_FG_WHITE "\033[37m"
#define ANSI_FG_GREEN "\033[32m"
#define ANSI_FG_DEFAULT "\033[39m"
#define ANSI_FG_YELLOW_UNDERLINE "\033[33;4m"
#define ANSI_FG_WHITE_UNDERLINE "\033[37;4m"
#define ANSI_FG_WHITE_NO_UNDERLINE "\033[37;24m"
#define ANSI_BG_BLUE  "\033[48;2;0;0;170m"
#define ANSI_BG_BLACK "\033[40m"
#define ANSI_BG_DEFAULT "\033[49m"
#define ANSI_RESET    "\033[0m"
#define OSC_SET_BG_BLUE "\033]11;" LOG_BLUE_HEX "\007"
#define OSC_RESET_BG    "\033]111\007"

#define WORKING_SPEED_MIN_INTERVAL_SECONDS 0.25
#define WORKING_SPEED_MIN_DELTA_BYTES (8ULL * 1024ULL * 1024ULL)
#define WORKING_SPEED_SEGMENT_TARGET_BYTES (256ULL * 1024ULL * 1024ULL)
#define WORKING_SPEED_SEGMENT_MAX_SECONDS 60.0
#define WORKING_SPEED_DISPLAY_MEDIAN_SEGMENTS 8U
#define WORKING_SPEED_HISTORY_CAPACITY 24U
#define WORKING_SPEED_MIN_MEDIAN_SAMPLES 4U
#define WORKING_NOTICE_TTL_SECONDS 8.0
#define WORKING_TARGET_THROUGHPUT_MIB_PER_SEC 18.0
#define WORKING_TROUBLE_BUDGET_MIN_ELAPSED_SECONDS 180.0
#define WORKING_TROUBLE_BUDGET_MIN_PROGRESS_BYTES (256ULL * 1024ULL * 1024ULL)
#define WORKING_TROUBLE_BUDGET_GREEN_FRACTION 0.03
#define WORKING_TROUBLE_BUDGET_RED_FRACTION 0.10
#define WORKING_TROUBLE_BUDGET_GREEN_MIN_SECONDS (15ULL * 60ULL)
#define WORKING_TROUBLE_BUDGET_RED_MIN_SECONDS (60ULL * 60ULL)
#define WORKING_VALIDATOR_BUDGET_YELLOW_FRACTION 0.0075
#define WORKING_VALIDATOR_BUDGET_RED_FRACTION 0.025
#define WORKING_VALIDATOR_BUDGET_YELLOW_MIN_SECONDS (2ULL * 60ULL)
#define WORKING_VALIDATOR_BUDGET_RED_MIN_SECONDS (10ULL * 60ULL)
#define WORKING_TROUBLE_AVERAGE_RATIO_YELLOW 0.85
#define WORKING_TROUBLE_AVERAGE_RATIO_RED 0.60
#define WORKING_TROUBLE_RECENT_RATIO_YELLOW 0.75
#define WORKING_TROUBLE_RECENT_RATIO_RED 0.45
#define WORKING_VALIDATOR_AVERAGE_RATIO_YELLOW 0.80
#define WORKING_VALIDATOR_AVERAGE_RATIO_RED 0.55
#define WORKING_VALIDATOR_RECENT_RATIO_YELLOW 0.70
#define WORKING_VALIDATOR_RECENT_RATIO_RED 0.40

/* State */
static const char *current_color = ANSI_FG_DEFAULT;
static const char *current_background = ANSI_BG_DEFAULT;
static int blink_enabled = 1;
static int g_dynamic_terminal_background_active = 0;
static int g_log_verbose = 0;
static char g_runtime_event_path[1024] = "";
static int working_running = 0;
static pthread_t working_thread;
static pthread_mutex_t working_mutex = PTHREAD_MUTEX_INITIALIZER;
static char working_suffix[128] = "";
static char working_activity[96] = "";
static uint64_t working_processed_bytes = 0;
static uint64_t working_total_bytes = 0;
static uint64_t working_speed_base_bytes = 0;
static uint64_t working_budget_base_bytes = 0;
static uint64_t working_budget_penalty_bytes = 0;
static size_t working_recovered_files = 0;
static size_t working_named_files = 0;
static size_t working_unident_files = 0;
static size_t working_repair_pending_files = 0;
static size_t working_repair_queue_files = 0;
static size_t working_record_index_count = 0;
static size_t working_range_index_count = 0;
static unsigned long long working_stalled_seconds = 0;
static char working_background_activity[32] = "";
static double working_reconcile_files_per_sec = 0.0;
static double working_last_reconcile_rate_at = 0.0;
static int working_eta_phase = 1; /* 0=load, 1=scan */
static int working_load_eta_done = 0;
static struct timespec working_started_at = {0};
static int working_has_started = 0;
static double working_elapsed_bias_seconds = 0.0;
static uint64_t working_last_speed_bytes = 0;
static double working_last_speed_at = 0.0;
static double working_last_progress_at = 0.0;
static double working_fallback_mib_per_sec = 0.0;
static double working_recent_mib_per_sec = 0.0;
static double working_target_throughput_mib_per_sec =
    WORKING_TARGET_THROUGHPUT_MIB_PER_SEC;
static double working_speed_samples[WORKING_SPEED_HISTORY_CAPACITY] = {0};
static size_t working_speed_sample_count = 0;
static size_t working_speed_sample_next = 0;
static char working_notice[192] = "";
static char working_position_detail[128] = "";
static double working_notice_until = 0.0;
static int g_emergency_runtime_notice_printed = 0;

/* ========================= CORE ========================= */

static double monotonic_seconds(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + ((double)now.tv_nsec / 1000000000.0);
}

static double elapsed_seconds_since_start(void)
{
    double started_at;

    if (!working_has_started) {
        return 0.0;
    }

    started_at = (double)working_started_at.tv_sec +
                 ((double)working_started_at.tv_nsec / 1000000000.0);
    return monotonic_seconds() - started_at;
}

static int compare_double_values_local(const void *left, const void *right)
{
    double left_value = *(const double *)left;
    double right_value = *(const double *)right;

    if (left_value < right_value) {
        return -1;
    }
    if (left_value > right_value) {
        return 1;
    }
    return 0;
}

static void working_reset_speed_history_locked(void)
{
    working_last_speed_bytes = working_processed_bytes;
    working_last_speed_at = monotonic_seconds();
    working_last_progress_at = working_last_speed_at;
    working_fallback_mib_per_sec = 0.0;
    working_recent_mib_per_sec = 0.0;
    working_speed_sample_count = 0;
    working_speed_sample_next = 0;
    memset(working_speed_samples, 0, sizeof(working_speed_samples));
}

static double working_compute_speed_median_locked(size_t wanted_segments)
{
    double samples[WORKING_SPEED_HISTORY_CAPACITY];
    size_t take;
    size_t i;
    size_t index;

    if (working_speed_sample_count == 0 || wanted_segments == 0) {
        return 0.0;
    }

    take = working_speed_sample_count < wanted_segments ?
           working_speed_sample_count : wanted_segments;
    if (take < WORKING_SPEED_MIN_MEDIAN_SAMPLES) {
        return 0.0;
    }

    for (i = 0; i < take; ++i) {
        index = (working_speed_sample_next +
                 WORKING_SPEED_HISTORY_CAPACITY - 1U - i) %
                WORKING_SPEED_HISTORY_CAPACITY;
        samples[i] = working_speed_samples[index];
    }

    qsort(samples, take, sizeof(samples[0]), compare_double_values_local);
    if ((take % 2U) != 0U) {
        return samples[take / 2U];
    }

    return (samples[(take / 2U) - 1U] + samples[take / 2U]) / 2.0;
}

static void working_refresh_speed_estimates_locked(void)
{
    double display_speed;

    display_speed =
        working_compute_speed_median_locked(WORKING_SPEED_DISPLAY_MEDIAN_SEGMENTS);

    if (display_speed > 0.0) {
        working_recent_mib_per_sec = display_speed;
    } else {
        working_recent_mib_per_sec = working_fallback_mib_per_sec;
    }
}

static void working_append_speed_sample_locked(double sample_mib_per_sec)
{
    if (sample_mib_per_sec <= 0.0) {
        return;
    }

    working_speed_samples[working_speed_sample_next] = sample_mib_per_sec;
    working_speed_sample_next =
        (working_speed_sample_next + 1U) % WORKING_SPEED_HISTORY_CAPACITY;
    if (working_speed_sample_count < WORKING_SPEED_HISTORY_CAPACITY) {
        working_speed_sample_count++;
    }

    working_refresh_speed_estimates_locked();
}

static size_t stdout_terminal_columns(void)
{
    struct winsize ws;

    if (!isatty(STDOUT_FILENO)) {
        return 0;
    }

    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) != 0) {
        return 0;
    }

    if (ws.ws_col == 0) {
        return 0;
    }

    return (size_t)ws.ws_col;
}

static void clamp_line_to_terminal_width(char *line, size_t line_size)
{
    size_t columns;
    size_t limit;

    if (line == NULL || line_size == 0) {
        return;
    }

    columns = stdout_terminal_columns();
    if (columns <= 1) {
        return;
    }

    /*
     * Keep one column free so terminals do not auto-wrap and break
     * in-place redraws based on carriage return.
     */
    limit = columns - 1;
    if (strlen(line) > limit) {
        line[limit] = '\0';
    }
}

static void format_eta_text(
    unsigned long long total_seconds,
    char *out,
    size_t out_size
)
{
    unsigned long long hours;
    unsigned long long minutes;
    unsigned long long seconds;

    if (out == NULL || out_size == 0) {
        return;
    }

    if (total_seconds >= 3600ULL) {
        hours = total_seconds / 3600ULL;
        minutes = (total_seconds % 3600ULL) / 60ULL;
        snprintf(out, out_size, "eta=%lluh %llum", hours, minutes);
        return;
    }

    if (total_seconds >= 60ULL) {
        minutes = total_seconds / 60ULL;
        seconds = total_seconds % 60ULL;
        snprintf(out, out_size, "eta=%llum %llus", minutes, seconds);
        return;
    }

    snprintf(out, out_size, "eta=%llus", total_seconds);
}

static unsigned long long max_ull_local(
    unsigned long long left,
    unsigned long long right
)
{
    return left > right ? left : right;
}

static double clamp_double_local(double value, double minimum, double maximum)
{
    if (value < minimum) {
        return minimum;
    }
    if (value > maximum) {
        return maximum;
    }
    return value;
}

static LogTroubleBudgetState max_budget_state_local(
    LogTroubleBudgetState left,
    LogTroubleBudgetState right
)
{
    return left > right ? left : right;
}

static LogTroubleBudgetState budget_state_from_ratio_local(
    double ratio,
    double yellow_ratio,
    double red_ratio
)
{
    if (ratio <= 0.0) {
        return LOG_TROUBLE_BUDGET_RED;
    }
    if (ratio < red_ratio) {
        return LOG_TROUBLE_BUDGET_RED;
    }
    if (ratio < yellow_ratio) {
        return LOG_TROUBLE_BUDGET_YELLOW;
    }
    return LOG_TROUBLE_BUDGET_GREEN;
}

const char *log_trouble_budget_state_label(LogTroubleBudgetState state)
{
    switch (state) {
        case LOG_TROUBLE_BUDGET_GREEN:
            return "green";
        case LOG_TROUBLE_BUDGET_YELLOW:
            return "yellow";
        case LOG_TROUBLE_BUDGET_RED:
            return "red";
        case LOG_TROUBLE_BUDGET_UNKNOWN:
        default:
            return "unknown";
    }
}

static void working_calculate_budget_metrics(
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
)
{
    double target_mib_per_sec = working_target_throughput_mib_per_sec;
    double target_factor;
    double min_elapsed_seconds;
    uint64_t min_progress_bytes;
    double trouble_green_fraction;
    double trouble_red_fraction;
    unsigned long long trouble_green_min_seconds;
    unsigned long long trouble_red_min_seconds;
    double validator_yellow_fraction;
    double validator_red_fraction;
    unsigned long long validator_yellow_min_seconds;
    unsigned long long validator_red_min_seconds;
    const double target_bytes_per_second =
        (target_mib_per_sec > 0.0
             ? target_mib_per_sec
             : WORKING_TARGET_THROUGHPUT_MIB_PER_SEC) *
        1024.0 * 1024.0;
    unsigned long long nominal_total_seconds = 0ULL;
    unsigned long long nominal_remaining_seconds = 0ULL;
    unsigned long long budget_eta_seconds = 0ULL;
    long long schedule_delta_seconds = 0LL;
    LogTroubleBudgetState state = LOG_TROUBLE_BUDGET_UNKNOWN;
    LogTroubleBudgetState validator_state = LOG_TROUBLE_BUDGET_UNKNOWN;
    uint64_t window_total_bytes = 0ULL;
    uint64_t window_done_bytes = 0ULL;
    uint64_t effective_done_bytes = 0ULL;

    if (out_nominal_total_seconds != NULL) {
        *out_nominal_total_seconds = 0ULL;
    }
    if (out_nominal_remaining_seconds != NULL) {
        *out_nominal_remaining_seconds = 0ULL;
    }
    if (out_budget_eta_seconds != NULL) {
        *out_budget_eta_seconds = 0ULL;
    }
    if (out_schedule_delta_seconds != NULL) {
        *out_schedule_delta_seconds = 0LL;
    }
    if (out_state != NULL) {
        *out_state = LOG_TROUBLE_BUDGET_UNKNOWN;
    }
    if (out_validator_state != NULL) {
        *out_validator_state = LOG_TROUBLE_BUDGET_UNKNOWN;
    }

    if (target_bytes_per_second <= 0.0 || total_bytes == 0ULL) {
        return;
    }

    if (target_mib_per_sec <= 0.0) {
        target_mib_per_sec = WORKING_TARGET_THROUGHPUT_MIB_PER_SEC;
    }
    target_factor = clamp_double_local(
        target_mib_per_sec / WORKING_TARGET_THROUGHPUT_MIB_PER_SEC,
        0.25,
        2.5
    );
    min_elapsed_seconds = clamp_double_local(
        WORKING_TROUBLE_BUDGET_MIN_ELAPSED_SECONDS / target_factor,
        45.0,
        12.0 * 60.0
    );
    min_progress_bytes = (uint64_t)clamp_double_local(
        (double)WORKING_TROUBLE_BUDGET_MIN_PROGRESS_BYTES / target_factor,
        64.0 * 1024.0 * 1024.0,
        1024.0 * 1024.0 * 1024.0
    );
    trouble_green_fraction = clamp_double_local(
        WORKING_TROUBLE_BUDGET_GREEN_FRACTION / target_factor,
        0.01,
        0.15
    );
    trouble_red_fraction = clamp_double_local(
        WORKING_TROUBLE_BUDGET_RED_FRACTION / target_factor,
        0.03,
        0.40
    );
    trouble_green_min_seconds = (unsigned long long)clamp_double_local(
        (double)WORKING_TROUBLE_BUDGET_GREEN_MIN_SECONDS / target_factor,
        2.0 * 60.0,
        2.0 * 60.0 * 60.0
    );
    trouble_red_min_seconds = (unsigned long long)clamp_double_local(
        (double)WORKING_TROUBLE_BUDGET_RED_MIN_SECONDS / target_factor,
        10.0 * 60.0,
        6.0 * 60.0 * 60.0
    );
    validator_yellow_fraction = clamp_double_local(
        WORKING_VALIDATOR_BUDGET_YELLOW_FRACTION / target_factor,
        0.0025,
        0.05
    );
    validator_red_fraction = clamp_double_local(
        WORKING_VALIDATOR_BUDGET_RED_FRACTION / target_factor,
        0.01,
        0.12
    );
    validator_yellow_min_seconds = (unsigned long long)clamp_double_local(
        (double)WORKING_VALIDATOR_BUDGET_YELLOW_MIN_SECONDS / target_factor,
        30.0,
        30.0 * 60.0
    );
    validator_red_min_seconds = (unsigned long long)clamp_double_local(
        (double)WORKING_VALIDATOR_BUDGET_RED_MIN_SECONDS / target_factor,
        2.0 * 60.0,
        2.0 * 60.0 * 60.0
    );

    if (budget_base_bytes >= total_bytes) {
        budget_base_bytes = 0ULL;
    }

    window_total_bytes = total_bytes - budget_base_bytes;
    if (processed_bytes > budget_base_bytes) {
        window_done_bytes = processed_bytes - budget_base_bytes;
    }
    if (window_done_bytes > window_total_bytes) {
        window_done_bytes = window_total_bytes;
    }
    if (budget_penalty_bytes > window_total_bytes) {
        budget_penalty_bytes = window_total_bytes;
    }
    effective_done_bytes =
        window_done_bytes > budget_penalty_bytes
            ? window_done_bytes - budget_penalty_bytes
            : 0ULL;

    nominal_total_seconds = (unsigned long long)(
        ((double)window_total_bytes / target_bytes_per_second) + 0.999999
    );
    nominal_remaining_seconds = (unsigned long long)(
        ((double)(window_total_bytes - effective_done_bytes) / target_bytes_per_second) +
        0.999999
    );

    if (elapsed_seconds >= 0.0) {
        double expected_done_bytes = elapsed_seconds * target_bytes_per_second;
        double delta_seconds_double;
        double average_ratio = 1.0;
        double recent_ratio = 0.0;
        unsigned long long recent_remaining_seconds = 0ULL;
        unsigned long long debt_seconds = 0ULL;
        unsigned long long green_debt_seconds;
        unsigned long long red_debt_seconds;
        LogTroubleBudgetState throughput_state = LOG_TROUBLE_BUDGET_GREEN;
        LogTroubleBudgetState validator_throughput_state =
            LOG_TROUBLE_BUDGET_GREEN;
        LogTroubleBudgetState recent_state = LOG_TROUBLE_BUDGET_GREEN;
        LogTroubleBudgetState validator_recent_state =
            LOG_TROUBLE_BUDGET_GREEN;

        if (expected_done_bytes < 0.0) {
            expected_done_bytes = 0.0;
        }
        if (expected_done_bytes > (double)window_total_bytes) {
            expected_done_bytes = (double)window_total_bytes;
        }

        delta_seconds_double =
            ((double)effective_done_bytes - expected_done_bytes) / target_bytes_per_second;
        if (delta_seconds_double >= 0.0) {
            schedule_delta_seconds = (long long)(delta_seconds_double + 0.5);
        } else {
            schedule_delta_seconds = (long long)(delta_seconds_double - 0.5);
        }

        if (schedule_delta_seconds >= 0LL) {
            if ((unsigned long long)schedule_delta_seconds >= nominal_remaining_seconds) {
                budget_eta_seconds = 0ULL;
            } else {
                budget_eta_seconds =
                    nominal_remaining_seconds - (unsigned long long)schedule_delta_seconds;
            }
        } else {
            budget_eta_seconds =
                nominal_remaining_seconds + (unsigned long long)(-schedule_delta_seconds);
            debt_seconds = (unsigned long long)(-schedule_delta_seconds);
        }

        if (elapsed_seconds > 0.0) {
            average_ratio =
                ((double)effective_done_bytes / elapsed_seconds) /
                target_bytes_per_second;
        }
        if (average_ratio < 0.0) {
            average_ratio = 0.0;
        }
        if (recent_mib_per_sec > 0.0 && target_mib_per_sec > 0.0) {
            recent_ratio = recent_mib_per_sec / target_mib_per_sec;
            if (recent_mib_per_sec > 0.0) {
                recent_remaining_seconds = (unsigned long long)(
                    ((double)(window_total_bytes - effective_done_bytes) /
                     (recent_mib_per_sec * 1024.0 * 1024.0)) + 0.999999
                );
            }
        }

        if (average_ratio < 0.95 && schedule_delta_seconds > 0LL) {
            schedule_delta_seconds = 0LL;
            if (budget_eta_seconds < nominal_remaining_seconds) {
                budget_eta_seconds = nominal_remaining_seconds;
            }
        }
        if (recent_ratio > 0.0 &&
            recent_ratio < 0.95 &&
            recent_remaining_seconds > budget_eta_seconds) {
            budget_eta_seconds = recent_remaining_seconds;
            if (budget_eta_seconds > nominal_remaining_seconds) {
                unsigned long long delta =
                    budget_eta_seconds - nominal_remaining_seconds;
                schedule_delta_seconds =
                    delta > (unsigned long long)LLONG_MAX
                        ? LLONG_MIN + 1LL
                        : -(long long)delta;
            } else {
                schedule_delta_seconds =
                    (long long)(nominal_remaining_seconds - budget_eta_seconds);
            }
        }
        if (schedule_delta_seconds < 0LL) {
            debt_seconds = (unsigned long long)(-schedule_delta_seconds);
        } else {
            debt_seconds = 0ULL;
        }

        state = LOG_TROUBLE_BUDGET_GREEN;
        validator_state = LOG_TROUBLE_BUDGET_GREEN;
        if (elapsed_seconds >= min_elapsed_seconds &&
            window_done_bytes >= min_progress_bytes) {
            green_debt_seconds = max_ull_local(
                trouble_green_min_seconds,
                (unsigned long long)(
                    ((double)nominal_total_seconds * trouble_green_fraction) + 0.5
                )
            );
            red_debt_seconds = max_ull_local(
                trouble_red_min_seconds,
                (unsigned long long)(
                    ((double)nominal_total_seconds * trouble_red_fraction) + 0.5
                )
            );

            if (debt_seconds > red_debt_seconds) {
                state = LOG_TROUBLE_BUDGET_RED;
            } else if (debt_seconds > green_debt_seconds) {
                state = LOG_TROUBLE_BUDGET_YELLOW;
            }

            throughput_state = budget_state_from_ratio_local(
                average_ratio,
                WORKING_TROUBLE_AVERAGE_RATIO_YELLOW,
                WORKING_TROUBLE_AVERAGE_RATIO_RED
            );
            validator_throughput_state = budget_state_from_ratio_local(
                average_ratio,
                WORKING_VALIDATOR_AVERAGE_RATIO_YELLOW,
                WORKING_VALIDATOR_AVERAGE_RATIO_RED
            );
            state = max_budget_state_local(state, throughput_state);
            validator_state = max_budget_state_local(
                validator_state,
                validator_throughput_state
            );

            if (recent_ratio > 0.0) {
                recent_state = budget_state_from_ratio_local(
                    recent_ratio,
                    WORKING_TROUBLE_RECENT_RATIO_YELLOW,
                    WORKING_TROUBLE_RECENT_RATIO_RED
                );
                validator_recent_state = budget_state_from_ratio_local(
                    recent_ratio,
                    WORKING_VALIDATOR_RECENT_RATIO_YELLOW,
                    WORKING_VALIDATOR_RECENT_RATIO_RED
                );
                state = max_budget_state_local(state, recent_state);
                validator_state = max_budget_state_local(
                    validator_state,
                    validator_recent_state
                );
            }
        }

        if (elapsed_seconds >= min_elapsed_seconds &&
            window_done_bytes >= min_progress_bytes) {
            unsigned long long validator_yellow_debt_seconds = max_ull_local(
                validator_yellow_min_seconds,
                (unsigned long long)(
                    ((double)nominal_total_seconds * validator_yellow_fraction) + 0.5
                )
            );
            unsigned long long validator_red_debt_seconds = max_ull_local(
                validator_red_min_seconds,
                (unsigned long long)(
                    ((double)nominal_total_seconds * validator_red_fraction) + 0.5
                )
            );

            if (debt_seconds > validator_red_debt_seconds) {
                validator_state = LOG_TROUBLE_BUDGET_RED;
            } else if (debt_seconds > validator_yellow_debt_seconds) {
                validator_state = LOG_TROUBLE_BUDGET_YELLOW;
            }
        }
    }

    if (out_nominal_total_seconds != NULL) {
        *out_nominal_total_seconds = nominal_total_seconds;
    }
    if (out_nominal_remaining_seconds != NULL) {
        *out_nominal_remaining_seconds = nominal_remaining_seconds;
    }
    if (out_budget_eta_seconds != NULL) {
        *out_budget_eta_seconds = budget_eta_seconds;
    }
    if (out_schedule_delta_seconds != NULL) {
        *out_schedule_delta_seconds = schedule_delta_seconds;
    }
    if (out_state != NULL) {
        *out_state = state;
    }
    if (out_validator_state != NULL) {
        *out_validator_state = validator_state;
    }
}

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
)
{
    working_calculate_budget_metrics(
        processed_bytes,
        total_bytes,
        budget_base_bytes,
        budget_penalty_bytes,
        elapsed_seconds,
        recent_mib_per_sec,
        out_nominal_total_seconds,
        out_nominal_remaining_seconds,
        out_budget_eta_seconds,
        out_schedule_delta_seconds,
        out_state,
        out_validator_state
    );
}

static void format_stalled_text(
    unsigned long long stalled_seconds,
    char *out,
    size_t out_size
)
{
    unsigned long long tenths_minutes;
    unsigned long long whole_minutes;
    unsigned long long tenth;

    if (out == NULL || out_size == 0) {
        return;
    }

    out[0] = '\0';
    if (stalled_seconds < 60ULL) {
        return;
    }

    tenths_minutes = ((stalled_seconds * 10ULL) + 30ULL) / 60ULL;
    whole_minutes = tenths_minutes / 10ULL;
    tenth = tenths_minutes % 10ULL;
    snprintf(out, out_size, " stalled=%llu,%llum", whole_minutes, tenth);
}

static const char *display_activity_label(const char *activity)
{
    if (activity == NULL || activity[0] == '\0') {
        return "";
    }

    if (strcmp(activity, "starting raw-all scan") == 0 ||
        strcmp(activity, "scanning file signatures") == 0) {
        return "reading disk";
    }

    if (strcmp(activity, "preparing MFT index") == 0) {
        return "preparing index";
    }

    if (strcmp(activity, "mapping live filesystem metadata") == 0) {
        return "mapping metadata";
    }

    if (strcmp(activity, "finalizing existing raw-all run") == 0) {
        return "finalizing";
    }

    return activity;
}

static int activity_is_live_metadata_busy(const char *activity)
{
    if (activity == NULL || activity[0] == '\0') {
        return 0;
    }

    return strcmp(activity, "mapping live filesystem metadata") == 0 ||
           strstr(activity, "metadata mapping") != NULL ||
           strstr(activity, "directory-index wake-up") != NULL;
}

static void build_working_line(char *out, size_t out_size, int blink_on)
{
    char suffix[128];
    char activity[96];
    char notice[192];
    char position_detail[128];
    char background_activity[32];
    char phase_text[128] = "";
    char notice_text[224] = "";
    char position_detail_text[160] = "";
    char speed_text[64];
    char eta_text[48] = "";
    char eta_rendered[96] = "";
    char status_text[160] = "";
    char stalled_text[32] = "";
    char budget_text[32] = "";
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
    int eta_phase;
    int load_eta_done;
    unsigned long long stalled_seconds;
    uint64_t displayed_bytes;
    uint64_t measured_bytes;
    unsigned long long eta_seconds = 0ULL;
    int has_eta_seconds = 0;
    double elapsed_seconds;
    double mib_per_sec = 0.0;
    double name_percent_per_min = 0.0;
    double fallback_mib_per_sec = 0.0;
    double recent_mib_per_sec = 0.0;
    double notice_until = 0.0;
    double last_progress_at = 0.0;
    double now_seconds = 0.0;
    unsigned long long budget_eta_seconds = 0ULL;
    LogTroubleBudgetState trouble_budget_state = LOG_TROUBLE_BUDGET_UNKNOWN;
    LogTroubleBudgetState validator_budget_state = LOG_TROUBLE_BUDGET_UNKNOWN;
    const char *working_label;
    int suppress_eta = 0;
    int metadata_busy = 0;

    if (out == NULL || out_size == 0) {
        return;
    }

    pthread_mutex_lock(&working_mutex);
    snprintf(suffix, sizeof(suffix), "%s", working_suffix);
    snprintf(activity, sizeof(activity), "%s", working_activity);
    snprintf(notice, sizeof(notice), "%s", working_notice);
    snprintf(
        position_detail,
        sizeof(position_detail),
        "%s",
        working_position_detail
    );
    snprintf(
        background_activity,
        sizeof(background_activity),
        "%s",
        working_background_activity
    );
    processed_bytes = working_processed_bytes;
    total_bytes = working_total_bytes;
    speed_base_bytes = working_speed_base_bytes;
    budget_base_bytes = working_budget_base_bytes;
    budget_penalty_bytes = working_budget_penalty_bytes;
    recovered_files = working_recovered_files;
    named_files = working_named_files;
    unident_files = working_unident_files;
    repair_pending_files = working_repair_pending_files;
    repair_queue_files = working_repair_queue_files;
    stalled_seconds = working_stalled_seconds;
    eta_phase = working_eta_phase;
    load_eta_done = working_load_eta_done;
    fallback_mib_per_sec = working_fallback_mib_per_sec;
    recent_mib_per_sec = working_recent_mib_per_sec;
    notice_until = working_notice_until;
    last_progress_at = working_last_progress_at;
    elapsed_seconds = elapsed_seconds_since_start() + working_elapsed_bias_seconds;
    pthread_mutex_unlock(&working_mutex);
    now_seconds = monotonic_seconds();

    displayed_bytes = processed_bytes;
    if (total_bytes > 0 && displayed_bytes > total_bytes) {
        displayed_bytes = total_bytes;
    }
    measured_bytes = displayed_bytes > speed_base_bytes ? displayed_bytes - speed_base_bytes : 0;

    if (recent_mib_per_sec > 0.0) {
        mib_per_sec = recent_mib_per_sec;
    } else if (fallback_mib_per_sec > 0.0) {
        mib_per_sec = fallback_mib_per_sec;
    } else if (elapsed_seconds > 0.0 && measured_bytes > 0) {
        mib_per_sec = ((double)measured_bytes / (1024.0 * 1024.0)) / elapsed_seconds;
    }
    working_calculate_budget_metrics(
        displayed_bytes,
        total_bytes,
        budget_base_bytes,
        budget_penalty_bytes,
        elapsed_seconds,
        recent_mib_per_sec,
        NULL,
        NULL,
        &budget_eta_seconds,
        NULL,
        &trouble_budget_state,
        &validator_budget_state
    );

    working_label = blink_on ? "Working..." : "          ";
    suppress_eta = strcmp(suffix, "name") == 0;
    metadata_busy = activity_is_live_metadata_busy(activity);

    if (activity[0] != '\0') {
        snprintf(
            phase_text,
            sizeof(phase_text),
            " phase=%s",
            display_activity_label(activity)
        );
    }
    if (position_detail[0] != '\0') {
        snprintf(
            position_detail_text,
            sizeof(position_detail_text),
            " %s",
            position_detail
        );
    }
    if (notice[0] != '\0' && notice_until > monotonic_seconds()) {
        snprintf(notice_text, sizeof(notice_text), " note=%s", notice);
    }

    if (strcmp(suffix, "name") == 0 &&
        total_bytes > 0 &&
        elapsed_seconds > 0.0 &&
        displayed_bytes > 0U) {
        name_percent_per_min =
            (((double)displayed_bytes * 100.0) / (double)total_bytes) /
            (elapsed_seconds / 60.0);
        if (name_percent_per_min >= 0.05) {
            snprintf(speed_text, sizeof(speed_text), " pace=%.2f%%/min", name_percent_per_min);
        } else {
            snprintf(speed_text, sizeof(speed_text), " pace=measuring");
        }
    } else if (metadata_busy &&
               eta_phase == 1 &&
               total_bytes > 0U &&
               displayed_bytes < total_bytes &&
               last_progress_at > 0.0 &&
               now_seconds > last_progress_at &&
               (now_seconds - last_progress_at) >= 8.0) {
        snprintf(speed_text, sizeof(speed_text), " speed=metadata");
    } else if (eta_phase == 1 &&
               total_bytes > 0U &&
               displayed_bytes < total_bytes &&
               last_progress_at > 0.0 &&
               now_seconds > last_progress_at &&
               (now_seconds - last_progress_at) >= 8.0) {
        snprintf(speed_text, sizeof(speed_text), " speed=stalled");
    } else if (mib_per_sec >= 0.05) {
        snprintf(speed_text, sizeof(speed_text), " speed=%.1f MiB/s", mib_per_sec);
    } else if (eta_phase == 0 || strstr(activity, "indexing ") != NULL) {
        snprintf(speed_text, sizeof(speed_text), " speed=priming");
    } else {
        snprintf(speed_text, sizeof(speed_text), " speed=measuring");
    }

    format_stalled_text(
        metadata_busy ? 0ULL : stalled_seconds,
        stalled_text,
        sizeof(stalled_text)
    );
    if (!metadata_busy &&
        (trouble_budget_state == LOG_TROUBLE_BUDGET_YELLOW ||
         trouble_budget_state == LOG_TROUBLE_BUDGET_RED)) {
        snprintf(
            budget_text,
            sizeof(budget_text),
            " budget=%s",
            log_trouble_budget_state_label(trouble_budget_state)
        );
    }

    if (recovered_files > 0 || named_files > 0 ||
        unident_files > 0 || repair_pending_files > 0 ||
        repair_queue_files > 0 || background_activity[0] != '\0' ||
        budget_text[0] != '\0' ||
        stalled_text[0] != '\0') {
        int written = snprintf(
            status_text,
            sizeof(status_text),
            " carved=%zu",
            recovered_files
        );

        if (written < 0) {
            status_text[0] = '\0';
        } else {
            size_t used = (size_t)written < sizeof(status_text) ? (size_t)written : sizeof(status_text) - 1U;

            if (named_files > 0U) {
                written = snprintf(
                    status_text + used,
                    sizeof(status_text) - used,
                    " named=%zu",
                    named_files
                );
                if (written > 0) {
                    used += (size_t)written < (sizeof(status_text) - used) ? (size_t)written : (sizeof(status_text) - used - 1U);
                }
            }
            if (unident_files > 0U) {
                written = snprintf(
                    status_text + used,
                    sizeof(status_text) - used,
                    " unident=%zu",
                    unident_files
                );
                if (written > 0) {
                    used += (size_t)written < (sizeof(status_text) - used) ? (size_t)written : (sizeof(status_text) - used - 1U);
                }
            }
            if (repair_queue_files > 0U) {
                written = snprintf(
                    status_text + used,
                    sizeof(status_text) - used,
                    " repair_queue=%zu",
                    repair_queue_files
                );
                if (written > 0) {
                    used += (size_t)written < (sizeof(status_text) - used) ? (size_t)written : (sizeof(status_text) - used - 1U);
                }
            }
            if (repair_pending_files > 0U) {
                written = snprintf(
                    status_text + used,
                    sizeof(status_text) - used,
                    " repairable_jpg=%zu",
                    repair_pending_files
                );
                if (written > 0) {
                    used += (size_t)written < (sizeof(status_text) - used) ? (size_t)written : (sizeof(status_text) - used - 1U);
                }
            }
            if (background_activity[0] != '\0') {
                written = snprintf(
                    status_text + used,
                    sizeof(status_text) - used,
                    " bg=%s",
                    background_activity
                );
                if (written > 0) {
                    used += (size_t)written < (sizeof(status_text) - used) ? (size_t)written : (sizeof(status_text) - used - 1U);
                }
            }
            if (stalled_text[0] != '\0') {
                written = snprintf(
                    status_text + used,
                    sizeof(status_text) - used,
                    "%s",
                    stalled_text
                );
                if (written > 0) {
                    used += (size_t)written < (sizeof(status_text) - used)
                                ? (size_t)written
                                : (sizeof(status_text) - used - 1U);
                }
            }
            if (budget_text[0] != '\0') {
                (void)snprintf(
                    status_text + used,
                    sizeof(status_text) - used,
                    "%s",
                    budget_text
                );
            }
        }
    }

    if (strcmp(suffix, "name") == 0 &&
        strstr(activity, "indexing name candidates") != NULL) {
        snprintf(
            out,
            out_size,
            "%s%s%s%s%s%s%s",
            working_label,
            suffix,
            position_detail_text,
            speed_text,
            status_text,
            notice_text,
            phase_text
        );
        return;
    }

    if (total_bytes > 0) {
        double percent = ((double)displayed_bytes * 100.0) / (double)total_bytes;
        char tail[160];
        char percent_text[32];
        char percent_rendered[80];

        if (!suppress_eta &&
            metadata_busy &&
            displayed_bytes < total_bytes) {
            snprintf(eta_text, sizeof(eta_text), "eta=metadata");
        } else if (!suppress_eta &&
            eta_phase == 1 &&
                   budget_eta_seconds > 0ULL &&
                   displayed_bytes < total_bytes) {
            eta_seconds = budget_eta_seconds;
            has_eta_seconds = 1;
        }

        if (has_eta_seconds) {
            format_eta_text(eta_seconds, eta_text, sizeof(eta_text));
        } else if (!suppress_eta && eta_phase == 0 && !load_eta_done) {
            snprintf(eta_text, sizeof(eta_text), "eta=preparing");
        } else if (!suppress_eta &&
                   displayed_bytes >= total_bytes &&
                   (unident_files > 0U || repair_queue_files > 0U)) {
            snprintf(eta_text, sizeof(eta_text), "eta=finalizing");
        } else if (!suppress_eta && displayed_bytes < total_bytes) {
            snprintf(eta_text, sizeof(eta_text), "eta=measuring");
        }

        if (eta_text[0] != '\0') {
            snprintf(
                eta_rendered,
                sizeof(eta_rendered),
                " %s%s%s",
                ANSI_FG_YELLOW_UNDERLINE,
                eta_text,
                ANSI_FG_WHITE_NO_UNDERLINE
            );
        }

        snprintf(
            tail,
            sizeof(tail),
            "%s%s%s%s%s",
            speed_text,
            eta_rendered,
            status_text,
            notice_text,
            phase_text
        );

        snprintf(
            percent_text,
            sizeof(percent_text),
            "%.1f%%",
            percent
        );
        if (strcmp(suffix, "name") == 0) {
            snprintf(
                percent_rendered,
                sizeof(percent_rendered),
                "%sfinal=%s%s",
                ANSI_FG_YELLOW_UNDERLINE,
                percent_text,
                ANSI_FG_WHITE_NO_UNDERLINE
            );
        } else {
            snprintf(
                percent_rendered,
                sizeof(percent_rendered),
                "%s%s%s",
                ANSI_FG_YELLOW_UNDERLINE,
                percent_text,
                ANSI_FG_WHITE_NO_UNDERLINE
            );
        }

        snprintf(
            out,
            out_size,
            "%s%s pos=%llu/%llu MiB%s %s%s",
            working_label,
            suffix,
            (unsigned long long)(displayed_bytes / (1024ULL * 1024ULL)),
            (unsigned long long)(total_bytes / (1024ULL * 1024ULL)),
            position_detail_text,
            percent_rendered,
            tail
        );
        return;
    }

    snprintf(
        out,
        out_size,
        "%s%s pos=%llu MiB%s%s%s%s",
        working_label,
        suffix,
        (unsigned long long)(displayed_bytes / (1024ULL * 1024ULL)),
        position_detail_text,
        speed_text,
        notice_text,
        phase_text
    );
}

static void log_message(FILE *stream, const char *prefix, const char *fmt, va_list args)
{
    pthread_mutex_lock(&working_mutex);
    if (working_running) {
        fprintf(
            stream,
            "\r%s%s%s\033[K",
            ANSI_RESET,
            current_background,
            current_color
        );
    }
    pthread_mutex_unlock(&working_mutex);

    fprintf(stream, "%s%s%s%s", ANSI_RESET, current_background, current_color, prefix);
    vfprintf(stream, fmt, args);
    fprintf(stream, "\033[K\n%s%s%s", ANSI_RESET, current_background, current_color);
    fflush(stream);
}

static void log_message_text(FILE *stream, const char *prefix, const char *message)
{
    pthread_mutex_lock(&working_mutex);
    if (working_running) {
        fprintf(
            stream,
            "\r%s%s%s\033[K",
            ANSI_RESET,
            current_background,
            current_color
        );
    }
    pthread_mutex_unlock(&working_mutex);

    fprintf(
        stream,
        "%s%s%s%s%s\033[K\n%s%s%s",
        ANSI_RESET,
        current_background,
        current_color,
        prefix,
        message != NULL ? message : "",
        ANSI_RESET,
        current_background,
        current_color
    );
    fflush(stream);
}

static unsigned long long log_path_hash_local(const char *text)
{
    unsigned long long hash = 1469598103934665603ULL;
    const unsigned char *cursor = (const unsigned char *)text;

    if (cursor == NULL) {
        return hash;
    }
    while (*cursor != '\0') {
        hash ^= (unsigned long long)(*cursor++);
        hash *= 1099511628211ULL;
    }
    return hash;
}

static int ensure_emergency_runtime_dir_local(void)
{
    struct stat st;

    if (stat("/tmp/carv_emergency_logs", &st) == 0) {
        return S_ISDIR(st.st_mode);
    }
    return mkdir("/tmp/carv_emergency_logs", 0700) == 0;
}

static void append_runtime_event_line_emergency(
    const char *original_path,
    const char *level,
    const char *message
)
{
    char emergency_path[256];
    struct stat st;
    int have_existing;
    FILE *file;
    time_t now;
    struct tm tm_local;
    char timestamp[32];
    unsigned long long hash;

    if (level == NULL || message == NULL || message[0] == '\0' ||
        !ensure_emergency_runtime_dir_local()) {
        return;
    }

    hash = log_path_hash_local(original_path);
    if (snprintf(
            emergency_path,
            sizeof(emergency_path),
            "/tmp/carv_emergency_logs/runtime_%016llx.log",
            hash) >= (int)sizeof(emergency_path)) {
        return;
    }

    have_existing = stat(emergency_path, &st) == 0 && st.st_size > 0;
    file = fopen(emergency_path, "a");
    if (file == NULL) {
        return;
    }

    if (!have_existing) {
        fprintf(
            file,
            "# Emergency Carv runtime event mirror\n# original_path=%s\n",
            original_path != NULL ? original_path : ""
        );
    }

    now = time(NULL);
    if (localtime_r(&now, &tm_local) != NULL) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_local);
    } else {
        snprintf(timestamp, sizeof(timestamp), "unknown-time");
    }
    fprintf(file, "%s [%s] %s\n", timestamp, level, message);
    fclose(file);

    if (!g_emergency_runtime_notice_printed) {
        g_emergency_runtime_notice_printed = 1;
        fprintf(
            stderr,
            "[ERROR] Runtime log could not be written to the output disk; mirroring emergency events to %s\n",
            emergency_path
        );
        fflush(stderr);
    }
}

static void append_runtime_event_line(const char *level, const char *message)
{
    char path[sizeof(g_runtime_event_path)];
    FILE *file;
    time_t now;
    struct tm tm_local;
    char timestamp[32];

    pthread_mutex_lock(&working_mutex);
    snprintf(path, sizeof(path), "%s", g_runtime_event_path);
    pthread_mutex_unlock(&working_mutex);

    if (path[0] == '\0' || level == NULL || message == NULL || message[0] == '\0') {
        return;
    }

    file = fopen(path, "a");
    if (file == NULL) {
        append_runtime_event_line_emergency(path, level, message);
        return;
    }

    now = time(NULL);
    if (localtime_r(&now, &tm_local) != NULL) {
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_local);
    } else {
        snprintf(timestamp, sizeof(timestamp), "unknown-time");
    }

    fprintf(file, "%s [%s] %s\n", timestamp, level, message);
    fclose(file);
}

static int capture_working_notice_message(const char *message)
{
    double now;

    if (message == NULL || message[0] == '\0' ||
        g_log_verbose ||
        !isatty(STDOUT_FILENO)) {
        return 0;
    }

    pthread_mutex_lock(&working_mutex);
    if (!working_running) {
        pthread_mutex_unlock(&working_mutex);
        return 0;
    }

    now = monotonic_seconds();
    snprintf(working_notice, sizeof(working_notice), "%s", message);
    working_notice_until = now + WORKING_NOTICE_TTL_SECONDS;
    pthread_mutex_unlock(&working_mutex);
    return 1;
}

static void *working_loop(void *arg)
{
    char line[512];
    unsigned int pulse = 0;

    (void)arg;

    {
        sigset_t blocked;

        sigemptyset(&blocked);
        sigaddset(&blocked, SIGINT);
        sigaddset(&blocked, SIGTERM);
        (void)pthread_sigmask(SIG_BLOCK, &blocked, NULL);
    }

    while (1) {
        pthread_mutex_lock(&working_mutex);
        if (!working_running) {
            pthread_mutex_unlock(&working_mutex);
            break;
        }
        pthread_mutex_unlock(&working_mutex);

        build_working_line(
            line,
            sizeof(line),
            !blink_enabled || ((pulse % 2U) == 0U)
        );
        clamp_line_to_terminal_width(line, sizeof(line));
        printf(
            "\r%s%s%s\033[K%s",
            ANSI_RESET,
            current_background,
            current_color,
            line
        );
        fflush(stdout);

        pulse++;
        sleep(1);
    }

    return NULL;
}

void log_start_working_indicator(void)
{
    pthread_mutex_lock(&working_mutex);
    working_running = 1;
    working_has_started = 1;
    clock_gettime(CLOCK_MONOTONIC, &working_started_at);
    working_reset_speed_history_locked();
    pthread_mutex_unlock(&working_mutex);

    pthread_create(&working_thread, NULL, working_loop, NULL);
}

void log_stop_working_indicator(void)
{
    pthread_mutex_lock(&working_mutex);
    if (!working_running) {
        pthread_mutex_unlock(&working_mutex);
        return;
    }

    working_running = 0;
    pthread_mutex_unlock(&working_mutex);

    pthread_join(working_thread, NULL);

    /* städa raden */
    pthread_mutex_lock(&working_mutex);
    working_processed_bytes = 0;
    working_total_bytes = 0;
    working_speed_base_bytes = 0;
    working_budget_base_bytes = 0;
    working_budget_penalty_bytes = 0;
    working_recovered_files = 0;
    working_named_files = 0;
    working_unident_files = 0;
    working_repair_pending_files = 0;
    working_repair_queue_files = 0;
    working_record_index_count = 0;
    working_range_index_count = 0;
    working_stalled_seconds = 0;
    working_background_activity[0] = '\0';
    working_reconcile_files_per_sec = 0.0;
    working_last_reconcile_rate_at = 0.0;
    working_eta_phase = 1;
    working_load_eta_done = 0;
    working_suffix[0] = '\0';
    working_activity[0] = '\0';
    working_has_started = 0;
    working_elapsed_bias_seconds = 0.0;
    working_last_speed_bytes = 0;
    working_last_speed_at = 0.0;
    working_last_progress_at = 0.0;
    working_fallback_mib_per_sec = 0.0;
    working_recent_mib_per_sec = 0.0;
    working_speed_sample_count = 0;
    working_speed_sample_next = 0;
    memset(working_speed_samples, 0, sizeof(working_speed_samples));
    working_notice[0] = '\0';
    working_position_detail[0] = '\0';
    working_notice_until = 0.0;
    pthread_mutex_unlock(&working_mutex);

    printf(
        "\r%s%s%s\033[K",
        ANSI_RESET,
        current_background,
        current_color
    );
    fflush(stdout);
}

/* ========================= API ========================= */

void log_set_working_suffix(const char *suffix)
{
    pthread_mutex_lock(&working_mutex);
    if (suffix == NULL) {
        working_suffix[0] = '\0';
        pthread_mutex_unlock(&working_mutex);
        return;
    }

    snprintf(working_suffix, sizeof(working_suffix), " %s", suffix);
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_activity(const char *activity)
{
    pthread_mutex_lock(&working_mutex);
    if (activity == NULL || activity[0] == '\0') {
        working_activity[0] = '\0';
        pthread_mutex_unlock(&working_mutex);
        return;
    }

    snprintf(working_activity, sizeof(working_activity), "%s", activity);
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_position_detail(const char *detail)
{
    pthread_mutex_lock(&working_mutex);
    if (detail == NULL || detail[0] == '\0') {
        working_position_detail[0] = '\0';
        pthread_mutex_unlock(&working_mutex);
        return;
    }

    snprintf(working_position_detail, sizeof(working_position_detail), "%s", detail);
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_progress(uint64_t processed_bytes, uint64_t total_bytes)
{
    double now = monotonic_seconds();

    pthread_mutex_lock(&working_mutex);
    if (processed_bytes == 0U && total_bytes == 0U) {
        working_processed_bytes = 0U;
        working_total_bytes = 0U;
        pthread_mutex_unlock(&working_mutex);
        return;
    }

    if (processed_bytes > working_processed_bytes) {
        working_last_progress_at = now;
        if (working_last_speed_at > 0.0 &&
            processed_bytes > working_last_speed_bytes &&
            now > working_last_speed_at) {
            double delta_seconds = now - working_last_speed_at;
            uint64_t delta_bytes = processed_bytes - working_last_speed_bytes;
            if (delta_seconds >= WORKING_SPEED_MIN_INTERVAL_SECONDS ||
                delta_bytes >= WORKING_SPEED_MIN_DELTA_BYTES) {
                double instant_mib_per_sec =
                    ((double)delta_bytes / (1024.0 * 1024.0)) / delta_seconds;
                int should_commit_segment = 0;

                if (working_fallback_mib_per_sec <= 0.0) {
                    working_fallback_mib_per_sec = instant_mib_per_sec;
                } else {
                    working_fallback_mib_per_sec =
                        (working_fallback_mib_per_sec * 0.8) +
                        (instant_mib_per_sec * 0.2);
                }

                if (delta_bytes >= WORKING_SPEED_SEGMENT_TARGET_BYTES ||
                    delta_seconds >= WORKING_SPEED_SEGMENT_MAX_SECONDS) {
                    should_commit_segment = 1;
                }

                if (should_commit_segment) {
                    working_append_speed_sample_locked(instant_mib_per_sec);
                    working_last_speed_bytes = processed_bytes;
                    working_last_speed_at = now;
                } else if (working_recent_mib_per_sec <= 0.0 ||
                           working_speed_sample_count < WORKING_SPEED_MIN_MEDIAN_SAMPLES) {
                    working_recent_mib_per_sec = working_fallback_mib_per_sec;
                }
            }
        }
    }

    if (processed_bytes == 0 || processed_bytes > working_processed_bytes) {
        working_processed_bytes = processed_bytes;
    }

    if (total_bytes > 0) {
        working_total_bytes = total_bytes;
    }
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_speed_base(uint64_t base_bytes)
{
    pthread_mutex_lock(&working_mutex);
    working_speed_base_bytes = base_bytes;
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_budget_base(uint64_t base_bytes)
{
    pthread_mutex_lock(&working_mutex);
    working_budget_base_bytes = base_bytes;
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_budget_penalty(uint64_t penalty_bytes)
{
    pthread_mutex_lock(&working_mutex);
    working_budget_penalty_bytes = penalty_bytes;
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_elapsed_bias(double seconds)
{
    pthread_mutex_lock(&working_mutex);
    working_elapsed_bias_seconds = seconds > 0.0 ? seconds : 0.0;
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_recovered_files(size_t recovered_files)
{
    pthread_mutex_lock(&working_mutex);
    working_recovered_files = recovered_files;
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_named_files(size_t named_files)
{
    double now = monotonic_seconds();

    pthread_mutex_lock(&working_mutex);
    if (named_files > working_named_files) {
        size_t delta_files = named_files - working_named_files;

        if (working_last_reconcile_rate_at > 0.0 &&
            now > working_last_reconcile_rate_at) {
            double delta_seconds = now - working_last_reconcile_rate_at;

            if (delta_seconds >= 0.25) {
                double current_rate = (double)delta_files / delta_seconds;

                if (working_reconcile_files_per_sec <= 0.0) {
                    working_reconcile_files_per_sec = current_rate;
                } else {
                    working_reconcile_files_per_sec =
                        (working_reconcile_files_per_sec * 0.8) +
                        (current_rate * 0.2);
                }
            }
        }
        working_last_reconcile_rate_at = now;
    } else if (working_last_reconcile_rate_at <= 0.0) {
        working_last_reconcile_rate_at = now;
    }

    working_named_files = named_files;
    pthread_mutex_unlock(&working_mutex);
}

void log_set_working_queue_stats(
    size_t unident_files,
    size_t repair_pending_files,
    size_t repair_queue_files,
    size_t record_index_count,
    size_t range_index_count,
    unsigned long long stalled_seconds,
    const char *background_activity
)
{
    pthread_mutex_lock(&working_mutex);
    working_unident_files = unident_files;
    working_repair_pending_files = repair_pending_files;
    working_repair_queue_files = repair_queue_files;
    working_record_index_count = record_index_count;
    working_range_index_count = range_index_count;
    working_stalled_seconds = stalled_seconds;
    if (background_activity != NULL && background_activity[0] != '\0') {
        snprintf(
            working_background_activity,
            sizeof(working_background_activity),
            "%s",
            background_activity
        );
    } else {
        working_background_activity[0] = '\0';
    }
    pthread_mutex_unlock(&working_mutex);
}

void log_set_eta_phase_load(void)
{
    pthread_mutex_lock(&working_mutex);
    working_eta_phase = 0;
    working_load_eta_done = 0;
    pthread_mutex_unlock(&working_mutex);
}

void log_set_eta_phase_scan(void)
{
    pthread_mutex_lock(&working_mutex);
    working_eta_phase = 1;
    working_load_eta_done = 1;
    if (clock_gettime(CLOCK_MONOTONIC, &working_started_at) == 0) {
        working_has_started = 1;
    }
    working_last_progress_at = monotonic_seconds();
    working_reset_speed_history_locked();
    pthread_mutex_unlock(&working_mutex);
}

void log_mark_load_eta_done(void)
{
    pthread_mutex_lock(&working_mutex);
    working_load_eta_done = 1;
    pthread_mutex_unlock(&working_mutex);
}

int log_get_working_snapshot(LogWorkingSnapshot *out_snapshot)
{
    LogWorkingSnapshot snapshot = {0};
    LogTroubleBudgetState trouble_budget_state = LOG_TROUBLE_BUDGET_UNKNOWN;
    LogTroubleBudgetState validator_budget_state = LOG_TROUBLE_BUDGET_UNKNOWN;

    if (out_snapshot == NULL) {
        return 0;
    }

    pthread_mutex_lock(&working_mutex);
    snapshot.processed_bytes = working_processed_bytes;
    snapshot.total_bytes = working_total_bytes;
    snapshot.speed_base_bytes = working_speed_base_bytes;
    snapshot.budget_base_bytes = working_budget_base_bytes;
    snapshot.budget_penalty_bytes = working_budget_penalty_bytes;
    snapshot.recovered_files = working_recovered_files;
    snapshot.named_files = working_named_files;
    snapshot.unident_files = working_unident_files;
    snapshot.repair_pending_files = working_repair_pending_files;
    snapshot.repair_queue_files = working_repair_queue_files;
    snapshot.record_index_count = working_record_index_count;
    snapshot.range_index_count = working_range_index_count;
    snapshot.stalled_seconds = working_stalled_seconds;
    snapshot.elapsed_seconds = elapsed_seconds_since_start();
    snapshot.budget_elapsed_seconds =
        snapshot.elapsed_seconds + working_elapsed_bias_seconds;
    snapshot.recent_mib_per_sec = working_recent_mib_per_sec;
    snapshot.eta_phase = working_eta_phase;
    snapshot.load_eta_done = working_load_eta_done;
    snapshot.working_running = working_running;
    snapshot.working_has_started = working_has_started;
    snapshot.target_mib_per_sec =
        working_target_throughput_mib_per_sec > 0.0
            ? working_target_throughput_mib_per_sec
            : WORKING_TARGET_THROUGHPUT_MIB_PER_SEC;
    working_calculate_budget_metrics(
        snapshot.processed_bytes,
        snapshot.total_bytes,
        snapshot.budget_base_bytes,
        snapshot.budget_penalty_bytes,
        snapshot.budget_elapsed_seconds,
        snapshot.recent_mib_per_sec,
        &snapshot.nominal_total_seconds,
        &snapshot.nominal_remaining_seconds,
        &snapshot.budget_eta_seconds,
        &snapshot.schedule_delta_seconds,
        &trouble_budget_state,
        &validator_budget_state
    );
    snapshot.trouble_budget_state = (int)trouble_budget_state;
    snapshot.validator_budget_state = (int)validator_budget_state;
    if (snapshot.eta_phase == 1 &&
        snapshot.budget_eta_seconds > 0ULL &&
        snapshot.processed_bytes < snapshot.total_bytes) {
        snapshot.eta_seconds = snapshot.budget_eta_seconds;
    } else {
        snapshot.eta_seconds = 0ULL;
    }
    snprintf(snapshot.activity, sizeof(snapshot.activity), "%s", working_activity);
    snprintf(
        snapshot.background_activity,
        sizeof(snapshot.background_activity),
        "%s",
        working_background_activity
    );
    pthread_mutex_unlock(&working_mutex);

    *out_snapshot = snapshot;
    return 1;
}

double log_get_target_throughput_mib_per_sec(void)
{
    double target_mib_per_sec;

    pthread_mutex_lock(&working_mutex);
    target_mib_per_sec = working_target_throughput_mib_per_sec;
    pthread_mutex_unlock(&working_mutex);
    return target_mib_per_sec > 0.0
        ? target_mib_per_sec
        : WORKING_TARGET_THROUGHPUT_MIB_PER_SEC;
}

void log_set_target_throughput_mib_per_sec(double mib_per_sec)
{
    if (mib_per_sec <= 0.0) {
        mib_per_sec = WORKING_TARGET_THROUGHPUT_MIB_PER_SEC;
    }

    pthread_mutex_lock(&working_mutex);
    working_target_throughput_mib_per_sec = mib_per_sec;
    pthread_mutex_unlock(&working_mutex);
}

const char *log_target_throughput_profile_label(double target_mib_per_sec)
{
    if (target_mib_per_sec >= 30.0) {
        return "fast";
    }
    if (target_mib_per_sec <= 8.0) {
        return "slow";
    }
    return "normal";
}

const char *log_target_throughput_profile_ui_label(double target_mib_per_sec)
{
    if (target_mib_per_sec >= 30.0) {
        return "fast";
    }
    if (target_mib_per_sec <= 8.0) {
        return "slow";
    }
    return "normal";
}

LogTroubleBudgetState log_get_trouble_budget_state(void)
{
    LogTroubleBudgetState state = LOG_TROUBLE_BUDGET_UNKNOWN;
    LogTroubleBudgetState validator_state = LOG_TROUBLE_BUDGET_UNKNOWN;
    double elapsed_seconds;

    pthread_mutex_lock(&working_mutex);
    elapsed_seconds = elapsed_seconds_since_start() + working_elapsed_bias_seconds;
    working_calculate_budget_metrics(
        working_processed_bytes,
        working_total_bytes,
        working_budget_base_bytes,
        working_budget_penalty_bytes,
        elapsed_seconds,
        working_recent_mib_per_sec,
        NULL,
        NULL,
        NULL,
        NULL,
        &state,
        &validator_state
    );
    pthread_mutex_unlock(&working_mutex);
    return state;
}

LogTroubleBudgetState log_get_validator_budget_state(void)
{
    LogTroubleBudgetState state = LOG_TROUBLE_BUDGET_UNKNOWN;
    LogTroubleBudgetState validator_state = LOG_TROUBLE_BUDGET_UNKNOWN;
    double elapsed_seconds;

    pthread_mutex_lock(&working_mutex);
    elapsed_seconds = elapsed_seconds_since_start() + working_elapsed_bias_seconds;
    working_calculate_budget_metrics(
        working_processed_bytes,
        working_total_bytes,
        working_budget_base_bytes,
        working_budget_penalty_bytes,
        elapsed_seconds,
        working_recent_mib_per_sec,
        NULL,
        NULL,
        NULL,
        NULL,
        &state,
        &validator_state
    );
    pthread_mutex_unlock(&working_mutex);
    return validator_state;
}

void log_set_running_mode(void)
{
    if (isatty(STDOUT_FILENO) && !g_dynamic_terminal_background_active) {
        printf("%s", OSC_SET_BG_BLUE);
        g_dynamic_terminal_background_active = 1;
    }
    current_color = ANSI_FG_WHITE;
    current_background = ANSI_BG_BLUE;
    printf("%s%s%s\033[2J\033[H", ANSI_RESET, current_background, current_color);
    fflush(stdout);
}

void log_set_done_mode(void)
{
    if (isatty(STDOUT_FILENO) && !g_dynamic_terminal_background_active) {
        printf("%s", OSC_SET_BG_BLUE);
        g_dynamic_terminal_background_active = 1;
    }
    current_color = ANSI_FG_GREEN;
    current_background = ANSI_BG_BLUE;
    printf("%s%s%s\033[2J\033[H", ANSI_RESET, current_background, current_color);
    fflush(stdout);
}

void log_reset_terminal_mode(void)
{
    if (isatty(STDOUT_FILENO) && g_dynamic_terminal_background_active) {
        printf("%s", OSC_RESET_BG);
        g_dynamic_terminal_background_active = 0;
    }
    current_color = ANSI_FG_DEFAULT;
    current_background = ANSI_BG_DEFAULT;
    printf("%s", ANSI_RESET);
    fflush(stdout);
}

void log_disable_blink(void)
{
    blink_enabled = 0;
}

void log_info(const char *fmt, ...)
{
    va_list args;
    char message[192];

    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    if (capture_working_notice_message(message)) {
        return;
    }

    va_start(args, fmt);
    log_message(stdout, "\n[INFO] ", fmt, args);
    va_end(args);
}

void log_error(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    log_message(stderr, "[ERROR] ", fmt, args);
    va_end(args);
}

void log_set_runtime_event_path(const char *path)
{
    pthread_mutex_lock(&working_mutex);
    if (path == NULL || path[0] == '\0') {
        g_runtime_event_path[0] = '\0';
    } else {
        snprintf(g_runtime_event_path, sizeof(g_runtime_event_path), "%s", path);
    }
    pthread_mutex_unlock(&working_mutex);
}

void log_runtime_event_info(const char *fmt, ...)
{
    va_list args;
    char message[512];

    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    append_runtime_event_line("INFO", message);
    if (capture_working_notice_message(message)) {
        return;
    }
    log_message_text(stdout, "\n[INFO] ", message);
}

void log_runtime_event_verbose(const char *fmt, ...)
{
    va_list args;
    char message[512];

    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    append_runtime_event_line("INFO", message);
    if (!g_log_verbose) {
        return;
    }
    if (capture_working_notice_message(message)) {
        return;
    }
    log_message_text(stdout, "\n[INFO] ", message);
}

void log_runtime_event_error(const char *fmt, ...)
{
    va_list args;
    char message[512];

    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    append_runtime_event_line("ERROR", message);
    log_message_text(stderr, "[ERROR] ", message);
}

void log_set_verbose(int enabled)
{
    g_log_verbose = enabled != 0;
}

int log_is_verbose(void)
{
    return g_log_verbose;
}

void log_verbose(const char *fmt, ...)
{
    va_list args;

    if (!g_log_verbose) {
        return;
    }

    va_start(args, fmt);
    log_message(stdout, "\n[VERBOSE] ", fmt, args);
    va_end(args);
}
