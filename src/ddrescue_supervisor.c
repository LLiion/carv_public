#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE 1
#endif
#define _POSIX_C_SOURCE 200809L

#include "ddrescue_supervisor.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DDRESCUE_D_STATE_WARNING_SECONDS 60.0
#define DDRESCUE_CONFIRMED_D_STATE_SECONDS 3.0
#define DDRESCUE_CONFIRMED_NO_PROGRESS_SECONDS 10.0
#define DDRESCUE_KERNEL_MESSAGE_PAIR_SECONDS 30.0

static int ascii_contains_case_insensitive(
    const char *text,
    const char *needle
)
{
    size_t needle_length;
    const unsigned char *cursor;

    if (text == NULL || needle == NULL || needle[0] == '\0') {
        return 0;
    }
    needle_length = strlen(needle);
    for (cursor = (const unsigned char *)text; *cursor != '\0'; cursor++) {
        size_t index;

        for (index = 0U; index < needle_length; index++) {
            unsigned char actual = cursor[index];
            unsigned char expected = (unsigned char)needle[index];

            if (actual == '\0' ||
                tolower(actual) != tolower(expected)) {
                break;
            }
        }
        if (index == needle_length) {
            return 1;
        }
    }
    return 0;
}

static int kernel_message_is_severe_fault(const char *message)
{
    static const char *const markers[] = {
        "BUG: unable to handle",
        "Oops:",
        "general protection fault",
        "kernel BUG at",
        "Kernel panic",
        "Unable to handle kernel",
    };
    size_t index;

    for (index = 0U; index < sizeof(markers) / sizeof(markers[0]); index++) {
        if (ascii_contains_case_insensitive(message, markers[index])) {
            return 1;
        }
    }
    return 0;
}

static int kernel_message_has_storage_io_context(const char *message)
{
    static const char *const markers[] = {
        "iommu_dma_map_sg",
        "usb-storage",
        "usb_storage",
        "usb_stor_",
        "usb_hcd_",
        "xhci_",
        "scsi_dispatch_cmd",
        "blk_mq_",
        "nvme_",
        "ata_scsi_",
    };
    size_t index;

    for (index = 0U; index < sizeof(markers) / sizeof(markers[0]); index++) {
        if (ascii_contains_case_insensitive(message, markers[index])) {
            return 1;
        }
    }
    return 0;
}

static void maybe_confirm_kernel_fault(
    DdrescueSupervisor *supervisor
)
{
    double difference;

    if (supervisor == NULL ||
        !supervisor->kernel_fault_seen ||
        !supervisor->kernel_io_context_seen) {
        return;
    }
    difference = supervisor->kernel_fault_at - supervisor->kernel_io_context_at;
    if (difference < 0.0) {
        difference = -difference;
    }
    if (difference <= DDRESCUE_KERNEL_MESSAGE_PAIR_SECONDS) {
        supervisor->kernel_fault_confirmed = 1;
    }
}

void ddrescue_supervisor_init(
    DdrescueSupervisor *supervisor,
    double now
)
{
    if (supervisor == NULL) {
        return;
    }
    memset(supervisor, 0, sizeof(*supervisor));
    supervisor->started_at = now;
    supervisor->last_progress_at = now;
    supervisor->kmsg_fd = -1;
#ifdef __linux__
    supervisor->kmsg_fd = open(
        "/dev/kmsg",
        O_RDONLY | O_NONBLOCK | O_CLOEXEC
    );
    if (supervisor->kmsg_fd >= 0) {
        /* Only faults emitted after this ddrescue child starts are relevant. */
        (void)lseek(supervisor->kmsg_fd, 0, SEEK_END);
    }
#endif
}

void ddrescue_supervisor_close(DdrescueSupervisor *supervisor)
{
    if (supervisor == NULL) {
        return;
    }
    if (supervisor->kmsg_fd >= 0) {
        (void)close(supervisor->kmsg_fd);
        supervisor->kmsg_fd = -1;
    }
}

void ddrescue_supervisor_note_kernel_message(
    DdrescueSupervisor *supervisor,
    const char *message,
    double now
)
{
    if (supervisor == NULL || message == NULL) {
        return;
    }
    if (kernel_message_is_severe_fault(message)) {
        supervisor->kernel_fault_seen = 1;
        supervisor->kernel_fault_at = now;
    }
    if (kernel_message_has_storage_io_context(message)) {
        supervisor->kernel_io_context_seen = 1;
        supervisor->kernel_io_context_at = now;
    }
    maybe_confirm_kernel_fault(supervisor);
}

static void drain_kernel_messages(
    DdrescueSupervisor *supervisor,
    double now
)
{
#ifdef __linux__
    char buffer[4096];
    ssize_t amount;

    if (supervisor == NULL || supervisor->kmsg_fd < 0) {
        return;
    }
    for (;;) {
        amount = read(supervisor->kmsg_fd, buffer, sizeof(buffer) - 1U);
        if (amount > 0) {
            char *message;

            buffer[amount] = '\0';
            message = strchr(buffer, ';');
            ddrescue_supervisor_note_kernel_message(
                supervisor,
                message != NULL ? message + 1 : buffer,
                now
            );
            continue;
        }
        if (amount < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
#else
    (void)supervisor;
    (void)now;
#endif
}

static int read_linux_process_state(
    pid_t process_id,
    char *out_state
)
{
#ifdef __linux__
    char path[64];
    char buffer[512];
    FILE *file;
    char *close_paren;

    if (process_id <= 0 || out_state == NULL) {
        return 0;
    }
    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)process_id);
    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    if (fgets(buffer, (int)sizeof(buffer), file) == NULL) {
        fclose(file);
        return 0;
    }
    fclose(file);
    close_paren = strrchr(buffer, ')');
    if (close_paren == NULL || close_paren[1] != ' ' || close_paren[2] == '\0') {
        return 0;
    }
    *out_state = close_paren[2];
    return 1;
#else
    (void)process_id;
    (void)out_state;
    return 0;
#endif
}

static int map_progress_changed(
    DdrescueSupervisor *supervisor,
    const char *map_path
)
{
    struct stat state;
    long seconds;
    long nanoseconds;
    int changed;

    if (supervisor == NULL || map_path == NULL ||
        stat(map_path, &state) != 0) {
        return 0;
    }
#ifdef __APPLE__
    seconds = state.st_mtimespec.tv_sec;
    nanoseconds = state.st_mtimespec.tv_nsec;
#else
    seconds = state.st_mtim.tv_sec;
    nanoseconds = state.st_mtim.tv_nsec;
#endif
    changed = supervisor->map_observed &&
        (supervisor->map_size != (long long)state.st_size ||
         supervisor->map_mtime_seconds != seconds ||
         supervisor->map_mtime_nanoseconds != nanoseconds);
    supervisor->map_observed = 1;
    supervisor->map_size = (long long)state.st_size;
    supervisor->map_mtime_seconds = seconds;
    supervisor->map_mtime_nanoseconds = nanoseconds;
    return changed;
}

DdrescueSupervisorResult ddrescue_supervisor_observe(
    DdrescueSupervisor *supervisor,
    char process_state,
    int progress_changed,
    double now
)
{
    double no_progress_seconds;
    double blocked_seconds;

    if (supervisor == NULL) {
        return DDRESCUE_SUPERVISOR_ACTIVE;
    }
    if (progress_changed) {
        supervisor->last_progress_at = now;
    }
    if (process_state == 'D') {
        if (supervisor->d_state_started_at <= 0.0) {
            supervisor->d_state_started_at = now;
        }
    } else {
        supervisor->d_state_started_at = 0.0;
        return DDRESCUE_SUPERVISOR_ACTIVE;
    }

    no_progress_seconds = now - supervisor->last_progress_at;
    blocked_seconds = now - supervisor->d_state_started_at;
    if (supervisor->kernel_fault_confirmed &&
        blocked_seconds >= DDRESCUE_CONFIRMED_D_STATE_SECONDS &&
        no_progress_seconds >= DDRESCUE_CONFIRMED_NO_PROGRESS_SECONDS) {
        return DDRESCUE_SUPERVISOR_KERNEL_IO_HANG;
    }
    if (blocked_seconds >= DDRESCUE_D_STATE_WARNING_SECONDS &&
        no_progress_seconds >= DDRESCUE_D_STATE_WARNING_SECONDS) {
        return DDRESCUE_SUPERVISOR_SUSPECTED_STALL;
    }
    return DDRESCUE_SUPERVISOR_ACTIVE;
}

DdrescueSupervisorResult ddrescue_supervisor_poll(
    DdrescueSupervisor *supervisor,
    pid_t process_id,
    const char *map_path,
    double now,
    char *out_process_state
)
{
    char process_state = '?';
    int progress_changed;

    if (supervisor == NULL) {
        return DDRESCUE_SUPERVISOR_ACTIVE;
    }
    drain_kernel_messages(supervisor, now);
    (void)read_linux_process_state(process_id, &process_state);
    progress_changed = map_progress_changed(supervisor, map_path);
    if (out_process_state != NULL) {
        *out_process_state = process_state;
    }
    return ddrescue_supervisor_observe(
        supervisor,
        process_state,
        progress_changed,
        now
    );
}

double ddrescue_supervisor_no_progress_seconds(
    const DdrescueSupervisor *supervisor,
    double now
)
{
    if (supervisor == NULL || now <= supervisor->last_progress_at) {
        return 0.0;
    }
    return now - supervisor->last_progress_at;
}

double ddrescue_supervisor_blocked_seconds(
    const DdrescueSupervisor *supervisor,
    double now
)
{
    if (supervisor == NULL || supervisor->d_state_started_at <= 0.0 ||
        now <= supervisor->d_state_started_at) {
        return 0.0;
    }
    return now - supervisor->d_state_started_at;
}

int ddrescue_supervisor_kernel_fault_confirmed(
    const DdrescueSupervisor *supervisor
)
{
    return supervisor != NULL && supervisor->kernel_fault_confirmed;
}
