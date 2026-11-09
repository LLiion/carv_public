#ifndef CARVER_DDRESCUE_SUPERVISOR_H
#define CARVER_DDRESCUE_SUPERVISOR_H

#include <sys/types.h>

typedef enum DdrescueSupervisorResult {
    DDRESCUE_SUPERVISOR_ACTIVE = 0,
    DDRESCUE_SUPERVISOR_SUSPECTED_STALL = 1,
    DDRESCUE_SUPERVISOR_KERNEL_IO_HANG = 2
} DdrescueSupervisorResult;

typedef struct DdrescueSupervisor {
    double started_at;
    double last_progress_at;
    double d_state_started_at;
    double kernel_fault_at;
    double kernel_io_context_at;
    long long map_size;
    long map_mtime_seconds;
    long map_mtime_nanoseconds;
    int map_observed;
    int kernel_fault_seen;
    int kernel_io_context_seen;
    int kernel_fault_confirmed;
    int kmsg_fd;
} DdrescueSupervisor;

void ddrescue_supervisor_init(
    DdrescueSupervisor *supervisor,
    double now
);

void ddrescue_supervisor_close(DdrescueSupervisor *supervisor);

/* Exposed separately so the fault/context pairing can be tested without
 * requiring a real kernel crash. Production code normally calls poll(). */
void ddrescue_supervisor_note_kernel_message(
    DdrescueSupervisor *supervisor,
    const char *message,
    double now
);

DdrescueSupervisorResult ddrescue_supervisor_observe(
    DdrescueSupervisor *supervisor,
    char process_state,
    int progress_changed,
    double now
);

DdrescueSupervisorResult ddrescue_supervisor_poll(
    DdrescueSupervisor *supervisor,
    pid_t process_id,
    const char *map_path,
    double now,
    char *out_process_state
);

double ddrescue_supervisor_no_progress_seconds(
    const DdrescueSupervisor *supervisor,
    double now
);

double ddrescue_supervisor_blocked_seconds(
    const DdrescueSupervisor *supervisor,
    double now
);

int ddrescue_supervisor_kernel_fault_confirmed(
    const DdrescueSupervisor *supervisor
);

#endif
