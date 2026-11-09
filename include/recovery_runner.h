#ifndef RECOVERY_RUNNER_H
#define RECOVERY_RUNNER_H

#include "mftprobe_engine_types.h"

#include <stddef.h>
#include <stdint.h>

size_t recovery_runner_default_read_size(void);
int recovery_runner_ensure_parent_dirs(const char *path);
size_t recovery_runner_read_with_fallback(
    int image_fd,
    unsigned char *buffer,
    uint64_t offset,
    size_t want,
    uint64_t *failed_at
);
int recovery_runner_recover_target_fd(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size,
    int (*stop_requested)(void)
);
int recovery_runner_recover_target_best_effort_fd(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size,
    int (*stop_requested)(void)
);
int recovery_runner_recover_target_replay_fd(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size,
    int (*stop_requested)(void)
);
int recovery_runner_target_should_skip_image_fd(
    int image_fd,
    const RecoveryTarget *target,
    unsigned char *buffer,
    size_t buffer_size
);
const char *recovery_runner_failure_class(const char *reason);

#endif
