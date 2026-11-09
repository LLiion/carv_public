#ifndef MFTPROBE_FORMAT_JPEG_RECOVERY_H
#define MFTPROBE_FORMAT_JPEG_RECOVERY_H

#include "mftprobe_engine_types.h"

typedef struct MftprobeJpegRecoveryOps {
    int (*ensure_parent_dirs)(const char *path);
    size_t (*read_with_fallback)(
        int image_fd,
        unsigned char *buffer,
        uint64_t offset,
        size_t want,
        uint64_t *failed_at
    );
    int (*recovery_target_is_partial)(const RecoveryTarget *target);
    void (*recovery_validator_reset)(RecoveryTarget *target);
    int (*recovery_validator_start)(
        RecoveryTarget *target,
        const unsigned char *buffer,
        size_t len,
        size_t *skip_bytes
    );
    void (*recovery_validator_update)(
        RecoveryTarget *target,
        const unsigned char *buffer,
        size_t len
    );
    int (*recovery_validator_finish)(RecoveryTarget *target);
    int (*stop_requested)(void);
    size_t read_size;
} MftprobeJpegRecoveryOps;

int mftprobe_direct_recover_jpeg_target(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    const MftprobeJpegRecoveryOps *ops
);

int mftprobe_direct_recover_jpeg_target_replay(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    const MftprobeJpegRecoveryOps *ops
);

#endif
