#ifndef MFTPROBE_FORMAT_API_H
#define MFTPROBE_FORMAT_API_H

#include "mftprobe_engine_types.h"

typedef enum MftprobeFormatRecoverStatus {
    MFTPROBE_FORMAT_RECOVER_NOT_HANDLED = 0,
    MFTPROBE_FORMAT_RECOVER_SUCCESS = 1,
    MFTPROBE_FORMAT_RECOVER_FAILED = -1
} MftprobeFormatRecoverStatus;

typedef struct MftprobeFormatIoOps {
    int (*ensure_parent_dirs)(const char *path);
    size_t (*read_with_fallback)(
        int image_fd,
        unsigned char *buffer,
        uint64_t offset,
        size_t want,
        uint64_t *failed_at
    );
    int (*stop_requested)(void);
    size_t read_size;
} MftprobeFormatIoOps;

typedef struct MftprobeFormatSelection {
    const char *categories_csv;
    const char *formats_csv;
    const char *dev_format;
} MftprobeFormatSelection;

const RecoveryOrder *mftprobe_format_default_order(void);

int mftprobe_format_load_common_profiles(Config *config, const char *db_path);

int mftprobe_format_configure_active_order(
    Config *config,
    const MftprobeFormatSelection *selection,
    char *error_text,
    size_t error_text_size
);

void mftprobe_format_describe_active_order(
    const Config *config,
    char *out,
    size_t out_size
);

const RecoveryFormat *mftprobe_format_select_for_entry(
    const Config *config,
    const MftEntry *entry
);

int mftprobe_format_allows_partial_target(
    const RecoveryFormat *format,
    uint64_t available_bytes
);

int mftprobe_format_target_allows_partial_bytes(
    const RecoveryTarget *target,
    uint64_t available_bytes
);

int mftprobe_format_target_is_partial(const RecoveryTarget *target);

void mftprobe_format_validator_reset(RecoveryTarget *target);

int mftprobe_format_validator_start(
    RecoveryTarget *target,
    const unsigned char *buffer,
    size_t len,
    size_t *skip_bytes
);

void mftprobe_format_validator_update(
    RecoveryTarget *target,
    const unsigned char *buffer,
    size_t len
);

int mftprobe_format_validator_finish(RecoveryTarget *target);

MftprobeFormatRecoverStatus mftprobe_format_direct_recover(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    const MftprobeFormatIoOps *io_ops
);

#endif
