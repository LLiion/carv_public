#ifndef MFTPROBE_FORMAT_REGISTRY_H
#define MFTPROBE_FORMAT_REGISTRY_H

#include "mftprobe_engine_types.h"

const RecoveryOrder *mftprobe_recovery_default_order(void);

int mftprobe_recovery_order_load_common_profiles(Config *config, const char *db_path);

const RecoveryFormat *mftprobe_entry_selected_format(
    const Config *config,
    const MftEntry *entry
);

#endif
