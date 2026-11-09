#ifndef RAW_ALL_SELECTION_H
#define RAW_ALL_SELECTION_H

#include "config.h"

#include <stddef.h>
#include <stdint.h>

int raw_all_selection_requires_additive(
    const AppConfig *config,
    const char *current_active_formats,
    char *reason,
    size_t reason_size
);

void raw_all_selection_mark_completed(
    const AppConfig *config,
    const char *active_formats_csv,
    uint32_t active_category_mask
);

#endif
