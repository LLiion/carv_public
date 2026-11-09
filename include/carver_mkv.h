#ifndef CARVER_MKV_H
#define CARVER_MKV_H

#include <stddef.h>

#include "carver_audit.h"
#include "config.h"
#include "reader.h"

int carver_mkv_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

void carver_mkv_reset_last_audit(void);
void carver_mkv_get_last_audit(CarverAuditReport *out);

#endif
