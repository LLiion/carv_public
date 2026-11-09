#ifndef CARVER_MPEG_PS_H
#define CARVER_MPEG_PS_H

#include <stddef.h>

#include "carver_audit.h"
#include "config.h"
#include "reader.h"

int carver_mpeg_ps_find_pack_start_near(
    const Reader *reader,
    size_t match_offset,
    size_t *out_start_offset
);

int carver_mpeg_ps_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    const char *extension,
    size_t *resume_offset
);

void carver_mpeg_ps_reset_last_audit(void);
void carver_mpeg_ps_get_last_audit(CarverAuditReport *out);

#endif
