/*
 * carver_mov.h
 * Streams MOV/MP4-style file recovery by parsing top-level atoms.
 */

#ifndef CARVER_MOV_H
#define CARVER_MOV_H

#include <stddef.h>

#include "carver_audit.h"
#include "config.h"
#include "reader.h"
#include "signature_types.h"

int carver_mov_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

void carver_mov_get_last_audit(CarverAuditReport *out);
void carver_mov_reset_last_audit(void);

#endif
