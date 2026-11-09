/*
 * carver_riff.h
 * Streams RIFF-based file recovery from the current reader position.
 */

#ifndef CARVER_RIFF_H
#define CARVER_RIFF_H

#include <stddef.h>

#include "config.h"
#include "carver_audit.h"
#include "reader.h"
#include "signature_types.h"

int carver_riff_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

void carver_riff_reset_last_audit(void);
void carver_riff_get_last_audit(CarverAuditReport *out);

#endif
