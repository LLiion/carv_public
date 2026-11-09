#ifndef CARVER_GIF_H
#define CARVER_GIF_H

#include <stddef.h>
#include <stdint.h>

#include "carver_audit.h"

int carver_gif_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
);

void carver_gif_reset_last_audit(void);
void carver_gif_get_last_audit(CarverAuditReport *out);

#endif
