/*
 * carver_bmp.h
 * Recovers BMP files from a buffer using BMP header metadata.
 */

#ifndef CARVER_BMP_H
#define CARVER_BMP_H

#include <stddef.h>
#include <stdint.h>

#include "carver_audit.h"

int carver_bmp_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
);

void carver_bmp_reset_last_audit(void);
void carver_bmp_get_last_audit(CarverAuditReport *out);

#endif
