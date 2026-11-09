#ifndef CARVER_PDF_H
#define CARVER_PDF_H

#include <stddef.h>
#include <stdint.h>

#include "carver_audit.h"
#include "reader.h"

int carver_pdf_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
);

int carver_pdf_from_reader(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
);

const char *carver_pdf_last_reject_reason(void);
void carver_pdf_reset_last_audit(void);
void carver_pdf_get_last_audit(CarverAuditReport *out);

#endif
