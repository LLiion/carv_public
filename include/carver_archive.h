#ifndef CARVER_ARCHIVE_H
#define CARVER_ARCHIVE_H

#include <stddef.h>

#include "carver_audit.h"
#include "reader.h"

int carver_rar_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

int carver_7z_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

int carver_iso_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

void carver_rar_reset_last_audit(void);
void carver_rar_get_last_audit(CarverAuditReport *out);
void carver_7z_reset_last_audit(void);
void carver_7z_get_last_audit(CarverAuditReport *out);
void carver_iso_reset_last_audit(void);
void carver_iso_get_last_audit(CarverAuditReport *out);

#endif
