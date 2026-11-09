#ifndef CARVER_SQLITE_H
#define CARVER_SQLITE_H

#include <stddef.h>

#include "carver_audit.h"
#include "reader.h"

int carver_sqlite_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    int allow_lrcat,
    int allow_sqlite,
    int allow_db
);

void carver_sqlite_reset_last_audit(void);
void carver_sqlite_get_last_audit(CarverAuditReport *out);

#endif
