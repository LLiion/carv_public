#ifndef CARVER_RAW_H
#define CARVER_RAW_H

#include <stddef.h>

#include "carver_audit.h"
#include "config.h"
#include "reader.h"
#include "signature_types.h"

int carver_raw_tiff_probe_buffer(
    const unsigned char *buffer,
    size_t buffer_length,
    size_t start_offset
);

int carver_raw_tiff_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    const MagicTable *boundary_table
);

int carver_raw_raf_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

int carver_raw_cr3_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

int carver_raw_crw_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    const MagicTable *boundary_table
);

int carver_raw_x3f_streaming(
    Reader *reader,
    const AppConfig *config,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

void carver_raw_reset_last_audit(void);
void carver_raw_get_last_audit(CarverAuditReport *out);

#endif
