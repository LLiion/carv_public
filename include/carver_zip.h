#ifndef CARVER_ZIP_H
#define CARVER_ZIP_H

#include <stddef.h>
#include <stdint.h>

#include "carver_audit.h"

#define CARVER_ZIP_ALLOW_DOCX (1U << 0)
#define CARVER_ZIP_ALLOW_XLSX (1U << 1)
#define CARVER_ZIP_ALLOW_PPTX (1U << 2)
#define CARVER_ZIP_ALLOW_ZIP  (1U << 3)
#define CARVER_ZIP_ALLOW_ODT  (1U << 4)
#define CARVER_ZIP_ALLOW_ODS  (1U << 5)
#define CARVER_ZIP_ALLOW_ODP  (1U << 6)
#define CARVER_ZIP_ALLOW_EPUB (1U << 7)
#define CARVER_ZIP_ALLOW_APK  (1U << 8)
#define CARVER_ZIP_ALLOW_JAR  (1U << 9)
#define CARVER_ZIP_ALLOW_XPS  (1U << 10)

int carver_zip_family_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    uint32_t allowed_extensions,
    size_t *confirmed_span_out
);

void carver_zip_ooxml_reset_last_audit(void);
void carver_zip_ooxml_get_last_audit(CarverAuditReport *out);

#endif
