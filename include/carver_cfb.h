#ifndef CARVER_CFB_H
#define CARVER_CFB_H

#include <stddef.h>
#include <stdint.h>

#include "carver_audit.h"
#include "reader.h"

#define CARVER_CFB_ALLOW_DOC (1U << 0)
#define CARVER_CFB_ALLOW_DOT (1U << 1)
#define CARVER_CFB_ALLOW_XLS (1U << 2)
#define CARVER_CFB_ALLOW_XLA (1U << 3)
#define CARVER_CFB_ALLOW_PPT (1U << 4)
#define CARVER_CFB_ALLOW_PPS (1U << 5)
#define CARVER_CFB_ALLOW_WIZ (1U << 6)
#define CARVER_CFB_ALLOW_MSG (1U << 7)
#define CARVER_CFB_ALLOW_MDB (1U << 8)
#define CARVER_CFB_ALLOW_VSD (1U << 9)
#define CARVER_CFB_ALLOW_PUB (1U << 10)

int carver_cfb_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    uint32_t allowed_extensions
);

void carver_cfb_reset_last_audit(void);
void carver_cfb_get_last_audit(CarverAuditReport *out);

#endif
