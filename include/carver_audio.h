#ifndef CARVER_AUDIO_H
#define CARVER_AUDIO_H

#include <stddef.h>

#include "carver_audit.h"
#include "reader.h"

int carver_mp3_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

int carver_aac_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

int carver_flac_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset
);

void carver_mp3_reset_last_audit(void);
void carver_mp3_get_last_audit(CarverAuditReport *out);
void carver_aac_reset_last_audit(void);
void carver_aac_get_last_audit(CarverAuditReport *out);
void carver_flac_reset_last_audit(void);
void carver_flac_get_last_audit(CarverAuditReport *out);

#endif
