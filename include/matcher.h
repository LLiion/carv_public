/*
 * matcher.h
 * Matches a buffer position against loaded magic signatures.
 */

#ifndef MATCHER_H
#define MATCHER_H

#include <stddef.h>
#include <stdint.h>

#include "signature_types.h"

int matcher_maybe_match_prefix_at(
    const MagicTable *table,
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
);
const MagicEntry *matcher_match_at(
    const MagicTable *table,
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
);

#endif
