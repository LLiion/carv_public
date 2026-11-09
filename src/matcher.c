/*
 * matcher.c
 * Checks whether a given buffer position matches any loaded magic signature.
 */

#include "matcher.h"
#include "blob_start.h"
#include "magic.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

int matcher_maybe_match_prefix_at(
    const MagicTable *table,
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
)
{
    unsigned int key;

    if (table == NULL || buffer == NULL) {
        return 0;
    }

    if (offset + 1 >= buffer_length) {
        return 0;
    }

    key = ((unsigned int)buffer[offset] << 8) | buffer[offset + 1];
    return magic_has_prefix_2byte(table, key);
}

const MagicEntry *matcher_match_at(
    const MagicTable *table,
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
)
{
    const MagicIndexBucket *bucket;
    size_t i;
    unsigned int key;

    if (table == NULL || buffer == NULL) {
        return NULL;
    }

    if (offset + 1 >= buffer_length) {
        return NULL;
    }

    key = ((unsigned int)buffer[offset] << 8) | buffer[offset + 1];

    if (!magic_has_prefix_2byte(table, key)) {
        return NULL;
    }

    bucket = magic_get_bucket(table, key);

    if (bucket == NULL || bucket->count == 0) {
        return NULL;
    }

    for (i = 0; i < bucket->count; i++) {
        const MagicEntry *entry = &table->entries[bucket->entry_indexes[i]];
        const uint8_t *start_pattern =
            entry->start_pattern != NULL ? entry->start_pattern : entry->pattern;
        size_t start_pattern_length =
            entry->start_pattern != NULL ? entry->start_pattern_length : entry->pattern_length;
        size_t pattern_offset;

        if (entry->pattern == NULL || entry->pattern_length == 0) {
            continue;
        }
        if (start_pattern == NULL || start_pattern_length == 0) {
            continue;
        }
        if (!blob_start_matches(
                buffer + offset,
                buffer_length - offset,
                start_pattern,
                start_pattern_length)) {
            continue;
        }
        pattern_offset = offset + entry->pattern_offset;
        if (pattern_offset < offset ||
            pattern_offset + entry->pattern_length > buffer_length) {
            continue;
        }
        if (memcmp(
                buffer + pattern_offset,
                entry->pattern,
                entry->pattern_length) == 0) {
            return entry;
        }
    }

    return NULL;
}
