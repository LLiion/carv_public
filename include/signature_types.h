/*
 * signature_types.h
 * Defines in-memory structures for loaded file signatures.
 */

#ifndef SIGNATURE_TYPES_H
#define SIGNATURE_TYPES_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    int id;
    char *name;
    char *type;
    char *type_name;
    char *category;
    char *hex_string;
    uint8_t *pattern;
    size_t pattern_length;
    size_t pattern_offset;
    char *start_hex_string;
    uint8_t *start_pattern;
    size_t start_pattern_length;
    char *eof_hex_string;
    uint8_t *eof_pattern;
    size_t eof_pattern_length;
} MagicEntry;

typedef struct {
    size_t *entry_indexes;
    size_t count;
    uint32_t *prefix4_values;
    size_t prefix4_count;
    int has_short_index_pattern;
} MagicIndexBucket;

typedef struct {
    MagicEntry *entries;
    size_t count;
    MagicIndexBucket *index_2byte;
    uint8_t *prefix_1byte_present;
    uint8_t *prefix_2byte_present;
} MagicTable;

#endif
