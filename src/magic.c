/*
 * magic.c
 * Releases memory used by the in-memory magic table.
 */

#include "magic.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#define MAGIC_INDEX_SIZE 65536

static unsigned int make_2byte_key(unsigned char first, unsigned char second)
{
    return ((unsigned int)first << 8) | (unsigned int)second;
}

static uint32_t make_4byte_key(
    unsigned char first,
    unsigned char second,
    unsigned char third,
    unsigned char fourth
)
{
    return ((uint32_t)first << 24) |
           ((uint32_t)second << 16) |
           ((uint32_t)third << 8) |
           (uint32_t)fourth;
}

static const uint8_t *magic_entry_index_pattern(const MagicEntry *entry, size_t *length_out)
{
    if (length_out != NULL) {
        *length_out = 0;
    }
    if (entry == NULL) {
        return NULL;
    }
    if (entry->pattern != NULL &&
        entry->pattern_length > 0 &&
        entry->pattern_offset == 0) {
        if (length_out != NULL) {
            *length_out = entry->pattern_length;
        }
        return entry->pattern;
    }
    if (entry->start_pattern != NULL && entry->start_pattern_length > 0) {
        if (length_out != NULL) {
            *length_out = entry->start_pattern_length;
        }
        return entry->start_pattern;
    }
    if (entry->pattern != NULL && entry->pattern_length > 0) {
        if (length_out != NULL) {
            *length_out = entry->pattern_length;
        }
        return entry->pattern;
    }
    return NULL;
}

static int bucket_has_prefix4(const MagicIndexBucket *bucket, uint32_t key4)
{
    size_t i;

    if (bucket == NULL || bucket->prefix4_values == NULL) {
        return 0;
    }

    for (i = 0; i < bucket->prefix4_count; i++) {
        if (bucket->prefix4_values[i] == key4) {
            return 1;
        }
    }

    return 0;
}

int magic_build_index(MagicTable *table)
{
    size_t i;

    if (table == NULL || table->entries == NULL || table->count == 0) {
        return 0;
    }

    table->prefix_1byte_present = (uint8_t *)calloc(256U, sizeof(uint8_t));
    if (table->prefix_1byte_present == NULL) {
        return 0;
    }

    table->prefix_2byte_present = (uint8_t *)calloc(MAGIC_INDEX_SIZE, sizeof(uint8_t));
    if (table->prefix_2byte_present == NULL) {
        free(table->prefix_1byte_present);
        table->prefix_1byte_present = NULL;
        return 0;
    }

    table->index_2byte = (MagicIndexBucket *)calloc(MAGIC_INDEX_SIZE, sizeof(MagicIndexBucket));
    if (table->index_2byte == NULL) {
        free(table->prefix_1byte_present);
        table->prefix_1byte_present = NULL;
        free(table->prefix_2byte_present);
        table->prefix_2byte_present = NULL;
        return 0;
    }

    for (i = 0; i < table->count; i++) {
        MagicEntry *entry = &table->entries[i];
        MagicIndexBucket *bucket;
        size_t *new_indexes;
        const uint8_t *index_pattern;
        size_t index_length;
        unsigned int key;

        index_pattern = magic_entry_index_pattern(entry, &index_length);
        if (index_pattern == NULL || index_length < 2) {
            continue;
        }

        table->prefix_1byte_present[index_pattern[0]] = 1;
        key = make_2byte_key(index_pattern[0], index_pattern[1]);
        table->prefix_2byte_present[key] = 1;
        bucket = &table->index_2byte[key];

        new_indexes = (size_t *)realloc(bucket->entry_indexes, (bucket->count + 1) * sizeof(size_t));
        if (new_indexes == NULL) {
            return 0;
        }

        bucket->entry_indexes = new_indexes;
        bucket->entry_indexes[bucket->count] = i;
        bucket->count++;

        if (index_length >= 4) {
            uint32_t key4 = make_4byte_key(
                index_pattern[0],
                index_pattern[1],
                index_pattern[2],
                index_pattern[3]
            );

            if (!bucket_has_prefix4(bucket, key4)) {
                uint32_t *new_prefixes = (uint32_t *)realloc(
                    bucket->prefix4_values,
                    (bucket->prefix4_count + 1U) * sizeof(uint32_t)
                );

                if (new_prefixes == NULL) {
                    return 0;
                }

                bucket->prefix4_values = new_prefixes;
                bucket->prefix4_values[bucket->prefix4_count] = key4;
                bucket->prefix4_count++;
            }
        } else {
            bucket->has_short_index_pattern = 1;
        }
    }

    return 1;
}

int magic_has_prefix_1byte(const MagicTable *table, unsigned int key)
{
    if (table == NULL ||
        table->prefix_1byte_present == NULL ||
        key >= 256U) {
        return 0;
    }

    return table->prefix_1byte_present[key] != 0;
}

const MagicIndexBucket *magic_get_bucket(const MagicTable *table, unsigned int key)
{
    if (table == NULL || table->index_2byte == NULL || key >= MAGIC_INDEX_SIZE) {
        return NULL;
    }

    return &table->index_2byte[key];
}

int magic_has_prefix_2byte(const MagicTable *table, unsigned int key)
{
    if (table == NULL ||
        table->prefix_2byte_present == NULL ||
        key >= MAGIC_INDEX_SIZE) {
        return 0;
    }

    return table->prefix_2byte_present[key] != 0;
}

void magic_table_free(MagicTable *table)
{
    size_t i;

    if (table == NULL) {
        return;
    }

    if (table->index_2byte != NULL) {
        for (i = 0; i < MAGIC_INDEX_SIZE; i++) {
            free(table->index_2byte[i].entry_indexes);
            free(table->index_2byte[i].prefix4_values);
        }

        free(table->index_2byte);
        table->index_2byte = NULL;
    }

    free(table->prefix_1byte_present);
    table->prefix_1byte_present = NULL;
    free(table->prefix_2byte_present);
    table->prefix_2byte_present = NULL;

    if (table->entries != NULL) {
        for (i = 0; i < table->count; i++) {
            free(table->entries[i].name);
            free(table->entries[i].type);
            free(table->entries[i].type_name);
            free(table->entries[i].category);
            free(table->entries[i].hex_string);
            free(table->entries[i].pattern);
            free(table->entries[i].start_hex_string);
            free(table->entries[i].start_pattern);
            free(table->entries[i].eof_hex_string);
            free(table->entries[i].eof_pattern);
        }

        free(table->entries);
        table->entries = NULL;
    }

    table->count = 0;
}
