/*
 * magic.h
 * Owns loaded magic entries, builds a lookup index, and releases allocated memory.
 */

#ifndef MAGIC_H
#define MAGIC_H

#include "signature_types.h"

int magic_build_index(MagicTable *table);
const MagicIndexBucket *magic_get_bucket(const MagicTable *table, unsigned int key);
int magic_has_prefix_1byte(const MagicTable *table, unsigned int key);
int magic_has_prefix_2byte(const MagicTable *table, unsigned int key);
void magic_table_free(MagicTable *table);

#endif
