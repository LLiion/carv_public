/*
 * magic_db.h
 * Reads rows and metadata from the magic table.
 */

#ifndef MAGIC_DB_H
#define MAGIC_DB_H

#include "db.h"
#include "mftprobe_engine_types.h"
#include "signature_types.h"

int magic_db_count_rows(DbHandle *db, int *count);
int magic_db_load_all(DbHandle *db, MagicTable *table);
int magic_db_load_for_order(DbHandle *db, MagicTable *table, const RecoveryOrder *active_order);

#endif
