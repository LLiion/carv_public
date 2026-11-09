/*
 * db.h
 * Provides basic SQLite database open and close helpers.
 */

#ifndef DB_H
#define DB_H

#include <sqlite3.h>

typedef struct {
    sqlite3 *connection;
} DbHandle;

int db_open(DbHandle *db, const char *path);
void db_close(DbHandle *db);

#endif
