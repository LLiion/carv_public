/*
 * db.c
 * Wraps basic SQLite connection management for the application.
 */

#include "db.h"
#include <sqlite3.h>

#include <stddef.h>

int db_open(DbHandle *db, const char *path)
{
    if (db == NULL || path == NULL) {
        return 0;
    }

    db->connection = NULL;

    if (sqlite3_open(path, &db->connection) != SQLITE_OK) {
        db_close(db);
        return 0;
    }

    return 1;
}

void db_close(DbHandle *db)
{
    if (db == NULL) {
        return;
    }

    if (db->connection != NULL) {
        sqlite3_close(db->connection);
        db->connection = NULL;
    }
}
