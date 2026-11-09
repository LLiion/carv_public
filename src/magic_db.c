/*
 * magic_db.c
 * Executes queries against the magic table and builds an in-memory table.
 */

#include "magic_db.h"

#include "hex.h"
#include "magic.h"

#include <ctype.h>
#include <stddef.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

static char *duplicate_text(const unsigned char *text)
{
    size_t length;
    char *copy;

    if (text == NULL) {
        return NULL;
    }

    length = strlen((const char *)text);
    copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, text, length + 1);
    return copy;
}

static int ascii_tolower_local(int c)
{
    return tolower((unsigned char)c);
}

static int streq_ci_local(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    while (*a != '\0' && *b != '\0') {
        if (ascii_tolower_local((unsigned char)*a) !=
            ascii_tolower_local((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }

    return *a == '\0' && *b == '\0';
}

static int type_is_jpeg_local(const char *type)
{
    if (type == NULL) {
        return 0;
    }

    return streq_ci_local(type, "jpg") ||
           streq_ci_local(type, "jpeg") ||
           streq_ci_local(type, "jpe");
}

static int type_is_flac_local(const char *type)
{
    return type != NULL &&
           streq_ci_local(type, "flac");
}

static int type_is_zip_local(const char *type)
{
    return type != NULL &&
           streq_ci_local(type, "zip");
}

static int type_is_rar_local(const char *type)
{
    return type != NULL &&
           streq_ci_local(type, "rar");
}

static int magic_entry_force_jpeg_ffd8ff(MagicEntry *entry)
{
    static const uint8_t jpeg_pattern[] = {0xFF, 0xD8, 0xFF};
    uint8_t *new_pattern;
    uint8_t *new_start_pattern;

    if (entry == NULL || !type_is_jpeg_local(entry->type)) {
        return 1;
    }
    if (entry->pattern_offset != 0U ||
        entry->pattern == NULL ||
        entry->pattern_length != 2U ||
        entry->pattern[0] != 0xFFU ||
        entry->pattern[1] != 0xD8U) {
        return 1;
    }

    new_pattern = (uint8_t *)malloc(sizeof(jpeg_pattern));
    if (new_pattern == NULL) {
        return 0;
    }
    memcpy(new_pattern, jpeg_pattern, sizeof(jpeg_pattern));
    free(entry->pattern);
    entry->pattern = new_pattern;
    entry->pattern_length = sizeof(jpeg_pattern);

    new_start_pattern = (uint8_t *)malloc(sizeof(jpeg_pattern));
    if (new_start_pattern == NULL) {
        return 0;
    }
    memcpy(new_start_pattern, jpeg_pattern, sizeof(jpeg_pattern));
    free(entry->start_pattern);
    entry->start_pattern = new_start_pattern;
    entry->start_pattern_length = sizeof(jpeg_pattern);

    free(entry->start_hex_string);
    entry->start_hex_string = duplicate_text((const unsigned char *)"FFD8FF");

    return entry->start_hex_string != NULL;
}

static int magic_entry_force_flac_signature(MagicEntry *entry)
{
    static const uint8_t flac_pattern[] = {0x66, 0x4C, 0x61, 0x43};
    uint8_t *new_pattern;
    uint8_t *new_start_pattern;

    if (entry == NULL || !type_is_flac_local(entry->type)) {
        return 1;
    }
    if (entry->pattern_offset != 0U ||
        entry->pattern == NULL ||
        entry->pattern_length < sizeof(flac_pattern) ||
        memcmp(entry->pattern, flac_pattern, sizeof(flac_pattern)) != 0) {
        return 1;
    }

    new_pattern = (uint8_t *)malloc(sizeof(flac_pattern));
    if (new_pattern == NULL) {
        return 0;
    }
    memcpy(new_pattern, flac_pattern, sizeof(flac_pattern));
    free(entry->pattern);
    entry->pattern = new_pattern;
    entry->pattern_length = sizeof(flac_pattern);

    new_start_pattern = (uint8_t *)malloc(sizeof(flac_pattern));
    if (new_start_pattern == NULL) {
        return 0;
    }
    memcpy(new_start_pattern, flac_pattern, sizeof(flac_pattern));
    free(entry->start_pattern);
    entry->start_pattern = new_start_pattern;
    entry->start_pattern_length = sizeof(flac_pattern);

    free(entry->start_hex_string);
    entry->start_hex_string = duplicate_text((const unsigned char *)"664C6143");

    return entry->start_hex_string != NULL;
}

static int magic_entry_force_zip_local_header(MagicEntry *entry)
{
    static const uint8_t zip_pattern[] = {0x50, 0x4B, 0x03, 0x04};
    uint8_t *new_pattern;
    uint8_t *new_start_pattern;

    if (entry == NULL || !type_is_zip_local(entry->type)) {
        return 1;
    }
    if (entry->pattern_offset == 0U &&
        entry->pattern != NULL &&
        entry->pattern_length == sizeof(zip_pattern) &&
        memcmp(entry->pattern, zip_pattern, sizeof(zip_pattern)) == 0 &&
        entry->start_pattern != NULL &&
        entry->start_pattern_length == sizeof(zip_pattern) &&
        memcmp(entry->start_pattern, zip_pattern, sizeof(zip_pattern)) == 0) {
        return 1;
    }

    new_pattern = (uint8_t *)malloc(sizeof(zip_pattern));
    if (new_pattern == NULL) {
        return 0;
    }
    memcpy(new_pattern, zip_pattern, sizeof(zip_pattern));
    free(entry->pattern);
    entry->pattern = new_pattern;
    entry->pattern_length = sizeof(zip_pattern);
    entry->pattern_offset = 0U;

    new_start_pattern = (uint8_t *)malloc(sizeof(zip_pattern));
    if (new_start_pattern == NULL) {
        return 0;
    }
    memcpy(new_start_pattern, zip_pattern, sizeof(zip_pattern));
    free(entry->start_pattern);
    entry->start_pattern = new_start_pattern;
    entry->start_pattern_length = sizeof(zip_pattern);

    free(entry->start_hex_string);
    entry->start_hex_string = duplicate_text((const unsigned char *)"504B0304");

    return entry->start_hex_string != NULL;
}

static int magic_entry_force_rar_version_agnostic(MagicEntry *entry)
{
    static const uint8_t rar_prefix[] = {0x52, 0x61, 0x72, 0x21, 0x1A, 0x07};
    uint8_t *new_pattern;
    uint8_t *new_start_pattern;

    if (entry == NULL || !type_is_rar_local(entry->type)) {
        return 1;
    }
    if (entry->pattern_offset == 0U &&
        entry->pattern != NULL &&
        entry->pattern_length == sizeof(rar_prefix) &&
        memcmp(entry->pattern, rar_prefix, sizeof(rar_prefix)) == 0 &&
        entry->start_pattern != NULL &&
        entry->start_pattern_length == sizeof(rar_prefix) &&
        memcmp(entry->start_pattern, rar_prefix, sizeof(rar_prefix)) == 0) {
        return 1;
    }

    new_pattern = (uint8_t *)malloc(sizeof(rar_prefix));
    if (new_pattern == NULL) {
        return 0;
    }
    memcpy(new_pattern, rar_prefix, sizeof(rar_prefix));
    free(entry->pattern);
    entry->pattern = new_pattern;
    entry->pattern_length = sizeof(rar_prefix);
    entry->pattern_offset = 0U;

    new_start_pattern = (uint8_t *)malloc(sizeof(rar_prefix));
    if (new_start_pattern == NULL) {
        return 0;
    }
    memcpy(new_start_pattern, rar_prefix, sizeof(rar_prefix));
    free(entry->start_pattern);
    entry->start_pattern = new_start_pattern;
    entry->start_pattern_length = sizeof(rar_prefix);

    free(entry->start_hex_string);
    entry->start_hex_string = duplicate_text((const unsigned char *)"526172211A07");

    return entry->start_hex_string != NULL;
}

static void normalize_extension_local(char *text)
{
    size_t read_pos = 0;
    size_t write_pos = 0;

    if (text == NULL) {
        return;
    }

    while (text[read_pos] == '.' || isspace((unsigned char)text[read_pos])) {
        read_pos++;
    }

    while (text[read_pos] != '\0' &&
           write_pos + 1U < FORMAT_EXTENSION_MAX) {
        if (!isspace((unsigned char)text[read_pos])) {
            text[write_pos++] =
                (char)ascii_tolower_local((unsigned char)text[read_pos]);
        }
        read_pos++;
    }

    text[write_pos] = '\0';
}

static void copy_text_truncated_local(char *dst, size_t dst_size, const char *src)
{
    size_t length;

    if (dst == NULL || dst_size == 0) {
        return;
    }

    dst[0] = '\0';
    if (src == NULL) {
        return;
    }

    length = strlen(src);
    if (length >= dst_size) {
        length = dst_size - 1U;
    }

    memcpy(dst, src, length);
    dst[length] = '\0';
}

static int order_has_extension_local(
    const RecoveryOrder *order,
    const char *extension
)
{
    size_t i;
    size_t j;
    char normalized[FORMAT_EXTENSION_MAX];

    if (order == NULL || extension == NULL || extension[0] == '\0') {
        return 0;
    }

    copy_text_truncated_local(normalized, sizeof(normalized), extension);
    normalize_extension_local(normalized);
    if (normalized[0] == '\0') {
        return 0;
    }

    for (i = 0; i < order->count; i++) {
        const RecoveryFormat *format = &order->formats[i];

        if (format->default_extension != NULL &&
            streq_ci_local(format->default_extension, normalized)) {
            return 1;
        }

        for (j = 0; j < format->extension_count; j++) {
            if (streq_ci_local(format->extensions[j], normalized)) {
                return 1;
            }
        }
    }

    return 0;
}

static int value_contains_selected_extension(
    const RecoveryOrder *order,
    const char *value
)
{
    char work[256];
    char *cursor;

    if (order == NULL || value == NULL || value[0] == '\0') {
        return 0;
    }

    snprintf(work, sizeof(work), "%s", value);
    cursor = work;
    while (*cursor != '\0') {
        char *separator = strchr(cursor, '|');

        if (separator != NULL) {
            *separator = '\0';
        }

        normalize_extension_local(cursor);
        if (cursor[0] != '\0' &&
            order_has_extension_local(order, cursor)) {
            return 1;
        }

        if (separator == NULL) {
            break;
        }
        cursor = separator + 1;
    }

    return 0;
}

static int magic_row_selected_for_order(
    const RecoveryOrder *order,
    const char *type
)
{
    if (order == NULL || order->count == 0) {
        return 1;
    }

    if (streq_ci_local(type, "mov") &&
        (order_has_extension_local(order, "heic") ||
         order_has_extension_local(order, "heif") ||
         order_has_extension_local(order, "avif"))) {
        return 1;
    }

    if (streq_ci_local(type, "riff") &&
        (order_has_extension_local(order, "avi") ||
         order_has_extension_local(order, "wav") ||
         order_has_extension_local(order, "webp") ||
         order_has_extension_local(order, "rmi") ||
         order_has_extension_local(order, "riff"))) {
        return 1;
    }

    return value_contains_selected_extension(order, type);
}

static int schema_has_column(
    DbHandle *db,
    const char *table_name,
    const char *column_name
)
{
    sqlite3_stmt *stmt = NULL;
    char sql[128];
    int found = 0;

    if (db == NULL ||
        db->connection == NULL ||
        table_name == NULL ||
        column_name == NULL) {
        return 0;
    }

    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s);", table_name);
    if (sqlite3_prepare_v2(db->connection, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);

        if (name != NULL &&
            streq_ci_local((const char *)name, column_name)) {
            found = 1;
            break;
        }
    }

    sqlite3_finalize(stmt);
    return found;
}

static int schema_has_table(DbHandle *db, const char *table_name)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1 LIMIT 1;";
    int found = 0;

    if (db == NULL || db->connection == NULL || table_name == NULL) {
        return 0;
    }
    if (sqlite3_prepare_v2(db->connection, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }
    (void)sqlite3_bind_text(stmt, 1, table_name, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        found = 1;
    }
    sqlite3_finalize(stmt);
    return found;
}

int magic_db_count_rows(DbHandle *db, int *count)
{
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT COUNT(*) FROM magic;";
    int result = 0;

    if (db == NULL || db->connection == NULL || count == NULL) {
        return 0;
    }

    *count = 0;

    if (sqlite3_prepare_v2(db->connection, sql, -1, &stmt, NULL) != SQLITE_OK) {
        goto cleanup;
    }

    if (sqlite3_step(stmt) == SQLITE_ROW) {
        *count = sqlite3_column_int(stmt, 0);
        result = 1;
    }

cleanup:
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }

    return result;
}

int magic_db_load_for_order(
    DbHandle *db,
    MagicTable *table,
    const RecoveryOrder *active_order
)
{
    sqlite3_stmt *stmt = NULL;
    MagicEntry *entries = NULL;
    size_t count = 0;
    size_t capacity = 0;
    int result = 0;
    const char *source_table = "magic";
    int has_blob_string;
    int has_category;
    const char *sql;

    if (db == NULL || db->connection == NULL || table == NULL) {
        return 0;
    }

    table->entries = NULL;
    table->count = 0;
    table->index_2byte = NULL;
    table->prefix_1byte_present = NULL;
    table->prefix_2byte_present = NULL;

    if (schema_has_table(db, "common") &&
        schema_has_column(db, "common", "blob_string") &&
        schema_has_column(db, "common", "type")) {
        source_table = "common";
    }

    has_blob_string = schema_has_column(db, source_table, "blob_string");
    has_category = schema_has_column(db, source_table, "category");

    if (strcmp(source_table, "common") == 0) {
        sql = "SELECT id, name, type, type_name, NULL, "
              "CAST(blob_string AS TEXT), COALESCE(offset, 0), "
              "CAST(eof AS TEXT), CAST(blob_start AS TEXT) "
              "FROM common ORDER BY id;";
    } else if (has_blob_string) {
        sql = has_category
            ? "SELECT id, name, type, type_name, category, "
              "CAST(blob_string AS TEXT), COALESCE(offset, 0), "
              "CAST(eof AS TEXT), CAST(blob_start AS TEXT) "
              "FROM magic ORDER BY id;"
            : "SELECT id, name, type, type_name, NULL, "
              "CAST(blob_string AS TEXT), COALESCE(offset, 0), "
              "CAST(eof AS TEXT), CAST(blob_start AS TEXT) "
              "FROM magic ORDER BY id;";
    } else {
        sql = has_category
            ? "SELECT id, name, type, NULL, category, hex_string, 0, NULL, substr(hex_string, 1, 4) "
              "FROM magic ORDER BY id;"
            : "SELECT id, name, type, NULL, NULL, hex_string, 0, NULL, substr(hex_string, 1, 4) "
              "FROM magic ORDER BY id;";
    }

    if (sqlite3_prepare_v2(db->connection, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *name = sqlite3_column_text(stmt, 1);
        const unsigned char *type = sqlite3_column_text(stmt, 2);
        const unsigned char *type_name = sqlite3_column_text(stmt, 3);
        const unsigned char *category = sqlite3_column_text(stmt, 4);
        const unsigned char *hex_string = sqlite3_column_text(stmt, 5);
        sqlite3_int64 pattern_offset = sqlite3_column_int64(stmt, 6);
        const unsigned char *eof_hex = sqlite3_column_text(stmt, 7);
        const unsigned char *start_hex = sqlite3_column_text(stmt, 8);
        MagicEntry *entry;

        if (!magic_row_selected_for_order(active_order, (const char *)type)) {
            continue;
        }

        if (count == capacity) {
            size_t new_capacity = (capacity == 0) ? 32U : capacity * 2U;
            MagicEntry *new_entries =
                (MagicEntry *)realloc(entries, new_capacity * sizeof(MagicEntry));

            if (new_entries == NULL) {
                goto cleanup;
            }

            memset(
                new_entries + capacity,
                0,
                (new_capacity - capacity) * sizeof(MagicEntry));
            entries = new_entries;
            capacity = new_capacity;
        }

        entry = &entries[count];
        entry->id = sqlite3_column_int(stmt, 0);
        entry->name = duplicate_text(name);
        entry->type = duplicate_text(type);
        entry->type_name = duplicate_text(type_name);
        entry->category = duplicate_text(category);
        entry->hex_string = duplicate_text(hex_string);

        if (entry->name == NULL ||
            entry->type == NULL ||
            entry->hex_string == NULL) {
            goto cleanup;
        }

        if (!hex_string_to_bytes(
                entry->hex_string,
                &entry->pattern,
                &entry->pattern_length)) {
            goto cleanup;
        }

        entry->pattern_offset =
            pattern_offset > 0 ? (size_t)pattern_offset : 0U;

        if (start_hex != NULL && start_hex[0] != '\0') {
            entry->start_hex_string = duplicate_text(start_hex);
            if (entry->start_hex_string == NULL ||
                !hex_string_to_bytes(
                    entry->start_hex_string,
                    &entry->start_pattern,
                    &entry->start_pattern_length)) {
                goto cleanup;
            }
        }

        if (eof_hex != NULL && eof_hex[0] != '\0') {
            entry->eof_hex_string = duplicate_text(eof_hex);
            if (entry->eof_hex_string == NULL ||
                !hex_string_to_bytes(
                    entry->eof_hex_string,
                    &entry->eof_pattern,
                    &entry->eof_pattern_length)) {
                goto cleanup;
            }
        }

        if (!magic_entry_force_jpeg_ffd8ff(entry) ||
            !magic_entry_force_flac_signature(entry) ||
            !magic_entry_force_zip_local_header(entry) ||
            !magic_entry_force_rar_version_agnostic(entry)) {
            goto cleanup;
        }

        count++;
    }

    if (sqlite3_errcode(db->connection) != SQLITE_OK &&
        sqlite3_errcode(db->connection) != SQLITE_DONE) {
        goto cleanup;
    }

    table->entries = entries;
    table->count = count;
    entries = NULL;
    result = 1;

cleanup:
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }

    if (entries != NULL) {
        MagicTable temp;
        memset(&temp, 0, sizeof(temp));
        temp.entries = entries;
        temp.count = count;
        magic_table_free(&temp);
    }

    return result;
}

int magic_db_load_all(DbHandle *db, MagicTable *table)
{
    return magic_db_load_for_order(db, table, NULL);
}
