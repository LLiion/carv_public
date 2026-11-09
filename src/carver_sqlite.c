#include "carver_sqlite.h"

#include "carver_output.h"
#include "config.h"
#include "fs_backend.h"

#include <errno.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SQLITE_HEADER_SIZE 100U
#define SQLITE_FIRST_BTREE_OFFSET 100U
#define SQLITE_MIN_FILE_SIZE 512ULL
#define SQLITE_MAX_REASONABLE_FILE_SIZE (64ULL * 1024ULL * 1024ULL * 1024ULL)

typedef struct {
    uint32_t page_size;
    uint32_t page_count;
    uint64_t confirmed_span;
} SqliteHeaderInfo;

typedef struct {
    int lightroom_score;
    int has_aglibrary_file;
    int has_aglibrary_folder;
    int has_adobe_images;
} SqliteCatalogProbe;

static CarverAuditReport g_sqlite_last_audit;

void carver_sqlite_reset_last_audit(void)
{
    carver_audit_reset_inline(&g_sqlite_last_audit);
}

void carver_sqlite_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_sqlite_last_audit;
}

static uint64_t reader_buffer_base_absolute(const Reader *reader)
{
    if (reader == NULL ||
        (uint64_t)reader->bytes_in_buffer > (uint64_t)reader->total_bytes_read) {
        return 0U;
    }
    return (uint64_t)reader->total_bytes_read - (uint64_t)reader->bytes_in_buffer;
}

static int read_stream_bytes(
    Reader *reader,
    uint64_t start_abs,
    uint8_t *dst,
    size_t byte_count
)
{
    uint64_t current_abs = start_abs;
    size_t copied = 0U;

    if (reader == NULL || dst == NULL) {
        return 0;
    }

    while (copied < byte_count) {
        uint64_t base_abs;
        size_t buffer_offset;
        size_t available;
        size_t copy_now;

        base_abs = reader_buffer_base_absolute(reader);
        if (current_abs < base_abs) {
            return 0;
        }

        while (current_abs >= base_abs + (uint64_t)reader->bytes_in_buffer) {
            if (reader_read_next(reader) == 0U) {
                return 0;
            }
            base_abs = reader_buffer_base_absolute(reader);
            if (current_abs < base_abs) {
                return 0;
            }
        }

        buffer_offset = (size_t)(current_abs - base_abs);
        available = reader->bytes_in_buffer - buffer_offset;
        copy_now = available;
        if (copy_now > byte_count - copied) {
            copy_now = byte_count - copied;
        }

        memcpy(dst + copied, reader->buffer + buffer_offset, copy_now);
        current_abs += (uint64_t)copy_now;
        copied += copy_now;
    }

    return 1;
}

static int copy_stream_bytes(
    Reader *reader,
    FILE *output_file,
    uint64_t start_abs,
    uint64_t byte_count
)
{
    uint64_t current_abs = start_abs;
    uint64_t remaining = byte_count;

    if (reader == NULL || output_file == NULL) {
        return 0;
    }

    while (remaining > 0U) {
        uint64_t base_abs;
        size_t buffer_offset;
        size_t available;
        size_t write_now;

        base_abs = reader_buffer_base_absolute(reader);
        if (current_abs < base_abs) {
            return 0;
        }

        while (current_abs >= base_abs + (uint64_t)reader->bytes_in_buffer) {
            if (reader_read_next(reader) == 0U) {
                return 0;
            }
            base_abs = reader_buffer_base_absolute(reader);
            if (current_abs < base_abs) {
                return 0;
            }
        }

        buffer_offset = (size_t)(current_abs - base_abs);
        available = reader->bytes_in_buffer - buffer_offset;
        write_now = available;
        if ((uint64_t)write_now > remaining) {
            write_now = (size_t)remaining;
        }

        if (fwrite(reader->buffer + buffer_offset, 1U, write_now, output_file) != write_now) {
            return 0;
        }

        current_abs += (uint64_t)write_now;
        remaining -= (uint64_t)write_now;
    }

    return 1;
}

static int compute_resume_offset_local(
    const Reader *reader,
    uint64_t resume_abs,
    size_t fallback_offset,
    size_t *resume_offset_out
)
{
    uint64_t base_abs;

    if (reader == NULL || resume_offset_out == NULL) {
        return 0;
    }

    base_abs = reader_buffer_base_absolute(reader);
    if (resume_abs < base_abs) {
        *resume_offset_out = fallback_offset + 1U;
        return 1;
    }
    if (resume_abs >= base_abs + (uint64_t)reader->bytes_in_buffer) {
        *resume_offset_out = reader->bytes_in_buffer;
        return 1;
    }

    *resume_offset_out = (size_t)(resume_abs - base_abs);
    return 1;
}

static uint16_t read_u16_be_local(const uint8_t *data)
{
    return (uint16_t)(((uint16_t)data[0] << 8) | (uint16_t)data[1]);
}

static uint32_t read_u32_be_local(const uint8_t *data)
{
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) |
           (uint32_t)data[3];
}

static int sqlite_page_size_plausible(uint32_t page_size)
{
    return page_size >= 512U &&
           page_size <= 65536U &&
           (page_size & (page_size - 1U)) == 0U;
}

static int sqlite_btree_page_type_plausible(uint8_t page_type)
{
    return page_type == 0x02U ||
           page_type == 0x05U ||
           page_type == 0x0aU ||
           page_type == 0x0dU;
}

static int sqlite_parse_header(
    const uint8_t *header,
    uint8_t first_btree_page_type,
    SqliteHeaderInfo *out,
    const char **reject_reason
)
{
    uint32_t page_size;
    uint32_t page_count;
    uint64_t confirmed_span;

    if (reject_reason != NULL) {
        *reject_reason = "invalid_input";
    }
    if (header == NULL || out == NULL) {
        return 0;
    }
    if (memcmp(header, "SQLite format 3\000", 16U) != 0) {
        if (reject_reason != NULL) {
            *reject_reason = "missing_sqlite_header";
        }
        return 0;
    }

    page_size = read_u16_be_local(header + 16U);
    if (page_size == 1U) {
        page_size = 65536U;
    }
    if (!sqlite_page_size_plausible(page_size)) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_page_size";
        }
        return 0;
    }
    if (!((header[18] == 1U || header[18] == 2U) &&
          (header[19] == 1U || header[19] == 2U))) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_rw_version";
        }
        return 0;
    }
    if (header[21] != 64U || header[22] != 32U || header[23] != 32U) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_payload_fractions";
        }
        return 0;
    }
    if (!sqlite_btree_page_type_plausible(first_btree_page_type)) {
        if (reject_reason != NULL) {
            *reject_reason = "invalid_first_btree_page";
        }
        return 0;
    }

    page_count = read_u32_be_local(header + 28U);
    if (page_count == 0U) {
        if (reject_reason != NULL) {
            *reject_reason = "missing_page_count";
        }
        return 0;
    }

    confirmed_span = (uint64_t)page_size * (uint64_t)page_count;
    if (confirmed_span < SQLITE_MIN_FILE_SIZE) {
        if (reject_reason != NULL) {
            *reject_reason = "too_small";
        }
        return 0;
    }
    if (confirmed_span > SQLITE_MAX_REASONABLE_FILE_SIZE ||
        confirmed_span / (uint64_t)page_size != (uint64_t)page_count) {
        if (reject_reason != NULL) {
            *reject_reason = "size_over_cap";
        }
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->page_size = page_size;
    out->page_count = page_count;
    out->confirmed_span = confirmed_span;
    if (reject_reason != NULL) {
        *reject_reason = "";
    }
    return 1;
}

static int sqlite_name_has_prefix_ci(const char *name, const char *prefix)
{
    size_t i;

    if (name == NULL || prefix == NULL) {
        return 0;
    }
    for (i = 0U; prefix[i] != '\0'; i++) {
        char a = name[i];
        char b = prefix[i];

        if (a >= 'A' && a <= 'Z') {
            a = (char)(a - 'A' + 'a');
        }
        if (b >= 'A' && b <= 'Z') {
            b = (char)(b - 'A' + 'a');
        }
        if (a != b || a == '\0') {
            return 0;
        }
    }
    return 1;
}

static int sqlite_name_equals_ci(const char *a, const char *b)
{
    size_t i;

    if (a == NULL || b == NULL) {
        return 0;
    }
    for (i = 0U; a[i] != '\0' || b[i] != '\0'; i++) {
        char ca = a[i];
        char cb = b[i];

        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
    }
    return 1;
}

static void sqlite_catalog_probe_name(
    SqliteCatalogProbe *probe,
    const char *name
)
{
    if (probe == NULL || name == NULL || name[0] == '\0') {
        return;
    }

    if (sqlite_name_has_prefix_ci(name, "AgLibrary")) {
        probe->lightroom_score += 2;
    } else if (sqlite_name_has_prefix_ci(name, "AgHarvested")) {
        probe->lightroom_score += 2;
    } else if (sqlite_name_has_prefix_ci(name, "Adobe_")) {
        probe->lightroom_score += 1;
    } else if (sqlite_name_has_prefix_ci(name, "Adobe_image")) {
        probe->lightroom_score += 1;
    } else if (sqlite_name_has_prefix_ci(name, "Adobe_library")) {
        probe->lightroom_score += 1;
    }

    if (sqlite_name_equals_ci(name, "AgLibraryFile")) {
        probe->has_aglibrary_file = 1;
    } else if (sqlite_name_equals_ci(name, "AgLibraryFolder")) {
        probe->has_aglibrary_folder = 1;
    } else if (sqlite_name_equals_ci(name, "Adobe_images")) {
        probe->has_adobe_images = 1;
    }
}

static int sqlite_path_looks_like_lightroom_catalog(const char *path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    SqliteCatalogProbe probe = {0};
    const char *sql =
        "SELECT name FROM sqlite_master "
        "WHERE type IN ('table','view','index','trigger') LIMIT 512;";
    int is_lightroom = 0;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db != NULL) {
            sqlite3_close(db);
        }
        return 0;
    }
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char *name = sqlite3_column_text(stmt, 0);

            sqlite_catalog_probe_name(&probe, (const char *)name);
        }
    }
    if (stmt != NULL) {
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);

    if (probe.has_aglibrary_file &&
        (probe.has_aglibrary_folder || probe.has_adobe_images)) {
        is_lightroom = 1;
    } else if (probe.lightroom_score >= 4) {
        is_lightroom = 1;
    }
    return is_lightroom;
}

static int sqlite_select_final_extension(
    const char *path,
    int allow_lrcat,
    int allow_sqlite,
    int allow_db,
    const char **extension_out,
    const char **reject_reason_out
)
{
    int is_lrcat;

    if (extension_out == NULL || reject_reason_out == NULL) {
        return 0;
    }

    *extension_out = "sqlite";
    *reject_reason_out = "";
    is_lrcat = sqlite_path_looks_like_lightroom_catalog(path);
    if (is_lrcat) {
        if (allow_lrcat) {
            *extension_out = "lrcat";
            return 1;
        }
        if (allow_sqlite) {
            *extension_out = "sqlite";
            return 1;
        }
        if (allow_db) {
            *extension_out = "db";
            return 1;
        }
        *reject_reason_out = "lrcat_disabled_by_filter";
        return 0;
    }

    if (allow_sqlite) {
        *extension_out = "sqlite";
        return 1;
    }
    if (allow_db) {
        *extension_out = "db";
        return 1;
    }
    *reject_reason_out = "not_lightroom_catalog";
    return 0;
}

static int sqlite_finish_deferred_output(
    CarverOutput *output,
    long long abs_offset,
    const char *final_extension
)
{
    char final_path[sizeof(output->path)];

    if (output == NULL ||
        output->file == NULL ||
        final_extension == NULL ||
        final_extension[0] == '\0') {
        return 0;
    }

    if (fclose(output->file) != 0) {
        output->file = NULL;
        remove(output->path);
        return 0;
    }
    output->file = NULL;

    if (strcmp(final_extension, "sqlite") != 0) {
        if (!fs_backend_build_deferred_output_path(
                final_path,
                sizeof(final_path),
                abs_offset,
                APP_DEFAULT_UNIDENT_DIR,
                "recov",
                final_extension) ||
            !fs_backend_output_path_write_guard_allows(final_path)) {
            remove(output->path);
            return 0;
        }
        if (access(final_path, F_OK) == 0) {
            remove(output->path);
            return 0;
        }
        if (rename(output->path, final_path) != 0) {
            remove(output->path);
            return 0;
        }
        snprintf(output->path, sizeof(output->path), "%s", final_path);
    }

    (void)fs_backend_apply_output_owner_to_path(output->path);
    carver_output_note_deferred_completion(output->path, abs_offset);
    output->path[0] = '\0';
    return 1;
}

int carver_sqlite_streaming(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *resume_offset,
    int allow_lrcat,
    int allow_sqlite,
    int allow_db
)
{
    uint8_t header[SQLITE_HEADER_SIZE];
    uint8_t first_btree_page_type = 0U;
    SqliteHeaderInfo info;
    const char *reject_reason = "unknown";
    const char *final_extension = "sqlite";
    CarverOutput output = {0};

#define SQLITE_REJECT(reason, span) \
    do { \
        carver_audit_set_inline( \
            &g_sqlite_last_audit, \
            "rejected", \
            (reason), \
            carver_audit_span_from_u64((span))); \
        return 0; \
    } while (0)

    carver_sqlite_reset_last_audit();
    if (resume_offset != NULL) {
        *resume_offset = start_offset + 1U;
    }
    if (reader == NULL || resume_offset == NULL) {
        SQLITE_REJECT("invalid_input", 0U);
    }
    if (!allow_lrcat && !allow_sqlite && !allow_db) {
        SQLITE_REJECT("disabled_by_filter", 0U);
    }
    if (!read_stream_bytes(
            reader,
            (uint64_t)absolute_offset,
            header,
            sizeof(header))) {
        SQLITE_REJECT("source_eof_before_header", 0U);
    }
    if (!read_stream_bytes(
            reader,
            (uint64_t)absolute_offset + SQLITE_FIRST_BTREE_OFFSET,
            &first_btree_page_type,
            sizeof(first_btree_page_type))) {
        SQLITE_REJECT("source_eof_before_btree", 0U);
    }
    if (!sqlite_parse_header(header, first_btree_page_type, &info, &reject_reason)) {
        SQLITE_REJECT(reject_reason, 0U);
    }
    if (reader->source_size > 0U &&
        (uint64_t)absolute_offset >= reader->source_size) {
        SQLITE_REJECT("source_eof_before_start", info.confirmed_span);
    }
    if (reader->source_size > 0U &&
        info.confirmed_span > reader->source_size - (uint64_t)absolute_offset) {
        SQLITE_REJECT("source_eof_before_end", info.confirmed_span);
    }

    if (!carver_output_open_deferred(
            &output,
            (long long)absolute_offset,
            APP_DEFAULT_UNIDENT_DIR,
            "recov",
            "sqlite")) {
        SQLITE_REJECT("output_open_failed", info.confirmed_span);
    }
    if (!copy_stream_bytes(
            reader,
            output.file,
            (uint64_t)absolute_offset,
            info.confirmed_span)) {
        carver_output_abort(&output);
        SQLITE_REJECT("write_failed", info.confirmed_span);
    }
    if (fflush(output.file) != 0) {
        carver_output_abort(&output);
        SQLITE_REJECT("write_failed", info.confirmed_span);
    }

    if (!sqlite_select_final_extension(
            output.path,
            allow_lrcat,
            allow_sqlite,
            allow_db,
            &final_extension,
            &reject_reason)) {
        carver_output_abort(&output);
        SQLITE_REJECT(reject_reason, info.confirmed_span);
    }
    if (!sqlite_finish_deferred_output(
            &output,
            (long long)absolute_offset,
            final_extension)) {
        SQLITE_REJECT("finish_failed", info.confirmed_span);
    }

    compute_resume_offset_local(
        reader,
        (uint64_t)absolute_offset + info.confirmed_span,
        start_offset,
        resume_offset);
    carver_audit_set_inline(
        &g_sqlite_last_audit,
        "recovered",
        final_extension,
        carver_audit_span_from_u64(info.confirmed_span));
    return 1;

#undef SQLITE_REJECT
}
