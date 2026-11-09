#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L

#include "recovered_content_index.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char block[64];
    size_t block_used;
} ContentSha256;

typedef struct {
    sqlite3 *db;
    sqlite3_stmt *upsert;
    sqlite3_stmt *evidence_lookup;
    sqlite3_stmt *old_hash_lookup;
    uint64_t generation;
    const RecoveredContentIndexOptions *options;
    RecoveredContentIndexStats *stats;
    double deadline;
    uint64_t work_items;
    int stopped;
} ContentScanContext;

typedef struct {
    int available;
    char phase[32];
    uint64_t generation;
    uint64_t ledger_offset;
    uint64_t ledger_dev;
    uint64_t ledger_inode;
    uint64_t ledger_size;
    int64_t ledger_mtime_sec;
    int64_t ledger_mtime_nsec;
    uint64_t files_seen;
    uint64_t files_bytes;
    uint64_t client_artifacts_ignored;
    uint64_t directories_completed;
} ContentPersistentScanState;

#define CONTENT_TREE_BATCH_ENTRIES 256U
#define CONTENT_LEDGER_COMMIT_LINES 4096U
#define CONTENT_DIRECTORY_COMMIT_ENTRIES 4096U

static int content_is_client_artifact_name(const char *name)
{
    return name != NULL &&
           (strncmp(name, "._", 2U) == 0 || strcmp(name, ".DS_Store") == 0);
}

static int content_path_is_unidentified(const char *path)
{
    const char *cursor;
    if (path == NULL) return 0;
    for (cursor = path; *cursor != '\0'; ++cursor) {
        if (strncasecmp(cursor, "/Unidentified/", 14U) == 0 ||
            strncasecmp(cursor, "/unident/", 9U) == 0) return 1;
    }
    return 0;
}

static int content_lookup_recovery_evidence(
    ContentScanContext *context,
    const char *path,
    int *out_tracked,
    int64_t *out_offset)
{
    int result;
    if (context == NULL || context->evidence_lookup == NULL ||
        path == NULL || out_tracked == NULL || out_offset == NULL) return 0;
    *out_tracked = 0;
    *out_offset = -1;
    sqlite3_reset(context->evidence_lookup);
    sqlite3_clear_bindings(context->evidence_lookup);
    sqlite3_bind_text(context->evidence_lookup, 1, path, -1, SQLITE_TRANSIENT);
    result = sqlite3_step(context->evidence_lookup);
    if (result != SQLITE_ROW && result != SQLITE_DONE) return 0;
    *out_tracked = result == SQLITE_ROW;
    if (*out_tracked) *out_offset = sqlite3_column_int64(context->evidence_lookup, 0);
    return 1;
}

static uint32_t content_rotr32(uint32_t value, unsigned shift)
{
    return (value >> shift) | (value << (32U - shift));
}

static uint32_t content_be32(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void content_put_be32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)(value >> 24);
    p[1] = (unsigned char)(value >> 16);
    p[2] = (unsigned char)(value >> 8);
    p[3] = (unsigned char)value;
}

static void content_sha256_transform(ContentSha256 *sha)
{
    static const uint32_t k[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,
        0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,
        0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,
        0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,
        0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,
        0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,
        0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,
        0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,
        0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    uint32_t w[64];
    uint32_t a,b,c,d,e,f,g,h;
    size_t i;

    for (i = 0U; i < 16U; ++i) w[i] = content_be32(sha->block + i * 4U);
    for (; i < 64U; ++i) {
        uint32_t s0 = content_rotr32(w[i-15U],7U) ^
            content_rotr32(w[i-15U],18U) ^ (w[i-15U] >> 3U);
        uint32_t s1 = content_rotr32(w[i-2U],17U) ^
            content_rotr32(w[i-2U],19U) ^ (w[i-2U] >> 10U);
        w[i] = w[i-16U] + s0 + w[i-7U] + s1;
    }
    a=sha->state[0]; b=sha->state[1]; c=sha->state[2]; d=sha->state[3];
    e=sha->state[4]; f=sha->state[5]; g=sha->state[6]; h=sha->state[7];
    for (i = 0U; i < 64U; ++i) {
        uint32_t s1=content_rotr32(e,6U)^content_rotr32(e,11U)^content_rotr32(e,25U);
        uint32_t ch=(e&f)^((~e)&g);
        uint32_t t1=h+s1+ch+k[i]+w[i];
        uint32_t s0=content_rotr32(a,2U)^content_rotr32(a,13U)^content_rotr32(a,22U);
        uint32_t maj=(a&b)^(a&c)^(b&c);
        uint32_t t2=s0+maj;
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    sha->state[0]+=a; sha->state[1]+=b; sha->state[2]+=c; sha->state[3]+=d;
    sha->state[4]+=e; sha->state[5]+=f; sha->state[6]+=g; sha->state[7]+=h;
}

static void content_sha256_init(ContentSha256 *sha)
{
    static const uint32_t initial[8] = {
        0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
        0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U
    };
    memset(sha, 0, sizeof(*sha));
    memcpy(sha->state, initial, sizeof(initial));
}

static void content_sha256_update(ContentSha256 *sha, const void *data, size_t size)
{
    const unsigned char *p = (const unsigned char *)data;
    sha->bit_count += (uint64_t)size * 8U;
    while (size > 0U) {
        size_t take = 64U - sha->block_used;
        if (take > size) take = size;
        memcpy(sha->block + sha->block_used, p, take);
        sha->block_used += take; p += take; size -= take;
        if (sha->block_used == 64U) {
            content_sha256_transform(sha);
            sha->block_used = 0U;
        }
    }
}

static void content_sha256_final(ContentSha256 *sha, unsigned char out[32])
{
    uint64_t bits = sha->bit_count;
    size_t i;
    sha->block[sha->block_used++] = 0x80U;
    if (sha->block_used > 56U) {
        memset(sha->block + sha->block_used, 0, 64U - sha->block_used);
        content_sha256_transform(sha);
        sha->block_used = 0U;
    }
    memset(sha->block + sha->block_used, 0, 56U - sha->block_used);
    for (i = 0U; i < 8U; ++i)
        sha->block[63U-i] = (unsigned char)(bits >> (i*8U));
    content_sha256_transform(sha);
    for (i = 0U; i < 8U; ++i) content_put_be32(out + i*4U, sha->state[i]);
}

static int content_should_stop(const RecoveredContentIndexOptions *options)
{
    return options != NULL && options->stop_requested != NULL &&
           options->stop_requested(options->context);
}

static double content_monotonic_seconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0.0;
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

static int content_deadline_reached(double deadline)
{
    return deadline > 0.0 && content_monotonic_seconds() >= deadline;
}

static int content_scan_should_pause(ContentScanContext *context)
{
    if (context == NULL) return 0;
    if (content_should_stop(context->options)) {
        context->stopped = 1;
        return 1;
    }
    if (content_deadline_reached(context->deadline)) {
        if (context->stats != NULL) context->stats->budget_exhausted = 1;
        return 1;
    }
    if (context->options != NULL &&
        context->options->work_item_budget > 0U &&
        context->work_items >= context->options->work_item_budget) {
        if (context->stats != NULL) context->stats->budget_exhausted = 1;
        return 1;
    }
    return 0;
}

static void content_scan_note_work_item(ContentScanContext *context)
{
    if (context != NULL && context->work_items < UINT64_MAX) {
        context->work_items++;
    }
}

static int content_write_allowed(
    const RecoveredContentIndexOptions *options,
    const char *path)
{
    return options == NULL || options->path_write_allowed == NULL ||
           options->path_write_allowed(path, options->context);
}

static int content_finalize_path(
    const RecoveredContentIndexOptions *options,
    const char *path)
{
    return options == NULL || options->finalize_path == NULL ||
           options->finalize_path(path, options->context);
}

static int content_hash_file(
    const char *path,
    const RecoveredContentIndexOptions *options,
    double deadline,
    char hex[65],
    uint64_t *bytes_out)
{
    unsigned char buffer[256U * 1024U];
    unsigned char digest[32];
    static const char digits[] = "0123456789abcdef";
    ContentSha256 sha;
    uint64_t total = 0U;
    int fd;
    size_t i;

    fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    content_sha256_init(&sha);
    for (;;) {
        ssize_t got;
        if (content_should_stop(options) ||
            (deadline > 0.0 && content_monotonic_seconds() >= deadline)) {
            (void)close(fd);
            return -1;
        }
        got = read(fd, buffer, sizeof(buffer));
        if (got == 0) break;
        if (got < 0) {
            if (errno == EINTR) continue;
            (void)close(fd); return 0;
        }
        content_sha256_update(&sha, buffer, (size_t)got);
        total += (uint64_t)got;
    }
    if (close(fd) != 0) return 0;
    content_sha256_final(&sha, digest);
    for (i = 0U; i < 32U; ++i) {
        hex[i*2U] = digits[digest[i] >> 4];
        hex[i*2U+1U] = digits[digest[i] & 15U];
    }
    hex[64] = '\0';
    if (bytes_out != NULL) *bytes_out = total;
    return 1;
}

static int64_t content_mtime_nsec(const struct stat *status)
{
#if defined(__APPLE__)
    return status->st_mtimespec.tv_nsec;
#else
    return status->st_mtim.tv_nsec;
#endif
}

static int64_t content_parse_recov_offset(const char *path)
{
    const char *base = strrchr(path, '/');
    char *end = NULL;
    unsigned long long value;
    if (base == NULL) base = path; else base++;
    if (strncmp(base, "recov_", 6U) != 0) return -1;
    errno = 0;
    value = strtoull(base + 6U, &end, 10);
    return errno == 0 && end != base + 6U && (*end == '.' || *end == '_') &&
           value <= INT64_MAX ? (int64_t)value : -1;
}

static void content_write_tsv_field(FILE *file, const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    while (p != NULL && *p != '\0') {
        unsigned char ch = *p++;
        fputc(ch == '\t' || ch == '\r' || ch == '\n' ? ' ' : ch, file);
    }
}

static int content_exec(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static int content_load_scan_state(
    sqlite3 *db,
    ContentPersistentScanState *state)
{
    sqlite3_stmt *statement = NULL;
    int result;

    if (db == NULL || state == NULL) return 0;
    memset(state, 0, sizeof(*state));
    if (sqlite3_prepare_v2(
            db,
            "SELECT phase,generation,ledger_offset,ledger_dev,ledger_inode,"
            "ledger_size,ledger_mtime_sec,ledger_mtime_nsec,files_seen,"
            "files_bytes,client_artifacts_ignored,directories_completed "
            "FROM content_scan_state WHERE id=1",
            -1,
            &statement,
            NULL) != SQLITE_OK) {
        return 0;
    }
    result = sqlite3_step(statement);
    if (result == SQLITE_DONE) {
        sqlite3_finalize(statement);
        return 1;
    }
    if (result != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return 0;
    }
    snprintf(
        state->phase,
        sizeof(state->phase),
        "%s",
        sqlite3_column_text(statement, 0) != NULL
            ? (const char *)sqlite3_column_text(statement, 0)
            : "unknown"
    );
    state->generation = (uint64_t)sqlite3_column_int64(statement, 1);
    state->ledger_offset = (uint64_t)sqlite3_column_int64(statement, 2);
    state->ledger_dev = (uint64_t)sqlite3_column_int64(statement, 3);
    state->ledger_inode = (uint64_t)sqlite3_column_int64(statement, 4);
    state->ledger_size = (uint64_t)sqlite3_column_int64(statement, 5);
    state->ledger_mtime_sec = (int64_t)sqlite3_column_int64(statement, 6);
    state->ledger_mtime_nsec = (int64_t)sqlite3_column_int64(statement, 7);
    state->files_seen = (uint64_t)sqlite3_column_int64(statement, 8);
    state->files_bytes = (uint64_t)sqlite3_column_int64(statement, 9);
    state->client_artifacts_ignored =
        (uint64_t)sqlite3_column_int64(statement, 10);
    state->directories_completed =
        (uint64_t)sqlite3_column_int64(statement, 11);
    state->available = 1;
    sqlite3_finalize(statement);
    return 1;
}

static void content_ledger_signature(
    const struct stat *status,
    uint64_t *out_dev,
    uint64_t *out_inode,
    uint64_t *out_size,
    int64_t *out_mtime_sec,
    int64_t *out_mtime_nsec)
{
    if (out_dev != NULL) *out_dev = status != NULL ? (uint64_t)status->st_dev : 0U;
    if (out_inode != NULL) *out_inode = status != NULL ? (uint64_t)status->st_ino : 0U;
    if (out_size != NULL) {
        *out_size = status != NULL && status->st_size > 0
            ? (uint64_t)status->st_size
            : 0U;
    }
    if (out_mtime_sec != NULL) {
        *out_mtime_sec = status != NULL ? (int64_t)status->st_mtime : 0;
    }
    if (out_mtime_nsec != NULL) {
        *out_mtime_nsec = status != NULL ? content_mtime_nsec(status) : 0;
    }
}

static int content_scan_signature_matches(
    const ContentPersistentScanState *state,
    const struct stat *status)
{
    uint64_t dev = 0U, inode = 0U, size = 0U;
    int64_t mtime_sec = 0, mtime_nsec = 0;
    if (state == NULL || !state->available) return 0;
    content_ledger_signature(
        status, &dev, &inode, &size, &mtime_sec, &mtime_nsec);
    return state->ledger_dev == dev && state->ledger_inode == inode &&
           state->ledger_size == size && state->ledger_mtime_sec == mtime_sec &&
           state->ledger_mtime_nsec == mtime_nsec;
}

static int content_begin_new_snapshot(
    sqlite3 *db,
    const char *recovered_dir,
    uint64_t generation,
    const struct stat *ledger_status,
    ContentPersistentScanState *state)
{
    sqlite3_stmt *statement = NULL;
    uint64_t dev = 0U, inode = 0U, size = 0U;
    int64_t mtime_sec = 0, mtime_nsec = 0;
    const char *phase = ledger_status != NULL && ledger_status->st_size > 0
        ? "recovered_ledger"
        : "recovered_tree";
    int ok = 0;

    if (db == NULL || recovered_dir == NULL || state == NULL) return 0;
    content_ledger_signature(
        ledger_status, &dev, &inode, &size, &mtime_sec, &mtime_nsec);
    if (!content_exec(
            db,
            "BEGIN IMMEDIATE;"
            "DELETE FROM content_scan_files;"
            "DELETE FROM content_scan_dirs;"
            "DELETE FROM content_scan_entries;"
            "DELETE FROM content_scan_evidence;"
            "DELETE FROM content_candidate_sizes;"
            "DELETE FROM content_scan_state;")) {
        return 0;
    }
    if (sqlite3_prepare_v2(
            db,
            "INSERT INTO content_scan_state("
            "id,phase,generation,ledger_offset,ledger_dev,ledger_inode,"
            "ledger_size,ledger_mtime_sec,ledger_mtime_nsec,files_seen,"
            "files_bytes,client_artifacts_ignored,directories_completed) "
            "VALUES(1,?1,?2,0,?3,?4,?5,?6,?7,0,0,0,0)",
            -1,
            &statement,
            NULL) != SQLITE_OK) {
        goto done;
    }
    sqlite3_bind_text(statement, 1, phase, -1, SQLITE_STATIC);
    sqlite3_bind_int64(statement, 2, (sqlite3_int64)generation);
    sqlite3_bind_int64(statement, 3, (sqlite3_int64)dev);
    sqlite3_bind_int64(statement, 4, (sqlite3_int64)inode);
    sqlite3_bind_int64(statement, 5, (sqlite3_int64)size);
    sqlite3_bind_int64(statement, 6, (sqlite3_int64)mtime_sec);
    sqlite3_bind_int64(statement, 7, (sqlite3_int64)mtime_nsec);
    if (sqlite3_step(statement) != SQLITE_DONE) goto done;
    sqlite3_finalize(statement);
    statement = NULL;
    if (strcmp(phase, "recovered_tree") == 0) {
        if (sqlite3_prepare_v2(
                db,
                "INSERT INTO content_scan_dirs(path,enumerated,done) "
                "VALUES(?1,0,0)",
                -1,
                &statement,
                NULL) != SQLITE_OK) {
            goto done;
        }
        sqlite3_bind_text(statement, 1, recovered_dir, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) != SQLITE_DONE) goto done;
    }
    if (!content_exec(db, "COMMIT;")) goto done_no_rollback;
    ok = content_load_scan_state(db, state);
    goto done_no_rollback;

done:
    (void)content_exec(db, "ROLLBACK;");
done_no_rollback:
    sqlite3_finalize(statement);
    return ok;
}

static int content_save_ledger_progress(
    sqlite3 *db,
    uint64_t offset,
    const char *phase,
    const char *recovered_dir)
{
    sqlite3_stmt *statement = NULL;
    int ok = 0;
    if (sqlite3_prepare_v2(
            db,
            "UPDATE content_scan_state SET ledger_offset=?1,phase=?2 WHERE id=1",
            -1,
            &statement,
            NULL) != SQLITE_OK) {
        goto done;
    }
    sqlite3_bind_int64(statement, 1, (sqlite3_int64)offset);
    sqlite3_bind_text(statement, 2, phase, -1, SQLITE_STATIC);
    if (sqlite3_step(statement) != SQLITE_DONE) goto done;
    sqlite3_finalize(statement);
    statement = NULL;
    if (strcmp(phase, "recovered_tree") == 0) {
        if (sqlite3_prepare_v2(
                db,
                "INSERT OR IGNORE INTO content_scan_dirs(path,enumerated,done) "
                "VALUES(?1,0,0)",
                -1,
                &statement,
                NULL) != SQLITE_OK) {
            goto done;
        }
        sqlite3_bind_text(statement, 1, recovered_dir, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(statement) != SQLITE_DONE) goto done;
    }
    ok = 1;
done:
    sqlite3_finalize(statement);
    return ok;
}

static int content_scan_ledger_slice(
    ContentScanContext *context,
    ContentPersistentScanState *state,
    const char *ledger_path,
    const char *recovered_dir)
{
    FILE *file = NULL;
    sqlite3_stmt *insert = NULL;
    char *line = NULL;
    size_t line_capacity = 0U;
    uint64_t lines_in_transaction = 0U;
    uint64_t offset = state->ledger_offset;
    int transaction_open = 0;
    int ok = 0;

    file = fopen(ledger_path, "r");
    if (file == NULL) {
        if (errno != ENOENT || state->ledger_size != 0U) goto done;
        if (!content_exec(context->db, "BEGIN IMMEDIATE;")) goto done;
        transaction_open = 1;
        if (!content_save_ledger_progress(
                context->db, 0U, "recovered_tree", recovered_dir) ||
            !content_exec(context->db, "COMMIT;")) {
            goto done;
        }
        transaction_open = 0;
        snprintf(state->phase, sizeof(state->phase), "%s", "recovered_tree");
        ok = 1;
        goto done;
    }
    if (fseeko(file, (off_t)offset, SEEK_SET) != 0 ||
        !content_exec(context->db, "BEGIN IMMEDIATE;")) {
        goto done;
    }
    transaction_open = 1;
    if (sqlite3_prepare_v2(
            context->db,
            "INSERT INTO content_scan_evidence(path,abs_offset) VALUES(?1,?2) "
            "ON CONFLICT(path) DO UPDATE SET abs_offset=excluded.abs_offset",
            -1,
            &insert,
            NULL) != SQLITE_OK) {
        goto done;
    }
    while (getline(&line, &line_capacity, file) >= 0) {
        char *first_tab;
        char *second_tab;
        char *end = NULL;
        long long recovered_offset;
        off_t next_offset;

        first_tab = strchr(line, '\t');
        if (first_tab != NULL) {
            *first_tab = '\0';
            errno = 0;
            recovered_offset = strtoll(line, &end, 10);
            second_tab = strchr(first_tab + 1U, '\t');
            if (errno == 0 && end != line && *end == '\0' &&
                recovered_offset >= 0 && second_tab != NULL) {
                *second_tab = '\0';
                if (first_tab[1] != '\0') {
                    sqlite3_reset(insert);
                    sqlite3_clear_bindings(insert);
                    sqlite3_bind_text(
                        insert, 1, first_tab + 1U, -1, SQLITE_TRANSIENT);
                    sqlite3_bind_int64(
                        insert, 2, (sqlite3_int64)recovered_offset);
                    if (sqlite3_step(insert) != SQLITE_DONE) goto done;
                }
            }
        }
        next_offset = ftello(file);
        if (next_offset < 0) goto done;
        offset = (uint64_t)next_offset;
        content_scan_note_work_item(context);
        lines_in_transaction++;
        if (lines_in_transaction >= CONTENT_LEDGER_COMMIT_LINES) {
            if (!content_save_ledger_progress(
                    context->db, offset, "recovered_ledger", recovered_dir) ||
                !content_exec(context->db, "COMMIT;")) {
                goto done;
            }
            transaction_open = 0;
            state->ledger_offset = offset;
            context->stats->ledger_bytes_consumed = offset;
            if (content_scan_should_pause(context)) {
                ok = 1;
                goto done;
            }
            if (!content_exec(context->db, "BEGIN IMMEDIATE;")) goto done;
            transaction_open = 1;
            lines_in_transaction = 0U;
        }
        if (content_scan_should_pause(context)) break;
    }
    if (ferror(file)) goto done;
    sqlite3_finalize(insert);
    insert = NULL;
    if (context->stats->budget_exhausted || context->stopped) {
        if (!content_save_ledger_progress(
                context->db, offset, "recovered_ledger", recovered_dir) ||
            !content_exec(context->db, "COMMIT;")) {
            goto done;
        }
        transaction_open = 0;
        state->ledger_offset = offset;
        context->stats->ledger_bytes_consumed = offset;
        ok = 1;
        goto done;
    }
    if (!content_save_ledger_progress(
            context->db, offset, "recovered_tree", recovered_dir) ||
        !content_exec(context->db, "COMMIT;")) {
        goto done;
    }
    transaction_open = 0;
    state->ledger_offset = offset;
    context->stats->ledger_bytes_consumed = offset;
    snprintf(state->phase, sizeof(state->phase), "%s", "recovered_tree");
    ok = 1;

done:
    if (transaction_open) (void)content_exec(context->db, "ROLLBACK;");
    sqlite3_finalize(insert);
    if (file != NULL) fclose(file);
    free(line);
    return ok;
}

static int content_get_current_directory(
    sqlite3 *db,
    char path[PATH_MAX],
    int *out_enumerated,
    int *out_found)
{
    sqlite3_stmt *statement = NULL;
    int result;
    *out_found = 0;
    *out_enumerated = 0;
    if (sqlite3_prepare_v2(
            db,
            "SELECT path,enumerated FROM content_scan_dirs WHERE done=0 "
            "ORDER BY path LIMIT 1",
            -1,
            &statement,
            NULL) != SQLITE_OK) {
        return 0;
    }
    result = sqlite3_step(statement);
    if (result == SQLITE_ROW) {
        const char *value = (const char *)sqlite3_column_text(statement, 0);
        if (value == NULL ||
            snprintf(path, PATH_MAX, "%s", value) >= PATH_MAX) {
            sqlite3_finalize(statement);
            return 0;
        }
        *out_enumerated = sqlite3_column_int(statement, 1) != 0;
        *out_found = 1;
    } else if (result != SQLITE_DONE) {
        sqlite3_finalize(statement);
        return 0;
    }
    sqlite3_finalize(statement);
    return 1;
}

static int content_enumerate_directory(
    ContentScanContext *context,
    const char *directory)
{
    DIR *dir = NULL;
    struct dirent *entry;
    sqlite3_stmt *insert = NULL;
    sqlite3_stmt *mark = NULL;
    uint64_t entries_in_transaction = 0U;
    int transaction_open = 0;
    int read_error = 0;
    int ok = 0;

    dir = opendir(directory);
    if (dir == NULL && errno != ENOENT) return 0;
    if (!content_exec(context->db, "BEGIN IMMEDIATE;")) goto done;
    transaction_open = 1;
    if (dir == NULL) goto mark_enumerated;
    if (sqlite3_prepare_v2(
            context->db,
            "INSERT OR IGNORE INTO content_scan_entries(parent,name,path,processed) "
            "VALUES(?1,?2,?3,0)",
            -1,
            &insert,
            NULL) != SQLITE_OK) {
        goto done;
    }
    errno = 0;
    while ((entry = readdir(dir)) != NULL) {
        char path[PATH_MAX];
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) >=
            (int)sizeof(path)) {
            continue;
        }
        sqlite3_reset(insert);
        sqlite3_clear_bindings(insert);
        sqlite3_bind_text(insert, 1, directory, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert, 2, entry->d_name, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(insert, 3, path, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(insert) != SQLITE_DONE) goto done;
        entries_in_transaction++;
        if (entries_in_transaction >= CONTENT_DIRECTORY_COMMIT_ENTRIES) {
            if (!content_exec(context->db, "COMMIT;")) goto done;
            transaction_open = 0;
            if (content_should_stop(context->options)) {
                context->stopped = 1;
                ok = 1;
                goto done;
            }
            if (!content_exec(context->db, "BEGIN IMMEDIATE;")) goto done;
            transaction_open = 1;
            entries_in_transaction = 0U;
        }
        if (content_should_stop(context->options)) {
            context->stopped = 1;
            break;
        }
        errno = 0;
    }
    read_error = errno;
    if (context->stopped) {
        if (!content_exec(context->db, "COMMIT;")) goto done;
        transaction_open = 0;
        ok = 1;
        goto done;
    }
    if (read_error != 0) goto done;

mark_enumerated:
    sqlite3_finalize(insert);
    insert = NULL;
    if (sqlite3_prepare_v2(
            context->db,
            "UPDATE content_scan_dirs SET enumerated=1 WHERE path=?1",
            -1,
            &mark,
            NULL) != SQLITE_OK) {
        goto done;
    }
    sqlite3_bind_text(mark, 1, directory, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(mark) != SQLITE_DONE ||
        !content_exec(context->db, "COMMIT;")) {
        goto done;
    }
    transaction_open = 0;
    ok = 1;

done:
    if (transaction_open) (void)content_exec(context->db, "ROLLBACK;");
    sqlite3_finalize(insert);
    sqlite3_finalize(mark);
    if (dir != NULL) closedir(dir);
    return ok;
}

static int content_reusable_hash_for_file(
    ContentScanContext *context,
    const char *path,
    const struct stat *status,
    int64_t offset,
    char hash[65])
{
    int result;
    int old_has_offset;
    int identity_matches;
    const char *old_hash;

    hash[0] = '\0';
    sqlite3_reset(context->old_hash_lookup);
    sqlite3_clear_bindings(context->old_hash_lookup);
    sqlite3_bind_text(context->old_hash_lookup, 1, path, -1, SQLITE_TRANSIENT);
    result = sqlite3_step(context->old_hash_lookup);
    if (result == SQLITE_DONE) return 1;
    if (result != SQLITE_ROW) return 0;
    old_has_offset = sqlite3_column_type(context->old_hash_lookup, 5) != SQLITE_NULL;
    identity_matches =
        sqlite3_column_int64(context->old_hash_lookup, 0) == status->st_size &&
        sqlite3_column_int64(context->old_hash_lookup, 1) == status->st_mtime &&
        sqlite3_column_int64(context->old_hash_lookup, 2) ==
            content_mtime_nsec(status) &&
        ((old_has_offset && offset >= 0 &&
          sqlite3_column_int64(context->old_hash_lookup, 5) == offset) ||
         (!old_has_offset && offset < 0 &&
          sqlite3_column_int64(context->old_hash_lookup, 3) ==
              (sqlite3_int64)status->st_dev &&
          sqlite3_column_int64(context->old_hash_lookup, 4) ==
              (sqlite3_int64)status->st_ino));
    old_hash = (const char *)sqlite3_column_text(context->old_hash_lookup, 6);
    if (identity_matches && old_hash != NULL) {
        snprintf(hash, 65U, "%s", old_hash);
    }
    return 1;
}

static int content_process_directory_entries(
    ContentScanContext *context,
    ContentPersistentScanState *state,
    const char *directory)
{
    char *paths[CONTENT_TREE_BATCH_ENTRIES] = {0};
    sqlite3_stmt *select = NULL;
    sqlite3_stmt *mark = NULL;
    sqlite3_stmt *add_directory = NULL;
    sqlite3_stmt *save_counts = NULL;
    size_t path_count = 0U;
    size_t index;
    uint64_t files_added = 0U;
    uint64_t bytes_added = 0U;
    uint64_t artifacts_added = 0U;
    int transaction_open = 0;
    int ok = 0;

    if (sqlite3_prepare_v2(
            context->db,
            "SELECT path FROM content_scan_entries WHERE parent=?1 "
            "ORDER BY name LIMIT ?2",
            -1,
            &select,
            NULL) != SQLITE_OK) {
        goto done;
    }
    sqlite3_bind_text(select, 1, directory, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(select, 2, (int)CONTENT_TREE_BATCH_ENTRIES);
    while (path_count < CONTENT_TREE_BATCH_ENTRIES) {
        int result = sqlite3_step(select);
        const char *path;
        if (result == SQLITE_DONE) break;
        if (result != SQLITE_ROW) goto done;
        path = (const char *)sqlite3_column_text(select, 0);
        if (path == NULL || (paths[path_count] = strdup(path)) == NULL) goto done;
        path_count++;
    }
    sqlite3_finalize(select);
    select = NULL;
    if (path_count == 0U) {
        if (!content_exec(context->db, "BEGIN IMMEDIATE;")) goto done;
        transaction_open = 1;
        if (sqlite3_prepare_v2(
                context->db,
                "UPDATE content_scan_dirs SET done=1 WHERE path=?1",
                -1,
                &mark,
                NULL) != SQLITE_OK) {
            goto done;
        }
        sqlite3_bind_text(mark, 1, directory, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(mark) != SQLITE_DONE ||
            sqlite3_prepare_v2(
                context->db,
                "UPDATE content_scan_state SET directories_completed="
                "directories_completed+1 WHERE id=1",
                -1,
                &save_counts,
                NULL) != SQLITE_OK ||
            sqlite3_step(save_counts) != SQLITE_DONE ||
            !content_exec(context->db, "COMMIT;")) {
            goto done;
        }
        transaction_open = 0;
        state->directories_completed++;
        context->stats->directories_completed = state->directories_completed;
        ok = 1;
        goto done;
    }

    if (!content_exec(context->db, "BEGIN IMMEDIATE;")) goto done;
    transaction_open = 1;
    if (sqlite3_prepare_v2(
            context->db,
            "DELETE FROM content_scan_entries WHERE path=?1",
            -1,
            &mark,
            NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(
            context->db,
            "INSERT OR IGNORE INTO content_scan_dirs(path,enumerated,done) "
            "VALUES(?1,0,0)",
            -1,
            &add_directory,
            NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(
            context->db,
            "INSERT INTO content_scan_files("
            "path,size,mtime_sec,mtime_nsec,dev,inode,abs_offset,seen,sha256) "
            "VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) "
            "ON CONFLICT(path) DO UPDATE SET size=excluded.size,"
            "mtime_sec=excluded.mtime_sec,mtime_nsec=excluded.mtime_nsec,"
            "dev=excluded.dev,inode=excluded.inode,abs_offset=excluded.abs_offset,"
            "seen=excluded.seen,sha256=excluded.sha256",
            -1,
            &context->upsert,
            NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(
            context->db,
            "SELECT abs_offset FROM content_scan_evidence WHERE path=?1",
            -1,
            &context->evidence_lookup,
            NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(
            context->db,
            "SELECT size,mtime_sec,mtime_nsec,dev,inode,abs_offset,sha256 "
            "FROM files WHERE path=?1",
            -1,
            &context->old_hash_lookup,
            NULL) != SQLITE_OK) {
        goto done;
    }
    for (index = 0U; index < path_count; ++index) {
        struct stat status;
        const char *base;
        int tracked = 0;
        int64_t offset = -1;
        char reusable_hash[65];

        if (content_scan_should_pause(context)) break;
        if (lstat(paths[index], &status) != 0) {
            if (errno != ENOENT) goto done;
        } else if (S_ISDIR(status.st_mode)) {
            sqlite3_reset(add_directory);
            sqlite3_clear_bindings(add_directory);
            sqlite3_bind_text(
                add_directory, 1, paths[index], -1, SQLITE_TRANSIENT);
            if (sqlite3_step(add_directory) != SQLITE_DONE) goto done;
        } else if (S_ISREG(status.st_mode) && status.st_size > 0) {
            if (!content_lookup_recovery_evidence(
                    context, paths[index], &tracked, &offset)) {
                goto done;
            }
            base = strrchr(paths[index], '/');
            base = base != NULL ? base + 1U : paths[index];
            if (content_is_client_artifact_name(base) && !tracked) {
                artifacts_added++;
            } else {
                if (!tracked) offset = content_parse_recov_offset(paths[index]);
                if (!content_reusable_hash_for_file(
                        context, paths[index], &status, offset, reusable_hash)) {
                    goto done;
                }
                sqlite3_reset(context->upsert);
                sqlite3_clear_bindings(context->upsert);
                sqlite3_bind_text(
                    context->upsert, 1, paths[index], -1, SQLITE_TRANSIENT);
                sqlite3_bind_int64(context->upsert, 2, status.st_size);
                sqlite3_bind_int64(context->upsert, 3, status.st_mtime);
                sqlite3_bind_int64(
                    context->upsert, 4, content_mtime_nsec(&status));
                sqlite3_bind_int64(
                    context->upsert, 5, (sqlite3_int64)status.st_dev);
                sqlite3_bind_int64(
                    context->upsert, 6, (sqlite3_int64)status.st_ino);
                if (offset >= 0) {
                    sqlite3_bind_int64(context->upsert, 7, offset);
                } else {
                    sqlite3_bind_null(context->upsert, 7);
                }
                sqlite3_bind_int64(
                    context->upsert, 8, (sqlite3_int64)context->generation);
                if (reusable_hash[0] != '\0') {
                    sqlite3_bind_text(
                        context->upsert, 9, reusable_hash, -1, SQLITE_TRANSIENT);
                } else {
                    sqlite3_bind_null(context->upsert, 9);
                }
                if (sqlite3_step(context->upsert) != SQLITE_DONE) goto done;
                files_added++;
                bytes_added += (uint64_t)status.st_size;
            }
        }
        sqlite3_reset(mark);
        sqlite3_clear_bindings(mark);
        sqlite3_bind_text(mark, 1, paths[index], -1, SQLITE_TRANSIENT);
        if (sqlite3_step(mark) != SQLITE_DONE) goto done;
        content_scan_note_work_item(context);
    }
    sqlite3_finalize(context->upsert);
    context->upsert = NULL;
    sqlite3_finalize(context->evidence_lookup);
    context->evidence_lookup = NULL;
    sqlite3_finalize(context->old_hash_lookup);
    context->old_hash_lookup = NULL;
    if (sqlite3_prepare_v2(
            context->db,
            "UPDATE content_scan_state SET files_seen=files_seen+?1,"
            "files_bytes=files_bytes+?2,client_artifacts_ignored="
            "client_artifacts_ignored+?3 WHERE id=1",
            -1,
            &save_counts,
            NULL) != SQLITE_OK) {
        goto done;
    }
    sqlite3_bind_int64(save_counts, 1, (sqlite3_int64)files_added);
    sqlite3_bind_int64(save_counts, 2, (sqlite3_int64)bytes_added);
    sqlite3_bind_int64(save_counts, 3, (sqlite3_int64)artifacts_added);
    if (sqlite3_step(save_counts) != SQLITE_DONE ||
        !content_exec(context->db, "COMMIT;")) {
        goto done;
    }
    transaction_open = 0;
    state->files_seen += files_added;
    state->files_bytes += bytes_added;
    state->client_artifacts_ignored += artifacts_added;
    context->stats->files_seen = state->files_seen;
    context->stats->files_bytes = state->files_bytes;
    context->stats->client_artifacts_ignored =
        state->client_artifacts_ignored;
    context->stats->files_added_this_slice += files_added;
    ok = 1;

done:
    if (transaction_open) (void)content_exec(context->db, "ROLLBACK;");
    sqlite3_finalize(select);
    sqlite3_finalize(mark);
    sqlite3_finalize(add_directory);
    sqlite3_finalize(save_counts);
    sqlite3_finalize(context->upsert);
    context->upsert = NULL;
    sqlite3_finalize(context->evidence_lookup);
    context->evidence_lookup = NULL;
    sqlite3_finalize(context->old_hash_lookup);
    context->old_hash_lookup = NULL;
    for (index = 0U; index < path_count; ++index) free(paths[index]);
    return ok;
}

static int content_count_pending_directories(sqlite3 *db, uint64_t *out_count)
{
    sqlite3_stmt *statement = NULL;
    int ok = sqlite3_prepare_v2(
        db,
        "SELECT count(*) FROM content_scan_dirs WHERE done=0",
        -1,
        &statement,
        NULL) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW;
    if (ok && out_count != NULL) {
        *out_count = (uint64_t)sqlite3_column_int64(statement, 0);
    }
    sqlite3_finalize(statement);
    return ok;
}

static int content_scan_tree_slice(
    ContentScanContext *context,
    ContentPersistentScanState *state)
{
    for (;;) {
        char directory[PATH_MAX];
        int enumerated = 0;
        int found = 0;
        if (content_scan_should_pause(context)) break;
        if (!content_get_current_directory(
                context->db, directory, &enumerated, &found)) {
            return 0;
        }
        if (!found) {
            if (!content_exec(context->db, "BEGIN IMMEDIATE;") ||
                !content_exec(
                    context->db,
                    "UPDATE content_scan_state SET phase='snapshot_finalize' "
                    "WHERE id=1; COMMIT;")) {
                (void)content_exec(context->db, "ROLLBACK;");
                return 0;
            }
            snprintf(
                state->phase, sizeof(state->phase), "%s", "snapshot_finalize");
            break;
        }
        if (!enumerated &&
            !content_enumerate_directory(context, directory)) {
            return 0;
        }
        if (context->stats->budget_exhausted || context->stopped) break;
        if (!content_process_directory_entries(context, state, directory)) {
            return 0;
        }
    }
    return content_count_pending_directories(
        context->db, &context->stats->pending_directories);
}

static int content_write_catalog_duplicate_evidence(
    const char *state_dir,
    sqlite3 *db,
    const RecoveredContentIndexOptions *options,
    RecoveredContentIndexStats *stats,
    double deadline,
    int *out_paused)
{
    char path[PATH_MAX], temp_path[PATH_MAX];
    sqlite3_stmt *groups = NULL;
    sqlite3_stmt *canonical = NULL;
    sqlite3_stmt *duplicates = NULL;
    FILE *file = NULL;
    int ok = 0;

    if (out_paused != NULL) *out_paused = 0;

    if (snprintf(path, sizeof(path), "%s/exact_catalog_duplicates.tsv", state_dir) >=
            (int)sizeof(path) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp.%ld", path, (long)getpid()) >=
            (int)sizeof(temp_path) ||
        !content_write_allowed(options, temp_path)) return 0;
    file = fopen(temp_path, "w");
    if (file == NULL) goto done;
    fprintf(file,
        "sha256\tsize\tcanonical_offset\tduplicate_offset\toffset_relation\t"
        "canonical_path\tduplicate_path\tclassification\n");
    if (sqlite3_prepare_v2(db,
            "SELECT sha256,size FROM files WHERE sha256 IS NOT NULL "
            "GROUP BY sha256,size HAVING "
            "max(instr(lower(path),'/unidentified/')>0 OR instr(lower(path),'/unident/')>0)>0 AND "
            "max(NOT (instr(lower(path),'/unidentified/')>0 OR instr(lower(path),'/unident/')>0))>0 "
            "ORDER BY size DESC,sha256",
            -1, &groups, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
            "SELECT path,abs_offset FROM files WHERE sha256=?1 AND size=?2 AND "
            "NOT (instr(lower(path),'/unidentified/')>0 OR instr(lower(path),'/unident/')>0) ORDER BY "
            "CASE WHEN instr(path,'/recov_')=0 THEN 0 ELSE 1 END,length(path),path LIMIT 1",
            -1, &canonical, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
            "SELECT path,abs_offset FROM files WHERE sha256=?1 AND size=?2 AND "
            "(instr(lower(path),'/unidentified/')>0 OR instr(lower(path),'/unident/')>0) ORDER BY path",
            -1, &duplicates, NULL) != SQLITE_OK) goto done;
    while (sqlite3_step(groups) == SQLITE_ROW) {
        const char *hash = (const char *)sqlite3_column_text(groups, 0);
        sqlite3_int64 size = sqlite3_column_int64(groups, 1);
        const char *canonical_path;
        sqlite3_int64 canonical_offset = 0;
        int canonical_has_offset;

        if (content_should_stop(options) || content_deadline_reached(deadline)) {
            if (out_paused != NULL) *out_paused = 1;
            goto done;
        }

        sqlite3_reset(canonical); sqlite3_clear_bindings(canonical);
        sqlite3_bind_text(canonical, 1, hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(canonical, 2, size);
        if (sqlite3_step(canonical) != SQLITE_ROW) goto done;
        canonical_path = (const char *)sqlite3_column_text(canonical, 0);
        canonical_has_offset = sqlite3_column_type(canonical, 1) != SQLITE_NULL;
        if (canonical_has_offset) canonical_offset = sqlite3_column_int64(canonical, 1);
        stats->catalog_duplicate_groups++;

        sqlite3_reset(duplicates); sqlite3_clear_bindings(duplicates);
        sqlite3_bind_text(duplicates, 1, hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(duplicates, 2, size);
        while (sqlite3_step(duplicates) == SQLITE_ROW) {
            const char *duplicate_path =
                (const char *)sqlite3_column_text(duplicates, 0);
            int duplicate_has_offset =
                sqlite3_column_type(duplicates, 1) != SQLITE_NULL;
            sqlite3_int64 duplicate_offset = duplicate_has_offset
                ? sqlite3_column_int64(duplicates, 1) : 0;
            const char *relation = "unknown";
            if (content_should_stop(options) ||
                content_deadline_reached(deadline)) {
                if (out_paused != NULL) *out_paused = 1;
                goto done;
            }
            if (canonical_has_offset && duplicate_has_offset) {
                relation = canonical_offset == duplicate_offset
                    ? "same_physical_start" : "distinct_physical_occurrence";
            }
            fprintf(file, "%s\t%lld\t", hash, (long long)size);
            if (canonical_has_offset) fprintf(file, "%lld\t", (long long)canonical_offset);
            else fputc('\t', file);
            if (duplicate_has_offset) fprintf(file, "%lld\t", (long long)duplicate_offset);
            else fputc('\t', file);
            fprintf(file, "%s\t", relation);
            content_write_tsv_field(file, canonical_path);
            fputc('\t', file);
            content_write_tsv_field(file, duplicate_path);
            fprintf(file, "\texact_duplicate_of_named_catalog_file\n");
            stats->catalog_duplicate_files++;
            stats->catalog_duplicate_bytes += (uint64_t)size;
        }
    }
    if (fclose(file) != 0) { file = NULL; goto done; }
    file = NULL;
    if (rename(temp_path, path) != 0 || !content_finalize_path(options, path)) goto done;
    ok = 1;
done:
    if (file != NULL) fclose(file);
    sqlite3_finalize(groups);
    sqlite3_finalize(canonical);
    sqlite3_finalize(duplicates);
    if (!ok) unlink(temp_path);
    return ok;
}

static int content_write_checkpoint_status(
    const char *state_dir,
    const RecoveredContentIndexOptions *options,
    const RecoveredContentIndexStats *stats,
    const char *phase,
    int snapshot_committed)
{
    char status[PATH_MAX];
    char status_temp[PATH_MAX];
    FILE *file = NULL;
    int ok = 0;

    if (state_dir == NULL || stats == NULL ||
        snprintf(status, sizeof(status), "%s/duplicate_status.txt", state_dir) >=
            (int)sizeof(status) ||
        snprintf(status_temp, sizeof(status_temp), "%s.tmp.%ld", status,
                 (long)getpid()) >= (int)sizeof(status_temp) ||
        !content_write_allowed(options, status_temp)) {
        return 0;
    }

    file = fopen(status_temp, "w");
    if (file == NULL) return 0;
    fprintf(
        file,
        "format_version=3\nscheduler=customer_media_cross_class_v1\n"
        "status=checkpoint\ncheckpoint_phase=%s\n"
        "snapshot_preserved=1\nsnapshot_committed=%d\n"
        "checkpoint_resumed=%d\ngeneration=%llu\n"
        "files_seen_before_slice=%llu\nfiles_added_this_slice=%llu\n"
        "files_seen=%llu\n"
        "files_bytes=%llu\nclient_artifacts_ignored=%llu\n"
        "ledger_bytes_consumed=%llu\ndirectories_completed=%llu\n"
        "pending_directories=%llu\n"
        "candidate_files=%llu\ncross_class_candidate_files=%llu\n"
        "photo_candidate_files=%llu\nfiles_hashed_now=%llu\n"
        "hashes_reused=%llu\nhash_failures=%llu\nbytes_hashed_now=%llu\n"
        "duplicate_groups=%llu\nduplicate_occurrences=%llu\n"
        "redundant_copies=%llu\nredundant_bytes=%llu\n"
        "catalog_duplicate_groups=%llu\ncatalog_duplicate_files=%llu\n"
        "catalog_duplicate_bytes=%llu\nbudget_exhausted=%d\n"
        "seconds_total=%.6f\n",
        phase != NULL && phase[0] != '\0' ? phase : "unknown",
        snapshot_committed ? 1 : 0,
        stats->checkpoint_resumed,
        (unsigned long long)stats->generation,
        (unsigned long long)stats->files_seen_before_slice,
        (unsigned long long)stats->files_added_this_slice,
        (unsigned long long)stats->files_seen,
        (unsigned long long)stats->files_bytes,
        (unsigned long long)stats->client_artifacts_ignored,
        (unsigned long long)stats->ledger_bytes_consumed,
        (unsigned long long)stats->directories_completed,
        (unsigned long long)stats->pending_directories,
        (unsigned long long)stats->candidate_files,
        (unsigned long long)stats->cross_class_candidate_files,
        (unsigned long long)stats->photo_candidate_files,
        (unsigned long long)stats->files_hashed_now,
        (unsigned long long)stats->hashes_reused,
        (unsigned long long)stats->hash_failures,
        (unsigned long long)stats->bytes_hashed_now,
        (unsigned long long)stats->duplicate_groups,
        (unsigned long long)stats->duplicate_occurrences,
        (unsigned long long)stats->redundant_copies,
        (unsigned long long)stats->redundant_bytes,
        (unsigned long long)stats->catalog_duplicate_groups,
        (unsigned long long)stats->catalog_duplicate_files,
        (unsigned long long)stats->catalog_duplicate_bytes,
        stats->budget_exhausted,
        stats->seconds_total
    );
    if (fclose(file) != 0) {
        file = NULL;
        goto done;
    }
    file = NULL;
    if (rename(status_temp, status) != 0 ||
        !content_finalize_path(options, status)) {
        goto done;
    }
    ok = 1;

done:
    if (file != NULL) fclose(file);
    if (!ok) unlink(status_temp);
    return ok;
}

static int content_write_outputs(
    const char *state_dir,
    sqlite3 *db,
    const RecoveredContentIndexOptions *options,
    RecoveredContentIndexStats *stats,
    double deadline,
    int *out_paused)
{
    char plan[PATH_MAX], plan_temp[PATH_MAX], status[PATH_MAX], status_temp[PATH_MAX];
    sqlite3_stmt *groups = NULL;
    sqlite3_stmt *members = NULL;
    FILE *plan_file = NULL;
    FILE *status_file = NULL;
    uint64_t group_id = 0U;
    int ok = 0;

    if (out_paused != NULL) *out_paused = 0;

    if (snprintf(plan, sizeof(plan), "%s/duplicate_plan.tsv", state_dir) >= (int)sizeof(plan) ||
        snprintf(plan_temp, sizeof(plan_temp), "%s.tmp.%ld", plan, (long)getpid()) >= (int)sizeof(plan_temp) ||
        snprintf(status, sizeof(status), "%s/duplicate_status.txt", state_dir) >= (int)sizeof(status) ||
        snprintf(status_temp, sizeof(status_temp), "%s.tmp.%ld", status, (long)getpid()) >= (int)sizeof(status_temp) ||
        !content_write_allowed(options, plan_temp) || !content_write_allowed(options, status_temp)) return 0;
    plan_file = fopen(plan_temp, "w");
    if (plan_file == NULL) goto done;
    fprintf(plan_file, "group_id\tsha256\tsize\tcopies\tcanonical\tabs_offset\tpath_class\tpath\n");
    if (sqlite3_prepare_v2(db,
            "SELECT sha256,size,count(*) FROM files WHERE sha256 IS NOT NULL "
            "GROUP BY sha256,size HAVING count(*)>1 ORDER BY size DESC,sha256", -1,
            &groups, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db,
            "SELECT path,abs_offset FROM files WHERE sha256=?1 AND size=?2 "
            "ORDER BY CASE WHEN NOT (instr(lower(path),'/unidentified/')>0 OR "
            "instr(lower(path),'/unident/')>0) THEN 0 ELSE 1 END,"
            "CASE WHEN instr(path,'/recov_')=0 THEN 0 ELSE 1 END,length(path),path", -1,
            &members, NULL) != SQLITE_OK) goto done;
    while (sqlite3_step(groups) == SQLITE_ROW) {
        const char *hash = (const char *)sqlite3_column_text(groups, 0);
        sqlite3_int64 size = sqlite3_column_int64(groups, 1);
        sqlite3_int64 copies = sqlite3_column_int64(groups, 2);
        int member_index = 0;
        if (content_should_stop(options) || content_deadline_reached(deadline)) {
            if (out_paused != NULL) *out_paused = 1;
            goto done;
        }
        group_id++;
        stats->duplicate_groups++;
        stats->duplicate_occurrences += (uint64_t)copies;
        stats->redundant_copies += (uint64_t)(copies - 1);
        stats->redundant_bytes += (uint64_t)(copies - 1) * (uint64_t)size;
        sqlite3_reset(members); sqlite3_clear_bindings(members);
        sqlite3_bind_text(members, 1, hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(members, 2, size);
        while (sqlite3_step(members) == SQLITE_ROW) {
            const char *path = (const char *)sqlite3_column_text(members, 0);
            const char *path_class = content_path_is_unidentified(path)
                ? "unidentified" : "named_or_contextual";
            if (content_should_stop(options) ||
                content_deadline_reached(deadline)) {
                if (out_paused != NULL) *out_paused = 1;
                goto done;
            }
            fprintf(plan_file, "%llu\t%s\t%lld\t%lld\t%d\t",
                    (unsigned long long)group_id, hash, (long long)size,
                    (long long)copies, member_index == 0 ? 1 : 0);
            if (sqlite3_column_type(members, 1) == SQLITE_NULL) fputc('\t', plan_file);
            else fprintf(plan_file, "%lld\t", (long long)sqlite3_column_int64(members, 1));
            fprintf(plan_file, "%s\t", path_class);
            content_write_tsv_field(plan_file, path);
            fputc('\n', plan_file);
            member_index++;
        }
    }
    if (fclose(plan_file) != 0) { plan_file = NULL; goto done; }
    plan_file = NULL;
    if (rename(plan_temp, plan) != 0 || !content_finalize_path(options, plan)) goto done;
    if (!content_write_catalog_duplicate_evidence(
            state_dir, db, options, stats, deadline, out_paused)) goto done;
    if (content_should_stop(options) || content_deadline_reached(deadline)) {
        if (out_paused != NULL) *out_paused = 1;
        goto done;
    }
    status_file = fopen(status_temp, "w");
    if (status_file == NULL) goto done;
    fprintf(status_file,
        "format_version=3\nscheduler=customer_media_cross_class_v1\n"
        "status=%s\ngeneration=%llu\nfiles_seen=%llu\nfiles_bytes=%llu\n"
        "client_artifacts_ignored=%llu\ncandidate_files=%llu\n"
        "cross_class_candidate_files=%llu\nphoto_candidate_files=%llu\n"
        "files_hashed_now=%llu\nhashes_reused=%llu\n"
        "hash_failures=%llu\nbytes_hashed_now=%llu\nduplicate_groups=%llu\nduplicate_occurrences=%llu\n"
        "redundant_copies=%llu\nredundant_bytes=%llu\n"
        "catalog_duplicate_groups=%llu\ncatalog_duplicate_files=%llu\n"
        "catalog_duplicate_bytes=%llu\nbudget_exhausted=%d\nseconds_total=%.6f\n",
        stats->completed ? "ready" : "checkpoint",
        (unsigned long long)stats->generation,
        (unsigned long long)stats->files_seen,
        (unsigned long long)stats->files_bytes,
        (unsigned long long)stats->client_artifacts_ignored,
        (unsigned long long)stats->candidate_files,
        (unsigned long long)stats->cross_class_candidate_files,
        (unsigned long long)stats->photo_candidate_files,
        (unsigned long long)stats->files_hashed_now,
        (unsigned long long)stats->hashes_reused,
        (unsigned long long)stats->hash_failures,
        (unsigned long long)stats->bytes_hashed_now,
        (unsigned long long)stats->duplicate_groups,
        (unsigned long long)stats->duplicate_occurrences,
        (unsigned long long)stats->redundant_copies,
        (unsigned long long)stats->redundant_bytes,
        (unsigned long long)stats->catalog_duplicate_groups,
        (unsigned long long)stats->catalog_duplicate_files,
        (unsigned long long)stats->catalog_duplicate_bytes,
        stats->budget_exhausted,
        stats->seconds_total);
    if (fclose(status_file) != 0) { status_file = NULL; goto done; }
    status_file = NULL;
    if (rename(status_temp, status) != 0 || !content_finalize_path(options, status)) goto done;
    ok = 1;
done:
    if (plan_file != NULL) fclose(plan_file);
    if (status_file != NULL) fclose(status_file);
    sqlite3_finalize(groups); sqlite3_finalize(members);
    if (!ok) { unlink(plan_temp); unlink(status_temp); }
    return ok;
}

int recovered_content_index_update(
    const char *run_dir,
    const RecoveredContentIndexOptions *options,
    RecoveredContentIndexStats *stats_out)
{
    char recovered_dir[PATH_MAX], state_dir[PATH_MAX], db_path[PATH_MAX];
    char ledger_path[PATH_MAX];
    RecoveredContentIndexStats stats = {0};
    ContentScanContext scan = {0};
    ContentPersistentScanState persistent = {0};
    struct stat ledger_status_value;
    const struct stat *ledger_status = NULL;
    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    sqlite3_stmt *update_hash = NULL;
    double started;
    double deadline = 0.0;
    struct timespec now;
    uint64_t committed_generation = 0U;
    uint64_t remaining_candidates = 0U;
    int stopped = 0;
    int output_paused = 0;
    int snapshot_committed = 0;
    int ok = 0;
    const char *checkpoint_phase = "opening_index";

    clock_gettime(CLOCK_MONOTONIC, &now);
    started = (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
    if (options != NULL && options->time_budget_seconds > 0.0) {
        deadline = started + options->time_budget_seconds;
    }
    if (stats_out != NULL) memset(stats_out, 0, sizeof(*stats_out));
    if (run_dir == NULL || run_dir[0] == '\0' ||
        snprintf(recovered_dir, sizeof(recovered_dir), "%s/recovered", run_dir) >= (int)sizeof(recovered_dir) ||
        snprintf(state_dir, sizeof(state_dir), "%s/state", run_dir) >= (int)sizeof(state_dir) ||
        snprintf(db_path, sizeof(db_path), "%s/content_index.sqlite3", state_dir) >= (int)sizeof(db_path) ||
        snprintf(ledger_path, sizeof(ledger_path), "%s/recovered_outputs.tsv", state_dir) >= (int)sizeof(ledger_path) ||
        !content_write_allowed(options, db_path)) return 0;
    if (mkdir(state_dir, 0775) != 0 && errno != EEXIST) return 0;
    if (lstat(ledger_path, &ledger_status_value) == 0) {
        if (!S_ISREG(ledger_status_value.st_mode)) return 0;
        ledger_status = &ledger_status_value;
    } else if (errno != ENOENT) {
        return 0;
    }
    if (sqlite3_open(db_path, &db) != SQLITE_OK) goto done;
    sqlite3_busy_timeout(db, 5000);
    if (!content_exec(db, "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; "
        "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY,size INTEGER NOT NULL,"
        "mtime_sec INTEGER NOT NULL,mtime_nsec INTEGER NOT NULL,dev INTEGER NOT NULL,"
        "inode INTEGER NOT NULL,abs_offset INTEGER,seen INTEGER NOT NULL,sha256 TEXT);"
        "CREATE TABLE IF NOT EXISTS content_scan_files("
        "path TEXT PRIMARY KEY,size INTEGER NOT NULL,mtime_sec INTEGER NOT NULL,"
        "mtime_nsec INTEGER NOT NULL,dev INTEGER NOT NULL,inode INTEGER NOT NULL,"
        "abs_offset INTEGER,seen INTEGER NOT NULL,sha256 TEXT);"
        "CREATE TABLE IF NOT EXISTS content_scan_dirs("
        "path TEXT PRIMARY KEY,enumerated INTEGER NOT NULL,done INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS content_scan_dirs_work_idx ON "
        "content_scan_dirs(done,path);"
        "CREATE TABLE IF NOT EXISTS content_scan_entries("
        "parent TEXT NOT NULL,name TEXT NOT NULL,path TEXT NOT NULL UNIQUE,"
        "processed INTEGER NOT NULL,PRIMARY KEY(parent,name));"
        "CREATE INDEX IF NOT EXISTS content_scan_entries_work_idx ON "
        "content_scan_entries(parent,processed,name);"
        "CREATE INDEX IF NOT EXISTS content_scan_entries_queue_idx ON "
        "content_scan_entries(parent,name);"
        "CREATE TABLE IF NOT EXISTS content_scan_evidence("
        "path TEXT PRIMARY KEY,abs_offset INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS content_candidate_sizes("
        "size INTEGER PRIMARY KEY,priority INTEGER NOT NULL,"
        "copies INTEGER NOT NULL,cross_class INTEGER NOT NULL,"
        "has_photo INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS content_scan_state("
        "id INTEGER PRIMARY KEY,phase TEXT NOT NULL,generation INTEGER NOT NULL,"
        "ledger_offset INTEGER NOT NULL,ledger_dev INTEGER NOT NULL,"
        "ledger_inode INTEGER NOT NULL,ledger_size INTEGER NOT NULL,"
        "ledger_mtime_sec INTEGER NOT NULL,ledger_mtime_nsec INTEGER NOT NULL,"
        "files_seen INTEGER NOT NULL,files_bytes INTEGER NOT NULL,"
        "client_artifacts_ignored INTEGER NOT NULL,"
        "directories_completed INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS files_size_idx ON files(size);"
        "CREATE INDEX IF NOT EXISTS files_hash_idx ON files(sha256,size);"
        "INSERT OR IGNORE INTO meta(key,value) VALUES('generation',0);")) goto done;
    if (sqlite3_prepare_v2(
            db,
            "SELECT value FROM meta WHERE key='generation'",
            -1,
            &statement,
            NULL) != SQLITE_OK ||
        sqlite3_step(statement) != SQLITE_ROW) {
        goto done;
    }
    committed_generation = (uint64_t)sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    statement = NULL;
    if (!content_load_scan_state(db, &persistent)) goto done;
    if (!persistent.available || strcmp(persistent.phase, "ready") == 0 ||
        !content_scan_signature_matches(&persistent, ledger_status)) {
        if (!content_begin_new_snapshot(
                db,
                recovered_dir,
                committed_generation + 1U,
                ledger_status,
                &persistent)) {
            goto done;
        }
    } else {
        stats.checkpoint_resumed = strcmp(persistent.phase, "ready") != 0;
    }
    stats.generation = persistent.generation;
    stats.files_seen = persistent.files_seen;
    stats.files_bytes = persistent.files_bytes;
    stats.client_artifacts_ignored = persistent.client_artifacts_ignored;
    stats.directories_completed = persistent.directories_completed;
    stats.files_seen_before_slice = persistent.files_seen;
    stats.ledger_bytes_consumed = persistent.ledger_offset;
    scan.db = db;
    scan.generation = stats.generation;
    scan.options = options;
    scan.stats = &stats;
    scan.deadline = deadline;

    if (strcmp(persistent.phase, "recovered_ledger") == 0) {
        checkpoint_phase = "recovered_ledger";
        if (!content_scan_ledger_slice(
                &scan, &persistent, ledger_path, recovered_dir)) {
            goto done;
        }
        if (scan.stopped || stats.budget_exhausted) goto checkpoint;
    }
    if (strcmp(persistent.phase, "recovered_tree") == 0) {
        checkpoint_phase = "recovered_tree";
        if (!content_scan_tree_slice(&scan, &persistent)) goto done;
        if (scan.stopped || stats.budget_exhausted) goto checkpoint;
    }
    if (strcmp(persistent.phase, "snapshot_finalize") == 0) {
        checkpoint_phase = "snapshot_finalize";
        if (content_deadline_reached(deadline)) {
            stats.budget_exhausted = 1;
            goto checkpoint;
        }
        if (!content_exec(db, "BEGIN IMMEDIATE;") ||
            !content_exec(
                db,
                "UPDATE content_scan_files AS current SET sha256=("
                "SELECT old.sha256 FROM files AS old WHERE old.sha256 IS NOT NULL "
                "AND old.size=current.size AND old.mtime_sec=current.mtime_sec "
                "AND old.mtime_nsec=current.mtime_nsec AND "
                "((old.abs_offset IS NOT NULL AND current.abs_offset IS NOT NULL "
                "AND old.abs_offset=current.abs_offset) OR "
                "(old.dev=current.dev AND old.inode=current.inode)) LIMIT 1) "
                "WHERE current.sha256 IS NULL;"
                "DELETE FROM files;"
                "INSERT INTO files(path,size,mtime_sec,mtime_nsec,dev,inode,"
                "abs_offset,seen,sha256) SELECT path,size,mtime_sec,mtime_nsec,"
                "dev,inode,abs_offset,seen,sha256 FROM content_scan_files;"
                "UPDATE meta SET value=(SELECT generation FROM content_scan_state "
                "WHERE id=1) WHERE key='generation';"
                "DELETE FROM content_scan_files;"
                "DELETE FROM content_scan_dirs;"
                "DELETE FROM content_scan_entries;"
                "DELETE FROM content_scan_evidence;"
                "UPDATE content_scan_state SET phase='candidate_classification' "
                "WHERE id=1;"
                "COMMIT;")) {
            (void)content_exec(db, "ROLLBACK;");
            goto done;
        }
        snprintf(
            persistent.phase,
            sizeof(persistent.phase),
            "%s",
            "candidate_classification");
        snapshot_committed = 1;
        if (content_deadline_reached(deadline)) {
            stats.budget_exhausted = 1;
            checkpoint_phase = "candidate_classification";
            goto checkpoint;
        }
    }
    if (strcmp(persistent.phase, "candidate_classification") != 0 &&
        strcmp(persistent.phase, "hashing") != 0 &&
        strcmp(persistent.phase, "evidence_output") != 0) {
        goto done;
    }
    snapshot_committed = 1;
    checkpoint_phase = "candidate_classification";
    if (strcmp(persistent.phase, "candidate_classification") == 0 &&
        !content_exec(db,
        "BEGIN IMMEDIATE;"
        "DELETE FROM content_candidate_sizes;"
        "INSERT INTO content_candidate_sizes(size,priority,copies,cross_class,has_photo) "
        "SELECT size,CASE "
        "WHEN has_unident>0 AND has_named>0 AND has_photo>0 THEN 0 "
        "WHEN has_unident>0 AND has_named>0 THEN 1 "
        "WHEN has_unident>0 AND has_photo>0 THEN 2 "
        "WHEN has_unident>0 THEN 3 "
        "WHEN has_photo>0 THEN 4 ELSE 5 END,"
        "copies,(has_unident>0 AND has_named>0),has_photo FROM ("
        "SELECT size,count(*) copies,"
        "max(instr(lower(path),'/unidentified/')>0 OR instr(lower(path),'/unident/')>0) has_unident,"
        "max(NOT (instr(lower(path),'/unidentified/')>0 OR instr(lower(path),'/unident/')>0)) has_named,"
        "max(lower(path) GLOB '*.jpg' OR lower(path) GLOB '*.jpeg' OR "
        "lower(path) GLOB '*.heic' OR lower(path) GLOB '*.heif' OR "
        "lower(path) GLOB '*.tif' OR lower(path) GLOB '*.tiff' OR "
        "lower(path) GLOB '*.png' OR lower(path) GLOB '*.gif' OR "
        "lower(path) GLOB '*.bmp' OR lower(path) GLOB '*.webp' OR "
        "lower(path) GLOB '*.jp2' OR lower(path) GLOB '*.j2k' OR "
        "lower(path) GLOB '*.dng' OR lower(path) GLOB '*.cr2' OR "
        "lower(path) GLOB '*.cr3' OR lower(path) GLOB '*.nef' OR "
        "lower(path) GLOB '*.arw' OR lower(path) GLOB '*.raf' OR "
        "lower(path) GLOB '*.orf' OR lower(path) GLOB '*.rw2' OR "
        "lower(path) GLOB '*.pef' OR lower(path) GLOB '*.srw') has_photo "
        "FROM files GROUP BY size HAVING count(*)>1);"
        "UPDATE content_scan_state SET phase='hashing' WHERE id=1;"
        "COMMIT;")) {
        (void)content_exec(db, "ROLLBACK;");
        goto done;
    }
    if (strcmp(persistent.phase, "candidate_classification") == 0) {
        snprintf(persistent.phase, sizeof(persistent.phase), "%s", "hashing");
    }
    if (content_deadline_reached(deadline)) {
        stats.budget_exhausted = 1;
        goto checkpoint;
    }

    if (sqlite3_prepare_v2(db,
        "SELECT count(*),"
        "coalesce(sum(CASE WHEN files.sha256 IS NOT NULL THEN 1 ELSE 0 END),0),"
        "coalesce(sum(CASE WHEN files.sha256 IS NULL THEN 1 ELSE 0 END),0),"
        "coalesce(sum(candidate_sizes.cross_class),0),"
        "coalesce(sum(candidate_sizes.has_photo),0) "
        "FROM files JOIN content_candidate_sizes AS candidate_sizes "
        "ON candidate_sizes.size=files.size",
        -1, &statement, NULL) != SQLITE_OK || sqlite3_step(statement) != SQLITE_ROW) goto done;
    stats.candidate_files = (uint64_t)sqlite3_column_int64(statement, 0);
    stats.hashes_reused = (uint64_t)sqlite3_column_int64(statement, 1);
    remaining_candidates = (uint64_t)sqlite3_column_int64(statement, 2);
    stats.cross_class_candidate_files =
        (uint64_t)sqlite3_column_int64(statement, 3);
    stats.photo_candidate_files =
        (uint64_t)sqlite3_column_int64(statement, 4);
    sqlite3_finalize(statement); statement=NULL;
    if (content_deadline_reached(deadline)) {
        stats.budget_exhausted = 1;
        goto checkpoint;
    }

    checkpoint_phase = "hashing";
    while (strcmp(persistent.phase, "hashing") == 0 &&
           remaining_candidates > 0U) {
        int rows = 0;
        int step_result = SQLITE_DONE;
        if (deadline > 0.0 && content_monotonic_seconds() >= deadline) {
            stats.budget_exhausted = 1;
            break;
        }
        if (!content_exec(db, "BEGIN IMMEDIATE;")) goto done;
        if (sqlite3_prepare_v2(db,
            "SELECT files.path,files.size,files.sha256 FROM files JOIN "
            "content_candidate_sizes AS candidate_sizes "
            "ON candidate_sizes.size=files.size WHERE files.sha256 IS NULL "
            "ORDER BY candidate_sizes.priority,candidate_sizes.copies,files.size,"
            "CASE WHEN NOT (instr(lower(files.path),'/unidentified/')>0 OR "
            "instr(lower(files.path),'/unident/')>0) THEN 0 ELSE 1 END,files.path "
            "LIMIT 256", -1, &statement, NULL) != SQLITE_OK ||
            sqlite3_prepare_v2(db,"UPDATE files SET sha256=?1 WHERE path=?2",-1,
                               &update_hash,NULL)!=SQLITE_OK) goto hash_rollback;
        while ((step_result = sqlite3_step(statement)) == SQLITE_ROW) {
            const char *column_path=(const char *)sqlite3_column_text(statement,0);
            char path[PATH_MAX];
            if (column_path == NULL ||
                snprintf(path, sizeof(path), "%s", column_path) >= (int)sizeof(path)) {
                goto hash_rollback;
            }
            rows++;
            {
                char hash[65]; uint64_t bytes=0U;
                int hash_result = content_hash_file(
                    path, options, deadline, hash, &bytes);
                if (hash_result <= 0) {
                    if (hash_result < 0) {
                        if (content_should_stop(options)) stopped=1;
                        else stats.budget_exhausted=1;
                        break;
                    }
                    stats.hash_failures++;
                    continue;
                }
                sqlite3_reset(update_hash); sqlite3_clear_bindings(update_hash);
                sqlite3_bind_text(update_hash,1,hash,-1,SQLITE_TRANSIENT);
                sqlite3_bind_text(update_hash,2,path,-1,SQLITE_TRANSIENT);
                if (sqlite3_step(update_hash)!=SQLITE_DONE) goto hash_rollback;
                stats.files_hashed_now++; stats.bytes_hashed_now+=bytes;
                remaining_candidates--;
            }
        }
        if (!stopped && !stats.budget_exhausted &&
            step_result != SQLITE_DONE) goto hash_rollback;
        sqlite3_finalize(statement); statement=NULL;
        sqlite3_finalize(update_hash); update_hash=NULL;
        if (!content_exec(db, "COMMIT;")) goto done;
        if (stopped || stats.budget_exhausted || stats.hash_failures > 0U ||
            rows < 256) break;
    }
    if (strcmp(persistent.phase, "hashing") == 0 && remaining_candidates == 0U &&
        !stopped && !stats.budget_exhausted && stats.hash_failures == 0U &&
        !content_should_stop(options)) {
        if (!content_exec(
                db,
                "UPDATE content_scan_state SET phase='evidence_output' WHERE id=1")) {
            goto done;
        }
        snprintf(
            persistent.phase, sizeof(persistent.phase), "%s", "evidence_output");
    }
    clock_gettime(CLOCK_MONOTONIC,&now);
    stats.seconds_total=(double)now.tv_sec+(double)now.tv_nsec/1000000000.0-started;
    if (stopped || stats.budget_exhausted) goto checkpoint;
    checkpoint_phase = "evidence_output";
    stats.completed = 1;
    /* The final TSVs are replaced atomically.  Once the durable database is
     * complete, let this comparatively small flush finish instead of
     * repeatedly discarding the same partial temp file at every time slice.
     * An operator stop is still honored inside the writers. */
    if (!content_write_outputs(
            state_dir,db,options,&stats,0.0,&output_paused)) {
        if (output_paused) {
            stopped = content_should_stop(options);
            if (!stopped) stats.budget_exhausted = 1;
            goto checkpoint;
        }
        goto done;
    }
    if (!content_exec(
            db,
            "UPDATE content_scan_state SET phase='ready' WHERE id=1")) {
        goto done;
    }
    (void)content_finalize_path(options,db_path);
    ok=1;
    goto done;
hash_rollback:
    sqlite3_finalize(statement); statement=NULL;
    sqlite3_finalize(update_hash); update_hash=NULL;
    (void)content_exec(db,"ROLLBACK;");
    goto done;
checkpoint:
    stopped = stopped || scan.stopped || content_should_stop(options);
    stats.completed = 0;
    (void)content_count_pending_directories(db, &stats.pending_directories);
    clock_gettime(CLOCK_MONOTONIC,&now);
    stats.seconds_total=(double)now.tv_sec+(double)now.tv_nsec/1000000000.0-started;
    if (!stopped && stats.budget_exhausted &&
        content_write_checkpoint_status(
            state_dir,
            options,
            &stats,
            checkpoint_phase,
            snapshot_committed)) {
        (void)content_finalize_path(options,db_path);
        ok=1;
    }
    goto done;
done:
    sqlite3_finalize(scan.upsert); sqlite3_finalize(scan.evidence_lookup);
    sqlite3_finalize(scan.old_hash_lookup);
    sqlite3_finalize(statement); sqlite3_finalize(update_hash);
    if (db!=NULL) sqlite3_close(db);
    if (stats_out!=NULL) *stats_out=stats;
    return ok;
}
