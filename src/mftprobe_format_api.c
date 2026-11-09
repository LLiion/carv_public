#include "mftprobe_format_api.h"

#include "blob_start.h"
#include "mftprobe_format_jpeg_recovery.h"
#include "mftprobe_format_jpeg_validator.h"
#include "mftprobe_format_riff_validator.h"
#include "mftprobe_format_registry.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FORMAT_TOKEN_MAX 64U
#define PDF_HEADER_SIZE 5U
#define PDF_EOF_SIZE 5U
#define PDF_PARTIAL_MIN_SIZE 32U
#define SQLITE_HEADER_SIZE 100U
#define SQLITE_FIRST_BTREE_OFFSET 100U
#define SQLITE_MIN_FILE_SIZE 512ULL
#define SQLITE_MAX_REASONABLE_FILE_SIZE (64ULL * 1024ULL * 1024ULL * 1024ULL)

static int ascii_tolower_local(int c)
{
    return tolower((unsigned char)c);
}

static int streq_ci_local(const char *a, const char *b)
{
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

static char *trim_spaces_local(char *text)
{
    char *end;

    if (text == NULL) {
        return NULL;
    }

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }

    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        end--;
    }
    *end = '\0';
    return text;
}

static void normalize_extension_local(char *text)
{
    size_t read_pos = 0;
    size_t write_pos = 0;

    if (text == NULL) {
        return;
    }
    while (text[read_pos] == '.') {
        read_pos++;
    }
    while (text[read_pos] != '\0' && write_pos + 1U < FORMAT_EXTENSION_MAX) {
        text[write_pos++] = (char)ascii_tolower_local((unsigned char)text[read_pos++]);
    }
    text[write_pos] = '\0';
}

static int extension_in_list_local(
    char values[][FORMAT_EXTENSION_MAX],
    size_t count,
    const char *candidate
)
{
    size_t i;

    if (candidate == NULL || candidate[0] == '\0') {
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (streq_ci_local(values[i], candidate)) {
            return 1;
        }
    }
    return 0;
}

static int pdf_header_matches_local(const unsigned char *buffer, size_t len)
{
    if (buffer == NULL || len < PDF_HEADER_SIZE) {
        return 0;
    }
    return memcmp(buffer, "%PDF-", PDF_HEADER_SIZE) == 0 ||
           memcmp(buffer, "%FDF-", PDF_HEADER_SIZE) == 0;
}

static uint16_t read_u16_be_local(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_u32_be_local(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static int sqlite_page_size_plausible_local(uint32_t page_size)
{
    return page_size >= 512U &&
           page_size <= 65536U &&
           (page_size & (page_size - 1U)) == 0U;
}

static int sqlite_btree_page_type_plausible_local(unsigned char page_type)
{
    return page_type == 0x02U ||
           page_type == 0x05U ||
           page_type == 0x0AU ||
           page_type == 0x0DU;
}

static int sqlite_header_validate_for_target_local(
    RecoveryTarget *target,
    const unsigned char *buffer,
    size_t len
)
{
    uint32_t page_size;
    uint32_t page_count;
    uint64_t declared_size;

    if (target == NULL || buffer == NULL) {
        return 0;
    }
    if (len < SQLITE_HEADER_SIZE || len <= SQLITE_FIRST_BTREE_OFFSET) {
        snprintf(
            target->last_error,
            sizeof(target->last_error),
            "SQLite data at byte %llu did not include a full first page header",
            (unsigned long long)target->abs_offset
        );
        return 0;
    }
    if (memcmp(buffer, "SQLite format 3\000", 16U) != 0) {
        snprintf(
            target->last_error,
            sizeof(target->last_error),
            "data at byte %llu did not start like SQLite",
            (unsigned long long)target->abs_offset
        );
        return 0;
    }

    page_size = read_u16_be_local(buffer + 16U);
    if (page_size == 1U) {
        page_size = 65536U;
    }
    if (!sqlite_page_size_plausible_local(page_size)) {
        snprintf(target->last_error, sizeof(target->last_error), "SQLite page size was invalid");
        return 0;
    }
    if (!((buffer[18] == 1U || buffer[18] == 2U) &&
          (buffer[19] == 1U || buffer[19] == 2U))) {
        snprintf(target->last_error, sizeof(target->last_error), "SQLite read/write version was invalid");
        return 0;
    }
    if (buffer[21] != 64U || buffer[22] != 32U || buffer[23] != 32U) {
        snprintf(target->last_error, sizeof(target->last_error), "SQLite payload fractions were invalid");
        return 0;
    }
    if (!sqlite_btree_page_type_plausible_local(buffer[SQLITE_FIRST_BTREE_OFFSET])) {
        snprintf(target->last_error, sizeof(target->last_error), "SQLite first btree page type was invalid");
        return 0;
    }

    page_count = read_u32_be_local(buffer + 28U);
    if (page_count == 0U) {
        snprintf(target->last_error, sizeof(target->last_error), "SQLite page count was missing");
        return 0;
    }
    declared_size = (uint64_t)page_size * (uint64_t)page_count;
    if (declared_size < SQLITE_MIN_FILE_SIZE ||
        declared_size > SQLITE_MAX_REASONABLE_FILE_SIZE ||
        declared_size / (uint64_t)page_size != (uint64_t)page_count) {
        snprintf(target->last_error, sizeof(target->last_error), "SQLite declared size was implausible");
        return 0;
    }
    if (target->expected_size != 0U && target->expected_size != declared_size) {
        snprintf(
            target->last_error,
            sizeof(target->last_error),
            "SQLite MFT size %llu did not match header-declared size %llu",
            (unsigned long long)target->expected_size,
            (unsigned long long)declared_size
        );
        return 0;
    }
    if (target->size != declared_size) {
        snprintf(
            target->last_error,
            sizeof(target->last_error),
            "SQLite recovery size %llu did not match header-declared size %llu",
            (unsigned long long)target->size,
            (unsigned long long)declared_size
        );
        return 0;
    }

    return 1;
}

static void validator_tail_update_local(
    unsigned char *tail,
    size_t *tail_len,
    const unsigned char *buffer,
    size_t len,
    size_t tail_capacity
)
{
    size_t keep;

    if (tail == NULL || tail_len == NULL || tail_capacity == 0U ||
        buffer == NULL || len == 0U) {
        return;
    }

    if (len >= tail_capacity) {
        memcpy(tail, buffer + (len - tail_capacity), tail_capacity);
        *tail_len = tail_capacity;
        return;
    }

    keep = *tail_len;
    if (keep > tail_capacity) {
        keep = tail_capacity;
    }
    if (keep + len > tail_capacity) {
        size_t drop = keep + len - tail_capacity;
        memmove(tail, tail + drop, keep - drop);
        keep -= drop;
    }

    memcpy(tail + keep, buffer, len);
    *tail_len = keep + len;
}

static int pdf_tail_has_eof_local(const unsigned char *tail, size_t tail_len)
{
    size_t pos;

    if (tail == NULL || tail_len < PDF_EOF_SIZE) {
        return 0;
    }

    for (pos = 0; pos + PDF_EOF_SIZE <= tail_len; pos++) {
        size_t cursor;

        if (memcmp(tail + pos, "%%EOF", PDF_EOF_SIZE) != 0) {
            continue;
        }
        for (cursor = pos + PDF_EOF_SIZE; cursor < tail_len; cursor++) {
            unsigned char byte = tail[cursor];

            if (!(byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n')) {
                break;
            }
        }
        if (cursor == tail_len) {
            return 1;
        }
    }

    return 0;
}

static size_t parse_extension_list_local(
    const char *csv,
    char out[][FORMAT_EXTENSION_MAX],
    size_t out_max
)
{
    char work[512];
    char *cursor;
    size_t count = 0;

    if (csv == NULL || csv[0] == '\0' || out == NULL || out_max == 0) {
        return 0;
    }

    snprintf(work, sizeof(work), "%s", csv);
    cursor = work;
    while (*cursor != '\0') {
        char *sep = strpbrk(cursor, ",;");
        char *token;

        if (sep != NULL) {
            *sep = '\0';
        }

        token = trim_spaces_local(cursor);
        normalize_extension_local(token);
        if (token[0] != '\0' &&
            !extension_in_list_local(out, count, token) &&
            count < out_max) {
            snprintf(out[count], FORMAT_EXTENSION_MAX, "%s", token);
            count++;
        }

        if (sep == NULL) {
            break;
        }
        cursor = sep + 1;
    }

    return count;
}

static uint32_t category_mask_for_token(const char *token)
{
    if (token == NULL || token[0] == '\0') {
        return 0;
    }

    if (streq_ci_local(token, "all") ||
        streq_ci_local(token, "alla")) {
        return RECOVERY_CATEGORY_ALL;
    }
    if (streq_ci_local(token, "media")) {
        return RECOVERY_CATEGORY_IMAGE | RECOVERY_CATEGORY_VIDEO | RECOVERY_CATEGORY_RAW;
    }
    if (streq_ci_local(token, "photo") ||
        streq_ci_local(token, "photos") ||
        streq_ci_local(token, "photo_pro") ||
        streq_ci_local(token, "photo-pro") ||
        streq_ci_local(token, "photopro") ||
        streq_ci_local(token, "prophoto") ||
        streq_ci_local(token, "foto") ||
        streq_ci_local(token, "bilder_pro") ||
        streq_ci_local(token, "bildpro")) {
        return RECOVERY_CATEGORY_IMAGE |
               RECOVERY_CATEGORY_RAW |
               RECOVERY_CATEGORY_LIBRARY;
    }
    if (streq_ci_local(token, "image") ||
        streq_ci_local(token, "images") ||
        streq_ci_local(token, "img") ||
        streq_ci_local(token, "picture") ||
        streq_ci_local(token, "pictures") ||
        streq_ci_local(token, "bilder") ||
        streq_ci_local(token, "bild")) {
        return RECOVERY_CATEGORY_IMAGE;
    }
    if (streq_ci_local(token, "raw") ||
        streq_ci_local(token, "camera_raw") ||
        streq_ci_local(token, "camera-raw") ||
        streq_ci_local(token, "systemkamera") ||
        streq_ci_local(token, "raformat")) {
        return RECOVERY_CATEGORY_RAW;
    }
    if (streq_ci_local(token, "library") ||
        streq_ci_local(token, "libraries") ||
        streq_ci_local(token, "librarys") ||
        streq_ci_local(token, "catalog") ||
        streq_ci_local(token, "catalogs") ||
        streq_ci_local(token, "catalogue") ||
        streq_ci_local(token, "catalogues") ||
        streq_ci_local(token, "katalog") ||
        streq_ci_local(token, "kataloger") ||
        streq_ci_local(token, "bibliotek")) {
        return RECOVERY_CATEGORY_LIBRARY;
    }
    if (streq_ci_local(token, "video") ||
        streq_ci_local(token, "videos") ||
        streq_ci_local(token, "vid") ||
        streq_ci_local(token, "movie") ||
        streq_ci_local(token, "movies") ||
        streq_ci_local(token, "film") ||
        streq_ci_local(token, "filmer")) {
        return RECOVERY_CATEGORY_VIDEO;
    }
    if (streq_ci_local(token, "document") ||
        streq_ci_local(token, "documents") ||
        streq_ci_local(token, "doc") ||
        streq_ci_local(token, "docs") ||
        streq_ci_local(token, "dokument")) {
        return RECOVERY_CATEGORY_DOCUMENT;
    }
    if (streq_ci_local(token, "audio") ||
        streq_ci_local(token, "sound") ||
        streq_ci_local(token, "ljud")) {
        return RECOVERY_CATEGORY_AUDIO;
    }
    if (streq_ci_local(token, "archive") ||
        streq_ci_local(token, "archives") ||
        streq_ci_local(token, "arkiv")) {
        return RECOVERY_CATEGORY_ARCHIVE;
    }
    if (streq_ci_local(token, "other") ||
        streq_ci_local(token, "ovrigt")) {
        return RECOVERY_CATEGORY_OTHER;
    }

    return 0;
}

static int parse_category_mask_local(
    const char *csv,
    uint32_t *mask_out,
    char *error_text,
    size_t error_text_size
)
{
    char work[512];
    char *cursor;
    uint32_t mask = 0;

    if (mask_out != NULL) {
        *mask_out = 0;
    }
    if (csv == NULL || csv[0] == '\0') {
        return 1;
    }

    snprintf(work, sizeof(work), "%s", csv);
    cursor = work;
    while (*cursor != '\0') {
        char *sep = strpbrk(cursor, ",;");
        char *token;
        uint32_t token_mask;

        if (sep != NULL) {
            *sep = '\0';
        }

        token = trim_spaces_local(cursor);
        token_mask = category_mask_for_token(token);
        if (token[0] != '\0' && token_mask == 0) {
            if (error_text != NULL && error_text_size > 0) {
                snprintf(error_text, error_text_size, "unknown format category '%s'", token);
            }
            return 0;
        }
        mask |= token_mask;

        if (sep == NULL) {
            break;
        }
        cursor = sep + 1;
    }

    if (mask_out != NULL) {
        *mask_out = mask;
    }
    return 1;
}

static int format_has_extension(const RecoveryFormat *format, const char *extension)
{
    size_t i;

    if (format == NULL || extension == NULL || extension[0] == '\0') {
        return 0;
    }
    if (format->extensions == NULL || format->extension_count == 0) {
        return streq_ci_local(format->default_extension, extension);
    }
    for (i = 0; i < format->extension_count; i++) {
        if (streq_ci_local(format->extensions[i], extension)) {
            return 1;
        }
    }
    return 0;
}

static int format_matches_any_extension(
    const RecoveryFormat *format,
    char extensions[][FORMAT_EXTENSION_MAX],
    size_t extension_count
)
{
    size_t i;

    if (format == NULL) {
        return 0;
    }
    if (extension_count == 0) {
        return 1;
    }
    for (i = 0; i < extension_count; i++) {
        if (format_has_extension(format, extensions[i])) {
            return 1;
        }
    }
    return 0;
}

static int has_explicit_selection(const MftprobeFormatSelection *selection)
{
    return selection != NULL &&
           ((selection->categories_csv != NULL && selection->categories_csv[0] != '\0') ||
            (selection->formats_csv != NULL && selection->formats_csv[0] != '\0') ||
            (selection->dev_format != NULL && selection->dev_format[0] != '\0'));
}

const RecoveryOrder *mftprobe_format_default_order(void)
{
    return mftprobe_recovery_default_order();
}

int mftprobe_format_load_common_profiles(Config *config, const char *db_path)
{
    return mftprobe_recovery_order_load_common_profiles(config, db_path);
}

int mftprobe_format_configure_active_order(
    Config *config,
    const MftprobeFormatSelection *selection,
    char *error_text,
    size_t error_text_size
)
{
    const RecoveryOrder *pool;
    uint32_t category_mask = 0;
    size_t selected_count = 0;
    char filter_extensions[FORMAT_TOKEN_MAX][FORMAT_EXTENSION_MAX] = {{0}};
    size_t filter_extension_count = 0;
    char dev_extension[FORMAT_EXTENSION_MAX] = {0};
    size_t i;

    if (error_text != NULL && error_text_size > 0) {
        error_text[0] = '\0';
    }
    if (config == NULL) {
        if (error_text != NULL && error_text_size > 0) {
            snprintf(error_text, error_text_size, "format configuration missing");
        }
        return 0;
    }

    if (!has_explicit_selection(selection)) {
        config->recovery_order = mftprobe_recovery_default_order();
        return 1;
    }

    pool = config->loaded_recovery_order.count > 0
        ? &config->loaded_recovery_order
        : mftprobe_recovery_default_order();

    if (!parse_category_mask_local(
            selection != NULL ? selection->categories_csv : NULL,
            &category_mask,
            error_text,
            error_text_size)) {
        return 0;
    }

    filter_extension_count = parse_extension_list_local(
        selection != NULL ? selection->formats_csv : NULL,
        filter_extensions,
        FORMAT_TOKEN_MAX
    );

    if (selection != NULL && selection->dev_format != NULL && selection->dev_format[0] != '\0') {
        snprintf(dev_extension, sizeof(dev_extension), "%s", selection->dev_format);
        normalize_extension_local(dev_extension);
        if (dev_extension[0] == '\0') {
            if (error_text != NULL && error_text_size > 0) {
                snprintf(error_text, error_text_size, "invalid --dev-format value");
            }
            return 0;
        }
        filter_extension_count = 0;
        snprintf(filter_extensions[filter_extension_count], FORMAT_EXTENSION_MAX, "%s", dev_extension);
        filter_extension_count = 1;
    }

    for (i = 0; i < pool->count && selected_count < RECOVERY_FORMAT_MAX; i++) {
        const RecoveryFormat *format = &pool->formats[i];

        if (category_mask != 0 && (format->category_mask & category_mask) == 0) {
            continue;
        }
        if (!format_matches_any_extension(format, filter_extensions, filter_extension_count)) {
            continue;
        }

        config->selected_recovery_formats[selected_count++] = *format;
    }

    if (selected_count == 0) {
        if (error_text != NULL && error_text_size > 0) {
            snprintf(error_text, error_text_size, "no formats matched current selection");
        }
        return 0;
    }

    config->selected_recovery_order.formats = config->selected_recovery_formats;
    config->selected_recovery_order.count = selected_count;
    config->recovery_order = &config->selected_recovery_order;
    return 1;
}

void mftprobe_format_describe_active_order(
    const Config *config,
    char *out,
    size_t out_size
)
{
    const RecoveryOrder *order;
    size_t i;
    size_t pos = 0;

    if (out == NULL || out_size == 0) {
        return;
    }
    out[0] = '\0';

    order = config != NULL ? config->recovery_order : NULL;
    if (order == NULL || order->count == 0) {
        snprintf(out, out_size, "(none)");
        return;
    }

    for (i = 0; i < order->count; i++) {
        int wrote;

        wrote = snprintf(
            out + pos,
            out_size - pos,
            "%s%s",
            i == 0 ? "" : ",",
            order->formats[i].default_extension != NULL
                ? order->formats[i].default_extension
                : "?"
        );
        if (wrote < 0 || (size_t)wrote >= out_size - pos) {
            snprintf(out + (pos > 0 ? pos - 1 : 0), out_size - (pos > 0 ? pos - 1 : 0), "...");
            return;
        }
        pos += (size_t)wrote;
    }
}

const RecoveryFormat *mftprobe_format_select_for_entry(
    const Config *config,
    const MftEntry *entry
)
{
    return mftprobe_entry_selected_format(config, entry);
}

int mftprobe_format_allows_partial_target(
    const RecoveryFormat *format,
    uint64_t available_bytes
)
{
    if (format == NULL) {
        return 0;
    }

    switch (format->validator_id) {
        case RECOVERY_VALIDATOR_JPEG:
            return available_bytes >= mftprobe_jpeg_partial_min_size();
        case RECOVERY_VALIDATOR_PDF:
            return available_bytes >= PDF_PARTIAL_MIN_SIZE;
        case RECOVERY_VALIDATOR_SQLITE:
            return 0;
        case RECOVERY_VALIDATOR_NONE:
        default:
            return 0;
    }
}

int mftprobe_format_target_allows_partial_bytes(
    const RecoveryTarget *target,
    uint64_t available_bytes
)
{
    if (target == NULL) {
        return 0;
    }

    switch (target->validator_id) {
        case RECOVERY_VALIDATOR_JPEG:
            return available_bytes >= mftprobe_jpeg_partial_min_size();
        case RECOVERY_VALIDATOR_PDF:
            return available_bytes >= PDF_PARTIAL_MIN_SIZE;
        case RECOVERY_VALIDATOR_SQLITE:
            return 0;
        case RECOVERY_VALIDATOR_NONE:
        default:
            return 0;
    }
}

int mftprobe_format_target_is_partial(const RecoveryTarget *target)
{
    if (target == NULL) {
        return 0;
    }

    switch (target->validator_id) {
        case RECOVERY_VALIDATOR_JPEG:
            return mftprobe_jpeg_size_looks_partial(target->size, target->expected_size);
        case RECOVERY_VALIDATOR_PDF:
            return target->expected_size > 0U && target->size < target->expected_size;
        case RECOVERY_VALIDATOR_SQLITE:
            return 0;
        case RECOVERY_VALIDATOR_NONE:
        default:
            return 0;
    }
}

void mftprobe_format_validator_reset(RecoveryTarget *target)
{
    if (target == NULL) {
        return;
    }
    memset(&target->validator_state, 0, sizeof(target->validator_state));
}

int mftprobe_format_validator_start(
    RecoveryTarget *target,
    const unsigned char *buffer,
    size_t len,
    size_t *skip_bytes
)
{
    if (target == NULL) {
        return 0;
    }
    if (skip_bytes != NULL) {
        *skip_bytes = 0;
    }
    if (target->validator_id == RECOVERY_VALIDATOR_PDF) {
        if (!pdf_header_matches_local(buffer, len)) {
            snprintf(
                target->last_error,
                sizeof(target->last_error),
                "data at byte %llu did not start like PDF/FDF",
                (unsigned long long)target->abs_offset
            );
            return 0;
        }
        return 1;
    }
    if (target->validator_id == RECOVERY_VALIDATOR_SQLITE) {
        return sqlite_header_validate_for_target_local(target, buffer, len);
    }
    if (!blob_start_matches(
            buffer,
            len,
            target->blob_start,
            target->blob_start_length)) {
        snprintf(
            target->last_error,
            sizeof(target->last_error),
            "data at byte %llu did not match expected start bytes",
            (unsigned long long)target->abs_offset
        );
        return 0;
    }

    switch (target->validator_id) {
        case RECOVERY_VALIDATOR_JPEG:
            return mftprobe_jpeg_validator_start(
                target->abs_offset,
                target->last_error,
                sizeof(target->last_error),
                buffer,
                len,
                skip_bytes
            );
        case RECOVERY_VALIDATOR_RIFF:
            return mftprobe_riff_validator_start(
                target->abs_offset,
                target->extension,
                target->last_error,
                sizeof(target->last_error),
                buffer,
                len
            );
        case RECOVERY_VALIDATOR_SQLITE:
            return 1;
        case RECOVERY_VALIDATOR_NONE:
        default:
            return 1;
    }
}

void mftprobe_format_validator_update(
    RecoveryTarget *target,
    const unsigned char *buffer,
    size_t len
)
{
    if (target == NULL) {
        return;
    }

    switch (target->validator_id) {
        case RECOVERY_VALIDATOR_JPEG:
            mftprobe_jpeg_validator_update(
                target->validator_state.tail,
                &target->validator_state.tail_len,
                buffer,
                len
            );
            break;
        case RECOVERY_VALIDATOR_PDF:
            validator_tail_update_local(
                target->validator_state.tail,
                &target->validator_state.tail_len,
                buffer,
                len,
                sizeof(target->validator_state.tail)
            );
            break;
        case RECOVERY_VALIDATOR_SQLITE:
            break;
        case RECOVERY_VALIDATOR_NONE:
        default:
            break;
    }
}

int mftprobe_format_validator_finish(RecoveryTarget *target)
{
    if (target == NULL) {
        return 0;
    }

    switch (target->validator_id) {
        case RECOVERY_VALIDATOR_JPEG:
            return mftprobe_jpeg_validator_finish(
                target->abs_offset,
                target->size,
                target->expected_size,
                mftprobe_jpeg_partial_min_size(),
                mftprobe_jpeg_partial_size_tolerance(),
                target->validator_state.tail,
                target->validator_state.tail_len,
                target->last_error,
                sizeof(target->last_error)
            );
        case RECOVERY_VALIDATOR_RIFF:
            return mftprobe_riff_validator_finish(
                target->abs_offset,
                target->size,
                target->extension,
                target->last_error,
                sizeof(target->last_error)
            );
        case RECOVERY_VALIDATOR_PDF:
            if (pdf_tail_has_eof_local(
                    target->validator_state.tail,
                    target->validator_state.tail_len)) {
                return 1;
            }
            snprintf(
                target->last_error,
                sizeof(target->last_error),
                "PDF data at byte %llu did not end with %%EOF",
                (unsigned long long)target->abs_offset
            );
            return 0;
        case RECOVERY_VALIDATOR_SQLITE:
            return 1;
        case RECOVERY_VALIDATOR_NONE:
        default:
            return 1;
    }
}

MftprobeFormatRecoverStatus mftprobe_format_direct_recover(
    int image_fd,
    RecoveryTarget *target,
    unsigned char *buffer,
    const MftprobeFormatIoOps *io_ops
)
{
    if (target == NULL) {
        return MFTPROBE_FORMAT_RECOVER_FAILED;
    }

    switch (target->validator_id) {
        case RECOVERY_VALIDATOR_JPEG: {
            MftprobeJpegRecoveryOps jpeg_ops;

            if (io_ops == NULL ||
                io_ops->ensure_parent_dirs == NULL ||
                io_ops->read_with_fallback == NULL) {
                snprintf(target->last_error, sizeof(target->last_error), "invalid format recovery ops");
                return MFTPROBE_FORMAT_RECOVER_FAILED;
            }

            jpeg_ops.ensure_parent_dirs = io_ops->ensure_parent_dirs;
            jpeg_ops.read_with_fallback = io_ops->read_with_fallback;
            jpeg_ops.recovery_target_is_partial = mftprobe_format_target_is_partial;
            jpeg_ops.recovery_validator_reset = mftprobe_format_validator_reset;
            jpeg_ops.recovery_validator_start = mftprobe_format_validator_start;
            jpeg_ops.recovery_validator_update = mftprobe_format_validator_update;
            jpeg_ops.recovery_validator_finish = mftprobe_format_validator_finish;
            jpeg_ops.stop_requested = io_ops->stop_requested;
            jpeg_ops.read_size = io_ops->read_size;

            if (mftprobe_direct_recover_jpeg_target(image_fd, target, buffer, &jpeg_ops)) {
                return MFTPROBE_FORMAT_RECOVER_SUCCESS;
            }
            return MFTPROBE_FORMAT_RECOVER_FAILED;
        }
        case RECOVERY_VALIDATOR_NONE:
        default:
            return MFTPROBE_FORMAT_RECOVER_NOT_HANDLED;
    }
}
