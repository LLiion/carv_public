#include "mftprobe_format_registry.h"

#include "hex.h"

#include <sqlite3.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *const g_recovery_jpeg_extensions[] = {"jpg", "jpeg"};
static const RecoveryFormat g_default_recovery_formats[] = {
    {
        .format_id = 1U,
        .name = "jpeg",
        .default_extension = "jpg",
        .extensions = g_recovery_jpeg_extensions,
        .extension_count =
            sizeof(g_recovery_jpeg_extensions) / sizeof(g_recovery_jpeg_extensions[0]),
        .validator_id = RECOVERY_VALIDATOR_JPEG,
        .category_mask = RECOVERY_CATEGORY_IMAGE
    }
};
static const RecoveryOrder g_default_recovery_order = {
    g_default_recovery_formats,
    sizeof(g_default_recovery_formats) / sizeof(g_default_recovery_formats[0])
};

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

static int has_ext_ci_local(const char *name, const char *ext)
{
    const char *dot = strrchr(name, '.');

    if (name == NULL || ext == NULL) {
        return 0;
    }
    return dot != NULL && streq_ci_local(dot + 1, ext);
}

const RecoveryOrder *mftprobe_recovery_default_order(void)
{
    return &g_default_recovery_order;
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

static void normalize_extension(char *text)
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

static int extension_exists_local(
    char extensions[][FORMAT_EXTENSION_MAX],
    size_t count,
    const char *extension
)
{
    size_t i;

    if (extension == NULL) {
        return 0;
    }
    for (i = 0; i < count; i++) {
        if (streq_ci_local(extensions[i], extension)) {
            return 1;
        }
    }
    return 0;
}

static size_t split_type_extensions(
    const char *type_text,
    char out[][FORMAT_EXTENSION_MAX],
    size_t out_max
)
{
    char work[256];
    char *cursor;
    size_t count = 0;

    if (type_text == NULL || out == NULL || out_max == 0) {
        return 0;
    }

    snprintf(work, sizeof(work), "%s", type_text);
    cursor = work;
    while (*cursor != '\0') {
        char *sep = strchr(cursor, '|');
        char *token;

        if (sep != NULL) {
            *sep = '\0';
        }

        token = trim_spaces_local(cursor);
        normalize_extension(token);
        if (token[0] != '\0' &&
            !extension_exists_local(out, count, token) &&
            count < out_max) {
            snprintf(out[count], FORMAT_EXTENSION_MAX, "%s", token);
            count++;
        }

        if (sep == NULL) {
            break;
        }
        cursor = sep + 1;
    }

    if (count > 0 &&
        extension_exists_local(out, count, "jpg") &&
        !extension_exists_local(out, count, "jpeg") &&
        count < out_max) {
        snprintf(out[count], FORMAT_EXTENSION_MAX, "jpeg");
        count++;
    }
    if (count > 0 &&
        extension_exists_local(out, count, "jpeg") &&
        !extension_exists_local(out, count, "jpg") &&
        count < out_max) {
        snprintf(out[count], FORMAT_EXTENSION_MAX, "jpg");
        count++;
    }

    return count;
}

static size_t append_alias_local(
    char aliases[][FORMAT_EXTENSION_MAX],
    size_t alias_count,
    size_t alias_max,
    const char *extension
)
{
    size_t i;

    if (aliases == NULL || extension == NULL || extension[0] == '\0') {
        return alias_count;
    }

    for (i = 0; i < alias_count; i++) {
        if (streq_ci_local(aliases[i], extension)) {
            return alias_count;
        }
    }

    if (alias_count >= alias_max) {
        return alias_count;
    }

    copy_text_truncated_local(
        aliases[alias_count],
        FORMAT_EXTENSION_MAX,
        extension
    );
    return alias_count + 1U;
}

static size_t expand_builtin_format_aliases(
    char aliases[][FORMAT_EXTENSION_MAX],
    size_t alias_count,
    size_t alias_max
)
{
    if (aliases == NULL || alias_count == 0U) {
        return alias_count;
    }

    if (streq_ci_local(aliases[0], "mov")) {
        alias_count = append_alias_local(aliases, alias_count, alias_max, "mp4");
        alias_count = append_alias_local(aliases, alias_count, alias_max, "m4a");
        alias_count = append_alias_local(aliases, alias_count, alias_max, "m4b");
        alias_count = append_alias_local(aliases, alias_count, alias_max, "m4v");
        alias_count = append_alias_local(aliases, alias_count, alias_max, "3gp");
        alias_count = append_alias_local(aliases, alias_count, alias_max, "3g2");
    }

    return alias_count;
}

static uint32_t extension_category_mask_local(const char *extension)
{
    if (extension == NULL || extension[0] == '\0') {
        return 0;
    }

    if (streq_ci_local(extension, "jpg") ||
        streq_ci_local(extension, "jpeg") ||
        streq_ci_local(extension, "jp2") ||
        streq_ci_local(extension, "webp") ||
        streq_ci_local(extension, "png") ||
        streq_ci_local(extension, "gif") ||
        streq_ci_local(extension, "bmp") ||
        streq_ci_local(extension, "dib") ||
        streq_ci_local(extension, "tif") ||
        streq_ci_local(extension, "tiff") ||
        streq_ci_local(extension, "psd")) {
        return RECOVERY_CATEGORY_IMAGE;
    }

    if (streq_ci_local(extension, "dng") ||
        streq_ci_local(extension, "cr2") ||
        streq_ci_local(extension, "cr3") ||
        streq_ci_local(extension, "crw") ||
        streq_ci_local(extension, "nef") ||
        streq_ci_local(extension, "nrw") ||
        streq_ci_local(extension, "arw") ||
        streq_ci_local(extension, "sr2") ||
        streq_ci_local(extension, "srf") ||
        streq_ci_local(extension, "arq") ||
        streq_ci_local(extension, "orf") ||
        streq_ci_local(extension, "ori") ||
        streq_ci_local(extension, "rw2") ||
        streq_ci_local(extension, "rwl") ||
        streq_ci_local(extension, "raw") ||
        streq_ci_local(extension, "pef") ||
        streq_ci_local(extension, "ptx") ||
        streq_ci_local(extension, "srw") ||
        streq_ci_local(extension, "raf") ||
        streq_ci_local(extension, "x3f") ||
        streq_ci_local(extension, "3fr") ||
        streq_ci_local(extension, "fff") ||
        streq_ci_local(extension, "iiq") ||
        streq_ci_local(extension, "mos")) {
        return RECOVERY_CATEGORY_RAW;
    }

    if (streq_ci_local(extension, "mov") ||
        streq_ci_local(extension, "mp4") ||
        streq_ci_local(extension, "m4v") ||
        streq_ci_local(extension, "mkv") ||
        streq_ci_local(extension, "avi") ||
        streq_ci_local(extension, "wmv") ||
        streq_ci_local(extension, "asf") ||
        streq_ci_local(extension, "mpg") ||
        streq_ci_local(extension, "vob") ||
        streq_ci_local(extension, "3gp") ||
        streq_ci_local(extension, "3g2") ||
        streq_ci_local(extension, "rm") ||
        streq_ci_local(extension, "rmvb") ||
        streq_ci_local(extension, "ivr")) {
        return RECOVERY_CATEGORY_VIDEO;
    }

    if (streq_ci_local(extension, "heic") ||
        streq_ci_local(extension, "heif") ||
        streq_ci_local(extension, "avif")) {
        return RECOVERY_CATEGORY_IMAGE;
    }

    if (streq_ci_local(extension, "mp3") ||
        streq_ci_local(extension, "m4a") ||
        streq_ci_local(extension, "m4b") ||
        streq_ci_local(extension, "wav") ||
        streq_ci_local(extension, "flac") ||
        streq_ci_local(extension, "ra") ||
        streq_ci_local(extension, "mid") ||
        streq_ci_local(extension, "midi") ||
        streq_ci_local(extension, "rmi") ||
        streq_ci_local(extension, "wma") ||
        streq_ci_local(extension, "aac") ||
        streq_ci_local(extension, "ast")) {
        return RECOVERY_CATEGORY_AUDIO;
    }

    if (streq_ci_local(extension, "lrcat")) {
        return RECOVERY_CATEGORY_DOCUMENT | RECOVERY_CATEGORY_LIBRARY;
    }

    if (streq_ci_local(extension, "pdf") ||
        streq_ci_local(extension, "fdf") ||
        streq_ci_local(extension, "doc") ||
        streq_ci_local(extension, "dot") ||
        streq_ci_local(extension, "docx") ||
        streq_ci_local(extension, "xls") ||
        streq_ci_local(extension, "xla") ||
        streq_ci_local(extension, "xlsx") ||
        streq_ci_local(extension, "ppt") ||
        streq_ci_local(extension, "pps") ||
        streq_ci_local(extension, "wiz") ||
        streq_ci_local(extension, "pptx") ||
        streq_ci_local(extension, "odt") ||
        streq_ci_local(extension, "ods") ||
        streq_ci_local(extension, "odp") ||
        streq_ci_local(extension, "epub") ||
        streq_ci_local(extension, "xps") ||
        streq_ci_local(extension, "msg") ||
        streq_ci_local(extension, "mdb") ||
        streq_ci_local(extension, "vsd") ||
        streq_ci_local(extension, "pub") ||
        streq_ci_local(extension, "ole") ||
        streq_ci_local(extension, "sqlite") ||
        streq_ci_local(extension, "db")) {
        return RECOVERY_CATEGORY_DOCUMENT;
    }

    if (streq_ci_local(extension, "zip") ||
        streq_ci_local(extension, "apk") ||
        streq_ci_local(extension, "jar") ||
        streq_ci_local(extension, "rar") ||
        streq_ci_local(extension, "7z") ||
        streq_ci_local(extension, "gz") ||
        streq_ci_local(extension, "lha") ||
        streq_ci_local(extension, "lzh") ||
        streq_ci_local(extension, "iso")) {
        return RECOVERY_CATEGORY_ARCHIVE;
    }

    return 0;
}

static uint32_t normalize_loaded_format_category_mask_local(
    uint32_t category_mask,
    char aliases[][FORMAT_EXTENSION_MAX],
    size_t alias_count
)
{
    const char *primary_extension =
        alias_count > 0U ? aliases[0] : NULL;

    /*
     * Keep category selection aligned with what raw-all should actually
     * carve for a plain image run. The profile DB contains an IMG bitmap
     * entry and the MOV profile carries HEIC/HEIF/AVIF aliases, but selecting
     * the broad "img" category must not pull in disk-image-like .img files or
     * the whole MOV family.
     */
    if (primary_extension != NULL &&
        (streq_ci_local(primary_extension, "img") ||
         streq_ci_local(primary_extension, "mov"))) {
        category_mask &= ~RECOVERY_CATEGORY_IMAGE;
    }

    return category_mask;
}

static uint32_t category_mask_from_type_name(const char *type_name)
{
    char normalized[FORMAT_NAME_MAX];
    size_t write_pos = 0;
    size_t i;

    if (type_name == NULL) {
        return 0;
    }

    for (i = 0; type_name[i] != '\0' && write_pos + 1U < sizeof(normalized); i++) {
        if (isalnum((unsigned char)type_name[i])) {
            normalized[write_pos++] =
                (char)ascii_tolower_local((unsigned char)type_name[i]);
        }
    }
    normalized[write_pos] = '\0';

    if (normalized[0] == '\0') {
        return 0;
    }
    if (strcmp(normalized, "picture") == 0) {
        return RECOVERY_CATEGORY_IMAGE;
    }
    if (strcmp(normalized, "raw") == 0 ||
        strcmp(normalized, "rawimage") == 0 ||
        strcmp(normalized, "cameraraw") == 0) {
        return RECOVERY_CATEGORY_RAW;
    }
    if (strcmp(normalized, "multimedia") == 0) {
        return 0;
    }
    if (strcmp(normalized, "audio") == 0) {
        return RECOVERY_CATEGORY_AUDIO;
    }
    if (strcmp(normalized, "compressedarchive") == 0) {
        return RECOVERY_CATEGORY_ARCHIVE;
    }
    if (strcmp(normalized, "wordprocessingsuite") == 0) {
        return RECOVERY_CATEGORY_DOCUMENT;
    }
    return 0;
}

static RecoveryValidatorId validator_for_extensions(
    char extensions[][FORMAT_EXTENSION_MAX],
    size_t extension_count
)
{
    size_t i;
    int has_riff = 0;

    for (i = 0; i < extension_count; i++) {
        if (streq_ci_local(extensions[i], "jpg") ||
            streq_ci_local(extensions[i], "jpeg")) {
            return RECOVERY_VALIDATOR_JPEG;
        }
        if (streq_ci_local(extensions[i], "pdf") ||
            streq_ci_local(extensions[i], "fdf")) {
            return RECOVERY_VALIDATOR_PDF;
        }
        if (streq_ci_local(extensions[i], "lrcat") ||
            streq_ci_local(extensions[i], "sqlite") ||
            streq_ci_local(extensions[i], "db")) {
            return RECOVERY_VALIDATOR_SQLITE;
        }
        if (streq_ci_local(extensions[i], "avi") ||
            streq_ci_local(extensions[i], "wav") ||
            streq_ci_local(extensions[i], "webp") ||
            streq_ci_local(extensions[i], "rmi") ||
            streq_ci_local(extensions[i], "riff")) {
            has_riff = 1;
        }
    }
    if (has_riff) {
        return RECOVERY_VALIDATOR_RIFF;
    }
    return RECOVERY_VALIDATOR_NONE;
}

static int recovery_format_already_loaded(
    const Config *config,
    const char *extension,
    size_t loaded_count
)
{
    size_t i;

    if (config == NULL || extension == NULL) {
        return 0;
    }
    for (i = 0; i < loaded_count; i++) {
        if (streq_ci_local(config->loaded_format_extensions[i], extension)) {
            return 1;
        }
    }
    return 0;
}

static int append_loaded_builtin_format_local(
    Config *config,
    size_t *count,
    const char *extension,
    const char *name,
    uint32_t category_mask
)
{
    size_t index;

    if (config == NULL ||
        count == NULL ||
        extension == NULL ||
        extension[0] == '\0' ||
        *count >= RECOVERY_FORMAT_MAX ||
        recovery_format_already_loaded(config, extension, *count)) {
        return 1;
    }

    index = *count;
    copy_text_truncated_local(
        config->loaded_format_extensions[index],
        sizeof(config->loaded_format_extensions[index]),
        extension
    );
    copy_text_truncated_local(
        config->loaded_format_aliases[index][0],
        FORMAT_EXTENSION_MAX,
        extension
    );
    config->loaded_format_extension_lists[index][0] =
        config->loaded_format_aliases[index][0];
    copy_text_truncated_local(
        config->loaded_format_names[index],
        sizeof(config->loaded_format_names[index]),
        name != NULL ? name : extension
    );

    config->loaded_recovery_formats[index].format_id =
        900000U + (uint32_t)index;
    config->loaded_recovery_formats[index].name =
        config->loaded_format_names[index];
    config->loaded_recovery_formats[index].default_extension =
        config->loaded_format_extensions[index];
    config->loaded_recovery_formats[index].extensions =
        config->loaded_format_extension_lists[index];
    config->loaded_recovery_formats[index].extension_count = 1U;
    config->loaded_recovery_formats[index].validator_id = RECOVERY_VALIDATOR_NONE;
    config->loaded_recovery_formats[index].category_mask = category_mask;
    (*count)++;
    return 1;
}

static int append_builtin_container_image_formats_local(
    Config *config,
    size_t *count
)
{
    return append_loaded_builtin_format_local(
               config,
               count,
               "heic",
               "HEIC image",
               RECOVERY_CATEGORY_IMAGE) &&
           append_loaded_builtin_format_local(
               config,
               count,
               "heif",
               "HEIF image",
               RECOVERY_CATEGORY_IMAGE) &&
           append_loaded_builtin_format_local(
               config,
               count,
               "avif",
               "AVIF image",
               RECOVERY_CATEGORY_IMAGE);
}

static int append_builtin_raw_formats_local(
    Config *config,
    size_t *count
)
{
    static const struct {
        const char *extension;
        const char *name;
    } raw_formats[] = {
        {"raw", "Camera RAW image"},
        {"dng", "DNG raw image"},
        {"cr2", "Canon CR2 raw image"},
        {"cr3", "Canon CR3 raw image"},
        {"crw", "Canon CRW raw image"},
        {"nef", "Nikon NEF raw image"},
        {"nrw", "Nikon NRW raw image"},
        {"arw", "Sony ARW raw image"},
        {"sr2", "Sony SR2 raw image"},
        {"srf", "Sony SRF raw image"},
        {"arq", "Sony ARQ raw image"},
        {"orf", "Olympus ORF raw image"},
        {"ori", "Olympus ORI raw image"},
        {"rw2", "Panasonic RW2 raw image"},
        {"rwl", "Leica RWL raw image"},
        {"pef", "Pentax PEF raw image"},
        {"ptx", "Pentax PTX raw image"},
        {"srw", "Samsung SRW raw image"},
        {"raf", "Fujifilm RAF raw image"},
        {"x3f", "Sigma X3F raw image"},
        {"3fr", "Hasselblad 3FR raw image"},
        {"fff", "Hasselblad FFF raw image"},
        {"iiq", "Phase One IIQ raw image"},
        {"mos", "Leaf MOS raw image"}
    };
    size_t i;

    for (i = 0U; i < sizeof(raw_formats) / sizeof(raw_formats[0]); i++) {
        if (!append_loaded_builtin_format_local(
                config,
                count,
                raw_formats[i].extension,
                raw_formats[i].name,
                RECOVERY_CATEGORY_RAW)) {
            return 0;
        }
    }
    return 1;
}

int mftprobe_recovery_order_load_common_profiles(Config *config, const char *db_path)
{
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT id, name, type, type_name, CAST(blob_start AS TEXT) "
        "FROM common "
        "WHERE type IS NOT NULL AND type <> '' "
        "ORDER BY id;";
    size_t count = 0;

    if (config == NULL || db_path == NULL) {
        return 0;
    }

    memset(config->loaded_recovery_formats, 0, sizeof(config->loaded_recovery_formats));
    memset(config->loaded_format_names, 0, sizeof(config->loaded_format_names));
    memset(config->loaded_format_extensions, 0, sizeof(config->loaded_format_extensions));
    memset(config->loaded_format_aliases, 0, sizeof(config->loaded_format_aliases));
    memset(config->loaded_format_extension_lists, 0, sizeof(config->loaded_format_extension_lists));
    config->loaded_recovery_order.formats = config->loaded_recovery_formats;
    config->loaded_recovery_order.count = 0;

    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db != NULL) {
            sqlite3_close(db);
        }
        return 0;
    }
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return 0;
    }

    while (sqlite3_step(stmt) == SQLITE_ROW && count < RECOVERY_FORMAT_MAX) {
        int id = sqlite3_column_int(stmt, 0);
        const unsigned char *name_text = sqlite3_column_text(stmt, 1);
        const unsigned char *type_text = sqlite3_column_text(stmt, 2);
        const unsigned char *type_name_text = sqlite3_column_text(stmt, 3);
        const unsigned char *blob_start_text = sqlite3_column_text(stmt, 4);
        size_t alias_count;
        size_t i;
        RecoveryValidatorId validator;
        uint32_t category_mask = 0;

        if (type_text == NULL) {
            continue;
        }

        alias_count = split_type_extensions(
            (const char *)type_text,
            config->loaded_format_aliases[count],
            FORMAT_EXTENSION_ALIAS_MAX
        );
        alias_count = expand_builtin_format_aliases(
            config->loaded_format_aliases[count],
            alias_count,
            FORMAT_EXTENSION_ALIAS_MAX
        );
        if (alias_count == 0) {
            continue;
        }

        copy_text_truncated_local(
            config->loaded_format_extensions[count],
            sizeof(config->loaded_format_extensions[count]),
            config->loaded_format_aliases[count][0]
        );
        if (config->loaded_format_extensions[count][0] == '\0' ||
            recovery_format_already_loaded(
                config,
                config->loaded_format_extensions[count],
                count)) {
            continue;
        }

        validator = validator_for_extensions(config->loaded_format_aliases[count], alias_count);
        category_mask = category_mask_from_type_name((const char *)type_name_text);
        for (i = 0; i < alias_count; i++) {
            category_mask |=
                extension_category_mask_local(config->loaded_format_aliases[count][i]);
            config->loaded_format_extension_lists[count][i] =
                config->loaded_format_aliases[count][i];
        }
        category_mask = normalize_loaded_format_category_mask_local(
            category_mask,
            config->loaded_format_aliases[count],
            alias_count
        );
        if (category_mask == 0) {
            category_mask = RECOVERY_CATEGORY_OTHER;
        }

        snprintf(
            config->loaded_format_names[count],
            sizeof(config->loaded_format_names[count]),
            "%s",
            name_text != NULL ? (const char *)name_text : config->loaded_format_extensions[count]
        );

        config->loaded_recovery_formats[count].format_id = (uint32_t)id;
        config->loaded_recovery_formats[count].name = config->loaded_format_names[count];
        config->loaded_recovery_formats[count].default_extension =
            config->loaded_format_extensions[count];
        config->loaded_recovery_formats[count].extensions =
            config->loaded_format_extension_lists[count];
        config->loaded_recovery_formats[count].extension_count = alias_count;
        config->loaded_recovery_formats[count].validator_id = validator;
        config->loaded_recovery_formats[count].category_mask = category_mask;
        if (blob_start_text != NULL && blob_start_text[0] != '\0') {
            uint8_t *blob_bytes = NULL;
            size_t blob_len = 0;

            if (hex_string_to_bytes(
                    (const char *)blob_start_text,
                    &blob_bytes,
                    &blob_len) &&
                blob_bytes != NULL &&
                blob_len > 0 &&
                blob_len <= FORMAT_BLOB_START_MAX) {
                memcpy(
                    config->loaded_recovery_formats[count].blob_start,
                    blob_bytes,
                    blob_len);
                config->loaded_recovery_formats[count].blob_start_length = blob_len;
            }
            free(blob_bytes);
        }
        /* The common database stores the RIFF subtype search key (for
         * example "AV" from the AVI marker at byte 8) in blob_start.  That
         * is useful to the raw scanner, but a metadata extent starts at the
         * beginning of the file.  Direct MFT recovery must therefore check
         * the outer RIFF header here; the RIFF validator below then checks
         * AVI/WAVE/WEBP/RMID at byte 8. */
        if (validator == RECOVERY_VALIDATOR_RIFF) {
            memcpy(config->loaded_recovery_formats[count].blob_start, "RIFF", 4U);
            config->loaded_recovery_formats[count].blob_start_length = 4U;
        }
        count++;
    }

    if (!append_builtin_container_image_formats_local(config, &count)) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }
    if (!append_builtin_raw_formats_local(config, &count)) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 0;
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (count == 0) {
        return 0;
    }
    config->loaded_recovery_order.formats = config->loaded_recovery_formats;
    config->loaded_recovery_order.count = count;
    return 1;
}

static int recovery_format_matches_name(const RecoveryFormat *format, const char *name)
{
    size_t i;

    if (format == NULL || name == NULL) {
        return 0;
    }

    for (i = 0; i < format->extension_count; i++) {
        if (has_ext_ci_local(name, format->extensions[i])) {
            return 1;
        }
    }
    return 0;
}

static const RecoveryFormat *recovery_order_match_name(
    const RecoveryOrder *order,
    const char *name
)
{
    size_t i;

    if (order == NULL) {
        order = mftprobe_recovery_default_order();
    }
    if (name == NULL) {
        return NULL;
    }

    for (i = 0; i < order->count; i++) {
        if (recovery_format_matches_name(&order->formats[i], name)) {
            return &order->formats[i];
        }
    }
    return NULL;
}

const RecoveryFormat *mftprobe_entry_selected_format(
    const Config *config,
    const MftEntry *entry
)
{
    if (entry == NULL || (entry->flags & 0x0002U)) {
        return NULL;
    }
    return recovery_order_match_name(
        config != NULL ? config->recovery_order : NULL,
        entry->name
    );
}
