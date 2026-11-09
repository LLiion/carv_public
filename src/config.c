/*
 * config.c
 * Initializes and releases application configuration.
 */

#include "config.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

#define DEFAULT_CHUNK_SIZE_USERS   (1024 * 1024)
#define DEFAULT_CHUNK_SIZE_RAW_ALL (8 * 1024 * 1024)
#define DEFAULT_DB_PATH            "data/database.db"
#define DEFAULT_CRASH_RETRIES      2
#define DEFAULT_TARGET_MIB_PER_SEC 18.0
#define ARRAY_LEN(array) (sizeof(array) / sizeof((array)[0]))
#define RECOVER_CATEGORY_IMG 0x01
#define RECOVER_CATEGORY_VID 0x02
#define RECOVER_CATEGORY_DOC 0x04
#define CONFIG_SCOPE_V1_PREFIX "@scope-v1:"

static char g_config_last_error[256] = "";

static void config_clear_error(void)
{
    g_config_last_error[0] = '\0';
}

static void config_set_errorf(const char *fmt, ...)
{
    va_list args;

    if (fmt == NULL) {
        config_clear_error();
        return;
    }

    va_start(args, fmt);
    vsnprintf(g_config_last_error, sizeof(g_config_last_error), fmt, args);
    va_end(args);
}

static int streq_ci_local(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    while (*a != '\0' && *b != '\0') {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) {
            return 0;
        }
        a++;
        b++;
    }

    return *a == '\0' && *b == '\0';
}

static int config_scope_hex_value(unsigned char value)
{
    if (value >= '0' && value <= '9') {
        return (int)(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return 10 + (int)(value - 'a');
    }
    if (value >= 'A' && value <= 'F') {
        return 10 + (int)(value - 'A');
    }
    return -1;
}

int config_scope_next_item(
    const char *scope_text,
    size_t *offset,
    char *out,
    size_t out_size
)
{
    const size_t prefix_length = strlen(CONFIG_SCOPE_V1_PREFIX);
    size_t input_offset;
    size_t output_length = 0U;
    int encoded;

    if (scope_text == NULL || offset == NULL || out == NULL || out_size == 0U) {
        return -1;
    }

    encoded = strncmp(scope_text, CONFIG_SCOPE_V1_PREFIX, prefix_length) == 0;
    input_offset = *offset;
    if (input_offset == 0U && encoded) {
        input_offset = prefix_length;
    }
    if (scope_text[input_offset] == '\0') {
        out[0] = '\0';
        *offset = input_offset;
        return 0;
    }

    while (scope_text[input_offset] != '\0' && scope_text[input_offset] != ',') {
        unsigned char value = (unsigned char)scope_text[input_offset++];

        if (encoded && value == '%') {
            int high;
            int low;

            if (scope_text[input_offset] == '\0' ||
                scope_text[input_offset + 1U] == '\0') {
                return -1;
            }
            high = config_scope_hex_value((unsigned char)scope_text[input_offset]);
            low = config_scope_hex_value((unsigned char)scope_text[input_offset + 1U]);
            if (high < 0 || low < 0) {
                return -1;
            }
            value = (unsigned char)((high << 4) | low);
            input_offset += 2U;
            if (value == '\0') {
                return -1;
            }
        }

        if (output_length + 1U >= out_size) {
            return -1;
        }
        out[output_length++] = (char)value;
    }

    if (scope_text[input_offset] == ',') {
        input_offset++;
    }
    out[output_length] = '\0';
    *offset = input_offset;

    if (!encoded) {
        char *start = out;
        char *end;

        while (*start == ' ' || *start == '\t') {
            start++;
        }
        if (start != out) {
            memmove(out, start, strlen(start) + 1U);
        }
        end = out + strlen(out);
        while (end > out && (end[-1] == ' ' || end[-1] == '\t')) {
            *--end = '\0';
        }
    }

    return 1;
}

int config_scope_append_item_v1(
    char *out,
    size_t out_size,
    const char *item
)
{
    static const char hex[] = "0123456789ABCDEF";
    const size_t prefix_length = strlen(CONFIG_SCOPE_V1_PREFIX);
    size_t length;
    const unsigned char *cursor;

    if (out == NULL || out_size == 0U || item == NULL) {
        return 0;
    }
    length = strlen(out);
    if (length == 0U) {
        if (prefix_length + 1U > out_size) {
            return 0;
        }
        memcpy(out, CONFIG_SCOPE_V1_PREFIX, prefix_length + 1U);
        length = prefix_length;
    } else if (strncmp(out, CONFIG_SCOPE_V1_PREFIX, prefix_length) != 0) {
        return 0;
    } else {
        if (length + 2U > out_size) {
            return 0;
        }
        out[length++] = ',';
        out[length] = '\0';
    }

    for (cursor = (const unsigned char *)item; *cursor != '\0'; cursor++) {
        unsigned char value = *cursor;
        int safe =
            (value >= 'a' && value <= 'z') ||
            (value >= 'A' && value <= 'Z') ||
            (value >= '0' && value <= '9') ||
            value == '/' || value == '-' || value == '_' ||
            value == '.' || value == '~';

        if (safe) {
            if (length + 2U > out_size) {
                return 0;
            }
            out[length++] = (char)value;
        } else {
            if (length + 4U > out_size) {
                return 0;
            }
            out[length++] = '%';
            out[length++] = hex[value >> 4];
            out[length++] = hex[value & 0x0FU];
        }
        out[length] = '\0';
    }

    return 1;
}

static const char *config_next_arg(int argc, char *argv[], int *index, const char *arg)
{
    if (argv == NULL || index == NULL || *index + 1 >= argc) {
        config_set_errorf("Missing value for %s", (arg != NULL) ? arg : "option");
        return NULL;
    }

    (*index)++;
    return argv[*index];
}

#define CONFIG_REQUIRE_NEXT_ARG(name) \
    const char *name = config_next_arg(argc, argv, &i, arg); \
    if ((name) == NULL) { \
        return 0; \
    }

static int valid_run_name(const char *value)
{
    if (value == NULL || value[0] == '\0') {
        return 0;
    }
    if (strcmp(value, ".") == 0 || strcmp(value, "..") == 0) {
        return 0;
    }
    return strchr(value, '/') == NULL && strchr(value, '\\') == NULL;
}

static void apply_scan_mode_defaults(AppConfig *config)
{
    if (config == NULL) {
        return;
    }

    if (config->scan_mode == APP_SCAN_MODE_RAW_ALL) {
        config->chunk_size = DEFAULT_CHUNK_SIZE_RAW_ALL;
        return;
    }

    config->chunk_size = DEFAULT_CHUNK_SIZE_USERS;
}

static void config_set_defaults(AppConfig *config)
{
    config_clear_error();
    config->root_scope_csv_storage[0] = '\0';
    config->db_path = DEFAULT_DB_PATH;
    config->input_path = NULL;
    config->source_path = NULL;
    config->image_path = NULL;
    config->output_dir = NULL;
    config->run_name = NULL;
    config->compare_mount_path = NULL;
    config->compare_scope_csv = NULL;
    config->record_list_path = NULL;
    config->target_filter_csv = NULL;
    config->root_scope_csv = NULL;
    config->root_scope_defaulted = 0;
    config->target_date_value = NULL;
    config->target_find_value = NULL;
    config->target_deleted_value = NULL;
    config->target_folder_levels = 0;
    config->mft_categories_csv = "all";
    config->mft_formats_csv = NULL;
    config->mft_dev_format = NULL;
    config->mft_limit = 0;
    config->metadata_test_jpegs = 0;
    config->metadata_test_jpeg_count = 0U;
    config->scan_mode = APP_SCAN_MODE_MFT_USERS;
    config->recover_img = 1;
    config->recover_vid = 1;
    config->recover_doc = 1;
    config->auto_recover_missed = 1;
    config->only_recover_missed = 0;
    config->auto_name_after_all = APP_AUTO_NAME_AFTER_ALL_DEFAULT;
    config->name_only = 0;
    config->make_image_first = 0;
    config->image_only = 0;
    config->image_size_bytes = 0;
    config->recovery_nap_enabled = 0;
    config->recovery_nap_power_cycle = 0;
    config->recovery_nap_minutes = 60U;
    config->recovery_nap_cycles = 3U;
    config->recovery_nap_test_after_seconds = 0U;
    config->image_ddrescue_mode = APP_IMAGE_DDRESCUE_MODE_BASIC;
    config->filesystem_target = APP_FILESYSTEM_TARGET_AUTO;
    config->mft_path_requested = 0;
    config->skip_mft_observation = 0;
    config->quick_resume = 0;
    config->additive_pass = 0;
    config->additive_requested = 0;
    config->additive_auto_selection = 0;
    config->resume_active = 0;
    config->resume_completed = 0;
    config->resume_scan_completed = 0;
    config->crash_retries = DEFAULT_CRASH_RETRIES;
    config->stall_retries = 4;
    config->resume_offset = 0;
    config->manual_start_offset = 0;
    config->crash_retry_skip_bytes = 0;
    config->stall_timeout_seconds = 5ULL * 60ULL;
    config->stall_retry_backtrack_bytes = 8ULL * 1024ULL * 1024ULL;
    config->target_mib_per_sec = DEFAULT_TARGET_MIB_PER_SEC;
    config->manual_start_explicit = 0;
    config->scan_state_path = NULL;
    config->record_list_auto = 0;
    config->list_formats = 0;
    config->list_root_folders = 0;
    config->list_folders_under = NULL;
    config->hypersafe_folder_fetch = 0;
    config->hypersafe_strategy = APP_HYPERSAFE_STRATEGY_NONE;
    config->hypersafe_preview_status_path = NULL;
    config->probe_source = 0;
    config->input_explicit = 0;
    config->show_help = 0;
    config->verbose = 0;
    apply_scan_mode_defaults(config);
}

static int parse_scan_mode(AppConfig *config, const char *value)
{
    if (config == NULL || value == NULL) {
        return 0;
    }

    if (strcmp(value, "folders") == 0 ||
        strcmp(value, "folder-path") == 0 ||
        strcmp(value, "folder_path") == 0 ||
        strcmp(value, "folder") == 0) {
        config->scan_mode = APP_SCAN_MODE_MFT_USERS;
        return 1;
    }

    if (strcmp(value, "all") == 0) {
        config->scan_mode = APP_SCAN_MODE_RAW_ALL;
        return 1;
    }

    if (strcmp(value, "mft") == 0) {
        config->scan_mode = APP_SCAN_MODE_MFT_USERS;
        config->mft_path_requested = 1;
        return 1;
    }

    if (strcmp(value, "comp") == 0) {
        config->scan_mode = APP_SCAN_MODE_COMPARE;
        return 1;
    }

    if (strcmp(value, "name") == 0) {
        config->name_only = 1;
        config->scan_mode = APP_SCAN_MODE_MFT_USERS;
        return 1;
    }

    return 0;
}

static int parse_filesystem_target(AppConfig *config, const char *value)
{
    if (config == NULL || value == NULL) {
        return 0;
    }

    if (streq_ci_local(value, "auto")) {
        config->filesystem_target = APP_FILESYSTEM_TARGET_AUTO;
        return 1;
    }

    if (streq_ci_local(value, "ntfs")) {
        config->filesystem_target = APP_FILESYSTEM_TARGET_NTFS;
        return 1;
    }

    if (streq_ci_local(value, "hfsplus") ||
        streq_ci_local(value, "hfs+") ||
        streq_ci_local(value, "hfs")) {
        config->filesystem_target = APP_FILESYSTEM_TARGET_HFSPLUS;
        return 1;
    }

    return 0;
}

typedef struct {
    const char *token;
    int flags;
} CategoryRecoverToken;

static const CategoryRecoverToken g_category_recover_tokens[] = {
    {"all", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_VID | RECOVER_CATEGORY_DOC},
    {"alla", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_VID | RECOVER_CATEGORY_DOC},
    {"media", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_VID},
    {"image", RECOVER_CATEGORY_IMG},
    {"images", RECOVER_CATEGORY_IMG},
    {"img", RECOVER_CATEGORY_IMG},
    {"picture", RECOVER_CATEGORY_IMG},
    {"pictures", RECOVER_CATEGORY_IMG},
    {"bild", RECOVER_CATEGORY_IMG},
    {"bilder", RECOVER_CATEGORY_IMG},
    {"raw", RECOVER_CATEGORY_IMG},
    {"camera_raw", RECOVER_CATEGORY_IMG},
    {"camera-raw", RECOVER_CATEGORY_IMG},
    {"systemkamera", RECOVER_CATEGORY_IMG},
    {"raformat", RECOVER_CATEGORY_IMG},
    {"photo", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_DOC},
    {"photos", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_DOC},
    {"photo_pro", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_DOC},
    {"photo-pro", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_DOC},
    {"photopro", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_DOC},
    {"prophoto", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_DOC},
    {"foto", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_DOC},
    {"bilder_pro", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_DOC},
    {"bildpro", RECOVER_CATEGORY_IMG | RECOVER_CATEGORY_DOC},
    {"library", RECOVER_CATEGORY_DOC},
    {"libraries", RECOVER_CATEGORY_DOC},
    {"librarys", RECOVER_CATEGORY_DOC},
    {"catalog", RECOVER_CATEGORY_DOC},
    {"catalogs", RECOVER_CATEGORY_DOC},
    {"catalogue", RECOVER_CATEGORY_DOC},
    {"catalogues", RECOVER_CATEGORY_DOC},
    {"katalog", RECOVER_CATEGORY_DOC},
    {"kataloger", RECOVER_CATEGORY_DOC},
    {"bibliotek", RECOVER_CATEGORY_DOC},
    {"video", RECOVER_CATEGORY_VID},
    {"videos", RECOVER_CATEGORY_VID},
    {"vid", RECOVER_CATEGORY_VID},
    {"movie", RECOVER_CATEGORY_VID},
    {"movies", RECOVER_CATEGORY_VID},
    {"film", RECOVER_CATEGORY_VID},
    {"filmer", RECOVER_CATEGORY_VID},
    {"document", RECOVER_CATEGORY_DOC},
    {"documents", RECOVER_CATEGORY_DOC},
    {"doc", RECOVER_CATEGORY_DOC},
    {"docs", RECOVER_CATEGORY_DOC},
    {"dokument", RECOVER_CATEGORY_DOC}
};

static int category_token_recover_flags(const char *token)
{
    size_t i;

    if (token == NULL || token[0] == '\0') {
        return 0;
    }

    for (i = 0; i < ARRAY_LEN(g_category_recover_tokens); i++) {
        const CategoryRecoverToken *entry = &g_category_recover_tokens[i];

        if (streq_ci_local(token, entry->token)) {
            return entry->flags;
        }
    }

    return 0;
}

int config_category_csv_requests_all(const char *categories_csv)
{
    const char *cursor;

    if (categories_csv == NULL || categories_csv[0] == '\0') {
        return 0;
    }
    cursor = categories_csv;
    while (*cursor != '\0') {
        const char *start;
        const char *end;

        while (*cursor == ',' || *cursor == ';' ||
               isspace((unsigned char)*cursor)) {
            cursor++;
        }
        start = cursor;
        while (*cursor != '\0' && *cursor != ',' && *cursor != ';') {
            cursor++;
        }
        end = cursor;
        while (end > start && isspace((unsigned char)end[-1])) {
            end--;
        }
        if ((size_t)(end - start) == 3U &&
            tolower((unsigned char)start[0]) == 'a' &&
            tolower((unsigned char)start[1]) == 'l' &&
            tolower((unsigned char)start[2]) == 'l') {
            return 1;
        }
    }
    return 0;
}

static void sync_recover_flags_from_categories(AppConfig *config, const char *csv)
{
    char work[256];
    char *token;
    int flags = 0;

    if (config == NULL || csv == NULL || csv[0] == '\0') {
        return;
    }

    if (strlen(csv) >= sizeof(work)) {
        return;
    }

    snprintf(work, sizeof(work), "%s", csv);

    token = strtok(work, ",;");
    while (token != NULL) {
        while (*token != '\0' && isspace((unsigned char)*token)) {
            token++;
        }

        flags |= category_token_recover_flags(token);
        token = strtok(NULL, ",;");
    }

    if (flags == 0) {
        return;
    }

    config->recover_img = 0;
    config->recover_vid = 0;
    config->recover_doc = 0;
    if ((flags & RECOVER_CATEGORY_IMG) != 0) {
        config->recover_img = 1;
    }
    if ((flags & RECOVER_CATEGORY_VID) != 0) {
        config->recover_vid = 1;
    }
    if ((flags & RECOVER_CATEGORY_DOC) != 0) {
        config->recover_doc = 1;
    }
}

int config_init(AppConfig *config, int argc, char *argv[])
{
    int i;

    if (config == NULL) {
        config_set_errorf("Config object is missing");
        return 0;
    }

    config_set_defaults(config);

    for (i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            config->show_help = 1;
            config_print_help(argv[0]);
            return 1;
        }

        if (strcmp(arg, "--version") == 0 || strcmp(arg, "-V") == 0) {
            config->show_help = 1;
            printf("Carv %s\n", CARV_VERSION);
            return 1;
        }

        if (arg[0] == '-' && arg[1] != '-' && arg[1] != '\0') {
            config_set_errorf("Unknown option: %s", arg);
            config_print_help(argv[0]);
            return 0;
        }

        if (strcmp(arg, "--src") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->source_path = value;
            config->input_path = config->source_path;
            config->input_explicit = 1;
            continue;
        }

        if (strcmp(arg, "--probe") == 0) {
            config->probe_source = 1;
            continue;
        }

        if (strcmp(arg, "--make-image") == 0) {
            config->make_image_first = 1;
            continue;
        }

        if (strcmp(arg, "--image-only") == 0) {
            config->make_image_first = 1;
            config->image_only = 1;
            continue;
        }

        if (strcmp(arg, "--image-size") == 0) {
            char trailing;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%llu%c", &config->image_size_bytes, &trailing) != 1 ||
                config->image_size_bytes == 0ULL) {
                config_set_errorf("Invalid value for %s: %s", arg, value);
                return 0;
            }

            continue;
        }

        if (strcmp(arg, "--recovery-nap") == 0) {
            config->recovery_nap_enabled = 1;
            config->make_image_first = 1;
            continue;
        }

        if (strcmp(arg, "--recovery-nap-power-cycle") == 0) {
            config->recovery_nap_enabled = 1;
            config->recovery_nap_power_cycle = 1;
            config->make_image_first = 1;
            continue;
        }

        if (strcmp(arg, "--recovery-nap-minutes") == 0) {
            char trailing;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%u%c", &config->recovery_nap_minutes, &trailing) != 1 ||
                config->recovery_nap_minutes == 0U ||
                config->recovery_nap_minutes > 10080U) {
                config_set_errorf("Invalid value for %s: %s (expected 1-10080)", arg, value);
                return 0;
            }
            config->recovery_nap_enabled = 1;
            config->make_image_first = 1;
            continue;
        }

        if (strcmp(arg, "--recovery-nap-cycles") == 0) {
            char trailing;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%u%c", &config->recovery_nap_cycles, &trailing) != 1 ||
                config->recovery_nap_cycles == 0U ||
                config->recovery_nap_cycles > 999U) {
                config_set_errorf("Invalid value for %s: %s (expected 1-999)", arg, value);
                return 0;
            }
            config->recovery_nap_enabled = 1;
            config->make_image_first = 1;
            continue;
        }

        if (strcmp(arg, "--recovery-nap-test-after-seconds") == 0) {
            char trailing;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%u%c", &config->recovery_nap_test_after_seconds, &trailing) != 1 ||
                config->recovery_nap_test_after_seconds == 0U ||
                config->recovery_nap_test_after_seconds > 604800U) {
                config_set_errorf("Invalid value for %s: %s (expected 1-604800)", arg, value);
                return 0;
            }
            config->recovery_nap_enabled = 1;
            config->make_image_first = 1;
            continue;
        }

        if (strcmp(arg, "--ddrescue-mode") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            if (streq_ci_local(value, "basic")) {
                config->image_ddrescue_mode = APP_IMAGE_DDRESCUE_MODE_BASIC;
            } else if (streq_ci_local(value, "thorough")) {
                config->image_ddrescue_mode = APP_IMAGE_DDRESCUE_MODE_THOROUGH;
            } else {
                config_set_errorf(
                    "Invalid value for %s: %s (expected basic|thorough)",
                    arg,
                    value
                );
                return 0;
            }
            continue;
        }

        if (strcmp(arg, "--filesys") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            if (!parse_filesystem_target(config, value)) {
                config_set_errorf(
                    "Invalid value for %s: %s (expected auto|ntfs|hfsplus)",
                    arg,
                    value
                );
                return 0;
            }
            continue;
        }

        if (strcmp(arg, "--mft") == 0) {
            config->mft_path_requested = 1;
            continue;
        }

        if (strcmp(arg, "--mode") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            if (!parse_scan_mode(config, value)) {
                config_set_errorf("Invalid value for %s: %s", arg, value);
                return 0;
            }

            continue;
        }

        if (strcmp(arg, "--out") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            if (value[0] == '\0') {
                config_set_errorf("Missing value for --out");
                return 0;
            }
            config->output_dir = value;
            continue;
        }

        if (strcmp(arg, "--verbose") == 0) {
            config->verbose = 1;
            continue;
        }

        if (strcmp(arg, "--list-formats") == 0) {
            config->list_formats = 1;
            continue;
        }

        if (strcmp(arg, "--list-root-folders") == 0) {
            config->list_root_folders = 1;
            continue;
        }

        if (strcmp(arg, "--list-folders-under") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->list_folders_under = value;
            continue;
        }

        if (strcmp(arg, "--hypersafe-folder-fetch") == 0) {
            config->hypersafe_folder_fetch = 1;
            config->filesystem_target = APP_FILESYSTEM_TARGET_NTFS;
            continue;
        }

        if (strcmp(arg, "--hypersafe") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            if (strcmp(value, "immediate") == 0 ||
                strcmp(value, "image-immediately") == 0) {
                config->hypersafe_strategy =
                    APP_HYPERSAFE_STRATEGY_IMAGE_IMMEDIATELY;
            } else if (strcmp(value, "selected-folders") == 0) {
                config->hypersafe_strategy =
                    APP_HYPERSAFE_STRATEGY_SELECTED_FOLDERS;
            } else {
                config_set_errorf(
                    "Unknown --hypersafe strategy: %s (expected immediate or selected-folders)",
                    value
                );
                return 0;
            }
            config->filesystem_target = APP_FILESYSTEM_TARGET_NTFS;
            continue;
        }

        if (strcmp(arg, "--hypersafe-recover") == 0) {
            config->hypersafe_strategy =
                APP_HYPERSAFE_STRATEGY_SELECTED_FOLDERS;
            config->filesystem_target = APP_FILESYSTEM_TARGET_NTFS;
            continue;
        }

        if (strcmp(arg, "--hypersafe-preview-status") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->hypersafe_preview_status_path = value;
            config->filesystem_target = APP_FILESYSTEM_TARGET_NTFS;
            continue;
        }

        if (strcmp(arg, "--fold") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->root_scope_csv = value;
            config->root_scope_defaulted = 0;
            continue;
        }

        if (strcmp(arg, "--comp") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->compare_mount_path = value;
            continue;
        }

        if (strcmp(arg, "--scp") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->compare_scope_csv = value;
            continue;
        }

        if (strcmp(arg, "--recdiff") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            if (strcmp(value, "1") == 0 ||
                streq_ci_local(value, "on") ||
                streq_ci_local(value, "yes") ||
                streq_ci_local(value, "true")) {
                config->record_list_auto = 1;
                config->record_list_path = NULL;
            } else if (strcmp(value, "0") == 0 ||
                       streq_ci_local(value, "off") ||
                       streq_ci_local(value, "no") ||
                       streq_ci_local(value, "false")) {
                config->record_list_auto = 0;
                config->record_list_path = NULL;
            } else {
                config->record_list_path = value;
                config->record_list_auto = 0;
            }
            continue;
        }

        if (strcmp(arg, "--date") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->target_date_value = value;
            continue;
        }

        if (strcmp(arg, "--find") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->target_find_value = value;
            continue;
        }

        if (strcmp(arg, "--del") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->target_deleted_value = value;
            continue;
        }

        if (strcmp(arg, "--id") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            if (!valid_run_name(value)) {
                config_set_errorf("Invalid value for %s: %s (expected a folder name)", arg, value);
                return 0;
            }
            config->run_name = value;
            continue;
        }

        if (strcmp(arg, "--limit") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%llu", &config->mft_limit) != 1) {
                config_set_errorf("Invalid value for --limit: %s", value);
                return 0;
            }

            continue;
        }

        if (strcmp(arg, "--test-jpegs") == 0) {
            unsigned int count = 0U;
            char trailing;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%u%c", &count, &trailing) != 1 ||
                count == 0U ||
                count > 100U) {
                config_set_errorf("Invalid value for --test-jpegs: %s (expected 1-100)", value);
                return 0;
            }
            config->metadata_test_jpegs = 1;
            config->metadata_test_jpeg_count = count;
            continue;
        }

        if (strcmp(arg, "--start") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%llu", &config->manual_start_offset) != 1) {
                config_set_errorf("Invalid value for %s: %s", arg, value);
                return 0;
            }
            config->manual_start_explicit = 1;
            continue;
        }

        if (strcmp(arg, "--cat") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->mft_categories_csv = value;
            continue;
        }

        if (strcmp(arg, "--fmt") == 0) {
            CONFIG_REQUIRE_NEXT_ARG(value);
            config->mft_formats_csv = value;
            continue;
        }

        if (strcmp(arg, "--additive") == 0) {
            config->additive_requested = 1;
            continue;
        }

        if (strcmp(arg, "--crash-retries") == 0) {
            int retries = 0;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%d", &retries) != 1 ||
                retries < 0 ||
                retries > 10) {
                config_set_errorf(
                    "Invalid value for --crash-retries: %s (expected 0-10)",
                    value
                );
                return 0;
            }
            config->crash_retries = retries;
            continue;
        }

        if (strcmp(arg, "--crash-retry-skip-mib") == 0) {
            unsigned long long skip_mib = 0;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%llu", &skip_mib) != 1 ||
                skip_mib > (1024ULL * 1024ULL)) {
                config_set_errorf(
                    "Invalid value for --crash-retry-skip-mib: %s",
                    value
                );
                return 0;
            }
            config->crash_retry_skip_bytes = skip_mib * 1024ULL * 1024ULL;
            continue;
        }

        if (strcmp(arg, "--stall-retries") == 0) {
            int retries = 0;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%d", &retries) != 1 ||
                retries < 0 ||
                retries > 10) {
                config_set_errorf(
                    "Invalid value for --stall-retries: %s (expected 0-10)",
                    value
                );
                return 0;
            }
            config->stall_retries = retries;
            continue;
        }

        if (strcmp(arg, "--stall-timeout-min") == 0) {
            unsigned long long timeout_min = 0;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%llu", &timeout_min) != 1 ||
                timeout_min > (24ULL * 60ULL)) {
                config_set_errorf(
                    "Invalid value for --stall-timeout-min: %s",
                    value
                );
                return 0;
            }
            config->stall_timeout_seconds = timeout_min * 60ULL;
            continue;
        }

        if (strcmp(arg, "--stall-retry-backtrack-mib") == 0) {
            unsigned long long backtrack_mib = 0;

            CONFIG_REQUIRE_NEXT_ARG(value);
            if (sscanf(value, "%llu", &backtrack_mib) != 1 ||
                backtrack_mib > (1024ULL * 1024ULL)) {
                config_set_errorf(
                    "Invalid value for --stall-retry-backtrack-mib: %s",
                    value
                );
                return 0;
            }
            config->stall_retry_backtrack_bytes =
                backtrack_mib * 1024ULL * 1024ULL;
            continue;
        }

        config_set_errorf("Unknown option: %s", arg);
        config_print_help(argv[0]);
        return 0;
    }

    if (config->mft_categories_csv != NULL &&
        config->mft_categories_csv[0] != '\0') {
        if (config_category_csv_requests_all(config->mft_categories_csv)) {
            config->mft_categories_csv = "all";
        }
        sync_recover_flags_from_categories(config, config->mft_categories_csv);
    }

    if (config->hypersafe_folder_fetch &&
        (config->list_root_folders || config->list_folders_under != NULL ||
         config->hypersafe_preview_status_path != NULL)) {
        config_set_errorf(
            "--hypersafe-folder-fetch cannot be combined with folder-list preview options"
        );
        return 0;
    }
    if (config->hypersafe_preview_status_path != NULL &&
        !config->list_root_folders && config->list_folders_under == NULL) {
        config_set_errorf(
            "--hypersafe-preview-status requires --list-root-folders or --list-folders-under"
        );
        return 0;
    }
    if ((config->hypersafe_folder_fetch ||
         config->hypersafe_strategy != APP_HYPERSAFE_STRATEGY_NONE ||
         config->hypersafe_preview_status_path != NULL) &&
        config->filesystem_target != APP_FILESYSTEM_TARGET_NTFS) {
        config_set_errorf("Hypersafe currently requires NTFS");
        return 0;
    }
    if (config->hypersafe_folder_fetch &&
        config->hypersafe_strategy != APP_HYPERSAFE_STRATEGY_NONE) {
        config_set_errorf(
            "--hypersafe-folder-fetch and --hypersafe-recover are separate steps"
        );
        return 0;
    }
    if (config->hypersafe_strategy ==
            APP_HYPERSAFE_STRATEGY_SELECTED_FOLDERS &&
        (config->root_scope_csv == NULL || config->root_scope_csv[0] == '\0')) {
        config_set_errorf(
            "Hypersafe selected-folders requires --fold <selected-folders>"
        );
        return 0;
    }

    if (!config->show_help &&
        !config->list_formats &&
        !config->probe_source &&
        !config->name_only &&
        !config->input_explicit) {
        config_set_errorf("Missing required --src <path>");
        return 0;
    }

    if (!config->show_help &&
        !config->list_formats &&
        !config->list_root_folders &&
        config->list_folders_under == NULL &&
        !config->probe_source &&
        (config->output_dir == NULL || config->output_dir[0] == '\0')) {
        config_set_errorf("Missing required --out <dir>");
        return 0;
    }

    if (!config->show_help &&
        !config->list_formats &&
        !config->list_root_folders &&
        config->list_folders_under == NULL &&
        !config->probe_source &&
        !valid_run_name(config->run_name)) {
        config_set_errorf("Missing required --id <name>");
        return 0;
    }

    if (config->mft_path_requested &&
        config->scan_mode == APP_SCAN_MODE_RAW_ALL) {
        config->scan_mode = APP_SCAN_MODE_MFT_USERS;
    }
    if (config->mft_path_requested) {
        config->mft_categories_csv = NULL;
        config->mft_formats_csv = NULL;
        config->mft_dev_format = NULL;
    }

    apply_scan_mode_defaults(config);

    return 1;
}

const char *config_last_error(void)
{
    return g_config_last_error;
}

void config_free(AppConfig *config)
{
    if (config == NULL) {
        return;
    }

    config->root_scope_csv_storage[0] = '\0';
    config->chunk_size = 0;
    config->db_path = NULL;
    config->input_path = NULL;
    config->source_path = NULL;
    config->image_path = NULL;
    config->output_dir = NULL;
    config->run_name = NULL;
    config->compare_mount_path = NULL;
    config->compare_scope_csv = NULL;
    config->record_list_path = NULL;
    config->target_filter_csv = NULL;
    config->root_scope_csv = NULL;
    config->root_scope_defaulted = 0;
    config->target_date_value = NULL;
    config->target_find_value = NULL;
    config->target_deleted_value = NULL;
    config->target_folder_levels = 0;
    config->mft_categories_csv = NULL;
    config->mft_formats_csv = NULL;
    config->mft_dev_format = NULL;
    config->mft_limit = 0;
    config->metadata_test_jpegs = 0;
    config->metadata_test_jpeg_count = 0U;
    config->scan_mode = APP_SCAN_MODE_RAW_ALL;
    config->recover_img = 0;
    config->recover_vid = 0;
    config->recover_doc = 0;
    config->auto_recover_missed = 0;
    config->only_recover_missed = 0;
    config->auto_name_after_all = 0;
    config->name_only = 0;
    config->make_image_first = 0;
    config->image_only = 0;
    config->image_size_bytes = 0;
    config->recovery_nap_enabled = 0;
    config->recovery_nap_power_cycle = 0;
    config->recovery_nap_minutes = 60U;
    config->recovery_nap_cycles = 3U;
    config->recovery_nap_test_after_seconds = 0U;
    config->image_ddrescue_mode = APP_IMAGE_DDRESCUE_MODE_BASIC;
    config->filesystem_target = APP_FILESYSTEM_TARGET_AUTO;
    config->mft_path_requested = 0;
    config->skip_mft_observation = 0;
    config->quick_resume = 0;
    config->additive_pass = 0;
    config->additive_requested = 0;
    config->additive_auto_selection = 0;
    config->resume_active = 0;
    config->resume_completed = 0;
    config->resume_scan_completed = 0;
    config->crash_retries = DEFAULT_CRASH_RETRIES;
    config->stall_retries = 4;
    config->resume_offset = 0;
    config->manual_start_offset = 0;
    config->crash_retry_skip_bytes = 0;
    config->stall_timeout_seconds = 5ULL * 60ULL;
    config->stall_retry_backtrack_bytes = 8ULL * 1024ULL * 1024ULL;
    config->target_mib_per_sec = DEFAULT_TARGET_MIB_PER_SEC;
    config->manual_start_explicit = 0;
    config->scan_state_path = NULL;
    config->record_list_auto = 0;
    config->list_formats = 0;
    config->list_root_folders = 0;
    config->list_folders_under = NULL;
    config->hypersafe_folder_fetch = 0;
    config->hypersafe_strategy = APP_HYPERSAFE_STRATEGY_NONE;
    config->hypersafe_preview_status_path = NULL;
    config->probe_source = 0;
    config->input_explicit = 0;
    config->show_help = 0;
    config->verbose = 0;
}

void config_print_help(const char *program_name)
{
    const char *name = (program_name != NULL) ? program_name : "file_carver";

    printf("Usage:\n");
    printf("  %s --src <path> --mode <folder-path|folders|all|mft|comp> --out <dir> --id <run> [options]\n", name);
    printf("  %s --mode name --out <dir> --id <run> [--src <path>]\n", name);
    printf("  %s --probe [--src <path>] [--out <dir> --id <run>]\n", name);
    printf("  %s --list-formats\n", name);
    printf("  %s --src <path> --list-root-folders\n", name);
    printf("  %s --src <path> --list-folders-under <folder>\n", name);
    printf("  %s --src <path> --out <dir> --id <run> --hypersafe-folder-fetch\n", name);
    printf("  %s --src <path> --out <dir> --id <run> --hypersafe immediate\n", name);
    printf("  %s --src <path> --out <dir> --id <run> --hypersafe-recover --fold <list> [--cat/--fmt]\n", name);
    printf("\n");
    printf("Required for recovery runs:\n");
    printf("  --src <path>     source device, disk image, or mounted tree (not required for --mode name)\n");
    printf("  --out <dir>      output base directory\n");
    printf("  --id <name>      run folder name under --out\n");
    printf("  --mode <mode>    folder-path/folders, all, mft, comp, or name (default: folder-path)\n");
    printf("\n");
    printf("Recovery selection:\n");
    printf("  --cat <list>     all, media, photo, images, raw, libraries, vid, doc\n");
    printf("  --fmt <list>     exact extensions, comma-separated\n");
    printf("  --fold <list>    exact paths or partial NTFS terms; comma=OR, uppercase AND=all terms\n");
    printf("                   (default: Users; use / for full root)\n");
    printf("  --date <value>   YYYYMMDD or YYYYMMDD-YYYYMMDD\n");
    printf("  --find <text>    filename/path/header text filter for compare workflows\n");
    printf("  --del <0|1|2>    0 live, 1 deleted, 2 both\n");
    printf("  --start <bytes>  manual start offset\n");
    printf("  --limit <bytes>  manual stop/limit byte value\n");
    printf("  --test-jpegs <n> recover up to n JPEGs from filesystem metadata into recovered/test\n");
    printf("  --additive       reuse an existing completed all-run and scan for additional formats\n");
    printf("\n");
    printf("Filesystem and compare:\n");
    printf("  --filesys <auto|ntfs|hfsplus>  filesystem target (default: auto)\n");
    printf("  --mft                  legacy alias for metadata-first folder-path recovery\n");
    printf("  --comp <path>          diagnostic compare mount/tree\n");
    printf("  --scp <list>           compare scope, for example desktop,pictures,documents\n");
    printf("  --recdiff <0|1|path>   compare-only, current-run diff, or explicit diff/list path\n");
    printf("\n");
    printf("Probe and previews:\n");
    printf("  --probe                    inspect visible disks or the selected source and exit\n");
    printf("  --list-formats             print known file extensions and exit\n");
    printf("  --list-root-folders        print top-level folders from --src and exit\n");
    printf("  --list-folders-under <p>   print child folders under path p from --src and exit\n");
    printf("  --hypersafe-folder-fetch   ddrescue only disk headers and NTFS $MFT into a sparse preview image\n");
    printf("  --hypersafe immediate      wait for the source, bind its identity, and image it immediately\n");
    printf("  --hypersafe-recover        rescue selected NTFS folders first, then continue the same image/map to the full source\n");
    printf("  --hypersafe-preview-status <path>  read a folder preview through its ddrescue map/status\n");
    printf("\n");
    printf("Image-first and difficult disks:\n");
    printf("  --make-image                       create a full-source ddrescue image before scanning\n");
    printf("  --image-only                       create/update the image without reconstructing files (also valid with Hypersafe)\n");
    printf("  --image-size <bytes>               manual image size when device size is unavailable\n");
    printf("  --ddrescue-mode <basic|thorough>   basic quick pass or thorough rescue pass\n");
    printf("  --recovery-nap                     sleep and retry after a lost ddrescue source\n");
    printf("  --recovery-nap-minutes <n>         minutes to sleep between Recovery Nap cycles\n");
    printf("  --recovery-nap-cycles <n>          maximum Recovery Nap cycles\n");
    printf("  --recovery-nap-power-cycle         try USB deauthorize/reauthorize during naps\n");
    printf("  --recovery-nap-test-after-seconds <n>  simulate one ddrescue loss for testing\n");
    printf("\n");
    printf("Supervision and diagnostics:\n");
    printf("  --crash-retries <n>              restart after crash-class failures\n");
    printf("  --crash-retry-skip-mib <n>       advance the scan offset before crash retry\n");
    printf("  --stall-retries <n>              restart after raw-I/O stalls\n");
    printf("  --stall-timeout-min <n>          stalled minutes before restart logic triggers\n");
    printf("  --stall-retry-backtrack-mib <n>  backtrack before a stall retry restart\n");
    printf("  --verbose                        print detailed logs\n");
    printf("  --version, -V                    show Carv version\n");
    printf("  --help, -h                       show this help\n");
    printf("\n");
    printf("Defaults:\n");
    printf("  folder-path uses --fold Users when no folder list is given.\n");
    printf("  follow-up recovery, revisit passes, and post-all naming run automatically when supported.\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s --src /dev/disk10 --mode folders --out /media/eh/out --id kund_users --cat media\n", name);
    printf("  %s --src /dev/disk10 --mode all --make-image --out /media/eh/out --id kund_all --cat photo\n", name);
    printf("  %s --probe --src /dev/sdX --out /media/eh/out --id probe_sdX\n", name);
}

const char *config_scan_mode_label(const AppConfig *config)
{
    if (config == NULL) {
        return "folders";
    }

    switch (config->scan_mode) {
        case APP_SCAN_MODE_RAW_ALL:
            return "all";
        case APP_SCAN_MODE_COMPARE:
            return "comp";
        case APP_SCAN_MODE_MFT_USERS:
        default:
            return "folders";
    }
}

const char *config_recover_mode_label(const AppConfig *config)
{
    if (config == NULL) {
        return "all";
    }

    if (config->recover_img &&
        config->recover_vid &&
        config->recover_doc) {
        return "all";
    }

    if (config->recover_img &&
        config->recover_vid &&
        !config->recover_doc) {
        return "img,vid";
    }

    if (config->recover_img &&
        !config->recover_vid &&
        config->recover_doc) {
        return "img,doc";
    }

    if (!config->recover_img &&
        config->recover_vid &&
        config->recover_doc) {
        return "vid,doc";
    }

    if (config->recover_img) {
        return "img";
    }

    if (config->recover_vid) {
        return "vid";
    }

    if (config->recover_doc) {
        return "doc";
    }

    return "none";
}
