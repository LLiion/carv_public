#include "raw_all_selection.h"

#include "config.h"
#include "fs_backend.h"
#include "mftprobe_engine_types.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    int present;
    time_t updated_unix;
    uint32_t category_mask;
    char categories_csv[1024];
    char formats_csv[1024];
    char dev_format[128];
    char active_formats_csv[1024];
} RawAllSelectionState;

static int text_has_value(const char *text)
{
    return text != NULL && text[0] != '\0';
}

static int build_selection_path(
    const char *run_dir,
    char *out,
    size_t out_size
)
{
    if (!text_has_value(run_dir) || out == NULL || out_size == 0U) {
        return 0;
    }
    return snprintf(
               out,
               out_size,
               "%s/%s/raw_all_selection.txt",
               run_dir,
               APP_STATE_DIR_NAME) < (int)out_size;
}

static int parse_state_value(
    const char *line,
    const char *key,
    char *out,
    size_t out_size
)
{
    size_t key_len;
    size_t value_len;
    const char *value;

    if (line == NULL || key == NULL || out == NULL || out_size == 0U) {
        return 0;
    }

    key_len = strlen(key);
    if (strncmp(line, key, key_len) != 0 || line[key_len] != '=') {
        return 0;
    }

    value = line + key_len + 1U;
    value_len = strlen(value);
    while (value_len > 0U &&
           (value[value_len - 1U] == '\n' ||
            value[value_len - 1U] == '\r')) {
        value_len--;
    }
    if (value_len >= out_size) {
        value_len = out_size - 1U;
    }
    memcpy(out, value, value_len);
    out[value_len] = '\0';
    return 1;
}

static int csv_has_token_ci(const char *csv, const char *wanted)
{
    const char *cursor;
    size_t wanted_len;

    if (!text_has_value(csv) || !text_has_value(wanted)) {
        return 0;
    }
    wanted_len = strlen(wanted);
    cursor = csv;
    while (*cursor != '\0') {
        const char *start;
        const char *end;
        size_t len;

        while (*cursor == ',' ||
               *cursor == ';' ||
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
        len = (size_t)(end - start);
        if (len == wanted_len && strncasecmp(start, wanted, len) == 0) {
            return 1;
        }
    }
    return 0;
}

static void normalize_csv_tokens(
    const char *input,
    char *out,
    size_t out_size
)
{
    char work[1024];
    char *token;
    size_t used = 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }
    out[0] = '\0';
    if (!text_has_value(input) || strlen(input) >= sizeof(work)) {
        return;
    }

    snprintf(work, sizeof(work), "%s", input);
    token = strtok(work, ",;");
    while (token != NULL) {
        char clean[128];
        size_t len;
        size_t i;

        while (*token != '\0' && isspace((unsigned char)*token)) {
            token++;
        }
        len = strlen(token);
        while (len > 0U && isspace((unsigned char)token[len - 1U])) {
            token[--len] = '\0';
        }
        if (len > 0U && len < sizeof(clean)) {
            for (i = 0U; i < len; i++) {
                clean[i] = (char)tolower((unsigned char)token[i]);
            }
            clean[len] = '\0';
            if (!csv_has_token_ci(out, clean)) {
                int wrote = snprintf(
                    out + used,
                    out_size > used ? out_size - used : 0U,
                    "%s%s",
                    used > 0U ? "," : "",
                    clean
                );
                if (wrote < 0 ||
                    (size_t)wrote >= (out_size > used ? out_size - used : 0U)) {
                    out[out_size - 1U] = '\0';
                    return;
                }
                used += (size_t)wrote;
            }
        }
        token = strtok(NULL, ",;");
    }
}

static int current_selection_is_default_all(const AppConfig *config)
{
    return config != NULL &&
           !text_has_value(config->mft_formats_csv) &&
           !text_has_value(config->mft_dev_format) &&
           (!text_has_value(config->mft_categories_csv) ||
            config_category_csv_requests_all(config->mft_categories_csv));
}

static int load_selection_state(
    const char *run_dir,
    RawAllSelectionState *out
)
{
    char path[PATH_MAX_LEN];
    FILE *file;
    char line[1400];
    char value[1024];
    RawAllSelectionState state = {0};

    if (!text_has_value(run_dir) ||
        out == NULL ||
        !build_selection_path(run_dir, path, sizeof(path))) {
        return 0;
    }

    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        if (parse_state_value(line, "updated_unix", value, sizeof(value))) {
            state.updated_unix = (time_t)strtoull(value, NULL, 10);
            continue;
        }
        if (parse_state_value(line, "category_mask", value, sizeof(value))) {
            state.category_mask = (uint32_t)strtoul(value, NULL, 16);
            continue;
        }
        if (parse_state_value(line, "categories_csv", state.categories_csv, sizeof(state.categories_csv))) {
            continue;
        }
        if (parse_state_value(line, "formats_csv", state.formats_csv, sizeof(state.formats_csv))) {
            continue;
        }
        if (parse_state_value(line, "dev_format", state.dev_format, sizeof(state.dev_format))) {
            continue;
        }
        if (parse_state_value(line, "active_formats_csv", state.active_formats_csv, sizeof(state.active_formats_csv))) {
            continue;
        }
    }
    fclose(file);
    state.present = 1;
    *out = state;
    return 1;
}

static int load_hfs_measurement_active_formats(
    const char *run_dir,
    RawAllSelectionState *out)
{
    char path[PATH_MAX_LEN];
    char line[1400];
    char value[1024];
    FILE *file;
    RawAllSelectionState state = {0};

    if (!text_has_value(run_dir) || out == NULL ||
        snprintf(
            path,
            sizeof(path),
            "%s/%s/metadata/sequential_extent_measurement.txt",
            run_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(path)) {
        return 0;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        if (parse_state_value(
                line,
                "assembly_selected_formats",
                value,
                sizeof(value))) {
            normalize_csv_tokens(
                value,
                state.active_formats_csv,
                sizeof(state.active_formats_csv));
            break;
        }
    }
    fclose(file);
    if (!text_has_value(state.active_formats_csv)) {
        return 0;
    }
    state.present = 1;
    *out = state;
    return 1;
}

static int active_formats_cover_current(
    const RawAllSelectionState *saved,
    const char *current_active_formats,
    char *missing_token,
    size_t missing_token_size
)
{
    char normalized[1024];
    char work[1024];
    char *token;

    if (missing_token != NULL && missing_token_size > 0U) {
        missing_token[0] = '\0';
    }
    if (!text_has_value(current_active_formats)) {
        return 1;
    }
    if (saved == NULL ||
        !text_has_value(saved->active_formats_csv) ||
        strlen(current_active_formats) >= sizeof(work)) {
        return 0;
    }

    normalize_csv_tokens(current_active_formats, normalized, sizeof(normalized));
    if (!text_has_value(normalized)) {
        return 1;
    }
    snprintf(work, sizeof(work), "%s", normalized);
    token = strtok(work, ",;");
    while (token != NULL) {
        if (!csv_has_token_ci(saved->active_formats_csv, token)) {
            if (missing_token != NULL && missing_token_size > 0U) {
                snprintf(missing_token, missing_token_size, "%s", token);
            }
            return 0;
        }
        token = strtok(NULL, ",;");
    }
    return 1;
}

int raw_all_selection_requires_additive(
    const AppConfig *config,
    const char *current_active_formats,
    char *reason,
    size_t reason_size
)
{
    RawAllSelectionState saved = {0};
    char missing_token[128];

    if (reason != NULL && reason_size > 0U) {
        reason[0] = '\0';
    }
    if (config == NULL ||
        config->scan_mode != APP_SCAN_MODE_RAW_ALL ||
        config->additive_requested ||
        config->manual_start_explicit ||
        !text_has_value(config->output_dir) ||
        !text_has_value(current_active_formats)) {
        return 0;
    }

    if (!load_selection_state(config->output_dir, &saved) &&
        !load_hfs_measurement_active_formats(config->output_dir, &saved)) {
        if (current_selection_is_default_all(config)) {
            return 0;
        }
        if (reason != NULL && reason_size > 0U) {
            snprintf(
                reason,
                reason_size,
                "no previous active raw-all format list is recorded for this run"
            );
        }
        return 1;
    }

    if (!active_formats_cover_current(
            &saved,
            current_active_formats,
            missing_token,
            sizeof(missing_token))) {
        if (reason != NULL && reason_size > 0U) {
            snprintf(
                reason,
                reason_size,
                "active format '%s' was not covered by the saved run selection",
                missing_token[0] != '\0' ? missing_token : "unknown"
            );
        }
        return 1;
    }
    return 0;
}

static void append_unique_csv_tokens(
    char *dst,
    size_t dst_size,
    const char *src
)
{
    char normalized[1024];
    char work[1024];
    char *token;
    size_t used;

    if (dst == NULL || dst_size == 0U || !text_has_value(src)) {
        return;
    }
    normalize_csv_tokens(src, normalized, sizeof(normalized));
    if (!text_has_value(normalized) || strlen(normalized) >= sizeof(work)) {
        return;
    }
    used = strlen(dst);
    snprintf(work, sizeof(work), "%s", normalized);
    token = strtok(work, ",;");
    while (token != NULL) {
        if (!csv_has_token_ci(dst, token)) {
            int wrote = snprintf(
                dst + used,
                dst_size > used ? dst_size - used : 0U,
                "%s%s",
                used > 0U ? "," : "",
                token
            );
            if (wrote < 0 ||
                (size_t)wrote >= (dst_size > used ? dst_size - used : 0U)) {
                dst[dst_size - 1U] = '\0';
                return;
            }
            used += (size_t)wrote;
        }
        token = strtok(NULL, ",;");
    }
}

void raw_all_selection_mark_completed(
    const AppConfig *config,
    const char *active_formats_csv,
    uint32_t active_category_mask
)
{
    RawAllSelectionState saved = {0};
    char path[PATH_MAX_LEN];
    char temp_path[PATH_MAX_LEN + 32];
    char current_categories[1024];
    char current_formats[1024];
    char current_dev[128];
    FILE *file;
    uint32_t merged_mask;

    if (config == NULL ||
        config->scan_mode != APP_SCAN_MODE_RAW_ALL ||
        !text_has_value(config->output_dir) ||
        !build_selection_path(config->output_dir, path, sizeof(path)) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >=
            (int)sizeof(temp_path)) {
        return;
    }

    (void)load_selection_state(config->output_dir, &saved);
    current_categories[0] = '\0';
    current_formats[0] = '\0';
    current_dev[0] = '\0';
    if (!text_has_value(config->mft_formats_csv) &&
        !text_has_value(config->mft_dev_format)) {
        normalize_csv_tokens(
            config->mft_categories_csv,
            current_categories,
            sizeof(current_categories)
        );
    }
    normalize_csv_tokens(
        config->mft_formats_csv,
        current_formats,
        sizeof(current_formats)
    );
    normalize_csv_tokens(
        config->mft_dev_format,
        current_dev,
        sizeof(current_dev)
    );

    append_unique_csv_tokens(
        saved.categories_csv,
        sizeof(saved.categories_csv),
        current_categories
    );
    append_unique_csv_tokens(
        saved.formats_csv,
        sizeof(saved.formats_csv),
        current_formats
    );
    append_unique_csv_tokens(
        saved.dev_format,
        sizeof(saved.dev_format),
        current_dev
    );
    if (text_has_value(active_formats_csv)) {
        append_unique_csv_tokens(
            saved.active_formats_csv,
            sizeof(saved.active_formats_csv),
            active_formats_csv
        );
    }
    merged_mask = saved.category_mask | active_category_mask;

    file = fs_backend_fopen_output_write_guarded(temp_path, "w");
    if (file == NULL) {
        return;
    }
    fprintf(file, "version=1\n");
    fprintf(file, "updated_unix=%llu\n", (unsigned long long)time(NULL));
    fprintf(file, "category_mask=%08x\n", (unsigned int)merged_mask);
    fprintf(file, "categories_csv=%s\n", saved.categories_csv);
    fprintf(file, "formats_csv=%s\n", saved.formats_csv);
    fprintf(file, "dev_format=%s\n", saved.dev_format);
    fprintf(file, "active_formats_csv=%s\n", saved.active_formats_csv);
    if (fclose(file) != 0) {
        (void)unlink(temp_path);
        return;
    }
    if (rename(temp_path, path) != 0) {
        (void)unlink(temp_path);
    }
}
