#define _POSIX_C_SOURCE 200809L

#include "exfat_backend.h"

#include "app.h"
#include "config.h"
#include "container_context.h"
#include "fs_backend.h"
#include "log.h"
#include "mft.h"
#include "mft_spool.h"

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#define EXFAT_SECTOR_SIZE 512U
#define EXFAT_BOOT_SIGNATURE_OFFSET 3U
#define EXFAT_BOOT_SIGNATURE_SIZE 8U
#define EXFAT_BOOT_SIGNATURE "EXFAT   "
#define EXFAT_ENTRY_SIZE 32U
#define EXFAT_FILE_ENTRY_TYPE 0x85U
#define EXFAT_STREAM_ENTRY_TYPE 0xC0U
#define EXFAT_NAME_ENTRY_TYPE 0xC1U
#define EXFAT_ATTR_DIRECTORY 0x0010U
#define EXFAT_GENERAL_FLAG_NO_FAT_CHAIN 0x02U
#define EXFAT_FAT_BAD_CLUSTER 0xFFFFFFF7U
#define EXFAT_FAT_END_MIN 0xFFFFFFF8U
#define EXFAT_NAME_MAX 512U
#define EXFAT_PATH_MAX 2048U
#define EXFAT_MAX_DIRECTORY_BYTES (256U * 1024U * 1024U)
#define EXFAT_MAX_ENTRY_COUNT 1048576U
#define EXFAT_MAX_DEPTH 64U
#define GPT_PARTITION_ENTRY_MIN 128U
#define GPT_PARTITION_ENTRY_MAX 4096U
#define GPT_PARTITION_ENTRY_LIMIT 4096U

typedef struct {
    uint64_t abs_offset;
    uint64_t data_size;
    uint64_t allocated_size;
    time_t created_unix;
    size_t run_count;
    int run_truncated;
    int is_directory;
    int has_data;
    int path_complete;
    MftViewRun runs[MFT_VIEW_MAX_RUNS];
    char name[EXFAT_NAME_MAX];
    char path[EXFAT_PATH_MAX];
} ExfatEntry;

typedef struct {
    uint64_t abs_offset;
    size_t entry_index;
} ExfatOffsetIndexEntry;

typedef struct {
    char path[EXFAT_PATH_MAX];
    long long abs_offset;
    int reconciled;
} ExfatRecoveredOutput;

typedef struct {
    long long abs_offset;
    size_t output_index;
} ExfatRecoveredOutputIndexEntry;

typedef struct {
    uint32_t *items;
    size_t count;
    size_t capacity;
} ExfatClusterListLocal;

typedef struct {
    ExfatClusterListLocal clusters;
    uint64_t allocated_size;
    size_t run_count;
    int run_truncated;
    MftViewRun runs[MFT_VIEW_MAX_RUNS];
} ExfatResolvedStreamLocal;

static ExfatBackendGeometry g_exfat_geometry = {0};
static char g_exfat_source_hint[32] = "";
static char g_exfat_source_path[EXFAT_PATH_MAX] = "";
static char g_exfat_output_dir[EXFAT_PATH_MAX] = "";
static int g_exfat_catalog_loaded = 0;
static ExfatEntry *g_exfat_entries = NULL;
static size_t g_exfat_entry_count = 0U;
static size_t g_exfat_entry_capacity = 0U;
static ExfatOffsetIndexEntry *g_exfat_offset_index = NULL;
static size_t g_exfat_offset_index_count = 0U;
static size_t g_exfat_offset_index_capacity = 0U;
static size_t g_exfat_lookup_index_entry_count = (size_t)-1;
static ExfatRecoveredOutput *g_exfat_recovered_outputs = NULL;
static size_t g_exfat_recovered_output_count = 0U;
static size_t g_exfat_recovered_output_capacity = 0U;
static int g_exfat_recovered_outputs_log_needs_rewrite = 0;
static ExfatRecoveredOutputIndexEntry *g_exfat_recovered_output_index = NULL;
static size_t g_exfat_recovered_output_index_count = 0U;
static size_t g_exfat_recovered_output_index_capacity = 0U;
static size_t g_exfat_recovered_output_index_sorted_count = 0U;
static size_t g_exfat_recovered_output_index_output_count = (size_t)-1;
static unsigned int g_exfat_live_background_phase =
    MFT_SPOOL_BACKGROUND_PHASE_IDLE;

static void free_recovered_outputs_local(void);
static void free_recovered_output_index_local(void);
static int ensure_recovered_output_capacity_local(size_t required);
static size_t find_recovered_output_index_local(long long abs_offset);
static size_t find_recovered_output_index_by_path_local(const char *path);

static uint16_t read_u16_le_local(const unsigned char *data)
{
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static uint32_t read_u32_le_local(const unsigned char *data)
{
    return (uint32_t)data[0] |
           ((uint32_t)data[1] << 8) |
           ((uint32_t)data[2] << 16) |
           ((uint32_t)data[3] << 24);
}

static uint64_t read_u64_le_local(const unsigned char *data)
{
    return (uint64_t)read_u32_le_local(data) |
           ((uint64_t)read_u32_le_local(data + 4U) << 32);
}

static double monotonic_seconds_local(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)now.tv_sec + ((double)now.tv_nsec / 1000000000.0);
}

static int read_bytes_at_local(
    FILE *input_file,
    uint64_t absolute_offset,
    void *buffer,
    size_t buffer_size
)
{
    if (input_file == NULL || buffer == NULL || buffer_size == 0U) {
        return 0;
    }
    if (absolute_offset > (uint64_t)LLONG_MAX) {
        return 0;
    }
    if (fseeko(input_file, (off_t)absolute_offset, SEEK_SET) != 0) {
        return 0;
    }

    return fread(buffer, 1, buffer_size, input_file) == buffer_size;
}

static int detect_source_size_local(const char *path, uint64_t *out_size)
{
    struct stat st;
    FILE *file;
    off_t size;

    if (out_size == NULL) {
        return 0;
    }

    *out_size = 0U;
    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    if (stat(path, &st) == 0 && st.st_size >= 0) {
        *out_size = (uint64_t)st.st_size;
        return 1;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }
    if (fseeko(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }

    size = ftello(file);
    fclose(file);
    if (size < 0) {
        return 0;
    }

    *out_size = (uint64_t)size;
    return 1;
}

static size_t append_utf8_codepoint_local(
    char *out,
    size_t out_size,
    size_t pos,
    uint32_t codepoint
)
{
    if (out == NULL || out_size == 0U || pos >= out_size - 1U) {
        return pos;
    }

    if (codepoint <= 0x7FU) {
        out[pos++] = (char)codepoint;
    } else if (codepoint <= 0x7FFU && pos + 2U < out_size) {
        out[pos++] = (char)(0xC0U | (codepoint >> 6));
        out[pos++] = (char)(0x80U | (codepoint & 0x3FU));
    } else if (codepoint <= 0xFFFFU && pos + 3U < out_size) {
        out[pos++] = (char)(0xE0U | (codepoint >> 12));
        out[pos++] = (char)(0x80U | ((codepoint >> 6) & 0x3FU));
        out[pos++] = (char)(0x80U | (codepoint & 0x3FU));
    } else if (codepoint <= 0x10FFFFU && pos + 4U < out_size) {
        out[pos++] = (char)(0xF0U | (codepoint >> 18));
        out[pos++] = (char)(0x80U | ((codepoint >> 12) & 0x3FU));
        out[pos++] = (char)(0x80U | ((codepoint >> 6) & 0x3FU));
        out[pos++] = (char)(0x80U | (codepoint & 0x3FU));
    } else {
        out[pos++] = '_';
    }

    return pos;
}

static void append_utf16le_chars_to_utf8_local(
    const unsigned char *in,
    size_t char_count,
    char *out,
    size_t out_size,
    size_t *io_pos
)
{
    size_t i;
    size_t pos = io_pos != NULL ? *io_pos : 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }

    for (i = 0U; i < char_count && pos + 1U < out_size; ++i) {
        uint16_t ch;

        if (in == NULL) {
            break;
        }
        ch = read_u16_le_local(in + (i * 2U));
        if (ch == 0U) {
            break;
        }
        if (ch < 32U) {
            out[pos++] = '_';
        } else if (ch >= 0xD800U && ch <= 0xDBFFU) {
            if (i + 1U < char_count) {
                uint16_t low = read_u16_le_local(in + ((i + 1U) * 2U));

                if (low >= 0xDC00U && low <= 0xDFFFU) {
                    uint32_t codepoint =
                        0x10000U +
                        (((uint32_t)(ch - 0xD800U) << 10) |
                         (uint32_t)(low - 0xDC00U));
                    pos = append_utf8_codepoint_local(out, out_size, pos, codepoint);
                    ++i;
                } else {
                    out[pos++] = '_';
                }
            } else {
                out[pos++] = '_';
            }
        } else if (ch >= 0xDC00U && ch <= 0xDFFFU) {
            out[pos++] = '_';
        } else {
            pos = append_utf8_codepoint_local(out, out_size, pos, ch);
        }
    }

    out[pos] = '\0';
    if (io_pos != NULL) {
        *io_pos = pos;
    }
}

static void copy_text_bounded_local(char *out, size_t out_size, const char *text)
{
    size_t length;

    if (out == NULL || out_size == 0U) {
        return;
    }

    if (text == NULL) {
        out[0] = '\0';
        return;
    }

    length = strlen(text);
    if (length >= out_size) {
        length = out_size - 1U;
    }

    if (length > 0U) {
        memcpy(out, text, length);
    }
    out[length] = '\0';
}

static int file_exists_local(const char *path)
{
    struct stat st;

    return path != NULL && path[0] != '\0' && stat(path, &st) == 0;
}

static int ensure_directory_recursive_local(const char *path)
{
    char partial[EXFAT_PATH_MAX];
    size_t i;
    size_t length;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    if (!fs_backend_output_path_write_guard_allows(path)) {
        log_error(
            "Refusing to create exFAT output directory because its mounted output volume is not live: %s",
            path
        );
        return 0;
    }

    length = strlen(path);
    if (length >= sizeof(partial)) {
        return 0;
    }

    snprintf(partial, sizeof(partial), "%s", path);
    for (i = 1U; i < length; ++i) {
        if (partial[i] != '/') {
            continue;
        }
        partial[i] = '\0';
        if (!fs_backend_output_path_write_guard_allows(partial)) {
            partial[i] = '/';
            return 0;
        }
        if (mkdir(partial, 0777) != 0 && errno != EEXIST) {
            partial[i] = '/';
            return 0;
        }
        partial[i] = '/';
    }

    if (mkdir(partial, 0777) != 0 && errno != EEXIST) {
        return 0;
    }

    return 1;
}

static const char *path_basename_local(const char *path)
{
    const char *basename;

    if (path == NULL) {
        return NULL;
    }

    basename = strrchr(path, '/');
    return basename != NULL ? (basename + 1) : path;
}

static const char *path_extension_local(const char *path)
{
    const char *basename;
    const char *dot;

    if (path == NULL) {
        return NULL;
    }

    basename = path_basename_local(path);
    dot = strrchr(basename, '.');
    if (dot == NULL || dot[1] == '\0') {
        return NULL;
    }

    return dot + 1;
}

static void copy_name_without_extension_local(
    const char *name,
    char *out,
    size_t out_size
)
{
    const char *dot;
    size_t length;

    if (out == NULL || out_size == 0U) {
        return;
    }

    out[0] = '\0';
    if (name == NULL) {
        return;
    }

    dot = strrchr(name, '.');
    if (dot == NULL || dot == name) {
        snprintf(out, out_size, "%s", name);
        return;
    }

    length = (size_t)(dot - name);
    if (length >= out_size) {
        length = out_size - 1U;
    }
    memcpy(out, name, length);
    out[length] = '\0';
}

static int extensions_are_same_recovery_family_local(const char *lhs, const char *rhs)
{
    if (lhs == NULL || rhs == NULL) {
        return 0;
    }
    if (strcasecmp(lhs, rhs) == 0) {
        return 1;
    }
    if ((strcasecmp(lhs, "jpg") == 0 && strcasecmp(rhs, "jpeg") == 0) ||
        (strcasecmp(lhs, "jpeg") == 0 && strcasecmp(rhs, "jpg") == 0)) {
        return 1;
    }
    if ((strcasecmp(lhs, "tif") == 0 && strcasecmp(rhs, "tiff") == 0) ||
        (strcasecmp(lhs, "tiff") == 0 && strcasecmp(rhs, "tif") == 0)) {
        return 1;
    }
    if ((strcasecmp(lhs, "mpg") == 0 && strcasecmp(rhs, "mpeg") == 0) ||
        (strcasecmp(lhs, "mpeg") == 0 && strcasecmp(rhs, "mpg") == 0)) {
        return 1;
    }

    return 0;
}

static void append_sanitized_visible_component_local(
    char *out,
    size_t out_size,
    size_t *io_length,
    const char *component
)
{
    size_t pos = io_length != NULL ? *io_length : 0U;
    size_t i;

    if (out == NULL || out_size == 0U || component == NULL) {
        return;
    }

    for (i = 0U; component[i] != '\0' && pos + 1U < out_size; ++i) {
        unsigned char ch = (unsigned char)component[i];

        if (ch < 32U || ch == '/' || ch == '\\' || ch == ':' || ch == '$') {
            out[pos++] = '_';
        } else {
            out[pos++] = (char)ch;
        }
    }

    out[pos] = '\0';
    if (io_length != NULL) {
        *io_length = pos;
    }
}

static int append_visible_recovery_relative_path_local(
    char *out,
    size_t out_size,
    const char *relative_path
)
{
    char segment[EXFAT_NAME_MAX];
    size_t out_len = 0U;
    size_t seg_len = 0U;
    const char *src;

    if (out == NULL || out_size == 0U) {
        return 0;
    }

    out[0] = '\0';
    if (relative_path == NULL) {
        return 1;
    }

    src = relative_path;
    while (*src == '/') {
        ++src;
    }

    while (*src != '\0') {
        if (*src == '/') {
            const char *visible;

            if (seg_len > 0U) {
                segment[seg_len] = '\0';
                visible = mft_visible_windows_component_name(segment);
                if (out_len > 0U) {
                    if (out_len + 1U >= out_size) {
                        return 0;
                    }
                    out[out_len++] = '/';
                    out[out_len] = '\0';
                }
                append_sanitized_visible_component_local(
                    out,
                    out_size,
                    &out_len,
                    visible
                );
                seg_len = 0U;
            }

            ++src;
            while (*src == '/') {
                ++src;
            }
            continue;
        }

        if (seg_len + 1U < sizeof(segment)) {
            segment[seg_len++] = *src;
        }
        ++src;
    }

    if (seg_len > 0U) {
        const char *visible;

        segment[seg_len] = '\0';
        visible = mft_visible_windows_component_name(segment);
        if (out_len > 0U) {
            if (out_len + 1U >= out_size) {
                return 0;
            }
            out[out_len++] = '/';
            out[out_len] = '\0';
        }
        append_sanitized_visible_component_local(
            out,
            out_size,
            &out_len,
            visible
        );
    }

    return 1;
}

static int build_output_path_from_relative_local(
    char *out_path,
    size_t out_size,
    const char *relative_path
)
{
    char visible_relative[EXFAT_PATH_MAX];
    char recovered_relative[EXFAT_PATH_MAX];

    if (out_path == NULL || out_size == 0U || relative_path == NULL) {
        return 0;
    }
    if (!append_visible_recovery_relative_path_local(
            visible_relative,
            sizeof(visible_relative),
            relative_path)) {
        return 0;
    }
    if (visible_relative[0] == '\0') {
        return mft_build_output_path(out_path, out_size, APP_RECOVERED_DIR_NAME);
    }
    if (snprintf(
            recovered_relative,
            sizeof(recovered_relative),
            "%s/%s",
            APP_RECOVERED_DIR_NAME,
            visible_relative) >= (int)sizeof(recovered_relative)) {
        return 0;
    }

    return mft_build_output_path(out_path, out_size, recovered_relative);
}

static int build_unique_path_from_base_local(
    char *out_path,
    size_t out_size,
    const char *base_path,
    const char *current_path
)
{
    char candidate[EXFAT_PATH_MAX];
    const char *dot;
    int index = 1;

    if (out_path == NULL || out_size == 0U || base_path == NULL || base_path[0] == '\0') {
        return 0;
    }

    if ((current_path != NULL && strcmp(base_path, current_path) == 0) ||
        !file_exists_local(base_path)) {
        return snprintf(out_path, out_size, "%s", base_path) < (int)out_size;
    }

    dot = strrchr(base_path, '.');
    if (dot == NULL) {
        while (1) {
            if (snprintf(candidate, sizeof(candidate), "%s_%d", base_path, index) >=
                (int)sizeof(candidate)) {
                return 0;
            }
            if ((current_path != NULL && strcmp(candidate, current_path) == 0) ||
                !file_exists_local(candidate)) {
                return snprintf(out_path, out_size, "%s", candidate) < (int)out_size;
            }
            ++index;
        }
    }

    while (1) {
        size_t stem_len = (size_t)(dot - base_path);

        if (stem_len + 16U + strlen(dot) + 1U > sizeof(candidate)) {
            return 0;
        }
        memcpy(candidate, base_path, stem_len);
        candidate[stem_len] = '\0';
        if (snprintf(
                candidate + stem_len,
                sizeof(candidate) - stem_len,
                "_%d%s",
                index,
                dot) >= (int)(sizeof(candidate) - stem_len)) {
            return 0;
        }
        if ((current_path != NULL && strcmp(candidate, current_path) == 0) ||
            !file_exists_local(candidate)) {
            return snprintf(out_path, out_size, "%s", candidate) < (int)out_size;
        }
        ++index;
    }
}

static int build_unique_contextual_output_path_local(
    char *out_path,
    size_t out_size,
    const char *relative_path,
    const char *current_path
)
{
    char base[EXFAT_PATH_MAX];
    char conflict_safe[EXFAT_PATH_MAX];
    char parent_dir[EXFAT_PATH_MAX];
    char *last_slash;

    if (!build_output_path_from_relative_local(base, sizeof(base), relative_path) ||
        !mft_normalize_directory_conflicts_for_path(
            conflict_safe,
            sizeof(conflict_safe),
            base,
            0) ||
        !build_unique_path_from_base_local(
            out_path,
            out_size,
            conflict_safe,
            current_path)) {
        return 0;
    }

    snprintf(parent_dir, sizeof(parent_dir), "%s", out_path);
    last_slash = strrchr(parent_dir, '/');
    if (last_slash != NULL) {
        *last_slash = '\0';
        if (!ensure_directory_recursive_local(parent_dir)) {
            return 0;
        }
    }

    return 1;
}

static int build_unique_default_output_path_local(
    char *out_path,
    size_t out_size,
    const char *directory,
    const char *prefix,
    long long abs_offset,
    const char *extension,
    const char *current_path
)
{
    char base[EXFAT_PATH_MAX];

    if (out_path == NULL || out_size == 0U ||
        directory == NULL || prefix == NULL || extension == NULL) {
        return 0;
    }

    if (!ensure_directory_recursive_local(directory)) {
        return 0;
    }
    if (snprintf(
            base,
            sizeof(base),
            "%s/%s_%lld.%s",
            directory,
            prefix,
            abs_offset,
            extension) >= (int)sizeof(base)) {
        return 0;
    }

    return build_unique_path_from_base_local(out_path, out_size, base, current_path);
}

static int build_unique_flat_name_output_path_local(
    char *out_path,
    size_t out_size,
    const char *directory,
    const char *name,
    const char *extension,
    int force_extension,
    const char *current_path
)
{
    char visible_name[EXFAT_NAME_MAX];
    char stem[EXFAT_NAME_MAX];
    char base[EXFAT_PATH_MAX];
    size_t visible_length = 0U;

    if (out_path == NULL || out_size == 0U || directory == NULL || name == NULL) {
        return 0;
    }
    if (!ensure_directory_recursive_local(directory)) {
        return 0;
    }

    visible_name[0] = '\0';
    append_sanitized_visible_component_local(
        visible_name,
        sizeof(visible_name),
        &visible_length,
        mft_visible_windows_component_name(name)
    );
    if (visible_name[0] == '\0') {
        return 0;
    }

    if (!force_extension) {
        if (snprintf(base, sizeof(base), "%s/%s", directory, visible_name) >= (int)sizeof(base)) {
            return 0;
        }
        return build_unique_path_from_base_local(out_path, out_size, base, current_path);
    }

    copy_name_without_extension_local(visible_name, stem, sizeof(stem));
    if (stem[0] == '\0') {
        snprintf(stem, sizeof(stem), "%s", visible_name);
    }
    if (snprintf(base, sizeof(base), "%s/%s.%s", directory, stem, extension) >= (int)sizeof(base)) {
        return 0;
    }

    return build_unique_path_from_base_local(out_path, out_size, base, current_path);
}

static int path_is_under_unident_local(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    return strstr(path, "/" APP_RECOVERED_DIR_NAME "/" APP_UNIDENT_DIR_NAME "/") != NULL ||
           strstr(path, "/" APP_RECOVERED_DIR_NAME "/" APP_LEGACY_UNIDENT_DIR_NAME "/") != NULL;
}

static int recovered_output_name_requires_naming_local(const char *name)
{
    const char *digits;
    size_t digit_count = 0U;

    if (name == NULL || name[0] == '\0') {
        return 0;
    }
    if (strncmp(name, "recov_", 6U) == 0) {
        digits = name + 6U;
    } else if (name[0] == 'f') {
        digits = name + 1U;
    } else {
        return 0;
    }

    while (*digits >= '0' && *digits <= '9') {
        ++digit_count;
        ++digits;
    }

    return digit_count > 0U && (*digits == '\0' || *digits == '.');
}

static int recovered_output_path_defaults_reconciled_local(const char *path)
{
    const char *basename;

    if (path == NULL || path[0] == '\0' || path_is_under_unident_local(path)) {
        return 0;
    }

    basename = path_basename_local(path);
    if (basename == NULL) {
        return 0;
    }

    return !recovered_output_name_requires_naming_local(basename);
}

static int build_recovered_outputs_log_path_local(char *out_path, size_t out_size)
{
    if (out_path == NULL || out_size == 0U || g_exfat_output_dir[0] == '\0') {
        return 0;
    }

    return snprintf(
               out_path,
               out_size,
               "%s/%s/recovered_outputs.tsv",
               g_exfat_output_dir,
               APP_STATE_DIR_NAME) < (int)out_size;
}

static int remember_recovered_output_from_state_local(
    const char *path,
    long long abs_offset,
    int reconciled
)
{
    size_t index;

    if (path == NULL || path[0] == '\0' || abs_offset < 0) {
        return 0;
    }

    index = find_recovered_output_index_local(abs_offset);
    if (index != (size_t)-1) {
        copy_text_bounded_local(
            g_exfat_recovered_outputs[index].path,
            sizeof(g_exfat_recovered_outputs[index].path),
            path
        );
        g_exfat_recovered_outputs[index].reconciled = reconciled ? 1 : 0;
        g_exfat_recovered_output_index_output_count = (size_t)-1;
        return 1;
    }

    index = find_recovered_output_index_by_path_local(path);
    if (index != (size_t)-1) {
        g_exfat_recovered_outputs[index].abs_offset = abs_offset;
        g_exfat_recovered_outputs[index].reconciled = reconciled ? 1 : 0;
        g_exfat_recovered_output_index_output_count = (size_t)-1;
        return 1;
    }

    if (!ensure_recovered_output_capacity_local(g_exfat_recovered_output_count + 1U)) {
        return 0;
    }

    copy_text_bounded_local(
        g_exfat_recovered_outputs[g_exfat_recovered_output_count].path,
        sizeof(g_exfat_recovered_outputs[g_exfat_recovered_output_count].path),
        path
    );
    g_exfat_recovered_outputs[g_exfat_recovered_output_count].abs_offset = abs_offset;
    g_exfat_recovered_outputs[g_exfat_recovered_output_count].reconciled =
        reconciled ? 1 : 0;
    ++g_exfat_recovered_output_count;
    g_exfat_recovered_output_index_output_count = (size_t)-1;
    return 1;
}

static int resolve_recovered_output_path_for_current_run_local(
    const char *stored_path,
    char *resolved_path,
    size_t resolved_path_size
)
{
    struct stat st;
    const char *recovered_suffix;
    const char *photorec_suffix;

    if (resolved_path != NULL && resolved_path_size > 0U) {
        resolved_path[0] = '\0';
    }
    if (stored_path == NULL ||
        stored_path[0] == '\0' ||
        g_exfat_output_dir[0] == '\0' ||
        resolved_path == NULL ||
        resolved_path_size == 0U) {
        return 0;
    }

    if (snprintf(resolved_path, resolved_path_size, "%s", stored_path) <
            (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    recovered_suffix = strstr(stored_path, "/" APP_RECOVERED_DIR_NAME "/");
    if (recovered_suffix != NULL &&
        snprintf(
            resolved_path,
            resolved_path_size,
            "%s%s",
            g_exfat_output_dir,
            recovered_suffix) < (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    if (strncmp(
            stored_path,
            APP_RECOVERED_DIR_NAME "/",
            strlen(APP_RECOVERED_DIR_NAME) + 1U) == 0 &&
        snprintf(
            resolved_path,
            resolved_path_size,
            "%s/%s",
            g_exfat_output_dir,
            stored_path) < (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    photorec_suffix = strstr(stored_path, "/recup_dir.");
    if (photorec_suffix != NULL &&
        snprintf(
            resolved_path,
            resolved_path_size,
            "%s%s",
            g_exfat_output_dir,
            photorec_suffix) < (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    if (strncmp(stored_path, "recup_dir.", 10) == 0 &&
        snprintf(
            resolved_path,
            resolved_path_size,
            "%s/%s",
            g_exfat_output_dir,
            stored_path) < (int)resolved_path_size &&
        stat(resolved_path, &st) == 0 &&
        S_ISREG(st.st_mode)) {
        return 1;
    }

    resolved_path[0] = '\0';
    return 0;
}

static int load_recovered_output_state_local(void)
{
    char log_path[EXFAT_PATH_MAX];
    FILE *file;
    char line[EXFAT_PATH_MAX + 128];
    int loaded = 0;

    if (!build_recovered_outputs_log_path_local(log_path, sizeof(log_path))) {
        return 0;
    }

    file = fopen(log_path, "r");
    if (file == NULL) {
        return 0;
    }

    free_recovered_outputs_local();
    free_recovered_output_index_local();
    while (fgets(line, sizeof(line), file) != NULL) {
        char *offset_text;
        char *path_text;
        char *reconciled_text;
        char *saveptr = NULL;
        long long abs_offset = -1;
        char resolved_path[EXFAT_PATH_MAX];
        int reconciled;

        if (strncmp(line, "offset\t", 7) == 0) {
            continue;
        }

        offset_text = strtok_r(line, "\t\r\n", &saveptr);
        path_text = strtok_r(NULL, "\t\r\n", &saveptr);
        reconciled_text = strtok_r(NULL, "\t\r\n", &saveptr);
        if (offset_text == NULL ||
            path_text == NULL ||
            sscanf(offset_text, "%lld", &abs_offset) != 1 ||
            abs_offset < 0) {
            continue;
        }

        reconciled = recovered_output_path_defaults_reconciled_local(path_text);
        if (reconciled_text != NULL && reconciled_text[0] != '\0') {
            reconciled = (reconciled_text[0] == '1') ? 1 : 0;
        }
        if (!resolve_recovered_output_path_for_current_run_local(
                path_text,
                resolved_path,
                sizeof(resolved_path))) {
            continue;
        }
        if (remember_recovered_output_from_state_local(
                resolved_path,
                abs_offset,
                reconciled)) {
            loaded = 1;
        }
    }

    fclose(file);
    g_exfat_recovered_outputs_log_needs_rewrite = 0;
    return loaded;
}

static int append_recovered_output_log_entry_to_stream_local(
    FILE *file,
    const char *path,
    long long abs_offset,
    int reconciled
)
{
    if (file == NULL || path == NULL || path[0] == '\0' || abs_offset < 0) {
        return 0;
    }

    return fprintf(file, "%lld\t%s\t%d\n", abs_offset, path, reconciled ? 1 : 0) >= 0;
}

static int append_recovered_output_log_entry_local(
    const char *path,
    long long abs_offset,
    int reconciled
)
{
    char log_path[EXFAT_PATH_MAX];
    FILE *file;

    if (!build_recovered_outputs_log_path_local(log_path, sizeof(log_path)) ||
        path == NULL ||
        path[0] == '\0' ||
        abs_offset < 0) {
        return 0;
    }

    file = fopen(log_path, "a");
    if (file == NULL) {
        return 0;
    }

    if (ftell(file) == 0L) {
        fprintf(file, "offset\tpath\treconciled\n");
    }

    if (!append_recovered_output_log_entry_to_stream_local(
            file,
            path,
            abs_offset,
            reconciled)) {
        fclose(file);
        return 0;
    }

    if (fclose(file) != 0) {
        return 0;
    }

    return mft_apply_output_owner_to_path(log_path);
}

static int rewrite_recovered_outputs_log_local(void)
{
    char log_path[EXFAT_PATH_MAX];
    FILE *file;
    size_t index;

    if (!build_recovered_outputs_log_path_local(log_path, sizeof(log_path))) {
        return 0;
    }

    file = fopen(log_path, "w");
    if (file == NULL) {
        return 0;
    }

    fprintf(file, "offset\tpath\treconciled\n");
    for (index = 0U; index < g_exfat_recovered_output_count; ++index) {
        if (!append_recovered_output_log_entry_to_stream_local(
                file,
                g_exfat_recovered_outputs[index].path,
                g_exfat_recovered_outputs[index].abs_offset,
                g_exfat_recovered_outputs[index].reconciled)) {
            fclose(file);
            return 0;
        }
    }

    if (fclose(file) != 0) {
        return 0;
    }

    g_exfat_recovered_outputs_log_needs_rewrite = 0;
    return mft_apply_output_owner_to_path(log_path);
}

static int exfat_offset_index_compare_local(const void *left, const void *right)
{
    const ExfatOffsetIndexEntry *a = (const ExfatOffsetIndexEntry *)left;
    const ExfatOffsetIndexEntry *b = (const ExfatOffsetIndexEntry *)right;

    if (a->abs_offset < b->abs_offset) {
        return -1;
    }
    if (a->abs_offset > b->abs_offset) {
        return 1;
    }
    if (a->entry_index < b->entry_index) {
        return -1;
    }
    if (a->entry_index > b->entry_index) {
        return 1;
    }

    return 0;
}

static int exfat_recovered_output_index_compare_local(
    const void *left,
    const void *right
)
{
    const ExfatRecoveredOutputIndexEntry *a =
        (const ExfatRecoveredOutputIndexEntry *)left;
    const ExfatRecoveredOutputIndexEntry *b =
        (const ExfatRecoveredOutputIndexEntry *)right;

    if (a->abs_offset < b->abs_offset) {
        return -1;
    }
    if (a->abs_offset > b->abs_offset) {
        return 1;
    }
    if (a->output_index < b->output_index) {
        return -1;
    }
    if (a->output_index > b->output_index) {
        return 1;
    }

    return 0;
}

static void free_lookup_index_local(void)
{
    free(g_exfat_offset_index);
    g_exfat_offset_index = NULL;
    g_exfat_offset_index_count = 0U;
    g_exfat_offset_index_capacity = 0U;
    g_exfat_lookup_index_entry_count = (size_t)-1;
}

static void free_recovered_output_index_local(void)
{
    free(g_exfat_recovered_output_index);
    g_exfat_recovered_output_index = NULL;
    g_exfat_recovered_output_index_count = 0U;
    g_exfat_recovered_output_index_capacity = 0U;
    g_exfat_recovered_output_index_sorted_count = 0U;
    g_exfat_recovered_output_index_output_count = (size_t)-1;
}

static void free_entries_local(void)
{
    free(g_exfat_entries);
    g_exfat_entries = NULL;
    g_exfat_entry_count = 0U;
    g_exfat_entry_capacity = 0U;
}

static void free_recovered_outputs_local(void)
{
    free(g_exfat_recovered_outputs);
    g_exfat_recovered_outputs = NULL;
    g_exfat_recovered_output_count = 0U;
    g_exfat_recovered_output_capacity = 0U;
    g_exfat_recovered_outputs_log_needs_rewrite = 0;
}

static void exfat_reset_globals_local(void)
{
    free_entries_local();
    free_lookup_index_local();
    free_recovered_outputs_local();
    free_recovered_output_index_local();
    memset(&g_exfat_geometry, 0, sizeof(g_exfat_geometry));
    g_exfat_source_hint[0] = '\0';
    g_exfat_source_path[0] = '\0';
    g_exfat_catalog_loaded = 0;
    g_exfat_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;
}

void exfat_backend_set_output_dir(const char *output_dir)
{
    copy_text_bounded_local(
        g_exfat_output_dir,
        sizeof(g_exfat_output_dir),
        output_dir
    );
}

static int ensure_entry_capacity_local(size_t required)
{
    ExfatEntry *expanded;
    size_t new_capacity;

    if (required <= g_exfat_entry_capacity) {
        return 1;
    }
    if (required > EXFAT_MAX_ENTRY_COUNT) {
        return 0;
    }

    new_capacity = g_exfat_entry_capacity == 0U ? 1024U : g_exfat_entry_capacity;
    while (new_capacity < required) {
        if (new_capacity > EXFAT_MAX_ENTRY_COUNT / 2U) {
            new_capacity = EXFAT_MAX_ENTRY_COUNT;
        } else {
            new_capacity *= 2U;
        }
        if (new_capacity < required && new_capacity == EXFAT_MAX_ENTRY_COUNT) {
            return 0;
        }
    }

    expanded = (ExfatEntry *)realloc(g_exfat_entries, new_capacity * sizeof(*expanded));
    if (expanded == NULL) {
        return 0;
    }

    g_exfat_entries = expanded;
    g_exfat_entry_capacity = new_capacity;
    return 1;
}

static int ensure_offset_index_capacity_local(size_t required)
{
    ExfatOffsetIndexEntry *expanded;
    size_t new_capacity;

    if (required <= g_exfat_offset_index_capacity) {
        return 1;
    }

    new_capacity = g_exfat_offset_index_capacity == 0U ? 1024U : g_exfat_offset_index_capacity;
    while (new_capacity < required) {
        new_capacity *= 2U;
    }

    expanded = (ExfatOffsetIndexEntry *)realloc(
        g_exfat_offset_index,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_exfat_offset_index = expanded;
    g_exfat_offset_index_capacity = new_capacity;
    return 1;
}

static int ensure_recovered_output_capacity_local(size_t required)
{
    ExfatRecoveredOutput *expanded;
    size_t new_capacity;

    if (required <= g_exfat_recovered_output_capacity) {
        return 1;
    }

    new_capacity =
        g_exfat_recovered_output_capacity == 0U ? 256U : g_exfat_recovered_output_capacity;
    while (new_capacity < required) {
        new_capacity *= 2U;
    }

    expanded = (ExfatRecoveredOutput *)realloc(
        g_exfat_recovered_outputs,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_exfat_recovered_outputs = expanded;
    g_exfat_recovered_output_capacity = new_capacity;
    return 1;
}

static int ensure_recovered_output_index_capacity_local(size_t required)
{
    ExfatRecoveredOutputIndexEntry *expanded;
    size_t new_capacity;

    if (required <= g_exfat_recovered_output_index_capacity) {
        return 1;
    }

    new_capacity =
        g_exfat_recovered_output_index_capacity == 0U
            ? 256U
            : g_exfat_recovered_output_index_capacity;
    while (new_capacity < required) {
        new_capacity *= 2U;
    }

    expanded = (ExfatRecoveredOutputIndexEntry *)realloc(
        g_exfat_recovered_output_index,
        new_capacity * sizeof(*expanded)
    );
    if (expanded == NULL) {
        return 0;
    }

    g_exfat_recovered_output_index = expanded;
    g_exfat_recovered_output_index_capacity = new_capacity;
    return 1;
}

static int cluster_list_append_local(ExfatClusterListLocal *list, uint32_t cluster)
{
    uint32_t *expanded;
    size_t new_capacity;

    if (list == NULL) {
        return 0;
    }
    if (list->count < list->capacity) {
        list->items[list->count++] = cluster;
        return 1;
    }

    new_capacity = list->capacity == 0U ? 64U : list->capacity * 2U;
    expanded = (uint32_t *)realloc(list->items, new_capacity * sizeof(*expanded));
    if (expanded == NULL) {
        return 0;
    }

    list->items = expanded;
    list->capacity = new_capacity;
    list->items[list->count++] = cluster;
    return 1;
}

static void cluster_list_free_local(ExfatClusterListLocal *list)
{
    if (list == NULL) {
        return;
    }

    free(list->items);
    list->items = NULL;
    list->count = 0U;
    list->capacity = 0U;
}

static int has_valid_sector_signature_local(const unsigned char *sector, size_t length)
{
    if (sector == NULL || length < EXFAT_SECTOR_SIZE) {
        return 0;
    }

    return sector[510] == 0x55U && sector[511] == 0xAAU;
}

static int parse_exfat_boot_sector_local(
    const unsigned char *boot_sector,
    uint64_t source_size,
    uint64_t volume_offset,
    ExfatBackendGeometry *out_geometry
)
{
    ExfatBackendGeometry geometry = {0};
    uint8_t bytes_per_sector_shift;
    uint8_t sectors_per_cluster_shift;
    uint64_t volume_length_sectors;

    if (boot_sector == NULL || out_geometry == NULL ||
        !has_valid_sector_signature_local(boot_sector, EXFAT_SECTOR_SIZE) ||
        memcmp(
            boot_sector + EXFAT_BOOT_SIGNATURE_OFFSET,
            EXFAT_BOOT_SIGNATURE,
            EXFAT_BOOT_SIGNATURE_SIZE) != 0) {
        return 0;
    }

    if (memcmp(boot_sector + 11U, "\0\0\0\0\0\0\0\0", 8U) != 0) {
        return 0;
    }

    bytes_per_sector_shift = boot_sector[108U];
    sectors_per_cluster_shift = boot_sector[109U];
    if (bytes_per_sector_shift < 9U || bytes_per_sector_shift > 12U) {
        return 0;
    }
    if (sectors_per_cluster_shift > (25U - bytes_per_sector_shift)) {
        return 0;
    }

    geometry.source_size = source_size;
    geometry.volume_offset = volume_offset;
    geometry.bytes_per_sector = 1U << bytes_per_sector_shift;
    geometry.sectors_per_cluster = 1U << sectors_per_cluster_shift;
    geometry.fat_offset_sectors = read_u32_le_local(boot_sector + 80U);
    geometry.fat_length_sectors = read_u32_le_local(boot_sector + 84U);
    geometry.cluster_heap_offset_sectors = read_u32_le_local(boot_sector + 88U);
    geometry.cluster_count = read_u32_le_local(boot_sector + 92U);
    geometry.root_directory_cluster = read_u32_le_local(boot_sector + 96U);
    geometry.number_of_fats = boot_sector[110U];
    geometry.volume_flags = read_u16_le_local(boot_sector + 106U);
    volume_length_sectors = read_u64_le_local(boot_sector + 72U);
    geometry.volume_size = volume_length_sectors * (uint64_t)geometry.bytes_per_sector;

    if (geometry.fat_offset_sectors < 24U ||
        geometry.fat_length_sectors == 0U ||
        geometry.cluster_heap_offset_sectors <= geometry.fat_offset_sectors ||
        geometry.cluster_count < 1U ||
        geometry.root_directory_cluster < 2U ||
        geometry.root_directory_cluster > geometry.cluster_count + 1U ||
        (geometry.number_of_fats != 1U && geometry.number_of_fats != 2U) ||
        geometry.volume_size == 0U) {
        return 0;
    }

    *out_geometry = geometry;
    return 1;
}

static int exfat_geometry_is_truncated_local(
    const ExfatBackendGeometry *geometry
)
{
    if (geometry == NULL ||
        geometry->source_size == 0U ||
        geometry->volume_size == 0U) {
        return 0;
    }
    if (geometry->volume_offset >= geometry->source_size) {
        return 1;
    }

    return geometry->volume_size > (geometry->source_size - geometry->volume_offset);
}

static int try_probe_candidate_offset_local(
    FILE *input_file,
    uint64_t source_size,
    uint64_t candidate_offset,
    ExfatBackendGeometry *out_geometry
)
{
    unsigned char boot_sector[EXFAT_SECTOR_SIZE];

    if (source_size != 0U &&
        candidate_offset + sizeof(boot_sector) > source_size) {
        return 0;
    }
    if (!read_bytes_at_local(input_file, candidate_offset, boot_sector, sizeof(boot_sector))) {
        return 0;
    }

    return parse_exfat_boot_sector_local(
        boot_sector,
        source_size,
        candidate_offset,
        out_geometry
    );
}

static int prefer_exfat_candidate_local(
    const ExfatBackendGeometry *candidate,
    const ExfatBackendGeometry *best
)
{
    int candidate_truncated;
    int best_truncated;

    if (candidate == NULL) {
        return 0;
    }
    if (best == NULL || best->bytes_per_sector == 0U) {
        return 1;
    }
    candidate_truncated = exfat_geometry_is_truncated_local(candidate);
    best_truncated = exfat_geometry_is_truncated_local(best);
    if (candidate_truncated != best_truncated) {
        return best_truncated;
    }
    if (candidate->volume_size != best->volume_size) {
        return candidate->volume_size > best->volume_size;
    }
    return candidate->volume_offset < best->volume_offset;
}

static int find_gpt_exfat_volume_local(
    FILE *input_file,
    uint64_t source_size,
    ExfatBackendGeometry *out_geometry
)
{
    unsigned char gpt_header[EXFAT_SECTOR_SIZE];
    unsigned char *partition_entry = NULL;
    uint64_t entries_lba;
    uint32_t entry_count;
    uint32_t entry_size;
    uint32_t i;
    int found = 0;
    ExfatBackendGeometry best_geometry = {0};

    if (input_file == NULL || out_geometry == NULL) {
        return 0;
    }
    if (!read_bytes_at_local(input_file, EXFAT_SECTOR_SIZE, gpt_header, sizeof(gpt_header))) {
        return 0;
    }
    if (memcmp(gpt_header, "EFI PART", 8U) != 0) {
        return 0;
    }

    entries_lba = read_u64_le_local(gpt_header + 72U);
    entry_count = read_u32_le_local(gpt_header + 80U);
    entry_size = read_u32_le_local(gpt_header + 84U);
    if (entries_lba == 0U || entry_count == 0U) {
        return 0;
    }
    if (entry_size < GPT_PARTITION_ENTRY_MIN || entry_size > GPT_PARTITION_ENTRY_MAX) {
        return 0;
    }
    if (entry_count > GPT_PARTITION_ENTRY_LIMIT) {
        entry_count = GPT_PARTITION_ENTRY_LIMIT;
    }

    partition_entry = (unsigned char *)malloc(entry_size);
    if (partition_entry == NULL) {
        return 0;
    }

    for (i = 0U; i < entry_count; ++i) {
        uint64_t first_lba;
        uint64_t last_lba;
        uint64_t entry_offset =
            (entries_lba * EXFAT_SECTOR_SIZE) + ((uint64_t)i * (uint64_t)entry_size);
        uint64_t candidate_offset;
        ExfatBackendGeometry candidate_geometry = {0};

        if (!read_bytes_at_local(input_file, entry_offset, partition_entry, entry_size)) {
            continue;
        }
        if (memcmp(partition_entry, "\0\0\0\0\0\0\0\0", 8U) == 0 &&
            memcmp(partition_entry + 8U, "\0\0\0\0\0\0\0\0", 8U) == 0) {
            continue;
        }

        first_lba = read_u64_le_local(partition_entry + 32U);
        last_lba = read_u64_le_local(partition_entry + 40U);
        if (first_lba == 0U || last_lba < first_lba) {
            continue;
        }

        candidate_offset = first_lba * EXFAT_SECTOR_SIZE;
        if (!try_probe_candidate_offset_local(
                input_file,
                source_size,
                candidate_offset,
                &candidate_geometry)) {
            continue;
        }

        if (!found || prefer_exfat_candidate_local(&candidate_geometry, &best_geometry)) {
            best_geometry = candidate_geometry;
            found = 1;
        }
    }

    free(partition_entry);
    if (!found) {
        return 0;
    }

    *out_geometry = best_geometry;
    return 1;
}

static int find_mbr_exfat_volume_local(
    FILE *input_file,
    uint64_t source_size,
    ExfatBackendGeometry *out_geometry
)
{
    unsigned char mbr[EXFAT_SECTOR_SIZE];
    int i;
    int found = 0;
    ExfatBackendGeometry best_geometry = {0};

    if (input_file == NULL || out_geometry == NULL) {
        return 0;
    }
    if (!read_bytes_at_local(input_file, 0U, mbr, sizeof(mbr)) ||
        !has_valid_sector_signature_local(mbr, sizeof(mbr))) {
        return 0;
    }

    for (i = 0; i < 4; ++i) {
        const unsigned char *entry = mbr + 446U + ((size_t)i * 16U);
        uint8_t partition_type = entry[4];
        uint32_t start_lba = read_u32_le_local(entry + 8U);
        uint32_t sector_count = read_u32_le_local(entry + 12U);
        uint64_t candidate_offset;
        ExfatBackendGeometry candidate_geometry = {0};

        if (partition_type == 0x00U || partition_type == 0xEEU ||
            start_lba == 0U || sector_count == 0U) {
            continue;
        }

        candidate_offset = (uint64_t)start_lba * EXFAT_SECTOR_SIZE;
        if (!try_probe_candidate_offset_local(
                input_file,
                source_size,
                candidate_offset,
                &candidate_geometry)) {
            continue;
        }

        if (!found || prefer_exfat_candidate_local(&candidate_geometry, &best_geometry)) {
            best_geometry = candidate_geometry;
            found = 1;
        }
    }

    if (!found) {
        return 0;
    }

    *out_geometry = best_geometry;
    return 1;
}

static uint32_t cluster_size_bytes_local(void)
{
    return g_exfat_geometry.bytes_per_sector * g_exfat_geometry.sectors_per_cluster;
}

static int cluster_to_abs_offset_local(uint32_t cluster, uint64_t *out_abs_offset)
{
    uint64_t cluster_index;
    uint64_t offset_sectors;

    if (out_abs_offset == NULL ||
        cluster < 2U ||
        cluster > g_exfat_geometry.cluster_count + 1U) {
        return 0;
    }

    cluster_index = (uint64_t)(cluster - 2U);
    offset_sectors =
        (uint64_t)g_exfat_geometry.cluster_heap_offset_sectors +
        (cluster_index * (uint64_t)g_exfat_geometry.sectors_per_cluster);
    *out_abs_offset =
        g_exfat_geometry.volume_offset +
        (offset_sectors * (uint64_t)g_exfat_geometry.bytes_per_sector);
    return 1;
}

static uint64_t fat_base_offset_bytes_local(void)
{
    uint64_t active_fat_index =
        (g_exfat_geometry.number_of_fats > 1U && (g_exfat_geometry.volume_flags & 0x0001U) != 0U)
            ? 1U
            : 0U;

    return g_exfat_geometry.volume_offset +
           ((uint64_t)g_exfat_geometry.fat_offset_sectors * (uint64_t)g_exfat_geometry.bytes_per_sector) +
           (active_fat_index * (uint64_t)g_exfat_geometry.fat_length_sectors *
            (uint64_t)g_exfat_geometry.bytes_per_sector);
}

static int read_fat_entry_local(FILE *input_file, uint32_t cluster, uint32_t *out_value)
{
    unsigned char entry_bytes[4];
    uint64_t fat_entry_offset;

    if (input_file == NULL || out_value == NULL ||
        cluster > g_exfat_geometry.cluster_count + 1U) {
        return 0;
    }

    fat_entry_offset = fat_base_offset_bytes_local() + ((uint64_t)cluster * 4U);
    if (!read_bytes_at_local(input_file, fat_entry_offset, entry_bytes, sizeof(entry_bytes))) {
        return 0;
    }

    *out_value = read_u32_le_local(entry_bytes);
    return 1;
}

static int exfat_timestamp_valid_local(
    int year,
    int month,
    int day,
    int hour,
    int minute,
    int second
)
{
    return year >= 1980 && year <= 2107 &&
           month >= 1 && month <= 12 &&
           day >= 1 && day <= 31 &&
           hour >= 0 && hour <= 23 &&
           minute >= 0 && minute <= 59 &&
           second >= 0 && second <= 59;
}

static time_t exfat_timestamp_to_unix_local(uint32_t exfat_timestamp)
{
    struct tm broken = {0};
    int year = 1980 + (int)((exfat_timestamp >> 25) & 0x7FU);
    int month = (int)((exfat_timestamp >> 21) & 0x0FU);
    int day = (int)((exfat_timestamp >> 16) & 0x1FU);
    int hour = (int)((exfat_timestamp >> 11) & 0x1FU);
    int minute = (int)((exfat_timestamp >> 5) & 0x3FU);
    int second = (int)(exfat_timestamp & 0x1FU) * 2;

    if (!exfat_timestamp_valid_local(year, month, day, hour, minute, second)) {
        return (time_t)0;
    }

    broken.tm_year = year - 1900;
    broken.tm_mon = month - 1;
    broken.tm_mday = day;
    broken.tm_hour = hour;
    broken.tm_min = minute;
    broken.tm_sec = second;
    broken.tm_isdst = -1;
    return mktime(&broken);
}

static void resolved_stream_reset_local(ExfatResolvedStreamLocal *stream)
{
    if (stream == NULL) {
        return;
    }

    cluster_list_free_local(&stream->clusters);
    memset(stream, 0, sizeof(*stream));
}

static void resolved_stream_rebuild_runs_local(ExfatResolvedStreamLocal *stream)
{
    uint32_t cluster_size;
    size_t i;

    if (stream == NULL) {
        return;
    }

    stream->run_count = 0U;
    stream->run_truncated = 0;
    stream->allocated_size = (uint64_t)stream->clusters.count * (uint64_t)cluster_size_bytes_local();
    cluster_size = cluster_size_bytes_local();
    if (cluster_size == 0U || stream->clusters.count == 0U) {
        return;
    }

    for (i = 0U; i < stream->clusters.count; ) {
        uint32_t start_cluster = stream->clusters.items[i];
        uint64_t abs_offset;
        size_t run_cluster_count = 1U;

        while (i + run_cluster_count < stream->clusters.count &&
               stream->clusters.items[i + run_cluster_count] ==
                   start_cluster + (uint32_t)run_cluster_count) {
            ++run_cluster_count;
        }

        if (!cluster_to_abs_offset_local(start_cluster, &abs_offset)) {
            stream->run_truncated = 1;
            return;
        }

        if (stream->run_count < MFT_VIEW_MAX_RUNS) {
            stream->runs[stream->run_count].abs_offset = abs_offset;
            stream->runs[stream->run_count].byte_length =
                (uint64_t)run_cluster_count * (uint64_t)cluster_size;
            ++stream->run_count;
        } else {
            stream->run_truncated = 1;
        }

        i += run_cluster_count;
    }
}

static uint64_t ceil_div_u64_local(uint64_t value, uint64_t divisor)
{
    return divisor == 0U ? 0U : ((value + divisor - 1U) / divisor);
}

static int resolve_stream_local(
    FILE *input_file,
    uint32_t first_cluster,
    uint64_t data_length,
    int no_fat_chain,
    int allow_unknown_length,
    ExfatResolvedStreamLocal *out_stream
)
{
    uint32_t cluster_size;
    uint64_t required_clusters = 0U;
    uint32_t cluster;
    size_t steps = 0U;

    if (out_stream == NULL) {
        return 0;
    }

    memset(out_stream, 0, sizeof(*out_stream));
    cluster_size = cluster_size_bytes_local();
    if (cluster_size == 0U) {
        return 0;
    }
    if (first_cluster == 0U) {
        return 1;
    }
    if (first_cluster < 2U || first_cluster > g_exfat_geometry.cluster_count + 1U) {
        return 0;
    }

    if (no_fat_chain) {
        if (data_length == 0U && !allow_unknown_length) {
            return 1;
        }
        required_clusters = data_length == 0U
            ? 1U
            : ceil_div_u64_local(data_length, (uint64_t)cluster_size);
        if (required_clusters == 0U) {
            required_clusters = 1U;
        }
        if (required_clusters > g_exfat_geometry.cluster_count) {
            return 0;
        }

        for (steps = 0U; steps < (size_t)required_clusters; ++steps) {
            uint32_t current_cluster = first_cluster + (uint32_t)steps;

            if (current_cluster < 2U ||
                current_cluster > g_exfat_geometry.cluster_count + 1U ||
                !cluster_list_append_local(&out_stream->clusters, current_cluster)) {
                resolved_stream_reset_local(out_stream);
                return 0;
            }
        }

        resolved_stream_rebuild_runs_local(out_stream);
        return 1;
    }

    required_clusters = data_length == 0U
        ? 0U
        : ceil_div_u64_local(data_length, (uint64_t)cluster_size);
    cluster = first_cluster;
    while (cluster >= 2U &&
           cluster <= g_exfat_geometry.cluster_count + 1U &&
           steps < (size_t)g_exfat_geometry.cluster_count) {
        uint32_t next_cluster = 0U;

        if (!cluster_list_append_local(&out_stream->clusters, cluster)) {
            resolved_stream_reset_local(out_stream);
            return 0;
        }
        ++steps;

        if (!allow_unknown_length &&
            required_clusters != 0U &&
            out_stream->clusters.count >= (size_t)required_clusters) {
            break;
        }

        if (!read_fat_entry_local(input_file, cluster, &next_cluster)) {
            out_stream->run_truncated = 1;
            break;
        }
        if (next_cluster == EXFAT_FAT_BAD_CLUSTER) {
            out_stream->run_truncated = 1;
            break;
        }
        if (next_cluster >= EXFAT_FAT_END_MIN) {
            break;
        }
        if (next_cluster < 2U ||
            next_cluster > g_exfat_geometry.cluster_count + 1U ||
            next_cluster == cluster) {
            out_stream->run_truncated = 1;
            break;
        }
        cluster = next_cluster;
    }

    if (steps >= (size_t)g_exfat_geometry.cluster_count) {
        out_stream->run_truncated = 1;
    }

    resolved_stream_rebuild_runs_local(out_stream);
    return 1;
}

static int read_stream_data_local(
    FILE *input_file,
    const ExfatResolvedStreamLocal *stream,
    uint64_t requested_bytes,
    unsigned char **out_buffer,
    size_t *out_size
)
{
    unsigned char *buffer = NULL;
    uint64_t remaining;
    uint64_t offset = 0U;
    size_t i;
    uint32_t cluster_size;

    if (out_buffer != NULL) {
        *out_buffer = NULL;
    }
    if (out_size != NULL) {
        *out_size = 0U;
    }
    if (input_file == NULL || stream == NULL || out_buffer == NULL || out_size == NULL) {
        return 0;
    }
    if (requested_bytes == 0U) {
        return 1;
    }
    if (requested_bytes > (uint64_t)SIZE_MAX) {
        return 0;
    }

    cluster_size = cluster_size_bytes_local();
    buffer = (unsigned char *)malloc((size_t)requested_bytes);
    if (buffer == NULL) {
        return 0;
    }

    remaining = requested_bytes;
    for (i = 0U; i < stream->clusters.count && remaining > 0U; ++i) {
        uint64_t cluster_abs_offset;
        size_t chunk_size =
            remaining > (uint64_t)cluster_size ? (size_t)cluster_size : (size_t)remaining;

        if (!cluster_to_abs_offset_local(stream->clusters.items[i], &cluster_abs_offset) ||
            !read_bytes_at_local(
                input_file,
                cluster_abs_offset,
                buffer + offset,
                chunk_size)) {
            free(buffer);
            return 0;
        }
        offset += chunk_size;
        remaining -= (uint64_t)chunk_size;
    }

    if (remaining != 0U) {
        free(buffer);
        return 0;
    }

    *out_buffer = buffer;
    *out_size = (size_t)requested_bytes;
    return 1;
}

static int rebuild_lookup_index_local(void)
{
    size_t count = 0U;
    size_t i;

    for (i = 0U; i < g_exfat_entry_count; ++i) {
        if (g_exfat_entries[i].has_data && g_exfat_entries[i].abs_offset > 0U) {
            ++count;
        }
    }

    if (!ensure_offset_index_capacity_local(count == 0U ? 1U : count)) {
        return 0;
    }

    g_exfat_offset_index_count = 0U;
    for (i = 0U; i < g_exfat_entry_count; ++i) {
        if (!g_exfat_entries[i].has_data || g_exfat_entries[i].abs_offset == 0U) {
            continue;
        }
        g_exfat_offset_index[g_exfat_offset_index_count].abs_offset = g_exfat_entries[i].abs_offset;
        g_exfat_offset_index[g_exfat_offset_index_count].entry_index = i;
        ++g_exfat_offset_index_count;
    }

    if (g_exfat_offset_index_count > 1U) {
        qsort(
            g_exfat_offset_index,
            g_exfat_offset_index_count,
            sizeof(*g_exfat_offset_index),
            exfat_offset_index_compare_local
        );
    }

    g_exfat_lookup_index_entry_count = g_exfat_entry_count;
    return 1;
}

static int ensure_lookup_index_current_local(void)
{
    if (g_exfat_lookup_index_entry_count == g_exfat_entry_count) {
        return 1;
    }

    return rebuild_lookup_index_local();
}

static size_t recovered_output_index_lower_bound_local(long long abs_offset)
{
    size_t lo = 0U;
    size_t hi = g_exfat_recovered_output_index_count;

    while (lo < hi) {
        size_t mid = lo + ((hi - lo) / 2U);

        if (g_exfat_recovered_output_index[mid].abs_offset < abs_offset) {
            lo = mid + 1U;
        } else {
            hi = mid;
        }
    }

    return lo;
}

static int rebuild_recovered_output_index_local(void)
{
    size_t i;

    if (g_exfat_recovered_output_index_output_count == g_exfat_recovered_output_count &&
        g_exfat_recovered_output_index_sorted_count == g_exfat_recovered_output_count) {
        return 1;
    }
    if (!ensure_recovered_output_index_capacity_local(
            g_exfat_recovered_output_count == 0U ? 1U : g_exfat_recovered_output_count)) {
        return 0;
    }

    for (i = 0U; i < g_exfat_recovered_output_count; ++i) {
        g_exfat_recovered_output_index[i].abs_offset = g_exfat_recovered_outputs[i].abs_offset;
        g_exfat_recovered_output_index[i].output_index = i;
    }
    g_exfat_recovered_output_index_count = g_exfat_recovered_output_count;
    if (g_exfat_recovered_output_index_count > 1U) {
        qsort(
            g_exfat_recovered_output_index,
            g_exfat_recovered_output_index_count,
            sizeof(*g_exfat_recovered_output_index),
            exfat_recovered_output_index_compare_local
        );
    }
    g_exfat_recovered_output_index_sorted_count = g_exfat_recovered_output_count;
    g_exfat_recovered_output_index_output_count = g_exfat_recovered_output_count;
    return 1;
}

static size_t find_recovered_output_index_local(long long abs_offset)
{
    size_t index;

    if (abs_offset < 0 || !rebuild_recovered_output_index_local() ||
        g_exfat_recovered_output_index_count == 0U) {
        return (size_t)-1;
    }

    index = recovered_output_index_lower_bound_local(abs_offset);
    if (index >= g_exfat_recovered_output_index_count ||
        g_exfat_recovered_output_index[index].abs_offset != abs_offset ||
        g_exfat_recovered_output_index[index].output_index >= g_exfat_recovered_output_count) {
        return (size_t)-1;
    }

    return g_exfat_recovered_output_index[index].output_index;
}

static size_t find_recovered_output_index_by_path_local(const char *path)
{
    size_t i;

    if (path == NULL || path[0] == '\0') {
        return (size_t)-1;
    }

    for (i = 0U; i < g_exfat_recovered_output_count; ++i) {
        if (strcmp(g_exfat_recovered_outputs[i].path, path) == 0) {
            return i;
        }
    }

    return (size_t)-1;
}

static void remember_recovered_output_local(
    const char *path,
    long long abs_offset
)
{
    size_t index;

    if (path == NULL || path[0] == '\0' || abs_offset < 0) {
        return;
    }

    index = find_recovered_output_index_local(abs_offset);
    if (index != (size_t)-1) {
        copy_text_bounded_local(
            g_exfat_recovered_outputs[index].path,
            sizeof(g_exfat_recovered_outputs[index].path),
            path
        );
        g_exfat_recovered_outputs[index].reconciled =
            recovered_output_path_defaults_reconciled_local(path) ? 1 : 0;
        g_exfat_recovered_outputs_log_needs_rewrite = 1;
        g_exfat_recovered_output_index_output_count = (size_t)-1;
        return;
    }

    index = find_recovered_output_index_by_path_local(path);
    if (index != (size_t)-1) {
        g_exfat_recovered_outputs[index].abs_offset = abs_offset;
        g_exfat_recovered_outputs[index].reconciled =
            recovered_output_path_defaults_reconciled_local(path) ? 1 : 0;
        g_exfat_recovered_outputs_log_needs_rewrite = 1;
        g_exfat_recovered_output_index_output_count = (size_t)-1;
        return;
    }

    if (!ensure_recovered_output_capacity_local(g_exfat_recovered_output_count + 1U)) {
        return;
    }

    copy_text_bounded_local(
        g_exfat_recovered_outputs[g_exfat_recovered_output_count].path,
        sizeof(g_exfat_recovered_outputs[g_exfat_recovered_output_count].path),
        path
    );
    g_exfat_recovered_outputs[g_exfat_recovered_output_count].abs_offset = abs_offset;
    g_exfat_recovered_outputs[g_exfat_recovered_output_count].reconciled =
        recovered_output_path_defaults_reconciled_local(path) ? 1 : 0;
    ++g_exfat_recovered_output_count;
    g_exfat_recovered_outputs_log_needs_rewrite = 1;
    g_exfat_recovered_output_index_output_count = (size_t)-1;
    app_gui_note_recovery_path(path, abs_offset);
    if (!append_recovered_output_log_entry_local(
            path,
            abs_offset,
            recovered_output_path_defaults_reconciled_local(path))) {
        g_exfat_recovered_outputs_log_needs_rewrite = 1;
    }
}

static ExfatEntry *find_entry_by_exact_offset_local(long long abs_offset)
{
    size_t lo = 0U;
    size_t hi;

    if (abs_offset < 0 || !ensure_lookup_index_current_local()) {
        return NULL;
    }

    hi = g_exfat_offset_index_count;
    while (lo < hi) {
        size_t mid = lo + ((hi - lo) / 2U);

        if (g_exfat_offset_index[mid].abs_offset < (uint64_t)abs_offset) {
            lo = mid + 1U;
        } else {
            hi = mid;
        }
    }

    if (lo >= g_exfat_offset_index_count ||
        g_exfat_offset_index[lo].abs_offset != (uint64_t)abs_offset ||
        g_exfat_offset_index[lo].entry_index >= g_exfat_entry_count) {
        return NULL;
    }

    return &g_exfat_entries[g_exfat_offset_index[lo].entry_index];
}

static ExfatEntry *find_entry_by_offset_local(long long abs_offset)
{
    ExfatEntry *entry = find_entry_by_exact_offset_local(abs_offset);

    if (entry != NULL) {
        return entry;
    }

    if (g_exfat_geometry.volume_offset > 0U &&
        abs_offset >= 0 &&
        (uint64_t)abs_offset <= (uint64_t)LLONG_MAX - g_exfat_geometry.volume_offset) {
        entry = find_entry_by_exact_offset_local(
            (long long)((uint64_t)abs_offset + g_exfat_geometry.volume_offset)
        );
        if (entry != NULL) {
            return entry;
        }
    }

    if (g_exfat_geometry.volume_offset > 0U &&
        (uint64_t)abs_offset >= g_exfat_geometry.volume_offset) {
        entry = find_entry_by_exact_offset_local(
            (long long)((uint64_t)abs_offset - g_exfat_geometry.volume_offset)
        );
    }

    return entry;
}

static int store_entry_local(const ExfatEntry *entry)
{
    if (entry == NULL) {
        return 0;
    }
    if (!ensure_entry_capacity_local(g_exfat_entry_count + 1U)) {
        return 0;
    }

    g_exfat_entries[g_exfat_entry_count] = *entry;
    ++g_exfat_entry_count;
    g_exfat_lookup_index_entry_count = (size_t)-1;
    return 1;
}

static int build_directory_child_path_local(
    char *out_path,
    size_t out_size,
    const char *parent_path,
    const char *name
)
{
    if (out_path == NULL || out_size == 0U || name == NULL || name[0] == '\0') {
        return 0;
    }

    if (parent_path == NULL || parent_path[0] == '\0') {
        return snprintf(out_path, out_size, "%s", name) < (int)out_size;
    }

    return snprintf(out_path, out_size, "%s/%s", parent_path, name) < (int)out_size;
}

static int parse_directory_local(
    FILE *input_file,
    const char *parent_path,
    uint32_t first_cluster,
    uint64_t data_length,
    int no_fat_chain,
    unsigned int depth
);

static int parse_file_entry_set_local(
    FILE *input_file,
    const unsigned char *set_data,
    size_t set_size,
    const char *parent_path,
    unsigned int depth
)
{
    const unsigned char *primary = set_data;
    const unsigned char *stream = set_data + EXFAT_ENTRY_SIZE;
    uint8_t secondary_count;
    uint8_t name_length;
    uint16_t file_attributes;
    uint32_t first_cluster;
    uint64_t data_length;
    int is_directory;
    int no_fat_chain;
    time_t created_unix;
    ExfatEntry entry = {0};
    size_t name_pos = 0U;
    size_t offset;

    if (input_file == NULL || set_data == NULL || set_size < EXFAT_ENTRY_SIZE * 2U) {
        return 0;
    }
    if ((primary[0] & 0x7FU) != 0x05U || (stream[0] & 0x7FU) != 0x40U) {
        return 0;
    }

    secondary_count = primary[1];
    name_length = stream[3];
    if (secondary_count == 0U || name_length == 0U) {
        return 0;
    }

    file_attributes = read_u16_le_local(primary + 4U);
    first_cluster = read_u32_le_local(stream + 20U);
    data_length = read_u64_le_local(stream + 24U);
    is_directory = (file_attributes & EXFAT_ATTR_DIRECTORY) != 0;
    no_fat_chain = (stream[1] & EXFAT_GENERAL_FLAG_NO_FAT_CHAIN) != 0;
    created_unix = exfat_timestamp_to_unix_local(read_u32_le_local(primary + 8U));

    for (offset = EXFAT_ENTRY_SIZE * 2U;
         offset + EXFAT_ENTRY_SIZE <= set_size && name_pos + 1U < sizeof(entry.name);
         offset += EXFAT_ENTRY_SIZE) {
        const unsigned char *name_entry = set_data + offset;

        if ((name_entry[0] & 0x7FU) != 0x41U) {
            continue;
        }
        append_utf16le_chars_to_utf8_local(
            name_entry + 2U,
            15U,
            entry.name,
            sizeof(entry.name),
            &name_pos
        );
    }

    if (entry.name[0] == '\0' ||
        !build_directory_child_path_local(
            entry.path,
            sizeof(entry.path),
            parent_path,
            entry.name)) {
        return 0;
    }

    entry.is_directory = is_directory;
    entry.path_complete = 1;
    entry.created_unix = created_unix;
    entry.data_size = data_length;
    if (!is_directory && first_cluster >= 2U && data_length > 0U) {
        ExfatResolvedStreamLocal resolved = {0};

        if (resolve_stream_local(
                input_file,
                first_cluster,
                data_length,
                no_fat_chain,
                0,
                &resolved)) {
            if (resolved.run_count > 0U) {
                size_t run_index;

                entry.abs_offset = resolved.runs[0].abs_offset;
                entry.allocated_size = resolved.allocated_size;
                entry.run_count = resolved.run_count;
                entry.run_truncated = resolved.run_truncated;
                entry.has_data = 1;
                for (run_index = 0U; run_index < resolved.run_count; ++run_index) {
                    entry.runs[run_index] = resolved.runs[run_index];
                }
            }
            resolved_stream_reset_local(&resolved);
        }
    }

    if (!store_entry_local(&entry)) {
        return 0;
    }

    if (is_directory &&
        first_cluster >= 2U &&
        depth < EXFAT_MAX_DEPTH &&
        data_length <= EXFAT_MAX_DIRECTORY_BYTES) {
        (void)parse_directory_local(
            input_file,
            entry.path,
            first_cluster,
            data_length,
            no_fat_chain,
            depth + 1U
        );
    }

    return 1;
}

static int parse_directory_local(
    FILE *input_file,
    const char *parent_path,
    uint32_t first_cluster,
    uint64_t data_length,
    int no_fat_chain,
    unsigned int depth
)
{
    ExfatResolvedStreamLocal resolved = {0};
    unsigned char *buffer = NULL;
    size_t buffer_size = 0U;
    uint64_t requested_bytes;
    size_t offset = 0U;
    int ok = 0;

    if (input_file == NULL || first_cluster < 2U || depth > EXFAT_MAX_DEPTH) {
        return 0;
    }
    if (!resolve_stream_local(
            input_file,
            first_cluster,
            data_length,
            no_fat_chain,
            data_length == 0U ? 1 : 0,
            &resolved)) {
        return 0;
    }
    if (resolved.allocated_size == 0U || resolved.clusters.count == 0U) {
        resolved_stream_reset_local(&resolved);
        return 1;
    }

    requested_bytes = data_length > 0U ? data_length : resolved.allocated_size;
    if (requested_bytes > resolved.allocated_size) {
        requested_bytes = resolved.allocated_size;
    }
    if (requested_bytes > EXFAT_MAX_DIRECTORY_BYTES) {
        requested_bytes = EXFAT_MAX_DIRECTORY_BYTES;
    }
    if (!read_stream_data_local(
            input_file,
            &resolved,
            requested_bytes,
            &buffer,
            &buffer_size)) {
        resolved_stream_reset_local(&resolved);
        return 0;
    }

    while (offset + EXFAT_ENTRY_SIZE <= buffer_size) {
        const unsigned char *entry = buffer + offset;
        size_t set_size;

        if (entry[0] == 0x00U) {
            ok = 1;
            break;
        }
        if (entry[0] < 0x80U || (entry[0] & 0x7FU) != 0x05U) {
            offset += EXFAT_ENTRY_SIZE;
            continue;
        }

        set_size = ((size_t)entry[1] + 1U) * EXFAT_ENTRY_SIZE;
        if (set_size <= EXFAT_ENTRY_SIZE || offset + set_size > buffer_size) {
            offset += EXFAT_ENTRY_SIZE;
            continue;
        }

        (void)parse_file_entry_set_local(
            input_file,
            entry,
            set_size,
            parent_path,
            depth
        );
        offset += set_size;
    }

    if (offset >= buffer_size) {
        ok = 1;
    }

    free(buffer);
    resolved_stream_reset_local(&resolved);
    return ok;
}

static int parse_root_directory_local(FILE *input_file)
{
    return parse_directory_local(
        input_file,
        "",
        g_exfat_geometry.root_directory_cluster,
        0U,
        0,
        0U
    );
}

static int build_contextual_relative_path_for_entry_local(
    const ExfatEntry *entry,
    const char *recovered_extension,
    char *out_relative_path,
    size_t out_size
)
{
    char stem[EXFAT_NAME_MAX];
    char parent_path[EXFAT_PATH_MAX];
    const char *basename;
    const char *dot;
    const char *entry_extension;
    size_t parent_len;

    if (out_relative_path == NULL || out_size == 0U || entry == NULL ||
        !entry->path_complete || entry->path[0] == '\0') {
        return 0;
    }

    if (recovered_extension == NULL || recovered_extension[0] == '\0') {
        return snprintf(out_relative_path, out_size, "%s", entry->path) < (int)out_size;
    }

    entry_extension = path_extension_local(entry->path);
    if (entry_extension != NULL &&
        extensions_are_same_recovery_family_local(entry_extension, recovered_extension)) {
        return snprintf(out_relative_path, out_size, "%s", entry->path) < (int)out_size;
    }

    basename = path_basename_local(entry->path);
    if (basename == NULL || basename[0] == '\0') {
        return 0;
    }

    copy_name_without_extension_local(basename, stem, sizeof(stem));
    if (stem[0] == '\0') {
        copy_text_bounded_local(stem, sizeof(stem), basename);
    }

    dot = strrchr(entry->path, '/');
    parent_len = dot != NULL ? (size_t)(dot - entry->path) : 0U;
    if (parent_len >= sizeof(parent_path)) {
        return 0;
    }
    memcpy(parent_path, entry->path, parent_len);
    parent_path[parent_len] = '\0';

    if (parent_path[0] == '\0') {
        return snprintf(
            out_relative_path,
            out_size,
            "%s.%s",
            stem,
            recovered_extension) < (int)out_size;
    }

    return snprintf(
        out_relative_path,
        out_size,
        "%s/%s.%s",
        parent_path,
        stem,
        recovered_extension) < (int)out_size;
}

static int build_recovered_output_path_internal_local(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension,
    const char *current_path,
    int *out_contextual,
    time_t *out_created_time
)
{
    ExfatEntry *entry;
    char resolved_default_directory[EXFAT_PATH_MAX];

    if (out_contextual != NULL) {
        *out_contextual = 0;
    }
    if (out_created_time != NULL) {
        *out_created_time = (time_t)0;
    }

    if (out_path == NULL || out_size == 0U ||
        default_directory == NULL || default_prefix == NULL || extension == NULL) {
        return 0;
    }

    if (strcmp(default_directory, APP_DEFAULT_UNIDENT_DIR) == 0) {
        if (!mft_build_unident_typed_bucket_dir(
                resolved_default_directory,
                sizeof(resolved_default_directory),
                extension)) {
            return 0;
        }
    } else {
        snprintf(
            resolved_default_directory,
            sizeof(resolved_default_directory),
            "%s",
            default_directory
        );
    }

    entry = find_entry_by_offset_local(abs_offset);
    if (out_created_time != NULL && entry != NULL) {
        *out_created_time = entry->created_unix;
    }

    if (entry != NULL &&
        entry->path_complete &&
        entry->path[0] != '\0' &&
        entry->has_data) {
        char contextual_relative[EXFAT_PATH_MAX];

        if (build_contextual_relative_path_for_entry_local(
                entry,
                extension,
                contextual_relative,
                sizeof(contextual_relative)) &&
            build_unique_contextual_output_path_local(
                out_path,
                out_size,
                contextual_relative,
                current_path)) {
            if (out_contextual != NULL) {
                *out_contextual = 1;
            }
            return 1;
        }
    }

    if (entry != NULL &&
        entry->name[0] != '\0') {
        const char *name_extension = path_extension_local(entry->name);
        int exact_family =
            name_extension != NULL &&
            extensions_are_same_recovery_family_local(name_extension, extension);

        if (build_unique_flat_name_output_path_local(
                out_path,
                out_size,
                resolved_default_directory,
                entry->name,
                extension,
                exact_family ? 0 : 1,
                current_path)) {
            if (out_contextual != NULL) {
                *out_contextual = 1;
            }
            return 1;
        }
    }

    return build_unique_default_output_path_local(
        out_path,
        out_size,
        resolved_default_directory,
        default_prefix,
        abs_offset,
        extension,
        current_path
    );
}

static int exfat_catalog_available_local(void)
{
    return g_exfat_catalog_loaded && g_exfat_entry_count > 0U;
}

void exfat_backend_reset(void)
{
    exfat_reset_globals_local();
}

int exfat_backend_configure_from_source(const char *input_path)
{
    FILE *input_file = NULL;
    uint64_t source_size = 0U;
    double configure_started_at = monotonic_seconds_local();
    double phase_started_at = configure_started_at;
    double probe_seconds = 0.0;
    double catalog_seconds = 0.0;
    int ok = 0;

    if (input_path == NULL || input_path[0] == '\0') {
        return 0;
    }

    if (g_exfat_geometry.bytes_per_sector != 0U &&
        g_exfat_source_path[0] != '\0' &&
        strcmp(g_exfat_source_path, input_path) == 0) {
        return 1;
    }

    exfat_reset_globals_local();
    (void)detect_source_size_local(input_path, &source_size);
    input_file = fopen(input_path, "rb");
    if (input_file == NULL) {
        return 0;
    }

    if (try_probe_candidate_offset_local(
            input_file,
            source_size,
            0U,
            &g_exfat_geometry)) {
        ok = 1;
        log_info(
            "Detected exFAT source volume at offset %llu",
            (unsigned long long)g_exfat_geometry.volume_offset
        );
    } else if (find_gpt_exfat_volume_local(
                   input_file,
                   source_size,
                   &g_exfat_geometry)) {
        ok = 1;
        log_info(
            "Detected GPT exFAT partition at offset %llu",
            (unsigned long long)g_exfat_geometry.volume_offset
        );
    } else if (find_mbr_exfat_volume_local(
                   input_file,
                   source_size,
                   &g_exfat_geometry)) {
        ok = 1;
        log_info(
            "Detected MBR exFAT partition at offset %llu",
            (unsigned long long)g_exfat_geometry.volume_offset
        );
    }
    probe_seconds = monotonic_seconds_local() - phase_started_at;

    if (!ok) {
        fclose(input_file);
        return 0;
    }

    snprintf(g_exfat_source_hint, sizeof(g_exfat_source_hint), "%s", "exFAT");
    snprintf(g_exfat_source_path, sizeof(g_exfat_source_path), "%s", input_path);
    if (exfat_geometry_is_truncated_local(&g_exfat_geometry)) {
        uint64_t readable_bytes =
            g_exfat_geometry.source_size > g_exfat_geometry.volume_offset
                ? (g_exfat_geometry.source_size - g_exfat_geometry.volume_offset)
                : 0U;
        uint64_t missing_bytes =
            g_exfat_geometry.volume_size > readable_bytes
                ? (g_exfat_geometry.volume_size - readable_bytes)
                : 0U;

        log_info(
            "exFAT source image is shorter than the declared volume size; continuing in best-effort mode with %.2f GiB readable and %.2f GiB missing",
            (double)readable_bytes / (1024.0 * 1024.0 * 1024.0),
            (double)missing_bytes / (1024.0 * 1024.0 * 1024.0)
        );
    }

    phase_started_at = monotonic_seconds_local();
    if (parse_root_directory_local(input_file)) {
        g_exfat_catalog_loaded = 1;
        log_info(
            "Loaded %zu exFAT directory entr%s for naming/path reconstruction",
            g_exfat_entry_count,
            g_exfat_entry_count == 1U ? "y" : "ies"
        );
    } else {
        log_info(
            "exFAT volume detected, but directory parsing is not complete enough for naming on this source yet"
        );
    }
    catalog_seconds = monotonic_seconds_local() - phase_started_at;

    fclose(input_file);
    log_info(
        "exFAT configure timings: probe=%.2fs catalog=%.2fs total=%.2fs entries=%zu",
        probe_seconds,
        catalog_seconds,
        monotonic_seconds_local() - configure_started_at,
        g_exfat_entry_count
    );
    return 1;
}

int exfat_backend_has_geometry(void)
{
    return g_exfat_geometry.bytes_per_sector != 0U;
}

int exfat_backend_translate_photorec_file_number(
    unsigned long long file_number,
    long long *out_abs_offset
)
{
    uint64_t abs_offset;
    uint64_t bytes_per_sector;

    if (out_abs_offset != NULL) {
        *out_abs_offset = -1;
    }
    if (out_abs_offset == NULL || !exfat_backend_has_geometry()) {
        return 0;
    }

    bytes_per_sector = (uint64_t)g_exfat_geometry.bytes_per_sector;
    if (bytes_per_sector == 0U ||
        file_number > (ULLONG_MAX - g_exfat_geometry.volume_offset) / bytes_per_sector) {
        return 0;
    }

    abs_offset = g_exfat_geometry.volume_offset + (file_number * bytes_per_sector);
    if (abs_offset > (uint64_t)LLONG_MAX) {
        return 0;
    }

    *out_abs_offset = (long long)abs_offset;
    return 1;
}

const char *exfat_backend_source_hint(void)
{
    return g_exfat_source_hint;
}

const ExfatBackendGeometry *exfat_backend_current_geometry(void)
{
    return exfat_backend_has_geometry() ? &g_exfat_geometry : NULL;
}

size_t exfat_backend_entry_count(void)
{
    return g_exfat_entry_count;
}

int exfat_backend_prepare_index(void)
{
    double prepare_started_at = monotonic_seconds_local();

    if (!exfat_catalog_available_local()) {
        return 0;
    }
    log_set_working_activity("preparing exFAT index");
    g_exfat_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_INDEX;
    if (!rebuild_lookup_index_local()) {
        g_exfat_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;
        log_error("Failed to prepare exFAT offset lookup index");
        return 0;
    }
    g_exfat_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;

    log_info(
        "exFAT prepare timings: index=%.2fs entries=%zu exact_offsets=%zu",
        monotonic_seconds_local() - prepare_started_at,
        g_exfat_entry_count,
        g_exfat_offset_index_count
    );
    return 1;
}

int exfat_backend_load_recovered_output_state(void)
{
    return load_recovered_output_state_local();
}

const char *exfat_backend_lookup_path_by_offset(long long abs_offset)
{
    ExfatEntry *entry = find_entry_by_offset_local(abs_offset);

    if (entry == NULL || entry->path[0] == '\0') {
        return NULL;
    }

    return entry->path;
}

time_t exfat_backend_lookup_created_time_by_offset(long long abs_offset)
{
    ExfatEntry *entry = find_entry_by_offset_local(abs_offset);

    return entry == NULL ? (time_t)0 : entry->created_unix;
}

int exfat_backend_lookup_scan_hint(long long abs_offset, MftScanHint *out)
{
    ExfatEntry *entry = find_entry_by_offset_local(abs_offset);

    if (out == NULL) {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->record_number = -1;
    if (entry == NULL || !entry->has_data) {
        return 0;
    }

    out->inside_nonresident_run = 1;
    if (entry->abs_offset == (uint64_t)abs_offset) {
        out->exact_data_match = 1;
    }

    return 1;
}

const char *exfat_backend_lookup_container_label_by_offset(long long abs_offset)
{
    return container_context_label_from_path(
        exfat_backend_lookup_path_by_offset(abs_offset)
    );
}

int exfat_backend_build_recovered_output_path(
    char *out_path,
    size_t out_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
)
{
    char current_path[EXFAT_PATH_MAX];
    const char *reuse_path = NULL;
    int current_reconciled = 0;

    current_path[0] = '\0';
    if (exfat_backend_get_recovered_output_info(
            abs_offset,
            current_path,
            sizeof(current_path),
            &current_reconciled) &&
        current_path[0] != '\0') {
        reuse_path = current_path;
    }

    return build_recovered_output_path_internal_local(
        out_path,
        out_size,
        abs_offset,
        default_directory,
        default_prefix,
        extension,
        reuse_path,
        NULL,
        NULL
    );
}

void exfat_backend_note_recovered_output(const char *path, long long abs_offset)
{
    remember_recovered_output_local(path, abs_offset);
}

int exfat_backend_get_recovered_output_info(
    long long abs_offset,
    char *out_path,
    size_t out_path_size,
    int *out_reconciled
)
{
    size_t index;

    if (out_path != NULL && out_path_size > 0U) {
        out_path[0] = '\0';
    }
    if (out_reconciled != NULL) {
        *out_reconciled = 0;
    }

    index = find_recovered_output_index_local(abs_offset);
    if (index == (size_t)-1) {
        return 0;
    }

    if (out_path != NULL && out_path_size > 0U) {
        snprintf(
            out_path,
            out_path_size,
            "%s",
            g_exfat_recovered_outputs[index].path
        );
    }
    if (out_reconciled != NULL) {
        *out_reconciled = g_exfat_recovered_outputs[index].reconciled;
    }
    return 1;
}

size_t exfat_backend_recovered_output_count(void)
{
    return g_exfat_recovered_output_count;
}

size_t exfat_backend_named_output_count(void)
{
    size_t count = 0U;
    size_t i;

    for (i = 0U; i < g_exfat_recovered_output_count; ++i) {
        if (g_exfat_recovered_outputs[i].reconciled) {
            ++count;
        }
    }
    return count;
}

size_t exfat_backend_unreconciled_output_count(void)
{
    return g_exfat_recovered_output_count - exfat_backend_named_output_count();
}

int exfat_backend_is_offset_fully_recovered(long long abs_offset)
{
    return find_recovered_output_index_local(abs_offset) != (size_t)-1;
}

void exfat_backend_get_live_stats(MftSpoolLiveStats *out)
{
    uint64_t named_outputs;
    uint64_t total_outputs;

    if (out == NULL) {
        return;
    }

    memset(out, 0, sizeof(*out));
    named_outputs = (uint64_t)exfat_backend_named_output_count();
    total_outputs = (uint64_t)g_exfat_recovered_output_count;
    out->recovered_outputs_current = total_outputs;
    out->named_outputs_current = named_outputs;
    out->unident_outputs_current =
        total_outputs >= named_outputs ? total_outputs - named_outputs : 0ULL;
    out->record_index_count = g_exfat_entry_count;
    out->range_index_count = g_exfat_offset_index_count;
    out->background_phase = g_exfat_live_background_phase;
}

int exfat_backend_finalize_recovered_outputs(void)
{
    double finalize_started_at = monotonic_seconds_local();
    double phase_started_at = finalize_started_at;
    double reconcile_seconds = 0.0;
    double rewrite_outputs_seconds = 0.0;
    size_t i;
    size_t moved = 0U;

    log_set_working_activity("reconciling exFAT outputs");
    g_exfat_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_NAMING;
    for (i = 0U; i < g_exfat_recovered_output_count; ++i) {
        ExfatRecoveredOutput *output = &g_exfat_recovered_outputs[i];
        const char *extension;
        char new_path[EXFAT_PATH_MAX];
        int contextual = 0;
        time_t created_time = (time_t)0;

        if (output->reconciled) {
            continue;
        }

        extension = path_extension_local(output->path);
        if (extension == NULL) {
            continue;
        }

        if (!build_recovered_output_path_internal_local(
                new_path,
                sizeof(new_path),
                output->abs_offset,
                APP_DEFAULT_UNIDENT_DIR,
                "recov",
                extension,
                output->path,
                &contextual,
                &created_time) ||
            !contextual) {
            continue;
        }

        if (strcmp(new_path, output->path) == 0) {
            output->reconciled = recovered_output_path_defaults_reconciled_local(new_path);
            continue;
        }

        if (rename(output->path, new_path) != 0) {
            continue;
        }

        copy_text_bounded_local(output->path, sizeof(output->path), new_path);
        output->reconciled = recovered_output_path_defaults_reconciled_local(new_path);
        (void)mft_apply_output_owner_to_path(output->path);
        if (created_time > 0) {
            (void)mft_apply_created_time_value_to_path(output->path, created_time);
        }
        ++moved;
    }
    g_exfat_live_background_phase = MFT_SPOOL_BACKGROUND_PHASE_IDLE;
    reconcile_seconds = monotonic_seconds_local() - phase_started_at;

    if (moved > 0U) {
        log_info("Reconciled %zu recovered files with exFAT directory context", moved);
    }
    phase_started_at = monotonic_seconds_local();
    if (moved > 0U || g_exfat_recovered_outputs_log_needs_rewrite) {
        (void)rewrite_recovered_outputs_log_local();
    }
    rewrite_outputs_seconds = monotonic_seconds_local() - phase_started_at;
    log_info(
        "exFAT finalize timings: reconcile=%.2fs rewrite_outputs=%.2fs total=%.2fs recovered=%zu moved=%zu",
        reconcile_seconds,
        rewrite_outputs_seconds,
        monotonic_seconds_local() - finalize_started_at,
        g_exfat_recovered_output_count,
        moved
    );
    return 1;
}

void exfat_backend_reconcile_recovered_outputs_live(void)
{
    /*
     * exFAT currently reconciles during the explicit finalize pass rather than
     * maintaining a separate live spool worker.
     */
}

void exfat_backend_refresh_recovery_state(size_t *entry_count_snapshot)
{
    if (entry_count_snapshot != NULL) {
        *entry_count_snapshot = g_exfat_entry_count;
    }
}
