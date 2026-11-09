#include "carver_output.h"
#include "config.h"
#include "fs_backend.h"
#include "log.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

static int g_carver_output_metadata_context_skip_enabled = 1;
#define CARVER_OUTPUT_SMALL_DERIVATIVE_IMAGE_MAX_BYTES (2U * 1024U * 1024U)
#define CARVER_OUTPUT_QUALITY_HEAD_BYTES (64U * 1024U)
#define CARVER_OUTPUT_QUALITY_TAIL_BYTES (256U * 1024U)
#define CARVER_OUTPUT_REPLACE_MIN_BYTES 512U

typedef struct {
    size_t size;
    int known_format;
    int signature_ok;
    int terminal_ok;
    int structure_ok;
    int score;
    char reason[64];
} CarverOutputQuality;

static void carver_output_reset(CarverOutput *out)
{
    if (out == NULL) {
        return;
    }

    out->file = NULL;
    out->path[0] = '\0';
    out->replacement_existing_path[0] = '\0';
    out->extension[0] = '\0';
    out->replacement_existing_size = 0U;
    out->abs_offset = -1;
    out->deferred_capture = 0;
    out->replacement_candidate = 0;
    out->replacement_existing_reconciled = 0;
}

static int bytes_contain_local(
    const uint8_t *haystack,
    size_t haystack_len,
    const void *needle_data,
    size_t needle_len
)
{
    const uint8_t *needle = (const uint8_t *)needle_data;
    size_t i;

    if (haystack == NULL || needle == NULL || needle_len == 0U ||
        haystack_len < needle_len) {
        return 0;
    }
    for (i = 0U; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return 1;
        }
    }
    return 0;
}

static char ascii_tolower_local(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char)(c - 'A' + 'a');
    }

    return c;
}

static int ascii_equals_ci(const char *a, const char *b)
{
    if (a == NULL || b == NULL) {
        return 0;
    }

    while (*a != '\0' && *b != '\0') {
        if (ascii_tolower_local(*a) != ascii_tolower_local(*b)) {
            return 0;
        }
        a++;
        b++;
    }

    return *a == '\0' && *b == '\0';
}

static int ascii_starts_with_ci(const char *text, const char *prefix)
{
    if (text == NULL || prefix == NULL) {
        return 0;
    }

    while (*prefix != '\0') {
        if (*text == '\0' ||
            ascii_tolower_local(*text) != ascii_tolower_local(*prefix)) {
            return 0;
        }
        text++;
        prefix++;
    }

    return 1;
}

static int ascii_ends_with_ci(const char *text, const char *suffix)
{
    size_t text_len;
    size_t suffix_len;
    size_t i;

    if (text == NULL || suffix == NULL) {
        return 0;
    }

    text_len = strlen(text);
    suffix_len = strlen(suffix);
    if (suffix_len > text_len) {
        return 0;
    }

    for (i = 0; i < suffix_len; i++) {
        if (ascii_tolower_local(text[text_len - suffix_len + i]) !=
            ascii_tolower_local(suffix[i])) {
            return 0;
        }
    }

    return 1;
}

static void normalize_extension_local(
    const char *extension,
    char *out,
    size_t out_size
)
{
    size_t i = 0U;

    if (out != NULL && out_size > 0U) {
        out[0] = '\0';
    }
    if (extension == NULL || out == NULL || out_size == 0U) {
        return;
    }
    while (*extension == '.') {
        extension++;
    }
    while (extension[i] != '\0' && i + 1U < out_size) {
        out[i] = ascii_tolower_local(extension[i]);
        i++;
    }
    out[i] = '\0';
    if (strcmp(out, "jpeg") == 0 || strcmp(out, "jpe") == 0) {
        snprintf(out, out_size, "%s", "jpg");
    } else if (strcmp(out, "m4v") == 0 || strcmp(out, "3gp") == 0 ||
               strcmp(out, "3g2") == 0) {
        snprintf(out, out_size, "%s", "mp4");
    }
}

static const char *path_extension_local(const char *path)
{
    const char *slash;
    const char *dot;

    if (path == NULL) {
        return NULL;
    }
    slash = strrchr(path, '/');
    dot = strrchr(path, '.');
    if (dot == NULL || dot[1] == '\0' ||
        (slash != NULL && dot < slash)) {
        return NULL;
    }
    return dot + 1;
}

static int extensions_match_for_replace_local(
    const char *existing_path,
    const char *new_extension
)
{
    char existing_ext[32];
    char candidate_ext[32];

    normalize_extension_local(
        path_extension_local(existing_path),
        existing_ext,
        sizeof(existing_ext)
    );
    normalize_extension_local(new_extension, candidate_ext, sizeof(candidate_ext));
    return existing_ext[0] != '\0' &&
           candidate_ext[0] != '\0' &&
           strcmp(existing_ext, candidate_ext) == 0;
}

static void carver_output_quality_from_segments(
    const char *extension,
    const uint8_t *head,
    size_t head_len,
    const uint8_t *tail,
    size_t tail_len,
    size_t total_size,
    CarverOutputQuality *out
)
{
    char ext[32];

    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->size = total_size;
    snprintf(out->reason, sizeof(out->reason), "%s", "unknown_format");
    normalize_extension_local(extension, ext, sizeof(ext));

    if (strcmp(ext, "jpg") == 0) {
        out->known_format = 1;
        out->signature_ok =
            head_len >= 2U && head[0] == 0xffU && head[1] == 0xd8U;
        out->terminal_ok =
            bytes_contain_local(tail, tail_len, "\xff\xd9", 2U);
        snprintf(out->reason, sizeof(out->reason), "%s",
                 out->terminal_ok ? "jpeg_eoi" : "jpeg_missing_eoi");
    } else if (strcmp(ext, "png") == 0) {
        static const uint8_t png_sig[8] =
            {0x89U, 'P', 'N', 'G', 0x0dU, 0x0aU, 0x1aU, 0x0aU};

        out->known_format = 1;
        out->signature_ok = head_len >= sizeof(png_sig) &&
                            memcmp(head, png_sig, sizeof(png_sig)) == 0;
        out->terminal_ok = bytes_contain_local(tail, tail_len, "IEND", 4U);
        snprintf(out->reason, sizeof(out->reason), "%s",
                 out->terminal_ok ? "png_iend" : "png_missing_iend");
    } else if (strcmp(ext, "pdf") == 0) {
        out->known_format = 1;
        out->signature_ok =
            bytes_contain_local(
                head,
                head_len < 1024U ? head_len : 1024U,
                "%PDF-",
                5U
            );
        out->terminal_ok =
            bytes_contain_local(tail, tail_len, "%%EOF", 5U) &&
            bytes_contain_local(tail, tail_len, "startxref", 9U);
        snprintf(out->reason, sizeof(out->reason), "%s",
                 out->terminal_ok ? "pdf_startxref_eof" : "pdf_missing_startxref_eof");
    } else if (strcmp(ext, "zip") == 0 || strcmp(ext, "docx") == 0 ||
               strcmp(ext, "xlsx") == 0 || strcmp(ext, "pptx") == 0 ||
               strcmp(ext, "odt") == 0 || strcmp(ext, "ods") == 0 ||
               strcmp(ext, "odp") == 0 || strcmp(ext, "epub") == 0 ||
               strcmp(ext, "jar") == 0 || strcmp(ext, "apk") == 0 ||
               strcmp(ext, "xps") == 0) {
        out->known_format = 1;
        out->signature_ok =
            head_len >= 4U && head[0] == 'P' && head[1] == 'K';
        out->terminal_ok =
            bytes_contain_local(tail, tail_len, "PK\005\006", 4U);
        snprintf(out->reason, sizeof(out->reason), "%s",
                 out->terminal_ok ? "zip_eocd" : "zip_missing_eocd");
    } else if (strcmp(ext, "mov") == 0 || strcmp(ext, "mp4") == 0 ||
               strcmp(ext, "heic") == 0 || strcmp(ext, "heif") == 0 ||
               strcmp(ext, "cr3") == 0) {
        int has_moov;
        int has_mdat;

        out->known_format = 1;
        out->signature_ok =
            head_len >= 12U && memcmp(head + 4U, "ftyp", 4U) == 0;
        has_moov = bytes_contain_local(head, head_len, "moov", 4U) ||
                   bytes_contain_local(tail, tail_len, "moov", 4U);
        has_mdat = bytes_contain_local(head, head_len, "mdat", 4U) ||
                   bytes_contain_local(tail, tail_len, "mdat", 4U);
        out->structure_ok = has_moov && (has_mdat || strcmp(ext, "heic") == 0 ||
                                         strcmp(ext, "heif") == 0 ||
                                         strcmp(ext, "cr3") == 0);
        out->terminal_ok = out->structure_ok;
        snprintf(out->reason, sizeof(out->reason), "%s",
                 out->structure_ok ? "isobmff_moov_media" : "isobmff_missing_moov_media");
    } else if (strcmp(ext, "mkv") == 0 || strcmp(ext, "webm") == 0) {
        static const uint8_t ebml_sig[4] = {0x1aU, 0x45U, 0xdfU, 0xa3U};

        out->known_format = 1;
        out->signature_ok = head_len >= sizeof(ebml_sig) &&
                            memcmp(head, ebml_sig, sizeof(ebml_sig)) == 0;
        out->structure_ok =
            bytes_contain_local(head, head_len, "matroska", 8U) ||
            bytes_contain_local(head, head_len, "webm", 4U);
        out->terminal_ok = out->structure_ok;
        snprintf(out->reason, sizeof(out->reason), "%s",
                 out->structure_ok ? "ebml_doctype" : "ebml_missing_doctype");
    } else if (strcmp(ext, "avi") == 0 || strcmp(ext, "wav") == 0) {
        out->known_format = 1;
        out->signature_ok =
            head_len >= 12U && memcmp(head, "RIFF", 4U) == 0;
        out->structure_ok =
            head_len >= 12U &&
            ((strcmp(ext, "avi") == 0 && memcmp(head + 8U, "AVI ", 4U) == 0) ||
             (strcmp(ext, "wav") == 0 && memcmp(head + 8U, "WAVE", 4U) == 0));
        out->terminal_ok = out->structure_ok;
        snprintf(out->reason, sizeof(out->reason), "%s",
                 out->structure_ok ? "riff_kind" : "riff_kind_missing");
    } else if (strcmp(ext, "sqlite") == 0 || strcmp(ext, "db") == 0 ||
               strcmp(ext, "lrcat") == 0) {
        out->known_format = 1;
        out->signature_ok =
            head_len >= 16U && memcmp(head, "SQLite format 3", 15U) == 0;
        out->structure_ok = out->signature_ok;
        out->terminal_ok = out->signature_ok;
        snprintf(out->reason, sizeof(out->reason), "%s",
                 out->signature_ok ? "sqlite_header" : "sqlite_missing_header");
    }

    if (!out->known_format) {
        return;
    }
    out->score =
        (out->signature_ok ? 100 : 0) +
        (out->structure_ok ? 120 : 0) +
        (out->terminal_ok ? 220 : 0) +
        (int)(total_size > 65536U ? 64U : total_size / 1024U);
}

static const char *path_basename_local(const char *path)
{
    const char *slash_basename;
    const char *backslash_basename;

    if (path == NULL) {
        return NULL;
    }

    slash_basename = strrchr(path, '/');
    backslash_basename = strrchr(path, '\\');
    if (slash_basename == NULL && backslash_basename == NULL) {
        return path;
    }
    if (slash_basename == NULL) {
        return backslash_basename + 1;
    }
    if (backslash_basename == NULL) {
        return slash_basename + 1;
    }

    return (slash_basename > backslash_basename)
        ? (slash_basename + 1)
        : (backslash_basename + 1);
}

static int basename_is_system_container_ci(const char *basename)
{
    return ascii_equals_ci(basename, "hiberfil.sys") ||
           ascii_equals_ci(basename, "pagefile.sys") ||
           ascii_equals_ci(basename, "swapfile.sys") ||
           ascii_equals_ci(basename, "memory.dmp") ||
           ascii_equals_ci(basename, "dumpstack.log") ||
           ascii_equals_ci(basename, "dumpstack.log.tmp");
}

static int path_has_segment_ci(const char *path, const char *segment_name)
{
    const char *cursor;

    if (path == NULL || segment_name == NULL) {
        return 0;
    }

    cursor = path;
    while (*cursor == '/' || *cursor == '\\') {
        cursor++;
    }

    while (*cursor != '\0') {
        const char *next_slash = cursor;
        size_t segment_len;
        size_t name_len = strlen(segment_name);
        size_t i;
        int match = 1;

        while (*next_slash != '\0' &&
               *next_slash != '/' &&
               *next_slash != '\\') {
            next_slash++;
        }
        segment_len = (size_t)(next_slash - cursor);

        if (segment_len == name_len) {
            for (i = 0; i < name_len; i++) {
                if (ascii_tolower_local(cursor[i]) !=
                    ascii_tolower_local(segment_name[i])) {
                    match = 0;
                    break;
                }
            }
            if (match) {
                return 1;
            }
        }

        if (*next_slash == '\0') {
            break;
        }

        cursor = next_slash + 1;
        while (*cursor == '/' || *cursor == '\\') {
            cursor++;
        }
    }

    return 0;
}

static int basename_has_nikon_derivative_prefix_ci(const char *basename)
{
    const char *prefixes[] = {"SSCN", "RSCN", "FSCN"};
    size_t i;

    if (basename == NULL) {
        return 0;
    }

    for (i = 0U; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
        size_t j;
        const char *prefix = prefixes[i];

        for (j = 0U; prefix[j] != '\0'; j++) {
            if (basename[j] == '\0' ||
                ascii_tolower_local(basename[j]) !=
                    ascii_tolower_local(prefix[j])) {
                break;
            }
        }
        if (prefix[j] == '\0') {
            return 1;
        }
    }

    return 0;
}

static int path_is_low_value_system_image_context_ci(const char *path)
{
    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    if (path_has_segment_ci(path, "WAILLPAPER")) {
        return 1;
    }

    if (path_has_segment_ci(path, "Windows") &&
        path_has_segment_ci(path, "Wallpaper")) {
        return 1;
    }

    if (path_has_segment_ci(path, "Web") &&
        path_has_segment_ci(path, "Wallpaper")) {
        return 1;
    }

    return 0;
}

static int output_path_file_size_local(const char *path, size_t *out_size)
{
    struct stat st;

    if (out_size != NULL) {
        *out_size = 0U;
    }

    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        return 0;
    }

    if (out_size != NULL) {
        *out_size = (size_t)st.st_size;
    }
    return 1;
}

static int output_quality_for_path_local(
    const char *path,
    const char *extension,
    CarverOutputQuality *out
)
{
    FILE *file;
    size_t file_size = 0U;
    size_t head_len;
    size_t tail_len;
    uint8_t *head = NULL;
    uint8_t *tail = NULL;
    int ok = 0;

    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (path == NULL || extension == NULL || out == NULL ||
        !output_path_file_size_local(path, &file_size)) {
        return 0;
    }

    head_len = file_size < CARVER_OUTPUT_QUALITY_HEAD_BYTES
        ? file_size
        : CARVER_OUTPUT_QUALITY_HEAD_BYTES;
    tail_len = file_size < CARVER_OUTPUT_QUALITY_TAIL_BYTES
        ? file_size
        : CARVER_OUTPUT_QUALITY_TAIL_BYTES;
    head = (uint8_t *)malloc(head_len > 0U ? head_len : 1U);
    tail = (uint8_t *)malloc(tail_len > 0U ? tail_len : 1U);
    if (head == NULL || tail == NULL) {
        goto cleanup;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        goto cleanup;
    }
    if (head_len > 0U &&
        fread(head, 1, head_len, file) != head_len) {
        fclose(file);
        goto cleanup;
    }
    if (tail_len > 0U) {
        off_t tail_offset = file_size > tail_len
            ? (off_t)(file_size - tail_len)
            : (off_t)0;

        if (fseeko(file, tail_offset, SEEK_SET) != 0) {
            fclose(file);
            goto cleanup;
        }
        if (fread(tail, 1, tail_len, file) != tail_len) {
            fclose(file);
            goto cleanup;
        }
    }
    fclose(file);

    carver_output_quality_from_segments(
        extension,
        head,
        head_len,
        tail,
        tail_len,
        file_size,
        out
    );
    ok = 1;

cleanup:
    free(head);
    free(tail);
    return ok;
}

static void output_quality_for_buffer_local(
    const uint8_t *data,
    size_t data_size,
    const char *extension,
    CarverOutputQuality *out
)
{
    const uint8_t *head = data;
    size_t head_len = data_size < CARVER_OUTPUT_QUALITY_HEAD_BYTES
        ? data_size
        : CARVER_OUTPUT_QUALITY_HEAD_BYTES;
    const uint8_t *tail = data;
    size_t tail_len = data_size < CARVER_OUTPUT_QUALITY_TAIL_BYTES
        ? data_size
        : CARVER_OUTPUT_QUALITY_TAIL_BYTES;

    if (data != NULL && data_size > tail_len) {
        tail = data + data_size - tail_len;
    }
    carver_output_quality_from_segments(
        extension,
        head,
        head_len,
        tail,
        tail_len,
        data_size,
        out
    );
}

static int existing_quality_allows_replace_attempt_local(
    const CarverOutputQuality *existing
)
{
    if (existing == NULL || !existing->known_format) {
        return 0;
    }
    if (existing->size < CARVER_OUTPUT_REPLACE_MIN_BYTES) {
        return 1;
    }
    return !existing->signature_ok || !existing->terminal_ok;
}

static int candidate_quality_replaces_existing_local(
    const CarverOutputQuality *existing,
    const CarverOutputQuality *candidate
)
{
    if (existing == NULL || candidate == NULL ||
        !existing->known_format ||
        !candidate->known_format ||
        !candidate->signature_ok ||
        candidate->size < CARVER_OUTPUT_REPLACE_MIN_BYTES) {
        return 0;
    }

    if (candidate->terminal_ok && !existing->terminal_ok &&
        candidate->score >= existing->score + 80) {
        return 1;
    }
    if (candidate->structure_ok && !existing->structure_ok &&
        candidate->score >= existing->score + 80 &&
        candidate->size + (candidate->size / 2U) >= existing->size) {
        return 1;
    }
    if (existing->size < CARVER_OUTPUT_REPLACE_MIN_BYTES &&
        candidate->score >= existing->score + 120) {
        return 1;
    }
    if (candidate->terminal_ok && existing->terminal_ok &&
        candidate->score >= existing->score + 120 &&
        candidate->size > existing->size + 4096U) {
        return 1;
    }
    return 0;
}

static int build_replacement_temp_path_local(
    char *out_path,
    size_t out_size,
    const char *existing_path,
    long long abs_offset
)
{
    if (out_path == NULL || out_size == 0U ||
        existing_path == NULL || existing_path[0] == '\0') {
        return 0;
    }

    return snprintf(
               out_path,
               out_size,
               "%s.carv-replace-%ld-%lld.tmp",
               existing_path,
               (long)getpid(),
               abs_offset) < (int)out_size;
}

static void append_replacement_audit_local(
    long long abs_offset,
    const char *extension,
    const char *decision,
    const char *existing_path,
    const CarverOutputQuality *existing,
    const CarverOutputQuality *candidate
)
{
    char path[1024];
    const char *output_dir = fs_backend_current_output_dir();
    FILE *file;
    int write_header = 0;

    if (output_dir == NULL || output_dir[0] == '\0' ||
        decision == NULL || existing == NULL || candidate == NULL ||
        snprintf(
            path,
            sizeof(path),
            "%s/%s/replacement_audit.tsv",
            output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(path)) {
        return;
    }

    file = fopen(path, "a");
    if (file == NULL) {
        return;
    }
    if (ftell(file) == 0L) {
        write_header = 1;
    }
    if (write_header) {
        fprintf(
            file,
            "abs_offset\textension\tdecision\texisting_size\tcandidate_size\texisting_score\tcandidate_score\texisting_reason\tcandidate_reason\texisting_path\n"
        );
    }
    fprintf(
        file,
        "%lld\t%s\t%s\t%zu\t%zu\t%d\t%d\t%s\t%s\t%s\n",
        abs_offset,
        extension != NULL ? extension : "",
        decision,
        existing->size,
        candidate->size,
        existing->score,
        candidate->score,
        existing->reason,
        candidate->reason,
        existing_path != NULL ? existing_path : ""
    );
    fclose(file);
    (void)fs_backend_apply_output_owner_to_path(path);
}

static int prepare_replacement_candidate_local(
    CarverOutput *out,
    long long abs_offset,
    const char *extension
)
{
    char current_path[1024];
    char temp_path[1024];
    int current_reconciled = 0;
    size_t current_size = 0U;
    CarverOutputQuality existing_quality;

    if (out == NULL || abs_offset < 0) {
        return 0;
    }
    current_path[0] = '\0';
    if (!fs_backend_get_recovered_output_info(
            abs_offset,
            current_path,
            sizeof(current_path),
            &current_reconciled) ||
        current_path[0] == '\0' ||
        !output_path_file_size_local(current_path, &current_size)) {
        return 0;
    }

    if (!extensions_match_for_replace_local(current_path, extension) ||
        !output_quality_for_path_local(
            current_path,
            extension,
            &existing_quality) ||
        !existing_quality_allows_replace_attempt_local(&existing_quality) ||
        !build_replacement_temp_path_local(
            temp_path,
            sizeof(temp_path),
            current_path,
            abs_offset)) {
        return -1;
    }

    snprintf(out->path, sizeof(out->path), "%s", temp_path);
    snprintf(
        out->replacement_existing_path,
        sizeof(out->replacement_existing_path),
        "%s",
        current_path
    );
    out->replacement_existing_size = current_size;
    out->replacement_existing_reconciled = current_reconciled ? 1 : 0;
    out->replacement_candidate = 1;
    log_verbose(
        "Trying replace-if-better candidate at offset %lld: existing_size=%zu existing_quality=%s score=%d",
        abs_offset,
        existing_quality.size,
        existing_quality.reason,
        existing_quality.score
    );
    return 1;
}

int carver_output_should_skip_by_metadata_context(long long abs_offset)
{
    const char *path;
    const char *basename;

    if (!g_carver_output_metadata_context_skip_enabled) {
        return 0;
    }

    path = fs_backend_lookup_path_by_offset(abs_offset);
    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    basename = path_basename_local(path);
    if (basename_is_system_container_ci(basename)) {
        return 1;
    }

    if (ascii_equals_ci(basename, "thumbs.db") ||
        ascii_equals_ci(basename, "ehthumbs.db") ||
        ascii_equals_ci(basename, ".thumb") ||
        ascii_starts_with_ci(basename, "thumbcache_") ||
        ascii_ends_with_ci(basename, ".thumb")) {
        return 1;
    }

    return path_has_segment_ci(path, ".thumbs") ||
           path_has_segment_ci(path, ".thumbnails") ||
           path_has_segment_ci(path, "thumbs") ||
           path_has_segment_ci(path, "thumbnails") ||
           path_has_segment_ci(path, "thumbcache") ||
           path_has_segment_ci(path, "thumbnailcache");
}

int carver_output_should_skip_small_derivative_image_view(
    const FsViewEntry *view
)
{
    const char *basename;
    int system_tree;

    if (view == NULL) {
        return 0;
    }

    basename = path_basename_local(
        (view->path[0] != '\0') ? view->path : view->name
    );
    if (basename_has_nikon_derivative_prefix_ci(basename)) {
        return 1;
    }

    if (!path_is_low_value_system_image_context_ci(view->path) &&
        view->data_size >= CARVER_OUTPUT_SMALL_DERIVATIVE_IMAGE_MAX_BYTES) {
        return 0;
    }

    system_tree = (view->flags & FS_VIEW_FLAG_TREE_SYSTEM) != 0;
    if (path_is_low_value_system_image_context_ci(view->path)) {
        return view->data_size == 0U ||
               view->data_size < CARVER_OUTPUT_SMALL_DERIVATIVE_IMAGE_MAX_BYTES ||
               system_tree;
    }

    return system_tree &&
           view->data_size > 0U &&
           view->data_size < CARVER_OUTPUT_SMALL_DERIVATIVE_IMAGE_MAX_BYTES;
}

int carver_output_should_skip_existing_recovered(
    long long abs_offset,
    size_t start_offset,
    size_t *resume_offset
)
{
    char current_path[1024];
    int current_reconciled = 0;
    size_t file_size = 0U;

    if (resume_offset != NULL) {
        *resume_offset = start_offset + 1U;
    }

    if (abs_offset < 0 ||
        !fs_backend_get_recovered_output_info(
            abs_offset,
            current_path,
            sizeof(current_path),
            &current_reconciled) ||
        current_path[0] == '\0' ||
        !output_path_file_size_local(current_path, &file_size)) {
        return 0;
    }

    if (resume_offset != NULL &&
        start_offset <= ((size_t)-1) - file_size) {
        *resume_offset = start_offset + file_size;
    }

    return 1;
}

int carver_output_existing_recovered_allows_replace_attempt(
    long long abs_offset,
    const char *extension
)
{
    char current_path[1024];
    int current_reconciled = 0;
    CarverOutputQuality existing_quality;

    if (abs_offset < 0 || extension == NULL || extension[0] == '\0') {
        log_verbose(
            "Replace-if-better gate closed at offset %lld: missing candidate extension",
            abs_offset
        );
        return 0;
    }
    current_path[0] = '\0';
    if (!fs_backend_get_recovered_output_info(
            abs_offset,
            current_path,
            sizeof(current_path),
            &current_reconciled) ||
        current_path[0] == '\0') {
        log_verbose(
            "Replace-if-better gate closed at offset %lld: no tracked existing output",
            abs_offset
        );
        return 0;
    }
    if (!extensions_match_for_replace_local(current_path, extension)) {
        log_verbose(
            "Replace-if-better gate closed at offset %lld: extension mismatch existing=%s candidate=%s",
            abs_offset,
            path_extension_local(current_path) != NULL
                ? path_extension_local(current_path)
                : "",
            extension
        );
        return 0;
    }
    if (!output_quality_for_path_local(
            current_path,
            extension,
            &existing_quality)) {
        log_verbose(
            "Replace-if-better gate closed at offset %lld: could not read existing output quality for %s",
            abs_offset,
            current_path
        );
        return 0;
    }
    (void)current_reconciled;
    if (!existing_quality_allows_replace_attempt_local(&existing_quality)) {
        log_verbose(
            "Replace-if-better gate closed at offset %lld: existing output is already strong enough (%zu bytes/%s score=%d)",
            abs_offset,
            existing_quality.size,
            existing_quality.reason,
            existing_quality.score
        );
        return 0;
    }
    return 1;
}

void carver_output_set_metadata_context_skip_enabled(int enabled)
{
    g_carver_output_metadata_context_skip_enabled = enabled ? 1 : 0;
}

int carver_output_should_skip_by_mft_context(long long abs_offset)
{
    return carver_output_should_skip_by_metadata_context(abs_offset);
}

void carver_output_set_mft_context_skip_enabled(int enabled)
{
    carver_output_set_metadata_context_skip_enabled(enabled);
}

int carver_output_open(
    CarverOutput *out,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
)
{
    int replacement_state;

    if (out == NULL ||
        default_directory == NULL ||
        default_prefix == NULL ||
        extension == NULL) {
        return 0;
    }

    carver_output_reset(out);
    out->abs_offset = abs_offset;
    snprintf(out->extension, sizeof(out->extension), "%s", extension);

    replacement_state = prepare_replacement_candidate_local(out, abs_offset, extension);
    if (replacement_state < 0) {
        log_verbose(
            "Skipping recovered output open at offset %lld because that offset is already tracked with an existing output file",
            abs_offset
        );
        carver_output_reset(out);
        return 0;
    }
    if (replacement_state == 0) {
        if (!fs_backend_build_recovered_output_path(
                out->path,
                sizeof(out->path),
                abs_offset,
                default_directory,
                default_prefix,
                extension)) {
            if (!fs_backend_build_deferred_output_path(
                    out->path,
                    sizeof(out->path),
                    abs_offset,
                    default_directory,
                    default_prefix,
                    extension)) {
                log_error("Failed to build recovered output path");
                carver_output_reset(out);
                return 0;
            }
            log_verbose(
                "Recovered output path fell back to deterministic deferred path for offset %lld",
                abs_offset
            );
        }

    }

    if (!fs_backend_output_path_write_guard_allows(out->path)) {
        log_error(
            "Refusing to open output file because its mounted output volume is not live: %s",
            out->path
        );
        carver_output_reset(out);
        return 0;
    }
    out->file = fopen(out->path, "wb");
    if (out->file == NULL) {
        log_error(
            "Failed to open output file: %s (%s)",
            out->path,
            strerror(errno)
        );
        carver_output_reset(out);
        return 0;
    }

    if (!fs_backend_apply_output_owner_to_path(out->path)) {
        log_error("Failed to assign ownership to output file: %s", out->path);
        fclose(out->file);
        out->file = NULL;
        (void)remove(out->path);
        carver_output_reset(out);
        return 0;
    }

    return 1;
}

int carver_output_open_deferred(
    CarverOutput *out,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension
)
{
    int replacement_state;

    if (out == NULL ||
        default_directory == NULL ||
        default_prefix == NULL ||
        extension == NULL) {
        return 0;
    }

    carver_output_reset(out);
    out->abs_offset = abs_offset;
    out->deferred_capture = 1;
    snprintf(out->extension, sizeof(out->extension), "%s", extension);

    replacement_state = prepare_replacement_candidate_local(out, abs_offset, extension);
    if (replacement_state < 0) {
        log_verbose(
            "Skipping deferred output open at offset %lld because that offset is already tracked with an existing output file",
            abs_offset
        );
        carver_output_reset(out);
        return 0;
    }
    if (replacement_state == 0) {
        if (!fs_backend_build_deferred_output_path(
                out->path,
                sizeof(out->path),
                abs_offset,
                default_directory,
                default_prefix,
                extension)) {
            log_error("Failed to build recovered output path");
            carver_output_reset(out);
            return 0;
        }
    }

    if (!fs_backend_output_path_write_guard_allows(out->path)) {
        log_error(
            "Refusing to open output file because its mounted output volume is not live: %s",
            out->path
        );
        carver_output_reset(out);
        return 0;
    }
    out->file = fopen(out->path, "wb");
    if (out->file == NULL) {
        log_error(
            "Failed to open output file: %s (%s)",
            out->path,
            strerror(errno)
        );
        carver_output_reset(out);
        return 0;
    }

    if (!fs_backend_apply_output_owner_to_path(out->path)) {
        log_error("Failed to assign ownership to output file: %s", out->path);
        fclose(out->file);
        out->file = NULL;
        (void)remove(out->path);
        carver_output_reset(out);
        return 0;
    }

    return 1;
}

int carver_output_note_deferred_completion(const char *path, long long abs_offset)
{
    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    fs_backend_note_recovered_output(path, abs_offset);
    return 1;
}

int carver_output_replace_existing_buffer_if_better(
    long long abs_offset,
    const char *extension,
    const uint8_t *data,
    size_t data_size
)
{
    char current_path[1024];
    char temp_path[1024];
    int current_reconciled = 0;
    CarverOutputQuality existing_quality;
    CarverOutputQuality candidate_quality;
    FILE *file;

    if (data == NULL || data_size == 0U || abs_offset < 0 ||
        extension == NULL || extension[0] == '\0') {
        log_verbose(
            "Replace-if-better buffer skipped at offset %lld: invalid candidate input",
            abs_offset
        );
        return 0;
    }
    current_path[0] = '\0';
    if (!fs_backend_get_recovered_output_info(
            abs_offset,
            current_path,
            sizeof(current_path),
            &current_reconciled) ||
        current_path[0] == '\0') {
        log_verbose(
            "Replace-if-better buffer skipped at offset %lld: no tracked existing output",
            abs_offset
        );
        return 0;
    }
    if (!output_path_file_size_local(current_path, NULL)) {
        log_verbose(
            "Replace-if-better buffer skipped at offset %lld: existing output is not readable as a regular file: %s",
            abs_offset,
            current_path
        );
        return 0;
    }
    if (!extensions_match_for_replace_local(current_path, extension)) {
        log_verbose(
            "Replace-if-better buffer skipped at offset %lld: extension mismatch existing=%s candidate=%s",
            abs_offset,
            path_extension_local(current_path) != NULL
                ? path_extension_local(current_path)
                : "",
            extension
        );
        return 0;
    }
    if (!output_quality_for_path_local(current_path, extension, &existing_quality)) {
        log_verbose(
            "Replace-if-better buffer skipped at offset %lld: could not read existing output quality for %s",
            abs_offset,
            current_path
        );
        return 0;
    }
    if (!existing_quality_allows_replace_attempt_local(&existing_quality)) {
        log_verbose(
            "Replace-if-better buffer skipped at offset %lld: existing output is already strong enough (%zu bytes/%s score=%d)",
            abs_offset,
            existing_quality.size,
            existing_quality.reason,
            existing_quality.score
        );
        return 0;
    }

    output_quality_for_buffer_local(data, data_size, extension, &candidate_quality);
    if (!candidate_quality_replaces_existing_local(
            &existing_quality,
            &candidate_quality) ||
        !build_replacement_temp_path_local(
            temp_path,
            sizeof(temp_path),
            current_path,
            abs_offset)) {
        append_replacement_audit_local(
            abs_offset,
            extension,
            "kept_existing_buffer",
            current_path,
            &existing_quality,
            &candidate_quality
        );
        return 0;
    }

    if (!fs_backend_output_path_write_guard_allows(temp_path)) {
        return 0;
    }
    file = fopen(temp_path, "wb");
    if (file == NULL) {
        return 0;
    }
    if (fwrite(data, 1, data_size, file) != data_size) {
        fclose(file);
        (void)remove(temp_path);
        return 0;
    }
    if (fclose(file) != 0) {
        (void)remove(temp_path);
        return 0;
    }

    if (!fs_backend_output_path_write_guard_allows(current_path) ||
        rename(temp_path, current_path) != 0) {
        append_replacement_audit_local(
            abs_offset,
            extension,
            "replace_failed_buffer",
            current_path,
            &existing_quality,
            &candidate_quality
        );
        (void)remove(temp_path);
        return 0;
    }

    append_replacement_audit_local(
        abs_offset,
        extension,
        "replaced_buffer",
        current_path,
        &existing_quality,
        &candidate_quality
    );
    log_info(
        "Replace-if-better accepted buffer output at offset %lld (%s): existing %zu bytes/%s -> candidate %zu bytes/%s",
        abs_offset,
        extension,
        existing_quality.size,
        existing_quality.reason,
        candidate_quality.size,
        candidate_quality.reason
    );
    if (current_reconciled) {
        (void)fs_backend_apply_created_time_to_path(current_path, abs_offset);
    }
    (void)carver_output_note_deferred_completion(current_path, abs_offset);
    (void)fs_backend_apply_output_owner_to_path(current_path);
    return 1;
}

int carver_output_finish_validated(
    CarverOutput *out,
    CarverOutputValidator validator,
    void *ctx
)
{
    if (out == NULL || out->file == NULL) {
        return 0;
    }

    if (fclose(out->file) != 0) {
        log_error("Failed to finalize output file: %s", out->path);
        out->file = NULL;
        (void)remove(out->path);
        return 0;
    }

    out->file = NULL;
    if (validator != NULL && !validator(out->path, ctx)) {
        (void)remove(out->path);
        carver_output_reset(out);
        return 0;
    }
    if (out->replacement_candidate) {
        CarverOutputQuality existing_quality = {0};
        CarverOutputQuality candidate_quality = {0};
        int existing_ok = output_quality_for_path_local(
            out->replacement_existing_path,
            out->extension,
            &existing_quality
        );
        int candidate_ok = output_quality_for_path_local(
            out->path,
            out->extension,
            &candidate_quality
        );

        if (existing_ok &&
            candidate_ok &&
            candidate_quality_replaces_existing_local(
                &existing_quality,
                &candidate_quality)) {
            char final_path[sizeof(out->path)];

            snprintf(final_path, sizeof(final_path), "%s", out->replacement_existing_path);
            if (!fs_backend_output_path_write_guard_allows(final_path) ||
                rename(out->path, final_path) != 0) {
                log_error(
                    "Replace-if-better could not atomically replace %s with candidate %s (%s)",
                    final_path,
                    out->path,
                    strerror(errno)
                );
                append_replacement_audit_local(
                    out->abs_offset,
                    out->extension,
                    "replace_failed",
                    final_path,
                    existing_ok ? &existing_quality : &candidate_quality,
                    &candidate_quality
                );
                (void)remove(out->path);
                carver_output_reset(out);
                return 0;
            }
            snprintf(out->path, sizeof(out->path), "%s", final_path);
            append_replacement_audit_local(
                out->abs_offset,
                out->extension,
                "replaced",
                final_path,
                &existing_quality,
                &candidate_quality
            );
            log_info(
                "Replace-if-better accepted offset %lld (%s): existing %zu bytes/%s -> candidate %zu bytes/%s",
                out->abs_offset,
                out->extension,
                existing_quality.size,
                existing_quality.reason,
                candidate_quality.size,
                candidate_quality.reason
            );
            if (out->deferred_capture) {
                (void)carver_output_note_deferred_completion(
                    out->path,
                    out->abs_offset
                );
            } else {
                (void)fs_backend_apply_created_time_to_path(
                    out->path,
                    out->abs_offset
                );
                fs_backend_note_recovered_output(out->path, out->abs_offset);
            }
            (void)fs_backend_apply_output_owner_to_path(out->path);
            return 1;
        }

        append_replacement_audit_local(
            out->abs_offset,
            out->extension,
            "kept_existing",
            out->replacement_existing_path,
            existing_ok ? &existing_quality : &candidate_quality,
            candidate_ok ? &candidate_quality : &existing_quality
        );
        (void)remove(out->path);
        carver_output_reset(out);
        return 1;
    }
    if (out->deferred_capture) {
        (void)carver_output_note_deferred_completion(out->path, out->abs_offset);
    } else {
        (void)fs_backend_apply_created_time_to_path(out->path, out->abs_offset);
        fs_backend_note_recovered_output(out->path, out->abs_offset);
    }
    return 1;
}

int carver_output_finish(CarverOutput *out)
{
    return carver_output_finish_validated(out, NULL, NULL);
}

void carver_output_abort(CarverOutput *out)
{
    if (out == NULL) {
        return;
    }

    if (out->file != NULL) {
        fclose(out->file);
        out->file = NULL;
    }

    if (out->path[0] != '\0') {
        (void)remove(out->path);
    }

    carver_output_reset(out);
}
