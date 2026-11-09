#define _POSIX_C_SOURCE 200809L

#include "filtered_image_log.h"

#include "config.h"
#include "fs_backend.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define FILTERED_IMAGE_LOG_PATH_MAX 4096U
#define FILTERED_IMAGE_LOG_FILE_NAME "filtered_images.tsv"

static pthread_mutex_t g_filtered_image_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static int text_is_empty_local(const char *text)
{
    return text == NULL || text[0] == '\0';
}

static void write_tsv_text_local(FILE *file, const char *text)
{
    const unsigned char *cursor;

    if (file == NULL || text == NULL) {
        return;
    }

    for (cursor = (const unsigned char *)text; *cursor != '\0'; ++cursor) {
        if (*cursor == '\t' || *cursor == '\r' || *cursor == '\n') {
            fputc(' ', file);
        } else {
            fputc((int)*cursor, file);
        }
    }
}

static int build_log_paths_local(
    const char *output_dir,
    char *state_dir,
    size_t state_dir_size,
    char *log_path,
    size_t log_path_size
)
{
    if (text_is_empty_local(output_dir) ||
        state_dir == NULL ||
        log_path == NULL ||
        snprintf(state_dir, state_dir_size, "%s/%s", output_dir, APP_STATE_DIR_NAME) >=
            (int)state_dir_size ||
        snprintf(log_path, log_path_size, "%s/%s/%s",
                 output_dir, APP_STATE_DIR_NAME, FILTERED_IMAGE_LOG_FILE_NAME) >=
            (int)log_path_size) {
        return 0;
    }
    return 1;
}

static int ensure_state_dir_local(const char *state_dir)
{
    if (text_is_empty_local(state_dir) ||
        !fs_backend_output_path_write_guard_allows(state_dir)) {
        return 0;
    }
    return mkdir(state_dir, 0775) == 0 || errno == EEXIST;
}

void filtered_image_log_append(
    const char *output_dir,
    const char *source,
    const char *format,
    const char *reason,
    uint64_t abs_offset,
    uint64_t expected_size,
    uint64_t detected_size,
    uint64_t width,
    uint64_t height,
    const char *path
)
{
    char state_dir[FILTERED_IMAGE_LOG_PATH_MAX];
    char log_path[FILTERED_IMAGE_LOG_PATH_MAX];
    struct stat st;
    int write_header = 0;
    FILE *file;

    if (text_is_empty_local(output_dir) || text_is_empty_local(reason)) {
        return;
    }

    if (!build_log_paths_local(
            output_dir,
            state_dir,
            sizeof(state_dir),
            log_path,
            sizeof(log_path)) ||
        !fs_backend_output_path_write_guard_allows(log_path)) {
        return;
    }

    pthread_mutex_lock(&g_filtered_image_log_mutex);

    if (!ensure_state_dir_local(state_dir)) {
        pthread_mutex_unlock(&g_filtered_image_log_mutex);
        return;
    }
    if (stat(log_path, &st) != 0 || st.st_size == 0) {
        write_header = 1;
    }

    file = fopen(log_path, "a");
    if (file == NULL) {
        pthread_mutex_unlock(&g_filtered_image_log_mutex);
        return;
    }

    if (write_header) {
        fprintf(
            file,
            "source\tformat\treason\tabs_offset\texpected_size\tdetected_size\twidth\theight\tpath\n"
        );
    }

    write_tsv_text_local(file, text_is_empty_local(source) ? "unknown" : source);
    fputc('\t', file);
    write_tsv_text_local(file, text_is_empty_local(format) ? "image" : format);
    fprintf(file, "\t");
    write_tsv_text_local(file, reason);
    fprintf(
        file,
        "\t%llu\t%llu\t%llu\t%llu\t%llu\t",
        (unsigned long long)abs_offset,
        (unsigned long long)expected_size,
        (unsigned long long)detected_size,
        (unsigned long long)width,
        (unsigned long long)height
    );
    write_tsv_text_local(file, path);
    fputc('\n', file);
    fclose(file);

    pthread_mutex_unlock(&g_filtered_image_log_mutex);
}

void filtered_image_log_append_current(
    const char *source,
    const char *format,
    const char *reason,
    uint64_t abs_offset,
    uint64_t expected_size,
    uint64_t detected_size,
    uint64_t width,
    uint64_t height,
    const char *path
)
{
    filtered_image_log_append(
        fs_backend_current_output_dir(),
        source,
        format,
        reason,
        abs_offset,
        expected_size,
        detected_size,
        width,
        height,
        path
    );
}
