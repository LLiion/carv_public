#define _POSIX_C_SOURCE 200809L

#include "carver_output.h"
#include "fs_backend.h"
#include "log.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define fopen(path, mode) fs_backend_fopen_output_write_guarded((path), (mode))

#define OUTPUT_ASYNC_QUEUE_CAPACITY 64U
#define OUTPUT_ASYNC_MAX_JOB_BYTES (64ULL * 1024ULL * 1024ULL)
#define OUTPUT_ASYNC_MAX_OUTSTANDING_BYTES (256ULL * 1024ULL * 1024ULL)

typedef struct {
    char path[1024];
    long long abs_offset;
    uint8_t *data;
    size_t data_size;
    time_t created_time;
} AsyncOutputJob;

typedef struct AsyncReservedPath {
    char path[1024];
    long long abs_offset;
    struct AsyncReservedPath *next;
} AsyncReservedPath;

static pthread_mutex_t async_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t async_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t async_not_full = PTHREAD_COND_INITIALIZER;
static pthread_cond_t async_done = PTHREAD_COND_INITIALIZER;
static pthread_t async_thread;
static AsyncOutputJob async_queue[OUTPUT_ASYNC_QUEUE_CAPACITY];
static size_t async_queue_head = 0;
static size_t async_queue_tail = 0;
static size_t async_queue_count = 0;
static size_t async_active_jobs = 0;
static uint64_t async_outstanding_bytes = 0;
static int async_running = 0;
static int async_stopping = 0;
static AsyncReservedPath *async_reserved_paths = NULL;

static int output_path_exists_local(const char *path)
{
    FILE *file;

    if (path == NULL || path[0] == '\0') {
        return 0;
    }

    file = fopen(path, "rb");
    if (file == NULL) {
        return 0;
    }

    fclose(file);
    return 1;
}

static int output_path_is_reserved_locked(const char *path)
{
    AsyncReservedPath *cursor;

    for (cursor = async_reserved_paths; cursor != NULL; cursor = cursor->next) {
        if (strcmp(cursor->path, path) == 0) {
            return 1;
        }
    }

    return 0;
}

static int split_output_path_extension(
    const char *path,
    char *stem,
    size_t stem_size,
    char *extension,
    size_t extension_size
)
{
    const char *slash;
    const char *dot;
    size_t stem_len;

    if (path == NULL || stem == NULL || extension == NULL ||
        stem_size == 0 || extension_size == 0) {
        return 0;
    }

    slash = strrchr(path, '/');
    dot = strrchr(path, '.');
    if (dot == NULL || (slash != NULL && dot < slash)) {
        dot = path + strlen(path);
    }

    stem_len = (size_t)(dot - path);
    if (stem_len + 1U > stem_size) {
        return 0;
    }

    memcpy(stem, path, stem_len);
    stem[stem_len] = '\0';
    snprintf(extension, extension_size, "%s", dot);
    return 1;
}

static int reserve_output_path(
    char *path,
    size_t path_size,
    int allow_existing_reuse,
    long long abs_offset,
    int *out_already_reserved_same_offset
)
{
    char stem[1024];
    char extension[128];
    char candidate[1024];
    unsigned int suffix;
    AsyncReservedPath *reserved;

    if (path == NULL || path_size == 0) {
        return 0;
    }

    if (out_already_reserved_same_offset != NULL) {
        *out_already_reserved_same_offset = 0;
    }

    if (!split_output_path_extension(
            path,
            stem,
            sizeof(stem),
            extension,
            sizeof(extension))) {
        return 0;
    }

    pthread_mutex_lock(&async_mutex);
    for (reserved = async_reserved_paths; reserved != NULL; reserved = reserved->next) {
        if (reserved->abs_offset == abs_offset) {
            snprintf(path, path_size, "%s", reserved->path);
            if (out_already_reserved_same_offset != NULL) {
                *out_already_reserved_same_offset = 1;
            }
            pthread_mutex_unlock(&async_mutex);
            return 1;
        }
    }

    if (!output_path_is_reserved_locked(path) &&
        (allow_existing_reuse || !output_path_exists_local(path))) {
        snprintf(candidate, sizeof(candidate), "%s", path);
    } else {
        candidate[0] = '\0';
        for (suffix = 1U; suffix < 100000U; suffix++) {
            if (snprintf(
                    candidate,
                    sizeof(candidate),
                    "%s_%u%s",
                    stem,
                    suffix,
                    extension) >= (int)sizeof(candidate)) {
                candidate[0] = '\0';
                break;
            }

            if (!output_path_is_reserved_locked(candidate) &&
                !output_path_exists_local(candidate)) {
                break;
            }
        }

        if (candidate[0] == '\0' || suffix >= 100000U) {
            pthread_mutex_unlock(&async_mutex);
            return 0;
        }
    }

    reserved = (AsyncReservedPath *)calloc(1, sizeof(*reserved));
    if (reserved == NULL) {
        pthread_mutex_unlock(&async_mutex);
        return 0;
    }

    snprintf(reserved->path, sizeof(reserved->path), "%s", candidate);
    reserved->abs_offset = abs_offset;
    reserved->next = async_reserved_paths;
    async_reserved_paths = reserved;
    snprintf(path, path_size, "%s", candidate);
    pthread_mutex_unlock(&async_mutex);
    return 1;
}

static void release_reserved_output_path(const char *path)
{
    AsyncReservedPath **cursor;

    if (path == NULL || path[0] == '\0') {
        return;
    }

    pthread_mutex_lock(&async_mutex);
    cursor = &async_reserved_paths;
    while (*cursor != NULL) {
        AsyncReservedPath *current = *cursor;

        if (strcmp(current->path, path) == 0) {
            *cursor = current->next;
            free(current);
            break;
        }

        cursor = &current->next;
    }
    pthread_mutex_unlock(&async_mutex);
}

static int write_prepared_output_file(
    const char *path,
    long long abs_offset,
    time_t created_time,
    const uint8_t *data,
    size_t data_size,
    int note_recovered
)
{
    FILE *file;

    if (path == NULL || path[0] == '\0' ||
        (data == NULL && data_size > 0)) {
        release_reserved_output_path(path);
        return 0;
    }
    if (!fs_backend_output_path_write_guard_allows(path)) {
        log_error(
            "Refusing to open async output file because its mounted output volume is not live: %s",
            path
        );
        release_reserved_output_path(path);
        return 0;
    }

    file = fopen(path, "wb");
    if (file == NULL) {
        log_error(
            "Failed to open output file: %s (%s)",
            path,
            strerror(errno)
        );
        release_reserved_output_path(path);
        return 0;
    }

    if (data_size > 0 && fwrite(data, 1, data_size, file) != data_size) {
        fclose(file);
        (void)remove(path);
        release_reserved_output_path(path);
        return 0;
    }

    if (fclose(file) != 0) {
        log_error("Failed to finalize output file: %s", path);
        (void)remove(path);
        release_reserved_output_path(path);
        return 0;
    }

    if (!fs_backend_apply_output_owner_to_path(path)) {
        log_error("Failed to assign ownership to output file: %s", path);
        (void)remove(path);
        release_reserved_output_path(path);
        return 0;
    }

    release_reserved_output_path(path);

    if (created_time > 0) {
        (void)fs_backend_apply_created_time_value_to_path(path, created_time);
    }

    if (note_recovered) {
        (void)carver_output_note_deferred_completion(path, abs_offset);
    }
    return 1;
}

static int prepare_buffer_output_path(
    char *path,
    size_t path_size,
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension,
    time_t *created_time_out,
    int *out_already_pending
)
{
    char current_path[1024];
    int current_reconciled = 0;
    int allow_existing_reuse = 0;
    int already_pending = 0;

    if (created_time_out != NULL) {
        *created_time_out = 0;
    }
    if (out_already_pending != NULL) {
        *out_already_pending = 0;
    }

    if (path == NULL || path_size == 0 ||
        !fs_backend_build_deferred_output_path(
            path,
            path_size,
            abs_offset,
            default_directory,
            default_prefix,
            extension)) {
        log_error("Failed to build recovered output path");
        return 0;
    }

    current_path[0] = '\0';
    if (fs_backend_get_recovered_output_info(
            abs_offset,
            current_path,
            sizeof(current_path),
            &current_reconciled) &&
        current_path[0] != '\0' &&
        strcmp(current_path, path) == 0) {
        allow_existing_reuse = 1;
    }

    if (!reserve_output_path(
            path,
            path_size,
            allow_existing_reuse,
            abs_offset,
            &already_pending)) {
        log_error("Failed to reserve output path: %s", path);
        return 0;
    }

    if (out_already_pending != NULL) {
        *out_already_pending = already_pending;
    }

    /*
     * Keep in-flight names reserved in memory until the writer creates the
     * real file. For raw-all deferred capture we avoid extra MFT lookups here;
     * timestamps can be applied later when contextual renaming catches up.
     */
    return 1;
}

static void async_output_job_clear(AsyncOutputJob *job)
{
    if (job == NULL) {
        return;
    }

    free(job->data);
    job->data = NULL;
    job->data_size = 0;
    job->path[0] = '\0';
    job->abs_offset = -1;
    job->created_time = 0;
}

static void *async_output_worker(void *arg)
{
    (void)arg;

    {
        sigset_t blocked;

        sigemptyset(&blocked);
        sigaddset(&blocked, SIGINT);
        sigaddset(&blocked, SIGTERM);
        (void)pthread_sigmask(SIG_BLOCK, &blocked, NULL);
    }

    for (;;) {
        AsyncOutputJob job;
        int ok;

        memset(&job, 0, sizeof(job));
        job.abs_offset = -1;

        pthread_mutex_lock(&async_mutex);
        while (async_queue_count == 0 && !async_stopping) {
            pthread_cond_wait(&async_not_empty, &async_mutex);
        }

        if (async_queue_count == 0 && async_stopping) {
            pthread_mutex_unlock(&async_mutex);
            break;
        }

        job = async_queue[async_queue_head];
        memset(&async_queue[async_queue_head], 0, sizeof(async_queue[async_queue_head]));
        async_queue_head = (async_queue_head + 1U) % OUTPUT_ASYNC_QUEUE_CAPACITY;
        async_queue_count--;
        async_active_jobs++;
        pthread_cond_broadcast(&async_not_full);
        pthread_mutex_unlock(&async_mutex);

        ok = write_prepared_output_file(
            job.path,
            job.abs_offset,
            job.created_time,
            job.data,
            job.data_size,
            1
        );
        (void)ok;

        pthread_mutex_lock(&async_mutex);
        if (async_outstanding_bytes >= (uint64_t)job.data_size) {
            async_outstanding_bytes -= (uint64_t)job.data_size;
        } else {
            async_outstanding_bytes = 0;
        }
        if (async_active_jobs > 0) {
            async_active_jobs--;
        }
        pthread_cond_broadcast(&async_not_full);
        pthread_cond_broadcast(&async_done);
        pthread_mutex_unlock(&async_mutex);

        async_output_job_clear(&job);
    }

    return NULL;
}

static int async_enqueue_output_job(AsyncOutputJob *job)
{
    if (job == NULL || job->data == NULL || job->data_size == 0) {
        return 0;
    }

    pthread_mutex_lock(&async_mutex);
    if (!async_running || async_stopping) {
        pthread_mutex_unlock(&async_mutex);
        return 0;
    }

    while (!async_stopping &&
           (async_queue_count == OUTPUT_ASYNC_QUEUE_CAPACITY ||
            async_outstanding_bytes + (uint64_t)job->data_size >
                OUTPUT_ASYNC_MAX_OUTSTANDING_BYTES)) {
        pthread_cond_wait(&async_not_full, &async_mutex);
    }

    if (async_stopping || !async_running) {
        pthread_mutex_unlock(&async_mutex);
        return 0;
    }

    async_queue[async_queue_tail] = *job;
    async_queue_tail = (async_queue_tail + 1U) % OUTPUT_ASYNC_QUEUE_CAPACITY;
    async_queue_count++;
    async_outstanding_bytes += (uint64_t)job->data_size;
    pthread_cond_signal(&async_not_empty);
    pthread_mutex_unlock(&async_mutex);

    job->data = NULL;
    job->data_size = 0;
    return 1;
}

int carver_output_async_start(void)
{
    int create_status;

    pthread_mutex_lock(&async_mutex);
    if (async_running) {
        pthread_mutex_unlock(&async_mutex);
        return 1;
    }

    async_queue_head = 0;
    async_queue_tail = 0;
    async_queue_count = 0;
    async_active_jobs = 0;
    async_outstanding_bytes = 0;
    async_stopping = 0;
    async_running = 1;
    pthread_mutex_unlock(&async_mutex);

    create_status = pthread_create(&async_thread, NULL, async_output_worker, NULL);
    if (create_status != 0) {
        pthread_mutex_lock(&async_mutex);
        async_running = 0;
        async_stopping = 0;
        pthread_mutex_unlock(&async_mutex);
        log_error("Failed to start async output writer");
        return 0;
    }

    return 1;
}

void carver_output_async_drain_completions(void)
{
    /* Async writer records recovered outputs directly after each file write. */
}

void carver_output_async_flush(void)
{
    int running;

    pthread_mutex_lock(&async_mutex);
    running = async_running;
    pthread_mutex_unlock(&async_mutex);

    if (!running) {
        return;
    }

    log_set_working_activity("writer catching up");
    for (;;) {
        int done;

        pthread_mutex_lock(&async_mutex);
        done = async_queue_count == 0 && async_active_jobs == 0;
        if (done) {
            pthread_mutex_unlock(&async_mutex);
            break;
        }
        pthread_cond_wait(&async_done, &async_mutex);
        pthread_mutex_unlock(&async_mutex);
    }

}

void carver_output_async_stop(void)
{
    int running;

    pthread_mutex_lock(&async_mutex);
    running = async_running;
    pthread_mutex_unlock(&async_mutex);

    if (!running) {
        return;
    }

    carver_output_async_flush();

    pthread_mutex_lock(&async_mutex);
    async_stopping = 1;
    pthread_cond_broadcast(&async_not_empty);
    pthread_mutex_unlock(&async_mutex);

    pthread_join(async_thread, NULL);

    pthread_mutex_lock(&async_mutex);
    async_running = 0;
    async_stopping = 0;
    pthread_mutex_unlock(&async_mutex);
}

void carver_output_async_get_live_stats(AsyncOutputLiveStats *out)
{
    if (out == NULL) {
        return;
    }

    memset(out, 0, sizeof(*out));

    pthread_mutex_lock(&async_mutex);
    out->queue_count = async_queue_count;
    out->queue_capacity = OUTPUT_ASYNC_QUEUE_CAPACITY;
    out->active_jobs = async_active_jobs;
    out->outstanding_bytes = async_outstanding_bytes;
    out->running = async_running;
    pthread_mutex_unlock(&async_mutex);
}

int carver_output_write_buffer(
    long long abs_offset,
    const char *default_directory,
    const char *default_prefix,
    const char *extension,
    const uint8_t *data,
    size_t data_size
)
{
    char path[1024];
    time_t created_time = 0;
    int already_pending = 0;
    AsyncOutputJob job;
    int can_queue;

    if (data == NULL || data_size == 0) {
        return 0;
    }

    if (carver_output_should_skip_existing_recovered(abs_offset, 0U, NULL)) {
        (void)carver_output_replace_existing_buffer_if_better(
            abs_offset,
            extension,
            data,
            data_size
        );
        return 1;
    }

    if (!prepare_buffer_output_path(
            path,
            sizeof(path),
            abs_offset,
            default_directory,
            default_prefix,
            extension,
            &created_time,
            &already_pending)) {
        return 0;
    }

    if (already_pending) {
        return 1;
    }

    pthread_mutex_lock(&async_mutex);
    can_queue = async_running &&
        !async_stopping &&
        data_size <= OUTPUT_ASYNC_MAX_JOB_BYTES &&
        (uint64_t)data_size <= OUTPUT_ASYNC_MAX_OUTSTANDING_BYTES;
    pthread_mutex_unlock(&async_mutex);

    if (!can_queue) {
        return write_prepared_output_file(
            path,
            abs_offset,
            created_time,
            data,
            data_size,
            1
        );
    }

    memset(&job, 0, sizeof(job));
    snprintf(job.path, sizeof(job.path), "%s", path);
    job.abs_offset = abs_offset;
    job.created_time = created_time;
    job.data_size = data_size;
    job.data = (uint8_t *)malloc(data_size);
    if (job.data == NULL) {
        return write_prepared_output_file(
            path,
            abs_offset,
            created_time,
            data,
            data_size,
            1
        );
    }

    memcpy(job.data, data, data_size);
    if (!async_enqueue_output_job(&job)) {
        int ok = write_prepared_output_file(
            path,
            abs_offset,
            created_time,
            data,
            data_size,
            1
        );
        async_output_job_clear(&job);
        return ok;
    }

    return 1;
}
