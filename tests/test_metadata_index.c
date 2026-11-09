#define _POSIX_C_SOURCE 200809L

#include "metadata_index.h"
#include "metadata_outcome.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define TEST_EXTENT_COUNT 100000U

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "metadata-index test failed at %s:%d: %s (errno=%d)\n", \
                __FILE__, __LINE__, #condition, errno); \
        goto cleanup; \
    } \
} while (0)

typedef struct {
    unsigned calls;
    unsigned stop_after;
    int armed;
} StopState;

typedef struct {
    size_t calls;
    uint64_t bytes;
    uint64_t first_object;
    uint64_t first_physical_row;
} DeliveryState;

static int note_delivery(
    const MetadataIndexPhysicalMatch *match,
    uint64_t physical_start,
    uint64_t physical_end,
    void *context)
{
    DeliveryState *state = (DeliveryState *)context;

    if (match == NULL || state == NULL || physical_end <= physical_start) return -1;
    if (state->calls == 0U) {
        state->first_object = match->object_key;
        state->first_physical_row = match->physical_row;
    }
    state->calls++;
    state->bytes += physical_end - physical_start;
    return 0;
}

static int stop_after_calls(void *context)
{
    StopState *state = (StopState *)context;
    if (!state->armed) return 0;
    state->calls++;
    return state->calls >= state->stop_after;
}

static int remove_test_tree(const char *path)
{
    DIR *directory = opendir(path);
    struct dirent *entry;

    if (directory == NULL) return unlink(path);
    while ((entry = readdir(directory)) != NULL) {
        char child[PATH_MAX];
        struct stat status;

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >=
            (int)sizeof(child)) {
            closedir(directory);
            return -1;
        }
        if (lstat(child, &status) != 0 ||
            (S_ISDIR(status.st_mode) ? remove_test_tree(child) : unlink(child)) != 0) {
            closedir(directory);
            return -1;
        }
    }
    if (closedir(directory) != 0) return -1;
    return rmdir(path);
}

static size_t count_file_lines(const char *path)
{
    FILE *file = fopen(path, "r");
    size_t lines = 0U;
    int ch;

    if (file == NULL) return 0U;
    while ((ch = fgetc(file)) != EOF) {
        if (ch == '\n') lines++;
    }
    fclose(file);
    return lines;
}

static int file_contains_text(const char *path, const char *needle)
{
    FILE *file = fopen(path, "r");
    char line[512];

    if (file == NULL || needle == NULL) {
        if (file != NULL) fclose(file);
        return 0;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        if (strstr(line, needle) != NULL) {
            fclose(file);
            return 1;
        }
    }
    fclose(file);
    return 0;
}

static int append_name(
    MetadataIndexWriter *writer,
    uint64_t link_key,
    uint64_t object_key,
    uint64_t parent_key,
    const char *name)
{
    MetadataIndexLink link = {0};
    size_t length = strlen(name);

    if (length > UINT32_MAX ||
        metadata_index_writer_append_string(
            writer,
            name,
            (uint32_t)length,
            &link.string_offset) != 0) {
        return -1;
    }
    link.link_key = link_key;
    link.object_key = object_key;
    link.parent_object_key = parent_key;
    link.string_length = (uint32_t)length;
    link.provenance = METADATA_INDEX_PROVENANCE_LIVE_HFSPLUS_CATALOG;
    link.confidence = 100U;
    return metadata_index_writer_append_link(writer, &link);
}

static int build_first_generation(
    const char *index_dir,
    const MetadataIndexVolumeIdentity *identity)
{
    MetadataIndexWriter *writer = NULL;
    MetadataIndexObject root = {0};
    MetadataIndexObject directory = {0};
    MetadataIndexObject photo = {0};
    MetadataIndexObject giant = {0};
    MetadataIndexObject empty = {0};
    MetadataIndexFork photo_fork = {0};
    MetadataIndexFork giant_fork = {0};
    MetadataIndexFork empty_fork = {0};
    uint32_t index;

    if (metadata_index_writer_create(index_dir, identity, &writer) != 0) return -1;

    root.object_key = 2U;
    root.best_link_row = 0U;
    root.first_fork_row = METADATA_INDEX_NO_ROW;
    root.flags = METADATA_INDEX_OBJECT_FLAG_DIRECTORY |
        METADATA_INDEX_OBJECT_FLAG_ROOT | METADATA_INDEX_OBJECT_FLAG_LIVE;
    directory.object_key = 5U;
    directory.best_link_row = 1U;
    directory.first_fork_row = METADATA_INDEX_NO_ROW;
    directory.flags = METADATA_INDEX_OBJECT_FLAG_DIRECTORY |
        METADATA_INDEX_OBJECT_FLAG_LIVE;
    photo.object_key = 10U;
    photo.best_link_row = 2U;
    photo.first_fork_row = 0U;
    photo.fork_count = 1U;
    photo.flags = METADATA_INDEX_OBJECT_FLAG_LIVE;
    photo.create_time = 1234U;
    giant.object_key = 20U;
    giant.best_link_row = 3U;
    giant.first_fork_row = 1U;
    giant.fork_count = 1U;
    giant.flags = METADATA_INDEX_OBJECT_FLAG_LIVE;
    empty.object_key = 30U;
    empty.best_link_row = 4U;
    empty.first_fork_row = 2U;
    empty.fork_count = 1U;
    empty.flags = METADATA_INDEX_OBJECT_FLAG_LIVE;

    if (metadata_index_writer_append_object(writer, &root) != 0 ||
        metadata_index_writer_append_object(writer, &directory) != 0 ||
        metadata_index_writer_append_object(writer, &photo) != 0 ||
        metadata_index_writer_append_object(writer, &giant) != 0 ||
        metadata_index_writer_append_object(writer, &empty) != 0 ||
        append_name(writer, 1U, 2U, 0U, "") != 0 ||
        append_name(writer, 2U, 5U, 2U, "dir") != 0 ||
        append_name(writer, 3U, 10U, 5U, "photo.jpg") != 0 ||
        append_name(writer, 4U, 20U, 2U, "giant.bin") != 0 ||
        append_name(writer, 5U, 30U, 2U, "empty.txt") != 0) {
        metadata_index_writer_abort(writer);
        return -1;
    }

    photo_fork.object_key = 10U;
    photo_fork.logical_size = (uint64_t)TEST_EXTENT_COUNT * 512U;
    photo_fork.allocated_size = photo_fork.logical_size;
    photo_fork.first_extent_row = 0U;
    photo_fork.extent_count = TEST_EXTENT_COUNT;
    photo_fork.fork_kind = METADATA_INDEX_FORK_DATA;
    photo_fork.flags = METADATA_INDEX_FORK_FLAG_COMPLETE;
    giant_fork.object_key = 20U;
    giant_fork.logical_size = 200000000U;
    giant_fork.allocated_size = 200000000U;
    giant_fork.first_extent_row = TEST_EXTENT_COUNT;
    giant_fork.extent_count = 1U;
    giant_fork.fork_kind = METADATA_INDEX_FORK_DATA;
    giant_fork.flags = METADATA_INDEX_FORK_FLAG_COMPLETE;
    empty_fork.object_key = 30U;
    empty_fork.first_extent_row = TEST_EXTENT_COUNT + 1U;
    empty_fork.fork_kind = METADATA_INDEX_FORK_DATA;
    empty_fork.flags = METADATA_INDEX_FORK_FLAG_COMPLETE;

    if (metadata_index_writer_append_fork(writer, &photo_fork) != 0 ||
        metadata_index_writer_append_fork(writer, &giant_fork) != 0 ||
        metadata_index_writer_append_fork(writer, &empty_fork) != 0) {
        metadata_index_writer_abort(writer);
        return -1;
    }
    for (index = 0U; index < TEST_EXTENT_COUNT; ++index) {
        MetadataIndexExtent extent = {
            1000U + (uint64_t)index * 1000U,
            (uint64_t)index * 512U,
            512U
        };
        if (metadata_index_writer_append_extent(writer, &extent) != 0) {
            metadata_index_writer_abort(writer);
            return -1;
        }
    }
    {
        MetadataIndexExtent extent = { 0U, 0U, 200000000U };
        if (metadata_index_writer_append_extent(writer, &extent) != 0) {
            metadata_index_writer_abort(writer);
            return -1;
        }
    }
    return metadata_index_writer_commit(writer);
}

int main(void)
{
    char temp_template[] = "/tmp/carv-metadata-index-XXXXXX";
    char *temp_dir = NULL;
    char index_dir[PATH_MAX];
    MetadataIndexVolumeIdentity identity = {0};
    MetadataIndexVolumeIdentity stale_identity;
    MetadataIndexReader *reader = NULL;
    MetadataIndexPhysicalMatch match;
    MetadataIndexCandidateContext candidate_context;
    MetadataOutcomeStats outcome_stats;
    MetadataCandidateStats candidate_stats = {0};
    MetadataOutcomeRecord outcome_records[] = {
        {0U, "bin", "named"},
        {1000U, "jpg", "unresolved"},
        {150000000U, "jpg", "embedded"},
        {250000000U, "png", "unresolved"}
    };
    MetadataIndexObject object;
    MetadataIndexSequentialMeter *meter = NULL;
    MetadataIndexSequentialStats meter_stats;
    MetadataIndexLayoutFingerprint generation_one_layout = {0};
    MetadataIndexLayoutFingerprint generation_two_layout = {0};
    MetadataIndexFork fork_row;
    uint64_t first_physical = 0U;
    DeliveryState delivery = {0};
    size_t match_count = 0U;
    char path[256];
    char object_table[PATH_MAX];
    char outcome_path[PATH_MAX];
    char outcome_status_path[PATH_MAX];
    unsigned char saved_byte = 0U;
    unsigned char corrupt_byte;
    int corrupt_fd = -1;
    StopState stop_state = {0, 1U, 0};
    MetadataIndexWriterOptions stop_options = { stop_after_calls, NULL, NULL, &stop_state };
    MetadataIndexWriter *interrupted_writer = NULL;
    MetadataIndexWriter *invalid_writer = NULL;
    int temp_fd = -1;
    int result = 1;

    temp_fd = mkstemp(temp_template);
    CHECK(temp_fd >= 0);
    CHECK(close(temp_fd) == 0);
    temp_fd = -1;
    CHECK(unlink(temp_template) == 0);
    CHECK(mkdir(temp_template, 0700) == 0);
    temp_dir = temp_template;
    CHECK(snprintf(index_dir, sizeof(index_dir), "%s/index", temp_dir) <
          (int)sizeof(index_dir));

    identity.backend_kind = METADATA_INDEX_BACKEND_HFSPLUS;
    identity.block_size = 4096U;
    identity.source_size = 1000000U;
    identity.container_offset = 512U;
    identity.volume_offset = 1024U;
    identity.volume_size = 900000U;
    identity.identity_primary = 0x12345678U;
    identity.identity_secondary = 0xabcdefU;
    identity.uuid[0] = 0x42U;

    CHECK(build_first_generation(index_dir, &identity) == 0);
    CHECK(metadata_index_reader_open_expected(index_dir, &identity, &reader) == 0);
    CHECK(metadata_index_reader_generation(reader) == 1U);
    CHECK(metadata_index_reader_get_layout_fingerprint(
              reader, &generation_one_layout) == 0);
    CHECK(metadata_index_reader_reconstruct_path(reader, 10U, path, sizeof(path)) == 0);
    CHECK(strcmp(path, "/dir/photo.jpg") == 0);
    CHECK(metadata_index_reader_get_object(reader, 10U, &object) == 0);
    CHECK(object.object_key == 10U);
    CHECK(object.create_time == 1234U);
    CHECK(metadata_index_reader_get_object_by_row(reader, 2U, &object) == 0);
    CHECK(object.object_key == 10U);
    errno = 0;
    CHECK(metadata_index_reader_get_object_by_row(reader, 5U, &object) != 0);
    CHECK(errno == EINVAL);
    CHECK(metadata_index_reader_get_fork_by_row(reader, 0U, &fork_row) == 0);
    CHECK(fork_row.object_key == 10U);
    CHECK(metadata_index_reader_get_fork_first_physical(
              reader, 0U, &first_physical) == 0);
    CHECK(first_physical == 1000U);
    errno = 0;
    CHECK(metadata_index_reader_reconstruct_path(reader, 10U, path, 4U) != 0);
    CHECK(errno == ENOSPC);
    CHECK(metadata_index_reader_lookup_physical(reader, 1000U, &match, &match_count) == 1);
    CHECK(match_count == 2U);
    CHECK(metadata_index_reader_get_candidate_context(
              reader, 1000U, &candidate_context) == 1);
    CHECK(candidate_context.has_owner && candidate_context.owner_count == 2U);
    CHECK(!candidate_context.unique_owner && !candidate_context.complete_data_fork);
    CHECK(metadata_index_reader_get_candidate_context(
              reader, 0U, &candidate_context) == 1);
    CHECK(candidate_context.unique_owner && candidate_context.complete_data_fork);
    CHECK(candidate_context.exact_file_start &&
          candidate_context.best_match.object_key == 20U);
    CHECK(metadata_index_reader_get_candidate_context(
              reader, 150000000U, &candidate_context) == 1);
    CHECK(candidate_context.unique_owner && candidate_context.complete_data_fork);
    CHECK(!candidate_context.exact_file_start);
    CHECK(metadata_index_reader_get_candidate_context(
              reader, 250000000U, &candidate_context) == 0);
    CHECK(!candidate_context.has_owner && candidate_context.owner_count == 0U);
    CHECK(metadata_candidate_stats_note_offset(&candidate_stats, 100U) == 1);
    candidate_stats.no_owner++;
    CHECK(metadata_candidate_stats_note_offset(&candidate_stats, 100U) == 0);
    CHECK(metadata_candidate_stats_note_offset(&candidate_stats, 99U) == 0);
    CHECK(metadata_candidate_stats_note_offset(&candidate_stats, 101U) == 1);
    candidate_stats.trusted_exact_start++;
    CHECK(candidate_stats.lookups == 2U);
    CHECK(candidate_stats.high_water_offset == 101U);
    CHECK(metadata_candidate_stats_is_consistent(&candidate_stats));
    candidate_stats.lookup_failures++;
    CHECK(!metadata_candidate_stats_is_consistent(&candidate_stats));
    candidate_stats.lookup_failures--;
    candidate_stats.shared_with_dispatch = 3U;
    CHECK(!metadata_candidate_stats_is_consistent(&candidate_stats));
    candidate_stats.shared_with_dispatch = 1U;
    CHECK(metadata_outcome_write_artifacts(
              reader,
              temp_dir,
              "hfsplus",
              outcome_records,
              sizeof(outcome_records) / sizeof(outcome_records[0]),
              NULL,
              &outcome_stats) == 0);
    CHECK(outcome_stats.outputs == 4U);
    CHECK(outcome_stats.trusted_exact_start == 1U);
    CHECK(outcome_stats.ambiguous_owner == 1U);
    CHECK(outcome_stats.trusted_interior == 1U);
    CHECK(outcome_stats.no_owner == 1U);
    CHECK(outcome_stats.lookup_failures == 0U);
    CHECK(outcome_stats.named_outputs == 1U);
    CHECK(outcome_stats.unresolved_outputs == 2U);
    CHECK(outcome_stats.embedded_outputs == 1U);
    CHECK(snprintf(outcome_path, sizeof(outcome_path),
                   "%s/recovered_output_metadata.tsv", temp_dir) <
          (int)sizeof(outcome_path));
    CHECK(snprintf(outcome_status_path, sizeof(outcome_status_path),
                   "%s/recovered_output_metadata_status.txt", temp_dir) <
          (int)sizeof(outcome_status_path));
    CHECK(count_file_lines(outcome_path) == 5U);
    CHECK(file_contains_text(outcome_path, "0\tbin\tnamed\ttrusted_exact_start"));
    CHECK(file_contains_text(outcome_path, "1000\tjpg\tunresolved\tambiguous_owner"));
    CHECK(file_contains_text(outcome_path, "150000000\tjpg\tembedded\ttrusted_interior"));
    CHECK(file_contains_text(outcome_path, "250000000\tpng\tunresolved\tno_owner"));
    CHECK(file_contains_text(outcome_status_path, "artifact_rows=4"));
    CHECK(metadata_outcome_write_artifacts(
              reader,
              temp_dir,
              "hfsplus",
              outcome_records,
              sizeof(outcome_records) / sizeof(outcome_records[0]),
              NULL,
              &outcome_stats) == 0);
    CHECK(count_file_lines(outcome_path) == 5U);
    CHECK(metadata_index_reader_offset_has_object(reader, 1000U, 10U) == 1);
    CHECK(metadata_index_reader_offset_has_object(reader, 1000U, 20U) == 1);
    CHECK(metadata_index_reader_offset_has_object(reader, 1512U, 10U) == 0);
    CHECK(metadata_index_reader_offset_has_object(reader, 70000U, 10U) == 1);
    CHECK(metadata_index_reader_offset_has_object(
              reader,
              1000U + ((uint64_t)TEST_EXTENT_COUNT - 1U) * 1000U,
              10U) == 1);
    CHECK(metadata_index_sequential_meter_create(reader, &meter) == 0);
    CHECK(metadata_index_sequential_meter_observe(meter, 0U, 200000000U) == 0);
    CHECK(metadata_index_sequential_meter_observe(meter, 0U, 4096U) == 0);
    metadata_index_sequential_meter_get_stats(meter, &meter_stats);
    CHECK(meter_stats.source_bytes_observed == 200000000U);
    CHECK(meter_stats.duplicate_or_backward_ranges == 1U);
    CHECK(meter_stats.extents_total == TEST_EXTENT_COUNT + 1U);
    CHECK(meter_stats.extents_complete == TEST_EXTENT_COUNT + 1U);
    CHECK(meter_stats.forks_total == 3U);
    CHECK(meter_stats.forks_complete == 3U);
    CHECK(meter_stats.forks_empty_complete == 1U);
    CHECK(meter_stats.forks_incomplete_runlist == 0U);
    CHECK(meter_stats.extent_delivery_bytes ==
          200000000U + (uint64_t)TEST_EXTENT_COUNT * 512U);
    metadata_index_sequential_meter_destroy(meter);
    meter = NULL;
    CHECK(metadata_index_sequential_meter_create(reader, &meter) == 0);
    CHECK(metadata_index_sequential_meter_observe(meter, 1000U, 1512U) == 0);
    metadata_index_sequential_meter_get_stats(meter, &meter_stats);
    CHECK(meter_stats.source_gap_bytes == 1000U);
    CHECK(meter_stats.source_bytes_observed == 512U);
    CHECK(meter_stats.extents_complete == 1U);
    CHECK(meter_stats.forks_complete == 1U);
    metadata_index_sequential_meter_destroy(meter);
    meter = NULL;
    CHECK(metadata_index_sequential_meter_create(reader, &meter) == 0);
    CHECK(metadata_index_sequential_meter_observe_with_delivery(
              meter, 1000U, 1512U, note_delivery, &delivery) == 0);
    CHECK(delivery.calls == 2U);
    CHECK(delivery.bytes == 1024U);
    CHECK(delivery.first_object != 0U);
    CHECK(delivery.first_physical_row < TEST_EXTENT_COUNT + 1U);
    metadata_index_sequential_meter_destroy(meter);
    meter = NULL;
    metadata_index_reader_close(reader);
    reader = NULL;

    CHECK(snprintf(
              object_table,
              sizeof(object_table),
              "%s/g000001/objects.bin",
              index_dir) < (int)sizeof(object_table));
    corrupt_fd = open(object_table, O_RDWR);
    CHECK(corrupt_fd >= 0);
    CHECK(lseek(corrupt_fd, 64, SEEK_SET) == 64);
    CHECK(read(corrupt_fd, &saved_byte, 1U) == 1);
    corrupt_byte = (unsigned char)(saved_byte ^ 0x5aU);
    CHECK(lseek(corrupt_fd, 64, SEEK_SET) == 64);
    CHECK(write(corrupt_fd, &corrupt_byte, 1U) == 1);
    CHECK(close(corrupt_fd) == 0);
    corrupt_fd = -1;
    CHECK(metadata_index_reader_open_expected(index_dir, &identity, &reader) != 0);
    corrupt_fd = open(object_table, O_RDWR);
    CHECK(corrupt_fd >= 0);
    CHECK(lseek(corrupt_fd, 64, SEEK_SET) == 64);
    CHECK(write(corrupt_fd, &saved_byte, 1U) == 1);
    CHECK(close(corrupt_fd) == 0);
    corrupt_fd = -1;
    CHECK(metadata_index_reader_open_expected(index_dir, &identity, &reader) == 0);
    metadata_index_reader_close(reader);
    metadata_index_sequential_meter_destroy(meter);
    reader = NULL;

    stale_identity = identity;
    stale_identity.identity_secondary++;
    errno = 0;
    CHECK(metadata_index_reader_open_expected(index_dir, &stale_identity, &reader) != 0);
    CHECK(errno == ESTALE);

    CHECK(metadata_index_writer_create(index_dir, &identity, &invalid_writer) == 0);
    {
        MetadataIndexObject object = {0};
        object.object_key = 2U;
        object.best_link_row = 0U;
        object.first_fork_row = METADATA_INDEX_NO_ROW;
        object.flags = METADATA_INDEX_OBJECT_FLAG_DIRECTORY |
            METADATA_INDEX_OBJECT_FLAG_ROOT;
        CHECK(metadata_index_writer_append_object(invalid_writer, &object) == 0);
        CHECK(append_name(invalid_writer, 1U, 99U, 0U, "") == 0);
        CHECK(metadata_index_writer_commit(invalid_writer) != 0);
        invalid_writer = NULL;
    }
    CHECK(metadata_index_reader_open_expected(index_dir, &identity, &reader) == 0);
    CHECK(metadata_index_reader_generation(reader) == 1U);
    metadata_index_reader_close(reader);
    reader = NULL;

    CHECK(metadata_index_writer_create_with_options(
              index_dir,
              &identity,
              &stop_options,
              &interrupted_writer) == 0);
    stop_state.armed = 1;
    {
        MetadataIndexObject object = {0};
        object.object_key = 2U;
        object.best_link_row = METADATA_INDEX_NO_ROW;
        object.first_fork_row = METADATA_INDEX_NO_ROW;
        CHECK(metadata_index_writer_append_object(interrupted_writer, &object) != 0);
        CHECK(errno == ECANCELED);
    }
    metadata_index_writer_abort(interrupted_writer);
    interrupted_writer = NULL;
    CHECK(metadata_index_reader_open_expected(index_dir, &identity, &reader) == 0);
    CHECK(metadata_index_reader_generation(reader) == 1U);

    metadata_index_reader_close(reader);
    reader = NULL;
    CHECK(build_first_generation(index_dir, &identity) == 0);
    CHECK(metadata_index_reader_open_expected(index_dir, &identity, &reader) == 0);
    CHECK(metadata_index_reader_generation(reader) == 2U);
    CHECK(metadata_index_reader_get_layout_fingerprint(
              reader, &generation_two_layout) == 0);
    CHECK(memcmp(&generation_one_layout, &generation_two_layout,
                 sizeof(generation_one_layout)) == 0);
    metadata_index_reader_close(reader);
    reader = NULL;
    CHECK(metadata_index_reader_open_generation(index_dir, 1U, &reader) == 0);
    CHECK(metadata_index_reader_generation(reader) == 1U);
    CHECK(metadata_index_reader_get_layout_fingerprint(
              reader, &generation_two_layout) == 0);
    CHECK(memcmp(&generation_one_layout, &generation_two_layout,
                 sizeof(generation_one_layout)) == 0);

    result = 0;
cleanup:
    if (corrupt_fd >= 0) close(corrupt_fd);
    if (temp_fd >= 0) close(temp_fd);
    metadata_index_reader_close(reader);
    metadata_index_writer_abort(interrupted_writer);
    metadata_index_writer_abort(invalid_writer);
    if (temp_dir != NULL && remove_test_tree(temp_dir) != 0 && result == 0) {
        fprintf(stderr, "metadata-index test cleanup failed: errno=%d\n", errno);
        result = 1;
    }
    if (result == 0) printf("metadata-index checks passed\n");
    return result;
}
