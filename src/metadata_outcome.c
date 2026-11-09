#include "metadata_outcome.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

int metadata_candidate_stats_note_offset(
    MetadataCandidateStats *stats,
    uint64_t physical_offset)
{
    if (stats == NULL) return 0;
    if (stats->high_water_valid &&
        physical_offset <= stats->high_water_offset) {
        return 0;
    }
    stats->high_water_offset = physical_offset;
    stats->high_water_valid = 1;
    stats->lookups++;
    return 1;
}

int metadata_candidate_stats_is_consistent(const MetadataCandidateStats *stats)
{
    if (stats == NULL) return 0;
    return stats->lookups ==
               stats->lookup_failures + stats->no_owner +
               stats->ambiguous_owner + stats->non_data_owner +
               stats->incomplete_owner +
               stats->trusted_exact_start + stats->trusted_interior &&
           stats->shared_with_dispatch <= stats->lookups &&
           (stats->lookups == 0U || stats->high_water_valid);
}

static void write_tsv_text(FILE *file, const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;

    if (file == NULL || cursor == NULL) return;
    while (*cursor != '\0') {
        unsigned char ch = *cursor++;
        fputc((ch == '\t' || ch == '\r' || ch == '\n') ? ' ' : (int)ch, file);
    }
}

static const char *metadata_class_label(
    int lookup_result,
    const MetadataIndexCandidateContext *context)
{
    if (lookup_result < 0 || context == NULL) return "lookup_failure";
    if (lookup_result == 0 || !context->has_owner) return "no_owner";
    if (!context->unique_owner) return "ambiguous_owner";
    if (context->fork.fork_kind != METADATA_INDEX_FORK_DATA) {
        return "non_data_owner";
    }
    if (!context->complete_data_fork) return "incomplete_owner";
    if (context->exact_file_start) return "trusted_exact_start";
    return "trusted_interior";
}

static void count_metadata_class(
    MetadataOutcomeStats *stats,
    const char *classification)
{
    if (strcmp(classification, "lookup_failure") == 0) stats->lookup_failures++;
    else if (strcmp(classification, "no_owner") == 0) stats->no_owner++;
    else if (strcmp(classification, "ambiguous_owner") == 0) stats->ambiguous_owner++;
    else if (strcmp(classification, "non_data_owner") == 0) stats->non_data_owner++;
    else if (strcmp(classification, "incomplete_owner") == 0) stats->incomplete_owner++;
    else if (strcmp(classification, "trusted_exact_start") == 0) stats->trusted_exact_start++;
    else if (strcmp(classification, "trusted_interior") == 0) stats->trusted_interior++;
}

static void count_output_kind(MetadataOutcomeStats *stats, const char *kind)
{
    if (kind != NULL && strcmp(kind, "embedded") == 0) stats->embedded_outputs++;
    else if (kind != NULL && strcmp(kind, "named") == 0) stats->named_outputs++;
    else stats->unresolved_outputs++;
}

static int write_status(
    const MetadataIndexReader *reader,
    const char *metadata_dir,
    const char *backend_id,
    const MetadataOutcomeStats *stats,
    MetadataOutcomeOpenFileFn open_file)
{
    char path[PATH_MAX];
    char temp_path[PATH_MAX + 32];
    FILE *file;

    if (snprintf(path, sizeof(path),
                 "%s/recovered_output_metadata_status.txt", metadata_dir) >=
            (int)sizeof(path) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >=
            (int)sizeof(temp_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    file = open_file != NULL ? open_file(temp_path, "w") : fopen(temp_path, "w");
    if (file == NULL) return -1;
    fprintf(file, "format_version=1\n");
    fprintf(file, "backend=%s\n", backend_id);
    fprintf(file, "status=ready\n");
    fprintf(file, "origin=recovered_outputs\n");
    fprintf(file, "policy_effect=none\n");
    fprintf(file, "generation=%llu\n",
            (unsigned long long)metadata_index_reader_generation(reader));
    fprintf(file, "outputs=%llu\n", (unsigned long long)stats->outputs);
    fprintf(file, "lookup_failures=%llu\n",
            (unsigned long long)stats->lookup_failures);
    fprintf(file, "no_owner=%llu\n", (unsigned long long)stats->no_owner);
    fprintf(file, "ambiguous_owner=%llu\n",
            (unsigned long long)stats->ambiguous_owner);
    fprintf(file, "non_data_owner=%llu\n",
            (unsigned long long)stats->non_data_owner);
    fprintf(file, "incomplete_owner=%llu\n",
            (unsigned long long)stats->incomplete_owner);
    fprintf(file, "trusted_exact_start=%llu\n",
            (unsigned long long)stats->trusted_exact_start);
    fprintf(file, "trusted_interior=%llu\n",
            (unsigned long long)stats->trusted_interior);
    fprintf(file, "named_outputs=%llu\n",
            (unsigned long long)stats->named_outputs);
    fprintf(file, "unresolved_outputs=%llu\n",
            (unsigned long long)stats->unresolved_outputs);
    fprintf(file, "embedded_outputs=%llu\n",
            (unsigned long long)stats->embedded_outputs);
    fprintf(file, "artifact_rows=%llu\n", (unsigned long long)stats->outputs);
    fprintf(file, "artifact_bytes=%llu\n",
            (unsigned long long)stats->artifact_bytes);
    fprintf(file, "artifact=recovered_output_metadata.tsv\n");
    fprintf(file, "join_key=offset\n");
    fprintf(file, "updated_unix=%llu\n", (unsigned long long)time(NULL));
    if (fclose(file) != 0) {
        (void)unlink(temp_path);
        return -1;
    }
    if (rename(temp_path, path) != 0) {
        (void)unlink(temp_path);
        return -1;
    }
    (void)chmod(path, 0644);
    return 0;
}

int metadata_outcome_write_artifacts(
    const MetadataIndexReader *reader,
    const char *metadata_dir,
    const char *backend_id,
    const MetadataOutcomeRecord *records,
    size_t record_count,
    MetadataOutcomeOpenFileFn open_file,
    MetadataOutcomeStats *stats_out)
{
    MetadataOutcomeStats stats = {0};
    char path[PATH_MAX];
    char temp_path[PATH_MAX + 32];
    struct stat artifact_stat;
    FILE *file;
    size_t index;

    if (stats_out != NULL) memset(stats_out, 0, sizeof(*stats_out));
    if (reader == NULL || metadata_dir == NULL || metadata_dir[0] == '\0' ||
        backend_id == NULL || backend_id[0] == '\0' ||
        (record_count > 0U && records == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (snprintf(path, sizeof(path), "%s/recovered_output_metadata.tsv",
                 metadata_dir) >= (int)sizeof(path) ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >=
            (int)sizeof(temp_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    file = open_file != NULL ? open_file(temp_path, "w") : fopen(temp_path, "w");
    if (file == NULL) return -1;
    fprintf(
        file,
        "offset\tformat\toutput_kind\tmetadata_class\towner_count\tobject_key\tfork_row\tlogical_position\tlogical_size\n"
    );
    for (index = 0U; index < record_count; ++index) {
        MetadataIndexCandidateContext context = {0};
        const char *classification;
        int lookup_result = metadata_index_reader_get_candidate_context(
            reader,
            records[index].physical_offset,
            &context);

        classification = metadata_class_label(lookup_result, &context);
        stats.outputs++;
        count_metadata_class(&stats, classification);
        count_output_kind(&stats, records[index].output_kind);
        fprintf(file, "%llu\t",
                (unsigned long long)records[index].physical_offset);
        write_tsv_text(file, records[index].format != NULL ? records[index].format : "");
        fputc('\t', file);
        write_tsv_text(file, records[index].output_kind != NULL
            ? records[index].output_kind : "unresolved");
        fprintf(file, "\t%s\t%llu\t%llu\t%u\t%llu\t%llu\n",
                classification,
                (unsigned long long)context.owner_count,
                (unsigned long long)context.best_match.object_key,
                context.best_match.fork_row,
                (unsigned long long)context.best_match.logical_position,
                (unsigned long long)context.fork.logical_size);
    }
    {
        int write_failed = ferror(file) != 0;
        if (fclose(file) != 0) write_failed = 1;
        if (write_failed) {
            (void)unlink(temp_path);
            return -1;
        }
    }
    if (rename(temp_path, path) != 0) {
        (void)unlink(temp_path);
        return -1;
    }
    (void)chmod(path, 0644);
    memset(&artifact_stat, 0, sizeof(artifact_stat));
    if (stat(path, &artifact_stat) == 0 && artifact_stat.st_size >= 0) {
        stats.artifact_bytes = (uint64_t)artifact_stat.st_size;
    }
    if (write_status(reader, metadata_dir, backend_id, &stats, open_file) != 0) return -1;
    if (stats_out != NULL) *stats_out = stats;
    return 0;
}
