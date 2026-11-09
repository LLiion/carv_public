#include "metadata_index.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    MetadataIndexReader *reader = NULL;
    MetadataIndexStats stats;
    uint64_t row;

    if (argc != 2) {
        fprintf(stderr, "usage: %s <state/metadata/index>\n", argv[0]);
        return 2;
    }
    if (metadata_index_reader_open(argv[1], &reader) != 0 || reader == NULL) {
        perror("metadata_index_reader_open");
        return 1;
    }

    metadata_index_reader_get_stats(reader, &stats);
    puts("extent_count\tlogical_size\tobject_key\tpath");
    for (row = 0U; row < stats.fork_count; row++) {
        MetadataIndexFork fork;
        char path[4096];

        if (metadata_index_reader_get_fork_by_row(reader, (uint32_t)row, &fork) != 0 ||
            fork.fork_kind != METADATA_INDEX_FORK_DATA ||
            metadata_index_reader_reconstruct_path(
                reader,
                fork.object_key,
                path,
                sizeof(path)) != 0) {
            continue;
        }
        printf(
            "%" PRIu32 "\t%" PRIu64 "\t%" PRIu64 "\t%s\n",
            fork.extent_count,
            fork.logical_size,
            fork.object_key,
            path
        );
    }

    metadata_index_reader_close(reader);
    return 0;
}
