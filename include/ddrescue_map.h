#ifndef DDRESCUE_MAP_H
#define DDRESCUE_MAP_H

#include <stddef.h>
#include <stdint.h>

typedef struct DdrescueMapRange {
    uint64_t start;
    uint64_t end;
    char status;
} DdrescueMapRange;

typedef struct DdrescueMap {
    DdrescueMapRange *ranges;
    size_t count;
    size_t capacity;
} DdrescueMap;

int ddrescue_map_load(const char *path, DdrescueMap *map);
void ddrescue_map_reset(DdrescueMap *map);

/*
 * Return the status covering offset and the first byte after that status
 * span. Bytes absent from a map are reported as '?' up to the next row.
 */
int ddrescue_map_status_span(
    const DdrescueMap *map,
    uint64_t offset,
    char *out_status,
    uint64_t *out_end
);

uint64_t ddrescue_map_finished_bytes(
    const DdrescueMap *map,
    uint64_t start,
    uint64_t length
);

int ddrescue_map_range_is_finished(
    const DdrescueMap *map,
    uint64_t start,
    uint64_t length
);

int ddrescue_map_find_finished_range(
    const DdrescueMap *map,
    uint64_t search_start,
    uint64_t search_length,
    uint64_t minimum_length,
    uint64_t *out_start,
    uint64_t *out_length
);

#endif
