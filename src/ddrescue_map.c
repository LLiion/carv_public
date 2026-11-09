#define _POSIX_C_SOURCE 200809L

#include "ddrescue_map.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int status_is_known(char status)
{
    return status == '?' || status == '*' || status == '/' ||
           status == '-' || status == '+';
}

static int parse_u64(const char *text, uint64_t *out)
{
    unsigned long long value;
    char *end = NULL;

    if (text == NULL || text[0] == '\0' || out == NULL) {
        return 0;
    }
    errno = 0;
    value = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        return 0;
    }
    *out = (uint64_t)value;
    return 1;
}

static int range_order(const void *left, const void *right)
{
    const DdrescueMapRange *a = (const DdrescueMapRange *)left;
    const DdrescueMapRange *b = (const DdrescueMapRange *)right;

    if (a->start < b->start) return -1;
    if (a->start > b->start) return 1;
    if (a->end < b->end) return -1;
    if (a->end > b->end) return 1;
    return 0;
}

static int append_range(
    DdrescueMap *map,
    uint64_t start,
    uint64_t length,
    char status
)
{
    DdrescueMapRange *expanded;
    size_t new_capacity;

    if (map == NULL || length == 0U || !status_is_known(status) ||
        start > UINT64_MAX - length) {
        return 0;
    }
    if (map->count == map->capacity) {
        new_capacity = map->capacity == 0U ? 64U : map->capacity * 2U;
        if (new_capacity <= map->capacity ||
            new_capacity > SIZE_MAX / sizeof(*expanded)) {
            return 0;
        }
        expanded = (DdrescueMapRange *)realloc(
            map->ranges,
            new_capacity * sizeof(*expanded)
        );
        if (expanded == NULL) {
            return 0;
        }
        map->ranges = expanded;
        map->capacity = new_capacity;
    }
    map->ranges[map->count].start = start;
    map->ranges[map->count].end = start + length;
    map->ranges[map->count].status = status;
    map->count++;
    return 1;
}

int ddrescue_map_load(const char *path, DdrescueMap *map)
{
    FILE *file;
    char line[512];
    DdrescueMap loaded = {0};

    if (path == NULL || path[0] == '\0' || map == NULL) {
        return 0;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char start_text[96];
        char size_text[96];
        char status_text[16];
        uint64_t start;
        uint64_t length;

        if (line[0] == '#' ||
            sscanf(line, "%95s %95s %15s", start_text, size_text, status_text) != 3 ||
            status_text[1] != '\0' ||
            !status_is_known(status_text[0]) ||
            !parse_u64(start_text, &start) ||
            !parse_u64(size_text, &length)) {
            continue;
        }
        if (!append_range(&loaded, start, length, status_text[0])) {
            fclose(file);
            ddrescue_map_reset(&loaded);
            return 0;
        }
    }
    if (ferror(file) || fclose(file) != 0 || loaded.count == 0U) {
        ddrescue_map_reset(&loaded);
        return 0;
    }
    qsort(loaded.ranges, loaded.count, sizeof(*loaded.ranges), range_order);
    ddrescue_map_reset(map);
    *map = loaded;
    return 1;
}

void ddrescue_map_reset(DdrescueMap *map)
{
    if (map == NULL) {
        return;
    }
    free(map->ranges);
    memset(map, 0, sizeof(*map));
}

int ddrescue_map_status_span(
    const DdrescueMap *map,
    uint64_t offset,
    char *out_status,
    uint64_t *out_end
)
{
    size_t low = 0U;
    size_t high;
    size_t candidate;

    if (map == NULL || out_status == NULL || out_end == NULL) {
        return 0;
    }
    high = map->count;
    while (low < high) {
        size_t mid = low + (high - low) / 2U;

        if (map->ranges[mid].start <= offset) {
            low = mid + 1U;
        } else {
            high = mid;
        }
    }
    if (low > 0U) {
        candidate = low - 1U;
        if (offset >= map->ranges[candidate].start &&
            offset < map->ranges[candidate].end) {
            *out_status = map->ranges[candidate].status;
            *out_end = map->ranges[candidate].end;
            return 1;
        }
    }
    *out_status = '?';
    *out_end = low < map->count ? map->ranges[low].start : UINT64_MAX;
    if (*out_end <= offset) {
        *out_end = UINT64_MAX;
    }
    return 1;
}

uint64_t ddrescue_map_finished_bytes(
    const DdrescueMap *map,
    uint64_t start,
    uint64_t length
)
{
    uint64_t finish;
    uint64_t cursor;
    uint64_t total = 0U;

    if (map == NULL || length == 0U || start > UINT64_MAX - length) {
        return 0U;
    }
    finish = start + length;
    cursor = start;
    while (cursor < finish) {
        char status;
        uint64_t span_end;
        uint64_t clipped_end;

        if (!ddrescue_map_status_span(map, cursor, &status, &span_end)) {
            break;
        }
        clipped_end = span_end < finish ? span_end : finish;
        if (clipped_end <= cursor) {
            break;
        }
        if (status == '+') {
            total += clipped_end - cursor;
        }
        cursor = clipped_end;
    }
    return total;
}

int ddrescue_map_range_is_finished(
    const DdrescueMap *map,
    uint64_t start,
    uint64_t length
)
{
    return length > 0U &&
           ddrescue_map_finished_bytes(map, start, length) == length;
}

int ddrescue_map_find_finished_range(
    const DdrescueMap *map,
    uint64_t search_start,
    uint64_t search_length,
    uint64_t minimum_length,
    uint64_t *out_start,
    uint64_t *out_length
)
{
    uint64_t search_end;
    size_t i;

    if (out_start != NULL) *out_start = 0U;
    if (out_length != NULL) *out_length = 0U;
    if (map == NULL || out_start == NULL || out_length == NULL ||
        search_length == 0U || minimum_length == 0U ||
        search_start > UINT64_MAX - search_length) {
        return 0;
    }
    search_end = search_start + search_length;
    for (i = 0U; i < map->count; ++i) {
        uint64_t start;
        uint64_t end;

        if (map->ranges[i].status != '+' ||
            map->ranges[i].end <= search_start ||
            map->ranges[i].start >= search_end) {
            continue;
        }
        start = map->ranges[i].start > search_start
            ? map->ranges[i].start : search_start;
        end = map->ranges[i].end < search_end
            ? map->ranges[i].end : search_end;
        if (end > start && end - start >= minimum_length) {
            *out_start = start;
            *out_length = end - start;
            return 1;
        }
    }
    return 0;
}
