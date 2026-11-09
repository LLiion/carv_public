#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif

#include "scan_state.h"
#include "fs_backend.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int fs_backend_output_path_write_guard_allows(const char *path)
{
    return path != NULL && path[0] != '\0';
}

FILE *fs_backend_fopen_output_write_guarded(const char *path, const char *mode)
{
    return fopen(path, mode);
}

int main(void)
{
    char temp_dir[] = "/tmp/carv-scan-state-XXXXXX";
    char state_dir[512];
    char state_path[640];
    ScanState state = {0};

    assert(mkdtemp(temp_dir) != NULL);
    assert(snprintf(state_dir, sizeof(state_dir), "%s/state", temp_dir) <
           (int)sizeof(state_dir));
    assert(mkdir(state_dir, 0700) == 0);
    assert(snprintf(
               state_path,
               sizeof(state_path),
               "%s/scan_state.txt",
               state_dir) < (int)sizeof(state_path));

    assert(scan_state_write(
        state_path,
        "/dev/test-hfs",
        "all",
        4096ULL,
        2048ULL,
        0,
        0));

    /* A post-scan worker with a temporarily unknown device size must retain
     * the known boundary for the same source and mode. */
    assert(scan_state_write(
        state_path,
        "/dev/test-hfs",
        "all",
        0ULL,
        4096ULL,
        1,
        1));
    assert(scan_state_load(state_path, &state));
    assert(state.source_size == 4096ULL);
    assert(state.scan_offset == 4096ULL);
    assert(state.scan_completed == 1);
    assert(state.completed == 1);

    /* Never carry that size into a genuinely different source identity. */
    assert(scan_state_write(
        state_path,
        "/dev/another-source",
        "all",
        0ULL,
        123ULL,
        0,
        0));
    memset(&state, 0, sizeof(state));
    assert(scan_state_load(state_path, &state));
    assert(state.source_size == 0ULL);
    assert(state.scan_offset == 123ULL);

    assert(unlink(state_path) == 0);
    assert(rmdir(state_dir) == 0);
    assert(rmdir(temp_dir) == 0);
    puts("scan-state source-size preservation checks passed");
    return 0;
}
