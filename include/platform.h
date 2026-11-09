/*
 * platform.h
 * Detects the current operating system platform.
 */

#ifndef PLATFORM_H
#define PLATFORM_H

#include <stdint.h>

typedef struct {
    const char *name;
    int is_macos;
    int is_linux;
} PlatformInfo;

typedef struct {
    uint64_t resident_bytes;
    uint64_t footprint_bytes;
    uint64_t peak_rss_bytes;
    int has_resident;
    int has_footprint;
    int has_peak_rss;
} PlatformMemoryUsage;

typedef struct {
    uint64_t total_bytes;
    uint64_t available_bytes;
    int has_total;
    int has_available;
} PlatformSystemMemory;

typedef struct {
    PlatformMemoryUsage memory;
    double user_cpu_seconds;
    double system_cpu_seconds;
    double total_cpu_seconds;
    double io_wait_seconds;
    int has_cpu;
    int has_io_wait;
} PlatformProcessResourceUsage;

int platform_detect(PlatformInfo *platform);
int platform_get_process_memory_usage(PlatformMemoryUsage *usage);
int platform_get_process_resource_usage(PlatformProcessResourceUsage *usage);
int platform_get_system_memory(PlatformSystemMemory *memory);
int platform_get_free_space_bytes(const char *path, uint64_t *available_bytes);

#endif
