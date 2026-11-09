/*
 * platform.c
 * Small platform abstraction layer for:
 * - compile-time platform detection
 * - process/system memory snapshots
 * - free-space queries
 *
 * The Linux memory path also tries to respect container/cgroup limits so
 * the rest of the program gets a more realistic working budget.
 */

#include "platform.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <unistd.h>

#if defined(__APPLE__) && defined(__MACH__)
#include <mach/mach.h>
#include <mach/mach_host.h>
#elif defined(__linux__)
#include <sys/sysinfo.h>
#endif

#if defined(__linux__)
static void trim_trailing_newlines(char *text)
{
    size_t length;

    if (text == NULL) {
        return;
    }

    length = strlen(text);
    while (length > 0U &&
           (text[length - 1U] == '\n' || text[length - 1U] == '\r')) {
        text[length - 1U] = '\0';
        length--;
    }
}

static int read_first_line(const char *path, char *buffer, size_t buffer_size)
{
    FILE *file;

    if (path == NULL || buffer == NULL || buffer_size == 0U) {
        return 0;
    }

    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }

    if (fgets(buffer, (int)buffer_size, file) == NULL) {
        fclose(file);
        return 0;
    }

    fclose(file);
    trim_trailing_newlines(buffer);
    return 1;
}

static int parse_u64_text(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed = 0ULL;

    if (text == NULL || value == NULL || text[0] == '\0') {
        return 0;
    }

    parsed = strtoull(text, &end, 10);
    if (end == text || (end != NULL && *end != '\0')) {
        return 0;
    }

    *value = (uint64_t)parsed;
    return 1;
}

static int read_u64_file(const char *path, uint64_t *value)
{
    char buffer[128];

    if (!read_first_line(path, buffer, sizeof(buffer))) {
        return 0;
    }

    return parse_u64_text(buffer, value);
}

static int read_proc_meminfo_value_bytes(const char *key, uint64_t *value)
{
    FILE *file;
    char line[256];
    size_t key_length;

    if (key == NULL || value == NULL) {
        return 0;
    }

    file = fopen("/proc/meminfo", "r");
    if (file == NULL) {
        return 0;
    }

    key_length = strlen(key);
    while (fgets(line, sizeof(line), file) != NULL) {
        char *cursor;
        char *end = NULL;
        unsigned long long kib_value = 0ULL;

        if (strncmp(line, key, key_length) != 0) {
            continue;
        }

        cursor = line + key_length;
        while (*cursor == ' ' || *cursor == '\t') {
            cursor++;
        }

        kib_value = strtoull(cursor, &end, 10);
        if (end == cursor) {
            fclose(file);
            return 0;
        }

        while (end != NULL && (*end == ' ' || *end == '\t')) {
            end++;
        }
        if (end != NULL && *end != '\0' && strncmp(end, "kB", 2) != 0) {
            fclose(file);
            return 0;
        }

        *value = (uint64_t)kib_value * 1024ULL;
        fclose(file);
        return 1;
    }

    fclose(file);
    return 0;
}

static int path_join_cgroup(
    char *buffer,
    size_t buffer_size,
    const char *mount_root,
    const char *relative_path,
    const char *suffix
)
{
    int needed;

    if (buffer == NULL || buffer_size == 0U ||
        mount_root == NULL || suffix == NULL) {
        return 0;
    }

    if (relative_path == NULL || relative_path[0] == '\0' ||
        strcmp(relative_path, "/") == 0) {
        needed = snprintf(buffer, buffer_size, "%s%s", mount_root, suffix);
    } else {
        needed = snprintf(buffer, buffer_size, "%s%s%s", mount_root, relative_path, suffix);
    }

    return needed > 0 && (size_t)needed < buffer_size;
}

static int linux_get_cgroup_relative_paths(
    char *v2_path,
    size_t v2_size,
    char *v1_memory_path,
    size_t v1_size
)
{
    FILE *file;
    char line[512];

    if (v2_path != NULL && v2_size > 0U) {
        v2_path[0] = '\0';
    }
    if (v1_memory_path != NULL && v1_size > 0U) {
        v1_memory_path[0] = '\0';
    }

    file = fopen("/proc/self/cgroup", "r");
    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *first_colon = strchr(line, ':');
        char *second_colon;
        char *controllers;
        char *path;

        if (first_colon == NULL) {
            continue;
        }
        second_colon = strchr(first_colon + 1, ':');
        if (second_colon == NULL) {
            continue;
        }

        *first_colon = '\0';
        *second_colon = '\0';
        controllers = first_colon + 1;
        path = second_colon + 1;
        trim_trailing_newlines(path);

        if (controllers[0] == '\0') {
            if (v2_path != NULL && v2_size > 0U) {
                snprintf(v2_path, v2_size, "%s", path);
            }
            continue;
        }

        if (strstr(controllers, "memory") != NULL) {
            if (v1_memory_path != NULL && v1_size > 0U) {
                snprintf(v1_memory_path, v1_size, "%s", path);
            }
        }
    }

    fclose(file);
    return 1;
}

static int linux_apply_cgroup_memory_limits(PlatformSystemMemory *memory)
{
    char v2_relpath[256];
    char v1_relpath[256];
    char path[PATH_MAX];
    uint64_t limit_bytes = 0ULL;
    uint64_t used_bytes = 0ULL;
    uint64_t remaining_bytes = 0ULL;
    int have_limit = 0;
    int have_used = 0;
    char buffer[128];

    if (memory == NULL) {
        return 0;
    }

    linux_get_cgroup_relative_paths(
        v2_relpath, sizeof(v2_relpath),
        v1_relpath, sizeof(v1_relpath)
    );

    if (path_join_cgroup(path, sizeof(path), "/sys/fs/cgroup", v2_relpath, "/memory.max") &&
        read_first_line(path, buffer, sizeof(buffer)) &&
        strcmp(buffer, "max") != 0 &&
        parse_u64_text(buffer, &limit_bytes) &&
        limit_bytes > 0ULL) {
        have_limit = 1;
        if (path_join_cgroup(path, sizeof(path), "/sys/fs/cgroup", v2_relpath, "/memory.current") &&
            read_u64_file(path, &used_bytes)) {
            have_used = 1;
        }
    } else if (
        path_join_cgroup(path, sizeof(path), "/sys/fs/cgroup/memory", v1_relpath, "/memory.limit_in_bytes") &&
        read_u64_file(path, &limit_bytes) &&
        limit_bytes > 0ULL) {
        uint64_t absurd_limit = 1ULL << 60;

        if (limit_bytes < absurd_limit) {
            have_limit = 1;
            if (path_join_cgroup(path, sizeof(path), "/sys/fs/cgroup/memory", v1_relpath, "/memory.usage_in_bytes") &&
                read_u64_file(path, &used_bytes)) {
                have_used = 1;
            }
        }
    }

    if (!have_limit) {
        return 0;
    }

    if (!memory->has_total || limit_bytes < memory->total_bytes) {
        memory->total_bytes = limit_bytes;
        memory->has_total = 1;
    }

    if (have_used) {
        remaining_bytes = used_bytes >= limit_bytes ? 0ULL : (limit_bytes - used_bytes);
        if (!memory->has_available || remaining_bytes < memory->available_bytes) {
            memory->available_bytes = remaining_bytes;
            memory->has_available = 1;
        }
    }

    return 1;
}
#endif

int platform_detect(PlatformInfo *platform)
{
    if (platform == NULL) {
        return 0;
    }

    platform->name = "Unknown";
    platform->is_macos = 0;
    platform->is_linux = 0;

#if defined(__APPLE__) && defined(__MACH__)
    platform->name = "macOS";
    platform->is_macos = 1;
    return 1;
#elif defined(__linux__)
    platform->name = "Linux";
    platform->is_linux = 1;
    return 1;
#else
    return 0;
#endif
}

#if defined(__APPLE__) && defined(__MACH__)
static int platform_get_process_memory_usage_macos(PlatformMemoryUsage *usage)
{
    int have_any = 0;

    {
        mach_task_basic_info_data_t basic_info;
        mach_msg_type_number_t basic_count = MACH_TASK_BASIC_INFO_COUNT;

        if (task_info(
                mach_task_self(),
                MACH_TASK_BASIC_INFO,
                (task_info_t)&basic_info,
                &basic_count) == KERN_SUCCESS) {
            usage->resident_bytes = (uint64_t)basic_info.resident_size;
            usage->has_resident = 1;
            have_any = 1;
        }
    }
    {
        task_vm_info_data_t vm_info;
        mach_msg_type_number_t vm_count = TASK_VM_INFO_COUNT;

        if (task_info(
                mach_task_self(),
                TASK_VM_INFO,
                (task_info_t)&vm_info,
                &vm_count) == KERN_SUCCESS) {
            usage->footprint_bytes = (uint64_t)vm_info.phys_footprint;
            usage->has_footprint = 1;
            have_any = 1;
        }
    }
    return have_any;
}
#endif

#if defined(__linux__)
static int platform_get_process_memory_usage_linux(PlatformMemoryUsage *usage)
{
    int have_any = 0;

    {
        FILE *file = fopen("/proc/self/statm", "r");

        if (file != NULL) {
            unsigned long long total_pages = 0ULL;
            unsigned long long resident_pages = 0ULL;
            long page_size = sysconf(_SC_PAGESIZE);

            if (page_size > 0 &&
                fscanf(file, "%llu %llu", &total_pages, &resident_pages) == 2) {
                (void)total_pages;
                usage->resident_bytes = (uint64_t)resident_pages * (uint64_t)page_size;
                usage->has_resident = 1;
                have_any = 1;
            }
            fclose(file);
        }
    }

    {
        struct rusage usage_stats;

        if (getrusage(RUSAGE_SELF, &usage_stats) == 0) {
            usage->peak_rss_bytes = (uint64_t)usage_stats.ru_maxrss * 1024ULL;
            usage->has_peak_rss = 1;
            have_any = 1;
        }
    }

    return have_any;
}
#endif

/*
 * Public wrapper around the split macOS/Linux implementations so callers
 * get one stable API while the platform-specific logic stays short enough
 * to read and maintain.
 */
int platform_get_process_memory_usage(PlatformMemoryUsage *usage)
{
    if (usage == NULL) {
        return 0;
    }

    memset(usage, 0, sizeof(*usage));

#if defined(__APPLE__) && defined(__MACH__)
    return platform_get_process_memory_usage_macos(usage);
#elif defined(__linux__)
    return platform_get_process_memory_usage_linux(usage);
#else
    return 0;
#endif
}

static double timeval_to_seconds_local(const struct timeval *value)
{
    if (value == NULL) {
        return 0.0;
    }
    return (double)value->tv_sec + ((double)value->tv_usec / 1000000.0);
}

#if defined(__linux__)
static int linux_read_process_blkio_delay_seconds(double *out_seconds)
{
    FILE *file;
    char line[4096];
    char *after_comm;
    char *cursor;
    char *saveptr = NULL;
    char *token;
    int field_number = 3;
    long ticks_per_second;

    if (out_seconds == NULL) {
        return 0;
    }
    *out_seconds = 0.0;

    file = fopen("/proc/self/stat", "r");
    if (file == NULL) {
        return 0;
    }
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return 0;
    }
    fclose(file);

    after_comm = strrchr(line, ')');
    if (after_comm == NULL || after_comm[1] == '\0') {
        return 0;
    }
    cursor = after_comm + 2;
    ticks_per_second = sysconf(_SC_CLK_TCK);
    if (ticks_per_second <= 0) {
        ticks_per_second = 100;
    }

    token = strtok_r(cursor, " \t\r\n", &saveptr);
    while (token != NULL) {
        if (field_number == 42) {
            char *end = NULL;
            unsigned long long ticks = strtoull(token, &end, 10);

            if (end == token) {
                return 0;
            }
            *out_seconds = (double)ticks / (double)ticks_per_second;
            return 1;
        }
        field_number++;
        token = strtok_r(NULL, " \t\r\n", &saveptr);
    }

    return 0;
}
#endif

int platform_get_process_resource_usage(PlatformProcessResourceUsage *usage)
{
    struct rusage usage_stats;
    int have_any = 0;

    if (usage == NULL) {
        return 0;
    }

    memset(usage, 0, sizeof(*usage));

    if (platform_get_process_memory_usage(&usage->memory)) {
        have_any = 1;
    }
    if (getrusage(RUSAGE_SELF, &usage_stats) == 0) {
        usage->user_cpu_seconds =
            timeval_to_seconds_local(&usage_stats.ru_utime);
        usage->system_cpu_seconds =
            timeval_to_seconds_local(&usage_stats.ru_stime);
        usage->total_cpu_seconds =
            usage->user_cpu_seconds + usage->system_cpu_seconds;
        usage->has_cpu = 1;
        have_any = 1;
    }

#if defined(__linux__)
    if (linux_read_process_blkio_delay_seconds(&usage->io_wait_seconds)) {
        usage->has_io_wait = 1;
        have_any = 1;
    }
#endif

    return have_any;
}

#if defined(__APPLE__) && defined(__MACH__)
static int platform_get_system_memory_macos(PlatformSystemMemory *memory)
{
    int have_any = 0;
    {
        mach_port_t host_port = mach_host_self();
        host_basic_info_data_t host_info_data;
        mach_msg_type_number_t host_info_count = HOST_BASIC_INFO_COUNT;

        if (host_info(
                host_port,
                HOST_BASIC_INFO,
                (host_info_t)&host_info_data,
                &host_info_count) == KERN_SUCCESS &&
            host_info_data.max_mem > 0U) {
            memory->total_bytes = (uint64_t)host_info_data.max_mem;
            memory->has_total = 1;
            have_any = 1;
        }
        (void)mach_port_deallocate(mach_task_self(), host_port);
    }
    {
        mach_port_t host_port = mach_host_self();
        vm_size_t page_size = 0;
        vm_statistics64_data_t vm_stats;
        mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;

        if (host_page_size(host_port, &page_size) == KERN_SUCCESS &&
            host_statistics64(
                host_port,
                HOST_VM_INFO64,
                (host_info64_t)&vm_stats,
                &count) == KERN_SUCCESS) {
            uint64_t available_pages =
                (uint64_t)vm_stats.free_count +
                (uint64_t)vm_stats.inactive_count +
                (uint64_t)vm_stats.speculative_count;

            memory->available_bytes = available_pages * (uint64_t)page_size;
            memory->has_available = 1;
            have_any = 1;
        }
        (void)mach_port_deallocate(mach_task_self(), host_port);
    }
    return have_any;
}
#endif

#if defined(__linux__)
static int platform_get_system_memory_linux(PlatformSystemMemory *memory)
{
    int have_any = 0;

    {
        struct sysinfo info;

        if (sysinfo(&info) == 0) {
            uint64_t mem_unit = info.mem_unit > 0U ? (uint64_t)info.mem_unit : 1ULL;

            if (info.totalram > 0UL) {
                memory->total_bytes = (uint64_t)info.totalram * mem_unit;
                memory->has_total = 1;
                have_any = 1;
            }

            if (read_proc_meminfo_value_bytes("MemAvailable:", &memory->available_bytes)) {
                memory->has_available = 1;
                have_any = 1;
            } else if (info.freeram > 0UL || info.bufferram > 0UL) {
                memory->available_bytes =
                    ((uint64_t)info.freeram + (uint64_t)info.bufferram) * mem_unit;
                memory->has_available = 1;
                have_any = 1;
            }
        }

        if (linux_apply_cgroup_memory_limits(memory)) {
            if (memory->has_total || memory->has_available) {
                have_any = 1;
            }
        }
    }

    return have_any;
}
#endif

/*
 * Same idea as the process-memory helper above, but for a coarse system
 * memory snapshot that the rest of the program can use for sizing and
 * progress heuristics.
 */
int platform_get_system_memory(PlatformSystemMemory *memory)
{
    if (memory == NULL) {
        return 0;
    }

    memset(memory, 0, sizeof(*memory));

#if defined(__APPLE__) && defined(__MACH__)
    return platform_get_system_memory_macos(memory);
#elif defined(__linux__)
    return platform_get_system_memory_linux(memory);
#else
    return 0;
#endif
}

int platform_get_free_space_bytes(const char *path, uint64_t *available_bytes)
{
    struct statvfs stats;

    if (path == NULL || path[0] == '\0' || available_bytes == NULL) {
        return 0;
    }

    if (statvfs(path, &stats) != 0) {
        return 0;
    }

    *available_bytes = (uint64_t)stats.f_bavail * (uint64_t)stats.f_frsize;
    return 1;
}
