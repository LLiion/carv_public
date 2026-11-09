#define _POSIX_C_SOURCE 200809L
#define _FILE_OFFSET_BITS 64

#include "ntfs_hypersafe.h"

#include "ddrescue_map.h"
#include "mft_probe_parser.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __APPLE__
#include <sys/disk.h>
#include <sys/ioctl.h>
#endif

#ifdef __linux__
#include <sys/ioctl.h>
#include <linux/fs.h>
#endif

#define HYPERSAFE_HEAD_BYTES (32ULL * 1024ULL * 1024ULL)
#define HYPERSAFE_VOLUME_FRONT_BYTES (2ULL * 1024ULL * 1024ULL)
#define HYPERSAFE_MFT_SEED_BYTES (1ULL * 1024ULL * 1024ULL)
#define HYPERSAFE_MAX_PARTITIONS 128U
#define HYPERSAFE_MAX_VOLUMES 16U
#define GPT_PARTITION_ENTRY_MAX 1024U

typedef struct PartitionCandidate {
    uint64_t offset;
    uint64_t size;
    int is_basic_data;
} PartitionCandidate;

typedef struct VolumeList {
    NtfsHypersafeVolume items[HYPERSAFE_MAX_VOLUMES];
    size_t count;
} VolumeList;

static uint16_t rd16(const unsigned char *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t rd32(const unsigned char *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const unsigned char *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static void copy_text_bounded(char *destination, size_t destination_size,
                              const char *source)
{
    size_t length;

    if (destination == NULL || destination_size == 0U) return;
    if (source == NULL) {
        destination[0] = '\0';
        return;
    }
    length = strnlen(source, destination_size - 1U);
    memcpy(destination, source, length);
    destination[length] = '\0';
}

static int text_present(const char *text)
{
    return text != NULL && text[0] != '\0';
}

static void capture_linux_source_identity(
    const char *source_path,
    NtfsHypersafeResult *result
)
{
    const char *by_id_dir = getenv("CARV_TEST_DISK_BY_ID_DIR");
    DIR *dir;
    struct dirent *entry;
#ifdef PATH_MAX
    char resolved_source[PATH_MAX];
#else
    char resolved_source[NTFS_HYPERSAFE_PATH_TEXT_MAX];
#endif

    if (!text_present(source_path) || result == NULL ||
        realpath(source_path, resolved_source) == NULL) {
        return;
    }
    if (!text_present(by_id_dir)) {
#if defined(__linux__)
        by_id_dir = "/dev/disk/by-id";
#else
        return;
#endif
    }
    dir = opendir(by_id_dir);
    if (dir == NULL) {
        return;
    }
    while ((entry = readdir(dir)) != NULL) {
        char candidate_path[NTFS_HYPERSAFE_PATH_TEXT_MAX];
#ifdef PATH_MAX
        char resolved_candidate[PATH_MAX];
#else
        char resolved_candidate[NTFS_HYPERSAFE_PATH_TEXT_MAX];
#endif
        char *destination = NULL;
        size_t destination_size = 0U;

        if (entry->d_name[0] == '.' ||
            snprintf(
                candidate_path,
                sizeof(candidate_path),
                "%s/%s",
                by_id_dir,
                entry->d_name
            ) >= (int)sizeof(candidate_path) ||
            realpath(candidate_path, resolved_candidate) == NULL ||
            strcmp(resolved_candidate, resolved_source) != 0) {
            continue;
        }
        if (strncmp(entry->d_name, "wwn-", 4U) == 0) {
            destination = result->linux_wwn_id;
            destination_size = sizeof(result->linux_wwn_id);
        } else if (strncmp(entry->d_name, "ata-", 4U) == 0) {
            destination = result->linux_ata_id;
            destination_size = sizeof(result->linux_ata_id);
        } else if (strncmp(entry->d_name, "usb-", 4U) == 0) {
            destination = result->linux_usb_id;
            destination_size = sizeof(result->linux_usb_id);
        }
        if (destination != NULL &&
            (destination[0] == '\0' || strcmp(entry->d_name, destination) < 0)) {
            copy_text_bounded(destination, destination_size, entry->d_name);
        }
    }
    closedir(dir);
}

static int is_power_of_two_u32(uint32_t value)
{
    return value != 0U && (value & (value - 1U)) == 0U;
}

static int guid_is_microsoft_basic_data(const unsigned char *guid)
{
    static const unsigned char basic_data_guid[16] = {
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44,
        0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7
    };

    return guid != NULL &&
           memcmp(guid, basic_data_guid, sizeof(basic_data_guid)) == 0;
}

static int pread_exact(int fd, uint64_t offset, void *buffer, size_t length)
{
    unsigned char *out = (unsigned char *)buffer;
    size_t done = 0U;

    if (fd < 0 || buffer == NULL || length == 0U ||
        offset > (uint64_t)INT64_MAX ||
        (uint64_t)length > (uint64_t)INT64_MAX - offset) {
        return 0;
    }
    while (done < length) {
        ssize_t got = pread(
            fd,
            out + done,
            length - done,
            (off_t)(offset + done)
        );

        if (got > 0) {
            done += (size_t)got;
            continue;
        }
        if (got < 0 && errno == EINTR) {
            continue;
        }
        return 0;
    }
    return 1;
}

static int mapped_pread_exact(
    int image_fd,
    const DdrescueMap *map,
    uint64_t offset,
    void *buffer,
    size_t length
)
{
    return length > 0U &&
           ddrescue_map_range_is_finished(map, offset, (uint64_t)length) &&
           pread_exact(image_fd, offset, buffer, length);
}

uint64_t ntfs_hypersafe_source_size(const char *path)
{
    struct stat st;
    int fd;

    if (path == NULL || path[0] == '\0' || stat(path, &st) != 0) {
        return 0U;
    }
    if (S_ISREG(st.st_mode)) {
        return st.st_size > 0 ? (uint64_t)st.st_size : 0U;
    }
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        return 0U;
    }
#ifdef __linux__
    {
        uint64_t bytes = 0U;

        if (ioctl(fd, BLKGETSIZE64, &bytes) == 0 && bytes > 0U) {
            close(fd);
            return bytes;
        }
    }
#endif
#ifdef __APPLE__
    {
        uint64_t blocks = 0U;
        uint32_t block_size = 0U;

        if (ioctl(fd, DKIOCGETBLOCKCOUNT, &blocks) == 0 &&
            ioctl(fd, DKIOCGETBLOCKSIZE, &block_size) == 0 &&
            blocks > 0U && block_size > 0U &&
            blocks <= UINT64_MAX / block_size) {
            close(fd);
            return blocks * block_size;
        }
    }
#endif
    close(fd);
    return 0U;
}

uint32_t ntfs_hypersafe_source_logical_sector_size(const char *path)
{
    int fd;
    uint32_t block_size = 0U;

    if (path == NULL || path[0] == '\0') {
        return 512U;
    }
    fd = open(path, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        return 512U;
    }
#ifdef __linux__
    {
        int value = 0;

        if (ioctl(fd, BLKSSZGET, &value) == 0 && value > 0) {
            block_size = (uint32_t)value;
        }
    }
#endif
#ifdef __APPLE__
    (void)ioctl(fd, DKIOCGETBLOCKSIZE, &block_size);
#endif
    close(fd);
    if (!is_power_of_two_u32(block_size) ||
        block_size < 512U || block_size > 4096U) {
        return 512U;
    }
    return block_size;
}

static int add_partition_candidate(
    PartitionCandidate *items,
    size_t *count,
    uint64_t source_size,
    uint64_t offset,
    uint64_t size,
    int is_basic_data
)
{
    size_t i;

    if (items == NULL || count == NULL || offset >= source_size) {
        return 0;
    }
    if (size == 0U || size > source_size - offset) {
        size = source_size - offset;
    }
    for (i = 0U; i < *count; ++i) {
        if (items[i].offset == offset) {
            if (size > items[i].size) items[i].size = size;
            if (is_basic_data) items[i].is_basic_data = 1;
            return 1;
        }
    }
    if (*count >= HYPERSAFE_MAX_PARTITIONS) {
        return 0;
    }
    items[*count].offset = offset;
    items[*count].size = size;
    items[*count].is_basic_data = is_basic_data;
    (*count)++;
    return 1;
}

static int add_volume(VolumeList *list, const NtfsHypersafeVolume *volume)
{
    size_t i;

    if (list == NULL || volume == NULL || volume->cluster_size == 0U) {
        return 0;
    }
    for (i = 0U; i < list->count; ++i) {
        if (list->items[i].volume_offset == volume->volume_offset) {
            if (volume->is_basic_data) list->items[i].is_basic_data = 1;
            return 1;
        }
    }
    if (list->count >= HYPERSAFE_MAX_VOLUMES) {
        return 0;
    }
    list->items[list->count++] = *volume;
    return 1;
}

static int parse_ntfs_boot_sector(
    const unsigned char *sector,
    uint64_t source_size,
    uint64_t volume_offset,
    uint64_t candidate_size,
    int is_basic_data,
    NtfsHypersafeVolume *out
)
{
    uint32_t bytes_per_sector;
    uint32_t sectors_per_cluster;
    uint64_t cluster_size;
    uint64_t total_sectors;
    uint64_t volume_size;
    uint64_t mft_lcn;
    uint64_t mirror_lcn;
    int8_t record_size_raw;
    uint32_t record_size;

    if (sector == NULL || out == NULL ||
        memcmp(sector + 3, "NTFS    ", 8) != 0 ||
        sector[510] != 0x55 || sector[511] != 0xAA) {
        return 0;
    }
    bytes_per_sector = rd16(sector + 11);
    sectors_per_cluster = sector[13];
    if (!is_power_of_two_u32(bytes_per_sector) ||
        bytes_per_sector < 512U || bytes_per_sector > 4096U ||
        !is_power_of_two_u32(sectors_per_cluster)) {
        return 0;
    }
    cluster_size = (uint64_t)bytes_per_sector * sectors_per_cluster;
    if (cluster_size == 0U || cluster_size > 16ULL * 1024ULL * 1024ULL) {
        return 0;
    }
    total_sectors = rd64(sector + 40);
    if (total_sectors == 0U || total_sectors > UINT64_MAX / bytes_per_sector) {
        return 0;
    }
    volume_size = total_sectors * bytes_per_sector;
    if (candidate_size > 0U && volume_size > candidate_size) {
        volume_size = candidate_size;
    }
    if (volume_offset >= source_size || volume_size > source_size - volume_offset) {
        volume_size = source_size - volume_offset;
    }
    mft_lcn = rd64(sector + 48);
    mirror_lcn = rd64(sector + 56);
    if (mft_lcn > UINT64_MAX / cluster_size ||
        mirror_lcn > UINT64_MAX / cluster_size ||
        mft_lcn * cluster_size >= volume_size ||
        mirror_lcn * cluster_size >= volume_size) {
        return 0;
    }
    record_size_raw = (int8_t)sector[64];
    if (record_size_raw < 0) {
        unsigned int shift = (unsigned int)(-record_size_raw);
        if (shift >= 32U) return 0;
        record_size = 1U << shift;
    } else if (record_size_raw > 0 &&
               (uint64_t)(uint8_t)record_size_raw * cluster_size <= UINT32_MAX) {
        record_size = (uint32_t)((uint64_t)(uint8_t)record_size_raw * cluster_size);
    } else {
        return 0;
    }
    if (record_size != MFT_PROBE_RECORD_SIZE) {
        return 0;
    }

    memset(out, 0, sizeof(*out));
    out->volume_offset = volume_offset;
    out->volume_size = volume_size;
    out->cluster_size = cluster_size;
    out->volume_serial = rd64(sector + 72);
    out->mft_abs_offset = volume_offset + mft_lcn * cluster_size;
    out->mft_mirror_abs_offset = volume_offset + mirror_lcn * cluster_size;
    out->mft_record_size = record_size;
    out->bytes_per_sector = bytes_per_sector;
    out->sectors_per_cluster = sectors_per_cluster;
    out->is_basic_data = is_basic_data;
    return 1;
}

static int write_status(
    const char *path,
    const char *source_path,
    const char *image_path,
    const char *map_path,
    const NtfsHypersafeResult *result
)
{
    char temp_path[4096];
    FILE *file;
    size_t i;

    if (path == NULL || path[0] == '\0' || result == NULL ||
        snprintf(temp_path, sizeof(temp_path), "%s.tmp", path) >= (int)sizeof(temp_path)) {
        return 0;
    }
    file = fopen(temp_path, "w");
    if (file == NULL) {
        return 0;
    }
    fprintf(file, "format_version=2\nbackend=ntfs\nstrategy=hypersafe_metadata_bootstrap\n");
    fprintf(file, "status=%s\ndetail=%s\n", result->status, result->detail);
    fprintf(file, "source_path=%s\nimage_path=%s\nmap_path=%s\n",
            result->source_path[0] != '\0' ? result->source_path :
                (source_path != NULL ? source_path : ""),
            result->image_path[0] != '\0' ? result->image_path :
                (image_path != NULL ? image_path : ""),
            result->map_path[0] != '\0' ? result->map_path :
                (map_path != NULL ? map_path : ""));
    fprintf(file, "source_size=%llu\nlogical_sector_size=%u\n",
            (unsigned long long)result->source_size,
            result->source_logical_sector_size);
    fprintf(
        file,
        "linux_wwn_id=%s\nlinux_ata_id=%s\nlinux_usb_id=%s\n",
        result->linux_wwn_id,
        result->linux_ata_id,
        result->linux_usb_id
    );
    fprintf(file, "volume_offset=%llu\nvolume_size=%llu\ncluster_size=%llu\n",
            (unsigned long long)result->volume.volume_offset,
            (unsigned long long)result->volume.volume_size,
            (unsigned long long)result->volume.cluster_size);
    fprintf(file, "volume_serial=%016llx\nmft_abs_offset=%llu\nmft_mirror_abs_offset=%llu\n",
            (unsigned long long)result->volume.volume_serial,
            (unsigned long long)result->volume.mft_abs_offset,
            (unsigned long long)result->volume.mft_mirror_abs_offset);
    fprintf(file, "mft_data_size=%llu\nmft_record_size=%u\nbytes_per_sector=%u\nsectors_per_cluster=%u\nis_basic_data=%d\n",
            (unsigned long long)result->volume.mft_data_size,
            result->volume.mft_record_size,
            result->volume.bytes_per_sector,
            result->volume.sectors_per_cluster,
            result->volume.is_basic_data);
    fprintf(file, "mft_run_count=%zu\nmft_run_truncated=%d\nmft_requested_bytes=%llu\nmft_finished_bytes=%llu\n",
            result->mft_run_count,
            result->mft_run_truncated,
            (unsigned long long)result->mft_requested_bytes,
            (unsigned long long)result->mft_finished_bytes);
    for (i = 0U; i < result->mft_run_count; ++i) {
        fprintf(file, "mft_run_%zu=%llu,%llu\n", i,
                (unsigned long long)result->mft_runs[i].lcn,
                (unsigned long long)result->mft_runs[i].clusters);
    }
    {
        int write_failed = 0;

        if (fflush(file) != 0) write_failed = 1;
        if (fsync(fileno(file)) != 0) write_failed = 1;
        if (fclose(file) != 0) write_failed = 1;
        if (write_failed) {
            (void)unlink(temp_path);
            return 0;
        }
    }
    if (rename(temp_path, path) != 0) {
        (void)unlink(temp_path);
        return 0;
    }
    return 1;
}

static void set_result_state(
    NtfsHypersafeResult *result,
    const char *status,
    const char *detail
)
{
    if (result == NULL) return;
    snprintf(result->status, sizeof(result->status), "%s", status != NULL ? status : "failed");
    snprintf(result->detail, sizeof(result->detail), "%s", detail != NULL ? detail : "");
}

static int load_current_map(const char *map_path, DdrescueMap *map)
{
    ddrescue_map_reset(map);
    return ddrescue_map_load(map_path, map);
}

static int build_partition_candidates(
    int image_fd,
    const DdrescueMap *map,
    uint64_t source_size,
    uint32_t sector_size,
    PartitionCandidate *items,
    size_t *count
)
{
    unsigned char sector[4096];
    size_t i;
    int maybe_gpt = 0;

    if (items == NULL || count == NULL || sector_size < 512U ||
        sector_size > sizeof(sector) ||
        !mapped_pread_exact(image_fd, map, 0U, sector, sector_size)) {
        return 0;
    }
    *count = 0U;
    if (sector[510] == 0x55 && sector[511] == 0xAA) {
        for (i = 0U; i < 4U; ++i) {
            const unsigned char *entry = sector + 446U + i * 16U;
            uint8_t type = entry[4];
            uint32_t first_lba = rd32(entry + 8);
            uint32_t sectors = rd32(entry + 12);

            if (type == 0xEEU) maybe_gpt = 1;
            if (type == 0U || type == 0xEEU || first_lba == 0U || sectors == 0U) continue;
            (void)add_partition_candidate(
                items, count, source_size,
                (uint64_t)first_lba * sector_size,
                (uint64_t)sectors * sector_size,
                type == 0x07U
            );
        }
    }
    if (maybe_gpt) {
        unsigned char header[4096];

        if (mapped_pread_exact(image_fd, map, sector_size, header, sector_size) &&
            memcmp(header, "EFI PART", 8) == 0) {
            uint64_t entries_lba = rd64(header + 72);
            uint32_t entry_count = rd32(header + 80);
            uint32_t entry_size = rd32(header + 84);
            uint32_t capped = entry_count > HYPERSAFE_MAX_PARTITIONS
                ? HYPERSAFE_MAX_PARTITIONS : entry_count;

            if (entries_lba > 0U &&
                entries_lba <= UINT64_MAX / sector_size &&
                entry_size >= 128U && entry_size <= GPT_PARTITION_ENTRY_MAX) {
                uint64_t entries_offset = entries_lba * sector_size;

                for (i = 0U; i < capped; ++i) {
                    unsigned char entry[GPT_PARTITION_ENTRY_MAX];
                    uint64_t entry_delta = (uint64_t)i * entry_size;
                    uint64_t entry_offset;
                    uint64_t first_lba;
                    uint64_t last_lba;
                    uint64_t lba_count;
                    size_t j;
                    int empty = 1;

                    if (entry_delta > UINT64_MAX - entries_offset) break;
                    entry_offset = entries_offset + entry_delta;
                    if (!mapped_pread_exact(image_fd, map, entry_offset, entry, entry_size)) break;
                    for (j = 0U; j < 16U; ++j) {
                        if (entry[j] != 0U) { empty = 0; break; }
                    }
                    if (empty) continue;
                    first_lba = rd64(entry + 32);
                    last_lba = rd64(entry + 40);
                    if (first_lba == 0U || last_lba < first_lba ||
                        first_lba > UINT64_MAX / sector_size) continue;
                    lba_count = last_lba - first_lba + 1U;
                    if (lba_count == 0U || lba_count > UINT64_MAX / sector_size) continue;
                    (void)add_partition_candidate(
                        items, count, source_size,
                        first_lba * sector_size,
                        lba_count * sector_size,
                        guid_is_microsoft_basic_data(entry)
                    );
                }
            }
        }
    }
    (void)add_partition_candidate(items, count, source_size, 0U, source_size, 0);
    return *count > 0U;
}

static size_t choose_volume(const VolumeList *list)
{
    size_t best = 0U;
    size_t i;

    for (i = 1U; i < list->count; ++i) {
        if ((list->items[i].is_basic_data && !list->items[best].is_basic_data) ||
            (list->items[i].is_basic_data == list->items[best].is_basic_data &&
             list->items[i].volume_size > list->items[best].volume_size)) {
            best = i;
        }
    }
    return best;
}

static uint64_t clipped_length(uint64_t source_size, uint64_t start, uint64_t wanted)
{
    if (start >= source_size) return 0U;
    return wanted < source_size - start ? wanted : source_size - start;
}

static int volume_run_range(
    const NtfsHypersafeVolume *volume,
    const MftDataRun *run,
    uint64_t byte_limit,
    uint64_t *out_offset,
    uint64_t *out_length,
    int *out_clipped
)
{
    uint64_t relative;
    uint64_t length;

    if (out_clipped != NULL) *out_clipped = 0;
    if (volume == NULL || run == NULL || out_offset == NULL ||
        out_length == NULL ||
        volume->cluster_size == 0U ||
        run->lcn > UINT64_MAX / volume->cluster_size ||
        run->clusters == 0U ||
        run->clusters > UINT64_MAX / volume->cluster_size) {
        return 0;
    }
    relative = run->lcn * volume->cluster_size;
    if (relative >= volume->volume_size ||
        relative > UINT64_MAX - volume->volume_offset) {
        return 0;
    }
    length = run->clusters * volume->cluster_size;
    if (length > byte_limit) length = byte_limit;
    if (length > volume->volume_size - relative) {
        length = volume->volume_size - relative;
        if (out_clipped != NULL) *out_clipped = 1;
    }
    if (length == 0U) return 0;
    *out_offset = volume->volume_offset + relative;
    *out_length = length;
    return 1;
}

int ntfs_hypersafe_bootstrap(
    const char *source_path,
    const char *image_path,
    const char *map_path,
    const char *status_path,
    NtfsHypersafeAcquireRangeFn acquire_range,
    void *acquire_context,
    NtfsHypersafeResult *out_result
)
{
    NtfsHypersafeResult result;
    DdrescueMap map = {0};
    PartitionCandidate candidates[HYPERSAFE_MAX_PARTITIONS];
    size_t candidate_count = 0U;
    VolumeList volumes = {0};
    int image_fd = -1;
    size_t i;
    unsigned char sector[512];
    unsigned char record[MFT_PROBE_RECORD_SIZE];
    MftProbeEntry mft_entry;
    uint64_t remaining;
    int ok = 0;

    memset(&result, 0, sizeof(result));
    snprintf(result.source_path, sizeof(result.source_path), "%s",
             source_path != NULL ? source_path : "");
    snprintf(result.image_path, sizeof(result.image_path), "%s",
             image_path != NULL ? image_path : "");
    snprintf(result.map_path, sizeof(result.map_path), "%s",
             map_path != NULL ? map_path : "");
    result.source_size = ntfs_hypersafe_source_size(source_path);
    result.source_logical_sector_size = ntfs_hypersafe_source_logical_sector_size(source_path);
    capture_linux_source_identity(source_path, &result);
    set_result_state(&result, "starting", "Preparing metadata bootstrap");
    if (!write_status(status_path, source_path, image_path, map_path, &result)) {
        set_result_state(&result, "failed", "Hypersafe state file is not writable");
        if (out_result != NULL) *out_result = result;
        return 0;
    }

    if (result.source_size == 0U || acquire_range == NULL) {
        set_result_state(&result, "failed", "Source size is unavailable");
        goto cleanup;
    }
    set_result_state(&result, "acquiring_head", "Reading the first 32 MiB with ddrescue");
    if (!write_status(status_path, source_path, image_path, map_path, &result)) {
        set_result_state(&result, "failed", "Could not update Hypersafe state before the header pass");
        goto cleanup;
    }
    if (!acquire_range(
            acquire_context, 0U,
            clipped_length(result.source_size, 0U, HYPERSAFE_HEAD_BYTES),
            result.status, result.detail)) {
        set_result_state(&result, "failed", "ddrescue could not acquire the disk header");
        goto cleanup;
    }
    if (!load_current_map(map_path, &map)) {
        set_result_state(&result, "failed", "The ddrescue map could not be read after the header pass");
        goto cleanup;
    }
    image_fd = open(image_path, O_RDONLY);
    if (image_fd < 0 ||
        !build_partition_candidates(
            image_fd, &map, result.source_size,
            result.source_logical_sector_size,
            candidates, &candidate_count)) {
        set_result_state(&result, "failed", "The rescued disk header did not contain a usable partition map");
        goto cleanup;
    }

    set_result_state(&result, "acquiring_volume_headers", "Reading candidate filesystem boot sectors");
    if (!write_status(status_path, source_path, image_path, map_path, &result)) {
        set_result_state(&result, "failed", "Could not update Hypersafe state before filesystem probing");
        goto cleanup;
    }
    for (i = 0U; i < candidate_count; ++i) {
        NtfsHypersafeVolume volume;
        uint64_t front_length = clipped_length(
            result.source_size,
            candidates[i].offset,
            HYPERSAFE_VOLUME_FRONT_BYTES
        );

        if (front_length == 0U) continue;
        (void)acquire_range(
            acquire_context,
            candidates[i].offset,
            front_length,
            result.status,
            "Reading one candidate filesystem header"
        );
        if (!load_current_map(map_path, &map) ||
            !mapped_pread_exact(image_fd, &map, candidates[i].offset, sector, sizeof(sector)) ||
            !parse_ntfs_boot_sector(
                sector,
                result.source_size,
                candidates[i].offset,
                candidates[i].size,
                candidates[i].is_basic_data,
                &volume)) {
            continue;
        }
        (void)add_volume(&volumes, &volume);
    }
    if (volumes.count == 0U) {
        set_result_state(&result, "failed", "No valid NTFS boot sector was recovered from the partition candidates");
        goto cleanup;
    }
    result.volume = volumes.items[choose_volume(&volumes)];

    set_result_state(&result, "acquiring_mft_seed", "Reading the first MFT and MFTMirr records");
    if (!write_status(status_path, source_path, image_path, map_path, &result)) {
        set_result_state(&result, "failed", "Could not update Hypersafe state before the MFT seed pass");
        goto cleanup;
    }
    (void)acquire_range(
        acquire_context,
        result.volume.mft_abs_offset,
        clipped_length(result.source_size, result.volume.mft_abs_offset, HYPERSAFE_MFT_SEED_BYTES),
        result.status,
        "Reading primary $MFT seed"
    );
    (void)acquire_range(
        acquire_context,
        result.volume.mft_mirror_abs_offset,
        clipped_length(result.source_size, result.volume.mft_mirror_abs_offset, HYPERSAFE_MFT_SEED_BYTES),
        result.status,
        "Reading $MFTMirr seed"
    );
    if (!load_current_map(map_path, &map)) {
        set_result_state(&result, "failed", "The ddrescue map could not be read after the MFT seed pass");
        goto cleanup;
    }
    memset(&mft_entry, 0, sizeof(mft_entry));
    if (!mapped_pread_exact(
            image_fd, &map, result.volume.mft_abs_offset,
            record, sizeof(record)) ||
        !mft_probe_parse_record_any(record, result.volume.mft_abs_offset, &mft_entry) ||
        !mft_entry.has_data || mft_entry.resident || mft_entry.stored_run_count == 0U) {
        memset(&mft_entry, 0, sizeof(mft_entry));
        if (!mapped_pread_exact(
                image_fd, &map, result.volume.mft_mirror_abs_offset,
                record, sizeof(record)) ||
            !mft_probe_parse_record_any(record, result.volume.mft_mirror_abs_offset, &mft_entry) ||
            !mft_entry.has_data || mft_entry.resident || mft_entry.stored_run_count == 0U) {
            set_result_state(&result, "failed", "Neither the primary $MFT record nor its mirror exposed a usable runlist");
            goto cleanup;
        }
    }
    result.volume.mft_data_size = mft_entry.data_size;
    result.mft_run_count = mft_entry.stored_run_count;
    if (result.mft_run_count > MFT_ENTRY_MAX_RUNS) {
        result.mft_run_count = MFT_ENTRY_MAX_RUNS;
    }
    result.mft_run_truncated = mft_entry.run_truncated;
    memcpy(
        result.mft_runs,
        mft_entry.runs,
        result.mft_run_count * sizeof(*result.mft_runs)
    );

    set_result_state(&result, "acquiring_mft", "Reading every known $MFT extent with ddrescue");
    if (!write_status(status_path, source_path, image_path, map_path, &result)) {
        set_result_state(&result, "failed", "Could not update Hypersafe state before MFT acquisition");
        goto cleanup;
    }
    remaining = result.volume.mft_data_size;
    for (i = 0U; i < result.mft_run_count && remaining > 0U; ++i) {
        uint64_t run_bytes;
        uint64_t run_offset;
        int run_clipped = 0;

        if (!volume_run_range(
                &result.volume,
                &result.mft_runs[i],
                remaining,
                &run_offset,
                &run_bytes,
                &run_clipped)) {
            result.mft_run_truncated = 1;
            continue;
        }
        if (run_clipped) result.mft_run_truncated = 1;
        result.mft_requested_bytes += run_bytes;
        (void)acquire_range(
            acquire_context,
            run_offset,
            run_bytes,
            result.status,
            "Reading one $MFT extent"
        );
        if (remaining >= run_bytes) remaining -= run_bytes;
        else remaining = 0U;
    }
    if (remaining > 0U) result.mft_run_truncated = 1;

    if (!load_current_map(map_path, &map)) {
        set_result_state(&result, "failed", "The final ddrescue map could not be read");
        goto cleanup;
    }
    remaining = result.volume.mft_data_size;
    for (i = 0U; i < result.mft_run_count && remaining > 0U; ++i) {
        uint64_t run_bytes;
        uint64_t run_offset;

        if (!volume_run_range(
                &result.volume,
                &result.mft_runs[i],
                remaining,
                &run_offset,
                &run_bytes,
                NULL)) continue;
        result.mft_finished_bytes += ddrescue_map_finished_bytes(
            &map, run_offset, run_bytes
        );
        if (remaining >= run_bytes) remaining -= run_bytes;
        else remaining = 0U;
    }
    if (result.mft_finished_bytes == 0U) {
        set_result_state(&result, "failed", "No readable $MFT data was acquired");
        goto cleanup;
    }
    if (result.mft_run_truncated ||
        result.mft_finished_bytes < result.mft_requested_bytes) {
        set_result_state(&result, "ready_partial", "MFT preview is available but some MFT bytes remain unread");
    } else {
        set_result_state(&result, "ready", "MFT preview image is complete for every known MFT extent");
    }
    ok = 1;

cleanup:
    if (image_fd >= 0) close(image_fd);
    ddrescue_map_reset(&map);
    if (!write_status(status_path, source_path, image_path, map_path, &result)) {
        set_result_state(&result, "failed", "Could not save final Hypersafe state");
        ok = 0;
    }
    if (out_result != NULL) *out_result = result;
    return ok;
}

static int parse_status_u64(const char *line, const char *key, uint64_t *out)
{
    size_t key_len = strlen(key);
    char *end = NULL;
    unsigned long long value;

    if (strncmp(line, key, key_len) != 0 || line[key_len] != '=') return 0;
    errno = 0;
    value = strtoull(line + key_len + 1U, &end, 0);
    if (errno != 0 || end == line + key_len + 1U || *end != '\0') return 0;
    *out = (uint64_t)value;
    return 1;
}

int ntfs_hypersafe_load_status(
    const char *status_path,
    NtfsHypersafeResult *out_result
)
{
    FILE *file;
    NtfsHypersafeResult result;
    char line[1024];

    if (status_path == NULL || out_result == NULL ||
        (file = fopen(status_path, "r")) == NULL) {
        return 0;
    }
    memset(&result, 0, sizeof(result));
    while (fgets(line, sizeof(line), file) != NULL) {
        uint64_t value;
        size_t index;
        unsigned long long lcn;
        unsigned long long clusters;

        line[strcspn(line, "\r\n")] = '\0';
        if (strncmp(line, "status=", 7) == 0) {
            copy_text_bounded(result.status, sizeof(result.status), line + 7);
        } else if (strncmp(line, "detail=", 7) == 0) {
            copy_text_bounded(result.detail, sizeof(result.detail), line + 7);
        } else if (strncmp(line, "source_path=", 12) == 0) {
            copy_text_bounded(result.source_path, sizeof(result.source_path), line + 12);
        } else if (strncmp(line, "image_path=", 11) == 0) {
            copy_text_bounded(result.image_path, sizeof(result.image_path), line + 11);
        } else if (strncmp(line, "map_path=", 9) == 0) {
            copy_text_bounded(result.map_path, sizeof(result.map_path), line + 9);
        } else if (strncmp(line, "linux_wwn_id=", 13) == 0) {
            copy_text_bounded(
                result.linux_wwn_id,
                sizeof(result.linux_wwn_id),
                line + 13
            );
        } else if (strncmp(line, "linux_ata_id=", 13) == 0) {
            copy_text_bounded(
                result.linux_ata_id,
                sizeof(result.linux_ata_id),
                line + 13
            );
        } else if (strncmp(line, "linux_usb_id=", 13) == 0) {
            copy_text_bounded(
                result.linux_usb_id,
                sizeof(result.linux_usb_id),
                line + 13
            );
        } else if (sscanf(line, "volume_serial=%llx", &lcn) == 1) {
            result.volume.volume_serial = (uint64_t)lcn;
        } else if (parse_status_u64(line, "source_size", &result.source_size)) {
        } else if (parse_status_u64(line, "volume_offset", &result.volume.volume_offset)) {
        } else if (parse_status_u64(line, "volume_size", &result.volume.volume_size)) {
        } else if (parse_status_u64(line, "cluster_size", &result.volume.cluster_size)) {
        } else if (parse_status_u64(line, "mft_abs_offset", &result.volume.mft_abs_offset)) {
        } else if (parse_status_u64(line, "mft_mirror_abs_offset", &result.volume.mft_mirror_abs_offset)) {
        } else if (parse_status_u64(line, "mft_data_size", &result.volume.mft_data_size)) {
        } else if (parse_status_u64(line, "mft_requested_bytes", &result.mft_requested_bytes)) {
        } else if (parse_status_u64(line, "mft_finished_bytes", &result.mft_finished_bytes)) {
        } else if (parse_status_u64(line, "logical_sector_size", &value)) {
            result.source_logical_sector_size = (uint32_t)value;
        } else if (parse_status_u64(line, "mft_record_size", &value)) {
            result.volume.mft_record_size = (uint32_t)value;
        } else if (parse_status_u64(line, "bytes_per_sector", &value)) {
            result.volume.bytes_per_sector = (uint32_t)value;
        } else if (parse_status_u64(line, "sectors_per_cluster", &value)) {
            result.volume.sectors_per_cluster = (uint32_t)value;
        } else if (parse_status_u64(line, "mft_run_truncated", &value)) {
            result.mft_run_truncated = value != 0U;
        } else if (parse_status_u64(line, "is_basic_data", &value)) {
            result.volume.is_basic_data = value != 0U;
        } else if (sscanf(line, "mft_run_%zu=%llu,%llu", &index, &lcn, &clusters) == 3 &&
                   index < MFT_ENTRY_MAX_RUNS) {
            result.mft_runs[index].lcn = (uint64_t)lcn;
            result.mft_runs[index].clusters = (uint64_t)clusters;
            if (index + 1U > result.mft_run_count) result.mft_run_count = index + 1U;
        }
    }
    if (ferror(file) || fclose(file) != 0 ||
        result.source_size == 0U || result.status[0] == '\0' ||
        result.image_path[0] == '\0' || result.map_path[0] == '\0') {
        return 0;
    }
    *out_result = result;
    return 1;
}

int ntfs_hypersafe_write_identity_status(
    const char *source_path,
    const char *image_path,
    const char *map_path,
    const char *status_path
)
{
    NtfsHypersafeResult result;

    if (source_path == NULL || source_path[0] == '\0' ||
        image_path == NULL || image_path[0] == '\0' ||
        map_path == NULL || map_path[0] == '\0' ||
        status_path == NULL || status_path[0] == '\0') {
        return 0;
    }
    memset(&result, 0, sizeof(result));
    copy_text_bounded(result.status, sizeof(result.status), "identity_bound");
    copy_text_bounded(
        result.detail,
        sizeof(result.detail),
        "Source identity bound from a rescued head sample"
    );
    copy_text_bounded(result.source_path, sizeof(result.source_path), source_path);
    copy_text_bounded(result.image_path, sizeof(result.image_path), image_path);
    copy_text_bounded(result.map_path, sizeof(result.map_path), map_path);
    result.source_size = ntfs_hypersafe_source_size(source_path);
    result.source_logical_sector_size =
        ntfs_hypersafe_source_logical_sector_size(source_path);
    capture_linux_source_identity(source_path, &result);
    return result.source_size > 0U &&
           write_status(status_path, source_path, image_path, map_path, &result);
}

NtfsHypersafeIdentityDecision ntfs_hypersafe_compare_linux_source_identity(
    const char *source_path,
    const NtfsHypersafeResult *expected
)
{
    NtfsHypersafeResult current;
    int compared = 0;

    if (!text_present(source_path) || expected == NULL) {
        return NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE;
    }
    if (!text_present(expected->linux_wwn_id) &&
        !text_present(expected->linux_ata_id)) {
        return NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE;
    }
    memset(&current, 0, sizeof(current));
    capture_linux_source_identity(source_path, &current);
    if (text_present(expected->linux_wwn_id) &&
        text_present(current.linux_wwn_id)) {
        compared = 1;
        if (strcmp(expected->linux_wwn_id, current.linux_wwn_id) != 0) {
            return NTFS_HYPERSAFE_IDENTITY_MISMATCH;
        }
    }
    if (text_present(expected->linux_ata_id) &&
        text_present(current.linux_ata_id)) {
        compared = 1;
        if (strcmp(expected->linux_ata_id, current.linux_ata_id) != 0) {
            return NTFS_HYPERSAFE_IDENTITY_MISMATCH;
        }
    }
    return compared
        ? NTFS_HYPERSAFE_IDENTITY_MATCH
        : NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE;
}

int ntfs_hypersafe_refresh_linux_identity_status(
    const char *status_path,
    const char *source_path
)
{
    NtfsHypersafeResult saved;
    NtfsHypersafeResult current;

    if (!ntfs_hypersafe_load_status(status_path, &saved) ||
        !text_present(source_path)) {
        return 0;
    }
    memset(&current, 0, sizeof(current));
    capture_linux_source_identity(source_path, &current);
    if (!text_present(current.linux_wwn_id) &&
        !text_present(current.linux_ata_id)) {
        return 1;
    }
    if (text_present(current.linux_wwn_id)) {
        copy_text_bounded(
            saved.linux_wwn_id,
            sizeof(saved.linux_wwn_id),
            current.linux_wwn_id
        );
    }
    if (text_present(current.linux_ata_id)) {
        copy_text_bounded(
            saved.linux_ata_id,
            sizeof(saved.linux_ata_id),
            current.linux_ata_id
        );
    }
    if (text_present(current.linux_usb_id)) {
        copy_text_bounded(
            saved.linux_usb_id,
            sizeof(saved.linux_usb_id),
            current.linux_usb_id
        );
    }
    return write_status(
        status_path,
        saved.source_path,
        saved.image_path,
        saved.map_path,
        &saved
    );
}

NtfsHypersafeIdentityDecision
ntfs_hypersafe_bind_explicit_linux_source_identity(
    const char *status_path,
    const char *source_path,
    const char *image_path,
    const char *map_path
)
{
    NtfsHypersafeResult saved;
    NtfsHypersafeResult current;
    uint64_t current_size;

    if (!text_present(status_path) || !text_present(source_path) ||
        !text_present(image_path) || !text_present(map_path) ||
        !ntfs_hypersafe_load_status(status_path, &saved) ||
        strcmp(saved.image_path, image_path) != 0 ||
        strcmp(saved.map_path, map_path) != 0) {
        return NTFS_HYPERSAFE_IDENTITY_MISMATCH;
    }
    current_size = ntfs_hypersafe_source_size(source_path);
    if (current_size == 0U) {
        return NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE;
    }
    if (current_size != saved.source_size) {
        return NTFS_HYPERSAFE_IDENTITY_MISMATCH;
    }
    if (text_present(saved.linux_wwn_id) ||
        text_present(saved.linux_ata_id)) {
        return ntfs_hypersafe_compare_linux_source_identity(
            source_path,
            &saved
        );
    }

    memset(&current, 0, sizeof(current));
    capture_linux_source_identity(source_path, &current);
    if (!text_present(current.linux_wwn_id) &&
        !text_present(current.linux_ata_id)) {
        return NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE;
    }
    copy_text_bounded(
        saved.linux_wwn_id,
        sizeof(saved.linux_wwn_id),
        current.linux_wwn_id
    );
    copy_text_bounded(
        saved.linux_ata_id,
        sizeof(saved.linux_ata_id),
        current.linux_ata_id
    );
    copy_text_bounded(
        saved.linux_usb_id,
        sizeof(saved.linux_usb_id),
        current.linux_usb_id
    );
    return write_status(
        status_path,
        source_path,
        saved.image_path,
        saved.map_path,
        &saved
    )
        ? NTFS_HYPERSAFE_IDENTITY_MATCH
        : NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE;
}

NtfsHypersafeIdentityDecision ntfs_hypersafe_image_identity_decision(
    const char *image_path,
    const char *map_path,
    const NtfsHypersafeResult *expected
)
{
    DdrescueMap map = {0};
    NtfsHypersafeVolume current;
    unsigned char sector[512];
    int image_fd = -1;
    NtfsHypersafeIdentityDecision decision =
        NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE;

    if (image_path == NULL || map_path == NULL || expected == NULL ||
        expected->source_size == 0U || expected->volume.volume_size == 0U ||
        !ddrescue_map_load(map_path, &map)) {
        return NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE;
    }
    image_fd = open(image_path, O_RDONLY);
    if (image_fd < 0 ||
        !mapped_pread_exact(
            image_fd, &map, expected->volume.volume_offset,
            sector, sizeof(sector))) {
        goto cleanup;
    }
    if (!parse_ntfs_boot_sector(
            sector,
            expected->source_size,
            expected->volume.volume_offset,
            expected->volume.volume_size,
            expected->volume.is_basic_data,
            &current)) {
        decision = NTFS_HYPERSAFE_IDENTITY_MISMATCH;
        goto cleanup;
    }
    decision =
        current.volume_offset == expected->volume.volume_offset &&
        current.volume_size == expected->volume.volume_size &&
        current.cluster_size == expected->volume.cluster_size &&
        current.volume_serial == expected->volume.volume_serial &&
        current.mft_abs_offset == expected->volume.mft_abs_offset
            ? NTFS_HYPERSAFE_IDENTITY_MATCH
            : NTFS_HYPERSAFE_IDENTITY_MISMATCH;

cleanup:
    if (image_fd >= 0) close(image_fd);
    ddrescue_map_reset(&map);
    return decision;
}

int ntfs_hypersafe_image_matches_status(
    const char *image_path,
    const char *map_path,
    const NtfsHypersafeResult *expected
)
{
    return ntfs_hypersafe_image_identity_decision(
        image_path,
        map_path,
        expected
    ) == NTFS_HYPERSAFE_IDENTITY_MATCH;
}

static int identity_sample_is_distinct(
    const unsigned char *sample,
    size_t length
)
{
    unsigned char seen[256] = {0};
    size_t distinct = 0U;
    size_t nonzero = 0U;
    size_t i;

    if (sample == NULL || length < 4096U) return 0;
    for (i = 0U; i < length; ++i) {
        if (!seen[sample[i]]) {
            seen[sample[i]] = 1U;
            distinct++;
        }
        if (sample[i] != 0U) nonzero++;
    }
    return distinct >= 8U && nonzero >= 128U;
}

NtfsHypersafeIdentityDecision ntfs_hypersafe_image_sample_identity_decision(
    const char *saved_image_path,
    const char *saved_map_path,
    const char *probe_image_path,
    const char *probe_map_path,
    uint64_t start,
    size_t length
)
{
    DdrescueMap saved_map = {0};
    DdrescueMap probe_map = {0};
    unsigned char *saved = NULL;
    unsigned char *probe = NULL;
    int saved_fd = -1;
    int probe_fd = -1;
    NtfsHypersafeIdentityDecision decision =
        NTFS_HYPERSAFE_IDENTITY_UNAVAILABLE;

    if (saved_image_path == NULL || saved_map_path == NULL ||
        probe_image_path == NULL || probe_map_path == NULL ||
        length < 4096U ||
        !ddrescue_map_load(saved_map_path, &saved_map) ||
        !ddrescue_map_load(probe_map_path, &probe_map) ||
        !ddrescue_map_range_is_finished(&saved_map, start, length) ||
        !ddrescue_map_range_is_finished(&probe_map, start, length)) {
        goto cleanup;
    }
    saved = (unsigned char *)malloc(length);
    probe = (unsigned char *)malloc(length);
    if (saved == NULL || probe == NULL) goto cleanup;
    saved_fd = open(saved_image_path, O_RDONLY);
    probe_fd = open(probe_image_path, O_RDONLY);
    if (saved_fd < 0 || probe_fd < 0 ||
        !pread_exact(saved_fd, start, saved, length) ||
        !pread_exact(probe_fd, start, probe, length) ||
        !identity_sample_is_distinct(saved, length)) {
        goto cleanup;
    }
    decision = memcmp(saved, probe, length) == 0
        ? NTFS_HYPERSAFE_IDENTITY_MATCH
        : NTFS_HYPERSAFE_IDENTITY_MISMATCH;

cleanup:
    if (saved_fd >= 0) close(saved_fd);
    if (probe_fd >= 0) close(probe_fd);
    free(saved);
    free(probe);
    ddrescue_map_reset(&saved_map);
    ddrescue_map_reset(&probe_map);
    return decision;
}

int ntfs_hypersafe_image_sample_matches(
    const char *saved_image_path,
    const char *saved_map_path,
    const char *probe_image_path,
    const char *probe_map_path,
    uint64_t start,
    size_t length
)
{
    return ntfs_hypersafe_image_sample_identity_decision(
        saved_image_path,
        saved_map_path,
        probe_image_path,
        probe_map_path,
        start,
        length
    ) == NTFS_HYPERSAFE_IDENTITY_MATCH;
}
