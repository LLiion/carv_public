#include "metadata_index.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define MI_HEADER_SIZE 64U
#define MI_MANIFEST_SIZE 64U
#define MI_VOLUME_ROW_SIZE 80U
#define MI_OBJECT_ROW_SIZE 48U
#define MI_LINK_ROW_SIZE 40U
#define MI_FORK_ROW_SIZE 40U
#define MI_EXTENT_ROW_SIZE 24U
#define MI_CHILD_ROW_SIZE 16U
#define MI_PHYSICAL_ROW_SIZE 32U
#define MI_MAX_PATH_DEPTH 4096U

typedef enum {
    MI_TABLE_VOLUME = 0,
    MI_TABLE_OBJECTS,
    MI_TABLE_LINKS,
    MI_TABLE_FORKS,
    MI_TABLE_EXTENTS,
    MI_TABLE_STRINGS,
    MI_TABLE_CHILDREN,
    MI_TABLE_PHYSICAL,
    MI_TABLE_COUNT
} MiTableKind;

typedef struct {
    const char *name;
    const char magic[8];
    uint32_t row_size;
} MiTableSpec;

static const MiTableSpec g_tables[MI_TABLE_COUNT] = {
    { "volume.bin",   { 'C','V','M','I','V','O','L','1' }, MI_VOLUME_ROW_SIZE },
    { "objects.bin",  { 'C','V','M','I','O','B','J','1' }, MI_OBJECT_ROW_SIZE },
    { "links.bin",    { 'C','V','M','I','L','N','K','1' }, MI_LINK_ROW_SIZE },
    { "forks.bin",    { 'C','V','M','I','F','R','K','1' }, MI_FORK_ROW_SIZE },
    { "extents.bin",  { 'C','V','M','I','E','X','T','1' }, MI_EXTENT_ROW_SIZE },
    { "strings.bin",  { 'C','V','M','I','S','T','R','1' }, 0U },
    { "children.idx", { 'C','V','M','I','C','H','D','1' }, MI_CHILD_ROW_SIZE },
    { "physical.idx", { 'C','V','M','I','P','H','Y','1' }, MI_PHYSICAL_ROW_SIZE }
};

typedef struct {
    FILE *file;
    uint64_t count;
    uint64_t data_bytes;
    uint32_t data_crc;
} MiOutputTable;

struct MetadataIndexWriter {
    char index_dir[PATH_MAX];
    char temp_dir[PATH_MAX];
    char final_dir[PATH_MAX];
    uint64_t generation;
    MetadataIndexVolumeIdentity identity;
    MetadataIndexWriterOptions options;
    uint8_t identity_hash[16];
    MiOutputTable table[MI_TABLE_COUNT];
    uint64_t last_object_key;
    uint64_t last_link_key;
    uint64_t last_fork_object;
    uint16_t last_fork_kind;
    int have_object;
    int have_link;
    int have_fork;
};

typedef struct {
    uint64_t parent_key;
    uint32_t link_row;
    uint32_t child_row;
} MiChildRow;

typedef struct {
    uint64_t start;
    uint64_t end;
    uint64_t subtree_max_end;
    uint32_t fork_row;
    uint32_t extent_ordinal;
} MiPhysicalRow;

struct MetadataIndexReader {
    uint64_t generation;
    MetadataIndexVolumeIdentity identity;
    struct {
        void *mapping;
        size_t mapping_size;
        const uint8_t *data;
        size_t data_size;
        uint64_t count;
    } mapped[MI_TABLE_COUNT];
    const uint8_t *objects;
    size_t object_count;
    const uint8_t *links;
    size_t link_count;
    const uint8_t *forks;
    size_t fork_count;
    const uint8_t *extents;
    size_t extent_count;
    const uint8_t *strings;
    size_t strings_size;
    const uint8_t *physical;
    size_t physical_count;
};

struct MetadataIndexSequentialMeter {
    const MetadataIndexReader *reader;
    MetadataIndexSequentialStats stats;
    uint64_t last_range_end;
    size_t next_physical_row;
    size_t *active_rows;
    size_t active_count;
    size_t active_capacity;
    uint64_t *extent_covered_bytes;
    uint32_t *fork_completed_extents;
    uint8_t *fork_touched;
    int have_range;
};

static uint32_t g_crc_table[256];
static int g_crc_ready;

static void mi_crc_init(void)
{
    uint32_t i;
    if (g_crc_ready) return;
    for (i = 0; i < 256U; ++i) {
        uint32_t value = i;
        unsigned bit;
        for (bit = 0; bit < 8U; ++bit)
            value = (value >> 1) ^ ((value & 1U) ? 0xEDB88320U : 0U);
        g_crc_table[i] = value;
    }
    g_crc_ready = 1;
}

static uint32_t mi_crc_update(uint32_t crc, const void *data, size_t size)
{
    const uint8_t *p = (const uint8_t *)data;
    size_t i;
    mi_crc_init();
    for (i = 0; i < size; ++i)
        crc = (crc >> 8) ^ g_crc_table[(crc ^ p[i]) & 0xffU];
    return crc;
}

static uint32_t mi_crc(const void *data, size_t size)
{
    return mi_crc_update(0xffffffffU, data, size) ^ 0xffffffffU;
}

static void mi_put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
}

static void mi_put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void mi_put64(uint8_t *p, uint64_t v)
{
    mi_put32(p, (uint32_t)v); mi_put32(p + 4, (uint32_t)(v >> 32));
}

static uint16_t mi_get16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t mi_get32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t mi_get64(const uint8_t *p)
{
    return (uint64_t)mi_get32(p) | ((uint64_t)mi_get32(p + 4) << 32);
}

static int mi_add_u64(uint64_t a, uint64_t b, uint64_t *out)
{
    if (UINT64_MAX - a < b) { errno = EOVERFLOW; return -1; }
    *out = a + b;
    return 0;
}

static int mi_path(char *out, size_t capacity, const char *a, const char *b)
{
    int n = snprintf(out, capacity, "%s/%s", a, b);
    if (n < 0 || (size_t)n >= capacity) { errno = ENAMETOOLONG; return -1; }
    return 0;
}

static int mi_mkdir_one(const char *path)
{
    struct stat st;
    if (mkdir(path, 0755) == 0) return 0;
    if (errno != EEXIST) return -1;
    if (stat(path, &st) != 0) return -1;
    if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
    return 0;
}

static int mi_writer_continue(MetadataIndexWriter *w, const char *path)
{
    if (w != NULL && w->options.stop_requested != NULL &&
        w->options.stop_requested(w->options.context)) {
        errno = ECANCELED;
        return 0;
    }
    if (path != NULL && w != NULL && w->options.path_write_allowed != NULL &&
        !w->options.path_write_allowed(path, w->options.context)) {
        errno = ENODEV;
        return 0;
    }
    return 1;
}

static int mi_writer_finalize_path(MetadataIndexWriter *w, const char *path)
{
    if (w == NULL || path == NULL || w->options.finalize_path == NULL) return 0;
    if (!w->options.finalize_path(path, w->options.context)) {
        errno = EACCES;
        return -1;
    }
    return 0;
}

static int mi_fsync_dir(const char *path)
{
    int fd = open(path, O_RDONLY);
    int result;
    if (fd < 0) return -1;
    result = fsync(fd);
    if (result != 0 && (errno == EINVAL || errno == ENOTSUP)) result = 0;
    if (close(fd) != 0 && result == 0) result = -1;
    return result;
}

static void mi_encode_identity(uint8_t out[MI_VOLUME_ROW_SIZE],
                               const MetadataIndexVolumeIdentity *id)
{
    memset(out, 0, MI_VOLUME_ROW_SIZE);
    mi_put32(out, id->backend_kind);
    mi_put32(out + 4, id->block_size);
    mi_put64(out + 8, id->source_size);
    mi_put64(out + 16, id->container_offset);
    mi_put64(out + 24, id->volume_offset);
    mi_put64(out + 32, id->volume_size);
    mi_put64(out + 40, id->identity_primary);
    mi_put64(out + 48, id->identity_secondary);
    memcpy(out + 56, id->uuid, 16);
}

static void mi_decode_identity(MetadataIndexVolumeIdentity *id, const uint8_t *in)
{
    memset(id, 0, sizeof(*id));
    id->backend_kind = mi_get32(in);
    id->block_size = mi_get32(in + 4);
    id->source_size = mi_get64(in + 8);
    id->container_offset = mi_get64(in + 16);
    id->volume_offset = mi_get64(in + 24);
    id->volume_size = mi_get64(in + 32);
    id->identity_primary = mi_get64(in + 40);
    id->identity_secondary = mi_get64(in + 48);
    memcpy(id->uuid, in + 56, 16);
}

static void mi_identity_hash(uint8_t out[16], const MetadataIndexVolumeIdentity *id)
{
    uint8_t encoded[MI_VOLUME_ROW_SIZE];
    uint32_t crc;
    mi_encode_identity(encoded, id);
    crc = mi_crc(encoded, sizeof(encoded));
    mi_put32(out, crc);
    mi_put32(out + 4, crc ^ 0xa5a5a5a5U);
    mi_put32(out + 8, mi_crc(encoded + 8, sizeof(encoded) - 8));
    mi_put32(out + 12, mi_crc(encoded, sizeof(encoded) - 16));
}

static int mi_identity_equal(
    const MetadataIndexVolumeIdentity *left,
    const MetadataIndexVolumeIdentity *right)
{
    return left != NULL && right != NULL &&
           left->backend_kind == right->backend_kind &&
           left->block_size == right->block_size &&
           left->source_size == right->source_size &&
           left->container_offset == right->container_offset &&
           left->volume_offset == right->volume_offset &&
           left->volume_size == right->volume_size &&
           left->identity_primary == right->identity_primary &&
           left->identity_secondary == right->identity_secondary &&
           memcmp(left->uuid, right->uuid, sizeof(left->uuid)) == 0;
}

static void mi_make_header(uint8_t out[MI_HEADER_SIZE], MiTableKind kind,
                           uint64_t count, uint64_t generation,
                           uint32_t backend, const uint8_t hash[16],
                           uint32_t data_crc)
{
    memset(out, 0, MI_HEADER_SIZE);
    memcpy(out, g_tables[kind].magic, 8);
    mi_put16(out + 8, METADATA_INDEX_FORMAT_VERSION);
    mi_put16(out + 10, MI_HEADER_SIZE);
    mi_put32(out + 12, g_tables[kind].row_size);
    mi_put64(out + 16, count);
    mi_put64(out + 24, generation);
    mi_put32(out + 32, backend);
    memcpy(out + 40, hash, 16);
    mi_put32(out + 56, data_crc);
    mi_put32(out + 60, mi_crc(out, 60));
}

static int mi_write_data(MiOutputTable *table, const void *data, size_t size,
                         int increment_count)
{
    if (size != 0 && fwrite(data, 1, size, table->file) != size) return -1;
    table->data_crc = mi_crc_update(table->data_crc, data, size);
    if (UINT64_MAX - table->data_bytes < size) { errno = EOVERFLOW; return -1; }
    table->data_bytes += size;
    if (increment_count) {
        if (table->count == UINT64_MAX) { errno = EOVERFLOW; return -1; }
        ++table->count;
    }
    return 0;
}

static int mi_finish_table(MetadataIndexWriter *w, MiTableKind kind)
{
    uint8_t header[MI_HEADER_SIZE];
    MiOutputTable *t = &w->table[kind];
    uint32_t data_crc;
    if (t->file == NULL) return 0;
    data_crc = t->data_crc ^ 0xffffffffU;
    mi_make_header(header, kind,
                   kind == MI_TABLE_STRINGS ? t->data_bytes : t->count,
                   w->generation,
                   w->identity.backend_kind, w->identity_hash, data_crc);
    if (fseek(t->file, 0, SEEK_SET) != 0 ||
        fwrite(header, 1, sizeof(header), t->file) != sizeof(header) ||
        fflush(t->file) != 0 || fsync(fileno(t->file)) != 0 || fclose(t->file) != 0) {
        t->file = NULL;
        return -1;
    }
    t->file = NULL;
    {
        char path[PATH_MAX];
        if (mi_path(path, sizeof(path), w->temp_dir, g_tables[kind].name) != 0 ||
            mi_writer_finalize_path(w, path) != 0) return -1;
    }
    return 0;
}

static uint64_t mi_next_generation(const char *index_dir)
{
    DIR *dir = opendir(index_dir);
    struct dirent *entry;
    uint64_t highest = 0;
    if (dir == NULL) return 1;
    while ((entry = readdir(dir)) != NULL) {
        unsigned long long value;
        char tail;
        if (sscanf(entry->d_name, "g%6llu%c", &value, &tail) == 1 && value > highest)
            highest = (uint64_t)value;
    }
    closedir(dir);
    return highest == UINT64_MAX ? 0 : highest + 1;
}

int metadata_index_writer_create_with_options(
    const char *index_dir,
    const MetadataIndexVolumeIdentity *identity,
    const MetadataIndexWriterOptions *options,
    MetadataIndexWriter **writer_out)
{
    MetadataIndexWriter *w;
    size_t i;
    uint8_t volume[MI_VOLUME_ROW_SIZE];
    if (index_dir == NULL || index_dir[0] == '\0' || identity == NULL ||
        writer_out == NULL || identity->backend_kind == METADATA_INDEX_BACKEND_NONE) {
        errno = EINVAL; return -1;
    }
    *writer_out = NULL;
    w = (MetadataIndexWriter *)calloc(1, sizeof(*w));
    if (w == NULL) return -1;
    if (strlen(index_dir) >= sizeof(w->index_dir)) { free(w); errno = ENAMETOOLONG; return -1; }
    strcpy(w->index_dir, index_dir);
    w->identity = *identity;
    if (options != NULL) w->options = *options;
    if (!mi_writer_continue(w, index_dir) || mi_mkdir_one(index_dir) != 0 ||
        mi_writer_finalize_path(w, index_dir) != 0) { free(w); return -1; }
    mi_identity_hash(w->identity_hash, identity);
    w->generation = mi_next_generation(index_dir);
    if (w->generation == 0 || w->generation > 999999ULL ||
        snprintf(
            w->temp_dir,
            sizeof(w->temp_dir),
            "%s/.g%06llu.tmp.%ld",
            index_dir,
            (unsigned long long)w->generation,
            (long)getpid()) >= (int)sizeof(w->temp_dir) ||
        snprintf(w->final_dir, sizeof(w->final_dir), "%s/g%06llu", index_dir,
                 (unsigned long long)w->generation) >= (int)sizeof(w->final_dir)) {
        free(w); errno = EOVERFLOW; return -1;
    }
    if (!mi_writer_continue(w, w->temp_dir) || mkdir(w->temp_dir, 0755) != 0 ||
        mi_writer_finalize_path(w, w->temp_dir) != 0) {
        (void)rmdir(w->temp_dir);
        free(w);
        return -1;
    }
    for (i = 0; i < MI_TABLE_COUNT; ++i) {
        char path[PATH_MAX];
        uint8_t blank[MI_HEADER_SIZE] = {0};
        if (mi_path(path, sizeof(path), w->temp_dir, g_tables[i].name) != 0) goto fail;
        if (!mi_writer_continue(w, path)) goto fail;
        w->table[i].file = fopen(path, "w+b");
        w->table[i].data_crc = 0xffffffffU;
        if (w->table[i].file == NULL ||
            fwrite(blank, 1, sizeof(blank), w->table[i].file) != sizeof(blank)) goto fail;
    }
    mi_encode_identity(volume, identity);
    if (mi_write_data(&w->table[MI_TABLE_VOLUME], volume, sizeof(volume), 1) != 0) goto fail;
    *writer_out = w;
    return 0;
fail:
    metadata_index_writer_abort(w);
    return -1;
}

int metadata_index_writer_create(
    const char *index_dir,
    const MetadataIndexVolumeIdentity *identity,
    MetadataIndexWriter **writer_out)
{
    return metadata_index_writer_create_with_options(
        index_dir,
        identity,
        NULL,
        writer_out
    );
}

int metadata_index_writer_append_string(MetadataIndexWriter *w, const void *utf8,
                                        uint32_t length, uint64_t *offset_out)
{
    MiOutputTable *t;
    if (w == NULL || offset_out == NULL || (length != 0 && utf8 == NULL)) { errno = EINVAL; return -1; }
    if (!mi_writer_continue(w, w->temp_dir)) return -1;
    t = &w->table[MI_TABLE_STRINGS];
    *offset_out = t->data_bytes;
    return mi_write_data(t, utf8, length, 0);
}

int metadata_index_writer_append_object(MetadataIndexWriter *w, const MetadataIndexObject *r)
{
    uint8_t b[MI_OBJECT_ROW_SIZE];
    if (w == NULL || r == NULL || (w->have_object && r->object_key <= w->last_object_key)) { errno = EINVAL; return -1; }
    if (!mi_writer_continue(w, w->temp_dir)) return -1;
    memset(b, 0, sizeof(b));
    mi_put64(b, r->object_key); mi_put32(b + 8, r->best_link_row);
    mi_put32(b + 12, r->first_fork_row); mi_put32(b + 16, r->fork_count);
    mi_put32(b + 20, r->flags); mi_put64(b + 24, r->source_reference);
    mi_put64(b + 32, r->create_time); mi_put64(b + 40, r->modify_time);
    if (mi_write_data(&w->table[MI_TABLE_OBJECTS], b, sizeof(b), 1) != 0) return -1;
    w->last_object_key = r->object_key; w->have_object = 1; return 0;
}

int metadata_index_writer_append_link(MetadataIndexWriter *w, const MetadataIndexLink *r)
{
    uint8_t b[MI_LINK_ROW_SIZE];
    if (w == NULL || r == NULL || (w->have_link && r->link_key <= w->last_link_key)) { errno = EINVAL; return -1; }
    if (!mi_writer_continue(w, w->temp_dir)) return -1;
    memset(b, 0, sizeof(b));
    mi_put64(b, r->link_key); mi_put64(b + 8, r->object_key);
    mi_put64(b + 16, r->parent_object_key); mi_put64(b + 24, r->string_offset);
    mi_put32(b + 32, r->string_length); b[36] = r->namespace_kind;
    b[37] = r->flags; b[38] = r->provenance; b[39] = r->confidence;
    if (mi_write_data(&w->table[MI_TABLE_LINKS], b, sizeof(b), 1) != 0) return -1;
    w->last_link_key = r->link_key; w->have_link = 1; return 0;
}

int metadata_index_writer_append_fork(MetadataIndexWriter *w, const MetadataIndexFork *r)
{
    uint8_t b[MI_FORK_ROW_SIZE];
    if (w == NULL || r == NULL || (w->have_fork &&
        (r->object_key < w->last_fork_object ||
         (r->object_key == w->last_fork_object && r->fork_kind <= w->last_fork_kind)))) {
        errno = EINVAL; return -1;
    }
    if (!mi_writer_continue(w, w->temp_dir)) return -1;
    memset(b, 0, sizeof(b)); mi_put64(b, r->object_key);
    mi_put64(b + 8, r->logical_size); mi_put64(b + 16, r->allocated_size);
    mi_put64(b + 24, r->first_extent_row); mi_put32(b + 32, r->extent_count);
    mi_put16(b + 36, r->fork_kind); mi_put16(b + 38, r->flags);
    if (mi_write_data(&w->table[MI_TABLE_FORKS], b, sizeof(b), 1) != 0) return -1;
    w->last_fork_object = r->object_key; w->last_fork_kind = r->fork_kind; w->have_fork = 1;
    return 0;
}

int metadata_index_writer_append_extent(MetadataIndexWriter *w, const MetadataIndexExtent *r)
{
    uint8_t b[MI_EXTENT_ROW_SIZE];
    if (w == NULL || r == NULL || r->byte_length == 0) { errno = EINVAL; return -1; }
    if (!mi_writer_continue(w, w->temp_dir)) return -1;
    mi_put64(b, r->physical_start); mi_put64(b + 8, r->logical_start);
    mi_put64(b + 16, r->byte_length);
    if (mi_write_data(&w->table[MI_TABLE_EXTENTS], b, sizeof(b), 1) != 0) return -1;
    return 0;
}

static int mi_read_writer_rows(MetadataIndexWriter *w, MiTableKind kind,
                               uint8_t **bytes_out, size_t *size_out)
{
    MiOutputTable *t = &w->table[kind];
    size_t size;
    uint8_t *bytes = NULL;
    if (t->data_bytes > SIZE_MAX) { errno = EOVERFLOW; return -1; }
    size = (size_t)t->data_bytes;
    if (size != 0) {
        bytes = (uint8_t *)malloc(size);
        if (bytes == NULL) return -1;
        if (fflush(t->file) != 0 || fseek(t->file, MI_HEADER_SIZE, SEEK_SET) != 0 ||
            fread(bytes, 1, size, t->file) != size) { free(bytes); return -1; }
    }
    *bytes_out = bytes; *size_out = size; return 0;
}

static size_t mi_object_lower_bytes(const uint8_t *objects, size_t count, uint64_t key)
{
    size_t lo = 0, hi = count;
    while (lo < hi) { size_t mid = lo + (hi - lo) / 2; if (mi_get64(objects + mid * MI_OBJECT_ROW_SIZE) < key) lo = mid + 1; else hi = mid; }
    return lo;
}

static int mi_child_compare(const void *a, const void *b)
{
    const MiChildRow *x = (const MiChildRow *)a, *y = (const MiChildRow *)b;
    if (x->parent_key != y->parent_key) return x->parent_key < y->parent_key ? -1 : 1;
    if (x->link_row != y->link_row) return x->link_row < y->link_row ? -1 : 1;
    return x->child_row < y->child_row ? -1 : x->child_row != y->child_row;
}

static int mi_physical_compare(const void *a, const void *b)
{
    const MiPhysicalRow *x = (const MiPhysicalRow *)a, *y = (const MiPhysicalRow *)b;
    if (x->start != y->start) return x->start < y->start ? -1 : 1;
    if (x->end != y->end) return x->end < y->end ? -1 : 1;
    if (x->fork_row != y->fork_row) return x->fork_row < y->fork_row ? -1 : 1;
    return x->extent_ordinal < y->extent_ordinal ? -1 : x->extent_ordinal != y->extent_ordinal;
}

/* Max end for the implicit balanced interval-tree rooted at each midpoint. */
static uint64_t mi_set_subtree_max(MiPhysicalRow *rows, size_t lo, size_t hi)
{
    size_t mid;
    uint64_t maximum;
    if (lo >= hi) return 0;
    mid = lo + (hi - lo) / 2;
    maximum = rows[mid].end;
    if (lo < mid) {
        uint64_t left = mi_set_subtree_max(rows, lo, mid);
        if (left > maximum) maximum = left;
    }
    if (mid + 1 < hi) {
        uint64_t right = mi_set_subtree_max(rows, mid + 1, hi);
        if (right > maximum) maximum = right;
    }
    rows[mid].subtree_max_end = maximum;
    return maximum;
}

static int mi_build_derived(MetadataIndexWriter *w)
{
    uint8_t *objects = NULL, *links = NULL, *forks = NULL, *extents = NULL;
    size_t os = 0, ls = 0, fs = 0, es = 0, i, physical_count = 0;
    size_t object_count, link_count, fork_count, extent_count;
    MiChildRow *children = NULL;
    MiPhysicalRow *physical = NULL;
    int result = -1;
    if (mi_read_writer_rows(w, MI_TABLE_OBJECTS, &objects, &os) != 0 ||
        mi_read_writer_rows(w, MI_TABLE_LINKS, &links, &ls) != 0 ||
        mi_read_writer_rows(w, MI_TABLE_FORKS, &forks, &fs) != 0 ||
        mi_read_writer_rows(w, MI_TABLE_EXTENTS, &extents, &es) != 0) goto done;
    object_count = os / MI_OBJECT_ROW_SIZE; link_count = ls / MI_LINK_ROW_SIZE;
    fork_count = fs / MI_FORK_ROW_SIZE; extent_count = es / MI_EXTENT_ROW_SIZE;
    if (object_count > UINT32_MAX || link_count > UINT32_MAX || fork_count > UINT32_MAX) {
        errno = EOVERFLOW; goto done;
    }
    if (link_count != 0) { children = (MiChildRow *)calloc(link_count, sizeof(*children)); if (children == NULL) goto done; }
    for (i = 0; i < link_count; ++i) {
        const uint8_t *l = links + i * MI_LINK_ROW_SIZE;
        uint64_t object_key = mi_get64(l + 8), parent = mi_get64(l + 16);
        uint64_t string_offset = mi_get64(l + 24), string_end;
        size_t child = mi_object_lower_bytes(objects, object_count, object_key);
        if (child == object_count || mi_get64(objects + child * MI_OBJECT_ROW_SIZE) != object_key ||
            mi_add_u64(string_offset, mi_get32(l + 32), &string_end) != 0 ||
            string_end > w->table[MI_TABLE_STRINGS].data_bytes || i > UINT32_MAX || child > UINT32_MAX) {
            errno = EINVAL; goto done;
        }
        children[i].parent_key = parent; children[i].link_row = (uint32_t)i;
        children[i].child_row = (uint32_t)child;
    }
    qsort(children, link_count, sizeof(*children), mi_child_compare);
    for (i = 0; i < object_count; ++i) {
        const uint8_t *o = objects + i * MI_OBJECT_ROW_SIZE;
        uint32_t best = mi_get32(o + 8), first = mi_get32(o + 12), count = mi_get32(o + 16);
        uint64_t end;
        if ((best != METADATA_INDEX_NO_ROW && best >= link_count) ||
            (count == 0 && first != METADATA_INDEX_NO_ROW) ||
            (count != 0 &&
             (first == METADATA_INDEX_NO_ROW ||
              mi_add_u64(first, count, &end) != 0 || end > fork_count))) {
            errno = EINVAL;
            goto done;
        }
        if (best != METADATA_INDEX_NO_ROW && mi_get64(links + (size_t)best * MI_LINK_ROW_SIZE + 8) != mi_get64(o)) { errno = EINVAL; goto done; }
        if (count != 0) {
            uint32_t fork_offset;
            for (fork_offset = 0U; fork_offset < count; ++fork_offset) {
                const uint8_t *fork =
                    forks + ((size_t)first + fork_offset) * MI_FORK_ROW_SIZE;
                if (mi_get64(fork) != mi_get64(o)) { errno = EINVAL; goto done; }
            }
        }
    }
    for (i = 0; i < fork_count; ++i) {
        const uint8_t *f = forks + i * MI_FORK_ROW_SIZE;
        uint64_t first = mi_get64(f + 24), end;
        uint32_t count = mi_get32(f + 32), j;
        uint64_t previous_logical = 0;
        size_t object_row = mi_object_lower_bytes(
            objects,
            object_count,
            mi_get64(f)
        );
        if (!mi_writer_continue(w, w->temp_dir)) goto done;
        if (object_row >= object_count ||
            mi_get64(objects + object_row * MI_OBJECT_ROW_SIZE) != mi_get64(f) ||
            first > SIZE_MAX || mi_add_u64(first, count, &end) != 0 ||
            end > extent_count) { errno = EINVAL; goto done; }
        for (j = 0; j < count; ++j) {
            const uint8_t *e = extents + ((size_t)first + j) * MI_EXTENT_ROW_SIZE;
            uint64_t physical_start = mi_get64(e), logical = mi_get64(e + 8), length = mi_get64(e + 16), physical_end;
            if (length == 0 || (j != 0 && logical < previous_logical)) { errno = EINVAL; goto done; }
            previous_logical = logical;
            if (physical_start != METADATA_INDEX_SPARSE_OFFSET) {
                if (mi_add_u64(physical_start, length, &physical_end) != 0) goto done;
                ++physical_count;
            }
        }
    }
    if (physical_count != 0) { physical = (MiPhysicalRow *)calloc(physical_count, sizeof(*physical)); if (physical == NULL) goto done; }
    physical_count = 0;
    for (i = 0; i < fork_count; ++i) {
        const uint8_t *f = forks + i * MI_FORK_ROW_SIZE;
        uint64_t first = mi_get64(f + 24); uint32_t count = mi_get32(f + 32), j;
        if (!mi_writer_continue(w, w->temp_dir)) goto done;
        for (j = 0; j < count; ++j) {
            const uint8_t *e = extents + ((size_t)first + j) * MI_EXTENT_ROW_SIZE;
            if (mi_get64(e) == METADATA_INDEX_SPARSE_OFFSET) continue;
            physical[physical_count].start = mi_get64(e);
            if (mi_add_u64(physical[physical_count].start, mi_get64(e + 16), &physical[physical_count].end) != 0) goto done;
            physical[physical_count].fork_row = (uint32_t)i;
            physical[physical_count].extent_ordinal = j;
            ++physical_count;
        }
    }
    qsort(physical, physical_count, sizeof(*physical), mi_physical_compare);
    (void)mi_set_subtree_max(physical, 0, physical_count);
    for (i = 0; i < physical_count; ++i) {
        uint8_t b[MI_PHYSICAL_ROW_SIZE];
        if ((i & 1023U) == 0U && !mi_writer_continue(w, w->temp_dir)) goto done;
        mi_put64(b, physical[i].start); mi_put64(b + 8, physical[i].end);
        mi_put64(b + 16, physical[i].subtree_max_end); mi_put32(b + 24, physical[i].fork_row);
        mi_put32(b + 28, physical[i].extent_ordinal);
        if (mi_write_data(&w->table[MI_TABLE_PHYSICAL], b, sizeof(b), 1) != 0) goto done;
    }
    for (i = 0; i < link_count; ++i) {
        uint8_t b[MI_CHILD_ROW_SIZE];
        if ((i & 1023U) == 0U && !mi_writer_continue(w, w->temp_dir)) goto done;
        mi_put64(b, children[i].parent_key); mi_put32(b + 8, children[i].link_row);
        mi_put32(b + 12, children[i].child_row);
        if (mi_write_data(&w->table[MI_TABLE_CHILDREN], b, sizeof(b), 1) != 0) goto done;
    }
    result = 0;
done:
    free(objects); free(links); free(forks); free(extents); free(children); free(physical);
    return result;
}

static int mi_publish_manifest(MetadataIndexWriter *w)
{
    uint8_t m[MI_MANIFEST_SIZE] = {0};
    char temp[PATH_MAX], final[PATH_MAX];
    FILE *file;
    memcpy(m, "CVMIMAN1", 8); mi_put16(m + 8, METADATA_INDEX_FORMAT_VERSION);
    mi_put16(m + 10, MI_MANIFEST_SIZE); mi_put64(m + 16, w->generation);
    mi_put32(m + 24, w->identity.backend_kind); memcpy(m + 32, w->identity_hash, 16);
    mi_put32(m + 60, mi_crc(m, 60));
    if (snprintf(
            temp,
            sizeof(temp),
            "%s/manifest.bin.tmp.%ld",
            w->index_dir,
            (long)getpid()) >= (int)sizeof(temp) ||
        mi_path(final, sizeof(final), w->index_dir, "manifest.bin") != 0) return -1;
    if (!mi_writer_continue(w, temp)) return -1;
    file = fopen(temp, "wb");
    if (file == NULL) return -1;
    if (fwrite(m, 1, sizeof(m), file) != sizeof(m) || fflush(file) != 0 ||
        fsync(fileno(file)) != 0) { fclose(file); unlink(temp); return -1; }
    if (fclose(file) != 0 || mi_writer_finalize_path(w, temp) != 0) {
        unlink(temp);
        return -1;
    }
    if (!mi_writer_continue(w, final) || rename(temp, final) != 0) {
        unlink(temp);
        return -1;
    }
    (void)mi_fsync_dir(w->index_dir);
    return 0;
}

int metadata_index_writer_commit(MetadataIndexWriter *w)
{
    size_t i;
    int saved;
    if (w == NULL) { errno = EINVAL; return -1; }
    if (mi_build_derived(w) != 0) goto fail;
    for (i = 0; i < MI_TABLE_COUNT; ++i) if (mi_finish_table(w, (MiTableKind)i) != 0) goto fail;
    if (!mi_writer_continue(w, w->final_dir) ||
        mi_fsync_dir(w->temp_dir) != 0 || rename(w->temp_dir, w->final_dir) != 0 ||
        mi_fsync_dir(w->index_dir) != 0 || mi_publish_manifest(w) != 0) goto fail;
    free(w); return 0;
fail:
    saved = errno; metadata_index_writer_abort(w); errno = saved; return -1;
}

void metadata_index_writer_abort(MetadataIndexWriter *w)
{
    size_t i;
    if (w == NULL) return;
    for (i = 0; i < MI_TABLE_COUNT; ++i) {
        char path[PATH_MAX];
        if (w->table[i].file != NULL) fclose(w->table[i].file);
        if (w->temp_dir[0] != '\0' && mi_path(path, sizeof(path), w->temp_dir, g_tables[i].name) == 0) unlink(path);
    }
    if (w->temp_dir[0] != '\0') rmdir(w->temp_dir);
    free(w);
}

static int mi_read_manifest(const char *dir, uint64_t *generation, uint8_t hash[16], uint32_t *backend)
{
    char path[PATH_MAX]; uint8_t m[MI_MANIFEST_SIZE]; FILE *f;
    if (mi_path(path, sizeof(path), dir, "manifest.bin") != 0) return -1;
    f = fopen(path, "rb"); if (f == NULL) return -1;
    if (fread(m, 1, sizeof(m), f) != sizeof(m) || fgetc(f) != EOF) { fclose(f); errno = EINVAL; return -1; }
    if (fclose(f) != 0) return -1;
    if (memcmp(m, "CVMIMAN1", 8) != 0 || mi_get16(m + 8) != METADATA_INDEX_FORMAT_VERSION ||
        mi_get16(m + 10) != MI_MANIFEST_SIZE || mi_get32(m + 60) != mi_crc(m, 60)) { errno = EINVAL; return -1; }
    *generation = mi_get64(m + 16); *backend = mi_get32(m + 24); memcpy(hash, m + 32, 16); return 0;
}

static int mi_read_generation_volume_header(
    const char *index_dir,
    uint64_t generation,
    uint8_t hash[16],
    uint32_t *backend)
{
    char generation_dir[PATH_MAX];
    char path[PATH_MAX];
    uint8_t header[MI_HEADER_SIZE];
    FILE *file;

    if (index_dir == NULL || hash == NULL || backend == NULL || generation == 0U ||
        snprintf(generation_dir, sizeof(generation_dir), "%s/g%06llu", index_dir,
                 (unsigned long long)generation) >= (int)sizeof(generation_dir) ||
        mi_path(path, sizeof(path), generation_dir,
                g_tables[MI_TABLE_VOLUME].name) != 0) {
        errno = EINVAL;
        return -1;
    }
    file = fopen(path, "rb");
    if (file == NULL) return -1;
    if (fread(header, 1, sizeof(header), file) != sizeof(header)) {
        (void)fclose(file);
        errno = EINVAL;
        return -1;
    }
    if (fclose(file) != 0) return -1;
    if (memcmp(header, g_tables[MI_TABLE_VOLUME].magic, 8) != 0 ||
        mi_get16(header + 8) != METADATA_INDEX_FORMAT_VERSION ||
        mi_get16(header + 10) != MI_HEADER_SIZE ||
        mi_get32(header + 12) != MI_VOLUME_ROW_SIZE ||
        mi_get64(header + 16) != 1U ||
        mi_get64(header + 24) != generation ||
        mi_get32(header + 60) != mi_crc(header, 60)) {
        errno = EINVAL;
        return -1;
    }
    *backend = mi_get32(header + 32);
    memcpy(hash, header + 40, 16);
    return 0;
}

static int mi_map_file(
    MetadataIndexReader *reader,
    const char *dir,
    MiTableKind kind,
    uint64_t generation,
    uint32_t backend,
    const uint8_t hash[16])
{
    char path[PATH_MAX];
    struct stat status;
    const uint8_t *header;
    uint64_t count;
    uint64_t expected_data_size;
    uint64_t expected_file_size;
    int fd = -1;
    void *mapping = MAP_FAILED;

    if (reader == NULL || mi_path(path, sizeof(path), dir, g_tables[kind].name) != 0) {
        errno = EINVAL;
        return -1;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0 || fstat(fd, &status) != 0 || status.st_size < (off_t)MI_HEADER_SIZE) {
        if (fd >= 0) close(fd);
        errno = EINVAL;
        return -1;
    }
    if ((uint64_t)status.st_size > SIZE_MAX) {
        close(fd);
        errno = EOVERFLOW;
        return -1;
    }
    mapping = mmap(NULL, (size_t)status.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (close(fd) != 0 && mapping != MAP_FAILED) {
        int saved = errno;
        munmap(mapping, (size_t)status.st_size);
        errno = saved;
        return -1;
    }
    if (mapping == MAP_FAILED) return -1;

    header = (const uint8_t *)mapping;
    if (memcmp(header, g_tables[kind].magic, 8) != 0 ||
        mi_get16(header + 8) != METADATA_INDEX_FORMAT_VERSION ||
        mi_get16(header + 10) != MI_HEADER_SIZE ||
        mi_get32(header + 12) != g_tables[kind].row_size ||
        mi_get64(header + 24) != generation ||
        mi_get32(header + 32) != backend ||
        memcmp(header + 40, hash, 16) != 0 ||
        mi_get32(header + 60) != mi_crc(header, 60)) {
        munmap(mapping, (size_t)status.st_size);
        errno = EINVAL;
        return -1;
    }
    count = mi_get64(header + 16);
    if (g_tables[kind].row_size == 0U) {
        expected_data_size = count;
    } else if (count > UINT64_MAX / g_tables[kind].row_size) {
        munmap(mapping, (size_t)status.st_size);
        errno = EOVERFLOW;
        return -1;
    } else {
        expected_data_size = count * g_tables[kind].row_size;
    }
    if (mi_add_u64(MI_HEADER_SIZE, expected_data_size, &expected_file_size) != 0 ||
        expected_file_size != (uint64_t)status.st_size ||
        expected_data_size > SIZE_MAX ||
        mi_get32(header + 56) !=
            mi_crc(header + MI_HEADER_SIZE, (size_t)expected_data_size)) {
        munmap(mapping, (size_t)status.st_size);
        errno = EINVAL;
        return -1;
    }
    reader->mapped[kind].mapping = mapping;
    reader->mapped[kind].mapping_size = (size_t)status.st_size;
    reader->mapped[kind].data = header + MI_HEADER_SIZE;
    reader->mapped[kind].data_size = (size_t)expected_data_size;
    reader->mapped[kind].count = count;
    return 0;
}

static void mi_decode_object(MetadataIndexObject *r, const uint8_t *b)
{
    r->object_key = mi_get64(b); r->best_link_row = mi_get32(b + 8);
    r->first_fork_row = mi_get32(b + 12); r->fork_count = mi_get32(b + 16);
    r->flags = mi_get32(b + 20); r->source_reference = mi_get64(b + 24);
    r->create_time = mi_get64(b + 32); r->modify_time = mi_get64(b + 40);
}

static void mi_decode_link(MetadataIndexLink *r, const uint8_t *b)
{
    r->link_key = mi_get64(b); r->object_key = mi_get64(b + 8); r->parent_object_key = mi_get64(b + 16);
    r->string_offset = mi_get64(b + 24); r->string_length = mi_get32(b + 32);
    r->namespace_kind = b[36]; r->flags = b[37]; r->provenance = b[38]; r->confidence = b[39];
}

static void mi_decode_fork(MetadataIndexFork *r, const uint8_t *b)
{
    r->object_key = mi_get64(b); r->logical_size = mi_get64(b + 8); r->allocated_size = mi_get64(b + 16);
    r->first_extent_row = mi_get64(b + 24); r->extent_count = mi_get32(b + 32);
    r->fork_kind = mi_get16(b + 36); r->flags = mi_get16(b + 38);
}

static void mi_decode_extent(MetadataIndexExtent *r, const uint8_t *b)
{
    r->physical_start = mi_get64(b); r->logical_start = mi_get64(b + 8); r->byte_length = mi_get64(b + 16);
}

static int mi_reader_open_generation_internal(
    const char *index_dir,
    uint64_t generation,
    uint32_t backend,
    const uint8_t hash[16],
    const MetadataIndexVolumeIdentity *expected,
    MetadataIndexReader **out)
{
    MetadataIndexReader *r = NULL;
    char generation_dir[PATH_MAX];
    if (index_dir == NULL || out == NULL) { errno = EINVAL; return -1; } *out = NULL;
    if (snprintf(generation_dir, sizeof(generation_dir), "%s/g%06llu", index_dir,
                 (unsigned long long)generation) >= (int)sizeof(generation_dir)) { errno = ENAMETOOLONG; return -1; }
    r = (MetadataIndexReader *)calloc(1, sizeof(*r)); if (r == NULL) return -1; r->generation = generation;
    if (mi_map_file(r, generation_dir, MI_TABLE_VOLUME, generation, backend, hash) != 0 ||
        r->mapped[MI_TABLE_VOLUME].count != 1U ||
        r->mapped[MI_TABLE_VOLUME].data_size != MI_VOLUME_ROW_SIZE) goto fail;
    mi_decode_identity(&r->identity, r->mapped[MI_TABLE_VOLUME].data);
    if (r->identity.backend_kind != backend) { errno = EINVAL; goto fail; }
    { uint8_t actual[16]; mi_identity_hash(actual, &r->identity); if (memcmp(actual, hash, 16) != 0) { errno = EINVAL; goto fail; } }
    if (expected != NULL && !mi_identity_equal(&r->identity, expected)) {
        errno = ESTALE;
        goto fail;
    }
    if (mi_map_file(r, generation_dir, MI_TABLE_OBJECTS, generation, backend, hash) != 0 ||
        mi_map_file(r, generation_dir, MI_TABLE_LINKS, generation, backend, hash) != 0 ||
        mi_map_file(r, generation_dir, MI_TABLE_FORKS, generation, backend, hash) != 0 ||
        mi_map_file(r, generation_dir, MI_TABLE_EXTENTS, generation, backend, hash) != 0 ||
        mi_map_file(r, generation_dir, MI_TABLE_STRINGS, generation, backend, hash) != 0 ||
        mi_map_file(r, generation_dir, MI_TABLE_PHYSICAL, generation, backend, hash) != 0 ||
        mi_map_file(r, generation_dir, MI_TABLE_CHILDREN, generation, backend, hash) != 0) goto fail;
    if (r->mapped[MI_TABLE_OBJECTS].count > SIZE_MAX ||
        r->mapped[MI_TABLE_LINKS].count > SIZE_MAX ||
        r->mapped[MI_TABLE_FORKS].count > SIZE_MAX ||
        r->mapped[MI_TABLE_EXTENTS].count > SIZE_MAX ||
        r->mapped[MI_TABLE_PHYSICAL].count > SIZE_MAX) { errno = EOVERFLOW; goto fail; }
    r->objects = r->mapped[MI_TABLE_OBJECTS].data;
    r->object_count = (size_t)r->mapped[MI_TABLE_OBJECTS].count;
    r->links = r->mapped[MI_TABLE_LINKS].data;
    r->link_count = (size_t)r->mapped[MI_TABLE_LINKS].count;
    r->forks = r->mapped[MI_TABLE_FORKS].data;
    r->fork_count = (size_t)r->mapped[MI_TABLE_FORKS].count;
    r->extents = r->mapped[MI_TABLE_EXTENTS].data;
    r->extent_count = (size_t)r->mapped[MI_TABLE_EXTENTS].count;
    r->strings = r->mapped[MI_TABLE_STRINGS].data;
    r->strings_size = r->mapped[MI_TABLE_STRINGS].data_size;
    r->physical = r->mapped[MI_TABLE_PHYSICAL].data;
    r->physical_count = (size_t)r->mapped[MI_TABLE_PHYSICAL].count;
    *out = r; return 0;
fail:
    metadata_index_reader_close(r); return -1;
}

static int mi_reader_open_internal(const char *index_dir,
                                   const MetadataIndexVolumeIdentity *expected,
                                   MetadataIndexReader **out)
{
    uint64_t generation;
    uint32_t backend;
    uint8_t hash[16];

    if (index_dir == NULL || out == NULL) { errno = EINVAL; return -1; }
    if (mi_read_manifest(index_dir, &generation, hash, &backend) != 0) return -1;
    return mi_reader_open_generation_internal(
        index_dir, generation, backend, hash, expected, out);
}

int metadata_index_reader_open(const char *index_dir, MetadataIndexReader **out)
{
    return mi_reader_open_internal(index_dir, NULL, out);
}

int metadata_index_reader_open_generation(
    const char *index_dir,
    uint64_t generation,
    MetadataIndexReader **out)
{
    uint32_t backend;
    uint8_t hash[16];

    if (out != NULL) *out = NULL;
    if (index_dir == NULL || out == NULL || generation == 0U) {
        errno = EINVAL;
        return -1;
    }
    if (mi_read_generation_volume_header(
            index_dir, generation, hash, &backend) != 0) return -1;
    return mi_reader_open_generation_internal(
        index_dir, generation, backend, hash, NULL, out);
}

int metadata_index_reader_open_expected(const char *index_dir,
                                        const MetadataIndexVolumeIdentity *expected,
                                        MetadataIndexReader **out)
{
    if (expected == NULL) { errno = EINVAL; return -1; }
    return mi_reader_open_internal(index_dir, expected, out);
}

void metadata_index_reader_close(MetadataIndexReader *r)
{
    size_t index;
    if (r == NULL) return;
    for (index = 0U; index < MI_TABLE_COUNT; ++index) {
        if (r->mapped[index].mapping != NULL &&
            r->mapped[index].mapping != MAP_FAILED) {
            (void)munmap(r->mapped[index].mapping, r->mapped[index].mapping_size);
        }
    }
    free(r);
}

const MetadataIndexVolumeIdentity *metadata_index_reader_volume(const MetadataIndexReader *r) { return r == NULL ? NULL : &r->identity; }
uint64_t metadata_index_reader_generation(const MetadataIndexReader *r) { return r == NULL ? 0 : r->generation; }

void metadata_index_reader_get_stats(
    const MetadataIndexReader *r,
    MetadataIndexStats *out)
{
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    if (r == NULL) return;
    out->object_count = r->object_count;
    out->link_count = r->link_count;
    out->fork_count = r->fork_count;
    out->extent_count = r->extent_count;
    out->physical_count = r->physical_count;
    out->string_bytes = r->strings_size;
}

int metadata_index_reader_get_layout_fingerprint(
    const MetadataIndexReader *reader,
    MetadataIndexLayoutFingerprint *out)
{
    if (reader == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->fork_count = reader->fork_count;
    out->extent_count = reader->extent_count;
    out->physical_count = reader->physical_count;
    out->forks_crc32 = mi_crc(
        reader->mapped[MI_TABLE_FORKS].data,
        reader->mapped[MI_TABLE_FORKS].data_size);
    out->extents_crc32 = mi_crc(
        reader->mapped[MI_TABLE_EXTENTS].data,
        reader->mapped[MI_TABLE_EXTENTS].data_size);
    out->physical_crc32 = mi_crc(
        reader->mapped[MI_TABLE_PHYSICAL].data,
        reader->mapped[MI_TABLE_PHYSICAL].data_size);
    return 0;
}

static size_t mi_object_lower(const MetadataIndexReader *r, uint64_t key)
{
    size_t lo = 0, hi = r->object_count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        uint64_t object_key = mi_get64(r->objects + mid * MI_OBJECT_ROW_SIZE);
        if (object_key < key) lo = mid + 1; else hi = mid;
    }
    return lo;
}

static int mi_reader_object_at(
    const MetadataIndexReader *reader,
    size_t row,
    MetadataIndexObject *out)
{
    if (reader == NULL || out == NULL || row >= reader->object_count) {
        errno = EINVAL;
        return -1;
    }
    mi_decode_object(out, reader->objects + row * MI_OBJECT_ROW_SIZE);
    return 0;
}

int metadata_index_reader_get_object(
    const MetadataIndexReader *reader,
    uint64_t object_key,
    MetadataIndexObject *object_out)
{
    size_t row;
    if (reader == NULL || object_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    row = mi_object_lower(reader, object_key);
    if (row >= reader->object_count ||
        mi_reader_object_at(reader, row, object_out) != 0 ||
        object_out->object_key != object_key) {
        memset(object_out, 0, sizeof(*object_out));
        errno = ENOENT;
        return -1;
    }
    return 0;
}

int metadata_index_reader_get_object_by_row(
    const MetadataIndexReader *reader,
    uint64_t object_row,
    MetadataIndexObject *object_out)
{
    if (object_row > SIZE_MAX) {
        if (object_out != NULL) memset(object_out, 0, sizeof(*object_out));
        errno = EINVAL;
        return -1;
    }
    return mi_reader_object_at(reader, (size_t)object_row, object_out);
}

static int mi_reader_link_at(
    const MetadataIndexReader *reader,
    size_t row,
    MetadataIndexLink *out)
{
    if (reader == NULL || out == NULL || row >= reader->link_count) {
        errno = EINVAL;
        return -1;
    }
    mi_decode_link(out, reader->links + row * MI_LINK_ROW_SIZE);
    return 0;
}

static int mi_reader_fork_at(
    const MetadataIndexReader *reader,
    size_t row,
    MetadataIndexFork *out)
{
    if (reader == NULL || out == NULL || row >= reader->fork_count) {
        errno = EINVAL;
        return -1;
    }
    mi_decode_fork(out, reader->forks + row * MI_FORK_ROW_SIZE);
    return 0;
}

int metadata_index_reader_get_fork_by_row(
    const MetadataIndexReader *reader,
    uint32_t fork_row,
    MetadataIndexFork *fork_out)
{
    return mi_reader_fork_at(reader, (size_t)fork_row, fork_out);
}

static int mi_reader_extent_at(
    const MetadataIndexReader *reader,
    size_t row,
    MetadataIndexExtent *out)
{
    if (reader == NULL || out == NULL || row >= reader->extent_count) {
        errno = EINVAL;
        return -1;
    }
    mi_decode_extent(out, reader->extents + row * MI_EXTENT_ROW_SIZE);
    return 0;
}

int metadata_index_reader_get_fork_first_physical(
    const MetadataIndexReader *reader,
    uint32_t fork_row,
    uint64_t *physical_start_out)
{
    MetadataIndexFork fork;
    uint32_t extent_ordinal;
    uint64_t best_logical = UINT64_MAX;
    uint64_t best_physical = 0U;
    int found = 0;

    if (reader == NULL || physical_start_out == NULL ||
        mi_reader_fork_at(reader, (size_t)fork_row, &fork) != 0) {
        errno = EINVAL;
        return -1;
    }
    for (extent_ordinal = 0U; extent_ordinal < fork.extent_count;
         ++extent_ordinal) {
        MetadataIndexExtent extent;
        uint64_t extent_row;

        if (mi_add_u64(fork.first_extent_row, extent_ordinal, &extent_row) != 0 ||
            extent_row >= reader->extent_count ||
            mi_reader_extent_at(reader, (size_t)extent_row, &extent) != 0) {
            errno = EINVAL;
            return -1;
        }
        if (extent.physical_start != METADATA_INDEX_SPARSE_OFFSET &&
            (!found || extent.logical_start < best_logical)) {
            best_logical = extent.logical_start;
            best_physical = extent.physical_start;
            found = 1;
        }
    }
    if (!found) {
        errno = ENOENT;
        return -1;
    }
    *physical_start_out = best_physical;
    return 0;
}

static int mi_reader_physical_at(
    const MetadataIndexReader *reader,
    size_t row,
    MiPhysicalRow *out)
{
    const uint8_t *bytes;
    if (reader == NULL || out == NULL || row >= reader->physical_count) {
        errno = EINVAL;
        return -1;
    }
    bytes = reader->physical + row * MI_PHYSICAL_ROW_SIZE;
    out->start = mi_get64(bytes);
    out->end = mi_get64(bytes + 8);
    out->subtree_max_end = mi_get64(bytes + 16);
    out->fork_row = mi_get32(bytes + 24);
    out->extent_ordinal = mi_get32(bytes + 28);
    return 0;
}

static int mi_match_from_row(const MetadataIndexReader *r, size_t physical_row,
                             const MiPhysicalRow *p,
                             MetadataIndexPhysicalMatch *out, uint64_t offset)
{
    MetadataIndexFork fork;
    MetadataIndexExtent extent;
    uint64_t extent_row, delta;
    if (p->fork_row >= r->fork_count) { errno = EINVAL; return -1; }
    if (mi_reader_fork_at(r, p->fork_row, &fork) != 0 ||
        mi_add_u64(fork.first_extent_row, p->extent_ordinal, &extent_row) != 0 ||
        extent_row >= r->extent_count ||
        mi_reader_extent_at(r, (size_t)extent_row, &extent) != 0) {
        errno = EINVAL; return -1;
    }
    delta = offset - p->start;
    if (UINT64_MAX - extent.logical_start < delta) { errno = EOVERFLOW; return -1; }
    out->object_key = fork.object_key; out->physical_row = physical_row;
    out->fork_row = p->fork_row;
    out->extent_ordinal = p->extent_ordinal; out->physical_start = p->start;
    out->physical_end = p->end; out->logical_position = extent.logical_start + delta;
    return 0;
}

typedef struct {
    size_t matches;
    size_t best_row;
    uint64_t best_length;
    uint64_t wanted_object;
    int check_object;
    int found_object;
} MiLookupState;

static void mi_query_tree(const MetadataIndexReader *r, size_t lo, size_t hi,
                          uint64_t offset, MiLookupState *state)
{
    size_t mid;
    MiPhysicalRow physical;
    MiPhysicalRow child;
    const MiPhysicalRow *p = &physical;
    if (lo >= hi) return;
    mid = lo + (hi - lo) / 2;
    if (mi_reader_physical_at(r, mid, &physical) != 0) return;
    if (lo < mid) {
        size_t left_root = lo + (mid - lo) / 2;
        if (mi_reader_physical_at(r, left_root, &child) == 0 &&
            child.subtree_max_end > offset)
            mi_query_tree(r, lo, mid, offset, state);
    }
    if (p->start <= offset && offset < p->end) {
        uint64_t length = p->end - p->start;
        if (state->matches == 0 || length < state->best_length ||
            (length == state->best_length && mid < state->best_row)) {
            state->best_length = length;
            state->best_row = mid;
        }
        ++state->matches;
        if (state->check_object) {
            MetadataIndexPhysicalMatch match;
            if (mi_match_from_row(r, mid, p, &match, offset) == 0 &&
                match.object_key == state->wanted_object)
                state->found_object = 1;
        }
    }
    if (mid + 1 < hi && p->start <= offset) {
        size_t right_root = mid + 1 + (hi - (mid + 1)) / 2;
        if (mi_reader_physical_at(r, right_root, &child) == 0 &&
            child.subtree_max_end > offset)
            mi_query_tree(r, mid + 1, hi, offset, state);
    }
}

int metadata_index_reader_lookup_physical(const MetadataIndexReader *r, uint64_t offset,
                                          MetadataIndexPhysicalMatch *best, size_t *matches_out)
{
    MiLookupState state = { 0, 0, UINT64_MAX, 0, 0, 0 };
    MiPhysicalRow physical;
    if (r == NULL || best == NULL || matches_out == NULL) { errno = EINVAL; return -1; }
    mi_query_tree(r, 0, r->physical_count, offset, &state);
    *matches_out = state.matches;
    if (state.matches == 0) { memset(best, 0, sizeof(*best)); return 0; }
    if (mi_reader_physical_at(r, state.best_row, &physical) != 0 ||
        mi_match_from_row(r, state.best_row, &physical, best, offset) != 0) return -1;
    return 1;
}

int metadata_index_reader_get_candidate_context(
    const MetadataIndexReader *reader,
    uint64_t physical_offset,
    MetadataIndexCandidateContext *context_out)
{
    MetadataIndexCandidateContext context = {0};
    size_t match_count = 0U;
    int result;

    if (reader == NULL || context_out == NULL) {
        errno = EINVAL;
        return -1;
    }
    result = metadata_index_reader_lookup_physical(
        reader,
        physical_offset,
        &context.best_match,
        &match_count);
    if (result < 0) return -1;
    context.owner_count = (uint64_t)match_count;
    context.has_owner = result == 1 && match_count > 0U;
    if (!context.has_owner) {
        *context_out = context;
        return 0;
    }
    if (metadata_index_reader_get_fork_by_row(
            reader,
            context.best_match.fork_row,
            &context.fork) != 0) {
        return -1;
    }
    context.unique_owner = match_count == 1U;
    context.complete_data_fork =
        context.unique_owner &&
        context.fork.fork_kind == METADATA_INDEX_FORK_DATA &&
        (context.fork.flags & METADATA_INDEX_FORK_FLAG_COMPLETE) != 0U &&
        context.best_match.logical_position < context.fork.logical_size;
    context.exact_file_start =
        context.complete_data_fork &&
        context.best_match.logical_position == 0U;
    *context_out = context;
    return 1;
}

int metadata_index_reader_offset_has_object(const MetadataIndexReader *r, uint64_t offset, uint64_t object_key)
{
    MiLookupState state = { 0, 0, UINT64_MAX, object_key, 1, 0 };
    if (r == NULL) { errno = EINVAL; return -1; }
    mi_query_tree(r, 0, r->physical_count, offset, &state);
    return state.found_object;
}

int metadata_index_reader_reconstruct_path(const MetadataIndexReader *r, uint64_t object_key,
                                           char *out, size_t capacity)
{
    typedef struct { const uint8_t *name; uint32_t length; } Part;
    Part *parts = NULL; size_t count = 0, allocated = 0, used = 0, i; uint64_t current = object_key;
    if (r == NULL || out == NULL || capacity == 0) { errno = EINVAL; return -1; }
    while (current != 0 && count < MI_MAX_PATH_DEPTH) {
        size_t row = mi_object_lower(r, current);
        MetadataIndexObject object;
        MetadataIndexLink link;
        uint64_t string_end;
        if (row >= r->object_count || mi_reader_object_at(r, row, &object) != 0 ||
            object.object_key != current) { errno = ENOENT; goto fail; }
        if (object.best_link_row == METADATA_INDEX_NO_ROW) break;
        if (object.best_link_row >= r->link_count ||
            mi_reader_link_at(r, object.best_link_row, &link) != 0) {
            errno = EINVAL; goto fail;
        }
        if (link.object_key != current ||
            mi_add_u64(link.string_offset, link.string_length, &string_end) != 0 ||
            string_end > r->strings_size) { errno = EINVAL; goto fail; }
        if (count == allocated) { size_t next = allocated == 0 ? 16 : allocated * 2; Part *grown; if (next > MI_MAX_PATH_DEPTH) next = MI_MAX_PATH_DEPTH; grown = (Part *)realloc(parts, next * sizeof(*parts)); if (grown == NULL) goto fail; parts = grown; allocated = next; }
        parts[count].name = r->strings + (size_t)link.string_offset; parts[count].length = link.string_length; ++count;
        if (link.parent_object_key == current) break;
        current = link.parent_object_key;
    }
    if (count == MI_MAX_PATH_DEPTH && current != 0) { errno = ELOOP; goto fail; }
    if (capacity < 2) { errno = ENOSPC; goto fail; }
    out[used++] = '/';
    for (i = count; i != 0; --i) {
        const Part *part = &parts[i - 1];
        if (part->length == 0) continue;
        if (used != 1) { if (used + 1 >= capacity) { errno = ENOSPC; goto fail; } out[used++] = '/'; }
        if (part->length > capacity - used - 1) { errno = ENOSPC; goto fail; }
        memcpy(out + used, part->name, part->length); used += part->length;
    }
    out[used] = '\0'; free(parts); return 0;
fail:
    out[0] = '\0'; free(parts); return -1;
}

static int mi_meter_ensure_active_capacity(
    MetadataIndexSequentialMeter *meter,
    size_t needed)
{
    size_t capacity;
    size_t *expanded;
    if (needed <= meter->active_capacity) return 0;
    capacity = meter->active_capacity == 0U ? 16U : meter->active_capacity;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2U) { errno = EOVERFLOW; return -1; }
        capacity *= 2U;
    }
    expanded = (size_t *)realloc(meter->active_rows, capacity * sizeof(*expanded));
    if (expanded == NULL) return -1;
    meter->active_rows = expanded;
    meter->active_capacity = capacity;
    return 0;
}

static int mi_meter_note_intersection(
    MetadataIndexSequentialMeter *meter,
    size_t physical_row,
    const MiPhysicalRow *physical,
    uint64_t range_start,
    uint64_t range_end,
    MetadataIndexSequentialDeliveryFn delivery,
    void *delivery_context)
{
    MetadataIndexFork fork;
    MetadataIndexPhysicalMatch match;
    uint64_t start;
    uint64_t end;
    uint64_t bytes;
    uint64_t extent_length;
    uint64_t previous;

    if (meter == NULL || physical == NULL || range_end <= range_start ||
        physical_row >= meter->reader->physical_count ||
        physical->fork_row >= meter->reader->fork_count) {
        errno = EINVAL;
        return -1;
    }
    start = range_start > physical->start ? range_start : physical->start;
    end = range_end < physical->end ? range_end : physical->end;
    if (end <= start) return 0;
    if (delivery != NULL) {
        if (mi_match_from_row(
                meter->reader, physical_row, physical, &match, start) != 0 ||
            delivery(&match, start, end, delivery_context) != 0) {
            return -1;
        }
    }
    bytes = end - start;
    extent_length = physical->end - physical->start;
    previous = meter->extent_covered_bytes[physical_row];
    if (previous == 0U) {
        meter->stats.extents_touched++;
        if (!meter->fork_touched[physical->fork_row]) {
            meter->fork_touched[physical->fork_row] = 1U;
            meter->stats.forks_touched++;
        }
    }
    meter->stats.extent_intersections++;
    if (UINT64_MAX - meter->stats.extent_delivery_bytes < bytes) {
        meter->stats.extent_delivery_bytes = UINT64_MAX;
    } else {
        meter->stats.extent_delivery_bytes += bytes;
    }
    if (bytes > extent_length - previous) bytes = extent_length - previous;
    meter->extent_covered_bytes[physical_row] = previous + bytes;
    if (previous < extent_length && previous + bytes == extent_length) {
        meter->stats.extents_complete++;
        meter->fork_completed_extents[physical->fork_row]++;
        if (mi_reader_fork_at(meter->reader, physical->fork_row, &fork) != 0) {
            return -1;
        }
        if ((fork.flags & METADATA_INDEX_FORK_FLAG_COMPLETE) != 0U &&
            fork.extent_count > 0U &&
            meter->fork_completed_extents[physical->fork_row] == fork.extent_count) {
            meter->stats.forks_complete++;
        }
    }
    return 0;
}

int metadata_index_sequential_meter_create(
    const MetadataIndexReader *reader,
    MetadataIndexSequentialMeter **meter_out)
{
    MetadataIndexSequentialMeter *meter;
    size_t fork_row;
    if (reader == NULL || meter_out == NULL) { errno = EINVAL; return -1; }
    *meter_out = NULL;
    meter = (MetadataIndexSequentialMeter *)calloc(1, sizeof(*meter));
    if (meter == NULL) return -1;
    meter->reader = reader;
    meter->stats.extents_total = reader->physical_count;
    meter->stats.forks_total = reader->fork_count;
    if (reader->physical_count != 0U) {
        meter->extent_covered_bytes = (uint64_t *)calloc(
            reader->physical_count,
            sizeof(*meter->extent_covered_bytes));
        if (meter->extent_covered_bytes == NULL) goto fail;
    }
    if (reader->fork_count != 0U) {
        meter->fork_completed_extents = (uint32_t *)calloc(
            reader->fork_count,
            sizeof(*meter->fork_completed_extents));
        meter->fork_touched = (uint8_t *)calloc(
            reader->fork_count,
            sizeof(*meter->fork_touched));
        if (meter->fork_completed_extents == NULL || meter->fork_touched == NULL) goto fail;
    }
    for (fork_row = 0U; fork_row < reader->fork_count; ++fork_row) {
        MetadataIndexFork fork;
        if (mi_reader_fork_at(reader, fork_row, &fork) != 0) goto fail;
        if ((fork.flags & METADATA_INDEX_FORK_FLAG_COMPLETE) == 0U ||
            (fork.extent_count == 0U && fork.logical_size != 0U)) {
            meter->stats.forks_incomplete_runlist++;
        } else if (fork.extent_count == 0U && fork.logical_size == 0U) {
            meter->stats.forks_empty_complete++;
            meter->stats.forks_complete++;
        }
    }
    *meter_out = meter;
    return 0;
fail:
    metadata_index_sequential_meter_destroy(meter);
    return -1;
}

int metadata_index_sequential_meter_observe(
    MetadataIndexSequentialMeter *meter,
    uint64_t range_start,
    uint64_t range_end)
{
    return metadata_index_sequential_meter_observe_with_delivery(
        meter,
        range_start,
        range_end,
        NULL,
        NULL
    );
}

int metadata_index_sequential_meter_observe_with_delivery(
    MetadataIndexSequentialMeter *meter,
    uint64_t range_start,
    uint64_t range_end,
    MetadataIndexSequentialDeliveryFn delivery,
    void *delivery_context)
{
    size_t active_index;
    size_t retained = 0U;

    if (meter == NULL || range_end <= range_start) { errno = EINVAL; return -1; }
    meter->stats.ranges_observed++;
    if (!meter->have_range && range_start > 0U) {
        meter->stats.source_gap_bytes = range_start;
    } else if (meter->have_range) {
        if (range_end <= meter->last_range_end) {
            meter->stats.duplicate_or_backward_ranges++;
            return 0;
        }
        if (range_start < meter->last_range_end) {
            meter->stats.duplicate_or_backward_ranges++;
            range_start = meter->last_range_end;
        } else if (range_start > meter->last_range_end) {
            meter->stats.source_gap_bytes += range_start - meter->last_range_end;
        }
    }
    if (range_end <= range_start) return 0;
    if (UINT64_MAX - meter->stats.source_bytes_observed < range_end - range_start) {
        meter->stats.source_bytes_observed = UINT64_MAX;
    } else {
        meter->stats.source_bytes_observed += range_end - range_start;
    }

    for (active_index = 0U; active_index < meter->active_count; ++active_index) {
        size_t row = meter->active_rows[active_index];
        MiPhysicalRow physical;
        if (mi_reader_physical_at(meter->reader, row, &physical) != 0) return -1;
        if (physical.end <= range_start) continue;
        if (mi_meter_note_intersection(
                meter, row, &physical, range_start, range_end,
                delivery, delivery_context) != 0) return -1;
        if (physical.end > range_end) meter->active_rows[retained++] = row;
    }
    meter->active_count = retained;

    while (meter->next_physical_row < meter->reader->physical_count) {
        size_t row = meter->next_physical_row;
        MiPhysicalRow physical;
        if (mi_reader_physical_at(meter->reader, row, &physical) != 0) return -1;
        if (physical.start >= range_end) break;
        meter->next_physical_row++;
        if (physical.end <= range_start) continue;
        if (mi_meter_note_intersection(
                meter, row, &physical, range_start, range_end,
                delivery, delivery_context) != 0) return -1;
        if (physical.end > range_end) {
            if (mi_meter_ensure_active_capacity(meter, meter->active_count + 1U) != 0) {
                return -1;
            }
            meter->active_rows[meter->active_count++] = row;
        }
    }
    meter->last_range_end = range_end;
    meter->have_range = 1;
    return 0;
}

void metadata_index_sequential_meter_get_stats(
    const MetadataIndexSequentialMeter *meter,
    MetadataIndexSequentialStats *stats_out)
{
    if (stats_out == NULL) return;
    memset(stats_out, 0, sizeof(*stats_out));
    if (meter != NULL) *stats_out = meter->stats;
}

void metadata_index_sequential_meter_destroy(MetadataIndexSequentialMeter *meter)
{
    if (meter == NULL) return;
    free(meter->active_rows);
    free(meter->extent_covered_bytes);
    free(meter->fork_completed_extents);
    free(meter->fork_touched);
    free(meter);
}
