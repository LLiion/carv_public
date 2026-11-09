#ifndef RUN_IDENTITY_H
#define RUN_IDENTITY_H

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define CARV_RUN_SUPERVISOR_GENERATION_ENV "CARV_SUPERVISOR_GENERATION"
#define CARV_RUN_GUI_PASS_ID_ENV "CARV_GUI_PASS_ID"

static inline uint64_t carv_run_supervisor_generation_inline(void)
{
    const char *text = getenv(CARV_RUN_SUPERVISOR_GENERATION_ENV);
    char *end = NULL;
    unsigned long long value;

    if (text == NULL || text[0] == '\0') {
        return 0ULL;
    }

    errno = 0;
    value = strtoull(text, &end, 10);
    if (errno != 0 || end == text) {
        return 0ULL;
    }
    return (uint64_t)value;
}

static inline const char *carv_run_pass_id_inline(void)
{
    const char *pass_id = getenv(CARV_RUN_GUI_PASS_ID_ENV);

    return pass_id != NULL && pass_id[0] != '\0' ? pass_id : "-";
}

static inline int carv_run_tsv_header_has_generation_inline(const char *path)
{
    FILE *file;
    char line[256];

    if (path == NULL || path[0] == '\0') {
        return 0;
    }
    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return 0;
    }
    fclose(file);

    return strncmp(line, "generation\tpass_id\t", 19U) == 0 ||
           strstr(line, "\tgeneration\tpass_id\t") != NULL;
}

static inline void carv_run_rotate_legacy_tsv_without_generation_inline(
    const char *path,
    int *io_have_existing
)
{
    char backup[1024];

    if (path == NULL ||
        path[0] == '\0' ||
        io_have_existing == NULL ||
        !*io_have_existing ||
        carv_run_tsv_header_has_generation_inline(path)) {
        return;
    }

    if (snprintf(
            backup,
            sizeof(backup),
            "%s.pre_generation.tsv",
            path) >= (int)sizeof(backup)) {
        return;
    }
    {
        FILE *existing_backup = fopen(backup, "r");

        if (existing_backup != NULL) {
            fclose(existing_backup);
            if (snprintf(
                    backup,
                    sizeof(backup),
                    "%s.pre_generation.%llu.tsv",
                    path,
                    (unsigned long long)time(NULL)) >= (int)sizeof(backup)) {
                return;
            }
        }
    }
    if (rename(path, backup) == 0) {
        *io_have_existing = 0;
    }
}

#endif
