#ifndef PERFORMANCE_LEDGER_H
#define PERFORMANCE_LEDGER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "config.h"
#include "fs_backend.h"
#include "run_identity.h"

static inline const char *performance_ledger_nonempty_inline(
    const char *value,
    const char *fallback
)
{
    return value != NULL && value[0] != '\0' ? value : fallback;
}

static inline void performance_ledger_write_text_inline(
    FILE *file,
    const char *value
)
{
    const char *cursor = performance_ledger_nonempty_inline(value, "");

    if (file == NULL) {
        return;
    }
    while (*cursor != '\0') {
        unsigned char c = (unsigned char)*cursor;
        if (c == '\t' || c == '\r' || c == '\n') {
            fputc(' ', file);
        } else {
            fputc((int)c, file);
        }
        cursor++;
    }
}

static inline void performance_ledger_append(
    const AppConfig *config,
    const char *component,
    const char *phase,
    double elapsed_seconds,
    uint64_t input_bytes,
    uint64_t output_before,
    uint64_t output_after,
    uint64_t useful_delta,
    uint64_t skipped,
    const char *status,
    const char *note
)
{
    char path[1024];
    struct stat st;
    int have_existing;
    FILE *file;
    const char *enabled = getenv("CARV_ENABLE_PERFORMANCE_LEDGER");
    const char *debug_logs = getenv("CARV_DEBUG_LOGS");

    if (!((enabled != NULL && enabled[0] != '\0' && enabled[0] != '0') ||
          (debug_logs != NULL && debug_logs[0] != '\0' && debug_logs[0] != '0'))) {
        (void)config;
        (void)component;
        (void)phase;
        (void)elapsed_seconds;
        (void)input_bytes;
        (void)output_before;
        (void)output_after;
        (void)useful_delta;
        (void)skipped;
        (void)status;
        (void)note;
        return;
    }

    if (config == NULL ||
        config->output_dir == NULL ||
        config->output_dir[0] == '\0') {
        return;
    }

    if (snprintf(
            path,
            sizeof(path),
            "%s/%s/performance_ledger.tsv",
            config->output_dir,
            APP_STATE_DIR_NAME) >= (int)sizeof(path)) {
        return;
    }

    have_existing = stat(path, &st) == 0 && st.st_size > 0;
    carv_run_rotate_legacy_tsv_without_generation_inline(path, &have_existing);
    file = fs_backend_fopen_output_write_guarded(path, "a");
    if (file == NULL) {
        return;
    }

    if (!have_existing) {
        fprintf(
            file,
            "updated_unix\tgeneration\tpass_id\tcomponent\tphase\telapsed_seconds\tinput_bytes\toutput_before\toutput_after\tuseful_delta\tskipped\tstatus\tnote\n"
        );
    }

    fprintf(
        file,
        "%llu\t%llu\t",
        (unsigned long long)time(NULL),
        (unsigned long long)carv_run_supervisor_generation_inline()
    );
    performance_ledger_write_text_inline(file, carv_run_pass_id_inline());
    fputc('\t', file);
    performance_ledger_write_text_inline(
        file,
        performance_ledger_nonempty_inline(component, "unknown")
    );
    fputc('\t', file);
    performance_ledger_write_text_inline(
        file,
        performance_ledger_nonempty_inline(phase, "phase")
    );
    fprintf(
        file,
        "\t%.3f\t%llu\t%llu\t%llu\t%llu\t%llu\t",
        elapsed_seconds,
        (unsigned long long)input_bytes,
        (unsigned long long)output_before,
        (unsigned long long)output_after,
        (unsigned long long)useful_delta,
        (unsigned long long)skipped
    );
    performance_ledger_write_text_inline(
        file,
        performance_ledger_nonempty_inline(status, "unknown")
    );
    fputc('\t', file);
    performance_ledger_write_text_inline(file, note);
    fputc('\n', file);

    fclose(file);
}

#endif
