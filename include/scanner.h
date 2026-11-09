/*
 * scanner.h
 * Scans chunk buffers and reports magic signature matches.
 */

#ifndef SCANNER_H
#define SCANNER_H

#include "reader.h"
#include "signature_types.h"
#include "config.h"
#include "mftprobe_engine_types.h"

int scanner_run(
    Reader *reader,
    const MagicTable *magic_table,
    const AppConfig *config,
    const RecoveryOrder *active_order
);

int scanner_run_raw_all(
    Reader *reader,
    const MagicTable *magic_table,
    const AppConfig *config,
    const RecoveryOrder *active_order,
    int *out_completed_full_scan
);

int scanner_run_primary_metadata_acquisition(Reader *reader, int phase);
int scanner_index_primary_metadata_catalog(Reader *reader);
int scanner_primary_metadata_bootstrap_should_disable_live_observation(void);
int scanner_index_primary_mft(Reader *reader);
int scanner_primary_mft_bootstrap_should_skip_mft(void);

#endif
