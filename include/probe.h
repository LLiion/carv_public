/*
 * probe.h
 * Lightweight source probing and gentle Linux rescan helpers.
 */

#ifndef PROBE_H
#define PROBE_H

#include <stdio.h>

int source_probe_run(
    const char *requested_source,
    const char *report_run_dir,
    FILE *stream
);

#endif
