#ifndef MFT_PROBE_FORMAT_H
#define MFT_PROBE_FORMAT_H

#include <stdint.h>

/*
 * Compact append-only MFT probe row.
 *
 * The row is deliberately fixed-size and little-endian so logs remain stable
 * across macOS/Linux compilers. A variable-length ASCII/UTF-8-ish name follows
 * each fixed row; MFT_PROBE_OFF_NAME_LEN tells the reader how many bytes.
 */
#define MFT_PROBE_MAGIC "C26MFT1"
#define MFT_PROBE_MAGIC_LEN 7U
#define MFT_PROBE_ROW_SIZE 104U

#define MFT_PROBE_OFF_OFFSET 8U
#define MFT_PROBE_OFF_RECORD 16U
#define MFT_PROBE_OFF_PARENT 20U
#define MFT_PROBE_OFF_FAMILY 28U
#define MFT_PROBE_OFF_FLAGS 32U
#define MFT_PROBE_OFF_NAME_LEN 34U
#define MFT_PROBE_OFF_DATA_OFFSET 36U
#define MFT_PROBE_OFF_DATA_SIZE 44U
#define MFT_PROBE_OFF_FIRST_LCN 52U
#define MFT_PROBE_OFF_RUN_CLUSTERS 60U
#define MFT_PROBE_OFF_RAW_RECORD 68U
#define MFT_PROBE_OFF_CREATED_TEXT 72U
#define MFT_PROBE_CREATED_TEXT_SIZE 32U

/*
 * Temporary display fallback only. Recovery planning must replace this with
 * parsed NTFS geometry before converting LCNs to absolute byte offsets.
 */
#define MFT_PROBE_FALLBACK_CLUSTER_SIZE 4096ULL

#endif
