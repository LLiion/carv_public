#ifndef CARVER_AUDIT_H
#define CARVER_AUDIT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define CARVER_AUDIT_MAX_CHILD_RANGES 4U

typedef struct {
    uint64_t start;
    uint64_t end;
    char reason[32];
} CarverAuditChildRange;

typedef struct {
    size_t confirmed_span;
    char status[32];
    char reject_reason[64];
    char trailing_child_reason[32];
    size_t child_range_count;
    int child_range_truncated;
    CarverAuditChildRange child_ranges[CARVER_AUDIT_MAX_CHILD_RANGES];
} CarverAuditReport;

static inline size_t carver_audit_span_from_u64(uint64_t value)
{
    const uint64_t max_size = (uint64_t)((size_t)-1);

    return value > max_size ? (size_t)-1 : (size_t)value;
}

static inline void carver_audit_copy_text_inline(
    char *out,
    size_t out_size,
    const char *value,
    const char *fallback
)
{
    const char *src = (value != NULL && value[0] != '\0') ? value : fallback;
    size_t i = 0U;

    if (out == NULL || out_size == 0U) {
        return;
    }
    if (src == NULL) {
        src = "";
    }
    while (i + 1U < out_size && src[i] != '\0') {
        out[i] = src[i];
        i++;
    }
    out[i] = '\0';
}

static inline void carver_audit_reset_inline(CarverAuditReport *report)
{
    if (report == NULL) {
        return;
    }
    memset(report, 0, sizeof(*report));
    carver_audit_copy_text_inline(
        report->status,
        sizeof(report->status),
        "not_run",
        "not_run");
    carver_audit_copy_text_inline(
        report->reject_reason,
        sizeof(report->reject_reason),
        "not_run",
        "not_run");
}

static inline void carver_audit_set_inline(
    CarverAuditReport *report,
    const char *status,
    const char *reason,
    size_t confirmed_span
)
{
    if (report == NULL) {
        return;
    }
    report->confirmed_span = confirmed_span;
    carver_audit_copy_text_inline(
        report->status,
        sizeof(report->status),
        status,
        "unknown");
    carver_audit_copy_text_inline(
        report->reject_reason,
        sizeof(report->reject_reason),
        reason,
        "");
}

static inline void carver_audit_set_trailing_reason_inline(
    CarverAuditReport *report,
    const char *reason
)
{
    if (report == NULL) {
        return;
    }
    carver_audit_copy_text_inline(
        report->trailing_child_reason,
        sizeof(report->trailing_child_reason),
        reason,
        "");
}

static inline void carver_audit_add_child_range_inline(
    CarverAuditReport *report,
    uint64_t start,
    uint64_t end,
    const char *reason
)
{
    size_t index;

    if (report == NULL || end <= start) {
        return;
    }
    if (report->child_range_count >= CARVER_AUDIT_MAX_CHILD_RANGES) {
        report->child_range_truncated = 1;
        return;
    }
    index = report->child_range_count++;
    report->child_ranges[index].start = start;
    report->child_ranges[index].end = end;
    carver_audit_copy_text_inline(
        report->child_ranges[index].reason,
        sizeof(report->child_ranges[index].reason),
        reason,
        "");
}

#endif
