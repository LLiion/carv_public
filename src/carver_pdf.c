#include "carver_pdf.h"

#include "carver_output.h"
#include "config.h"
#include "raw_candidate_stream.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define PDF_HEADER_SIZE 5U
#define PDF_EOF_SIZE 5U
#define PDF_MIN_FILE_SIZE 32U
#define PDF_MAX_EOF_CANDIDATES 256U
#define PDF_STREAM_SCAN_INITIAL (8U * 1024U * 1024U)
#define PDF_STREAM_SCAN_MAX (512U * 1024U * 1024U)
#define PDF_XREF_STREAM_PROBE_BYTES 4096U
#define PDF_TRAILING_CHILD_MIN_BYTES 4096U

typedef struct {
    int valid_header;
    int saw_object;
    int saw_trailer;
    int saw_xref;
    int saw_startxref;
    int saw_valid_startxref;
    int saw_eof;
    size_t file_size;
    size_t suspicious_child_start;
    size_t suspicious_child_end;
    const char *suspicious_child_reason;
    size_t after_eof_child_start;
    size_t after_eof_child_end;
    const char *after_eof_child_reason;
    const char *trailing_child_reason;
    const char *reject_reason;
} PdfAnalysis;

typedef struct {
    size_t eof_offset;
    size_t end_offset;
    int saw_object;
    int saw_trailer;
    int saw_xref;
    int saw_startxref;
    int saw_valid_startxref;
    int saw_nested_pdf_header;
    size_t nested_pdf_header_offset;
    uint64_t startxref_value;
} PdfEofCandidate;

static const char *g_pdf_last_reject_reason = "not_run";
static CarverAuditReport g_pdf_last_audit;

static void pdf_copy_audit_text(
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

static void pdf_reset_last_audit(void)
{
    memset(&g_pdf_last_audit, 0, sizeof(g_pdf_last_audit));
    pdf_copy_audit_text(
        g_pdf_last_audit.status,
        sizeof(g_pdf_last_audit.status),
        "not_run",
        "not_run"
    );
    pdf_copy_audit_text(
        g_pdf_last_audit.reject_reason,
        sizeof(g_pdf_last_audit.reject_reason),
        "not_run",
        "not_run"
    );
}

void carver_pdf_reset_last_audit(void)
{
    pdf_reset_last_audit();
}

static void pdf_set_last_audit_status(const char *status, const char *reason)
{
    pdf_copy_audit_text(
        g_pdf_last_audit.status,
        sizeof(g_pdf_last_audit.status),
        status,
        "unknown"
    );
    pdf_copy_audit_text(
        g_pdf_last_audit.reject_reason,
        sizeof(g_pdf_last_audit.reject_reason),
        reason,
        ""
    );
}

static void pdf_set_last_audit_trailing_reason(const char *reason)
{
    pdf_copy_audit_text(
        g_pdf_last_audit.trailing_child_reason,
        sizeof(g_pdf_last_audit.trailing_child_reason),
        reason,
        ""
    );
}

static void pdf_last_audit_add_child_range(
    uint64_t start,
    uint64_t end,
    const char *reason
)
{
    size_t index;

    if (end <= start) {
        return;
    }
    if (g_pdf_last_audit.child_range_count >= CARVER_AUDIT_MAX_CHILD_RANGES) {
        g_pdf_last_audit.child_range_truncated = 1;
        return;
    }
    index = g_pdf_last_audit.child_range_count++;
    g_pdf_last_audit.child_ranges[index].start = start;
    g_pdf_last_audit.child_ranges[index].end = end;
    pdf_copy_audit_text(
        g_pdf_last_audit.child_ranges[index].reason,
        sizeof(g_pdf_last_audit.child_ranges[index].reason),
        reason,
        "pdf_child_range"
    );
}

static void pdf_set_last_audit_from_analysis(
    size_t absolute_offset,
    const PdfAnalysis *analysis,
    int accepted
)
{
    if (analysis == NULL) {
        return;
    }
    g_pdf_last_audit.confirmed_span = accepted ? analysis->file_size : 0U;
    pdf_set_last_audit_status(
        accepted ? "recovered" : "rejected",
        accepted ? "" : analysis->reject_reason
    );
    if (accepted &&
        analysis->suspicious_child_end > analysis->suspicious_child_start) {
        pdf_last_audit_add_child_range(
            (uint64_t)absolute_offset + (uint64_t)analysis->suspicious_child_start,
            (uint64_t)absolute_offset + (uint64_t)analysis->suspicious_child_end,
            analysis->suspicious_child_reason != NULL
                ? analysis->suspicious_child_reason
                : "pdf_nested_header");
    }
    if (accepted &&
        analysis->after_eof_child_end > analysis->after_eof_child_start) {
        pdf_last_audit_add_child_range(
            (uint64_t)absolute_offset + (uint64_t)analysis->after_eof_child_start,
            (uint64_t)absolute_offset + (uint64_t)analysis->after_eof_child_end,
            analysis->after_eof_child_reason != NULL
                ? analysis->after_eof_child_reason
                : "pdf_after_eof_child");
    }
    if (accepted) {
        pdf_set_last_audit_trailing_reason(
            analysis->trailing_child_reason != NULL
                ? analysis->trailing_child_reason
                : "pdf_after_valid_span");
    }
}

static void pdf_set_last_reject_reason(const char *reason)
{
    g_pdf_last_reject_reason =
        (reason != NULL && reason[0] != '\0') ? reason : "unknown";
}

const char *carver_pdf_last_reject_reason(void)
{
    return g_pdf_last_reject_reason != NULL
        ? g_pdf_last_reject_reason
        : "unknown";
}

void carver_pdf_get_last_audit(CarverAuditReport *out)
{
    if (out == NULL) {
        return;
    }
    *out = g_pdf_last_audit;
}

static int write_pdf_file(
    const uint8_t *buffer,
    size_t start_offset,
    size_t file_size,
    size_t absolute_offset
)
{
    return carver_output_write_buffer(
        (long long)absolute_offset,
        APP_DEFAULT_UNIDENT_DIR,
        "recov",
        "pdf",
        buffer + start_offset,
        file_size
    );
}

static int is_pdf_space(uint8_t byte)
{
    return byte == ' ' || byte == '\t' || byte == '\r' || byte == '\n';
}

static int is_pdf_digit(uint8_t byte)
{
    return byte >= '0' && byte <= '9';
}

static int is_pdf_token_delimiter(uint8_t byte)
{
    return is_pdf_space(byte) ||
           byte == '<' || byte == '>' ||
           byte == '[' || byte == ']' ||
           byte == '(' || byte == ')' ||
           byte == '/' || byte == '%';
}

static int is_pdf_header_at(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
)
{
    return buffer != NULL &&
           offset + 8U <= buffer_length &&
           memcmp(buffer + offset, "%PDF-", PDF_HEADER_SIZE) == 0 &&
           is_pdf_digit(buffer[offset + 5U]) &&
           buffer[offset + 6U] == '.' &&
           is_pdf_digit(buffer[offset + 7U]);
}

static int pdf_buffer_find_header_between(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start,
    size_t end,
    size_t *offset_out
);

static int pdf_token_at(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset,
    const char *token
)
{
    size_t token_len;

    if (buffer == NULL || token == NULL) {
        return 0;
    }
    token_len = strlen(token);
    if (token_len == 0U || offset + token_len > buffer_length) {
        return 0;
    }
    if (memcmp(buffer + offset, token, token_len) != 0) {
        return 0;
    }
    if (offset > 0U && !is_pdf_token_delimiter(buffer[offset - 1U])) {
        return 0;
    }
    if (offset + token_len < buffer_length &&
        !is_pdf_token_delimiter(buffer[offset + token_len])) {
        return 0;
    }
    return 1;
}

static int pdf_buffer_contains_header_between(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start,
    size_t end
)
{
    size_t header_offset = SIZE_MAX;

    return pdf_buffer_find_header_between(
        buffer,
        buffer_length,
        start,
        end,
        &header_offset);
}

static int pdf_buffer_find_header_between(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start,
    size_t end,
    size_t *offset_out
)
{
    size_t cursor;

    if (offset_out != NULL) {
        *offset_out = SIZE_MAX;
    }
    if (buffer == NULL || start >= end || start >= buffer_length) {
        return 0;
    }
    if (end > buffer_length) {
        end = buffer_length;
    }
    for (cursor = start; cursor + 8U <= end; cursor++) {
        if (is_pdf_header_at(buffer, buffer_length, cursor)) {
            if (offset_out != NULL) {
                *offset_out = cursor;
            }
            return 1;
        }
    }
    return 0;
}

static int pdf_parse_uint64_at(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset,
    uint64_t *value_out
)
{
    uint64_t value = 0U;
    size_t cursor = offset;
    size_t digits = 0U;

    if (buffer == NULL || offset >= buffer_length) {
        return 0;
    }
    while (cursor < buffer_length && is_pdf_space(buffer[cursor])) {
        cursor++;
    }
    while (cursor < buffer_length && is_pdf_digit(buffer[cursor])) {
        uint64_t digit = (uint64_t)(buffer[cursor] - '0');

        if (value > (UINT64_MAX - digit) / 10U) {
            return 0;
        }
        value = value * 10U + digit;
        cursor++;
        digits++;
        if (digits > 20U) {
            return 0;
        }
    }
    if (digits == 0U) {
        return 0;
    }
    if (value_out != NULL) {
        *value_out = value;
    }
    return 1;
}

static int pdf_xref_stream_object_at(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t target
)
{
    size_t end;
    size_t cursor;
    int saw_obj = 0;
    int saw_xref_type = 0;

    if (buffer == NULL || target >= buffer_length) {
        return 0;
    }
    end = target + PDF_XREF_STREAM_PROBE_BYTES;
    if (end > buffer_length) {
        end = buffer_length;
    }
    for (cursor = target; cursor + 5U <= end; cursor++) {
        if (!saw_obj &&
            cursor + 4U <= end &&
            memcmp(buffer + cursor, " obj", 4U) == 0) {
            saw_obj = 1;
        }
        if (!saw_xref_type &&
            cursor + 5U <= end &&
            memcmp(buffer + cursor, "/XRef", 5U) == 0) {
            saw_xref_type = 1;
        }
        if (saw_obj && saw_xref_type) {
            return 1;
        }
    }
    return 0;
}

static int pdf_startxref_target_valid(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t pdf_start_offset,
    size_t eof_offset,
    uint64_t startxref_value
)
{
    uint64_t target64;
    size_t target;

    if (buffer == NULL || pdf_start_offset >= buffer_length) {
        return 0;
    }
    if (startxref_value > (uint64_t)(SIZE_MAX - pdf_start_offset)) {
        return 0;
    }
    target64 = (uint64_t)pdf_start_offset + startxref_value;
    if (target64 >= (uint64_t)buffer_length ||
        target64 >= (uint64_t)eof_offset) {
        return 0;
    }
    target = (size_t)target64;
    if (target + 4U <= buffer_length &&
        memcmp(buffer + target, "xref", 4U) == 0) {
        return 1;
    }
    return pdf_xref_stream_object_at(buffer, buffer_length, target);
}

static int pdf_parse_startxref_at(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t pdf_start_offset,
    size_t startxref_offset,
    size_t eof_offset,
    uint64_t *value_out
)
{
    uint64_t value = 0U;

    if (buffer == NULL ||
        startxref_offset + 9U > buffer_length ||
        memcmp(buffer + startxref_offset, "startxref", 9U) != 0) {
        return 0;
    }
    if (!pdf_parse_uint64_at(
            buffer,
            buffer_length,
            startxref_offset + 9U,
            &value)) {
        return 0;
    }
    if (value_out != NULL) {
        *value_out = value;
    }
    return pdf_startxref_target_valid(
        buffer,
        buffer_length,
        pdf_start_offset,
        eof_offset,
        value);
}

static int pdf_buffer_has_object_marker_at(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t offset
)
{
    return buffer != NULL &&
           offset + 4U <= buffer_length &&
           memcmp(buffer + offset, " obj", 4U) == 0;
}

static int pdf_buffer_has_incremental_markers_between(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start,
    size_t end
)
{
    size_t cursor;
    int saw_xref = 0;
    int saw_trailer = 0;

    if (buffer == NULL || start >= end || start >= buffer_length) {
        return 0;
    }
    if (end > buffer_length) {
        end = buffer_length;
    }

    for (cursor = start; cursor + 4U <= end; cursor++) {
        if (cursor + 9U <= end &&
            memcmp(buffer + cursor, "startxref", 9U) == 0) {
            return 1;
        }
        if (cursor + 7U <= end &&
            memcmp(buffer + cursor, "trailer", 7U) == 0) {
            saw_trailer = 1;
        }
        if (cursor + 4U <= end &&
            memcmp(buffer + cursor, "xref", 4U) == 0) {
            saw_xref = 1;
        }
    }

    return saw_xref && saw_trailer;
}

static int pdf_eof_candidate_is_usable(const PdfEofCandidate *candidate)
{
    if (candidate == NULL || !candidate->saw_object) {
        return 0;
    }
    if (candidate->saw_nested_pdf_header &&
        !candidate->saw_valid_startxref) {
        return 0;
    }
    return candidate->saw_valid_startxref ||
           (candidate->saw_xref && candidate->saw_trailer);
}

static size_t choose_pdf_eof_candidate(
    const uint8_t *buffer,
    size_t buffer_length,
    const PdfEofCandidate *candidates,
    size_t candidate_count
)
{
    size_t i;
    size_t last_usable = SIZE_MAX;

    for (i = 0U; i < candidate_count; i++) {
        size_t next;
        size_t next_usable = SIZE_MAX;
        int has_next_pdf_header;
        int has_incremental_markers;

        if (!pdf_eof_candidate_is_usable(&candidates[i])) {
            continue;
        }
        last_usable = i;

        for (next = i + 1U; next < candidate_count; next++) {
            if (pdf_eof_candidate_is_usable(&candidates[next])) {
                next_usable = next;
                break;
            }
        }

        if (next_usable == SIZE_MAX) {
            return i;
        }

        has_next_pdf_header = pdf_buffer_contains_header_between(
            buffer,
            buffer_length,
            candidates[i].end_offset,
            candidates[next_usable].eof_offset);
        if (has_next_pdf_header) {
            return i;
        }

        has_incremental_markers = pdf_buffer_has_incremental_markers_between(
            buffer,
            buffer_length,
            candidates[i].end_offset,
            candidates[next_usable].eof_offset);
        if (!has_incremental_markers) {
            return i;
        }
    }

    return last_usable;
}

static PdfAnalysis analyze_pdf_candidate(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset
)
{
    PdfAnalysis result = {0};
    PdfEofCandidate candidates[PDF_MAX_EOF_CANDIDATES];
    size_t candidate_count = 0U;
    size_t chosen_index;
    size_t cursor;
    int saw_startxref = 0;
    int saw_valid_startxref = 0;
    size_t last_startxref_offset = SIZE_MAX;
    uint64_t last_startxref_value = 0U;

    if (buffer == NULL || start_offset + PDF_MIN_FILE_SIZE > buffer_length) {
        result.reject_reason = "rejected_truncated_header";
        return result;
    }

    if (!is_pdf_header_at(buffer, buffer_length, start_offset)) {
        result.reject_reason = "rejected_invalid_header";
        return result;
    }

    result.valid_header = 1;
    result.reject_reason = "rejected_no_eof";

    for (cursor = start_offset + PDF_HEADER_SIZE;
         cursor + PDF_EOF_SIZE <= buffer_length;
         cursor++) {
        if (!result.saw_object &&
            pdf_buffer_has_object_marker_at(buffer, buffer_length, cursor)) {
            result.saw_object = 1;
        }
        if (!result.saw_trailer &&
            cursor + 7U <= buffer_length &&
            pdf_token_at(buffer, buffer_length, cursor, "trailer")) {
            result.saw_trailer = 1;
        }
        if (!result.saw_xref) {
            if ((cursor + 9U <= buffer_length &&
                 memcmp(buffer + cursor, "startxref", 9) == 0) ||
                (cursor + 4U <= buffer_length &&
                 pdf_token_at(buffer, buffer_length, cursor, "xref"))) {
                result.saw_xref = 1;
            }
        }
        if (cursor + 9U <= buffer_length &&
            memcmp(buffer + cursor, "startxref", 9U) == 0) {
            uint64_t parsed_value = 0U;

            saw_startxref = 1;
            result.saw_startxref = 1;
            result.saw_xref = 1;
            last_startxref_offset = cursor;
            if (pdf_parse_uint64_at(
                    buffer,
                    buffer_length,
                    cursor + 9U,
                    &parsed_value)) {
                last_startxref_value = parsed_value;
            }
        }
        if (memcmp(buffer + cursor, "%%EOF", PDF_EOF_SIZE) == 0) {
            size_t end_offset;
            int startxref_valid = 0;
            int nested_pdf_header = 0;
            size_t nested_pdf_header_offset = SIZE_MAX;

            end_offset = cursor + PDF_EOF_SIZE;
            while (end_offset < buffer_length && is_pdf_space(buffer[end_offset])) {
                end_offset++;
            }
            nested_pdf_header = pdf_buffer_find_header_between(
                buffer,
                buffer_length,
                start_offset + 8U,
                cursor,
                &nested_pdf_header_offset);
            if (last_startxref_offset != SIZE_MAX) {
                uint64_t parsed_value = 0U;

                startxref_valid = pdf_parse_startxref_at(
                    buffer,
                    buffer_length,
                    start_offset,
                    last_startxref_offset,
                    cursor,
                    &parsed_value);
                if (startxref_valid) {
                    last_startxref_value = parsed_value;
                    saw_valid_startxref = 1;
                    result.saw_valid_startxref = 1;
                }
            }

            if (candidate_count < PDF_MAX_EOF_CANDIDATES) {
                candidates[candidate_count].eof_offset = cursor;
                candidates[candidate_count].end_offset = end_offset;
                candidates[candidate_count].saw_object = result.saw_object;
                candidates[candidate_count].saw_trailer = result.saw_trailer;
                candidates[candidate_count].saw_xref = result.saw_xref;
                candidates[candidate_count].saw_startxref = saw_startxref;
                candidates[candidate_count].saw_valid_startxref =
                    startxref_valid;
                candidates[candidate_count].saw_nested_pdf_header =
                    nested_pdf_header;
                candidates[candidate_count].nested_pdf_header_offset =
                    nested_pdf_header_offset;
                candidates[candidate_count].startxref_value =
                    last_startxref_value;
                candidate_count++;
            }
        }
    }

    if (candidate_count == 0U) {
        result.reject_reason = "rejected_no_eof";
        return result;
    }

    chosen_index = choose_pdf_eof_candidate(
        buffer,
        buffer_length,
        candidates,
        candidate_count);
    if (chosen_index == SIZE_MAX) {
        if (!result.saw_object) {
            result.reject_reason = "rejected_no_object";
        } else if (result.saw_startxref && !saw_valid_startxref) {
            result.reject_reason = "rejected_bad_startxref";
        } else if (!result.saw_xref && !result.saw_trailer) {
            result.reject_reason = "rejected_no_xref_or_trailer";
        } else {
            result.reject_reason = "rejected_no_usable_eof";
        }
        return result;
    }

    result.saw_eof = 1;
    result.saw_object = candidates[chosen_index].saw_object;
    result.saw_trailer = candidates[chosen_index].saw_trailer;
    result.saw_xref = candidates[chosen_index].saw_xref;
    result.saw_startxref = candidates[chosen_index].saw_startxref;
    result.saw_valid_startxref = candidates[chosen_index].saw_valid_startxref;
    result.file_size = candidates[chosen_index].end_offset - start_offset;
    result.trailing_child_reason = result.saw_valid_startxref
        ? "pdf_after_valid_startxref"
        : "pdf_after_eof";
    if (candidates[chosen_index].nested_pdf_header_offset != SIZE_MAX &&
        candidates[chosen_index].nested_pdf_header_offset > start_offset &&
        candidates[chosen_index].nested_pdf_header_offset <
            candidates[chosen_index].end_offset) {
        result.suspicious_child_start =
            candidates[chosen_index].nested_pdf_header_offset - start_offset;
        result.suspicious_child_end = result.file_size;
        result.suspicious_child_reason = "pdf_nested_header_before_eof";
    }
    if (buffer_length > candidates[chosen_index].end_offset +
            PDF_TRAILING_CHILD_MIN_BYTES) {
        size_t after_eof_pdf_header = SIZE_MAX;

        if (pdf_buffer_find_header_between(
                buffer,
                buffer_length,
                candidates[chosen_index].end_offset,
                buffer_length,
                &after_eof_pdf_header)) {
            result.after_eof_child_start = after_eof_pdf_header - start_offset;
            result.after_eof_child_end = buffer_length - start_offset;
            result.after_eof_child_reason = "pdf_header_after_eof";
            result.trailing_child_reason = "pdf_header_after_eof";
        }
    }
    if (!result.saw_object) {
        result.reject_reason = "rejected_no_object";
    } else if (!result.saw_valid_startxref &&
               !(result.saw_trailer && result.saw_xref)) {
        result.reject_reason = result.saw_startxref
            ? "rejected_bad_startxref"
            : "rejected_no_xref_or_trailer";
    } else if (result.file_size < PDF_MIN_FILE_SIZE) {
        result.reject_reason = "rejected_too_small";
    } else {
        result.reject_reason = "accepted";
    }
    return result;
}

static int pdf_analysis_is_accepted(const PdfAnalysis *analysis)
{
    return analysis != NULL &&
           analysis->valid_header &&
           analysis->saw_eof &&
           analysis->saw_object &&
           (analysis->saw_valid_startxref ||
            (analysis->saw_trailer && analysis->saw_xref)) &&
           analysis->file_size >= PDF_MIN_FILE_SIZE;
}

static int pdf_analysis_needs_more_data(const PdfAnalysis *analysis)
{
    return analysis != NULL &&
           analysis->valid_header &&
           !analysis->saw_eof;
}

static void advance_reader_past_pdf_span(
    Reader *reader,
    size_t absolute_offset,
    size_t file_size,
    size_t bytes_already_buffered
)
{
    uint64_t seek_offset;

    if (reader == NULL || file_size <= bytes_already_buffered) {
        return;
    }

    seek_offset = (uint64_t)absolute_offset + (uint64_t)file_size;
    if (!reader_seek_absolute(reader, seek_offset)) {
        return;
    }
    (void)reader_read_next(reader);
}

int carver_pdf_from_buffer(
    const uint8_t *buffer,
    size_t buffer_length,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    PdfAnalysis analysis;

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0;
    }
    pdf_reset_last_audit();
    if (buffer == NULL || start_offset >= buffer_length) {
        pdf_set_last_reject_reason("rejected_invalid_input");
        pdf_set_last_audit_status("rejected", "rejected_invalid_input");
        return 0;
    }

    analysis = analyze_pdf_candidate(buffer, buffer_length, start_offset);
    if (!pdf_analysis_is_accepted(&analysis)) {
        pdf_set_last_reject_reason(analysis.reject_reason);
        pdf_set_last_audit_from_analysis(absolute_offset, &analysis, 0);
        return 0;
    }

    if (!write_pdf_file(
            buffer,
            start_offset,
            analysis.file_size,
            absolute_offset)) {
        pdf_set_last_reject_reason("rejected_write_failed");
        pdf_set_last_audit_status("rejected", "rejected_write_failed");
        return 0;
    }

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = analysis.file_size;
    }
    pdf_set_last_reject_reason("accepted");
    pdf_set_last_audit_from_analysis(absolute_offset, &analysis, 1);
    return 1;
}

int carver_pdf_from_reader(
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t *confirmed_span_out
)
{
    RawCandidateStream stream;
    PdfAnalysis analysis;
    size_t current_bytes;
    size_t want;
    size_t next_want;
    size_t max_want;
    size_t advanced;
    int ok = 0;

    if (confirmed_span_out != NULL) {
        *confirmed_span_out = 0U;
    }
    pdf_reset_last_audit();
    pdf_set_last_reject_reason("not_run");
    if (reader == NULL ||
        reader->buffer == NULL ||
        reader->fd < 0 ||
        start_offset >= reader->bytes_in_buffer) {
        pdf_set_last_reject_reason("rejected_invalid_input");
        pdf_set_last_audit_status("rejected", "rejected_invalid_input");
        return 0;
    }

    analysis = analyze_pdf_candidate(
        reader->buffer,
        reader->bytes_in_buffer,
        start_offset);
    if (pdf_analysis_is_accepted(&analysis)) {
        if (!write_pdf_file(
                reader->buffer,
                start_offset,
                analysis.file_size,
                absolute_offset)) {
            pdf_set_last_reject_reason("rejected_write_failed");
            pdf_set_last_audit_status("rejected", "rejected_write_failed");
            return 0;
        }
        if (confirmed_span_out != NULL) {
            *confirmed_span_out = analysis.file_size;
        }
        pdf_set_last_reject_reason("accepted");
        pdf_set_last_audit_from_analysis(absolute_offset, &analysis, 1);
        return 1;
    }
    if (!pdf_analysis_needs_more_data(&analysis)) {
        pdf_set_last_reject_reason(analysis.reject_reason);
        pdf_set_last_audit_from_analysis(absolute_offset, &analysis, 0);
        return 0;
    }

    if (!raw_candidate_stream_init(
            &stream,
            reader,
            start_offset,
            absolute_offset,
            PDF_STREAM_SCAN_MAX)) {
        pdf_set_last_reject_reason("rejected_stream_init_failed");
        pdf_set_last_audit_status("rejected", "rejected_stream_init_failed");
        return 0;
    }

    current_bytes = raw_candidate_stream_initial_buffer_bytes(&stream);
    want = PDF_STREAM_SCAN_INITIAL;
    if (want < current_bytes) {
        want = current_bytes;
    }
    max_want = PDF_STREAM_SCAN_MAX;
    if (raw_candidate_stream_remaining(&stream) + current_bytes < max_want) {
        max_want = raw_candidate_stream_remaining(&stream) + current_bytes;
    }
    if (want > max_want) {
        want = max_want;
    }

    while (raw_candidate_stream_size(&stream) < max_want) {
        const uint8_t *window;

        advanced = raw_candidate_stream_grow_to(&stream, want);
        window = raw_candidate_stream_data(&stream);
        current_bytes = raw_candidate_stream_size(&stream);
        analysis = analyze_pdf_candidate(window, current_bytes, 0U);
        if (pdf_analysis_is_accepted(&analysis)) {
            if (write_pdf_file(
                    window,
                    0U,
                    analysis.file_size,
                    absolute_offset)) {
                size_t bytes_already_buffered =
                    reader->bytes_in_buffer > start_offset
                        ? reader->bytes_in_buffer - start_offset
                        : 0U;

                if (confirmed_span_out != NULL) {
                    *confirmed_span_out = analysis.file_size;
                }
                advance_reader_past_pdf_span(
                    reader,
                    absolute_offset,
                    analysis.file_size,
                    bytes_already_buffered);
                pdf_set_last_reject_reason("accepted");
                pdf_set_last_audit_from_analysis(absolute_offset, &analysis, 1);
                ok = 1;
            } else {
                pdf_set_last_reject_reason("rejected_write_failed");
                pdf_set_last_audit_status("rejected", "rejected_write_failed");
            }
            break;
        }
        if (!pdf_analysis_needs_more_data(&analysis)) {
            pdf_set_last_reject_reason(analysis.reject_reason);
            pdf_set_last_audit_from_analysis(absolute_offset, &analysis, 0);
            break;
        }
        if (advanced == 0U) {
            pdf_set_last_reject_reason("rejected_no_eof");
            pdf_set_last_audit_status("rejected", "rejected_no_eof");
            break;
        }
        next_want = want;
        while (next_want <= want && next_want < max_want) {
            size_t doubled = next_want * 2U;

            if (doubled <= next_want) {
                next_want = max_want;
                break;
            }
            next_want = doubled;
        }
        if (next_want > max_want) {
            next_want = max_want;
        }
        if (next_want <= want) {
            pdf_set_last_reject_reason("rejected_no_eof");
            pdf_set_last_audit_status("rejected", "rejected_no_eof");
            break;
        }
        want = next_want;
    }

    if (!ok && raw_candidate_stream_size(&stream) >= max_want &&
        strcmp(carver_pdf_last_reject_reason(), "not_run") == 0) {
        pdf_set_last_reject_reason("rejected_scan_cap_no_eof");
        pdf_set_last_audit_status("rejected", "rejected_scan_cap_no_eof");
    }
    raw_candidate_stream_free(&stream);
    return ok;
}
