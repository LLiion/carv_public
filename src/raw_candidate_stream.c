#include "raw_candidate_stream.h"

#include "recovery_runner.h"

#include <stdlib.h>
#include <string.h>

static int raw_candidate_stream_reserve(
    RawCandidateStream *stream,
    size_t needed
)
{
    size_t new_capacity;
    uint8_t *replacement;

    if (stream == NULL) {
        return 0;
    }
    if (needed <= stream->capacity) {
        return 1;
    }

    new_capacity = stream->capacity == 0U ? 4096U : stream->capacity;
    while (new_capacity < needed) {
        if (new_capacity > (SIZE_MAX / 2U)) {
            return 0;
        }
        new_capacity *= 2U;
    }

    replacement = (uint8_t *)realloc(stream->buffer, new_capacity);
    if (replacement == NULL) {
        return 0;
    }

    stream->buffer = replacement;
    stream->capacity = new_capacity;
    return 1;
}

int raw_candidate_stream_init(
    RawCandidateStream *stream,
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t max_total_bytes
)
{
    uint64_t source_size;
    uint64_t remaining_source;
    size_t initial_bytes;

    if (stream == NULL || reader == NULL) {
        return 0;
    }

    memset(stream, 0, sizeof(*stream));
    if (reader->buffer == NULL ||
        reader->fd < 0 ||
        start_offset >= reader->bytes_in_buffer) {
        return 0;
    }

    initial_bytes = reader->bytes_in_buffer - start_offset;
    if (initial_bytes == 0U) {
        return 0;
    }

    source_size = reader_get_source_size(reader);
    remaining_source =
        source_size > (uint64_t)absolute_offset ? source_size - (uint64_t)absolute_offset : 0U;
    if (remaining_source == 0U) {
        return 0;
    }

    if ((uint64_t)max_total_bytes > remaining_source || max_total_bytes == 0U) {
        max_total_bytes = (size_t)remaining_source;
    }
    if (max_total_bytes < initial_bytes) {
        max_total_bytes = initial_bytes;
    }

    stream->reader = reader;
    stream->absolute_offset = (uint64_t)absolute_offset;
    stream->max_total_bytes = (uint64_t)max_total_bytes;
    stream->initial_buffer_bytes = initial_bytes;

    if (!raw_candidate_stream_reserve(stream, initial_bytes)) {
        raw_candidate_stream_free(stream);
        return 0;
    }

    memcpy(stream->buffer, reader->buffer + start_offset, initial_bytes);
    stream->size = initial_bytes;
    return 1;
}

void raw_candidate_stream_free(RawCandidateStream *stream)
{
    if (stream == NULL) {
        return;
    }

    free(stream->buffer);
    memset(stream, 0, sizeof(*stream));
}

const uint8_t *raw_candidate_stream_data(const RawCandidateStream *stream)
{
    if (stream == NULL) {
        return NULL;
    }

    return stream->buffer;
}

size_t raw_candidate_stream_size(const RawCandidateStream *stream)
{
    if (stream == NULL) {
        return 0U;
    }

    return stream->size;
}

size_t raw_candidate_stream_initial_buffer_bytes(const RawCandidateStream *stream)
{
    if (stream == NULL) {
        return 0U;
    }

    return stream->initial_buffer_bytes;
}

size_t raw_candidate_stream_remaining(const RawCandidateStream *stream)
{
    if (stream == NULL || stream->max_total_bytes <= (uint64_t)stream->size) {
        return 0U;
    }

    return (size_t)(stream->max_total_bytes - (uint64_t)stream->size);
}

size_t raw_candidate_stream_read_some(RawCandidateStream *stream, size_t want)
{
    uint64_t failed_at = 0U;
    size_t remaining;
    size_t got;

    if (stream == NULL || stream->reader == NULL || want == 0U) {
        return 0U;
    }

    remaining = raw_candidate_stream_remaining(stream);
    if (remaining == 0U) {
        return 0U;
    }
    if (want > remaining) {
        want = remaining;
    }
    if (!raw_candidate_stream_reserve(stream, stream->size + want)) {
        return 0U;
    }

    got = recovery_runner_read_with_fallback(
        stream->reader->fd,
        stream->buffer + stream->size,
        stream->absolute_offset + (uint64_t)stream->size,
        want,
        &failed_at
    );
    stream->size += got;
    return got;
}

size_t raw_candidate_stream_grow_to(
    RawCandidateStream *stream,
    size_t target_size
)
{
    size_t started_size;
    size_t chunk_size;

    if (stream == NULL || target_size <= stream->size) {
        return 0U;
    }

    if ((uint64_t)target_size > stream->max_total_bytes) {
        target_size = (size_t)stream->max_total_bytes;
    }
    if (target_size <= stream->size) {
        return 0U;
    }

    started_size = stream->size;
    chunk_size = recovery_runner_default_read_size();
    while (stream->size < target_size) {
        size_t want = target_size - stream->size;

        if (want > chunk_size) {
            want = chunk_size;
        }
        if (raw_candidate_stream_read_some(stream, want) == 0U) {
            break;
        }
    }

    return stream->size - started_size;
}
