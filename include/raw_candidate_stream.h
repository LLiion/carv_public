#ifndef RAW_CANDIDATE_STREAM_H
#define RAW_CANDIDATE_STREAM_H

#include "reader.h"

#include <stddef.h>
#include <stdint.h>

typedef struct {
    Reader *reader;
    uint8_t *buffer;
    size_t size;
    size_t capacity;
    size_t initial_buffer_bytes;
    uint64_t absolute_offset;
    uint64_t max_total_bytes;
} RawCandidateStream;

int raw_candidate_stream_init(
    RawCandidateStream *stream,
    Reader *reader,
    size_t start_offset,
    size_t absolute_offset,
    size_t max_total_bytes
);
void raw_candidate_stream_free(RawCandidateStream *stream);
const uint8_t *raw_candidate_stream_data(const RawCandidateStream *stream);
size_t raw_candidate_stream_size(const RawCandidateStream *stream);
size_t raw_candidate_stream_initial_buffer_bytes(const RawCandidateStream *stream);
size_t raw_candidate_stream_remaining(const RawCandidateStream *stream);
size_t raw_candidate_stream_read_some(RawCandidateStream *stream, size_t want);
size_t raw_candidate_stream_grow_to(
    RawCandidateStream *stream,
    size_t target_size
);

#endif
