#include "mftprobe_format_riff_validator.h"

#include <stdio.h>
#include <string.h>

static int streq_ci_local(const char *a, const char *b)
{
    while (*a != '\0' && *b != '\0') {
        char ca = *a;
        char cb = *b;

        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int riff_subtype_matches_extension(const char *extension, const unsigned char *subtype)
{
    if (extension == NULL || subtype == NULL) {
        return 1;
    }

    if (streq_ci_local(extension, "avi")) {
        return memcmp(subtype, "AVI ", 4) == 0;
    }
    if (streq_ci_local(extension, "wav")) {
        return memcmp(subtype, "WAVE", 4) == 0;
    }
    if (streq_ci_local(extension, "webp")) {
        return memcmp(subtype, "WEBP", 4) == 0;
    }
    if (streq_ci_local(extension, "rmi")) {
        return memcmp(subtype, "RMID", 4) == 0;
    }
    if (streq_ci_local(extension, "riff")) {
        return memcmp(subtype, "AVI ", 4) == 0 ||
               memcmp(subtype, "WAVE", 4) == 0 ||
               memcmp(subtype, "WEBP", 4) == 0 ||
               memcmp(subtype, "RMID", 4) == 0;
    }

    return 1;
}

int mftprobe_riff_validator_start(
    uint64_t abs_offset,
    const char *extension,
    char *last_error,
    size_t last_error_size,
    const unsigned char *buffer,
    size_t len
)
{
    if (buffer == NULL || len < 12) {
        if (last_error != NULL && last_error_size > 0) {
            snprintf(
                last_error,
                last_error_size,
                "data near byte %llu is too short for RIFF header",
                (unsigned long long)abs_offset
            );
        }
        return 0;
    }

    if (memcmp(buffer, "RIFF", 4) != 0) {
        if (last_error != NULL && last_error_size > 0) {
            snprintf(
                last_error,
                last_error_size,
                "data near byte %llu does not start with RIFF",
                (unsigned long long)abs_offset
            );
        }
        return 0;
    }

    if (!riff_subtype_matches_extension(extension, buffer + 8)) {
        if (last_error != NULL && last_error_size > 0) {
            snprintf(
                last_error,
                last_error_size,
                "RIFF subtype mismatch near byte %llu",
                (unsigned long long)abs_offset
            );
        }
        return 0;
    }

    return 1;
}

int mftprobe_riff_validator_finish(
    uint64_t abs_offset,
    uint64_t size,
    const char *extension,
    char *last_error,
    size_t last_error_size
)
{
    (void)extension;

    if (size >= 12) {
        return 1;
    }

    if (last_error != NULL && last_error_size > 0) {
        snprintf(
            last_error,
            last_error_size,
            "RIFF candidate at byte %llu is too small (%llu bytes)",
            (unsigned long long)abs_offset,
            (unsigned long long)size
        );
    }
    return 0;
}
