#define _POSIX_C_SOURCE 200809L

#include "image_triage.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #condition); \
        goto cleanup; \
    } \
} while (0)

static int replace_file(int fd, const unsigned char *bytes, size_t size)
{
    return ftruncate(fd, 0) == 0 && lseek(fd, 0, SEEK_SET) == 0 &&
           write(fd, bytes, size) == (ssize_t)size && fsync(fd) == 0;
}

int main(int argc, char **argv)
{
    static const unsigned char jpeg[] = {
        0xff, 0xd8,
        0xff, 0xe0, 0x00, 0x07, 'J', 'F', 'I', 'F', 0x00,
        0xff, 0xe1, 0x00, 0x08, 'E', 'x', 'i', 'f', 0x00, 0x00,
        0xff, 0xc0, 0x00, 0x08, 0x08, 0x02, 0x1c, 0x02, 0xd0, 0x01,
        0xff, 0xd9
    };
    static const unsigned char png[] = {
        0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n',
        0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10
    };
    char path[] = "/tmp/carv-image-triage-XXXXXX";
    ImageTriageResult result;
    int fd = mkstemp(path);
    int exit_code = 1;

    if (argc > 1) {
        int index;
        if (fd >= 0) { (void)close(fd); fd = -1; (void)unlink(path); }
        for (index = 1; index < argc; ++index) {
            struct stat status;
            const char *extension = strrchr(argv[index], '.');
            if (stat(argv[index], &status) != 0 ||
                !image_triage_inspect_file(
                    argv[index], extension != NULL ? extension + 1 : "",
                    status.st_size > 0 ? (uint64_t)status.st_size : 0U,
                    &result)) {
                fprintf(stderr, "could not inspect: %s\n", argv[index]);
                exit_code = 1;
                continue;
            }
            printf("%s\t%s\t%d\t%llux%llu\texif=%d\tjfif=%d\n",
                   argv[index], result.classification, result.score,
                   (unsigned long long)result.width,
                   (unsigned long long)result.height,
                   result.has_exif, result.has_jfif);
            exit_code = 0;
        }
        return exit_code;
    }

    CHECK(fd >= 0);
    CHECK(replace_file(fd, jpeg, sizeof(jpeg)));
    CHECK(image_triage_inspect_file(path, "jpg", 100U * 1024U, &result));
    CHECK(result.width == 720U && result.height == 540U);
    CHECK(result.has_exif && result.has_jfif);
    CHECK(strcmp(result.classification, "high_priority_photo") == 0);

    CHECK(replace_file(fd, png, sizeof(png)));
    CHECK(image_triage_inspect_file(path, "png", sizeof(png), &result));
    CHECK(result.width == 16U && result.height == 16U);
    CHECK(strcmp(result.classification, "likely_small_asset") == 0);

    exit_code = 0;
cleanup:
    if (fd >= 0) (void)close(fd);
    (void)unlink(path);
    if (exit_code == 0) printf("image-triage checks passed\n");
    return exit_code;
}
