/*
 * hex.c
 * Converts hexadecimal text such as "FFD8FF" into raw bytes.
 */

#include "hex.h"

#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static int hex_char_to_value(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }

    c = (char)toupper((unsigned char)c);

    if (c >= 'A' && c <= 'F') {
        return 10 + (c - 'A');
    }

    return -1;
}

int hex_string_to_bytes(const char *hex_string, uint8_t **out_bytes, size_t *out_length)
{
    size_t hex_length;
    size_t byte_length;
    uint8_t *bytes;
    size_t i;

    if (hex_string == NULL || out_bytes == NULL || out_length == NULL) {
        return 0;
    }

    *out_bytes = NULL;
    *out_length = 0;

    hex_length = strlen(hex_string);

    if (hex_length == 0 || (hex_length % 2) != 0) {
        return 0;
    }

    byte_length = hex_length / 2;
    bytes = (uint8_t *)malloc(byte_length);

    if (bytes == NULL) {
        return 0;
    }

    for (i = 0; i < byte_length; i++) {
        int high = hex_char_to_value(hex_string[i * 2]);
        int low = hex_char_to_value(hex_string[i * 2 + 1]);

        if (high < 0 || low < 0) {
            free(bytes);
            return 0;
        }

        bytes[i] = (uint8_t)((high << 4) | low);
    }

    *out_bytes = bytes;
    *out_length = byte_length;

    return 1;
}
