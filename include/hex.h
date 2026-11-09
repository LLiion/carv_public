/*
 * hex.h
 * Converts hexadecimal strings to raw byte arrays.
 */

#ifndef HEX_H
#define HEX_H

#include <stddef.h>
#include <stdint.h>

int hex_string_to_bytes(const char *hex_string, uint8_t **out_bytes, size_t *out_length);

#endif
