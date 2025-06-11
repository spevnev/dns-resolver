#ifndef ENCODE_H
#define ENCODE_H

#include <stdint.h>
#include <stdlib.h>

char *base64_encode(const uint8_t *src, size_t length);
char *hex_string_encode(const uint8_t *src, size_t length);

#endif  // ENCODE_H
