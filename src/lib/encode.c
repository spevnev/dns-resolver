#include "encode.h"
#include <stdint.h>
#include <stdlib.h>

static const char *BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char *HEX_TABLE = "0123456789ABCDEF";

char *base64_encode(const uint8_t *src, size_t length) {
    size_t output_size = ((length + 2) / 3) * 4 + 1;
    char *output = malloc(output_size);
    if (output == NULL) return NULL;

    const uint8_t *end = src + length;
    const uint8_t *in = src;
    char *pos = output;
    while (end - in >= 3) {
        *pos++ = BASE64_TABLE[in[0] >> 2];
        *pos++ = BASE64_TABLE[((in[0] & 0x03) << 4) | (in[1] >> 4)];
        *pos++ = BASE64_TABLE[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
        *pos++ = BASE64_TABLE[in[2] & 0x3F];
        in += 3;
    }

    if (end - in) {
        *pos++ = BASE64_TABLE[in[0] >> 2];
        if (end - in == 1) {
            *pos++ = BASE64_TABLE[(in[0] & 0x03) << 4];
            *pos++ = '=';
        } else {
            *pos++ = BASE64_TABLE[((in[0] & 0x03) << 4) | (in[1] >> 4)];
            *pos++ = BASE64_TABLE[(in[1] & 0x0F) << 2];
        }
        *pos++ = '=';
    }
    *pos = '\0';

    return output;
}

char *hex_string_encode(const uint8_t *src, size_t length) {
    size_t output_size = length * 2 + 1;
    char *output = malloc(output_size);
    if (output == NULL) return NULL;

    const uint8_t *in = src;
    char *pos = output;
    for (size_t i = 0; i < length; i++) {
        *pos++ = HEX_TABLE[(*in >> 4) & 0x0F];
        *pos++ = HEX_TABLE[(*in++) & 0x0F];
    }
    *pos = '\0';

    return output;
}
