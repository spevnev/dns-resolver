#include "encode.h"
#include <stdint.h>
#include <stdlib.h>

static const char *BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char *BASE32_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
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

    if (in < end) {
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

char *base32_encode(const uint8_t *src, size_t length) {
    size_t output_size = ((length + 4) / 5) * 8 + 1;
    char *output = malloc(output_size);
    if (output == NULL) return NULL;

    const uint8_t *end = src + length;
    const uint8_t *in = src;
    char *pos = output;
    while (end - in >= 5) {
        *pos++ = BASE32_TABLE[in[0] >> 3];
        *pos++ = BASE32_TABLE[((in[0] & 0x07) << 2) | (in[1] >> 6)];
        *pos++ = BASE32_TABLE[(in[1] & 0x3E) >> 1];
        *pos++ = BASE32_TABLE[((in[1] & 0x01) << 4) | (in[2] >> 4)];
        *pos++ = BASE32_TABLE[((in[2] & 0x0F) << 1) | (in[3] >> 7)];
        *pos++ = BASE32_TABLE[(in[3] & 0x7c) >> 2];
        *pos++ = BASE32_TABLE[((in[3] & 0x03) << 3) | (in[4] >> 5)];
        *pos++ = BASE32_TABLE[in[4] & 0x1F];
        in += 5;
    }

    if (in < end) {
        *pos++ = BASE32_TABLE[in[0] >> 3];
        switch (end - in) {
            case 1:
                *pos++ = BASE32_TABLE[(in[0] & 0x07) << 2];
                *pos++ = '=';
                *pos++ = '=';
                *pos++ = '=';
                *pos++ = '=';
                *pos++ = '=';
                break;
            case 2:
                *pos++ = BASE32_TABLE[(in[0] & 0x07) << 2 | (in[1] >> 6)];
                *pos++ = BASE32_TABLE[(in[1] & 0x3E) >> 1];
                *pos++ = BASE32_TABLE[(in[1] & 0x01) << 4];
                *pos++ = '=';
                *pos++ = '=';
                *pos++ = '=';
                break;
            case 3:
                *pos++ = BASE32_TABLE[((in[0] & 0x07) << 2) | (in[1] >> 6)];
                *pos++ = BASE32_TABLE[(in[1] & 0x3E) >> 1];
                *pos++ = BASE32_TABLE[((in[1] & 0x01) << 4) | (in[2] >> 4)];
                *pos++ = BASE32_TABLE[((in[2] & 0x0F) << 1)];
                *pos++ = '=';
                *pos++ = '=';
                break;
            case 4:
                *pos++ = BASE32_TABLE[((in[0] & 0x07) << 2) | (in[1] >> 6)];
                *pos++ = BASE32_TABLE[(in[1] & 0x3E) >> 1];
                *pos++ = BASE32_TABLE[((in[1] & 0x01) << 4) | (in[2] >> 4)];
                *pos++ = BASE32_TABLE[((in[2] & 0x0F) << 1) | (in[3] >> 7)];
                *pos++ = BASE32_TABLE[(in[3] & 0x7c) >> 2];
                *pos++ = BASE32_TABLE[((in[3] & 0x03) << 3)];
                break;
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
