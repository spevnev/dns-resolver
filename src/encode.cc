#include "encode.hh"
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

namespace {
const char *BASE64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const char *BASE32_TABLE = "0123456789abcdefghijklmnopqrstuv";
const char *HEX_TABLE = "0123456789ABCDEF";
}  // namespace

std::string base64_encode(const std::vector<uint8_t> &src) {
    std::string output;
    output.reserve(((src.size() + 2) / 3) * 4);

    auto it = src.cbegin();
    while (it + 3 <= src.cend()) {
        output.push_back(BASE64_TABLE[it[0] >> 2]);
        output.push_back(BASE64_TABLE[((it[0] & 0b11) << 4) | (it[1] >> 4)]);
        output.push_back(BASE64_TABLE[((it[1] & 0b1111) << 2) | (it[2] >> 6)]);
        output.push_back(BASE64_TABLE[it[2] & 0b111111]);
        it += 3;
    }

    if (it < src.cend()) {
        output.push_back(BASE64_TABLE[it[0] >> 2]);
        if (src.cend() - it == 1) {
            output.push_back(BASE64_TABLE[(it[0] & 0b11) << 4]);
            output.push_back('=');
        } else {
            output.push_back(BASE64_TABLE[((it[0] & 0b11) << 4) | (it[1] >> 4)]);
            output.push_back(BASE64_TABLE[(it[1] & 0b1111) << 2]);
        }
        output.push_back('=');
    }

    return output;
}

// Base 32 Encoding with Extended Hex Alphabet.
std::string base32_encode(const std::vector<uint8_t> &src) {
    std::string output;
    output.reserve(((src.size() + 4) / 5) * 8);

    auto it = src.cbegin();
    while (it + 5 <= src.cend()) {
        output.push_back(BASE32_TABLE[it[0] >> 3]);
        output.push_back(BASE32_TABLE[((it[0] & 0b111) << 2) | (it[1] >> 6)]);
        output.push_back(BASE32_TABLE[(it[1] & 0b111110) >> 1]);
        output.push_back(BASE32_TABLE[((it[1] & 0b1) << 4) | (it[2] >> 4)]);
        output.push_back(BASE32_TABLE[((it[2] & 0b1111) << 1) | (it[3] >> 7)]);
        output.push_back(BASE32_TABLE[(it[3] & 0b1111100) >> 2]);
        output.push_back(BASE32_TABLE[((it[3] & 0b11) << 3) | (it[4] >> 5)]);
        output.push_back(BASE32_TABLE[it[4] & 0b11111]);
        it += 5;
    }

    if (it < src.cend()) {
        output.push_back(BASE32_TABLE[it[0] >> 3]);
        switch (src.cend() - it) {
            case 1:
                output.push_back(BASE32_TABLE[(it[0] & 0b111) << 2]);
                output.push_back('=');
                output.push_back('=');
                output.push_back('=');
                output.push_back('=');
                output.push_back('=');
                break;
            case 2:
                output.push_back(BASE32_TABLE[(it[0] & 0b111) << 2 | (it[1] >> 6)]);
                output.push_back(BASE32_TABLE[(it[1] & 0b111110) >> 1]);
                output.push_back(BASE32_TABLE[(it[1] & 0b1) << 4]);
                output.push_back('=');
                output.push_back('=');
                output.push_back('=');
                break;
            case 3:
                output.push_back(BASE32_TABLE[((it[0] & 0b111) << 2) | (it[1] >> 6)]);
                output.push_back(BASE32_TABLE[(it[1] & 0b111110) >> 1]);
                output.push_back(BASE32_TABLE[((it[1] & 0b1) << 4) | (it[2] >> 4)]);
                output.push_back(BASE32_TABLE[((it[2] & 0b1111) << 1)]);
                output.push_back('=');
                output.push_back('=');
                break;
            case 4:
                output.push_back(BASE32_TABLE[((it[0] & 0b111) << 2) | (it[1] >> 6)]);
                output.push_back(BASE32_TABLE[(it[1] & 0b111110) >> 1]);
                output.push_back(BASE32_TABLE[((it[1] & 0b1) << 4) | (it[2] >> 4)]);
                output.push_back(BASE32_TABLE[((it[2] & 0b1111) << 1) | (it[3] >> 7)]);
                output.push_back(BASE32_TABLE[(it[3] & 0b1111100) >> 2]);
                output.push_back(BASE32_TABLE[((it[3] & 0b11) << 3)]);
                break;
            default: static_assert("Unreachable");
        }
        output.push_back('=');
    }

    return output;
}

std::string hex_string_encode(const std::vector<uint8_t> &src) {
    std::string output;
    output.reserve(src.size() * 2);

    for (auto in : src) {
        output.push_back(HEX_TABLE[(in >> 4) & 0x0F]);
        output.push_back(HEX_TABLE[in & 0x0F]);
    }

    return output;
}
