#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

template <typename T, typename I>
concept CastableEnum = std::is_scoped_enum_v<T> && std::same_as<std::underlying_type_t<T>, I>;

inline void write_u8(std::vector<uint8_t> &buffer, uint16_t value) { buffer.push_back(value); }

template <CastableEnum<uint8_t> T>
void write_u8(std::vector<uint8_t> &buffer, T value) {
    write_u8(buffer, std::to_underlying(value));
}

inline void write_u16(std::vector<uint8_t> &buffer, uint16_t value) {
    buffer.push_back(value >> 8);
    buffer.push_back(value);
}

template <CastableEnum<uint16_t> T>
void write_u16(std::vector<uint8_t> &buffer, T value) {
    write_u16(buffer, std::to_underlying(value));
}

inline void write_u32(std::vector<uint8_t> &buffer, uint32_t value) {
    buffer.push_back(value >> 24);
    buffer.push_back(value >> 16);
    buffer.push_back(value >> 8);
    buffer.push_back(value);
}

template <std::input_iterator T>
void write_bytes(std::vector<uint8_t> &buffer, T start, size_t length) {
    buffer.insert(buffer.end(), start, start + length);
}

inline void write_domain(std::vector<uint8_t> &buffer, std::string_view domain) {
    if (domain == ".") {
        write_u8(buffer, 0);
        return;
    }

    std::string_view current{domain};
    while (!current.empty()) {
        auto label_length = current.find('.');
        write_u8(buffer, static_cast<uint8_t>(label_length));
        write_bytes(buffer, current.cbegin(), label_length);
        current.remove_prefix(label_length + 1);
    }
    write_u8(buffer, 0);
}

inline void write_char_string(std::vector<uint8_t> &buffer, const std::string &str) {
    buffer.push_back(str.size());
    std::ranges::copy(str, std::back_inserter(buffer));
}
