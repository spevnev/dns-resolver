#pragma once

#include <cstdint>
#include <string>
#include <vector>

std::string base64_encode(const std::vector<uint8_t> &src);
std::string base32hex_encode(const std::vector<uint8_t> &src);
std::string hex_encode(const std::vector<uint8_t> &src);
