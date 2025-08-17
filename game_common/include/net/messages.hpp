#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace net {
inline std::vector<uint8_t> to_bytes(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}
inline std::string to_string(const std::vector<uint8_t>& b) {
    return std::string(b.begin(), b.end());
}
}
