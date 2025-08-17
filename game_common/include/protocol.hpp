// ==============================
// FILE: game_common/include/protocol.hpp
// Minimal key=value;key2=val2; line protocol helpers (no external deps)
// ==============================
#pragma once
#include <string>
#include <unordered_map>
#include <sstream>
#include <vector>

namespace proto {

inline std::unordered_map<std::string,std::string> parseKV(const std::string& s) {
    std::unordered_map<std::string,std::string> out;
    size_t i = 0;
    while (i < s.size()) {
        size_t eq = s.find('=', i);
        if (eq == std::string::npos) break;
        std::string key = s.substr(i, eq - i);
        size_t sc = s.find(';', eq + 1);
        std::string val = s.substr(eq + 1, (sc == std::string::npos ? s.size() : sc) - (eq + 1));
        out[key] = val;
        if (sc == std::string::npos) break;
        i = sc + 1;
    }
    return out;
}

inline std::string kv(const std::vector<std::pair<std::string,std::string>>& items) {
    std::ostringstream oss;
    for (size_t i=0;i<items.size();++i) {
        oss << items[i].first << '=' << items[i].second << ';';
    }
    return oss.str();
}

}
