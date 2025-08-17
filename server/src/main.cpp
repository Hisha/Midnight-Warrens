// ==============================
// FILE: server/src/main.cpp
// Auth-less demo server: login -> join overworld -> move -> periodic snapshots
// ==============================
#include "MWFW.h"
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <thread>
#include <iostream>
#include <iomanip>
#include <sstream>

#include "protocol.hpp"

using namespace MWFW;

static const std::string SHARED_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes
static const std::string IV         = "abcdef0123456789";                 // 16 bytes

struct Player {
    uint64_t id;
    float x{0}, y{0};
    std::string ip;
    uint16_t port{0};
    std::chrono::steady_clock::time_point lastSeen;
};

static std::string endpointKey(const std::string& ip, uint16_t port){
    std::ostringstream oss; oss << ip << ':' << port; return oss.str();
}

int main(){
    SecureUDP udp;
    if (!udp.initialize(50000)) { std::cerr << "Server bind failed\n"; return 1; }
    udp.setSharedKey(SHARED_KEY);

    std::mutex mtx;
    std::unordered_map<std::string, Player> players; // key: ip:port
    uint64_t nextId = 1;

    udp.setOnPacket([&](const std::string& ip, uint16_t port,
                        const std::vector<uint8_t>& data, bool){
        std::string msg(data.begin(), data.end());
        auto kv = proto::parseKV(msg);
        auto key = endpointKey(ip, port);
        std::lock_guard<std::mutex> lock(mtx);

        auto now = std::chrono::steady_clock::now();
        auto it = players.find(key);

        std::string type = kv.count("T")? kv["T"] : "";
        if (type == "login") {
            if (it == players.end()) {
                Player p; p.id = nextId++; p.ip = ip; p.port = port; p.lastSeen = now; players[key] = p;
            } else {
                it->second.lastSeen = now;
            }
            std::string ok = proto::kv({{"T","ok"},{"msg","login"}});
            udp.sendPacket(ip, port, std::vector<uint8_t>(ok.begin(), ok.end()), SHARED_KEY, IV, false);
        } else if (type == "join") {
            if (it != players.end()) it->second.lastSeen = now;
            std::string ok = proto::kv({{"T","ok"},{"msg","join"}});
            udp.sendPacket(ip, port, std::vector<uint8_t>(ok.begin(), ok.end()), SHARED_KEY, IV, false);
        } else if (type == "move") {
            if (it != players.end()) {
                float dx = kv.count("dx") ? std::stof(kv["dx"]) : 0.0f;
                float dy = kv.count("dy") ? std::stof(kv["dy"]) : 0.0f;
                it->second.x += dx; it->second.y += dy; it->second.lastSeen = now;
            }
        } else if (type == "hb") {
            if (it != players.end()) it->second.lastSeen = now;
        }
    });

    // Tick loop: broadcast snapshots 10 times per second
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::vector<std::string> lines;
        {
            std::lock_guard<std::mutex> lock(mtx);
            // prune inactive (>10s)
            auto now = std::chrono::steady_clock::now();
            for (auto it = players.begin(); it != players.end();) {
                if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.lastSeen).count() > 10) it = players.erase(it); else ++it;
            }
            // build one snapshot string
            std::ostringstream snap;
            snap << "T=snap;";
            size_t count = 0; for (auto &kvp : players) ++count;
            snap << "n=" << count << ";";
            size_t idx=0; for (auto &kvp : players){
                const Player& p = kvp.second;
                snap << "id"<<idx<<'='<<p.id<<';' << "x"<<idx<<'='<<p.x<<';' << "y"<<idx<<'='<<p.y<<';';
                ++idx;
            }
            std::string s = snap.str();
            std::vector<uint8_t> bytes(s.begin(), s.end());
            // send to all
            for (auto &kvp : players){
                udp.sendPacket(kvp.second.ip, kvp.second.port, bytes, SHARED_KEY, IV, false);
            }
        }
    }
}
