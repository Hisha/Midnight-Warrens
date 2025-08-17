// ==============================
// FILE: client/src/main.cpp
// Console client: logs snapshots and sends periodic moves
// ==============================
#include "MWFW.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <cmath>
#include "protocol.hpp"

using namespace MWFW;

static const std::string SHARED_KEY = "0123456789abcdef0123456789abcdef";
static const std::string IV         = "abcdef0123456789";

int main(int argc, char** argv){
    std::string host = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t    port = (argc > 2) ? static_cast<uint16_t>(std::stoi(argv[2])) : 50000;

    SecureUDP udp;
    if (!udp.initialize(0)) { std::cerr << "client init failed\n"; return 1; }
    udp.setSharedKey(SHARED_KEY);

    std::atomic<bool> running{true};

    udp.setOnPacket([&](const std::string&, uint16_t, const std::vector<uint8_t>& data, bool){
        std::string s(data.begin(), data.end());
        auto kv = proto::parseKV(s);
        if (kv.count("T") && kv["T"] == "snap") {
            size_t n = kv.count("n") ? static_cast<size_t>(std::stoul(kv["n"])) : 0;
            std::cout << "SNAP n=" << n;
            for (size_t i=0;i<n;++i){
                std::string idk = std::string("id") + std::to_string(i);
                std::string xk  = std::string("x")  + std::to_string(i);
                std::string yk  = std::string("y")  + std::to_string(i);
                if (kv.count(idk) && kv.count(xk) && kv.count(yk))
                    std::cout << " | id=" << kv[idk] << " x=" << kv[xk] << " y=" << kv[yk];
            }
            std::cout << "\n";
        } else if (kv.count("T") && kv["T"] == "ok") {
            std::cout << "OK: " << (kv.count("msg")? kv["msg"]:"") << "\n";
        }
    });

    auto sendKV = [&](const std::vector<std::pair<std::string,std::string>>& items){
        std::string m = proto::kv(items);
        udp.sendPacket(host, port, std::vector<uint8_t>(m.begin(), m.end()), SHARED_KEY, IV, false);
    };

    // login + join
    sendKV({{"T","login"},{"user","test"},{"pass","test"}});
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    sendKV({{"T","join"},{"zone","overworld"}});

    // movement spammer
    std::thread mover([&]{
        float angle = 0.0f;
        while (running.load()){
            float dx = 0.05f * std::cos(angle);
            float dy = 0.05f * std::sin(angle);
            angle += 0.2f;
            sendKV({{"T","move"},{"dx",std::to_string(dx)},{"dy",std::to_string(dy)}});
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });

    // heartbeat
    std::thread heart([&]{
        while (running.load()){
            sendKV({{"T","hb"}});
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    });

    std::cout << "Client running. Ctrl+C to exit." << std::endl;
    // naive wait loop (no signal handling)
    while (true) std::this_thread::sleep_for(std::chrono::seconds(1));

    running.store(false);
    mover.join();
    heart.join();
    return 0;
}
