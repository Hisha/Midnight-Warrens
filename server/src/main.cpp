#include "MWFW.h"
#include <iostream>
#include <chrono>
#include <thread>

using namespace MWFW;

static const std::string SHARED_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes
static const std::string IV         = "abcdef0123456789";                 // 16 bytes

int main() {
    SecureUDP udp;
    if (!udp.initialize(50000)) {
        std::cerr << "Server: failed to bind.\n";
        return 1;
    }
    udp.setSharedKey(SHARED_KEY);
    udp.setOnPacket([&](const std::string& ip, uint16_t port,
                        const std::vector<uint8_t>& data, bool isBinary){
        std::string s(data.begin(), data.end());
        std::cout << "Server got from " << ip << ":" << port << " -> " << s << "\n";
        // Simple echo/pong
        std::string reply = R"({"type":"pong","ok":true})";
        udp.sendPacket(ip, port, std::vector<uint8_t>(reply.begin(), reply.end()),
                       SHARED_KEY, IV, /*isBinary=*/false);
    });

    std::cout << "Server listening on UDP 50000...\n";
    while (true) std::this_thread::sleep_for(std::chrono::seconds(1));
}
