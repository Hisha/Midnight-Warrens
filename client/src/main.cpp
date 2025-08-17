#include "MWFW.h"
#include <iostream>
#include <chrono>
#include <thread>

using namespace MWFW;

static const std::string SHARED_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes
static const std::string IV         = "abcdef0123456789";                 // 16 bytes

int main(int argc, char** argv) {
    std::string host = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t    port = (argc > 2) ? static_cast<uint16_t>(std::stoi(argv[2])) : 50000;

    SecureUDP udp;
    if (!udp.initialize(0)) { // ephemeral local port
        std::cerr << "Client: failed to init.\n";
        return 1;
    }
    udp.setSharedKey(SHARED_KEY);
    udp.setOnPacket([&](const std::string& ip, uint16_t rport,
                        const std::vector<uint8_t>& data, bool isBinary){
        std::string s(data.begin(), data.end());
        std::cout << "Client got from " << ip << ":" << rport << " -> " << s << "\n";
    });

    std::string msg = R"({"type":"ping","time":123})";
    udp.sendPacket(host, port, std::vector<uint8_t>(msg.begin(), msg.end()),
                   SHARED_KEY, IV, /*isBinary=*/false);

    std::cout << "Client sent ping. Waiting for pong...\n";
    std::this_thread::sleep_for(std::chrono::seconds(5));
    return 0;
}
