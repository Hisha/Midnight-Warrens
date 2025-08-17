// ==============================
// FILE: client/src/main.cpp — manual controls (WASD/Arrow keys)
// ==============================
#include "MWFW.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include "protocol.hpp"

#ifdef _WIN32
  #include <conio.h>
  static int getch_nonblock(){ return _kbhit() ? _getch() : -1; }
#else
  #include <termios.h>
  #include <unistd.h>
  #include <fcntl.h>
  static termios orig_termios{};
  static void set_raw_mode(bool enable){
      if (enable){
          tcgetattr(STDIN_FILENO, &orig_termios);
          termios raw = orig_termios;
          raw.c_lflag &= ~(ICANON | ECHO);
          tcsetattr(STDIN_FILENO, TCSANOW, &raw);
          int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
          fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
      } else {
          tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
          int flags = fcntl(STDIN_FILENO, F_GETFL, 0);
          fcntl(STDIN_FILENO, F_SETFL, flags & ~O_NONBLOCK);
      }
  }
  static int getch_nonblock(){ unsigned char c; ssize_t n = read(STDIN_FILENO, &c, 1); return (n==1) ? c : -1; }
#endif

using namespace MWFW;

static const std::string SHARED_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes
static const std::string IV         = "abcdef0123456789";                 // 16 bytes

int main(int argc, char** argv){
    std::string host = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t    port = (argc > 2) ? static_cast<uint16_t>(std::stoi(argv[2])) : 50000;

    SecureUDP udp;
    if (!udp.initialize(0)) { std::cerr << "client init failed\n"; return 1; }
    udp.setSharedKey(SHARED_KEY);

    std::atomic<bool> running{true};

    auto sendKV = [&](const std::vector<std::pair<std::string,std::string>>& items){
        std::string m = proto::kv(items);
        udp.sendPacket(host, port, std::vector<uint8_t>(m.begin(), m.end()), SHARED_KEY, IV, false);
    };

    std::vector<int> charIds; std::vector<std::string> charNames;

    udp.setOnPacket([&](const std::string&, uint16_t, const std::vector<uint8_t>& data, bool){
        std::string s(data.begin(), data.end());
        auto kv = proto::parseKV(s);
        if (!kv.count("T")) return;
        if (kv["T"] == "ok") {
            std::cout << "OK: " << (kv.count("msg")? kv["msg"]:"") << "\n";
        } else if (kv["T"] == "err") {
            std::cout << "ERR: " << (kv.count("msg")? kv["msg"]:"") << "\n";
        } else if (kv["T"] == "chars") {
            charIds.clear(); charNames.clear();
            size_t n = kv.count("n") ? static_cast<size_t>(std::stoul(kv["n"])) : 0;
            for (size_t i=0;i<n;++i){
                std::string idk = "id"+std::to_string(i);
                std::string namek = "name"+std::to_string(i);
                if (kv.count(idk)) charIds.push_back(std::stoi(kv[idk]));
                if (kv.count(namek)) charNames.push_back(kv[namek]);
            }
            std::cout << "CHAR LIST ("<<n<<"): ";
            for (size_t i=0;i<charIds.size();++i) std::cout << '['<<charIds[i]<<":"<<(i<charNames.size()?charNames[i]:"?")<<"] ";
            std::cout << "\n";
            if (n==0) {
                sendKV({{"T","create_char"},{"name","Hero"},{"class","warrior"}});
            } else {
                sendKV({{"T","select_char"},{"id", std::to_string(charIds[0])}});
                sendKV({{"T","join"},{"zone","overworld"}});
                std::cout << "\nControls: WASD or Arrow Keys to move, Q to quit.\n";
            }
        } else if (kv["T"] == "snap") {
            size_t n = kv.count("n") ? static_cast<size_t>(std::stoul(kv["n"])) : 0;
            std::cout << "SNAP n=" << n;
            for (size_t i=0;i<n;++i){
                std::string idk = "id"+std::to_string(i);
                std::string xk = "x"+std::to_string(i);
                std::string yk = "y"+std::to_string(i);
                if (kv.count(idk) && kv.count(xk) && kv.count(yk))
                    std::cout << " | id="<<kv[idk]<<" x="<<kv[xk]<<" y="<<kv[yk];
            }
            std::cout << "\n";
        }
    });

    // Register (idempotent), then login, then list chars
    const std::string USER = "test";
    const std::string PASS = "test";

    sendKV({{"T","register"},{"user",USER},{"pass",PASS}});
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    sendKV({{"T","login"},{"user",USER},{"pass",PASS}});
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    sendKV({{"T","list_chars"}});

    // Heartbeat thread
    std::thread heart([&]{
        while (running.load()){
            sendKV({{"T","hb"}});
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    });

    // Controls thread (non-blocking key reads)
    std::thread controls([&]{
#ifndef _WIN32
        set_raw_mode(true);
        struct RawGuard{ ~RawGuard(){ set_raw_mode(false); } } guard; // RAII cleanup
#endif
        const float STEP = 0.25f; // movement step per keypress
        while (running.load()){
            int c = getch_nonblock();
            if (c < 0) { std::this_thread::sleep_for(std::chrono::milliseconds(16)); continue; }
            float dx = 0.0f, dy = 0.0f;
#ifdef _WIN32
            // Arrow keys on Windows: first _getch() returns 224, second gives code
            if (c == 224) {
                int code = getch_nonblock();
                if (code == -1) continue;
                if (code == 72) dy = -STEP;       // Up
                else if (code == 80) dy = STEP;   // Down
                else if (code == 75) dx = -STEP;  // Left
                else if (code == 77) dx = STEP;   // Right
            }
#endif
            if (c == 'w' || c == 'W') dy = -STEP;
            else if (c == 's' || c == 'S') dy = STEP;
            else if (c == 'a' || c == 'A') dx = -STEP;
            else if (c == 'd' || c == 'D') dx = STEP;
#ifndef _WIN32
            // Arrow keys on POSIX: ESC [ A/B/C/D
            static int esc_state = 0; // 0=none,1=got ESC,2=got '['
            if (c == 27) { esc_state = 1; continue; }
            if (esc_state == 1) { if (c == '[') { esc_state = 2; continue; } else esc_state = 0; }
            if (esc_state == 2) {
                if (c == 'A') dy = -STEP;        // Up
                else if (c == 'B') dy = STEP;    // Down
                else if (c == 'D') dx = -STEP;   // Left
                else if (c == 'C') dx = STEP;    // Right
                esc_state = 0;
            }
#endif
            if (c == 'q' || c == 'Q') { running.store(false); break; }
            if (dx != 0.0f || dy != 0.0f) {
                sendKV({{"T","move"},{"dx",std::to_string(dx)},{"dy",std::to_string(dy)}});
            }
        }
    });

    std::cout << "Client running. Press Q to quit." << std::endl;
    while (running.load()) std::this_thread::sleep_for(std::chrono::seconds(1));

    controls.join();
    heart.join();
    return 0;
}
