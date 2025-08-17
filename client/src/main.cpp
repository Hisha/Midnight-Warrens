// ==============================
// FILE: client/src/main.cpp — WASD controls with auto-select+join
// - Fixes: immediately enables raw input on POSIX
// - After char creation, auto-selects the new char and joins
// ==============================
#include "MWFW.h"
#include <iostream>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <string>
#include "protocol.hpp"

#ifdef _WIN32
  #include <conio.h>
  static int getch_nonblock(){ return _kbhit() ? _getch() : -1; }
#else
  #include <termios.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/ioctl.h>
  static termios orig_termios{};
  static bool tty_ok(){ return isatty(STDIN_FILENO); }
  static void set_raw_mode(bool enable){
      if (!tty_ok()) return;
      if (enable){
          tcgetattr(STDIN_FILENO, &orig_termios);
          termios raw = orig_termios;
          raw.c_lflag &= ~(ICANON | ECHO);
          raw.c_cc[VMIN]  = 0;
          raw.c_cc[VTIME] = 0;
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
  struct RawGuard { RawGuard(){ set_raw_mode(true); } ~RawGuard(){ set_raw_mode(false); } };
#endif

using namespace MWFW;

static const std::string SHARED_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes
static const std::string IV         = "abcdef0123456789";                 // 16 bytes

int main(int argc, char** argv){
    std::string host = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t    port = (argc > 2) ? static_cast<uint16_t>(std::stoi(argv[2])) : 50000;

#ifndef _WIN32
    RawGuard rg; // enable raw input immediately (POSIX)
#endif

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
        const std::string T = kv.at("T");
        if (T == "ok") {
            std::string msg = kv.count("msg")? kv.at("msg"):"";
            std::cout << "OK: " << msg << "\n";
            if (msg == "char_created") {
                // Prefer immediate select using returned char_id, else re-list
                if (kv.count("char_id")) {
                    std::string id = kv.at("char_id");
                    sendKV({{"T","select_char"},{"id", id}});
                    sendKV({{"T","join"},{"zone","overworld"}});
                    std::cout << "Controls: WASD/Arrows, Q=quit\n";
                } else {
                    sendKV({{"T","list_chars"}});
                }
            } else if (msg == "char_selected") {
                sendKV({{"T","join"},{"zone","overworld"}});
                std::cout << "Controls: WASD/Arrows, Q=quit\n";
            } else if (msg == "join") {
                std::cout << "Joined overworld. Controls: WASD/Arrows, Q=quit\n";
            }
        } else if (T == "err") {
            std::cout << "ERR: " << (kv.count("msg")? kv.at("msg"):"") << "\n";
        } else if (T == "chars") {
            charIds.clear(); charNames.clear();
            size_t n = kv.count("n") ? static_cast<size_t>(std::stoul(kv.at("n"))) : 0;
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
                std::cout << "Controls: WASD/Arrows, Q=quit\n";
            }
        } else if (T == "snap") {
            size_t n = kv.count("n") ? static_cast<size_t>(std::stoul(kv.at("n"))) : 0;
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
        const float STEP = 0.25f; // movement step per keypress
#ifndef _WIN32
        // simple state for POSIX escape sequences
        int esc_state = 0; // 0=none,1=got ESC,2=got '['
#endif
        while (running.load()){
            int c = getch_nonblock();
            if (c < 0) { std::this_thread::sleep_for(std::chrono::milliseconds(16)); continue; }
            float dx = 0.0f, dy = 0.0f;
#ifdef _WIN32
            if (c == 224) { // arrow prefix
                int code = getch_nonblock();
                if (code == -1) continue;
                if (code == 72) dy = -STEP;       // Up
                else if (code == 80) dy = STEP;   // Down
                else if (code == 75) dx = -STEP;  // Left
                else if (code == 77) dx = STEP;   // Right
            }
            if (c == 'w' || c == 'W') dy = -STEP;
            else if (c == 's' || c == 'S') dy = STEP;
            else if (c == 'a' || c == 'A') dx = -STEP;
            else if (c == 'd' || c == 'D') dx = STEP;
#else
            if (c == 27) { esc_state = 1; continue; }
            if (esc_state == 1) { if (c == '[') { esc_state = 2; continue; } else esc_state = 0; }
            if (esc_state == 2) {
                if (c == 'A') dy = -STEP;        // Up
                else if (c == 'B') dy = STEP;    // Down
                else if (c == 'D') dx = -STEP;   // Left
                else if (c == 'C') dx = STEP;    // Right
                esc_state = 0;
            }
            if (c == 'w' || c == 'W') dy = -STEP;
            else if (c == 's' || c == 'S') dy = STEP;
            else if (c == 'a' || c == 'A') dx = -STEP;
            else if (c == 'd' || c == 'D') dx = STEP;
#endif
            if (c == 'q' || c == 'Q') { running.store(false); break; }
            if (dx != 0.0f || dy != 0.0f) {
                sendKV({{"T","move"},{"dx",std::to_string(dx)},{"dy",std::to_string(dy)}});
            }
        }
    });

    std::cout << "Client running. (WASD/Arrows to move, Q to quit)\n";
    while (running.load()) std::this_thread::sleep_for(std::chrono::seconds(1));

    controls.join();
    heart.join();
    return 0;
}
