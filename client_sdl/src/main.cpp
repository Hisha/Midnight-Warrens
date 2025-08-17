// ==============================
// FILE: client_sdl/src/main.cpp
// ==============================
#include "MWFW.h"
#include "protocol.hpp"

#include <SDL.h>
#ifdef HAVE_SDL_IMAGE
  #include <SDL_image.h>
#endif

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <unordered_map>

using namespace MWFW;
using namespace std::chrono;

static const std::string SHARED_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes
static const std::string IV         = "abcdef0123456789";                 // 16 bytes

struct Entity { uint64_t id; float x, y; };

struct WorldState {
  std::vector<Entity> ents; // last snapshot
  std::mutex mx;
};

static void sendKV(SecureUDP& udp, const std::string& host, uint16_t port,
                   const std::vector<std::pair<std::string,std::string>>& items){
  std::string m = proto::kv(items);
  std::vector<uint8_t> bytes(m.begin(), m.end());
  udp.sendPacket(host, port, bytes, SHARED_KEY, IV, false);
}

// --- Iso helpers -----------------------------------------------------------
static const int TILE_W = 64;      // pixels
static const int TILE_H = 32;      // pixels (TILE_H = TILE_W/2 for 2:1 iso)

struct Camera { float cx=0, cy=0; float zoom=1.0f; int screenW=1280, screenH=720; };

static inline SDL_Point worldToScreen(float wx, float wy, const Camera& cam){
  // iso projection (diamond): screen x = (x - y) * TILE_W/2, y = (x + y) * TILE_H/2
  float ix = (wx - wy) * (TILE_W * 0.5f);
  float iy = (wx + wy) * (TILE_H * 0.5f);
  // Camera centers at (cam.cx, cam.cy)
  float icx = (cam.cx - cam.cy) * (TILE_W * 0.5f);
  float icy = (cam.cx + cam.cy) * (TILE_H * 0.5f);
  float sx = (ix - icx) * cam.zoom + cam.screenW * 0.5f;
  float sy = (iy - icy) * cam.zoom + cam.screenH * 0.5f;
  return SDL_Point{ (int)std::lround(sx), (int)std::lround(sy) };
}

static void drawIsoTile(SDL_Renderer* r, int tx, int ty, const Camera& cam){
  SDL_Point p = worldToScreen((float)tx, (float)ty, cam);
  int hw = (int)std::lround(TILE_W * 0.5f * cam.zoom);
  int hh = (int)std::lround(TILE_H * 0.5f * cam.zoom);
  SDL_Point v[5] = {
    { p.x,       p.y - hh },
    { p.x + hw,  p.y      },
    { p.x,       p.y + hh },
    { p.x - hw,  p.y      },
    { p.x,       p.y - hh }
  };
  SDL_RenderDrawLines(r, v, 5);
}

static void drawIsoGrid(SDL_Renderer* r, const Camera& cam){
  // draw a diamond area around the camera tile
  int radius = 16; // tiles
  int cx = (int)std::floor(cam.cx);
  int cy = (int)std::floor(cam.cy);
  for (int y = cy - radius; y <= cy + radius; ++y){
    for (int x = cx - radius; x <= cx + radius; ++x){
      if (std::abs((x - cx)) + std::abs((y - cy)) <= radius + 4)
        drawIsoTile(r, x, y, cam);
    }
  }
}

int main(int argc, char** argv){
  std::string host = (argc > 1) ? argv[1] : std::string("127.0.0.1");
  uint16_t    port = (argc > 2) ? (uint16_t)std::stoi(argv[2]) : 50000;

  if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_TIMER | SDL_INIT_EVENTS) != 0){
    std::cerr << "SDL_Init failed: " << SDL_GetError() << "\n"; return 1;
  }
#ifdef HAVE_SDL_IMAGE
  IMG_Init(IMG_INIT_PNG);
#endif

  int W=1280, H=720;
  SDL_Window*   win = SDL_CreateWindow("Midnight Warrens — SDL Client",
                    SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, W, H, SDL_WINDOW_SHOWN);
  SDL_Renderer* ren = SDL_CreateRenderer(win, -1, SDL_RENDERER_ACCELERATED | SDL_RENDERER_PRESENTVSYNC);
  if (!win || !ren){ std::cerr << "SDL window/renderer failed: " << SDL_GetError() << "\n"; return 1; }

  Camera cam; cam.screenW = W; cam.screenH = H; cam.zoom = 1.0f;

  // Networking
  SecureUDP udp;
  if (!udp.initialize(0)) { std::cerr << "client init failed\n"; return 1; }
  udp.setSharedKey(SHARED_KEY);

  WorldState world;
  std::atomic<bool> running{true};

  // Login flow state
  int myCharId = -1; // chosen character id

  udp.setOnPacket([&](const std::string&, uint16_t, const std::vector<uint8_t>& data, bool){
    std::string s(data.begin(), data.end());
    auto kv = proto::parseKV(s);
    if (!kv.count("T")) return;
    const std::string T = kv.at("T");
    if (T == "ok"){
      std::string msg = kv.count("msg")? kv.at("msg"):"";
      if (msg == "char_created"){
        if (kv.count("char_id")){
          myCharId = std::stoi(kv.at("char_id"));
          sendKV(udp, host, port, {{"T","select_char"},{"id", std::to_string(myCharId)}});
          sendKV(udp, host, port, {{"T","join"},{"zone","overworld"}});
        } else {
          sendKV(udp, host, port, {{"T","list_chars"}});
        }
      }
    } else if (T == "chars"){
      size_t n = kv.count("n") ? (size_t)std::stoul(kv.at("n")) : 0;
      if (n==0){
        sendKV(udp, host, port, {{"T","create_char"},{"name","Hero"},{"class","warrior"}});
      } else {
        // pick first
        if (kv.count("id0")) {
          myCharId = std::stoi(kv.at("id0"));
          sendKV(udp, host, port, {{"T","select_char"},{"id", std::to_string(myCharId)}});
          sendKV(udp, host, port, {{"T","join"},{"zone","overworld"}});
        }
      }
    } else if (T == "snap"){
      // Parse snapshot into world state
      std::vector<Entity> ents;
      size_t n = kv.count("n") ? (size_t)std::stoul(kv.at("n")) : 0;
      ents.reserve(n);
      for (size_t i=0; i<n; ++i){
        std::string idk = "id"+std::to_string(i);
        std::string xk  = "x" +std::to_string(i);
        std::string yk  = "y" +std::to_string(i);
        if (kv.count(idk) && kv.count(xk) && kv.count(yk)){
          Entity e; e.id = (uint64_t)std::stoull(kv[idk]); e.x = std::stof(kv[xk]); e.y = std::stof(kv[yk]);
          ents.push_back(e);
        }
      }
      {
        std::lock_guard<std::mutex> lk(world.mx);
        world.ents.swap(ents);
        // center camera on me if present
        for (auto& e : world.ents){ if ((int)e.id == myCharId){ cam.cx = e.x; cam.cy = e.y; break; } }
      }
    }
  });

  // Register/login/list
  const std::string USER = "test";
  const std::string PASS = "test";
  sendKV(udp, host, port, {{"T","register"},{"user",USER},{"pass",PASS}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  sendKV(udp, host, port, {{"T","login"},{"user",USER},{"pass",PASS}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  sendKV(udp, host, port, {{"T","list_chars"}});

  // simple timers
  auto lastHb   = steady_clock::now();
  auto lastMove = steady_clock::now();

  bool keyW=false,keyA=false,keyS=false,keyD=false;

  while (running.load()){
    // events
    SDL_Event ev;
    while (SDL_PollEvent(&ev)){
      if (ev.type == SDL_QUIT) running.store(false);
      else if (ev.type == SDL_KEYDOWN){
        if (ev.key.keysym.sym == SDLK_ESCAPE) running.store(false);
        if (ev.key.keysym.sym == SDLK_w) keyW = true;
        if (ev.key.keysym.sym == SDLK_a) keyA = true;
        if (ev.key.keysym.sym == SDLK_s) keyS = true;
        if (ev.key.keysym.sym == SDLK_d) keyD = true;
        if (ev.key.keysym.sym == SDLK_q) running.store(false);
        if (ev.key.keysym.sym == SDLK_EQUALS || ev.key.keysym.sym == SDLK_PLUS) cam.zoom = std::min(2.5f, cam.zoom + 0.1f);
        if (ev.key.keysym.sym == SDLK_MINUS) cam.zoom = std::max(0.5f, cam.zoom - 0.1f);
      } else if (ev.type == SDL_KEYUP){
        if (ev.key.keysym.sym == SDLK_w) keyW = false;
        if (ev.key.keysym.sym == SDLK_a) keyA = false;
        if (ev.key.keysym.sym == SDLK_s) keyS = false;
        if (ev.key.keysym.sym == SDLK_d) keyD = false;
      } else if (ev.type == SDL_WINDOWEVENT && ev.window.event == SDL_WINDOWEVENT_SIZE_CHANGED){
        cam.screenW = ev.window.data1; cam.screenH = ev.window.data2;
      }
    }

    // heartbeat every ~2s
    auto now = steady_clock::now();
    if (duration_cast<seconds>(now - lastHb).count() >= 2){
      sendKV(udp, host, port, {{"T","hb"}});
      lastHb = now;
    }

    // movement repeat (at most ~15Hz)
    if (duration_cast<milliseconds>(now - lastMove).count() >= 66){
      float dx=0, dy=0; const float STEP=0.25f;
      if (keyW) dy -= STEP;
      if (keyS) dy += STEP;
      if (keyA) dx -= STEP;
      if (keyD) dx += STEP;
      if (dx!=0 || dy!=0){
        sendKV(udp, host, port, {{"T","move"},{"dx",std::to_string(dx)},{"dy",std::to_string(dy)}});
      }
      lastMove = now;
    }

    // render
    SDL_SetRenderDrawColor(ren, 12, 12, 16, 255); // clear
    SDL_RenderClear(ren);

    // grid
    SDL_SetRenderDrawColor(ren, 40, 40, 48, 255);
    drawIsoGrid(ren, cam);

    // entities
    std::vector<Entity> entsCopy;
    {
      std::lock_guard<std::mutex> lk(world.mx);
      entsCopy = world.ents;
    }

    for (auto& e : entsCopy){
      SDL_Point p = worldToScreen(e.x, e.y, cam);
      int sz = (int)std::lround(10 * cam.zoom);
      SDL_Rect rect{ p.x - sz/2, p.y - sz, sz, sz };
      if ((int)e.id == myCharId) SDL_SetRenderDrawColor(ren, 200, 240, 80, 255); else SDL_SetRenderDrawColor(ren, 180, 80, 220, 255);
      SDL_RenderFillRect(ren, &rect);
      SDL_SetRenderDrawColor(ren, 12, 12, 16, 255);
      SDL_RenderDrawRect(ren, &rect);
    }

    SDL_RenderPresent(ren);
  }

#ifdef HAVE_SDL_IMAGE
  IMG_Quit();
#endif
  SDL_DestroyRenderer(ren);
  SDL_DestroyWindow(win);
  SDL_Quit();
  return 0;
}
