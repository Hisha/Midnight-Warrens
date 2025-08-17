// FILE: client_sdl/src/main.cpp (drop-in replacement)
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
struct WorldState { std::vector<Entity> ents; std::mutex mx; };

// ---------------------------------------------------------------------------
// Iso helpers
static const int TILE_W = 64;      // pixels
static const int TILE_H = 32;      // pixels

struct Camera { float cx=0, cy=0; float zoom=1.0f; int screenW=1280, screenH=720; };

static inline SDL_Point worldToScreen(float wx, float wy, const Camera& cam){
  float ix = (wx - wy) * (TILE_W * 0.5f);
  float iy = (wx + wy) * (TILE_H * 0.5f);
  float icx = (cam.cx - cam.cy) * (TILE_W * 0.5f);
  float icy = (cam.cx + cam.cy) * (TILE_H * 0.5f);
  float sx = (ix - icx) * cam.zoom + cam.screenW * 0.5f;
  float sy = (iy - icy) * cam.zoom + cam.screenH * 0.5f;
  return SDL_Point{ (int)std::lround(sx), (int)std::lround(sy) };
}

static void fillIsoDiamond(SDL_Renderer* r, int tx, int ty, const Camera& cam, SDL_Color c){
  SDL_Point p = worldToScreen((float)tx, (float)ty, cam);
  int hw = (int)std::lround(TILE_W * 0.5f * cam.zoom);
  int hh = (int)std::lround(TILE_H * 0.5f * cam.zoom);
  SDL_SetRenderDrawBlendMode(r, SDL_BLENDMODE_BLEND);
  SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
  // draw horizontal spans from top to middle then middle to bottom
  for (int y = -hh; y <= hh; ++y){
    int span = (int)std::lround((1.0 - std::abs((double)y)/hh) * hw);
    SDL_RenderDrawLine(r, p.x - span, p.y + y, p.x + span, p.y + y);
  }
}

static void drawIsoGridLines(SDL_Renderer* r, const Camera& cam, SDL_Color c){
  SDL_SetRenderDrawColor(r, c.r, c.g, c.b, c.a);
  int radius = 16;
  int cx = (int)std::floor(cam.cx);
  int cy = (int)std::floor(cam.cy);
  for (int y = cy - radius; y <= cy + radius; ++y){
    for (int x = cx - radius; x <= cx + radius; ++x){
      if (std::abs((x - cx)) + std::abs((y - cy)) <= radius + 4){
        SDL_Point p = worldToScreen((float)x, (float)y, cam);
        int hw = (int)std::lround(TILE_W * 0.5f * cam.zoom);
        int hh = (int)std::lround(TILE_H * 0.5f * cam.zoom);
        SDL_Point v[5] = {{p.x, p.y-hh},{p.x+hw,p.y},{p.x,p.y+hh},{p.x-hw,p.y},{p.x,p.y-hh}};
        SDL_RenderDrawLines(r, v, 5);
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Texture utilities
#ifdef HAVE_SDL_IMAGE
static SDL_Texture* loadTextureWithWhiteKey(SDL_Renderer* ren, const std::string& path){
  SDL_Surface* surf = IMG_Load(path.c_str());
  if (!surf){ std::cerr << "IMG_Load failed: " << IMG_GetError() << "\n"; return nullptr; }
  // Convert to RGBA32 for easy pixel access
  SDL_Surface* rgba = SDL_ConvertSurfaceFormat(surf, SDL_PIXELFORMAT_RGBA32, 0);
  SDL_FreeSurface(surf);
  if (!rgba){ std::cerr << "ConvertSurfaceFormat failed\n"; return nullptr; }
  // Simple near-white alpha key
  Uint32* pix = (Uint32*)rgba->pixels;
  int count = (rgba->pitch / 4) * rgba->h;
  for (int i=0;i<count;++i){
    Uint8 r,g,b,a; SDL_GetRGBA(pix[i], rgba->format, &r,&g,&b,&a);
    if (r>=245 && g>=245 && b>=245) { a = 0; }
    pix[i] = SDL_MapRGBA(rgba->format, r,g,b,a);
  }
  SDL_Texture* tex = SDL_CreateTextureFromSurface(ren, rgba);
  SDL_FreeSurface(rgba);
  if (!tex){ std::cerr << "CreateTextureFromSurface failed: " << SDL_GetError() << "\n"; }
  SDL_SetTextureBlendMode(tex, SDL_BLENDMODE_BLEND);
  return tex;
}
#endif

// ---------------------------------------------------------------------------
static void sendKV(SecureUDP& udp, const std::string& host, uint16_t port,
                   const std::vector<std::pair<std::string,std::string>>& items){
  std::string m = proto::kv(items);
  std::vector<uint8_t> bytes(m.begin(), m.end());
  udp.sendPacket(host, port, bytes, SHARED_KEY, IV, false);
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

  // --- Load assets (player strip) -----------------------------------------
#ifdef HAVE_SDL_IMAGE
  const std::string ASSET_PLAYER = "assets/player_walk_NE_strip.png"; // put your generated strip here
  SDL_Texture* playerStrip = loadTextureWithWhiteKey(ren, ASSET_PLAYER);
  int stripW=0, stripH=0; if (playerStrip) SDL_QueryTexture(playerStrip, nullptr, nullptr, &stripW, &stripH);
  const int FRAME_W = 128, FRAME_H = 128;
  int cols = (stripW>0) ? (stripW / FRAME_W) : 0; if (cols<=0) cols = 1; if (cols>12) cols=12; // safeguard
  int framesCount = std::min(6, cols); // we’ll just use up to 6 frames
  std::vector<SDL_Rect> playerSrc;
  for (int i=0;i<framesCount;++i) playerSrc.push_back(SDL_Rect{ i*FRAME_W, 0, FRAME_W, FRAME_H });
#else
  SDL_Texture* playerStrip = nullptr; std::vector<SDL_Rect> playerSrc; int framesCount = 0; const int FRAME_W=128, FRAME_H=128;
#endif

  // Networking
  SecureUDP udp; if (!udp.initialize(0)) { std::cerr << "client init failed\n"; return 1; }
  udp.setSharedKey(SHARED_KEY);
  WorldState world; std::atomic<bool> running{true}; int myCharId = -1;

  udp.setOnPacket([&](const std::string&, uint16_t, const std::vector<uint8_t>& data, bool){
    std::string s(data.begin(), data.end()); auto kv = proto::parseKV(s); if (!kv.count("T")) return; const std::string T = kv.at("T");
    if (T == "ok"){
      std::string msg = kv.count("msg")? kv.at("msg"):"";
      if (msg == "char_created"){
        if (kv.count("char_id")){
          myCharId = std::stoi(kv.at("char_id"));
          sendKV(udp, host, port, {{"T","select_char"},{"id", std::to_string(myCharId)}});
          sendKV(udp, host, port, {{"T","join"},{"zone","overworld"}});
        } else sendKV(udp, host, port, {{"T","list_chars"}});
      }
    } else if (T == "chars"){
      size_t n = kv.count("n") ? (size_t)std::stoul(kv.at("n")) : 0;
      if (n==0) sendKV(udp, host, port, {{"T","create_char"},{"name","Hero"},{"class","warrior"}});
      else if (kv.count("id0")){
        myCharId = std::stoi(kv.at("id0"));
        sendKV(udp, host, port, {{"T","select_char"},{"id", std::to_string(myCharId)}});
        sendKV(udp, host, port, {{"T","join"},{"zone","overworld"}});
      }
    } else if (T == "snap"){
      std::vector<Entity> ents; size_t n = kv.count("n") ? (size_t)std::stoul(kv.at("n")) : 0; ents.reserve(n);
      for (size_t i=0;i<n;++i){
        std::string idk="id"+std::to_string(i), xk="x"+std::to_string(i), yk="y"+std::to_string(i);
        if (kv.count(idk) && kv.count(xk) && kv.count(yk)){
          Entity e; e.id=(uint64_t)std::stoull(kv[idk]); e.x=std::stof(kv[xk]); e.y=std::stof(kv[yk]); ents.push_back(e);
        }
      }
      { std::lock_guard<std::mutex> lk(world.mx); world.ents.swap(ents); for (auto& e: world.ents){ if ((int)e.id==myCharId){ cam.cx=e.x; cam.cy=e.y; break; } } }
    }
  });

  // Register/login/list
  const std::string USER = "test"; const std::string PASS = "test";
  sendKV(udp, host, port, {{"T","register"},{"user",USER},{"pass",PASS}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  sendKV(udp, host, port, {{"T","login"},{"user",USER},{"pass",PASS}});
  std::this_thread::sleep_for(std::chrono::milliseconds(100));
  sendKV(udp, host, port, {{"T","list_chars"}});

  // timers
  auto lastHb = steady_clock::now(); auto lastMove = steady_clock::now(); auto lastAnim = steady_clock::now(); int animIdx = 0;
  bool keyW=false,keyA=false,keyS=false,keyD=false;

  while (running.load()){
    // events
    SDL_Event ev; while (SDL_PollEvent(&ev)){
      if (ev.type==SDL_QUIT) running.store(false);
      else if (ev.type==SDL_KEYDOWN){
        if (ev.key.keysym.sym == SDLK_ESCAPE || ev.key.keysym.sym==SDLK_q) running.store(false);
        if (ev.key.keysym.sym == SDLK_w) keyW = true; if (ev.key.keysym.sym == SDLK_a) keyA = true; if (ev.key.keysym.sym == SDLK_s) keyS = true; if (ev.key.keysym.sym == SDLK_d) keyD = true;
        if (ev.key.keysym.sym == SDLK_EQUALS || ev.key.keysym.sym == SDLK_PLUS) cam.zoom = std::min(2.5f, cam.zoom + 0.1f);
        if (ev.key.keysym.sym == SDLK_MINUS) cam.zoom = std::max(0.5f, cam.zoom - 0.1f);
      } else if (ev.type==SDL_KEYUP){
        if (ev.key.keysym.sym == SDLK_w) keyW = false; if (ev.key.keysym.sym == SDLK_a) keyA = false; if (ev.key.keysym.sym == SDLK_s) keyS = false; if (ev.key.keysym.sym == SDLK_d) keyD = false;
      } else if (ev.type==SDL_WINDOWEVENT && ev.window.event==SDL_WINDOWEVENT_SIZE_CHANGED){ cam.screenW=ev.window.data1; cam.screenH=ev.window.data2; }
    }

    auto now = steady_clock::now();
    if (duration_cast<seconds>(now - lastHb).count() >= 2){ sendKV(udp, host, port, {{"T","hb"}}); lastHb = now; }
    if (duration_cast<milliseconds>(now - lastMove).count() >= 66){
      float dx=0, dy=0; const float STEP=0.25f; if (keyW) dy-=STEP; if (keyS) dy+=STEP; if (keyA) dx-=STEP; if (keyD) dx+=STEP; if (dx||dy){ sendKV(udp, host, port, {{"T","move"},{"dx",std::to_string(dx)},{"dy",std::to_string(dy)}}); } lastMove = now; }
    if (duration_cast<milliseconds>(now - lastAnim).count() >= 120){ if (framesCount>0){ animIdx = (animIdx + 1) % framesCount; } lastAnim = now; }

    // render
    SDL_SetRenderDrawColor(ren, 18, 18, 22, 255); SDL_RenderClear(ren);

    // filled ground (simple checkerboard of two colors)
    SDL_Color c1{70,110,70,255}, c2{60,95,60,255};
    int radius = 14; int cxT=(int)std::floor(cam.cx), cyT=(int)std::floor(cam.cy);
    for (int ty=cyT-radius; ty<=cyT+radius; ++ty){
      for (int tx=cxT-radius; tx<=cxT+radius; ++tx){
        if (std::abs((tx-cxT)) + std::abs((ty-cyT)) <= radius + 2){ SDL_Color cc = ((tx+ty)&1) ? c1 : c2; fillIsoDiamond(ren, tx, ty, cam, cc); }
      }
    }
    // optional grid lines on top
    drawIsoGridLines(ren, cam, SDL_Color{30,30,36,180});

    // entities
    std::vector<Entity> entsCopy; { std::lock_guard<std::mutex> lk(world.mx); entsCopy = world.ents; }
    for (auto& e : entsCopy){
      SDL_Point p = worldToScreen(e.x, e.y, cam);
#ifdef HAVE_SDL_IMAGE
      if (playerStrip && !playerSrc.empty()){
        SDL_Rect src = playerSrc[animIdx % playerSrc.size()];
        int w = (int)std::lround(src.w * cam.zoom), h = (int)std::lround(src.h * cam.zoom);
        // anchor feet to tile center: place bottom center at (p.x, p.y)
        SDL_Rect dst{ p.x - w/2, p.y - h + (int)std::lround(8*cam.zoom), w, h };
        SDL_RenderCopy(ren, playerStrip, &src, &dst);
      } else
#endif
      {
        // fallback: colored marker
        int sz = (int)std::lround(10 * cam.zoom); SDL_Rect rect{ p.x - sz/2, p.y - sz, sz, sz };
        if ((int)e.id == myCharId) SDL_SetRenderDrawColor(ren, 200, 240, 80, 255); else SDL_SetRenderDrawColor(ren, 180, 80, 220, 255);
        SDL_RenderFillRect(ren, &rect); SDL_SetRenderDrawColor(ren, 12, 12, 16, 255); SDL_RenderDrawRect(ren, &rect);
      }
    }

    SDL_RenderPresent(ren);
  }

#ifdef HAVE_SDL_IMAGE
  IMG_Quit();
#endif
  SDL_DestroyRenderer(ren); SDL_DestroyWindow(win); SDL_Quit(); return 0;
}
