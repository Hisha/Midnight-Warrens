// ==============================
// FILE: server/src/main.cpp
// ==============================
#include "MWFW.h"
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <thread>
#include <iostream>
#include <sstream>
#include <optional>

#include "protocol.hpp"

using namespace MWFW;

static const std::string SHARED_KEY = "0123456789abcdef0123456789abcdef"; // 32 bytes
static const std::string IV         = "abcdef0123456789";                 // 16 bytes

// --- DB helpers ------------------------------------------------------------
struct DB {
    SQLite3Helper db;
    std::mutex mx;
};

static const char* SCHEMA_SQL = R"SQL(
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  salt TEXT NOT NULL,
  passhash TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS characters (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  account_id INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  class TEXT NOT NULL,
  level INTEGER NOT NULL DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(account_id, name)
);
CREATE INDEX IF NOT EXISTS idx_chars_account ON characters(account_id);
)SQL";

static bool ensureSchema(DB& db){
    std::lock_guard<std::mutex> lock(db.mx);
    return db.db.executeSQL(SCHEMA_SQL);
}

static std::optional<int> getAccountId(DB& db, const std::string& username){
    std::lock_guard<std::mutex> lock(db.mx);
    auto rows = db.db.queryTableWithParams("SELECT id FROM accounts WHERE username=?", {username});
    if (rows.empty()) return std::nullopt;
    const auto& v = rows[0][0];
    if (std::holds_alternative<int>(v)) return std::get<int>(v);
    return std::nullopt;
}

static bool createAccount(DB& db, const std::string& username, const std::string& password){
    std::string salt = PasswordManager::generateSalt(16);
    std::string hash = PasswordManager::hashPassword(password, salt);
    std::lock_guard<std::mutex> lock(db.mx);
    return db.db.insertRecord(
        "INSERT INTO accounts(username,salt,passhash) VALUES (?,?,?)",
        {username, salt, hash}
    );
}

static bool verifyAccount(DB& db, const std::string& username, const std::string& password, int& outAccountId){
    std::lock_guard<std::mutex> lock(db.mx);
    auto rows = db.db.queryTableWithParams("SELECT id,salt,passhash FROM accounts WHERE username=?", {username});
    if (rows.empty()) return false;
    int id = 0; std::string salt, passhash;
    if (std::holds_alternative<int>(rows[0][0])) id = std::get<int>(rows[0][0]); else return false;
    if (std::holds_alternative<std::string>(rows[0][1])) salt = std::get<std::string>(rows[0][1]); else return false;
    if (std::holds_alternative<std::string>(rows[0][2])) passhash = std::get<std::string>(rows[0][2]); else return false;
    bool ok = PasswordManager::verifyPassword(password, salt, passhash);
    if (ok) outAccountId = id;
    return ok;
}

static bool insertCharacter(DB& db, int accountId, const std::string& name, const std::string& klass, int& outCharId){
    std::lock_guard<std::mutex> lock(db.mx);
    bool ok = db.db.insertRecord(
        "INSERT INTO characters(account_id,name,class) VALUES (?,?,?)",
        {accountId, name, klass}
    );
    if (!ok) return false;
    // fetch id
    auto rows = db.db.queryTableWithParams("SELECT id FROM characters WHERE account_id=? AND name=?", {accountId, name});
    if (rows.empty() || !std::holds_alternative<int>(rows[0][0])) return false;
    outCharId = std::get<int>(rows[0][0]);
    return true;
}

struct CharRow { int id; std::string name; std::string klass; int level; };
static std::vector<CharRow> listCharacters(DB& db, int accountId){
    std::lock_guard<std::mutex> lock(db.mx);
    auto rows = db.db.queryTableWithParams("SELECT id,name,class,level FROM characters WHERE account_id=? ORDER BY id", {accountId});
    std::vector<CharRow> out;
    for (auto& r : rows){
        CharRow c{};
        if (r.size() >= 4 && std::holds_alternative<int>(r[0]) && std::holds_alternative<std::string>(r[1]) && std::holds_alternative<std::string>(r[2]) && std::holds_alternative<int>(r[3])){
            c.id = std::get<int>(r[0]);
            c.name = std::get<std::string>(r[1]);
            c.klass = std::get<std::string>(r[2]);
            c.level = std::get<int>(r[3]);
            out.push_back(c);
        }
    }
    return out;
}

// --- Session/Player state --------------------------------------------------
struct Session { int accountId{-1}; std::string username; int selectedChar{-1}; };
struct Player {
    uint64_t id; // char id for simplicity
    float x{0}, y{0};
    std::string ip; uint16_t port{0};
    std::chrono::steady_clock::time_point lastSeen;
};

static std::string endpointKey(const std::string& ip, uint16_t port){ std::ostringstream oss; oss<<ip<<":"<<port; return oss.str(); }

int main(){
    // DB init
    DB store;
    if (!store.db.openDatabase("mw.db")) { std::cerr << "DB open failed\n"; return 1; }
    if (!ensureSchema(store)) { std::cerr << "DB schema failed\n"; return 1; }

    // Net
    SecureUDP udp;
    if (!udp.initialize(50000)) { std::cerr << "Server bind failed\n"; return 1; }
    udp.setSharedKey(SHARED_KEY);

    std::mutex mtx; // protects sessions & players
    std::unordered_map<std::string, Session> sessions; // by ip:port
    std::unordered_map<std::string, Player>  players;  // by ip:port

    auto sendKV = [&](const std::string& ip, uint16_t port, const std::vector<std::pair<std::string,std::string>>& items){
        std::string m = proto::kv(items);
        udp.sendPacket(ip, port, std::vector<uint8_t>(m.begin(), m.end()), SHARED_KEY, IV, false);
    };

    udp.setOnPacket([&](const std::string& ip, uint16_t port, const std::vector<uint8_t>& data, bool){
        std::string msg(data.begin(), data.end());
        auto kv = proto::parseKV(msg);
        std::string type = kv.count("T")? kv["T"] : "";
        auto key = endpointKey(ip, port);
        auto now = std::chrono::steady_clock::now();

        if (type == "register") {
            std::string user = kv.count("user")? kv["user"] : "";
            std::string pass = kv.count("pass")? kv["pass"] : "";
            if (user.empty() || pass.empty()) { sendKV(ip,port,{{"T","err"},{"msg","missing"}}); return; }
            if (getAccountId(store, user).has_value()) { sendKV(ip,port,{{"T","err"},{"msg","exists"}}); return; }
            bool ok = false; try { ok = createAccount(store, user, pass); } catch(...) { ok = false; }
            if (ok) sendKV(ip,port,{{"T","ok"},{"msg","registered"}}); else sendKV(ip,port,{{"T","err"},{"msg","reg_fail"}});
            return;
        }
        if (type == "login") {
            std::string user = kv.count("user")? kv["user"] : "";
            std::string pass = kv.count("pass")? kv["pass"] : "";
            int accId = -1;
            if (!verifyAccount(store, user, pass, accId)) { sendKV(ip,port,{{"T","err"},{"msg","bad_login"}}); return; }
            {
                std::lock_guard<std::mutex> lock(mtx);
                sessions[key] = Session{accId, user, -1};
            }
            sendKV(ip,port,{{"T","ok"},{"msg","login"}});
            return;
        }
        if (type == "create_char") {
            std::lock_guard<std::mutex> lock(mtx);
            auto sit = sessions.find(key); if (sit==sessions.end()) { sendKV(ip,port,{{"T","err"},{"msg","no_session"}}); return; }
            int newId = -1; bool ok = insertCharacter(store, sit->second.accountId, kv["name"], kv.count("class")? kv["class"]:"adventurer", newId);
            if (ok) sendKV(ip,port,{{"T","ok"},{"msg","char_created"},{"char_id", std::to_string(newId)}});
            else sendKV(ip,port,{{"T","err"},{"msg","char_fail"}});
            return;
        }
        if (type == "list_chars") {
            std::lock_guard<std::mutex> lock(mtx);
            auto sit = sessions.find(key); if (sit==sessions.end()) { sendKV(ip,port,{{"T","err"},{"msg","no_session"}}); return; }
            auto rows = listCharacters(store, sit->second.accountId);
            std::vector<std::pair<std::string,std::string>> items; items.push_back({"T","chars"}); items.push_back({"n", std::to_string(rows.size())});
            for (size_t i=0;i<rows.size();++i){
                items.push_back({"id"+std::to_string(i), std::to_string(rows[i].id)});
                items.push_back({"name"+std::to_string(i), rows[i].name});
                items.push_back({"class"+std::to_string(i), rows[i].klass});
                items.push_back({"lvl"+std::to_string(i), std::to_string(rows[i].level)});
            }
            sendKV(ip,port,items);
            return;
        }
        if (type == "select_char") {
            int cid = kv.count("id") ? std::stoi(kv["id"]) : -1;
            if (cid<=0){ sendKV(ip,port,{{"T","err"},{"msg","bad_char"}}); return; }
            std::lock_guard<std::mutex> lock(mtx);
            auto sit = sessions.find(key); if (sit==sessions.end()) { sendKV(ip,port,{{"T","err"},{"msg","no_session"}}); return; }
            // validate ownership
            auto rows = listCharacters(store, sit->second.accountId);
            bool owned=false; for (auto &c:rows) if (c.id==cid) { owned=true; break; }
            if (!owned) { sendKV(ip,port,{{"T","err"},{"msg","not_owned"}}); return; }
            sit->second.selectedChar = cid;
            // ensure player exists
            auto it = players.find(key);
            if (it==players.end()){
                Player p; p.id = static_cast<uint64_t>(cid); p.ip=ip; p.port=port; p.lastSeen=now; players[key]=p;
            } else {
                it->second.id = static_cast<uint64_t>(cid); it->second.lastSeen=now;
            }
            sendKV(ip,port,{{"T","ok"},{"msg","char_selected"}});
            return;
        }
        if (type == "join") {
            std::lock_guard<std::mutex> lock(mtx);
            auto sit = sessions.find(key); if (sit==sessions.end() || sit->second.selectedChar<0) { sendKV(ip,port,{{"T","err"},{"msg","no_char"}}); return; }
            auto pit = players.find(key);
            if (pit!=players.end()) pit->second.lastSeen = now;
            sendKV(ip,port,{{"T","ok"},{"msg","join"}});
            return;
        }
        if (type == "move") {
            std::lock_guard<std::mutex> lock(mtx);
            auto it = players.find(key); if (it==players.end()) return;
            float dx = kv.count("dx") ? std::stof(kv["dx"]) : 0.0f;
            float dy = kv.count("dy") ? std::stof(kv["dy"]) : 0.0f;
            it->second.x += dx; it->second.y += dy; it->second.lastSeen = now;
            return;
        }
        if (type == "hb") { std::lock_guard<std::mutex> lock(mtx); auto it=players.find(key); if (it!=players.end()) it->second.lastSeen=now; return; }
    });

    // Tick loop: broadcast snapshots 10 Hz
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::vector<std::pair<std::string,std::string>> items;
        std::lock_guard<std::mutex> lock(mtx);
        // prune inactive (>10s)
        auto now = std::chrono::steady_clock::now();
        for (auto it = players.begin(); it != players.end();) {
            if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.lastSeen).count() > 10) it = players.erase(it); else ++it;
        }
        // build snapshot once
        std::ostringstream snap;
        snap << "T=snap;";
        size_t count = players.size();
        snap << "n=" << count << ";";
        size_t idx=0; for (auto &kvp : players){
            const Player& p = kvp.second;
            snap << "id"<<idx<<'='<<p.id<<';' << "x"<<idx<<'='<<p.x<<';' << "y"<<idx<<'='<<p.y<<';';
            ++idx;
        }
        std::string s = snap.str();
        std::vector<uint8_t> bytes(s.begin(), s.end());
        for (auto &kvp : players){ udp.sendPacket(kvp.second.ip, kvp.second.port, bytes, SHARED_KEY, IV, false); }
    }
}
