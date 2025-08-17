//============================================================================
// Name        : MWFW.h
// Author      : Hisha (patched)
// Version     : 1.1
// Description : Midnight Warrens Framework header (with callback + shared key)
//============================================================================

#ifndef MWFW_H
#define MWFW_H

// Standard includes
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdint>
#include <variant>
#include <thread>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <condition_variable>
#include <functional>

// OpenSSL includes
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// zlib
#include <zlib.h>

// SQLite3
#include <sqlite3.h>

// Platform-specific includes for sockets
#ifdef _WIN32
    #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0601
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <fcntl.h>
#endif

namespace MWFW {

// Variant type for SQLite values (using std::monostate to represent NULL)
using SQLiteValue = std::variant<std::monostate, int, double, std::string, std::vector<unsigned char>>;

/************************************
 * AESWrapper Class
 * Provides AES encryption/decryption using OpenSSL EVP.
 ************************************/
class AESWrapper {
public:
    AESWrapper();
    ~AESWrapper();

    /** Set the AES key (for AES-256, a 32-byte key is required). */
    void setKey(const std::string &key);

    /** Encrypt plaintext using AES-256-CBC. */
    std::string encrypt(const std::string &plaintext, const std::string &iv);

    /** Decrypt ciphertext using AES-256-CBC. */
    std::string decrypt(const std::string &ciphertext, const std::string &iv);

private:
    static constexpr size_t AES_KEY_SIZE = 32;
    static constexpr size_t AES_BLOCK_SIZE = 16;
    bool m_isKeySet;
    std::string m_key;

    static void handleOpenSSLErrors();
};

/************************************
 * CrossPlatformZlib Namespace
 * Provides data compression and decompression using zlib.
 ************************************/
namespace CrossPlatformZlib {
std::vector<std::uint8_t> compressData(const std::vector<std::uint8_t> &data,
        int compressionLevel = 9);
std::vector<std::uint8_t> decompressData(const std::vector<std::uint8_t> &data);
}

/************************************
 * PasswordManager Class
 * Provides secure password handling using PBKDF2-HMAC-SHA256.
 ************************************/
class PasswordManagerException: public std::runtime_error {
public:
    explicit PasswordManagerException(const std::string &message) :
            std::runtime_error(message) {}
};

class PasswordManager {
public:
    static std::string generateSalt(unsigned int length = 16);
    static std::string hashPassword(const std::string &password,
            const std::string &salt, unsigned int iterations = 100000,
            unsigned int keyLength = 32);
    static bool verifyPassword(const std::string &password,
            const std::string &salt, const std::string &correctHash,
            unsigned int iterations = 100000, unsigned int keyLength = 32);

private:
    static std::string toHex(const unsigned char *buffer, size_t length);
    static std::vector<unsigned char> fromHex(const std::string &hexStr);
};

/************************************
 * SecureUDP Class
 * Provides secure UDP communication with encryption, compression,
 * fragmentation, and reassembly.
 ************************************/
class SecureUDP {
public:
    SecureUDP();
    ~SecureUDP();

    /** Initialize SecureUDP by binding to a local port. */
    bool initialize(uint16_t localPort);

    /** Send a packet. */
    bool sendPacket(const std::string &address, uint16_t port,
            const std::vector<uint8_t> &data, const std::string &aesKey,
            const std::string &iv, bool isBinary);

    /** NEW: set a receive callback and the shared AES-256 key for incoming packets */
    void setOnPacket(std::function<void(const std::string&, uint16_t,
                                        const std::vector<uint8_t>&, bool)> cb);
    void setSharedKey(const std::string& key);

private:
    std::atomic<bool> m_initialized;
#ifdef _WIN32
    SOCKET m_socket;
#else
    int m_socket;
#endif
    std::thread m_receiveThread;
    std::atomic<bool> m_stopThread;

    // Structure for reassembling fragmented packets
    struct FragmentBuffer {
        std::vector<std::vector<uint8_t>> fragments;
        size_t totalFragments = 0;
        size_t receivedCount = 0;
        std::string iv;
        char packetType = 'B'; // 'B' for binary, 'S' for string
        // NEW: sender info
        std::string fromIP;
        uint16_t fromPort = 0;
    };

    std::mutex m_reassemblyMutex;
    std::unordered_map<uint32_t, FragmentBuffer> m_reassemblyMap;

    void receiveLoop();
    void handleIncomingPacket(const uint8_t *buffer, size_t size, const sockaddr_in& fromAddr);
    void finalizeReassembly(uint32_t msgID);
    void closeSocket();
    uint32_t generateMessageID();

    // NEW: callback + shared AES key for incoming packets
    std::function<void(const std::string&, uint16_t,
                       const std::vector<uint8_t>&, bool)> m_onPacket;
    std::string m_sharedKey; // must be 32 bytes (AES-256)
};

/************************************
 * SQLite3Helper Class
 * A helper for working with SQLite3 databases.
 ************************************/
class SQLite3Helper {
public:
    SQLite3Helper();
    ~SQLite3Helper();

    bool openDatabase(const std::string &dbName);
    void closeDatabase();
    bool createTable(const std::string &createTableSQL);
    bool insertRecord(const std::string &insertSQL,
            const std::vector<SQLiteValue> &parameters);
    bool updateRecord(const std::string &updateSQL,
            const std::vector<SQLiteValue> &parameters);
    bool hasTables();
    std::vector<std::vector<SQLiteValue>> queryTable(
            const std::string &querySQL);
    int queryCount(const std::string &querySQL, const SQLiteValue &parameter);
    bool insertMultipleRecords(const std::string &insertSQL,
            const std::vector<std::vector<SQLiteValue>> &records);
    std::vector<std::vector<SQLiteValue>> queryTableWithParams(
            const std::string &querySQL,
            const std::vector<SQLiteValue> &parameters);

private:
    sqlite3 *db;
    bool executeSQL(const std::string &sql);
    bool prepareStatement(sqlite3_stmt **stmt, const std::string &sql);
    bool bindParameters(sqlite3_stmt *stmt,
            const std::vector<SQLiteValue> &parameters);
    void finalizeStatement(sqlite3_stmt *stmt);
};

} // namespace MWFW
