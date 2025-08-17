//============================================================================
// Name        : MWFW.cpp
// Author      : Hisha (patched)
// Version     : 1.1
// Description : Midnight Warrens Framework source (with callback + shared key)
//============================================================================
#include "../include/MWFW.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <random>
#include <chrono>

namespace MWFW {

/************************************
 * AESWrapper Implementation
 ************************************/
AESWrapper::AESWrapper() :
        m_isKeySet(false) {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

AESWrapper::~AESWrapper() {
    ERR_free_strings();
}

void AESWrapper::setKey(const std::string &key) {
    if (key.size() != AES_KEY_SIZE) {
        throw std::runtime_error(
                "AESWrapper::setKey: Key length is not 32 bytes (AES-256).");
    }
    m_key = key;
    m_isKeySet = true;
}

std::string AESWrapper::encrypt(const std::string &plaintext,
        const std::string &iv) {
    if (!m_isKeySet) {
        throw std::runtime_error("AESWrapper::encrypt: No key is set.");
    }
    if (iv.size() != AES_BLOCK_SIZE) {
        throw std::runtime_error(
                "AESWrapper::encrypt: IV length must be 16 bytes for AES.");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleOpenSSLErrors();
        throw std::runtime_error(
                "AESWrapper::encrypt: Failed to create EVP_CIPHER_CTX.");
    }

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    if (1
            != EVP_EncryptInit_ex(ctx, cipher, nullptr,
                    reinterpret_cast<const unsigned char*>(m_key.data()),
                    reinterpret_cast<const unsigned char*>(iv.data()))) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
        throw std::runtime_error(
                "AESWrapper::encrypt: EVP_EncryptInit_ex failed.");
    }

    std::vector<unsigned char> outBuf(plaintext.size() + AES_BLOCK_SIZE);
    int outLen = 0;
    if (1
            != EVP_EncryptUpdate(ctx, outBuf.data(), &outLen,
                    reinterpret_cast<const unsigned char*>(plaintext.data()),
                    static_cast<int>(plaintext.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
        throw std::runtime_error(
                "AESWrapper::encrypt: EVP_EncryptUpdate failed.");
    }

    int finalLen = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, outBuf.data() + outLen, &finalLen)) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
        throw std::runtime_error(
                "AESWrapper::encrypt: EVP_EncryptFinal_ex failed.");
    }

    outLen += finalLen;
    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<const char*>(outBuf.data()),
            static_cast<size_t>(outLen));
}

std::string AESWrapper::decrypt(const std::string &ciphertext,
        const std::string &iv) {
    if (!m_isKeySet) {
        throw std::runtime_error("AESWrapper::decrypt: No key is set.");
    }
    if (iv.size() != AES_BLOCK_SIZE) {
        throw std::runtime_error(
                "AESWrapper::decrypt: IV length must be 16 bytes for AES.");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handleOpenSSLErrors();
        throw std::runtime_error(
                "AESWrapper::decrypt: Failed to create EVP_CIPHER_CTX.");
    }

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    if (1
            != EVP_DecryptInit_ex(ctx, cipher, nullptr,
                    reinterpret_cast<const unsigned char*>(m_key.data()),
                    reinterpret_cast<const unsigned char*>(iv.data()))) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
        throw std::runtime_error(
                "AESWrapper::decrypt: EVP_DecryptInit_ex failed.");
    }

    std::vector<unsigned char> outBuf(ciphertext.size() + AES_BLOCK_SIZE);
    int outLen = 0;
    if (1
            != EVP_DecryptUpdate(ctx, outBuf.data(), &outLen,
                    reinterpret_cast<const unsigned char*>(ciphertext.data()),
                    static_cast<int>(ciphertext.size()))) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
        throw std::runtime_error(
                "AESWrapper::decrypt: EVP_DecryptUpdate failed.");
    }

    int finalLen = 0;
    if (1 != EVP_DecryptFinal_ex(ctx, outBuf.data() + outLen, &finalLen)) {
        EVP_CIPHER_CTX_free(ctx);
        handleOpenSSLErrors();
        throw std::runtime_error(
                "AESWrapper::decrypt: EVP_DecryptFinal_ex failed (data may be corrupted).");
    }

    outLen += finalLen;
    EVP_CIPHER_CTX_free(ctx);
    return std::string(reinterpret_cast<const char*>(outBuf.data()),
            static_cast<size_t>(outLen));
}

void AESWrapper::handleOpenSSLErrors() {
    unsigned long errCode = ERR_get_error();
    if (errCode) {
        char errBuffer[120] = { 0 };
        ERR_error_string_n(errCode, errBuffer, sizeof(errBuffer));
        throw std::runtime_error(std::string("OpenSSL error: ") + errBuffer);
    }
}

/************************************
 * CrossPlatformZlib Implementation
 ************************************/
namespace CrossPlatformZlib {

static std::string zlibErrorToString(int errorCode) {
    switch (errorCode) {
    case Z_OK: return "Z_OK (no error)";
    case Z_STREAM_END: return "Z_STREAM_END (end of stream)";
    case Z_NEED_DICT: return "Z_NEED_DICT (dictionary needed)";
    case Z_ERRNO: return "Z_ERRNO (error reading or writing to file)";
    case Z_STREAM_ERROR: return "Z_STREAM_ERROR (invalid compression level)";
    case Z_DATA_ERROR: return "Z_DATA_ERROR (invalid or incomplete deflate data)";
    case Z_MEM_ERROR: return "Z_MEM_ERROR (out of memory)";
    case Z_BUF_ERROR: return "Z_BUF_ERROR (output buffer wasn't large enough)";
    case Z_VERSION_ERROR: return "Z_VERSION_ERROR (zlib library version mismatch)";
    default: return "Unknown zlib error code: " + std::to_string(errorCode);
    }
}

std::vector<std::uint8_t> compressData(const std::vector<std::uint8_t> &data,
        int compressionLevel) {
    if (data.empty()) return {};

    z_stream strm { };
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    int ret = deflateInit(&strm, compressionLevel);
    if (ret != Z_OK) {
        throw std::runtime_error(
                "deflateInit failed: " + zlibErrorToString(ret));
    }

    uLong bound = deflateBound(&strm, static_cast<uLong>(data.size()));
    std::vector<std::uint8_t> outBuffer(bound);

    strm.avail_in = static_cast<uInt>(data.size());
    strm.next_in =
            const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data.data()));
    strm.avail_out = static_cast<uInt>(outBuffer.size());
    strm.next_out = reinterpret_cast<Bytef*>(outBuffer.data());

    ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        deflateEnd(&strm);
        throw std::runtime_error("deflate failed: " + zlibErrorToString(ret));
    }

    outBuffer.resize(strm.total_out);
    ret = deflateEnd(&strm);
    if (ret != Z_OK) {
        throw std::runtime_error(
                "deflateEnd failed: " + zlibErrorToString(ret));
    }

    return outBuffer;
}

std::vector<std::uint8_t> decompressData(
        const std::vector<std::uint8_t> &data) {
    if (data.empty()) return {};

    z_stream strm { };
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    int ret = inflateInit(&strm);
    if (ret != Z_OK) {
        throw std::runtime_error(
                "inflateInit failed: " + zlibErrorToString(ret));
    }

    const size_t CHUNK_SIZE = 256 * 1024;
    std::vector<std::uint8_t> outBuffer;
    outBuffer.reserve(CHUNK_SIZE);

    strm.avail_in = static_cast<uInt>(data.size());
    strm.next_in =
            const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data.data()));

    std::vector<std::uint8_t> temp(CHUNK_SIZE);
    do {
        strm.avail_out = static_cast<uInt>(temp.size());
        strm.next_out = reinterpret_cast<Bytef*>(temp.data());
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT || ret == Z_DATA_ERROR
                || ret == Z_MEM_ERROR) {
            inflateEnd(&strm);
            throw std::runtime_error(
                    "inflate error: " + zlibErrorToString(ret));
        }
        size_t have = temp.size() - strm.avail_out;
        outBuffer.insert(outBuffer.end(), temp.begin(), temp.begin() + have);
    } while (ret != Z_STREAM_END);

    ret = inflateEnd(&strm);
    if (ret != Z_OK) {
        throw std::runtime_error(
                "inflateEnd failed: " + zlibErrorToString(ret));
    }

    return outBuffer;
}

} // namespace CrossPlatformZlib

/************************************
 * PasswordManager Implementation
 ************************************/
std::string PasswordManager::toHex(const unsigned char *buffer, size_t length) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i)
        oss << std::setw(2) << static_cast<int>(buffer[i]);
    return oss.str();
}

std::vector<unsigned char> PasswordManager::fromHex(const std::string &hexStr) {
    if (hexStr.size() % 2 != 0)
        throw PasswordManagerException("Invalid hex string length");
    std::vector<unsigned char> bytes;
    bytes.reserve(hexStr.size() / 2);
    for (size_t i = 0; i < hexStr.size(); i += 2) {
        unsigned int byte;
        std::istringstream iss(hexStr.substr(i, 2));
        iss >> std::hex >> byte;
        if (iss.fail())
            throw PasswordManagerException("Invalid hex character");
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    return bytes;
}

std::string PasswordManager::generateSalt(unsigned int length) {
    if (length == 0)
        throw PasswordManagerException("Salt length cannot be zero");
    std::vector<unsigned char> saltBuf(length);
    if (RAND_bytes(saltBuf.data(), static_cast<int>(saltBuf.size())) != 1)
        throw PasswordManagerException("Failed to generate random salt");
    return toHex(saltBuf.data(), saltBuf.size());
}

std::string PasswordManager::hashPassword(const std::string &password,
        const std::string &salt, unsigned int iterations,
        unsigned int keyLength) {
    if (password.empty())
        throw PasswordManagerException("Password cannot be empty");
    if (salt.empty())
        throw PasswordManagerException("Salt cannot be empty");
    if (iterations < 1000)
        throw PasswordManagerException("Iteration count is too low");
    if (keyLength == 0)
        throw PasswordManagerException("Key length cannot be zero");

    std::vector<unsigned char> saltBytes = fromHex(salt);
    std::vector<unsigned char> hashBuf(keyLength);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), static_cast<int>(password.size()),
            saltBytes.data(), static_cast<int>(saltBytes.size()),
            static_cast<int>(iterations), EVP_sha256(),
            static_cast<int>(keyLength), hashBuf.data()) != 1)
        throw PasswordManagerException("Failed to compute PBKDF2 hash");
    return toHex(hashBuf.data(), hashBuf.size());
}

bool PasswordManager::verifyPassword(const std::string &password,
        const std::string &salt, const std::string &correctHash,
        unsigned int iterations, unsigned int keyLength) {
    std::string hashedInput = hashPassword(password, salt, iterations,
            keyLength);
    if (hashedInput.size() != correctHash.size())
        return false;
    volatile unsigned int result = 0;
    for (size_t i = 0; i < hashedInput.size(); ++i)
        result |= (hashedInput[i] ^ correctHash[i]);
    return (result == 0);
}

/************************************
 * SecureUDP Implementation
 ************************************/

// Constants for UDP packet fragmentation
static const size_t MAX_UDP_PAYLOAD_SIZE = 65507;
static const size_t HEADER_SIZE = 4 + 2 + 2 + 16 + 1; // msgID + totalFrags + fragIdx + IV + type
static const size_t FRAGMENT_MAX_DATA_SIZE = MAX_UDP_PAYLOAD_SIZE - HEADER_SIZE;

// Utility functions for socket initialization and cleanup
static bool initializeSockets() {
#ifdef _WIN32
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (res != 0) {
        std::cerr << "WSAStartup failed with error: " << res << std::endl;
        return false;
    }
#endif
    return true;
}

static void cleanupSockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

SecureUDP::SecureUDP() :
        m_initialized(false), m_stopThread(false) {
#ifdef _WIN32
    m_socket = INVALID_SOCKET;
#else
    m_socket = -1;
#endif
    initializeSockets();
}

SecureUDP::~SecureUDP() {
    m_stopThread.store(true);
    closeSocket();
    if (m_receiveThread.joinable())
        m_receiveThread.join();
    cleanupSockets();
}

bool SecureUDP::initialize(uint16_t localPort) {
    // Create socket
#ifdef _WIN32
    m_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_socket == INVALID_SOCKET) {
        std::cerr << "Failed to create socket. Error: " << WSAGetLastError() << std::endl;
        return false;
    }
#else
    m_socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_socket < 0) {
        std::cerr << "Failed to create socket.\n";
        return false;
    }
#endif

    // Bind to local port
    sockaddr_in localAddr;
    memset(&localAddr, 0, sizeof(localAddr));
    localAddr.sin_family = AF_INET;
    localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    localAddr.sin_port = htons(localPort);
#ifdef _WIN32
    int addrLen = static_cast<int>(sizeof(localAddr));
    if (bind(m_socket, reinterpret_cast<const sockaddr*>(&localAddr), addrLen) < 0) {
#else
    socklen_t addrLen = static_cast<socklen_t>(sizeof(localAddr));
    if (bind(m_socket, (const sockaddr*) &localAddr, addrLen) < 0) {
#endif
        std::cerr << "Failed to bind socket.\n";
        closeSocket();
        return false;
    }

    m_stopThread.store(false);
    m_receiveThread = std::thread(&SecureUDP::receiveLoop, this);
    m_initialized.store(true);
    std::cout << "SecureUDP initialized and listening on port " << localPort
            << std::endl;
    return true;
}

bool SecureUDP::sendPacket(const std::string &address, uint16_t port,
        const std::vector<uint8_t> &data, const std::string &aesKey,
        const std::string &iv, bool isBinary) {
    if (!m_initialized.load()) {
        std::cerr << "[sendPacket] Not initialized.\n";
        return false;
    }

    // 1. Compress data
    std::vector<uint8_t> compressedData;
    try {
        compressedData = CrossPlatformZlib::compressData(data, 9);
    } catch (const std::runtime_error &e) {
        std::cerr << "Compression error: " << e.what() << std::endl;
        return false;
    }

    // 2. Encrypt data (AES CBC)
    AESWrapper aes;
    try {
        aes.setKey(aesKey);
    } catch (const std::runtime_error &e) {
        std::cerr << "Invalid AES key: " << e.what() << std::endl;
        return false;
    }
    std::string compressedStr(
            reinterpret_cast<const char*>(compressedData.data()),
            compressedData.size());
    std::string encryptedStr;
    try {
        encryptedStr = aes.encrypt(compressedStr, iv);
    } catch (const std::runtime_error &e) {
        std::cerr << "Encryption error: " << e.what() << std::endl;
        return false;
    }
    std::vector<uint8_t> encryptedData(encryptedStr.begin(), encryptedStr.end());

    // 3. Fragmentation of large packets
    uint32_t msgID = generateMessageID();
    size_t totalSize = encryptedData.size();
    size_t fragmentCount = (totalSize / FRAGMENT_MAX_DATA_SIZE)
            + ((totalSize % FRAGMENT_MAX_DATA_SIZE) ? 1 : 0);
    if (fragmentCount == 0) fragmentCount = 1;

    sockaddr_in remoteAddr;
    memset(&remoteAddr, 0, sizeof(remoteAddr));
    remoteAddr.sin_family = AF_INET;
    remoteAddr.sin_port = htons(port);
    inet_pton(AF_INET, address.c_str(), &remoteAddr.sin_addr);

    char packetType = (isBinary ? 'B' : 'S');
    for (size_t fragIndex = 0; fragIndex < fragmentCount; ++fragIndex) {
        size_t offset = fragIndex * FRAGMENT_MAX_DATA_SIZE;
        size_t bytesInFragment = std::min(FRAGMENT_MAX_DATA_SIZE,
                totalSize - offset);
        std::vector<uint8_t> packet;
        packet.resize(HEADER_SIZE + bytesInFragment);
        memcpy(packet.data(), &msgID, 4);
        uint16_t tf = static_cast<uint16_t>(fragmentCount);
        memcpy(packet.data() + 4, &tf, 2);
        uint16_t fi = static_cast<uint16_t>(fragIndex);
        memcpy(packet.data() + 6, &fi, 2);
        memcpy(packet.data() + 8, iv.data(), 16);
        packet[24] = static_cast<uint8_t>(packetType);
        if (bytesInFragment > 0) {
            memcpy(packet.data() + HEADER_SIZE, encryptedData.data() + offset,
                    bytesInFragment);
        }
#ifdef _WIN32
        int remoteAddrLen = static_cast<int>(sizeof(remoteAddr));
        int sentSize = sendto(m_socket,
                reinterpret_cast<const char*>(packet.data()),
                static_cast<int>(packet.size()),
                0,
                reinterpret_cast<const sockaddr*>(&remoteAddr),
                remoteAddrLen);
        if (sentSize == SOCKET_ERROR) {
            std::cerr << "Failed to send fragment " << fragIndex << " of " << fragmentCount << ".\n";
            return false;
        }
#else
        socklen_t remoteAddrLen = static_cast<socklen_t>(sizeof(remoteAddr));
        ssize_t sentSize = sendto(m_socket, packet.data(), packet.size(), 0,
                (const sockaddr*) &remoteAddr, remoteAddrLen);
        if (sentSize < 0) {
            std::cerr << "Failed to send fragment " << fragIndex << " of "
                    << fragmentCount << ".\n";
            return false;
        }
#endif
    }
    return true;
}

void SecureUDP::receiveLoop() {
    while (!m_stopThread.load()) {
        std::vector<uint8_t> buffer(MAX_UDP_PAYLOAD_SIZE);
        sockaddr_in fromAddr;
#ifdef _WIN32
        int fromLen = static_cast<int>(sizeof(fromAddr));
        int recvSize = recvfrom(m_socket,
                reinterpret_cast<char*>(buffer.data()),
                static_cast<int>(buffer.size()),
                0,
                reinterpret_cast<sockaddr*>(&fromAddr),
                &fromLen);
        if (recvSize == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK || err == WSAECONNRESET)
                continue;
            else {
                if (!m_stopThread.load())
                    std::cerr << "recvfrom error: " << err << std::endl;
                break;
            }
        } else if (recvSize > 0) {
            handleIncomingPacket(buffer.data(), static_cast<size_t>(recvSize), fromAddr);
        }
#else
        socklen_t fromLen = static_cast<socklen_t>(sizeof(fromAddr));
        ssize_t recvSize = ::recvfrom(m_socket, buffer.data(), buffer.size(), 0,
                (sockaddr*) &fromAddr, &fromLen);
        if (recvSize < 0)
            continue;
        else if (recvSize > 0)
            handleIncomingPacket(buffer.data(), static_cast<size_t>(recvSize), fromAddr);
#endif
    }
}

void SecureUDP::handleIncomingPacket(const uint8_t *buffer, size_t size, const sockaddr_in& fromAddr) {
    if (size < HEADER_SIZE)
        return;

    uint32_t msgID;
    memcpy(&msgID, buffer, 4);
    uint16_t totalFragments;
    memcpy(&totalFragments, buffer + 4, 2);
    uint16_t fragmentIndex;
    memcpy(&fragmentIndex, buffer + 6, 2);
    char packetType = static_cast<char>(buffer[24]);
    std::string iv(reinterpret_cast<const char*>(buffer + 8), 16);

    size_t payloadSize = size - HEADER_SIZE;
    std::vector<uint8_t> encryptedFragment(payloadSize);
    if (payloadSize > 0)
        memcpy(encryptedFragment.data(), buffer + HEADER_SIZE, payloadSize);

    {
        std::lock_guard<std::mutex> lock(m_reassemblyMutex);
        auto &fragBuf = m_reassemblyMap[msgID];
        if (fragBuf.receivedCount == 0) {
            char ipbuf[INET_ADDRSTRLEN]{};
            inet_ntop(AF_INET, &fromAddr.sin_addr, ipbuf, sizeof(ipbuf));
            fragBuf.fromIP = std::string(ipbuf);
            fragBuf.fromPort = ntohs(fromAddr.sin_port);
            fragBuf.totalFragments = totalFragments;
            fragBuf.iv = iv;
            fragBuf.packetType = packetType;
        }
        if (fragBuf.fragments.size() < totalFragments)
            fragBuf.fragments.resize(totalFragments);
        if (fragBuf.fragments[fragmentIndex].empty()) {
            fragBuf.fragments[fragmentIndex] = std::move(encryptedFragment);
            fragBuf.receivedCount++;
        }
        if (fragBuf.totalFragments > 0 && fragBuf.receivedCount == fragBuf.totalFragments)
            finalizeReassembly(msgID);
    }
}

void SecureUDP::finalizeReassembly(uint32_t msgID) {
    auto it = m_reassemblyMap.find(msgID);
    if (it == m_reassemblyMap.end())
        return;
    auto &fragBuf = it->second;
    std::vector<uint8_t> fullEncryptedData;
    for (auto &frag : fragBuf.fragments)
        fullEncryptedData.insert(fullEncryptedData.end(), frag.begin(), frag.end());

    AESWrapper aes;
    try {
        // Use the shared key provided by the app
        if (m_sharedKey.size() != 32) {
            std::cerr << "[Reassembly Error] Shared key not set or wrong length (32 bytes required).\n";
            m_reassemblyMap.erase(it);
            return;
        }
        aes.setKey(m_sharedKey);
        std::string encryptedStr(
                reinterpret_cast<const char*>(fullEncryptedData.data()),
                fullEncryptedData.size());
        std::string decryptedStr = aes.decrypt(encryptedStr, fragBuf.iv);
        std::vector<uint8_t> decryptedData(decryptedStr.begin(), decryptedStr.end());
        std::vector<uint8_t> decompressedData =
                CrossPlatformZlib::decompressData(decryptedData);

        if (m_onPacket) {
            bool isBinary = (fragBuf.packetType == 'B');
            m_onPacket(fragBuf.fromIP, fragBuf.fromPort, decompressedData, isBinary);
        } else {
            if (fragBuf.packetType == 'B') {
                std::cout << "[Received Binary Packet] msgID=" << msgID
                          << " size=" << decompressedData.size() << " bytes\n";
            } else {
                std::string result(reinterpret_cast<const char*>(decompressedData.data()),
                                   decompressedData.size());
                std::cout << "[Received String Packet] msgID=" << msgID
                          << " content='" << result << "'\n";
            }
        }
    } catch (const std::runtime_error &e) {
        std::cerr << "[Reassembly Error] " << e.what() << std::endl;
    }

    m_reassemblyMap.erase(it);
}

void SecureUDP::closeSocket() {
#ifdef _WIN32
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
#else
    if (m_socket >= 0) {
        close (m_socket);
        m_socket = -1;
    }
#endif
}

uint32_t SecureUDP::generateMessageID() {
    static std::mt19937_64 rng { std::random_device { }() };
    return static_cast<uint32_t>(rng());
}

void SecureUDP::setOnPacket(std::function<void(const std::string&, uint16_t,
                                               const std::vector<uint8_t>&, bool)> cb) {
    m_onPacket = std::move(cb);
}
void SecureUDP::setSharedKey(const std::string& key) {
    m_sharedKey = key;
}

/************************************
 * SQLite3Helper Implementation
 ************************************/
SQLite3Helper::SQLite3Helper() :
        db(nullptr) {
}

SQLite3Helper::~SQLite3Helper() {
    closeDatabase();
}

bool SQLite3Helper::openDatabase(const std::string &dbName) {
    if (sqlite3_open(dbName.c_str(), &db) == SQLITE_OK)
        return true;
    std::cerr << "Failed to open database: " << sqlite3_errmsg(db) << std::endl;
    return false;
}

void SQLite3Helper::closeDatabase() {
    if (db) {
        sqlite3_close (db);
        db = nullptr;
    }
}

bool SQLite3Helper::createTable(const std::string &createTableSQL) {
    return executeSQL(createTableSQL);
}

bool SQLite3Helper::insertRecord(const std::string &insertSQL,
        const std::vector<SQLiteValue> &parameters) {
    sqlite3_stmt *stmt = nullptr;
    if (!prepareStatement(&stmt, insertSQL))
        return false;
    if (!bindParameters(stmt, parameters)) {
        finalizeStatement(stmt);
        return false;
    }
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Insert failed: " << sqlite3_errmsg(db) << std::endl;
        finalizeStatement(stmt);
        return false;
    }
    finalizeStatement(stmt);
    return true;
}

bool SQLite3Helper::updateRecord(const std::string &updateSQL,
        const std::vector<SQLiteValue> &parameters) {
    sqlite3_stmt *stmt = nullptr;
    if (!prepareStatement(&stmt, updateSQL))
        return false;
    if (!bindParameters(stmt, parameters)) {
        finalizeStatement(stmt);
        return false;
    }
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Update failed: " << sqlite3_errmsg(db) << std::endl;
        finalizeStatement(stmt);
        return false;
    }
    finalizeStatement(stmt);
    return true;
}

bool SQLite3Helper::hasTables() {
    const std::string sql = "SELECT name FROM sqlite_master WHERE type='table';";
    auto result = queryTable(sql);
    return !result.empty();
}

std::vector<std::vector<SQLiteValue>> SQLite3Helper::queryTable(
        const std::string &querySQL) {
    std::vector<std::vector<SQLiteValue>> results;
    sqlite3_stmt *stmt = nullptr;
    if (!prepareStatement(&stmt, querySQL))
        return results;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int cols = sqlite3_column_count(stmt);
        std::vector<SQLiteValue> row;
        for (int i = 0; i < cols; ++i) {
            int colType = sqlite3_column_type(stmt, i);
            switch (colType) {
            case SQLITE_INTEGER:
                row.push_back(sqlite3_column_int(stmt, i));
                break;
            case SQLITE_FLOAT:
                row.push_back(sqlite3_column_double(stmt, i));
                break;
            case SQLITE_TEXT: {
                const unsigned char *text = sqlite3_column_text(stmt, i);
                row.push_back(
                        text ? std::string(
                                        reinterpret_cast<const char*>(text)) :
                                std::string());
                break;
            }
            case SQLITE_BLOB: {
                const void *blobData = sqlite3_column_blob(stmt, i);
                int size = sqlite3_column_bytes(stmt, i);
                const unsigned char *bytes =
                        reinterpret_cast<const unsigned char*>(blobData);
                row.push_back(std::vector<unsigned char>(bytes, bytes + size));
                break;
            }
            case SQLITE_NULL:
            default:
                row.push_back(std::monostate { });
                break;
            }
        }
        results.push_back(row);
    }
    finalizeStatement(stmt);
    return results;
}

int SQLite3Helper::queryCount(const std::string &querySQL,
        const SQLiteValue &parameter) {
    sqlite3_stmt *stmt = nullptr;
    if (!prepareStatement(&stmt, querySQL))
        return -1;
    if (!bindParameters(stmt, { parameter })) {
        finalizeStatement(stmt);
        return -1;
    }
    int count = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW)
        count = sqlite3_column_int(stmt, 0);
    finalizeStatement(stmt);
    return count;
}

bool SQLite3Helper::insertMultipleRecords(const std::string &insertSQL,
        const std::vector<std::vector<SQLiteValue>> &records) {
    sqlite3_stmt *stmt = nullptr;
    if (!prepareStatement(&stmt, insertSQL))
        return false;
    for (const auto &record : records) {
        if (!bindParameters(stmt, record)) {
            finalizeStatement(stmt);
            return false;
        }
        if (sqlite3_step(stmt) != SQLITE_DONE) {
            std::cerr << "Insert failed: " << sqlite3_errmsg(db) << std::endl;
            finalizeStatement(stmt);
            return false;
        }
        sqlite3_reset(stmt);
    }
    finalizeStatement(stmt);
    return true;
}

std::vector<std::vector<SQLiteValue>> SQLite3Helper::queryTableWithParams(
        const std::string &querySQL,
        const std::vector<SQLiteValue> &parameters) {
    std::vector<std::vector<SQLiteValue>> rows;
    sqlite3_stmt *stmt = nullptr;
    if (!prepareStatement(&stmt, querySQL))
        return rows;
    if (!bindParameters(stmt, parameters)) {
        finalizeStatement(stmt);
        return rows;
    }
    int rc = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        int colCount = sqlite3_column_count(stmt);
        std::vector<SQLiteValue> columns;
        columns.reserve(colCount);
        for (int i = 0; i < colCount; ++i) {
            int colType = sqlite3_column_type(stmt, i);
            switch (colType) {
            case SQLITE_INTEGER:
                columns.push_back(sqlite3_column_int(stmt, i));
                break;
            case SQLITE_FLOAT:
                columns.push_back(sqlite3_column_double(stmt, i));
                break;
            case SQLITE_TEXT: {
                const unsigned char *text = sqlite3_column_text(stmt, i);
                columns.push_back(
                        text ? std::string(
                                        reinterpret_cast<const char*>(text)) :
                                std::string());
                break;
            }
            case SQLITE_BLOB: {
                const void *blobData = sqlite3_column_blob(stmt, i);
                int size = sqlite3_column_bytes(stmt, i);
                const unsigned char *bytes =
                        reinterpret_cast<const unsigned char*>(blobData);
                columns.push_back(
                        std::vector<unsigned char>(bytes, bytes + size));
                break;
            }
            case SQLITE_NULL:
            default:
                columns.push_back(std::monostate { });
                break;
            }
        }
        rows.push_back(columns);
    }
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        std::cerr << "Error in queryTableWithParams: " << sqlite3_errmsg(db)
                << std::endl;
    }
    finalizeStatement(stmt);
    return rows;
}

bool SQLite3Helper::executeSQL(const std::string &sql) {
    char *errMsg = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL execution failed: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

bool SQLite3Helper::prepareStatement(sqlite3_stmt **stmt,
        const std::string &sql) {
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db)
                << std::endl;
        return false;
    }
    return true;
}

bool SQLite3Helper::bindParameters(sqlite3_stmt *stmt,
        const std::vector<SQLiteValue> &parameters) {
    for (size_t i = 0; i < parameters.size(); ++i) {
        int index = static_cast<int>(i + 1);
        int rc = SQLITE_OK;
        const SQLiteValue &val = parameters[i];
        if (std::holds_alternative<int>(val))
            rc = sqlite3_bind_int(stmt, index, std::get<int>(val));
        else if (std::holds_alternative<double>(val))
            rc = sqlite3_bind_double(stmt, index, std::get<double>(val));
        else if (std::holds_alternative<std::string>(val))
            rc = sqlite3_bind_text(stmt, index,
                    std::get<std::string>(val).c_str(), -1,
                    SQLITE_TRANSIENT);
        else if (std::holds_alternative<std::vector<unsigned char>>(val)) {
            const std::vector<unsigned char> &blobData = std::get<
                    std::vector<unsigned char>>(val);
            rc = sqlite3_bind_blob(stmt, index, blobData.data(),
                    static_cast<int>(blobData.size()), SQLITE_TRANSIENT);
        } else
            rc = sqlite3_bind_null(stmt, index);

        if (rc != SQLITE_OK) {
            std::cerr << "Failed to bind parameter " << index << ": "
                    << sqlite3_errmsg(db) << std::endl;
            return false;
        }
    }
    return true;
}

void SQLite3Helper::finalizeStatement(sqlite3_stmt *stmt) {
    if (stmt)
        sqlite3_finalize(stmt);
}

} // namespace MWFW
