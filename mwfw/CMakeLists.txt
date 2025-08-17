# mwfw/CMakeLists.txt
add_library(mwfw STATIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include/MWFW.h
  ${CMAKE_CURRENT_SOURCE_DIR}/src/MWFW.cpp
)

target_include_directories(mwfw PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)      # we use EVP in libcrypto
find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)

target_link_libraries(mwfw
  PUBLIC
    ZLIB::ZLIB
    OpenSSL::Crypto
    Threads::Threads
    SQLite::SQLite3
)

if (WIN32)
  target_compile_definitions(mwfw PUBLIC _WIN32_WINNT=0x0601)
  target_link_libraries(mwfw PUBLIC ws2_32)
endif()
