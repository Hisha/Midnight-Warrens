cmake_minimum_required(VERSION 3.16)
project(MidnightWarrens LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(BUILD_CLIENT "Build client" ON)
option(BUILD_SERVER "Build server" ON)

add_subdirectory(mwfw)
add_subdirectory(game_common)
if (BUILD_SERVER)
  add_subdirectory(server)
endif()
if (BUILD_CLIENT)
  add_subdirectory(client)
endif()
