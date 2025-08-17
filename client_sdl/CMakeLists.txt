// ==============================
// FILE: client_sdl/CMakeLists.txt
// ==============================
cmake_minimum_required(VERSION 3.16)

add_executable(mw_client_sdl
  src/main.cpp
)

target_include_directories(mw_client_sdl PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../game_common/include
)

target_link_libraries(mw_client_sdl PRIVATE mwfw)

# Try SDL2 via CMake config (MSYS2/vcpkg)
find_package(SDL2 CONFIG QUIET)
if (SDL2_FOUND)
  target_link_libraries(mw_client_sdl PRIVATE SDL2::SDL2 SDL2::SDL2main)
else()
  # Fallback to CMake's FindSDL2 module (Linux distros)
  find_package(SDL2 REQUIRED)
  if (TARGET SDL2::SDL2)
    target_link_libraries(mw_client_sdl PRIVATE SDL2::SDL2)
  else()
    target_include_directories(mw_client_sdl PRIVATE ${SDL2_INCLUDE_DIRS})
    target_link_libraries(mw_client_sdl PRIVATE ${SDL2_LIBRARIES})
  endif()
endif()

# Optional SDL2_image (not required yet, but ready for spritesheets)
find_package(SDL2_image CONFIG QUIET)
if (SDL2_image_FOUND)
  target_compile_definitions(mw_client_sdl PRIVATE HAVE_SDL_IMAGE=1)
  target_link_libraries(mw_client_sdl PRIVATE SDL2::SDL2_image)
else()
  find_package(SDL2_image QUIET)
  if (SDL2_IMAGE_FOUND)
    target_compile_definitions(mw_client_sdl PRIVATE HAVE_SDL_IMAGE=1)
    target_include_directories(mw_client_sdl PRIVATE ${SDL2_IMAGE_INCLUDE_DIRS})
    target_link_libraries(mw_client_sdl PRIVATE ${SDL2_IMAGE_LIBRARIES})
  endif()
endif()

if (WIN32)
  target_compile_definitions(mw_client_sdl PRIVATE _WIN32_WINNT=0x0601)
endif()
