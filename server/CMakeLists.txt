add_executable(mw_server src/main.cpp)
target_include_directories(mw_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../game_common/include)
target_link_libraries(mw_server PRIVATE mwfw)
