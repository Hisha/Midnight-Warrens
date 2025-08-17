add_executable(mw_client src/main.cpp)
target_include_directories(mw_client PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../game_common/include)
target_link_libraries(mw_client PRIVATE mwfw)
