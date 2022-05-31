cmake_minimum_required(VERSION 3.16.3)
project(play_libelectronic_id)

set(CMAKE_CXX_STANDARD 14)

add_executable(play_libelectronic_id
        main.cpp)

find_package(Qt5 COMPONENTS Core Widgets Network Test LinguistTools Svg REQUIRED)

add_subdirectory(lib/libelectronic-id)
target_link_libraries(play_libelectronic_id electronic-id pcsc Qt5::Network Qt5::Widgets)
