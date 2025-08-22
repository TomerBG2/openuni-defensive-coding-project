cmake_minimum_required(VERSION 3.21)

project(TCPClient)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Boost REQUIRED COMPONENTS system)
find_package(PkgConfig REQUIRED)
pkg_check_modules(Cryptopp REQUIRED IMPORTED_TARGET libcrypto++)

include_directories(${Boost_INCLUDE_DIRS})

file(GLOB SOURCES "src/*.cpp" "src/model/*.cpp" "src/view/*.cpp" "src/controller/*.cpp" "src/cryptopp_wrapper/*.cpp")

add_executable(tcp_client ${SOURCES})

target_link_libraries(tcp_client ${Boost_LIBRARIES} pthread  PkgConfig::Cryptopp)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")

