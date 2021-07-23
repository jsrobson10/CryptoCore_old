cmake_minimum_required(VERSION 3.14)

project(CryptoCore VERSION 1.0)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "-g")

file(GLOB_RECURSE SOURCES src/*.cpp)
add_executable(CryptoCore ${SOURCES})

target_link_libraries(CryptoCore PUBLIC crypto bdf pthread gmp)

