cmake_minimum_required(VERSION 3.6)

set(CMAKE_VERBOSE_MAKEFILE TRUE)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "-m32 --std=c++14")

add_definitions(
        -DUNICODE)
#        -D_WIN32_WINNT=0x0601)

include(${CMAKE_SOURCE_DIR}/contrib/contrib.cmake)
