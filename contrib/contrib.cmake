cmake_minimum_required(VERSION 3.6)

include(${CMAKE_CURRENT_LIST_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)

include_directories(${CMAKE_CURRENT_LIST_DIR}/griha/include)