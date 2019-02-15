cmake_minimum_required(VERSION 3.6)

project(hsm_lib CXX)

include(${${CMAKE_PROJECT_NAME}_CMAKE_DIR}/common.cmake)

set(${PROJECT_NAME}_PUBLIC_HEADERS
        crypto/hsm_lib/cipher.hpp
        crypto/hsm_lib/crypto_context.hpp)

set(${PROJECT_NAME}_HEADERS
        ../hsm_base/misc/common.hpp
        crypto_context_impl.hpp
        crypto_win_base.hpp
        keys.hpp)

set(${PROJECT_NAME}_SOURCES
        cipher.cpp
        crypto_context.cpp)

list(APPEND ${PROJECT_NAME}_HEADERS ${${PROJECT_NAME}_PUBLIC_HEADERS})

include_directories(
        ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/hsm_base)

add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_HEADERS} ${${PROJECT_NAME}_SOURCES})
target_link_libraries(${PROJECT_NAME}
        hsm_base
        CONAN_PKG::cryptopp)
