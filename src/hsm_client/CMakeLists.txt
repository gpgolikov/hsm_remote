cmake_minimum_required(VERSION 3.6)

project(hsm_client CXX)

include(${${CMAKE_PROJECT_NAME}_CMAKE_DIR}/common.cmake)

set(${PROJECT_NAME}_PUBLIC_HEADERS
        crypto/hsm_client/cipher.hpp
        crypto/hsm_client/crypto_context.hpp)

set(${PROJECT_NAME}_HEADERS
        )

set(${PROJECT_NAME}_SOURCES
        log.cpp
        client.cpp)

list(APPEND ${PROJECT_NAME}_HEADERS ${${PROJECT_NAME}_PUBLIC_HEADERS})

include_directories(
        ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/hsm_base)

add_library(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_HEADERS} ${${PROJECT_NAME}_SOURCES})
target_link_libraries(${PROJECT_NAME}
        hsm_base
        CONAN_PKG::Boost.Asio
        ws2_32 wsock32)