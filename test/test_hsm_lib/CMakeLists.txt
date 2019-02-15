cmake_minimum_required(VERSION 3.6)

set(PROJECT hsm_lib)

project(test_${PROJECT} CXX)

set(TARGET_LIB ${PROJECT_NAME})
set(TARGET_CLIENT ${PROJECT_NAME}_client)

include(${${CMAKE_PROJECT_NAME}_CMAKE_DIR}/common.cmake)

include_directories(
        ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/hsm_base
        ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/hsm_lib
        ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/hsm_client)

set(${TARGET_LIB}_HEADERS
        common.hpp)

set(${TARGET_LIB}_SOURCES
        main.cpp
        log.cpp
        test_crypto_context.cpp
        test_cipher.cpp
        test_rnd.cpp
        test_utilities.cpp)

add_executable(${TARGET_LIB} ${${TARGET_LIB}_SOURCES} ${${TARGET_LIB}_HEADERS})
target_link_libraries(${TARGET_LIB}
        hsm_base
        hsm_lib
        CONAN_PKG::Catch)

set(${TARGET_CLIENT}_HEADERS
        common.hpp)

set(${TARGET_CLIENT}_SOURCES
        main.cpp
        log.cpp
        test_client.cpp)

add_executable(${TARGET_CLIENT} ${${TARGET_CLIENT}_SOURCES} ${${TARGET_CLIENT}_HEADERS})
target_link_libraries(${TARGET_CLIENT}
        hsm_base
        hsm_client
        CONAN_PKG::Catch)