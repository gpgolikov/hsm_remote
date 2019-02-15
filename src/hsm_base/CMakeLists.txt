cmake_minimum_required(VERSION 3.6)

project(hsm_base CXX)

include(${${CMAKE_PROJECT_NAME}_CMAKE_DIR}/common.cmake)

set(${PROJECT_NAME}_PUBLIC_HEADERS
        crypto/crypto_types.hpp
        crypto/cipher.hpp
        crypto/crypto_context.hpp
        crypto/error.hpp
        crypto/input_output.hpp
        misc/encoding.hpp
        misc/io_manip.hpp
        misc/logger.hpp
        misc/unknown_based.hpp
        misc/functional.hpp)

set(${PROJECT_NAME}_SOURCES
        logger.cpp
        )

set(${PROJECT_NAME}_HEADERS
        misc/filesystem.hpp)

list(APPEND ${PROJECT_NAME}_HEADERS ${${PROJECT_NAME}_PUBLIC_HEADERS})

find_library(BOOST_LOG boost_log)

add_library(${PROJECT_NAME} STATIC ${${PROJECT_NAME}_HEADERS} ${${PROJECT_NAME}_SOURCES})
target_link_libraries(${PROJECT_NAME} CONAN_PKG::Boost.Log ${BOOST_LOG} CONAN_PKG::Boost.Filesystem)
#target_link_libraries(${PROJECT_NAME} CONAN_PKG::Boost.Log CONAN_PKG::Boost.Filesystem)
