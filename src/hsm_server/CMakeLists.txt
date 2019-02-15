cmake_minimum_required(VERSION 3.6)

project(hsm_server CXX)

include(${${CMAKE_PROJECT_NAME}_CMAKE_DIR}/common.cmake)

include_directories(
        ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/hsm_base
        ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/hsm_lib)

set(${PROJECT_NAME}_HEADERS
        error_sink.hpp
        io_crypto.hpp)

set(${PROJECT_NAME}_SOURCES
        main.cpp
        log.cpp)

add_definitions(-DBOOST_COROUTINES_NO_DEPRECATION_WARNING)

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SOURCES} ${${PROJECT_NAME}_HEADERS})
target_link_libraries(${PROJECT_NAME}
        hsm_base
        hsm_lib
        CONAN_PKG::Boost.Program_Options CONAN_PKG::Boost.Property_Tree CONAN_PKG::Boost.Asio
        ws2_32 wsock32)