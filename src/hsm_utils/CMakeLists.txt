cmake_minimum_required(VERSION 3.6)

project(hsm_utils CXX)

include(${${CMAKE_PROJECT_NAME}_CMAKE_DIR}/common.cmake)

include_directories(
        ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/hsm_base
        ${${CMAKE_PROJECT_NAME}_SOURCE_DIR}/hsm_lib)

set(${PROJECT_NAME}_HEADERS
        )

set(${PROJECT_NAME}_SOURCES
        main.cpp
        log.cpp)

add_executable(${PROJECT_NAME} ${${PROJECT_NAME}_SOURCES} ${${PROJECT_NAME}_HEADERS})
target_link_libraries(${PROJECT_NAME}
        hsm_base
        CONAN_PKG::Boost.Program_Options)