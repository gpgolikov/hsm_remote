cmake_minimum_required(VERSION 3.6)

project(hsm_remote)

option(BUILD_TEST "Build test module" ON)

get_filename_component(${CMAKE_PROJECT_NAME}_CMAKE_DIR cmake ABSOLUTE)
get_filename_component(${CMAKE_PROJECT_NAME}_CONTRIB_DIR contrib ABSOLUTE)
get_filename_component(${CMAKE_PROJECT_NAME}_SOURCE_DIR src ABSOLUTE)
get_filename_component(${CMAKE_PROJECT_NAME}_TEST_DIR test ABSOLUTE)

add_subdirectory(src)

if (BUILD_TEST)
    # Path to source dir
    add_subdirectory(test)
endif (BUILD_TEST)
