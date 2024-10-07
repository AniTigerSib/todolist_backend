cmake_minimum_required(VERSION 3.5)
project(Google_tests CXX)

# GoogleTest requires at least C++14
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

file(GLOB_RECURSE sources tests.cc ${CMAKE_CURRENT_SOURCE_DIR}/lib/*.cc)

# add_subdirectory(lib)
include_directories(${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR})

enable_testing()

add_executable(Google_Tests_run ${sources})
target_link_libraries(Google_Tests_run gtest gtest_main)

include(GoogleTest)
gtest_discover_tests(Google_Tests_run)