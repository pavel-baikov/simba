cmake_minimum_required(VERSION 3.14)
project(SimbaDecoder VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Define NDEBUG for Release builds
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -DNDEBUG")

# Source files
set(SOURCES
    SimbaDecoder.cpp
    parser.cpp
)

# Create executable
add_executable(simba_decoder ${SOURCES})

# Include directories
target_include_directories(simba_decoder PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Compile options
target_compile_options(simba_decoder PRIVATE -Wall -Wextra -Wpedantic)

# Debug-specific configurations
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_definitions(simba_decoder PRIVATE DEBUG)
else()
    target_compile_definitions(simba_decoder PRIVATE NDEBUG)
endif()

# Installation
install(TARGETS simba_decoder DESTINATION bin)
