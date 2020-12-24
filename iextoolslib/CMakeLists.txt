cmake_minimum_required(VERSION 3.10)

project(iex-tools VERSION 1.0)

# C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# static IEX Tools library
add_library(iextools STATIC src/pcap_utils.cpp src/pcap.cpp src/pcap_frames.cpp src/tops_messages.cpp src/tops.cpp)

# include paths
target_include_directories(iextools PUBLIC include)

# executable
add_executable(iex-tools src/main.cpp)

# link library
target_link_libraries(iex-tools iextools)
