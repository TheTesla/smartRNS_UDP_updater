
cmake_minimum_required (VERSION 2.8)
project (smartRNS_UDP_updater)
add_definitions("-Wall -O2 -std=c++11")

file(GLOB SRCFILES *.cpp)
add_executable(smartRNS_UDP_updater ${SRCFILES})

TARGET_LINK_LIBRARIES(smartRNS_UDP_updater cryptopp resolv)

