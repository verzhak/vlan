
cmake_minimum_required(VERSION 3.8)

project(vlan C CXX)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -pipe -std=gnu++11 -g" CACHE string "" FORCE)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR})

############################################################################ 

add_executable(vlan main.cpp)
target_link_libraries(vlan pcap)

