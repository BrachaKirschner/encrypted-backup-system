cmake_minimum_required(VERSION 3.29)
project(maman15)

set(CMAKE_CXX_STANDARD 14)

include_directories(client)

add_executable(maman15
    client/client.cpp
    client/connection_handler.cpp
    client/connection_handler.h
    client/file_utils.cpp
    client/file_utils.h
    client/protocol.h
    client/request_handler.cpp
    client/request_handler.h
    client/protocol.h)
