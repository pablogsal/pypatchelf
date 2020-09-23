cmake_minimum_required(VERSION 3.17)
project(_pypatchelf)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(_pypatchelf
        elf.h
        patchelf.cpp
        patchelf_api.h)
