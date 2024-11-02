cmake_minimum_required(VERSION 3.28)
project(ciphers_system)

set(CMAKE_CXX_STANDARD 17)

add_executable(ciphers_system CryptoSystem.cpp
        Cryptosystem.h
        bacon.cpp
        a1z26.cpp
        shamir.cpp
        bacon.h
        a1z26.h
        shamir.h
)
