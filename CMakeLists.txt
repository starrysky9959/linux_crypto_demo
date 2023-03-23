cmake_minimum_required(VERSION 3.8)
project(crypto_demo)

# set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS, "-Wno-narrowing")

add_executable(skcipher
    skcipher.c
)

add_executable(skcipher_iv
    skcipher_iv.c
)

add_executable(skcipher_binary
    skcipher_binary.cpp
)

target_compile_options(skcipher_binary
    PRIVATE
    -Wno-narrowing
)