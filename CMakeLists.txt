cmake_minimum_required(VERSION 3.6)
project(pb173hw)

set(CMAKE_C_COMPILER "gcc")
set(CMAKE_CXX_COMPILER "g++")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

target_include_directories(mylog PUBLIC ${PROJECT_SOURCE_DIR}/include)
set(MYLOG_SOURCE_FILES library/mylog.c)
add_library(mylog STATIC ${MYLOG_SOURCE_FILES})

target_include_directories(mbedtls PUBLIC ${PROJECT_SOURCE_DIR}/include)
set(MBEDTLS_SOURCE_FILES library/aes.c library/aesni.c library/ctr_drbg.c library/entropy_poll.c library/entropy.c library/padlock.c library/platform_util.c library/platform.c library/sha512.c library/threading.c)
add_library(mbedtls STATIC ${MBEDTLS_SOURCE_FILES})

add_executable(pb173hw main.cpp)
target_link_libraries(pb173hw PRIVATE mylog mbedtls)