cmake_minimum_required(VERSION 3.6)
project(pb173hw)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=c++17")

set(MYLOG_SOURCE_FILES library/litelog.cpp)
add_library(mylog STATIC ${MYLOG_SOURCE_FILES})

set(MBEDTLS_SOURCE_FILES library/aes.c library/aesni.c library/ctr_drbg.c library/entropy_poll.c library/entropy.c library/padlock.c library/platform_util.c library/platform.c library/sha512.c library/threading.c library/timing.c)
add_library(mbedtls STATIC ${MBEDTLS_SOURCE_FILES})

add_executable(main main.cpp)
add_executable(test_main test_main.cpp)

target_link_libraries(main PRIVATE mylog mbedtls)
target_link_libraries(test_main PRIVATE mylog mbedtls)