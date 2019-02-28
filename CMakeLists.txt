cmake_minimum_required(VERSION 3.6)
project(pb173hw)

include_directories(${PROJECT_SOURCE_DIR}/include)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra")


set(MBEDTLS_SOURCE_FILES library/aes.c library/aesni.c library/ctr_drbg.c library/entropy_poll.c library/entropy.c library/padlock.c library/platform_util.c library/platform.c library/sha512.c library/threading.c library/timing.c)
add_library(mbedtls STATIC ${MBEDTLS_SOURCE_FILES})

add_executable(main library/myaes.cpp main.cpp)
add_executable(test_main library/myaes.cpp test_main.cpp)

target_link_libraries(main PRIVATE mbedtls)
target_link_libraries(test_main PRIVATE mbedtls)