cmake_minimum_required(VERSION 3.22)
project(test-crypto C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

add_executable(tls tls.c)
target_link_libraries(tls PRIVATE OpenSSL::Crypto)

add_custom_target(run-tls
    COMMAND tls
    DEPENDS tls
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
)
