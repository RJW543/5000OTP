cmake_minimum_required(VERSION 3.20)
project(5000OTP LANGUAGES CXX)

# Language standard

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)     # stick to -std=c++17, not -std=gnu++17


# Device selection
#
# Pass -DDEVICE=PI5 when configuring on the Pi 5.
# Pass -DDEVICE=PI0 when configuring on the Pi Zero 2 W.
#
# PI5  (Cortex-A76):
#   -march=armv8.2-a+crypto enables ARMv8.2-A baseline plus AES/SHA/PMULL
#   crypto extensions.  OpenSSL and GCC both detect and use these at runtime.
#   This is the only build flag difference that enables hardware AES; the
#   cipher code itself is identical on both devices.
#
# PI0  (Cortex-A53):
#   -march=armv8-a deliberately omits the +crypto suffix so that neither
#   OpenSSL nor GCC emits hardware AES instructions.  AES runs in pure
#   software.  This is the controlled condition for exposing true
#   algorithmic differences between the four systems.
#
# The -mtune flag advises the instruction scheduler but does not change the
# ISA; it is safe to omit if the exact CPU model is uncertain.

set(DEVICE "PI5" CACHE STRING "Target device (PI5 or PI0)")
message(STATUS "Building for DEVICE=${DEVICE}")

if(DEVICE STREQUAL "PI5")
    set(DEVICE_CXX_FLAGS
        -O2
        -march=armv8.2-a+crypto
        -mtune=cortex-a76
        -fno-omit-frame-pointer   # keeps stack traces readable in perf
    )
    message(STATUS "  Flags: ARMv8.2-A + AES/SHA/PMULL hardware (Pi 5 / Cortex-A76)")
elseif(DEVICE STREQUAL "PI0")
    set(DEVICE_CXX_FLAGS
        -O2
        -march=armv8-a
        -mtune=cortex-a53
        -fno-omit-frame-pointer
    )
    message(STATUS "  Flags: ARMv8-A baseline, no AES hardware (Pi Zero 2 W / Cortex-A53)")
else()
    message(FATAL_ERROR
        "DEVICE must be PI5 or PI0.\n"
        "Usage: cmake -B build -DDEVICE=PI5   (on the Pi 5)\n"
        "       cmake -B build -DDEVICE=PI0   (on the Pi Zero 2 W)")
endif()

add_compile_options(${DEVICE_CXX_FLAGS})

# Dependency discovery

# OpenSSL — provides AES-256-GCM for System A.
# Expected on Raspberry Pi OS: sudo apt install libssl-dev
find_package(OpenSSL REQUIRED)
message(STATUS "OpenSSL version : ${OPENSSL_VERSION}")
message(STATUS "OpenSSL include : ${OPENSSL_INCLUDE_DIR}")

# libsodium — provides ChaCha20-Poly1305 for System C.
# Expected on Raspberry Pi OS: sudo apt install libsodium-dev
find_library(LIBSODIUM_LIB sodium REQUIRED)
find_path(LIBSODIUM_INC sodium.h PATH_SUFFIXES sodium)
if(NOT LIBSODIUM_LIB OR NOT LIBSODIUM_INC)
    message(FATAL_ERROR
        "libsodium not found.\n"
        "Install with: sudo apt install libsodium-dev")
endif()
message(STATUS "libsodium lib   : ${LIBSODIUM_LIB}")
message(STATUS "libsodium inc   : ${LIBSODIUM_INC}")

# liboqs — provides ML-KEM (FIPS 203) for all four systems.
# Build from source; see Utility/setup_env.sh.
# Default install prefix: /usr/local
find_library(LIBOQS_LIB oqs
    HINTS /usr/local/lib /usr/local/lib64
    REQUIRED)
find_path(LIBOQS_INC oqs/oqs.h
    HINTS /usr/local/include
    REQUIRED)
if(NOT LIBOQS_LIB OR NOT LIBOQS_INC)
    message(FATAL_ERROR
        "liboqs not found.\n"
        "Build and install from https://github.com/open-quantum-safe/liboqs\n"
        "Pin to 0.10.x or later for FIPS 203 final.")
endif()
message(STATUS "liboqs lib      : ${LIBOQS_LIB}")
message(STATUS "liboqs inc      : ${LIBOQS_INC}")


# Include directories used by all targets

set(HARNESS_INC  ${CMAKE_SOURCE_DIR}/harness)
set(LIBS_INC     ${CMAKE_SOURCE_DIR}/libs)

# add_system_target(<system_dir> <kem_level>)
#
# Creates one benchmark executable for the given system and KEM level.
# Binary name: system_<x>_kem<level>   e.g. system_a_kem768
#
# Each binary gets:
#   - The device compile flags (already set globally above)
#   - KEM_LEVEL=<level> as a preprocessor definition
#   - Include paths: harness/, libs/, and the system's own directory
#     (so cipher.hpp can be included without a path prefix)
#   - Link: OpenSSL::Crypto, libsodium, liboqs

function(add_system_target SYSTEM_DIR KEM_LEVEL)
    set(TARGET_NAME "${SYSTEM_DIR}_kem${KEM_LEVEL}")
    set(MAIN_SRC    "${CMAKE_SOURCE_DIR}/systems/${SYSTEM_DIR}/main.cpp")

    add_executable(${TARGET_NAME} ${MAIN_SRC})

    target_include_directories(${TARGET_NAME} PRIVATE
        ${HARNESS_INC}
        ${LIBS_INC}
        ${CMAKE_SOURCE_DIR}/systems/${SYSTEM_DIR}
        ${LIBOQS_INC}
        ${LIBSODIUM_INC}
        ${OPENSSL_INCLUDE_DIR}
    )

    target_compile_definitions(${TARGET_NAME} PRIVATE
        KEM_LEVEL=${KEM_LEVEL}
    )

    target_link_libraries(${TARGET_NAME} PRIVATE
        ${LIBOQS_LIB}
        OpenSSL::Crypto
        ${LIBSODIUM_LIB}
        pthread
    )
endfunction()

# Eight benchmark targets: 4 systems × 2 KEM levels

add_system_target(system_a 768)
add_system_target(system_a 1024)
add_system_target(system_b 768)
add_system_target(system_b 1024)
add_system_target(system_c 768)
add_system_target(system_c 1024)
add_system_target(system_d 768)
add_system_target(system_d 1024)

# Tests (ctest)

enable_testing()
add_subdirectory(tests)
