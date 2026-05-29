# tests/CMakeLists.txt
#
# Builds and registers the four KAT binaries as ctest tests.
#
# Run all tests from the build directory:
#   ctest --output-on-failure
#
# Run a single test:
#   ctest -R kat_system_c --output-on-failure

cmake_minimum_required(VERSION 3.20)

# Helper: create one KAT executable and register it as a ctest test.
function(add_kat_test NAME SRC SYSTEM_DIR)
    add_executable(${NAME} ${SRC})

    target_include_directories(${NAME} PRIVATE
        ${CMAKE_SOURCE_DIR}/harness
        ${CMAKE_SOURCE_DIR}/libs
        ${CMAKE_SOURCE_DIR}/systems/${SYSTEM_DIR}
        ${LIBOQS_INC}
        ${LIBSODIUM_INC}
        ${OPENSSL_INCLUDE_DIR}
    )

    target_link_libraries(${NAME} PRIVATE
        OpenSSL::Crypto
        ${LIBSODIUM_LIB}
        ${LIBOQS_LIB}
        pthread
    )

    add_test(NAME ${NAME} COMMAND ${NAME})
endfunction()

add_kat_test(kat_system_a
    ${CMAKE_CURRENT_SOURCE_DIR}/kat_system_a.cpp
    system_a)

add_kat_test(kat_system_b
    ${CMAKE_CURRENT_SOURCE_DIR}/kat_system_b.cpp
    system_b)

add_kat_test(kat_system_c
    ${CMAKE_CURRENT_SOURCE_DIR}/kat_system_c.cpp
    system_c)

add_kat_test(kat_system_d
    ${CMAKE_CURRENT_SOURCE_DIR}/kat_system_d.cpp
    system_d)
