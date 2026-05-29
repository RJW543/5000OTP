/*
 * systems/system_b/main.cpp - System B entry point (SNOW-V-GCM).
 *
 * Instantiates RunLoop<CipherB, KEM_LEVEL> and delegates to run().
 * KEM_LEVEL is defined by CMake as 768 or 1024 at compile time, producing
 * two separate binaries: system_b_kem768 and system_b_kem1024.
 *
 * Usage: ./system_b_kem768 <duration_secs> <rate_mbps> <packet_bytes>
 * Example: ./system_b_kem768 70 1.5 1400
 */

#include "cipher.hpp"
#include "../../harness/run_loop.hpp"

int main(int argc, char** argv) {
#if KEM_LEVEL == 768
    return RunLoop<CipherB, KEM_768>{}.run(argc, argv);
#elif KEM_LEVEL == 1024
    return RunLoop<CipherB, KEM_1024>{}.run(argc, argv);
#else
    #error "KEM_LEVEL must be 768 or 1024 - check CMakeLists.txt"
#endif
}
