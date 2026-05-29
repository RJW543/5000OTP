/*
 * systems/system_d/main.cpp - System D entry point (Ascon-PRNG XOR).
 *
 * Instantiates RunLoop<CipherD, KEM_LEVEL> and delegates to run().
 * KEM_LEVEL is defined by CMake as 768 or 1024 at compile time, producing
 * two separate binaries: system_d_kem768 and system_d_kem1024.
 *
 * Usage: ./system_d_kem768 <duration_secs> <rate_mbps> <packet_bytes>
 * Example: ./system_d_kem768 70 1.5 1400
 *
 * IMPORTANT - no dropped packets:
 * System D has no authentication tag.  Any packet dropped by the ring buffer
 * (visible as packets_produced > packets_consumed in the run summary) will
 * desynchronise the producer and consumer Ascon-XOF states, making ALL
 * subsequent decryptions incorrect.  The run is invalid if this occurs.
 * Use rate_mbps = 0 (max speed) only if confident the ring buffer can keep
 * up; otherwise set a target rate below the measured cipher throughput.
 */

#include "cipher.hpp"
#include "../../harness/run_loop.hpp"

int main(int argc, char** argv) {
#if KEM_LEVEL == 768
    return RunLoop<CipherD, KEM_768>{}.run(argc, argv);
#elif KEM_LEVEL == 1024
    return RunLoop<CipherD, KEM_1024>{}.run(argc, argv);
#else
    #error "KEM_LEVEL must be 768 or 1024 - check CMakeLists.txt"
#endif
}
