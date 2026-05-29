#pragma once

/*
 * kem.hpp
 *
 * Wraps the liboqs ML-KEM implementation (FIPS 203) and exposes the three
 * mandatory operations of a Key Encapsulation Mechanism:
 *
 *   keygen  - generates a public/secret key pair for the receiver
 *   encaps  - sender uses the public key to produce (ciphertext, shared secret)
 *   decaps  - receiver uses the secret key + ciphertext to recover shared secret
 *
 * After a successful exchange, both sides hold identical 32-byte shared
 * secrets.  This secret is passed directly to the symmetric cipher's init()
 * as the session key.  No KDF is applied here; the shared secret output of
 * ML-KEM is already a uniformly random byte string suitable for direct use
 * as a 256-bit key (FIPS 203 §7).
 *
 * Security levels
 * ---------------
 *   KEM_768  - ML-KEM-768  (FIPS 203 Security Category 3: at least as hard to
 *               break as AES-192; targets ~168-bit classical / post-quantum
 *               security against the best known lattice attacks)
 *   KEM_1024 - ML-KEM-1024 (FIPS 203 Security Category 5: at least as hard to
 *               break as AES-256; targets ~224-bit classical / post-quantum
 *               security)
 *
 * Compile-time selection
 * ----------------------
 * The KemLevel template parameter is resolved at compile time.  CMake
 * produces a separate binary for each level; there is no runtime switch.
 *
 * Benchmark model
 * ---------------
 * In this harness both the sender and receiver are the same process.  The
 * exchange therefore does not simulate a network round-trip; it measures
 * the computational cost of the three ML-KEM operations on the target
 * hardware (Pi 5 or Pi Zero 2 W).
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <stdexcept>
#include <vector>

#include <oqs/oqs.h>


// Both KEM levels produce a 32-byte shared secret.
static constexpr size_t KEM_SHARED_SECRET_BYTES = 32;


// ---------------------------------------------------------------------------
// KemLevel - selects the ML-KEM parameter set at compile time.
// ---------------------------------------------------------------------------

enum KemLevel { KEM_768 = 768, KEM_1024 = 1024 };


// ---------------------------------------------------------------------------
// MlKem<Level> - manages one complete ML-KEM key exchange.
//
// Not copyable; pass by reference.
// ---------------------------------------------------------------------------

template<KemLevel Level>
class MlKem {
    OQS_KEM* kem_ = nullptr;

    std::vector<uint8_t> public_key_;
    std::vector<uint8_t> secret_key_;
    std::vector<uint8_t> ciphertext_;
    std::vector<uint8_t> shared_secret_enc_;
    std::vector<uint8_t> shared_secret_dec_;

    // Returns the liboqs algorithm identifier string for the chosen level.
    // The static_assert ensures a compile-time error if a new KemLevel
    // value is added to the enum without updating this function - the two
    // independent if constexpr branches would otherwise leave the compiler
    // with an implicit non-void return path, which is undefined behaviour.
    static const char* algorithm_name() {
        static_assert(Level == KEM_768 || Level == KEM_1024,
                      "Unsupported KemLevel - add a branch to algorithm_name().");
        if constexpr (Level == KEM_768)  return OQS_KEM_alg_ml_kem_768;
        else                             return OQS_KEM_alg_ml_kem_1024;
    }

public:

    // Constructor - initialises the liboqs KEM context and pre-allocates
    // all key material buffers using sizes reported by the OQS_KEM struct
    // itself, so the code remains correct if liboqs is updated to a new
    // ML-KEM revision.  Throws std::runtime_error if liboqs cannot find
    // the algorithm (most likely cause: liboqs built without ML-KEM support).
    MlKem() {
        kem_ = OQS_KEM_new(algorithm_name());
        if (!kem_) {
            fprintf(stderr,
                "[kem] ERROR: OQS_KEM_new() returned null for '%s'.\n"
                "      Likely cause: liboqs was built without ML-KEM support.\n"
                "      Rebuild liboqs with: cmake -DOQS_ENABLE_KEM_ml_kem=ON\n",
                algorithm_name());
            throw std::runtime_error("OQS_KEM_new failed");
        }

        public_key_.resize(kem_->length_public_key);
        secret_key_.resize(kem_->length_secret_key);
        ciphertext_.resize(kem_->length_ciphertext);
        shared_secret_enc_.resize(kem_->length_shared_secret);
        shared_secret_dec_.resize(kem_->length_shared_secret);

        if (kem_->length_shared_secret != KEM_SHARED_SECRET_BYTES) {
            fprintf(stderr,
                "[kem] WARNING: expected a %zu-byte shared secret but liboqs "
                "reports %zu bytes for %s.\n"
                "      The cipher init() may receive the wrong key length.\n",
                KEM_SHARED_SECRET_BYTES,
                kem_->length_shared_secret,
                algorithm_name());
        }
    }

    // Destructor - calls OQS_KEM_free(), which zeroes all key material inside
    // the OQS_KEM struct before releasing the allocation (liboqs guarantee).
    ~MlKem() {
        if (kem_) OQS_KEM_free(kem_);
    }

    // Copying is disabled because the liboqs OQS_KEM struct must be freed
    // exactly once.  A copy would produce two objects pointing at the same
    // struct; both destructors would attempt to free it, causing a double-free.
    MlKem(const MlKem&)            = delete;
    MlKem& operator=(const MlKem&) = delete;


    // keygen() - generates a fresh public/private key pair.
    // Call once at the start of each benchmark run.
    void keygen() {
        OQS_STATUS rc = OQS_KEM_keypair(kem_,
                                        public_key_.data(),
                                        secret_key_.data());
        if (rc != OQS_SUCCESS)
            throw std::runtime_error("[kem] keygen() failed - check liboqs build");
    }

    // encaps() - uses the public key to produce a shared secret and a
    // ciphertext.  In a real deployment the ciphertext would be sent to
    // the receiver; here both sides are the same process.
    void encaps() {
        OQS_STATUS rc = OQS_KEM_encaps(kem_,
                                       ciphertext_.data(),
                                       shared_secret_enc_.data(),
                                       public_key_.data());
        if (rc != OQS_SUCCESS)
            throw std::runtime_error("[kem] encaps() failed - check liboqs build");
    }

    // decaps() - uses the private key and the ciphertext to recover the
    // shared secret.  After this call, shared_secret_dec_ should match
    // shared_secret_enc_ exactly.  Verify with verify() before use.
    void decaps() {
        OQS_STATUS rc = OQS_KEM_decaps(kem_,
                                       shared_secret_dec_.data(),
                                       ciphertext_.data(),
                                       secret_key_.data());
        if (rc != OQS_SUCCESS)
            throw std::runtime_error("[kem] decaps() failed - check liboqs build");
    }

    // shared_secret_sender() - returns the 32-byte secret from the sender side.
    // Pass to the producer thread's cipher init().
    const uint8_t* shared_secret_sender() const {
        return shared_secret_enc_.data();
    }

    // shared_secret_receiver() - returns the 32-byte secret from the receiver side.
    // Pass to the consumer thread's cipher init().
    const uint8_t* shared_secret_receiver() const {
        return shared_secret_dec_.data();
    }

    // verify() - returns true if both shared secrets are byte-for-byte identical.
    // Must return true before any benchmark results are collected; a mismatch
    // indicates a liboqs build fault or memory corruption and would cause every
    // subsequent authentication tag to fail.
    // Note: memcmp is not constant-time, but this is a correctness check, not
    // a timing-sensitive authentication comparison - a mismatch is fatal regardless.
    bool verify() const {
        return memcmp(shared_secret_enc_.data(),
                      shared_secret_dec_.data(),
                      KEM_SHARED_SECRET_BYTES) == 0;
    }

    // print_info() - prints the algorithm name and sizes of the public key,
    // secret key, ciphertext, and shared secret to stdout.
    void print_info() const {
        fprintf(stdout,
            "[kem] algorithm=%s  pk=%zu B  sk=%zu B  ct=%zu B  ss=%zu B\n",
            algorithm_name(),
            kem_->length_public_key,
            kem_->length_secret_key,
            kem_->length_ciphertext,
            kem_->length_shared_secret);
    }

    // level() - returns the integer level (768 or 1024).
    int level() const { return static_cast<int>(Level); }
};
