#pragma once

/*
 * systems/system_b/cipher.hpp
 *
 * System B - SNOW-V-GCM via Ekdahl et al. C reference + in-house GCM layer.
 *
 * Pipeline: ML-KEM → SNOW-V-GCM
 * Security: AEAD (confidentiality + integrity + authenticity)
 *
 * Libraries used:
 * SNOW-V stream cipher core: libs/snowv/snow-v.h
 *   Appendix D of Ekdahl, Johansson, Maximov, Yang (IACR ToSC 2019, Issue 3).
 *   Portable C/C++ reference (no Intel intrinsics); ARM NEON flags applied at
 *   compile time by CMakeLists.txt.
 *
 * GCM authentication layer: libs/snowv/snowv_gcm.hpp
 *   Implemented in-house per the same paper, Section 4.
 *
 * Nonce layout:
 * NONCE_BYTES = 16 (SNOW-V uses a 128-bit IV).
 * run_loop fills the last 8 bytes with the 64-bit packet counter (little-endian); the first 8 bytes are zero.  This matches the keyiv_setup()
 * word layout: A[0..7] are loaded from iv[0..15] as little-endian u16 pairs.
 *
 * AEAD mode flag:
 * keyiv_setup() is always called with is_aead_mode = 1.  This sets the
 * B[0..7] registers to the domain-separation constants from the paper,producing a different keystream from the non-AEAD mode tested in the KAT
 * harness. Using is_aead_mode = 0 here would be a correctness error.
 *
 * Statelessness between packets:
 * Unlike System D, System B is stateless between packets: every encrypt/
 * decrypt call re-initialises a fresh SnowV32 with the session key and the
 * per-packet nonce.  The GCM construction derives H and EJ0 from the first
 * two keystream blocks, ensuring each packet is independently authenticated.
 *
 * Validation requirement:
 * Run kat_system_b before recording any benchmark data.  The test verifies:
 *   (a) encrypt then decrypt round-trip
 *   (b) tag failure on single-byte ciphertext modification
 *   (c) GHASH cross-check against an independent Python reference
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "snowv/snowv_gcm.hpp"


class CipherB {

    uint8_t key_[32] = {};

public:

    static constexpr size_t      NONCE_BYTES = 16;
    static constexpr size_t      TAG_BYTES   = 16;
    static constexpr const char* NAME        = "SNOW-V-GCM";


    // init() - stores the 32-byte session key for use by encrypt() and decrypt().
    //
    // No persistent context is allocated; each encrypt()/decrypt() call
    // constructs a fresh SnowV32 from key_ and the per-packet nonce.
    void init(const uint8_t key[32]) {
        memcpy(key_, key, 32);
    }


    // encrypt() - SNOW-V-GCM encrypt.
    //
    // Output layout: [ ciphertext (pt_len bytes) ][ tag (16 bytes) ]
    // Returns pt_len + TAG_BYTES.
    size_t encrypt(const uint8_t* pt,  size_t pt_len,
                   const uint8_t* nonce,
                   const uint8_t* aad, size_t aad_len,
                   uint8_t*       out)
    {
        return snowv_gcm_encrypt(key_, nonce, aad, aad_len, pt, pt_len, out);
    }


    // decrypt() - SNOW-V-GCM decrypt + tag verify.
    //
    // Returns plaintext length on success, -1 on authentication failure.
    ssize_t decrypt(const uint8_t* in,  size_t ct_l