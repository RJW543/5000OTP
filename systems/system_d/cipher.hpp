#pragma once

/*
 * systems/system_d/cipher.hpp
 *
 * System D - Ascon-Xof (v1.2) CSPRNG keystream XOR (Vernam-inspired).
 *
 * Pipeline: ML-KEM → Ascon-XOF CSPRNG → XOR
 * Security: Confidentiality ONLY - deliberately unauthenticated.
 *
 * Library: libs/ascon/ascon_xof.hpp (self-contained Ascon-Xof (v1.2))
 *
 * Purpose:
 * System D establishes a throughput upper bound by removing the overhead
 * of computing and verifying authentication tags. 
 *
 * Mechanism:
 * The 32-byte ML-KEM shared secret is used as the seed for Ascon-XOF.
 * Both the producer (encryptor) and consumer (decryptor) are initialised
 * with the same seed; they therefore produce identical keystreams.
 *
 * Encryption: ciphertext[i] = plaintext[i] XOR keystream[i]
 * Decryption: plaintext[i]  = ciphertext[i] XOR keystream[i]
 *
 * XOR is its own inverse, so encrypt() and decrypt() execute identical code.
 *
 * State continuity:
 * The Ascon-XOF state is maintained across packets.  init() is called
 * exactly once; encrypt()/decrypt() squeeze bytes from the continuous
 * keystream without re-initialising.  If the encryptor and decryptor states
 * ever diverge (e.g. due to a dropped packet), all subsequent decryptions
 * will produce garbage, the run_loop ring-buffer comments document this
 * risk.  Because there is no authentication tag, corruption is silent until
 * an out-of-band check detects it (see kat_system_d.cpp).
 *
 * NONCE_BYTES = 0
 * No per-packet nonce is used.  The run_loop passes nullptr as the nonce
 * argument when NONCE_BYTES == 0; both encrypt() and decrypt() ignore it.
 * The run_loop comment explains why this desynchronises the keystream on
 * any dropped packet (the producer's state advances past a dropped block
 * while the consumer's does not).
 *
 * Ascon state size: 5 × 64 bits = 40 bytes (dissertation constitution §2).
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "ascon/ascon_xof.hpp"


class CipherD {

    AsconXOF xof_;

public:

    static constexpr size_t      NONCE_BYTES = 0;    // no per-packet nonce
    static constexpr size_t      TAG_BYTES   = 0;    // no authentication tag
    static constexpr const char* NAME        = "Ascon-PRNG-XOR";


    // init() - seed the Ascon-XOF state with the 32-byte ML-KEM shared secret.
    //
    // Call exactly once per session.  Both the encryptor and decryptor
    // instances must be initialised with the same key to produce matching
    // keystreams.  The run_loop satisfies this: cipher_enc is given
    // kem.shared_secret_sender() and cipher_dec is given
    // kem.shared_secret_receiver(), and kem.verify() confirms they are equal.
    void init(const uint8_t key[32]) {
        xof_.init(key, 32);
    }


    // encrypt() - XOR plaintext with Ascon keystream.
    //
    // The nonce parameter is always nullptr for System D (NONCE_BYTES == 0);
    // the aad parameters are unused (no authentication layer).
    //
    // Returns pt_len (no tag appended).
    size_t encrypt(const uint8_t* pt,  size_t pt_len,
                   const uint8_t* /*nonce*/,
                   const uint8_t* /*aad*/, size_t /*aad_len*/,
                   uint8_t*       out)
    {
        // Squeeze exactly pt_len bytes of keystream into out[], then XOR in
        // place.  Squeezing directly into out then XOR-ing avoids an extra
        // copy compared with squeezing into a temporary buffer.
        xof_.squeeze(out, pt_len);
        for (size_t i = 0; i < pt_len; i++) out[i] ^= pt[i];
        return pt_len;
    }


    // decrypt() - XOR ciphertext with Ascon keystream (identical to encrypt).
    //
    // Never returns -1: there is no authentication tag to verify.
    // Keystream desynchronisation (due to dropped packets) will produce
    // incorrect output silently; the run summary will show
    // packets_produced != packets_consumed to flag such events.
    ssize_t decrypt(const uint8_t* in,  size_t ct_len,
                    const uint8_t* /*nonce*/,
                    const uint8_t* /*aad*/, size_t /*aad_len*/,
                    uint8_t*       out)
    {
        xof_.squeeze(out, ct_len);
        for (size_t i = 0; i < ct_len; i++) out[i] ^= in[i];
        return (ssize_t)ct_len;
    }
};
