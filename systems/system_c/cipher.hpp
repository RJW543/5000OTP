#pragma once

/*
 * systems/system_c/cipher.hpp
 *
 * System C - ChaCha20-Poly1305 via libsodium (IETF variant, RFC 8439).
 *
 * Pipeline: ML-KEM → ChaCha20-Poly1305
 * Security: AEAD (confidentiality + integrity + authenticity)
 * Library:  libsodium crypto_aead_chacha20poly1305_ietf_*
 *
 * Design rationale:
 * ChaCha20-Poly1305 is a pure ARX (add-rotate-XOR) construction with no
 * data-dependent table lookups or special hardware instructions.  It is
 * therefore the cleanest software-only AEAD baseline: performance on the
 * Pi 5 and Pi Zero 2 W should be similar (unlike System A, where AES
 * hardware acceleration dramatically favours the Pi 5).
 *
 * This system is standardised in TLS 1.3 (RFC 8446) and WireGuard.
 *
 * IETF vs. original variant:
 * libsodium exposes two ChaCha20-Poly1305 variants:
 *   crypto_aead_chacha20poly1305_ietf_*  - 96-bit nonce (RFC 8439) ← used here
 *   crypto_aead_chacha20poly1305_*       - 64-bit nonce (original)
 *
 * The IETF variant is used because it matches the nonce length used in
 * deployed protocols and keeps NONCE_BYTES consistent with System A (12).
 *
 * Nonce layout:
 * NONCE_BYTES = 12.  run_loop fills the last 8 bytes with the 64-bit packet
 * counter; the first 4 bytes are zero.
 *
 * Statelessness between packets:
 * init() stores the 32-byte key.  Each encrypt/decrypt call passes key and
 * nonce directly to libsodium, no persistent context is needed because
 * libsodium initialises ChaCha20 internally from the key+nonce on each call.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include <sodium.h>


class CipherC {

    uint8_t key_[crypto_aead_chacha20poly1305_ietf_KEYBYTES] = {};

    static_assert(crypto_aead_chacha20poly1305_ietf_KEYBYTES == 32,
                  "libsodium ChaCha20-Poly1305 key must be 32 bytes");
    static_assert(crypto_aead_chacha20poly1305_ietf_ABYTES == 16,
                  "libsodium ChaCha20-Poly1305 tag must be 16 bytes");
    static_assert(crypto_aead_chacha20poly1305_ietf_NPUBBYTES == 12,
                  "libsodium IETF nonce must be 12 bytes");

public:

    static constexpr size_t      NONCE_BYTES = 12;
    static constexpr size_t      TAG_BYTES   = 16;
    static constexpr const char* NAME        = "ChaCha20-Poly1305";


    // init() - calls sodium_init() and stores the 32-byte session key.
    //
    // sodium_init() is idempotent; calling it multiple times is safe.
    // Throws std::runtime_error if the libsodium library fails to initialise.
    void init(const uint8_t key[32]) {
        if (sodium_init() < 0)
            throw std::runtime_error("[CipherC] sodium_init() failed");
        memcpy(key_, key, 32);
    }


    // encrypt() - ChaCha20-Poly1305 IETF encrypt.
    //
    // libsodium appends the Poly1305 MAC immediately after the ciphertext,
    // producing pt_len + 16 bytes total.  The clen_p output parameter
    // captures the total written length (used as a sanity check only; the
    // return value of this function is the authoritative length).
    //
    // Returns pt_len + TAG_BYTES.
    size_t encrypt(const uint8_t* pt,  size_t pt_len,
                   const uint8_t* nonce,
                   const uint8_t* aad, size_t aad_len,
                   uint8_t*       out)
    {
        unsigned long long clen = 0;
        crypto_aead_chacha20poly1305_ietf_encrypt(
            out, &clen,
            pt,  (unsigned long long)pt_len,
            aad, (unsigned long long)aad_len,
            nullptr,   // nsec - unused by this construction
            nonce,
            key_);
        return (size_t)clen;   // = pt_len + 16
    }


    // decrypt() - ChaCha20-Poly1305 IETF decrypt + MAC verify.
    //
    // Returns plaintext length on success, -1 on authentication failure.
    ssize_t decrypt(const uint8_t* in,  size_t ct_len,
                    const uint8_t* nonce,
                    const uint8_t* aad, size_t aad_len,
                    uint8_t*       out)
    {
        if (ct_len < TAG_BYTES) return -1;

        unsigned long long mlen = 0;
        int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
            out, &mlen,
            nullptr,
            in,  (unsigned long long)ct_len,
            aad, (unsigned long long)aad_len,
            nonce,
            key_);
        return (rc == 0) ? (ssize_t)mlen : -1;
    }
};