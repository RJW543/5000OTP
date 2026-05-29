#pragma once

/*
 * systems/system_a/cipher.hpp
 *
 * System A - AES-256-GCM via OpenSSL libcrypto.
 *
 * Pipeline: ML-KEM → AES-256-GCM
 * Security: AEAD (confidentiality + integrity + authenticity)
 * Library:  OpenSSL EVP high-level API
 *
 * Device behaviour
 * ----------------
 * Pi 5 (Cortex-A76, built with -march=armv8.2-a+crypto): AES instructions
 *   are hardware-accelerated via ARMv8 AES extensions.  OpenSSL detects
 *   these at runtime and selects the optimised path automatically.
 *
 * Pi Zero 2 W (Cortex-A53, built with -march=armv8-a): no AES hardware
 *   extension is available; OpenSSL falls back to its pure-software AES
 *   implementation.  This is the worst-case condition for System A and is
 *   intentional as it exposes the true algorithmic cost.
 *
 * Nonce layout
 * ------------
 * NONCE_BYTES = 12 (96-bit GCM IV, per NIST SP 800-38D recommendation).
 * The run_loop counter fills the last 8 bytes; the first 4 bytes are zero.
 * This gives each packet a unique IV for up to 2^64 packets per session,
 * well beyond any realistic run length.
 *
 * Context reuse
 * -------------
 * Two EVP_CIPHER_CTX handles are created in init() - one encrypt, one decrypt.
 * Each packet call re-initialises only the IV, keeping the key schedule in
 * the context.  This avoids a malloc/free pair per packet and the associated
 * non-deterministic allocator latency that would corrupt latency measurements.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/err.h>


class CipherA {

    EVP_CIPHER_CTX* enc_ctx_ = nullptr;
    EVP_CIPHER_CTX* dec_ctx_ = nullptr;

public:

    static constexpr size_t      NONCE_BYTES = 12;
    static constexpr size_t      TAG_BYTES   = 16;
    static constexpr const char* NAME        = "AES-256-GCM";


    // init() - stores the 32-byte key and allocates two persistent OpenSSL
    // contexts, one for encryption and one for decryption.
    //
    // Both contexts are pre-loaded with the cipher type, IV length, and key.
    // Subsequent encrypt()/decrypt() calls only need to supply the fresh IV.
    void init(const uint8_t key[32]) {
        enc_ctx_ = EVP_CIPHER_CTX_new();
        dec_ctx_ = EVP_CIPHER_CTX_new();
        if (!enc_ctx_ || !dec_ctx_)
            throw std::runtime_error("[CipherA] EVP_CIPHER_CTX_new() failed");

        // Encryption context.
        if (EVP_EncryptInit_ex(enc_ctx_, EVP_aes_256_gcm(),
                               nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(enc_ctx_, EVP_CTRL_GCM_SET_IVLEN,
                                (int)NONCE_BYTES, nullptr) != 1 ||
            EVP_EncryptInit_ex(enc_ctx_, nullptr, nullptr, key, nullptr) != 1)
        {
            throw std::runtime_error("[CipherA] Encrypt context init failed");
        }

        // Decryption context.
        if (EVP_DecryptInit_ex(dec_ctx_, EVP_aes_256_gcm(),
                               nullptr, nullptr, nullptr) != 1 ||
            EVP_CIPHER_CTX_ctrl(dec_ctx_, EVP_CTRL_GCM_SET_IVLEN,
                                (int)NONCE_BYTES, nullptr) != 1 ||
            EVP_DecryptInit_ex(dec_ctx_, nullptr, nullptr, key, nullptr) != 1)
        {
            throw std::runtime_error("[CipherA] Decrypt context init failed");
        }
    }

    ~CipherA() {
        if (enc_ctx_) EVP_CIPHER_CTX_free(enc_ctx_);
        if (dec_ctx_) EVP_CIPHER_CTX_free(dec_ctx_);
    }

    // Default constructor - pointers are zero-initialised via in-class
    // member initialisers; init() must be called before use.
    CipherA() = default;

    // Non-copyable: EVP_CIPHER_CTX must not be duplicated without OpenSSL's
    // own copy API (EVP_CIPHER_CTX_copy), and there is no need to copy here.
    CipherA(const CipherA&)            = delete;
    CipherA& operator=(const CipherA&) = delete;


    // encrypt() - AES-256-GCM encrypt.
    //
    // Output layout: [ ciphertext (pt_len bytes) ][ tag (16 bytes) ]
    // Returns pt_len + TAG_BYTES.
    //
    // The nonce is re-applied to enc_ctx_ on each call so the context is
    // valid for a fresh GCM invocation.  OpenSSL resets internal counters
    // when a new IV is set via EVP_EncryptInit_ex(..., NULL, NULL, NULL, iv).
    size_t encrypt(const uint8_t* pt,  size_t pt_len,
                   const uint8_t* nonce,
                   const uint8_t* aad, size_t aad_len,
                   uint8_t*       out)
    {
        int len = 0;

        // Re-initialise with the per-packet nonce (key is already set).
        EVP_EncryptInit_ex(enc_ctx_, nullptr, nullptr, nullptr, nonce);

        // Feed AAD if provided.
        if (aad && aad_len > 0)
            EVP_EncryptUpdate(enc_ctx_, nullptr, &len,
                              aad, (int)aad_len);

        // Encrypt plaintext.
        EVP_EncryptUpdate(enc_ctx_, out, &len, pt, (int)pt_len);
        int total = len;

        // Finalise (for GCM this writes zero additional bytes but flushes any pending state inside the context).
        EVP_EncryptFinal_ex(enc_ctx_, out + total, &len);
        total += len;

        // Append 16-byte authentication tag.
        EVP_CIPHER_CTX_ctrl(enc_ctx_, EVP_CTRL_GCM_GET_TAG,
                            (int)TAG_BYTES, out + total);

        return (size_t)(total) + TAG_BYTES;
    }


    // decrypt() - AES-256-GCM decrypt + tag verify.
    //
    // Input layout: [ ciphertext (ct_len - 16 bytes) ][ tag (16 bytes) ]
    // Returns plaintext length on success, -1 on authentication failure.
    ssize_t decrypt(const uint8_t* in,  size_t ct_len,
                    const uint8_t* nonce,
                    const uint8_t* aad, size_t aad_len,
                    uint8_t*       out)
    {
        if (ct_len < TAG_BYTES) return -1;

        const size_t   pt_len = ct_len - TAG_BYTES;
        const uint8_t* tag    = in + pt_len;

        int len = 0;

        EVP_DecryptInit_ex(dec_ctx_, nullptr, nullptr, nullptr, nonce);

        if (aad && aad_len > 0)
            EVP_DecryptUpdate(dec_ctx_, nullptr, &len,
                              aad, (int)aad_len);

        EVP_DecryptUpdate(dec_ctx_, out, &len, in, (int)pt_len);
        int total = len;

        // Supply the tag before calling Final; OpenSSL verifies it internally.
        EVP_CIPHER_CTX_ctrl(dec_ctx_, EVP_CTRL_GCM_SET_TAG,
                            (int)TAG_BYTES,
                            const_cast<uint8_t*>(tag));

        int rc = EVP_DecryptFinal_ex(dec_ctx_, out + total, &len);
        if (rc <= 0) return -1;   // authentication failure

        total += len;
        return (ssize_t)total;
    }
};
