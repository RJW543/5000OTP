#pragma once

/*
 * snowv_gcm.hpp
 *
 * SNOW-V-GCM authenticated encryption.
 *
 * Specification: Ekdahl, Johansson, Maximov, Yang - "A new SNOW stream cipher
 * called SNOW-V", IACR Transactions on Symmetric Cryptology, 2019, Issue 3,
 * Section 4 (SNOW-V-GCM construction).
 *
 * Construction summary
 * --------------------
 * Given key K (32 bytes) and nonce IV (16 bytes), initialised in AEAD mode:
 *
 *   1.  snowv.keyiv_setup(K, IV, 1)
 *   2.  H   = snowv.keystream()   - 16-byte GHASH subkey
 *   3.  EJ0 = snowv.keystream()   - 16-byte tag mask (analogous to AES(K,J0)
 *                                   in SP 800-38D)
 *   4.  For each 16-byte plaintext block Pi:
 *           Ci = Pi XOR snowv.keystream()
 *   5.  T   = GHASH_H(A, C) XOR EJ0
 *
 * The output ciphertext is C || T (ciphertext followed by 16-byte tag).
 *
 * Decryption verifies the tag before returning plaintext.  The comparison
 * uses a constant-time byte loop to prevent timing-oracle tag recovery.
 *
 * GHASH
 * -----
 * GHASH operates in GF(2^128) with the irreducible polynomial
 *   x^128 + x^7 + x^2 + x + 1   (NIST SP 800-38D, §6.3).
 *
 * Bit ordering follows the GCM convention: the most significant bit of the
 * first byte represents the coefficient of x^0.  The reduction constant
 * 0xe1 appears in the MSB position (byte 0) because x^128 reduces to
 * x^7 + x^2 + x + 1 = 0b11100001 = 0xe1 in that byte.
 *
 * Validation requirement (from implementation guide)
 * --------------------------------------------------
 * Before recording any throughput measurements, verify that
 * snowv_gcm_encrypt() produces the correct tag for at least one test vector
 * generated independently (e.g. a Python reference script using the same
 * SNOW-V keystream values and an independent GHASH implementation).
 * The SNOW-V keystream for all-zeros key/IV in non-AEAD mode is validated
 * by the KAT in libs/snowv/main_kat.cpp.  The AEAD-mode keystream differs
 * (B[0..7] are set to the domain-separation constants in keyiv_setup) and
 * must be separately verified.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include "snow-v.h"


// ---------------------------------------------------------------------------
// GHASH implementation
// ---------------------------------------------------------------------------

namespace snowv_gcm_detail {

/*
 * gmul128 - multiply two 128-bit field elements in GF(2^128).
 *
 * Both inputs and the output are 16-byte arrays in GCM bit order
 * (MSB of byte 0 = coefficient of x^0).
 *
 * Algorithm: left-to-right binary method (Shoup's algorithm).
 *   Z = 0
 *   V = X
 *   for i = 0 to 127:
 *       if bit i of Y is 1: Z ^= V
 *       if LSB of V (bit 127) is 1: V = (V >> 1) XOR R
 *       else:                       V = (V >> 1)
 *
 * where R = 0xe1 || 0x00...00 encodes the reduction polynomial
 * x^128 + x^7 + x^2 + x + 1 in GCM bit order.
 *
 * Performance note: this is an O(128) loop, sufficient for the packet
 * sizes used in this benchmark (up to 40 KB per frame).  A table-based
 * approach would be faster but adds ~4 KB of state and complicates the
 * memory-footprint measurement.  Speed differences in GHASH are captured
 * in the encrypt/decrypt timing columns of the CSV.
 */
static void gmul128(uint8_t Z[16], const uint8_t X[16], const uint8_t Y[16]) {
    uint8_t V[16];
    memcpy(V, X, 16);
    memset(Z, 0, 16);

    for (int i = 0; i < 128; i++) {
        // Test bit i of Y.  In GCM bit order bit i is the i%8-th bit
        // (from the MSB) of byte i/8.
        if ((Y[i >> 3] >> (7 - (i & 7))) & 1) {
            for (int j = 0; j < 16; j++) Z[j] ^= V[j];
        }

        // Shift V right by 1 in the 128-bit GCM polynomial representation.
        uint8_t lsb = V[15] & 1;   // bit 127 (the "x^127" coefficient)
        for (int j = 15; j > 0; j--)
            V[j] = (uint8_t)((V[j] >> 1) | ((V[j-1] & 1) << 7));
        V[0] >>= 1;

        // If the shifted-out bit was 1, reduce modulo the polynomial:
        //   XOR with R = 0xe1 00 00 ... 00
        if (lsb) V[0] ^= 0xe1;
    }
}

/*
 * ghash - GHASH_H(A, C) per NIST SP 800-38D §6.4.
 *
 * Inputs:
 *   H        - 16-byte hash subkey (first SNOW-V keystream block)
 *   aad      - additional authenticated data (may be nullptr if aad_len==0)
 *   aad_len  - byte length of aad
 *   ct       - ciphertext (without tag)
 *   ct_len   - byte length of ct
 *
 * Output:
 *   tag_out  - 16-byte GHASH result (before XOR with EJ0)
 *
 * Encoding: pad A and C to multiples of 16 bytes, then append the two
 * 64-bit big-endian length fields (len(A)*8 and len(C)*8 in bits).
 */
static void ghash(uint8_t tag_out[16],
                  const uint8_t H[16],
                  const uint8_t* aad, size_t aad_len,
                  const uint8_t* ct,  size_t ct_len)
{
    uint8_t g[16] = {};   // accumulator
    uint8_t blk[16];

    // --- Process AAD blocks ---
    size_t off = 0;
    while (off < aad_len) {
        memset(blk, 0, 16);
        size_t n = (aad_len - off < 16) ? (aad_len - off) : 16;
        memcpy(blk, aad + off, n);
        for (int j = 0; j < 16; j++) g[j] ^= blk[j];
        gmul128(g, g, H);
        off += 16;
    }

    // --- Process ciphertext blocks ---
    off = 0;
    while (off < ct_len) {
        memset(blk, 0, 16);
        size_t n = (ct_len - off < 16) ? (ct_len - off) : 16;
        memcpy(blk, ct + off, n);
        for (int j = 0; j < 16; j++) g[j] ^= blk[j];
        gmul128(g, g, H);
        off += 16;
    }

    // --- Length block: [len(A) in bits || len(C) in bits], big-endian 64-bit each ---
    uint64_t la = (uint64_t)aad_len * 8;
    uint64_t lc = (uint64_t)ct_len  * 8;

    blk[0]  = (uint8_t)(la >> 56); blk[1]  = (uint8_t)(la >> 48);
    blk[2]  = (uint8_t)(la >> 40); blk[3]  = (uint8_t)(la >> 32);
    blk[4]  = (uint8_t)(la >> 24); blk[5]  = (uint8_t)(la >> 16);
    blk[6]  = (uint8_t)(la >>  8); blk[7]  = (uint8_t)(la      );
    blk[8]  = (uint8_t)(lc >> 56); blk[9]  = (uint8_t)(lc >> 48);
    blk[10] = (uint8_t)(lc >> 40); blk[11] = (uint8_t)(lc >> 32);
    blk[12] = (uint8_t)(lc >> 24); blk[13] = (uint8_t)(lc >> 16);
    blk[14] = (uint8_t)(lc >>  8); blk[15] = (uint8_t)(lc      );

    for (int j = 0; j < 16; j++) g[j] ^= blk[j];
    gmul128(g, g, H);

    memcpy(tag_out, g, 16);
}

/*
 * ct_equal - constant-time 16-byte comparison.
 * Returns 1 if equal, 0 if not.  The OR-accumulation prevents the compiler
 * from short-circuiting the loop on a mismatch.
 */
static int ct_equal(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= (a[i] ^ b[i]);
    return diff == 0;
}

} // namespace snowv_gcm_detail


// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/*
 * snowv_gcm_encrypt
 *
 * Encrypts `pt_len` bytes of plaintext `pt` with authenticated encryption.
 *
 * Parameters:
 *   key     [32]           - session key (ML-KEM shared secret)
 *   iv      [16]           - per-packet nonce (from run_loop counter)
 *   aad     [aad_len]      - additional authenticated data (may be nullptr)
 *   pt      [pt_len]       - plaintext
 *   ct_out  [pt_len + 16]  - output: ciphertext followed by 16-byte tag
 *
 * Returns pt_len + 16.
 */
static inline size_t snowv_gcm_encrypt(const uint8_t key[32],
                                       const uint8_t iv[16],
                                       const uint8_t* aad, size_t aad_len,
                                       const uint8_t* pt,  size_t pt_len,
                                       uint8_t* ct_out)
{
    using namespace snowv_gcm_detail;

    SnowV32 snowv;
    snowv.keyiv_setup(const_cast<u8*>(key), const_cast<u8*>(iv), 1);

    // Block 0: GHASH subkey H
    uint8_t H[16];
    snowv.keystream(H);

    // Block 1: tag mask EJ0
    uint8_t EJ0[16];
    snowv.keystream(EJ0);

    // Encrypt plaintext by XOR with successive keystream blocks.
    uint8_t* ct = ct_out;
    size_t   remaining = pt_len;
    size_t   done      = 0;

    while (remaining >= 16) {
        uint8_t ks[16];
        snowv.keystream(ks);
        for (int i = 0; i < 16; i++) ct[done + i] = pt[done + i] ^ ks[i];
        done      += 16;
        remaining -= 16;
    }
    if (remaining > 0) {
        uint8_t ks[16];
        snowv.keystream(ks);
        for (size_t i = 0; i < remaining; i++)
            ct[done + i] = pt[done + i] ^ ks[i];
    }

    // Compute GHASH and XOR with EJ0 to produce the tag.
    uint8_t tag[16];
    ghash(tag, H, aad, aad_len, ct_out, pt_len);
    for (int i = 0; i < 16; i++) tag[i] ^= EJ0[i];

    memcpy(ct_out + pt_len, tag, 16);
    return pt_len + 16;
}

/*
 * snowv_gcm_decrypt
 *
 * Decrypts and verifies a SNOW-V-GCM ciphertext.
 *
 * Parameters:
 *   key          [32]        - session key
 *   iv           [16]        - per-packet nonce
 *   aad          [aad_len]   - additional authenticated data
 *   ct_with_tag  [ct_len]    - ciphertext with appended 16-byte tag
 *   ct_len                   - total byte count including tag
 *   pt_out       [ct_len-16] - output buffer for recovered plaintext
 *
 * Returns (ct_len - 16) on success, -1 on authentication failure.
 * Tag verification is constant-time.
 */
static inline ssize_t snowv_gcm_decrypt(const uint8_t key[32],
                                        const uint8_t iv[16],
                                        const uint8_t* aad, size_t aad_len,
                                        const uint8_t* ct_with_tag, size_t ct_len,
                                        uint8_t* pt_out)
{
    using namespace snowv_gcm_detail;

    if (ct_len < 16) return -1;

    const size_t   pt_len        = ct_len - 16;
    const uint8_t* ct            = ct_with_tag;
    const uint8_t* received_tag  = ct_with_tag + pt_len;

    SnowV32 snowv;
    snowv.keyiv_setup(const_cast<u8*>(key), const_cast<u8*>(iv), 1);

    uint8_t H[16];   snowv.keystream(H);
    uint8_t EJ0[16]; snowv.keystream(EJ0);

    // Verify tag before decryption (fail fast, avoid oracle).
    uint8_t expected_tag[16];
    ghash(expected_tag, H, aad, aad_len, ct, pt_len);
    for (int i = 0; i < 16; i++) expected_tag[i] ^= EJ0[i];

    if (!ct_equal(expected_tag, received_tag)) return -1;

    // Decrypt.
    size_t remaining = pt_len;
    size_t done      = 0;

    while (remaining >= 16) {
        uint8_t ks[16];
        snowv.keystream(ks);
        for (int i = 0; i < 16; i++) pt_out[done + i] = ct[done + i] ^ ks[i];
        done      += 16;
        remaining -= 16;
    }
    if (remaining > 0) {
        uint8_t ks[16];
        snowv.keystream(ks);
        for (size_t i = 0; i < remaining; i++)
            pt_out[done + i] = ct[done + i] ^ ks[i];
    }

    return (ssize_t)pt_len;
}
