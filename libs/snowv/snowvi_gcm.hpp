#pragma once
/*
 * snowvi_gcm.hpp
 *
 * SNOW-Vi-GCM authenticated encryption.
 *
 * The SNOW-V-GCM construction (Ekdahl, Johansson, Maximov, Yang, ToSC 2019,
 * Section 4) with the SNOW-Vi keystream generator (ePrint 2021/236) in place of
 * SNOW-V. The AEAD wrapper matches the SNOW-V-GCM construction; only the
 * keystream source changes.
 *
 * GHASH is provided by snowvi_ghash.hpp (PMULL on the Pi 5, a 4-bit Shoup table
 * on the Zero, PCLMUL on the x86 dev host), each validated to reproduce the
 * bitwise reference byte for byte. ct_equal is defined locally below.
 *
 * Validated (snowvi_gcm_test.cpp) by round-trip over all block boundaries,
 * tamper rejection on ciphertext/AAD/tag, and an independent spec re-derivation
 * of (ciphertext, tag), in both the table and PCLMUL builds.
 */
#include <cstdint>
#include <cstring>
#include <cstdlib>

#include "snow-vi.h"
#include "snowvi_ghash.hpp" // accelerated GHASH: PMULL (Pi 5) / table (Zero) / PCLMUL (dev)

// Constant-time 16-byte compare (local to the SNOW-Vi GCM layer).
static inline bool snowvi_ct_equal(const uint8_t a[16], const uint8_t b[16]) {
    uint8_t d = 0; for (int i = 0; i < 16; i++) d |= a[i] ^ b[i]; return d == 0;
}

static inline size_t snowvi_gcm_encrypt(const uint8_t key[32],
                                        const uint8_t iv[16],
                                        const uint8_t* aad, size_t aad_len,
                                        const uint8_t* pt,  size_t pt_len,
                                        uint8_t* ct_out)
{

    SnowVi s;
    s.keyiv_setup(key, iv, /*aead=*/1);

    uint8_t H[16], EJ0[16];
    { SnowVi::V k = s.keystream(); memcpy(H,   k.b, 16); }   // block 0 = H
    { SnowVi::V k = s.keystream(); memcpy(EJ0, k.b, 16); }   // block 1 = EJ0

    size_t done = 0, rem = pt_len;
    while (rem > 0) {
        SnowVi::V k = s.keystream();
        size_t n = rem < 16 ? rem : 16;
        for (size_t i = 0; i < n; i++) ct_out[done + i] = pt[done + i] ^ k.b[i];
        done += n; rem -= n;
    }

    uint8_t tag[16];
    snowvi_ghash::ghash(tag, H, aad, aad_len, ct_out, pt_len);
    for (int i = 0; i < 16; i++) tag[i] ^= EJ0[i];
    memcpy(ct_out + pt_len, tag, 16);
    return pt_len + 16;
}

static inline ssize_t snowvi_gcm_decrypt(const uint8_t key[32],
                                         const uint8_t iv[16],
                                         const uint8_t* aad, size_t aad_len,
                                         const uint8_t* ct_with_tag, size_t ct_len,
                                         uint8_t* pt_out)
{

    if (ct_len < 16) return -1;
    const size_t   pt_len = ct_len - 16;
    const uint8_t* ct     = ct_with_tag;
    const uint8_t* rtag   = ct_with_tag + pt_len;

    SnowVi s;
    s.keyiv_setup(key, iv, /*aead=*/1);

    uint8_t H[16], EJ0[16];
    { SnowVi::V k = s.keystream(); memcpy(H,   k.b, 16); }
    { SnowVi::V k = s.keystream(); memcpy(EJ0, k.b, 16); }

    uint8_t etag[16];
    snowvi_ghash::ghash(etag, H, aad, aad_len, ct, pt_len);
    for (int i = 0; i < 16; i++) etag[i] ^= EJ0[i];
    if (!snowvi_ct_equal(etag, rtag)) return -1;          // constant-time, fail before decrypt

    size_t done = 0, rem = pt_len;
    while (rem > 0) {
        SnowVi::V k = s.keystream();
        size_t n = rem < 16 ? rem : 16;
        for (size_t i = 0; i < n; i++) pt_out[done + i] = ct[done + i] ^ k.b[i];
        done += n; rem -= n;
    }
    return (ssize_t)pt_len;
}
