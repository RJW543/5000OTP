/*
 * tests/kat_system_d.cpp - Known-Answer Tests for System D (Ascon-PRNG XOR).
 *
 * Tests:
 *   1. Round-trip small: encrypt 32 bytes, decrypt, compare.
 *   2. Round-trip large: encrypt 10 MB, decrypt, verify every byte matches.
 *      This is the primary correctness proof for System D: because there is
 *      no authentication tag, a silent byte-for-byte comparison is the only
 *      way to detect keystream desynchronisation.
 *   3. State continuity: a single encrypt over N bytes produces the same
 *      ciphertext as N individual 1-byte encrypt calls.  This verifies that
 *      the keystream state advances correctly across buffer boundaries.
 *   4. Determinism: two instances initialised with the same key produce
 *      identical keystreams.  This simulates the encryptor/decryptor pair
 *      in the benchmark.
 *   5. Key sensitivity: different keys produce different keystreams.
 *   6. Ascon permutation sanity: verify the all-zeros state produces a
 *      known non-zero output after one round (regression guard for the
 *      permutation implementation).
 *
 * There is no authentication test (T2/T3 from other KATs) because System D
 * provides no authentication - this is deliberate and must be stated in the
 * dissertation.
 *
 * 10 MB round-trip (Test 2) is the minimum correctness check required before
 * E2 begins, per the implementation guide §6.
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "../systems/system_d/cipher.hpp"
#include "../libs/ascon/ascon_xof.hpp"


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static int check(const char* name, bool pass) {
    printf("[KAT-D] %-56s %s\n", name, pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}


// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

static const uint8_t KEY_A[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

static const uint8_t KEY_B[32] = {   // differs from KEY_A
    0xff,0xfe,0xfd,0xfc,0xfb,0xfa,0xf9,0xf8,
    0xf7,0xf6,0xf5,0xf4,0xf3,0xf2,0xf1,0xf0,
    0xef,0xee,0xed,0xec,0xeb,0xea,0xe9,0xe8,
    0xe7,0xe6,0xe5,0xe4,0xe3,0xe2,0xe1,0xe0
};

static const uint8_t PLAINTEXT_SMALL[32] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
    0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51
};


// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    printf("KAT System D - Ascon-PRNG-XOR\n");
    printf("============================================================\n");

    int failures = 0;

    // -----------------------------------------------------------------------
    // Test 1: small round-trip (32 bytes)
    // -----------------------------------------------------------------------
    {
        CipherD enc, dec;
        enc.init(KEY_A);
        dec.init(KEY_A);

        uint8_t ct[32], pt2[32];
        size_t ct_len = enc.encrypt(PLAINTEXT_SMALL, 32, nullptr, nullptr, 0, ct);
        failures += check("T1 encrypt returns 32 (no tag)",
                          ct_len == 32);

        ssize_t dec_len = dec.decrypt(ct, 32, nullptr, nullptr, 0, pt2);
        failures += check("T1 decrypt returns 32",
                          dec_len == 32);
        failures += check("T1 decrypted plaintext matches original",
                          memcmp(pt2, PLAINTEXT_SMALL, 32) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 2: 10 MB round-trip
    //
    // This is the primary correctness validation for System D.  Allocates
    // two 10 MB buffers; the first holds encrypted data, the second the
    // decrypted result.  Any keystream desynchronisation at buffer boundaries
    // will manifest as a mismatched byte.
    // -----------------------------------------------------------------------
    {
        static constexpr size_t TEN_MB = 10 * 1024 * 1024;

        printf("[KAT-D] T2 10 MB round-trip (allocating 20 MB)...\n");

        uint8_t* pt_buf  = new uint8_t[TEN_MB];
        uint8_t* ct_buf  = new uint8_t[TEN_MB];
        uint8_t* pt2_buf = new uint8_t[TEN_MB];

        // Fill plaintext with a deterministic pattern.
        for (size_t i = 0; i < TEN_MB; i++)
            pt_buf[i] = (uint8_t)(i & 0xFF);

        CipherD enc, dec;
        enc.init(KEY_A);
        dec.init(KEY_A);

        enc.encrypt(pt_buf, TEN_MB, nullptr, nullptr, 0, ct_buf);
        dec.decrypt(ct_buf, TEN_MB, nullptr, nullptr, 0, pt2_buf);

        bool ok = (memcmp(pt_buf, pt2_buf, TEN_MB) == 0);
        failures += check("T2 10 MB round-trip - all bytes match", ok);

        if (!ok) {
            // Find and report the first mismatch for debugging.
            for (size_t i = 0; i < TEN_MB; i++) {
                if (pt_buf[i] != pt2_buf[i]) {
                    printf("  First mismatch at byte %zu: "
                           "expected 0x%02x got 0x%02x\n",
                           i, pt_buf[i], pt2_buf[i]);
                    break;
                }
            }
        }

        delete[] pt_buf;
        delete[] ct_buf;
        delete[] pt2_buf;
    }

    // -----------------------------------------------------------------------
    // Test 3: state continuity across buffer boundaries
    //
    // Encrypt 48 bytes in one call.  Then encrypt the same 48 bytes as
    // 48 individual 1-byte calls.  Both must produce identical ciphertext.
    // -----------------------------------------------------------------------
    {
        uint8_t pt48[48];
        for (int i = 0; i < 48; i++) pt48[i] = (uint8_t)i;

        // Single-call path.
        CipherD enc_bulk;
        enc_bulk.init(KEY_A);
        uint8_t ct_bulk[48];
        enc_bulk.encrypt(pt48, 48, nullptr, nullptr, 0, ct_bulk);

        // Byte-at-a-time path.
        CipherD enc_byte;
        enc_byte.init(KEY_A);
        uint8_t ct_byte[48];
        for (int i = 0; i < 48; i++) {
            uint8_t tmp;
            enc_byte.encrypt(&pt48[i], 1, nullptr, nullptr, 0, &tmp);
            ct_byte[i] = tmp;
        }

        failures += check("T3 bulk encrypt == byte-at-a-time encrypt",
                          memcmp(ct_bulk, ct_byte, 48) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 4: determinism - two instances with the same key produce the
    //         same keystream (simulates enc/dec pair in the harness)
    // -----------------------------------------------------------------------
    {
        CipherD inst1, inst2;
        inst1.init(KEY_A);
        inst2.init(KEY_A);

        uint8_t zeros[64] = {};
        uint8_t ks1[64], ks2[64];
        inst1.encrypt(zeros, 64, nullptr, nullptr, 0, ks1);
        inst2.encrypt(zeros, 64, nullptr, nullptr, 0, ks2);

        failures += check("T4 two instances with same key → identical keystream",
                          memcmp(ks1, ks2, 64) == 0);
    }

    // -----------------------------------------------------------------------
    // Test 5: key sensitivity - different keys produce different keystreams
    // -----------------------------------------------------------------------
    {
        CipherD enc_a, enc_b;
        enc_a.init(KEY_A);
        enc_b.init(KEY_B);

        uint8_t zeros[64] = {};
        uint8_t ks_a[64], ks_b[64];
        enc_a.encrypt(zeros, 64, nullptr, nullptr, 0, ks_a);
        enc_b.encrypt(zeros, 64, nullptr, nullptr, 0, ks_b);

        failures += check("T5 different keys → different keystreams",
                          memcmp(ks_a, ks_b, 64) != 0);
    }

    // -----------------------------------------------------------------------
    // Test 6: Ascon permutation sanity - squeezing from an all-zeros seed
    //         must produce non-zero output (regression guard for the
    //         permutation implementation; a broken round function often
    //         produces all-zeros or all-ones).
    // -----------------------------------------------------------------------
    {
        uint8_t zeros32[32] = {};
        AsconXOF xof;
        xof.init(zeros32, 32);

        uint8_t out[32];
        xof.squeeze(out, 32);

        uint8_t zero32[32] = {};
        uint8_t all_ff[32];
        memset(all_ff, 0xff, 32);

        failures += check("T6 Ascon XOF output is non-zero for zero seed",
                          memcmp(out, zero32, 32) != 0);
        failures += check("T6 Ascon XOF output is not all-0xff",
                          memcmp(out, all_ff, 32) != 0);

        printf("  XOF(zeros_seed)[0..31]: ");
        for (int i = 0; i < 32; i++) printf("%02x", out[i]);
        printf("\n");
    }

    printf("============================================================\n");
    printf("Overall: %s (%d failure(s))\n\n",
           failures == 0 ? "ALL PASS" : "FAILURES DETECTED", failures);

    return failures == 0 ? 0 : 1;
}
