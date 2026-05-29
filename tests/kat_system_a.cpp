/*
 * tests/kat_system_a.cpp - Known-Answer Tests for System A (AES-256-GCM).
 *
 * Tests:
 *   1. Round-trip: encrypt then decrypt recovers original plaintext.
 *   2. Auth failure: flipping one ciphertext byte makes decrypt() return -1.
 *   3. Auth failure: flipping one tag byte makes decrypt() return -1.
 *   4. Nonce sensitivity: same plaintext with different nonces produces
 *      different ciphertext (probabilistic distinguishability check).
 *   5. Key sensitivity: different keys produce different ciphertext.
 *
 * These tests do NOT require liboqs.  The cipher is exercised directly with
 * a fixed test key, bypassing the ML-KEM key exchange.  That is intentional:
 * kem.hpp has its own correctness guarantee from liboqs; these tests isolate
 * the cipher layer.
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "../systems/system_a/cipher.hpp"


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void print_hex(const char* label, const uint8_t* d, size_t n) {
    printf("  %s: ", label);
    for (size_t i = 0; i < n && i < 32; i++) printf("%02x", d[i]);
    if (n > 32) printf("...");
    printf("\n");
}

static int check(const char* name, bool pass) {
    printf("[KAT-A] %-50s %s\n", name, pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}


// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

// 32-byte test key (arbitrary; not from a real session).
static const uint8_t TEST_KEY[32] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
};

// 12-byte nonce A and nonce B (different).
static const uint8_t NONCE_A[12] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b
};
static const uint8_t NONCE_B[12] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0c   // last byte differs
};

// Second key (differs from TEST_KEY).
static const uint8_t TEST_KEY_2[32] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
    0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
    0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
};

// 64-byte plaintext (two AES blocks of known content).
static const uint8_t PLAINTEXT[64] = {
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
    0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
    0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
    0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
};


// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    printf("KAT System A - AES-256-GCM\n");
    printf("============================================================\n");

    int failures = 0;
    CipherA cipher;
    cipher.init(TEST_KEY);

    // Buffers.
    static const size_t PT_LEN = sizeof(PLAINTEXT);
    uint8_t ct[PT_LEN + 16];   // ciphertext + tag
    uint8_t pt2[PT_LEN];       // recovered plaintext

    // -----------------------------------------------------------------------
    // Test 1: round-trip
    // -----------------------------------------------------------------------
    {
        size_t ct_len = cipher.encrypt(PLAINTEXT, PT_LEN,
                                       NONCE_A, nullptr, 0, ct);
        failures += check("T1 encrypt returns PT_LEN + 16",
                          ct_len == PT_LEN + 16);

        ssize_t dec_len = cipher.decrypt(ct, ct_len, NONCE_A, nullptr, 0, pt2);
        failures += check("T1 decrypt returns PT_LEN",
                          dec_len == (ssize_t)PT_LEN);
        failures += check("T1 decrypted plaintext matches original",
                          memcmp(pt2, PLAINTEXT, PT_LEN) == 0);

        print_hex("ciphertext[0..31]", ct, PT_LEN);
        print_hex("tag",               ct + PT_LEN, 16);
    }

    // -----------------------------------------------------------------------
    // Test 2: flip one ciphertext byte → authentication failure
    // -----------------------------------------------------------------------
    {
        uint8_t tampered[PT_LEN + 16];
        memcpy(tampered, ct, PT_LEN + 16);
        tampered[PT_LEN / 2] ^= 0x01;    // flip bit in middle of ciphertext

        ssize_t rc = cipher.decrypt(tampered, PT_LEN + 16,
                                    NONCE_A, nullptr, 0, pt2);
        failures += check("T2 tampered ciphertext → decrypt returns -1",
                          rc == -1);
    }

    // -----------------------------------------------------------------------
    // Test 3: flip one tag byte → authentication failure
    // -----------------------------------------------------------------------
    {
        uint8_t tampered[PT_LEN + 16];
        memcpy(tampered, ct, PT_LEN + 16);
        tampered[PT_LEN + 7] ^= 0x80;    // flip bit in tag

        ssize_t rc = cipher.decrypt(tampered, PT_LEN + 16,
                                    NONCE_A, nullptr, 0, pt2);
        failures += check("T3 tampered tag → decrypt returns -1",
                          rc == -1);
    }

    // -----------------------------------------------------------------------
    // Test 4: different nonces produce different ciphertext
    // -----------------------------------------------------------------------
    {
        uint8_t ct2[PT_LEN + 16];
        cipher.encrypt(PLAINTEXT, PT_LEN, NONCE_B, nullptr, 0, ct2);

        // The ciphertexts must differ (they almost certainly will for any
        // correct cipher; identical outputs would indicate a nonce-reuse bug).
        failures += check("T4 different nonces → different ciphertext",
                          memcmp(ct, ct2, PT_LEN) != 0);
    }

    // -----------------------------------------------------------------------
    // Test 5: different keys produce different ciphertext
    // -----------------------------------------------------------------------
    {
        CipherA cipher2;
        cipher2.init(TEST_KEY_2);
        uint8_t ct3[PT_LEN + 16];
        cipher2.encrypt(PLAINTEXT, PT_LEN, NONCE_A, nullptr, 0, ct3);

        failures += check("T5 different keys → different ciphertext",
                          memcmp(ct, ct3, PT_LEN) != 0);
    }

    printf("============================================================\n");
    printf("Overall: %s (%d failure(s))\n\n",
           failures == 0 ? "ALL PASS" : "FAILURES DETECTED", failures);

    return failures == 0 ? 0 : 1;
}
