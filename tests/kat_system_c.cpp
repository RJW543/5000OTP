/*
 * tests/kat_system_c.cpp - Known-Answer Tests for System C (ChaCha20-Poly1305).
 *
 * Tests:
 *   1. Round-trip: encrypt then decrypt recovers original plaintext.
 *   2. Auth failure: flipping one ciphertext byte makes decrypt() return -1.
 *   3. Auth failure: flipping one tag byte makes decrypt() return -1.
 *   4. Nonce sensitivity: different nonces produce different ciphertext.
 *   5. RFC 8439 §2.8.2 test vector: known plaintext, key, nonce, AAD →
 *      expected ciphertext and tag.  This provides an absolute correctness
 *      check against the standard, not just internal consistency.
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>

#include "../systems/system_c/cipher.hpp"


// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void print_hex(const char* label, const uint8_t* d, size_t n) {
    printf("  %s: ", label);
    for (size_t i = 0; i < n && i < 64; i++) printf("%02x", d[i]);
    if (n > 64) printf("...");
    printf("\n");
}

static int check(const char* name, bool pass) {
    printf("[KAT-C] %-56s %s\n", name, pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}


// ---------------------------------------------------------------------------
// RFC 8439 §2.8.2 test vector
// ---------------------------------------------------------------------------

// Key (32 bytes)
static const uint8_t RFC_KEY[32] = {
    0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
    0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
    0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
    0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
};

// Nonce (12 bytes, IETF variant)
static const uint8_t RFC_NONCE[12] = {
    0x07,0x00,0x00,0x00,
    0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
};

// Additional authenticated data
static const uint8_t RFC_AAD[] = {
    0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,
    0xc4,0xc5,0xc6,0xc7
};
static const size_t RFC_AAD_LEN = sizeof(RFC_AAD);

// Plaintext - RFC 8439 §2.8.2 (114 bytes):
// "Ladies and Gentlemen of the class of '99: If I could offer you only
//  one tip for the future, sunscreen would be it."
static const uint8_t RFC_PT[] = {
    0x4c,0x61,0x64,0x69,0x65,0x73,0x20,0x61,
    0x6e,0x64,0x20,0x47,0x65,0x6e,0x74,0x6c,
    0x65,0x6d,0x65,0x6e,0x20,0x6f,0x66,0x20,
    0x74,0x68,0x65,0x20,0x63,0x6c,0x61,0x73,
    0x73,0x20,0x6f,0x66,0x20,0x27,0x39,0x39,
    0x3a,0x20,0x49,0x66,0x20,0x49,0x20,0x63,
    0x6f,0x75,0x6c,0x64,0x20,0x6f,0x66,0x66,
    0x65,0x72,0x20,0x79,0x6f,0x75,0x20,0x6f,
    0x6e,0x6c,0x79,0x20,0x6f,0x6e,0x65,0x20,
    0x74,0x69,0x70,0x20,0x66,0x6f,0x72,0x20,
    0x74,0x68,0x65,0x20,0x66,0x75,0x74,0x75,
    0x72,0x65,0x2c,0x20,0x73,0x75,0x6e,0x73,
    0x63,0x72,0x65,0x65,0x6e,0x20,0x77,0x6f,
    0x75,0x6c,0x64,0x20,0x62,0x65,0x20,0x69,
    0x74,0x2e
};
static const size_t RFC_PT_LEN = sizeof(RFC_PT);

// Expected ciphertext (114 bytes)
static const uint8_t RFC_CT[] = {
    0xd3,0x1a,0x8d,0x34,0x64,0x8e,0x60,0xdb,
    0x7b,0x86,0xaf,0xbc,0x53,0xef,0x7e,0xc2,
    0xa4,0xad,0xed,0x51,0x29,0x6e,0x08,0xfe,
    0xa9,0xe2,0xb5,0xa7,0x36,0xee,0x62,0xd6,
    0x3d,0xbe,0xa4,0x5e,0x8c,0xa9,0x67,0x12,
    0x82,0xfa,0xfb,0x69,0xda,0x92,0x72,0x8b,
    0x1a,0x71,0xde,0x0a,0x9e,0x06,0x0b,0x29,
    0x05,0xd6,0xa5,0xb6,0x7e,0xcd,0x3b,0x36,
    0x92,0xdd,0xbd,0x7f,0x2d,0x77,0x8b,0x8c,
    0x98,0x03,0xae,0xe3,0x28,0x09,0x1b,0x58,
    0xfa,0xb3,0x24,0xe4,0xfa,0xd6,0x75,0x94,
    0x55,0x85,0x80,0x8b,0x48,0x31,0xd7,0xbc,
    0x3f,0xf4,0xde,0xf0,0x8e,0x4b,0x7a,0x9d,
    0xe5,0x76,0xd2,0x65,0x86,0xce,0xc6,0x4b,
    0x61,0x16
};

// Expected tag (16 bytes)
static const uint8_t RFC_TAG[16] = {
    0x1a,0xe1,0x0b,0x59,0x4f,0x09,0xe2,0x6a,
    0x7e,0x90,0x2e,0xcb,0xd0,0x60,0x06,0x91
};


// ---------------------------------------------------------------------------
// Round-trip test data
// ---------------------------------------------------------------------------

static const uint8_t TEST_KEY[32] = {
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
};
static const uint8_t NONCE_A[12] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b
};
static const uint8_t NONCE_B[12] = {
    0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0c
};
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
    printf("KAT System C - ChaCha20-Poly1305\n");
    printf("============================================================\n");

    int failures = 0;

    // -----------------------------------------------------------------------
    // Tests 1–4: round-trip and tamper detection (with TEST_KEY / NONCE_A/B)
    // -----------------------------------------------------------------------
    {
        CipherC cipher;
        cipher.init(TEST_KEY);

        static const size_t PT_LEN = sizeof(PLAINTEXT);
        uint8_t ct[PT_LEN + 16];
        uint8_t pt2[PT_LEN];

        // T1: round-trip
        size_t ct_len = cipher.encrypt(PLAINTEXT, PT_LEN,
                                       NONCE_A, nullptr, 0, ct);
        failures += check("T1 encrypt returns PT_LEN + 16",
                          ct_len == PT_LEN + 16);

        ssize_t dec_len = cipher.decrypt(ct, ct_len, NONCE_A, nullptr, 0, pt2);
        failures += check("T1 decrypt returns PT_LEN",
                          dec_len == (ssize_t)PT_LEN);
        failures += check("T1 decrypted plaintext matches original",
                          memcmp(pt2, PLAINTEXT, PT_LEN) == 0);

        print_hex("ciphertext[0..31]", ct, 32);
        print_hex("tag",               ct + PT_LEN, 16);

        // T2: tamper ciphertext
        {
            uint8_t tampered[PT_LEN + 16];
            memcpy(tampered, ct, PT_LEN + 16);
            tampered[PT_LEN / 2] ^= 0x01;
            ssize_t rc = cipher.decrypt(tampered, PT_LEN + 16, NONCE_A,
                                        nullptr, 0, pt2);
            failures += check("T2 tampered ciphertext → decrypt returns -1",
                              rc == -1);
        }

        // T3: tamper tag
        {
            uint8_t tampered[PT_LEN + 16];
            memcpy(tampered, ct, PT_LEN + 16);
            tampered[PT_LEN + 3] ^= 0x55;
            ssize_t rc = cipher.decrypt(tampered, PT_LEN + 16, NONCE_A,
                                        nullptr, 0, pt2);
            failures += check("T3 tampered tag → decrypt returns -1",
                              rc == -1);
        }

        // T4: nonce sensitivity
        {
            uint8_t ct2[PT_LEN + 16];
            cipher.encrypt(PLAINTEXT, PT_LEN, NONCE_B, nullptr, 0, ct2);
            failures += check("T4 different nonces → different ciphertext",
                              memcmp(ct, ct2, PT_LEN) != 0);
        }
    }

    // -----------------------------------------------------------------------
    // Test 5: RFC 8439 §2.8.2 test vector
    // -----------------------------------------------------------------------
    {
        CipherC rfc_cipher;
        rfc_cipher.init(RFC_KEY);

        uint8_t out[RFC_PT_LEN + 16];
        size_t out_len = rfc_cipher.encrypt(RFC_PT, RFC_PT_LEN,
                                             RFC_NONCE,
                                             RFC_AAD, RFC_AAD_LEN,
                                             out);
        failures += check("T5 RFC 8439 encrypt length correct",
                          out_len == RFC_PT_LEN + 16);
        failures += check("T5 RFC 8439 ciphertext matches",
                          memcmp(out, RFC_CT, RFC_PT_LEN) == 0);
        failures += check("T5 RFC 8439 tag matches",
                          memcmp(out + RFC_PT_LEN, RFC_TAG, 16) == 0);

        if (memcmp(out, RFC_CT, RFC_PT_LEN) != 0) {
            print_hex("  expected CT[0..31]", RFC_CT, RFC_PT_LEN);
            print_hex("  got      CT[0..31]", out,    RFC_PT_LEN);
        }
        if (memcmp(out + RFC_PT_LEN, RFC_TAG, 16) != 0) {
            print_hex("  expected tag", RFC_TAG,           16);
            print_hex("  got      tag", out + RFC_PT_LEN,  16);
        }

        // RFC round-trip
        uint8_t pt2[RFC_PT_LEN];
        ssize_t dec_len = rfc_cipher.decrypt(out, out_len,
                                              RFC_NONCE,
                                              RFC_AAD, RFC_AAD_LEN,
                                              pt2);
        failures += check("T5 RFC 8439 decrypt round-trip",
                          dec_len == (ssize_t)RFC_PT_LEN &&
                          memcmp(pt2, RFC_PT, RFC_PT_LEN) == 0);
    }

    printf("============================================================\n");
    printf("Overall: %s (%d failure(s))\n\n",
           failures == 0 ? "ALL PASS" : "FAILURES DETECTED", failures);

    return failures == 0 ? 0 : 1;
}
