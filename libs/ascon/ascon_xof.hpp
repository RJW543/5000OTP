#pragma once

/*
 * ascon_xof.hpp — Ascon-Xof (Ascon v1.2, NIST LWC submission), header-only.
 *
 * NOTE: this implements the Ascon v1.2 "Ascon-Xof" (big-endian, IV 0x00400c...).
 * It is NOT the finalised NIST SP 800-232 "Ascon-XOF128", which changed the IV
 * constants and switched to little-endian and therefore produces different output.
 *
 *   Rate 64 bits (8 bytes/squeeze), capacity 256, p12 throughout,
 *   IV = 0x00400c0000000000.
 *
 * Implementation note (2026-07-02): the permutation is written "opt64" style —
 * the 5-word state is loaded into locals once, all 12 rounds run fully inlined
 * on those registers, and the state is stored back once, so it stays in
 * registers through the round loop instead of being reloaded from memory each
 * round. Byte-for-byte identical to the previous reference: verified over
 * 3,000,000 random p12 states plus the all-zero state, and by the System D KAT.
 * Same primitive, same output, faster squeeze.
 *
 * Continuous keystream (System D): init(seed,len) once, then squeeze()
 * repeatedly; the state advances monotonically and must never be re-init'd
 * mid-session. Security rests on the pseudorandomness of the Ascon permutation
 * (Ascon v1.2 spec §2); computationally secure given a secret seed, not OTP-secret.
 */

#include <cstdint>
#include <cstring>

namespace ascon_detail {

static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

static inline uint64_t load_be64(const uint8_t* b) {
    return (uint64_t)b[0] << 56 | (uint64_t)b[1] << 48 |
           (uint64_t)b[2] << 40 | (uint64_t)b[3] << 32 |
           (uint64_t)b[4] << 24 | (uint64_t)b[5] << 16 |
           (uint64_t)b[6] <<  8 | (uint64_t)b[7];
}

static inline void store_be64(uint8_t* b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >>  8); b[7] = (uint8_t)(v      );
}

static inline uint64_t load_be_partial(const uint8_t* b, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i)
        v |= (uint64_t)b[i] << (56 - 8 * i);
    return v;
}

// ascon_round - one round on five register-resident state words:
// constant addition, 5-bit S-box (chi + affine), then rotation-based diffusion.
static inline void ascon_round(uint64_t& x0, uint64_t& x1, uint64_t& x2,
                               uint64_t& x3, uint64_t& x4, uint64_t c) {
    x2 ^= c;
    x0 ^= x4; x4 ^= x3; x2 ^= x1;
    uint64_t t0 = ~x0 & x1;
    uint64_t t1 = ~x1 & x2;
    uint64_t t2 = ~x2 & x3;
    uint64_t t3 = ~x3 & x4;
    uint64_t t4 = ~x4 & x0;
    x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
    x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = ~x2;
    x0 ^= rotr64(x0, 19) ^ rotr64(x0, 28);
    x1 ^= rotr64(x1, 61) ^ rotr64(x1, 39);
    x2 ^= rotr64(x2,  1) ^ rotr64(x2,  6);
    x3 ^= rotr64(x3, 10) ^ rotr64(x3, 17);
    x4 ^= rotr64(x4,  7) ^ rotr64(x4, 41);
}

// ascon_p12 - load state to registers, 12 unrolled rounds, store back.
static inline void ascon_p12(uint64_t x[5]) {
    uint64_t x0 = x[0], x1 = x[1], x2 = x[2], x3 = x[3], x4 = x[4];
    ascon_round(x0, x1, x2, x3, x4, 0xf0);
    ascon_round(x0, x1, x2, x3, x4, 0xe1);
    ascon_round(x0, x1, x2, x3, x4, 0xd2);
    ascon_round(x0, x1, x2, x3, x4, 0xc3);
    ascon_round(x0, x1, x2, x3, x4, 0xb4);
    ascon_round(x0, x1, x2, x3, x4, 0xa5);
    ascon_round(x0, x1, x2, x3, x4, 0x96);
    ascon_round(x0, x1, x2, x3, x4, 0x87);
    ascon_round(x0, x1, x2, x3, x4, 0x78);
    ascon_round(x0, x1, x2, x3, x4, 0x69);
    ascon_round(x0, x1, x2, x3, x4, 0x5a);
    ascon_round(x0, x1, x2, x3, x4, 0x4b);
    x[0] = x0; x[1] = x1; x[2] = x2; x[3] = x3; x[4] = x4;
}

} // namespace ascon_detail


class AsconXOF {
    uint64_t x_[5] = {};
    uint8_t  buf_[8] = {};
    size_t   buf_pos_ = 8;   // 8 == buffer empty

public:
    // Absorb a seed (System D: the 32-byte ML-KEM shared secret). Call once.
    void init(const uint8_t* seed, size_t seed_len) {
        using namespace ascon_detail;
        static constexpr uint64_t IV = 0x00400c0000000000ULL;
        x_[0] = IV;
        x_[1] = x_[2] = x_[3] = x_[4] = 0;
        ascon_p12(x_);
        while (seed_len >= 8) {
            x_[0] ^= load_be64(seed);
            ascon_p12(x_);
            seed += 8; seed_len -= 8;
        }
        uint64_t last = 0;
        if (seed_len > 0) last = load_be_partial(seed, seed_len);
        last ^= (uint64_t)0x80 << (8 * (7 - seed_len));   // 0x80 padding byte
        x_[0] ^= last;
        ascon_p12(x_);
        buf_pos_ = 8;
    }

    // Generate len bytes of continuous keystream. Consecutive calls are
    // identical to one squeeze(out, total_len); never re-init between calls.
    void squeeze(uint8_t* out, size_t len) {
        using namespace ascon_detail;
        while (len > 0) {
            if (buf_pos_ >= 8) {
                store_be64(buf_, x_[0]);
                ascon_p12(x_);
                buf_pos_ = 0;
            }
            size_t chunk = 8 - buf_pos_;
            if (chunk > len) chunk = len;
            memcpy(out, buf_ + buf_pos_, chunk);
            out += chunk; buf_pos_ += chunk; len -= chunk;
        }
    }
};
