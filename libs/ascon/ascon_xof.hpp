#pragma once

/*
 * ascon_xof.hpp
 *
 * Self-contained, header-only implementation of Ascon-XOF.
 *
 * Specification: Ascon v1.2 (NIST Lightweight Cryptography submission,
 * July 2021).  This is the variant standardised in NIST SP 800-232 as
 * Ascon-XOF128 (rate = 64 bits, a = b = 12 rounds).
 *
 * Parameters
 * ----------
 *   Rate    : 64 bits (8 bytes per permutation squeeze)
 *   Capacity: 256 bits
 *   Rounds  : 12 (p12 used throughout - init, absorb, and squeeze)
 *   IV      : 0x00400c0000000000
 *             Encoding: [rate_bytes=8][a=12][b=0][hash_bits=0][reserved=0]
 *
 * Usage for System D (continuous keystream)
 * -----------------------------------------
 *   AsconXOF xof;
 *   xof.init(shared_secret, 32);    // absorb 32-byte ML-KEM shared secret
 *   xof.squeeze(output_buf, len);   // generate len bytes of keystream
 *   xof.squeeze(more, more_len);    // state advances; never re-initialised
 *
 * Thread safety: NOT thread-safe.  Each thread must hold its own instance.
 *
 * Security note
 * -------------
 * Ascon-XOF is a cryptographic sponge construction whose security rests on
 * the assumed pseudorandomness of the Ascon permutation (SP 800-232 §2).
 * It must NOT be confused with a statistical PRNG such as xoshiro256**.
 * The keystream is computationally secure given a secret seed; it does not
 * provide information-theoretic secrecy.
 *
 * State continuity
 * ----------------
 * The squeeze state must advance monotonically across packets.  Calling
 * init() a second time would restart the keystream from byte 0 and
 * desynchronise encryptor from decryptor.  Call init() exactly once per
 * session, then squeeze continuously.
 */

#include <cstdint>
#include <cstring>


// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

namespace ascon_detail {

// ROTR64 - rotate-right a 64-bit word by n positions.
static inline uint64_t rotr64(uint64_t x, int n) {
    return (x >> n) | (x << (64 - n));
}

// load_be64 - load 8 bytes from a (potentially unaligned) buffer in
// big-endian order into a uint64_t.  Required because Ascon treats the
// state as a big-endian byte sequence.
static inline uint64_t load_be64(const uint8_t* b) {
    return (uint64_t)b[0] << 56 | (uint64_t)b[1] << 48 |
           (uint64_t)b[2] << 40 | (uint64_t)b[3] << 32 |
           (uint64_t)b[4] << 24 | (uint64_t)b[5] << 16 |
           (uint64_t)b[6] <<  8 | (uint64_t)b[7];
}

// store_be64 - write a uint64_t to 8 bytes in big-endian order.
static inline void store_be64(uint8_t* b, uint64_t v) {
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >>  8); b[7] = (uint8_t)(v      );
}

// load_be_partial - load n bytes (1 ≤ n ≤ 8) big-endian into uint64_t,
// zero-extending to 64 bits.  Used for the final absorb padding block.
static inline uint64_t load_be_partial(const uint8_t* b, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i)
        v |= (uint64_t)b[i] << (56 - 8 * i);
    return v;
}

// store_be_partial - write the n most-significant bytes of v to b.
// Used when the final squeeze block is smaller than 8 bytes.
static inline void store_be_partial(uint8_t* b, uint64_t v, size_t n) {
    for (size_t i = 0; i < n; ++i)
        b[i] = (uint8_t)(v >> (56 - 8 * i));
}

// ascon_round - one round of the Ascon permutation.
//   c   : round constant, XOR'd into x[2].
//   x[] : 5-word state (modified in place).
//
// Three layers per round (from the Ascon specification §2.3):
//   1. Constant addition  - x[2] ^= c
//   2. Substitution layer - 5-bit S-box applied to each bit column
//   3. Linear diffusion   - rotation-based mixing within each word
static inline void ascon_round(uint64_t x[5], uint64_t c) {
    // 1. Constant addition
    x[2] ^= c;

    // 2. Substitution layer (S-box on 5-bit column vectors)
    //    The S-box is defined by the following sequence of operations on
    //    the five words (each bit i forms a 5-bit column across the words).
    x[0] ^= x[4];  x[4] ^= x[3];  x[2] ^= x[1];
    uint64_t t0 = x[0], t1 = x[1], t2 = x[2], t3 = x[3], t4 = x[4];
    // NAND step: ~xi & x_{i+1}
    t0 &= ~x[1];   // t0 = x0 & ~x1 ... wait, we need (~x0 & x1)
    // Correct formulation from the Ascon spec:
    t0 = ~x[0];  t1 = ~x[1];  t2 = ~x[2];  t3 = ~x[3];  t4 = ~x[4];
    t0 &= x[1];   t1 &= x[2];  t2 &= x[3];  t3 &= x[4];  t4 &= x[0];
    x[0] ^= t1;  x[1] ^= t2;  x[2] ^= t3;  x[3] ^= t4;  x[4] ^= t0;
    x[1] ^= x[0]; x[0] ^= x[4]; x[3] ^= x[2]; x[2] = ~x[2];

    // 3. Linear diffusion layer
    x[0] ^= rotr64(x[0], 19) ^ rotr64(x[0], 28);
    x[1] ^= rotr64(x[1], 61) ^ rotr64(x[1], 39);
    x[2] ^= rotr64(x[2],  1) ^ rotr64(x[2],  6);
    x[3] ^= rotr64(x[3], 10) ^ rotr64(x[3], 17);
    x[4] ^= rotr64(x[4],  7) ^ rotr64(x[4], 41);
}

// ascon_p12 - apply the full 12-round Ascon permutation to state x[].
// Round constants start at 0xf0 and decrement by 0x0f per round.
static inline void ascon_p12(uint64_t x[5]) {
    ascon_round(x, 0xf0);
    ascon_round(x, 0xe1);
    ascon_round(x, 0xd2);
    ascon_round(x, 0xc3);
    ascon_round(x, 0xb4);
    ascon_round(x, 0xa5);
    ascon_round(x, 0x96);
    ascon_round(x, 0x87);
    ascon_round(x, 0x78);
    ascon_round(x, 0x69);
    ascon_round(x, 0x5a);
    ascon_round(x, 0x4b);
}

} // namespace ascon_detail


// ---------------------------------------------------------------------------
// AsconXOF - stateful Ascon-XOF context for continuous keystream generation.
// ---------------------------------------------------------------------------

class AsconXOF {

    // Ascon state: 5 × 64-bit words = 320 bits = 40 bytes.
    // "Ascon state is only 40 bytes" (dissertation constitution §2, System D).
    uint64_t x_[5] = {};

    // Output buffer: one rate-block (8 bytes) squeezed from the state.
    // buf_pos_ tracks how many bytes of buf_ have already been consumed.
    // buf_pos_ == 8 means the buffer is empty and the next squeeze call must
    // apply p12 before reading x_[0].
    uint8_t  buf_[8] = {};
    size_t   buf_pos_ = 8;   // initialise as "empty"

public:

    // init() - absorb a seed of arbitrary length and prepare the squeeze phase.
    //
    // For System D, seed = ML-KEM 256-bit shared secret (exactly 32 bytes).
    //
    // Process:
    //   1. Load IV into x_[0]; zero the remaining four words.
    //   2. Apply p12.
    //   3. Absorb the seed in 8-byte blocks, applying p12 after each.
    //   4. Apply a 1-byte domain-separation / padding bit after the last block.
    //   5. Apply p12 once more to finalise the absorb phase.
    //   6. The state is now ready for squeezing; buf_pos_ = 8 (buffer empty).
    //
    // Call exactly once per session.
    void init(const uint8_t* seed, size_t seed_len) {
        using namespace ascon_detail;

        // IV for Ascon-XOF (Ascon v1.2, rate=8 bytes, a=12, b=12)
        static constexpr uint64_t IV = 0x00400c0000000000ULL;

        x_[0] = IV;
        x_[1] = x_[2] = x_[3] = x_[4] = 0;

        ascon_p12(x_);

        // Absorb full 8-byte blocks.
        while (seed_len >= 8) {
            x_[0] ^= load_be64(seed);
            ascon_p12(x_);
            seed     += 8;
            seed_len -= 8;
        }

        // Final absorb block: partial bytes followed by the 0x80 padding bit.
        // Padding: the first bit after the data is 1, the rest are 0.
        // In big-endian 64-bit: the padding bit occupies bit position
        // (63 - seed_len * 8) of the rate word, i.e. the byte immediately
        // after the last data byte carries 0x80.
        uint64_t last = 0;
        if (seed_len > 0)
            last = load_be_partial(seed, seed_len);
        last ^= (uint64_t)0x80 << (8 * (7 - seed_len));   // append 0x80 pad byte
        x_[0] ^= last;
        ascon_p12(x_);

        // Buffer is empty; the next squeeze call will read x_[0] directly.
        buf_pos_ = 8;
    }

    // squeeze() - generate len bytes of keystream into out[].
    //
    // The state advances monotonically; do NOT call init() again between
    // squeeze calls.  Multiple consecutive calls produce a contiguous
    // keystream, identical to a single squeeze(out, total_len) call.
    void squeeze(uint8_t* out, size_t len) {
        using namespace ascon_detail;

        while (len > 0) {
            // Refill buffer if exhausted.
            if (buf_pos_ >= 8) {
                // Output the current rate word, then apply p12 to advance.
                store_be64(buf_, x_[0]);
                ascon_p12(x_);
                buf_pos_ = 0;
            }

            // Copy as many bytes as available in the buffer.
            size_t chunk = 8 - buf_pos_;
            if (chunk > len) chunk = len;
            memcpy(out, buf_ + buf_pos_, chunk);
            out      += chunk;
            buf_pos_ += chunk;
            len      -= chunk;
        }
    }
};
