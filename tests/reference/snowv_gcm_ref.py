"""
tests/reference/snowv_gcm_ref.py

Independent Python reference implementation of SNOW-V-GCM.

Purpose
-------
Generates reference test vectors for kat_system_b.cpp (Test 5).  Because the
Ekdahl et al. 2019 paper does not publish SNOW-V-GCM test vectors, this script
serves as an independent implementation of the same construction.  Any
discrepancy between this script's output and the C++ implementation is a bug
in one of the two codebases.

Usage
-----
    python3 snowv_gcm_ref.py

Copy the printed REFERENCE_TAG value into kat_system_b.cpp and set
SKIP_CROSS_CHECK = false.

SNOW-V Python port
------------------
This script reimplements the SnowV32 state machine from snow-v.h in Python
using the same arithmetic so that the output is bit-for-bit identical.

The GHASH implementation follows NIST SP 800-38D §6.3 with the same
GCM bit ordering used in snowv_gcm.hpp.

AEAD mode flag
--------------
keyiv_setup() is called with is_aead_mode=1, setting B[0..7] to the
domain-separation constants from the paper.  This matches the C++ code.
"""

import struct

# GF(2^128) multiplication (same algorithm as gmul128 in snowv_gcm.hpp)

def gmul128(X: bytes, Y: bytes) -> bytes:
    """Multiply two 128-bit GCM field elements."""
    assert len(X) == 16 and len(Y) == 16
    Z = bytearray(16)
    V = bytearray(X)
    for i in range(128):
        # Bit i of Y (MSB of byte 0 = bit 0 in GCM convention)
        if (Y[i >> 3] >> (7 - (i & 7))) & 1:
            for j in range(16):
                Z[j] ^= V[j]
        lsb = V[15] & 1
        # Right-shift V by 1 bit
        for j in range(15, 0, -1):
            V[j] = ((V[j] >> 1) | ((V[j-1] & 1) << 7)) & 0xFF
        V[0] >>= 1
        if lsb:
            V[0] ^= 0xe1
    return bytes(Z)


def ghash(H: bytes, aad: bytes, ct: bytes) -> bytes:
    """GHASH_H(aad, ct) per NIST SP 800-38D §6.4."""
    g = bytearray(16)

    def process_block(blk: bytes):
        assert len(blk) == 16
        for j in range(16):
            g[j] ^= blk[j]
        result = gmul128(bytes(g), H)
        g[:] = result

    # AAD blocks
    for i in range(0, len(aad), 16):
        blk = aad[i:i+16].ljust(16, b'\x00')
        process_block(blk)

    # Ciphertext blocks
    for i in range(0, len(ct), 16):
        blk = ct[i:i+16].ljust(16, b'\x00')
        process_block(blk)

    # Length block
    la = len(aad) * 8
    lc = len(ct)  * 8
    length_block = struct.pack('>QQ', la, lc)
    process_block(length_block)

    return bytes(g)


# SNOW-V state machine (Python port of snow-v.h SnowV32)

SBOX = [
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
]

SIGMA = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]

MASK16 = 0xFFFF
MASK32 = 0xFFFFFFFF


def makeu16(a, b):
    return ((a & 0xFF) << 8) | (b & 0xFF)


def makeu32(a, b):
    return ((a & 0xFFFF) << 16) | (b & 0xFFFF)


def mul_x(v, c):
    v &= MASK16
    if v & 0x8000:
        return ((v << 1) & MASK16) ^ c
    else:
        return (v << 1) & MASK16


def mul_x_inv(v, d):
    v &= MASK16
    if v & 0x0001:
        return (v >> 1) ^ d
    else:
        return v >> 1


def rotl32(word, offset):
    word &= MASK32
    return ((word << offset) | (word >> (32 - offset))) & MASK32


def aes_enc_round(state, round_key):
    sb = []
    for word in state:
        for shift in [0, 8, 16, 24]:
            sb.append(SBOX[(word >> shift) & 0xFF])
    result = []
    for j in range(4):
        def SB(index, offset):
            return (sb[index % 16] << (offset * 8)) & MASK32
        def MKSTEP(j):
            w = SB(j*4+0, 3) | SB(j*4+5, 0) | SB(j*4+10, 1) | SB(j*4+15, 2)
            w &= MASK32
            t = (rotl32(w, 16) ^ ((w << 1) & 0xFEFEFEFE) ^
                 (((w >> 7) & 0x01010101) * 0x1B)) & MASK32
            return (round_key[j] ^ w ^ t ^ rotl32(t, 8)) & MASK32
        result.append(MKSTEP(j))
    return result


def permute_sigma(state):
    tmp = []
    for i in range(16):
        word_idx = SIGMA[i] >> 2
        byte_shift = (SIGMA[i] & 3) << 3
        tmp.append((state[word_idx] >> byte_shift) & 0xFF)
    result = []
    for i in range(4):
        w = makeu32(makeu16(tmp[4*i+3], tmp[4*i+2]),
                    makeu16(tmp[4*i+1], tmp[4*i]))
        result.append(w)
    return result


class SnowV32:
    def __init__(self):
        self.A = [0] * 16
        self.B = [0] * 16
        self.R1 = [0] * 4
        self.R2 = [0] * 4
        self.R3 = [0] * 4
        self.AesKey1 = [0, 0, 0, 0]
        self.AesKey2 = [0, 0, 0, 0]

    def fsm_update(self):
        R1temp = self.R1[:]
        for i in range(4):
            T2 = makeu32(self.A[2*i+1], self.A[2*i])
            # C++: R1[i] = (T2 ^ R3[i]) + R2[i]   — XOR first, then add
            # Python + has higher precedence than ^, so parentheses are required.
            self.R1[i] = ((T2 ^ self.R3[i]) + self.R2[i]) & MASK32
        self.R1 = permute_sigma(self.R1)
        self.R3 = aes_enc_round(self.R2, self.AesKey2)
        self.R2 = aes_enc_round(R1temp, self.AesKey1)

    def lfsr_update(self):
        for _ in range(8):
            u = (mul_x(self.A[0], 0x990f) ^ self.A[1] ^
                 mul_x_inv(self.A[8], 0xcc87) ^ self.B[0]) & MASK16
            v = (mul_x(self.B[0], 0xc963) ^ self.B[3] ^
                 mul_x_inv(self.B[8], 0xe4b1) ^ self.A[0]) & MASK16
            self.A = self.A[1:] + [u]
            self.B = self.B[1:] + [v]

    def keystream(self):
        z = []
        for i in range(4):
            T1 = makeu32(self.B[2*i+9], self.B[2*i+8])
            v = (T1 + self.R1[i]) ^ self.R2[i]
            v &= MASK32
            z += [(v >> 0) & 0xFF, (v >> 8) & 0xFF,
                  (v >> 16) & 0xFF, (v >> 24) & 0xFF]
        self.fsm_update()
        self.lfsr_update()
        return bytes(z)

    def keyiv_setup(self, key: bytes, iv: bytes, is_aead_mode: int):
        assert len(key) == 32 and len(iv) == 16
        for i in range(8):
            self.A[i]   = makeu16(iv[2*i+1],    iv[2*i])
            self.A[i+8] = makeu16(key[2*i+1],   key[2*i])
            self.B[i]   = 0
            self.B[i+8] = makeu16(key[2*i+17],  key[2*i+16])
        if is_aead_mode == 1:
            self.B[0] = 0x6C41
            self.B[1] = 0x7865
            self.B[2] = 0x6B45
            self.B[3] = 0x2064
            self.B[4] = 0x694A
            self.B[5] = 0x676E
            self.B[6] = 0x6854
            self.B[7] = 0x6D6F
        self.R1 = [0]*4
        self.R2 = [0]*4
        self.R3 = [0]*4
        for i in range(16):
            z = self.keystream()
            for j in range(8):
                self.A[j+8] ^= makeu16(z[2*j+1], z[2*j])
            if i == 14:
                for j in range(4):
                    self.R1[j] ^= makeu32(
                        makeu16(key[4*j+3],  key[4*j+2]),
                        makeu16(key[4*j+1],  key[4*j+0]))
            if i == 15:
                for j in range(4):
                    self.R1[j] ^= makeu32(
                        makeu16(key[4*j+19], key[4*j+18]),
                        makeu16(key[4*j+17], key[4*j+16]))


# SNOW-V-GCM encrypt reference

def snowv_gcm_encrypt_ref(key: bytes, iv: bytes,
                           aad: bytes, pt: bytes) -> bytes:
    """Returns ciphertext || tag (len(pt) + 16 bytes)."""
    snowv = SnowV32()
    snowv.keyiv_setup(key, iv, 1)

    H   = snowv.keystream()   # block 0: GHASH subkey
    EJ0 = snowv.keystream()   # block 1: tag mask

    # Encrypt plaintext
    ct = bytearray()
    remaining = len(pt)
    done = 0
    while remaining >= 16:
        ks = snowv.keystream()
        for i in range(16):
            ct.append(pt[done + i] ^ ks[i])
        done += 16
        remaining -= 16
    if remaining > 0:
        ks = snowv.keystream()
        for i in range(remaining):
            ct.append(pt[done + i] ^ ks[i])

    # Tag = GHASH(H, aad, ct) XOR EJ0
    tag_raw = ghash(H, aad, bytes(ct))
    tag = bytes(a ^ b for a, b in zip(tag_raw, EJ0))

    return bytes(ct) + tag


# Test vectors (matching kat_system_b.cpp)

TEST_KEY = bytes([
    0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
    0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
    0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
    0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
])

NONCE_A = bytes([
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00
])

PLAINTEXT = bytes([
    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
    0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
    0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
    0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
    0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
    0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
    0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
    0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
])


if __name__ == "__main__":
    result = snowv_gcm_encrypt_ref(TEST_KEY, NONCE_A, b"", PLAINTEXT)
    ct  = result[:-16]
    tag = result[-16:]

    print("SNOW-V-GCM reference output")
    print("===========================")
    print(f"Key   : {TEST_KEY.hex()}")
    print(f"Nonce : {NONCE_A.hex()}")
    print(f"PT    : {PLAINTEXT.hex()}")
    print()
    print(f"CT    : {ct.hex()}")
    print(f"Tag   : {tag.hex()}")
    print()
    print("Copy the following into kat_system_b.cpp as REFERENCE_TAG:")
    print("static const uint8_t REFERENCE_TAG[16] = {")
    hex_vals = [f"0x{b:02x}" for b in tag]
    for i in range(0, 16, 8):
        line = ",".join(hex_vals[i:i+8])
        suffix = "," if i + 8 < 16 else ""
        print(f"    {line}{suffix}")
    print("};")
    print()
    print("Then set: static const bool SKIP_CROSS_CHECK = false;")
