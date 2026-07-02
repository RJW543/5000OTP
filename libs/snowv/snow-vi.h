/*
 * SNOW-Vi 128-bit portable reference (endianness-free, no SIMD).
 *
 * Source of truth: Ekdahl, Maximov, Johansson, Yang,
 *   "SNOW-Vi: an extreme performance variant of SNOW-V for lower grade CPUs",
 *   ACM WiSec '21 / IACR ePrint 2021/236, Appendix B, Listing 4.
 *
 * This is a byte-exact translation of that reference: every SSE intrinsic in
 * Listing 4 is emulated here with its precise semantics, so the logic is a 1:1
 * copy of the authors' code rather than a re-derivation.
 *
 * VALIDATION (see snowvi_portable_test.cpp), all passing in-sandbox:
 *   (a) the software AES round below is bit-identical to _mm_aesenc_si128(x,0)
 *       over 200,000 random inputs;
 *   (b) it reproduces official test vectors #1 (key=iv=0) and #2 (key=iv=ff)
 *       from Appendix C, Listing 5;
 *   (c) it matches a straight SSE translation of Listing 4 over 10,000 random
 *       key/IV pairs x 12 keystream blocks, in both plain and AEAD mode.
 *
 * This portable header is the correct target for AArch64. It intentionally
 * exposes the interface the SNOW-Vi GCM layer expects (matching the pattern of the
 * former SNOW-V core): construct, keyiv_setup(key, iv, aead), then call
 * keystream() for successive 16-byte blocks (block 0 = H, block 1 = EJ0, etc.).
 * The ARM-accelerated path (PMULL GHASH + AESE FSM) must reproduce this output
 * byte for byte and is validated on the Pi, not here.
 */
#ifndef SNOW_VI_H
#define SNOW_VI_H

#include <cstdint>
#include <cstring>

struct SnowVi {
    typedef uint8_t u8;

    struct V { u8 b[16]; };   // 128-bit little-endian lane block

    // --- exact SSE-op equivalents ---
    static V v_xor(V a, V b){ V r; for(int i=0;i<16;i++) r.b[i]=a.b[i]^b.b[i]; return r; }
    static V v_and(V a, V b){ V r; for(int i=0;i<16;i++) r.b[i]=a.b[i]&b.b[i]; return r; }
    static V v_add32(V a, V b){                      // _mm_add_epi32
        V r; for(int l=0;l<4;l++){ uint32_t x,y; memcpy(&x,a.b+4*l,4); memcpy(&y,b.b+4*l,4); x+=y; memcpy(r.b+4*l,&x,4);} return r; }
    static V v_set16(uint16_t v){                    // _mm_set1_epi16
        V r; for(int k=0;k<8;k++){ r.b[2*k]=v&0xff; r.b[2*k+1]=v>>8; } return r; }
    static V v_sll16(V a){                           // _mm_slli_epi16(a,1)
        V r; for(int k=0;k<8;k++){ uint16_t x; memcpy(&x,a.b+2*k,2); x<<=1; memcpy(r.b+2*k,&x,2);} return r; }
    static V v_sra16_15(V a){                        // _mm_srai_epi16(a,15) -> 0x0000/0xffff mask
        V r; for(int k=0;k<8;k++){ uint16_t x; memcpy(&x,a.b+2*k,2); uint16_t m=(x&0x8000)?0xffff:0x0000; memcpy(r.b+2*k,&m,2);} return r; }
    static V v_tap7(V Hi, V Lo){                      // _mm_alignr_epi8(Hi,Lo,14)
        u8 c[32]; memcpy(c,Lo.b,16); memcpy(c+16,Hi.b,16); V r; for(int i=0;i<16;i++) r.b[i]=c[i+14]; return r; }
    static V v_sigma(V a){                            // _mm_shuffle_epi8 with the SNOW-Vi sigma mask
        static const u8 S[16]={0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15};
        V r; for(int i=0;i<16;i++) r.b[i]=a.b[S[i]]; return r; }
    static V v_aesenc0(V a){                          // _mm_aesenc_si128(a, ZERO)
        static const u8 SB[256]={
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
        auto xt=[](u8 x)->u8{ return (u8)((x<<1)^((x>>7)*0x1b)); };
        u8 s[16]; for(int i=0;i<16;i++) s[i]=SB[a.b[i]];
        u8 sr[16]; for(int c=0;c<4;c++) for(int r=0;r<4;r++) sr[r+4*c]=s[r+4*((c+r)&3)];
        V o; for(int c=0;c<4;c++){ u8 a0=sr[4*c],a1=sr[4*c+1],a2=sr[4*c+2],a3=sr[4*c+3];
            o.b[4*c+0]=xt(a0)^(xt(a1)^a1)^a2^a3;
            o.b[4*c+1]=a0^xt(a1)^(xt(a2)^a2)^a3;
            o.b[4*c+2]=a0^a1^xt(a2)^(xt(a3)^a3);
            o.b[4*c+3]=(xt(a0)^a0)^a1^a2^xt(a3); }
        return o; }

    V A0,A1,B0,B1;   // LFSR
    V R1,R2,R3;      // FSM

    // One 128-bit keystream word (literal Listing 4).
    V keystream(){
        V T1=B1, T2=A1;
        A1 = v_xor(v_xor(v_xor(v_tap7(A1,A0), B0), v_sll16(A0)), v_and(v_set16(0x4a6d), v_sra16_15(A0)));
        B1 = v_xor(v_xor(v_sll16(B0), A0), v_xor(B1, v_and(v_set16(0xcc87), v_sra16_15(B0))));
        A0 = T2; B0 = T1;
        V z = v_xor(R2, v_add32(R1, T1));
        T2 = v_add32(v_xor(T2, R3), R2);
        R3 = v_aesenc0(R2);
        R2 = v_aesenc0(R1);
        R1 = v_sigma(T2);
        return z;
    }

    // key = 32 bytes, iv = 16 bytes. aead=1 loads the SNOW-V/Vi AEAD constant.
    void keyiv_setup(const u8* key, const u8* iv, int aead){
        memset(&B0,0,16); memset(&R1,0,16); memset(&R2,0,16); memset(&R3,0,16);
        memcpy(A0.b, iv, 16); memcpy(A1.b, key, 16); memcpy(B1.b, key+16, 16);
        if(aead) memcpy(B0.b, "AlexEkd JingThom", 16);
        for(int i=0;i<15;i++){ V k=keystream(); A1=v_xor(A1,k); }
        for(int i=0;i<16;i++) R1.b[i]^=key[i];
        { V k=keystream(); A1=v_xor(A1,k); }
        for(int i=0;i<16;i++) R1.b[i]^=key[16+i];
    }
};

#endif /* SNOW_VI_H */
