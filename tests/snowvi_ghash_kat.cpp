// snowvi_ghash_kat.cpp — validate the accelerated GHASH (snowvi_ghash::ghash,
// PMULL on Pi 5 / table on Zero / PCLMUL on x86) against a self-contained
// bitwise GF(2^128) reference, byte-for-byte over random AAD/ciphertext.
#include "snowvi_ghash.hpp"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <random>
#include <vector>
typedef uint8_t u8;

// --- independent bitwise GHASH reference (NIST SP 800-38D, GCM bit order) ---
static void gmul_bitwise(u8 Z[16], const u8 X[16], const u8 H[16]) {
    u8 V[16]; memcpy(V, X, 16); memset(Z, 0, 16);
    for (int i = 0; i < 128; i++) {
        if ((H[i>>3] >> (7-(i&7))) & 1) for (int j=0;j<16;j++) Z[j]^=V[j];
        u8 lsb = V[15] & 1;
        for (int j=15;j>0;j--) V[j]=(u8)((V[j]>>1)|((V[j-1]&1)<<7));
        V[0] >>= 1; if (lsb) V[0]^=0xe1;
    }
}
static void ghash_ref(u8 tag[16], const u8 H[16], const u8* aad, size_t al,
                      const u8* ct, size_t cl) {
    u8 g[16]={0}, blk[16];
    size_t off=0;
    while (off<al){ memset(blk,0,16); size_t n=(al-off<16)?(al-off):16; memcpy(blk,aad+off,n);
                    for(int j=0;j<16;j++) g[j]^=blk[j]; gmul_bitwise(g,g,H); off+=16; }
    off=0;
    while (off<cl){ memset(blk,0,16); size_t n=(cl-off<16)?(cl-off):16; memcpy(blk,ct+off,n);
                    for(int j=0;j<16;j++) g[j]^=blk[j]; gmul_bitwise(g,g,H); off+=16; }
    uint64_t la=(uint64_t)al*8, lc=(uint64_t)cl*8;
    for(int j=0;j<8;j++) blk[j]=(u8)(la>>(56-8*j));
    for(int j=0;j<8;j++) blk[8+j]=(u8)(lc>>(56-8*j));
    for(int j=0;j<16;j++) g[j]^=blk[j]; gmul_bitwise(g,g,H);
    memcpy(tag,g,16);
}

int main(){
#if defined(SNOWVI_GHASH_PCLMUL)
    const char* path="PCLMUL (x86 proxy for Pi 5 PMULL)";
#elif defined(SNOWVI_GHASH_TABLE)
    const char* path="TABLE (Pi Zero path)";
#else
    const char* path="PMULL";
#endif
    std::mt19937 rng(99); int bad=0;
    for(int t=0;t<200000;t++){
        u8 H[16]; for(int i=0;i<16;i++)H[i]=rng();
        size_t al=rng()%41, cl=rng()%301;
        std::vector<u8> aad(al),ct(cl); for(auto&x:aad)x=rng(); for(auto&x:ct)x=rng();
        u8 ref[16],acc[16];
        ghash_ref(ref,H,aad.data(),al,ct.data(),cl);
        snowvi_ghash::ghash(acc,H,aad.data(),al,ct.data(),cl);
        if(memcmp(ref,acc,16)) bad++;
    }
    printf("accelerated ghash() vs bitwise reference [%s], 200k random AAD/CT: %s\n",
           path, bad?"FAIL":"PASS");
    return bad?1:0;
}
