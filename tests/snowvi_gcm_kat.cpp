#include "snowvi_gcm.hpp"
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

// self-contained bitwise GHASH reference
static void gmul_bitwise(uint8_t Z[16], const uint8_t X[16], const uint8_t H[16]){
    uint8_t V[16]; memcpy(V,X,16); memset(Z,0,16);
    for(int i=0;i<128;i++){ if((H[i>>3]>>(7-(i&7)))&1) for(int j=0;j<16;j++) Z[j]^=V[j];
        uint8_t lsb=V[15]&1; for(int j=15;j>0;j--) V[j]=(uint8_t)((V[j]>>1)|((V[j-1]&1)<<7));
        V[0]>>=1; if(lsb) V[0]^=0xe1; } }
static void ghash_ref(uint8_t tag[16], const uint8_t H[16], const uint8_t* aad, size_t al,
                      const uint8_t* ct, size_t cl){
    uint8_t g[16]={0},blk[16]; size_t off=0;
    while(off<al){ memset(blk,0,16); size_t n=(al-off<16)?(al-off):16; memcpy(blk,aad+off,n);
        for(int j=0;j<16;j++) g[j]^=blk[j]; gmul_bitwise(g,g,H); off+=16; }
    off=0;
    while(off<cl){ memset(blk,0,16); size_t n=(cl-off<16)?(cl-off):16; memcpy(blk,ct+off,n);
        for(int j=0;j<16;j++) g[j]^=blk[j]; gmul_bitwise(g,g,H); off+=16; }
    uint64_t la=(uint64_t)al*8, lc=(uint64_t)cl*8;
    for(int j=0;j<8;j++) blk[j]=(uint8_t)(la>>(56-8*j));
    for(int j=0;j<8;j++) blk[8+j]=(uint8_t)(lc>>(56-8*j));
    for(int j=0;j<16;j++) g[j]^=blk[j]; gmul_bitwise(g,g,H); memcpy(tag,g,16); }
typedef uint8_t u8;

// Independent spec re-derivation of (ciphertext, tag) using a FRESH SnowVi and
// the trusted ghash, wired straight from the SNOW-V-GCM spec. Any wiring error
// in snowvi_gcm_encrypt (block order, offset, tag mask) shows up as a mismatch.
static void ref_encrypt(const u8* key,const u8* iv,const u8* aad,size_t al,
                        const u8* pt,size_t pl,std::vector<u8>& ct,u8 tag[16]){
    SnowVi s; s.keyiv_setup(key,iv,1);
    u8 H[16],EJ0[16];
    { SnowVi::V k=s.keystream(); memcpy(H,k.b,16);}   { SnowVi::V k=s.keystream(); memcpy(EJ0,k.b,16);}
    ct.assign(pl,0);
    size_t done=0,rem=pl;
    while(rem>0){ SnowVi::V k=s.keystream(); size_t n=rem<16?rem:16; for(size_t i=0;i<n;i++) ct[done+i]=pt[done+i]^k.b[i]; done+=n; rem-=n; }
    ghash_ref(tag,H,aad,al,ct.data(),pl);
    for(int i=0;i<16;i++) tag[i]^=EJ0[i];
}

int main(){
    std::mt19937 rng(2026); int fails=0;
    size_t lens[]={0,1,15,16,17,31,32,33,63,64,127,512,1000};

    // (1) round-trip over all boundary lengths + random aad
    int rt=0;
    for(int t=0;t<3000;t++){
        u8 key[32],iv[16]; for(int i=0;i<32;i++)key[i]=rng(); for(int i=0;i<16;i++)iv[i]=rng();
        size_t pl=lens[rng()%(sizeof(lens)/sizeof(lens[0]))];
        size_t al=rng()%40;
        std::vector<u8> pt(pl),aad(al),ct(pl+16),rec(pl);
        for(auto&x:pt)x=rng(); for(auto&x:aad)x=rng();
        size_t cl=snowvi_gcm_encrypt(key,iv,aad.data(),al,pt.data(),pl,ct.data());
        if(cl!=pl+16){rt++;continue;}
        ssize_t r=snowvi_gcm_decrypt(key,iv,aad.data(),al,ct.data(),cl,rec.data());
        if(r!=(ssize_t)pl || memcmp(rec.data(),pt.data(),pl)){rt++;}
    }
    printf("(1) round-trip (3000 cases, all block boundaries): %s\n", rt?"FAIL":"PASS"); fails+=!!rt;

    // (2) tamper: flip a bit in ciphertext / aad / tag -> must reject
    int tam=0;
    for(int t=0;t<3000;t++){
        u8 key[32],iv[16]; for(int i=0;i<32;i++)key[i]=rng(); for(int i=0;i<16;i++)iv[i]=rng();
        size_t pl=1+(rng()%200), al=1+(rng()%30);
        std::vector<u8> pt(pl),aad(al),ct(pl+16),rec(pl);
        for(auto&x:pt)x=rng(); for(auto&x:aad)x=rng();
        size_t cl=snowvi_gcm_encrypt(key,iv,aad.data(),al,pt.data(),pl,ct.data());
        // genuine must verify
        if(snowvi_gcm_decrypt(key,iv,aad.data(),al,ct.data(),cl,rec.data())!=(ssize_t)pl){tam++;continue;}
        // flip a ciphertext byte
        std::vector<u8> c1=ct; c1[rng()%pl]^=(1<<(rng()%8));
        if(snowvi_gcm_decrypt(key,iv,aad.data(),al,c1.data(),cl,rec.data())!=-1){tam++;}
        // flip an aad byte
        std::vector<u8> a1=aad; a1[rng()%al]^=(1<<(rng()%8));
        if(snowvi_gcm_decrypt(key,iv,a1.data(),al,ct.data(),cl,rec.data())!=-1){tam++;}
        // flip a tag byte
        std::vector<u8> c2=ct; c2[pl+(rng()%16)]^=(1<<(rng()%8));
        if(snowvi_gcm_decrypt(key,iv,aad.data(),al,c2.data(),cl,rec.data())!=-1){tam++;}
    }
    printf("(2) tamper rejection (ct/aad/tag, 3000x3 flips): %s\n", tam?"FAIL":"PASS"); fails+=!!tam;

    // (3) spec re-derivation cross-check of (C, tag)
    int xc=0;
    for(int t=0;t<3000;t++){
        u8 key[32],iv[16]; for(int i=0;i<32;i++)key[i]=rng(); for(int i=0;i<16;i++)iv[i]=rng();
        size_t pl=lens[rng()%(sizeof(lens)/sizeof(lens[0]))], al=rng()%40;
        std::vector<u8> pt(pl),aad(al),ct(pl+16); for(auto&x:pt)x=rng(); for(auto&x:aad)x=rng();
        snowvi_gcm_encrypt(key,iv,aad.data(),al,pt.data(),pl,ct.data());
        std::vector<u8> rc; u8 rtag[16]; ref_encrypt(key,iv,aad.data(),al,pt.data(),pl,rc,rtag);
        if(memcmp(ct.data(),rc.data(),pl) || memcmp(ct.data()+pl,rtag,16)){xc++;}
    }
    printf("(3) spec re-derivation of (ciphertext, tag): %s\n", xc?"FAIL":"PASS"); fails+=!!xc;

    printf("\nOVERALL: %s\n", fails?"FAILURE":"ALL CHECKS PASS");
    return fails?1:0;
}
