#include <stdint.h> // get uint32_t and uint64_t types, so is not platform dependent (unsigned int (32 bits) and unsigned long long (64 bits) could vary in size)
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>
#include <stdio.h>
#include "poly1305_opt.h"

#define B 2
#define PARALLEL_BLOCKS 4
#define NUM_LIMBS 5
#define POLY_BLOCK 16


const uint32_t mask_lowest_26bits = 0x3ffffff; // mask to keep only lowest 26 bits (26 ones in binary)
const uint64_t mask_lowest_32bits = 0xffffffffULL; 

#define MUL_MOD_P(acc64, r64, mult) do{ \
    mult[0] = acc64[0]*r64[0] + acc64[1]*5*r64[4] + acc64[2]*5*r64[3] + 5*acc64[3]*r64[2] + 5*acc64[4]*r64[1];\
    mult[1] = acc64[0]*r64[1] + acc64[1]*r64[0] + acc64[2]*5*r64[4] + acc64[3]*5*r64[3] + acc64[4]*5*r64[2];\
    mult[2] = acc64[0]*r64[2] + acc64[1]*r64[1] + acc64[2]*r64[0] + acc64[3]*5*r64[4] + acc64[4]*5*r64[3];\
    mult[3] = acc64[0]*r64[3] + acc64[1]*r64[2] + acc64[2]*r64[1] + acc64[3]*r64[0] + acc64[4]*5*r64[4];\
    mult[4] = acc64[0]*r64[4] + acc64[1]*r64[3] + acc64[2]*r64[2] + acc64[3]*r64[1] + acc64[4]*r64[0];\
}while(0)

#define CARRY_PROPAGATION(carry,mult,acc) do{ \
    for(int j = 0; j < 4; j++){\
        carry = (mult[j]) >> 26;\
        acc[j] = (uint32_t)(mult[j]&mask_lowest_26bits);\
        mult[j +1] += carry;\
    }\
    carry = mult[4] >> 26; \
    (acc[4]) = (uint32_t)((mult[4]) & mask_lowest_26bits);\
    \
    (acc[0]) += (uint32_t)(carry *5);\
    carry =(acc[0]) >> 26;\
    (acc[0]) &= mask_lowest_26bits;\
    (acc[1]) += (uint32_t)carry;\
}while(0)

#define COMPUTE_MOD_P(carry,acc,g) do{\
    carry = (uint64_t)acc[0] + 5; \
    for (int j = 0; j < 4; j++){\
        g[j] = (uint32_t)(carry & mask_lowest_26bits);\
        carry >>= 26;\
        carry += (uint64_t)acc[j+1];\
    }\
    \
    g[4] = (uint32_t)(carry & mask_lowest_26bits);\
    carry >>= 26;\
}while(0)

#define ADD_55(carry, a, b) do{ \
    for (int j = 0; j < 5; j++){    \
        carry = (uint64_t)a[j] + b[j] + carry;   \
        a[j] = (uint32_t)(carry &mask_lowest_26bits);   \
        carry >>= 26;     \
    }    \
    \
    a[0] += (uint32_t)(carry * 5);   \
}while(0)

#define DOUBLE_MULTIPLICATION_ADDITION(mult, a, _r8, _n0, _r4, n_00) do { \
    (mult)[0] = (((a)[0])*((_r8)[0]) + ((a)[1])*5*((_r8)[4]) + ((a)[2])*5*((_r8)[3]) + ((a)[3])*5*((_r8)[2]) + ((a)[4])*5*((_r8)[1])) + \
                (((_n0)[0])*((_r4)[0]) + ((_n0)[1])*5*((_r4)[4]) + ((_n0)[2])*5*((_r4)[3]) + ((_n0)[3])*5*((_r4)[2]) + ((_n0)[4])*5*((_r4)[1])); \
                                                                                                                                           \
    (mult)[1] = (((a)[0])*((_r8)[1]) + ((a)[1])*((_r8)[0]) + ((a)[2])*5*((_r8)[4]) + ((a)[3])*5*((_r8)[3]) + ((a)[4])*5*((_r8)[2])) + \
                (((_n0)[0])*((_r4)[1]) + ((_n0)[1])*((_r4)[0]) + ((_n0)[2])*5*((_r4)[4]) + ((_n0)[3])*5*((_r4)[3]) + ((_n0)[4])*5*((_r4)[2])); \
                                                                                                                                           \
    (mult)[2] = (((a)[0])*((_r8)[2]) + ((a)[1])*((_r8)[1]) + ((a)[2])*((_r8)[0]) + ((a)[3])*5*((_r8)[4]) + ((a)[4])*5*((_r8)[3])) + \
                (((_n0)[0])*((_r4)[2]) + ((_n0)[1])*((_r4)[1]) + ((_n0)[2])*((_r4)[0]) + ((_n0)[3])*5*((_r4)[4]) + ((_n0)[4])*5*((_r4)[3])); \
                                                                                                                                           \
    (mult)[3] = (((a)[0])*((_r8)[3]) + ((a)[1])*((_r8)[2]) + ((a)[2])*((_r8)[1]) + ((a)[3])*((_r8)[0]) + ((a)[4])*5*((_r8)[4])) + \
                (((_n0)[0])*((_r4)[3]) + ((_n0)[1])*((_r4)[2]) + ((_n0)[2])*((_r4)[1]) + ((_n0)[3])*((_r4)[0]) + ((_n0)[4])*5*((_r4)[4])); \
                                                                                                                                           \
    (mult)[4] = (((a)[0])*((_r8)[4]) + ((a)[1])*((_r8)[3]) + ((a)[2])*((_r8)[2]) + ((a)[3])*((_r8)[1]) + ((a)[4])*((_r8)[0])) + \
                (((_n0)[0])*((_r4)[4]) + ((_n0)[1])*((_r4)[3]) + ((_n0)[2])*((_r4)[2]) + ((_n0)[3])*((_r4)[1]) + ((_n0)[4])*((_r4)[0])); \
        \
    mult[0] += n_00[0]; \
    mult[1] += n_00[1]; \
    mult[2] += n_00[2]; \
    mult[3] += n_00[3]; \
    mult[4] += n_00[4]; \
} while(0)

#define DOUBLE_MULTIPLICATION_ADDITION_VECT(mult, a, r8, n, r4, nn, r4_5, r8_5) do { \
    for(int j = 0; j < 5; j++) { \
        /* Correct cyclic index mappings for full Poly1305 convolution */ \
        int i0 = 0, i1 = 1, i2 = 2, i3 = 3, i4 = 4; \
        int j0 = (j - 0 + 5) % 5; \
        int j1 = (j - 1 + 5) % 5; \
        int j2 = (j - 2 + 5) % 5; \
        int j3 = (j - 3 + 5) % 5; \
        int j4 = (j - 4 + 5) % 5; \
        \
        /* If the accumulator index is smaller than the r-constant index, */ \
        /* it implies a wrap-around occurred, demanding the r*_5 variants. */ \
        __m256i term_a0 = _mm256_mul_epu32(a[j0], r8[i0]); \
        __m256i term_a1 = (j < 1) ? _mm256_mul_epu32(a[j1], r8_5[i1]) : _mm256_mul_epu32(a[j1], r8[i1]); \
        __m256i term_a2 = (j < 2) ? _mm256_mul_epu32(a[j2], r8_5[i2]) : _mm256_mul_epu32(a[j2], r8[i2]); \
        __m256i term_a3 = (j < 3) ? _mm256_mul_epu32(a[j3], r8_5[i3]) : _mm256_mul_epu32(a[j3], r8[i3]); \
        __m256i term_a4 = (j < 4) ? _mm256_mul_epu32(a[j4], r8_5[i4]) : _mm256_mul_epu32(a[j4], r8[i4]); \
        \
        __m256i term_n0 = _mm256_mul_epu32(n[j0], r4[i0]); \
        __m256i term_n1 = (j < 1) ? _mm256_mul_epu32(n[j1], r4_5[i1]) : _mm256_mul_epu32(n[j1], r4[i1]); \
        __m256i term_n2 = (j < 2) ? _mm256_mul_epu32(n[j2], r4_5[i2]) : _mm256_mul_epu32(n[j2], r4[i2]); \
        __m256i term_n3 = (j < 3) ? _mm256_mul_epu32(n[j3], r4_5[i3]) : _mm256_mul_epu32(n[j3], r4[i3]); \
        __m256i term_n4 = (j < 4) ? _mm256_mul_epu32(n[j4], r4_5[i4]) : _mm256_mul_epu32(n[j4], r4[i4]); \
        \
        mult[j] = _mm256_add_epi64(term_a0, _mm256_add_epi64(term_a1, _mm256_add_epi64(term_a2, _mm256_add_epi64(term_a3, term_a4)))); \
        __m256i mult_n = _mm256_add_epi64(term_n0, _mm256_add_epi64(term_n1, _mm256_add_epi64(term_n2, _mm256_add_epi64(term_n3, term_n4)))); \
        mult[j] = _mm256_add_epi64(mult[j], _mm256_add_epi64(mult_n, nn[j])); \
    } \
} while(0)

#define CARRY_PROP_DELAYED(carry, mult, acc) do{ \
    for(int j = 0; j < 4; j++){   \
        carry = mult[j] >> 26;    \
        acc[j] = (uint32_t)(mult[j] & mask_lowest_26bits);  \
        mult[j + 1] += carry;  \
    }\
    \
    carry = mult[4] >> 26;   \
    acc[4] = (uint32_t)(mult[4] & mask_lowest_26bits);  \
    \
    acc[0] += (uint32_t)(carry * 5);  \
    carry = acc[0] >> 26;   \
    acc[0] &= mask_lowest_26bits;   \
    acc[1] += (uint32_t)carry;  \
}while(0)

#define CARRY_PROP_DELAYED_VECT(carry, mult, acc) do{ \
    __m256i v_mask_26 = _mm256_set1_epi64x(0x3FFFFFF); \
    for(int j = 0; j < 4; j++){   \
        carry = _mm256_srli_epi64(mult[j], 26);   \
        acc[j] = _mm256_and_si256(mult[j], v_mask_26);  \
        mult[j + 1] = _mm256_add_epi64(mult[j+1] , carry); \
    }\
    \
    carry = _mm256_srli_epi64(mult[4], 26);   \
    acc[4] = _mm256_and_si256(mult[4], v_mask_26);  \
    \
    __m256i five = _mm256_set1_epi64x(5); \
    __m256i carry5 = _mm256_mul_epu32(five, carry); \
    acc[0] = _mm256_add_epi64(acc[0], carry5);  \
    carry = _mm256_srli_epi64(acc[0], 26);   \
    acc[0] = _mm256_and_si256(acc[0], v_mask_26);  \
    acc[1] = _mm256_add_epi64(acc[1], carry);  \
}while(0)

#define MOD_P_DELAYED(carry,g,acc) do{ \
    carry = (uint64_t)acc[0] + 5;   \
    for (int j = 0; j < 4; j++){    \
        g[j] = (uint32_t)(carry & mask_lowest_26bits);  \
        carry >>= 26;    \
        carry += (uint64_t)acc[j+1];   \
    }\
    g[4] = (uint32_t)(carry & mask_lowest_26bits); \
    carry >>= 26; \
    \
    /*if (carry > 0) { */\
        /*memcpy(acc, g, 5 * sizeof(uint32_t));*/\
    /*}*/\
}while(0)

#define MOD_P_DELAYED_VECT(carry,g,acc) do{ \
    __m256i five = _mm256_set1_epi64x(5); \
    __m256i v_mask_26 = _mm256_set1_epi64x(0x3FFFFFF); \
    carry = _mm256_add_epi64(acc[0], five);   \
    for (int j = 0; j < 4; j++){    \
        g[j] = _mm256_and_si256(carry , v_mask_26);  \
        carry = _mm256_srli_epi64(carry, 26);    \
        carry = _mm256_add_epi64(carry, acc[j+1]);   \
    }\
    g[4] = _mm256_and_si256(carry , v_mask_26); \
    carry = _mm256_srli_epi64(carry, 26);     \
    \
}while(0)

/*
// handle conversions from bytes to 5x26-bit representationfor length 16 and 17 
void to_large_num_rep(uint32_t out[5], const unsigned char *bytes, uint64_t len_bytes){
    uint64_t t[5] = {0}; // initialize with zeros
    // convert the 16 bytes into the 5*64-bit integer representation (LE format)
    for (uint64_t i = 0; i < len_bytes; i++){
        t[i/4] |= ((uint64_t)bytes[i] << ((i%4)*8)); 
    }

    out[0] = (uint32_t)(t[0]) & mask_lowest_26bits; // get lowest 26 bits
    // (t[0] >> 26) only contains 6 non-zero bits (discarded the lowest 26 we saved before), 
    // thus shift t[1] by 6 bits, add them together 
    // and keep only lowest 26
    int left_shift = 6;
    int right_shift = 26;
    for(int i = 0; i < 4; i++){
        out[i+1] = (uint32_t)((t[i] >> right_shift) | (t[i+1] << left_shift)) & mask_lowest_26bits; // get next 26 bits

        left_shift += 6;
        right_shift -= 6;
    }
}
*/

//rewritten because the previous one created overflows
void to_large_num_rep(uint32_t out[5], const unsigned char *bytes, uint64_t len_bytes) {
    // 1. Safely load the 17 bytes into 3 uint64_t registers
    // bytes[0..7], bytes[8..15], and bytes[16] (the 0x01 marker)
    uint64_t low  = *(const uint64_t*)&bytes[0];
    uint64_t high = *(const uint64_t*)&bytes[8];
    uint64_t last = bytes[16]; // This is your 0x01 marker

    // 2. Carve out exactly 26 bits at a time using explicit mask/shifts
    out[0] = (uint32_t)(low) & 0x3FFFFFF;
    out[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;
    
    // Limb 2 spans across the 'low' and 'high' registers
    out[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
    
    out[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;
    
    // Limb 4 spans across the 'high' register and the 'last' byte
    out[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;
}

// handles conversion from 4x32-bit representation to 16 bytes in LE format
void to_16_le_bytes(uint32_t in[4], unsigned char out[16]){
    for (int i = 0; i < 4; i++){
        out[i*4] = (unsigned char)(in[i] & 0xff); // extract lowest 8 bits (least significant byte)
        out[i*4 + 1] = (unsigned char)((in[i] >> 8) & 0xff); // shift by 8 and extract next 8 bits
        out[i*4 + 2] = (unsigned char)((in[i]>> 16) & 0xff); // etc.
        out[i*4+ 3] = (unsigned char)((in[i] >> 24) & 0xff);
    }
}

// computes a = a + b (a and b need be in 5x26-bit representation)
static void add_large_nums_55(uint32_t a[5], const uint32_t b[5]){
    uint64_t carry = 0; // keeps track how much we exceeded 26 bits in each addition = carry
    // make the additions and keep track of carry
    for (int i = 0; i < 5; i++){
        carry = (uint64_t)a[i] + b[i] + carry; // add carry here as well
        a[i] = (uint32_t)(carry &mask_lowest_26bits); // keep lowest 26 bits
        carry >>= 26; // shift right by 26 bits (keep carry for next iteration)
    }

    // if carry is non-zero, we surpassed 2^130 -> need to compute mod (2^130 - 5) (specified by poly algorithm)
    a[0] += (uint32_t)(carry * 5);
}

// computes acc = acc * r mod p (where acc and r in 5x26 bit representation, p = 2^130 - 5)
static void mulmod_p(uint32_t acc[5], const uint32_t r[5]) {
    uint64_t acc64[5], r64[5], mult[5];
    for (int i = 0; i < 5; i++) {
        acc64[i] = (uint64_t)acc[i];
        r64[i] = (uint64_t )r[i];
    }

    // compute acc*r - if exceed 2^130 (= if indices i + j = 5), multiply by 5
    mult[0] = acc64[0]*r64[0] + acc64[1]*5*r64[4] + acc64[2]*5*r64[3] + 5*acc64[3]*r64[2] + 5*acc64[4]*r64[1];
    mult[1] = acc64[0]*r64[1] + acc64[1]*r64[0] + acc64[2]*5*r64[4] + acc64[3]*5*r64[3] + acc64[4]*5*r64[2];
    mult[2] = acc64[0]*r64[2] + acc64[1]*r64[1] + acc64[2]*r64[0] + acc64[3]*5*r64[4] + acc64[4]*5*r64[3];
    mult[3] = acc64[0]*r64[3] + acc64[1]*r64[2] + acc64[2]*r64[1] + acc64[3]*r64[0] + acc64[4]*5*r64[4];
    mult[4] = acc64[0]*r64[4] + acc64[1]*r64[3] + acc64[2]*r64[2] + acc64[3]*r64[1] + acc64[4]*r64[0];

    // distirbute the "overflow" of each mult[i] to the next one
    uint64_t carry;
    // extract carry (how much exceeded over 26 bits) and add to next one mult[1], keep only lowest 26 bits in acc[0]
    for(int i = 0; i < 4; i++){
        carry = mult[i] >> 26;
        acc[i] = (uint32_t)(mult[i]&mask_lowest_26bits);
        mult[i +1] += carry;
    }

    carry = mult[4] >> 26; // extract any overflow from last 26 bits in mult array
    acc[4] = (uint32_t)(mult[4] & mask_lowest_26bits); // write lowest 26 bits of mult[4] into acc[4]
    
    // if we surpass 2^130 (i.e. carry != 0), compute modulo (2^130 - 5) -> multply carry by 5 and add to acc[0]
    acc[0] += (uint32_t)(carry *5);
    carry = acc[0] >> 26; // check whether now acc[0] exceeds 26 bits, if so carry to acc[1] etc.
    acc[0] &= mask_lowest_26bits;
    acc[1] += (uint32_t)carry;


    // now check whether carry from mult caused acc array to represent number larger than p (=2^130 - 5) 
    // (can happen even if never exceed 26 bits) - if so, compute modulo p again
    uint32_t g[5];

    carry = (uint64_t)acc[0] + 5; // add 5 to acc, so if we surpass p, we will have 27 bits in last carry
    for (int i = 0; i < 4; i++){
        g[i] = (uint32_t)(carry & mask_lowest_26bits);
        carry >>= 26;
        carry += (uint64_t)acc[i+1];
    }
    
    g[4] = (uint32_t)(carry & mask_lowest_26bits);
    carry >>= 26;
     // if last carry is > 0, set acc to g (which is normalized)
    if (carry > 0) {
        memcpy(acc, g, 5 * sizeof(uint32_t));
    }
}


/*
// same as add_large_nums_55 but takes 4x32-bit and 5x26-bit and outputs 4x32-bit representation of their sum (acc = acc + s)
static void add_large_nums_54(uint32_t out[4], const uint32_t acc[5], const uint32_t s[4]) {
    uint32_t h[5];
    uint64_t carry;

    // write acc into h
    memcpy(h, acc, 5 * sizeof(uint32_t));

    // want final output in 4x32-bit, so need to shift 5x26 bits from h accordingly -> repack into 4x32 convert array
    uint64_t convert[4];
    int left_shift = 26;
    int right_shift = 0;
    for(unsigned int i = 0; i < 4; i++){
        convert[i] = ((uint64_t) h[i] >> right_shift) | ((uint64_t)h[i+1] << left_shift);
        left_shift -= 6;
        right_shift += 6;
    }
    
    // add s and convert  to carry, store carry in out[i], shift by 32 if overflow
    carry = 0;
    for(unsigned int i = 0; i < 4; i++){
        carry += (convert[i] & mask_lowest_32bits) + s[i]; // add s[i] and carry from previous addition
        out[i] = (uint32_t) carry; // cast drops overflow
        carry >>= 32; // extract carry for next iteration
    }
}

*/

static inline void add_large_nums_54(uint32_t out[4], const uint32_t acc[5], const uint32_t s[4]) {
    uint64_t convert[4];

    // 1. Unpack 5x26-bit limbs directly into 4x32-bit spaces explicitly
    convert[0] = (uint64_t)acc[0]        | ((uint64_t)acc[1] << 26);
    convert[1] = (uint64_t)(acc[1] >> 6)  | ((uint64_t)acc[2] << 20);
    convert[2] = (uint64_t)(acc[2] >> 12) | ((uint64_t)acc[3] << 14);
    convert[3] = (uint64_t)(acc[3] >> 18) | ((uint64_t)acc[4] << 8);

    // 2. Perform safe 32-bit additions with carry propagation
    uint64_t carry = 0;
    for(unsigned int i = 0; i < 4; i++){
        // convert[i] is masked automatically to 32-bits by casting to uint32_t
        carry += (uint32_t)convert[i] + (uint64_t)s[i]; 
        out[i] = (uint32_t)carry; 
        carry >>= 32; 
    }
}

// calculate authentication tag for data
unsigned char* create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + 15) / 16;
    for(uint64_t i = 0; i < num_blocks; i++){
        uint64_t offset = i*16;
        uint64_t block_len = (data_len - offset) < 16 ? (data_len - offset) : 16;
        unsigned char block[block_len + 1];
        memset(block, 0, block_len + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        uint32_t n[5];
        to_large_num_rep(n, block, block_len + 1); // convert representation of n to fit acc and r
        add_large_nums_55(acc, n); // acc += n 
        mulmod_p(acc, r); // acc = (acc * r) mod p
    }
    uint32_t addition[4];
    add_large_nums_54(addition, acc, s); // add 5x32 bit repr. acc and 4x32 bit repr. s together, output is 4x32 bit representation
    unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
    to_16_le_bytes(addition, tag); // convert addition (4x32-bit representation) to 16 bytes (LE format)
    return tag;
}


static void process_lane_8blocks_unified(uint32_t acc_0[5], const uint32_t r8[5], const uint32_t n_0[5], const uint32_t r4[5], const uint32_t n_00[5]) {
    uint64_t mult[5];
    
    uint64_t a[5]   = {acc_0[0], acc_0[1], acc_0[2], acc_0[3], acc_0[4]};
    uint64_t _r8[5] = {r8[0],    r8[1],    r8[2],    r8[3],    r8[4]};
    uint64_t _n0[5] = {n_0[0],   n_0[1],   n_0[2],   n_0[3],   n_0[4]};
    uint64_t _r4[5] = {r4[0],    r4[1],    r4[2],    r4[3],    r4[4]};


    mult[0] = (a[0]*_r8[0] + a[1]*5*_r8[4] + a[2]*5*_r8[3] + a[3]*5*_r8[2] + a[4]*5*_r8[1]) +
              (_n0[0]*_r4[0] + _n0[1]*5*_r4[4] + _n0[2]*5*_r4[3] + _n0[3]*5*_r4[2] + _n0[4]*5*_r4[1]);

    mult[1] = (a[0]*_r8[1] + a[1]*_r8[0] + a[2]*5*_r8[4] + a[3]*5*_r8[3] + a[4]*5*_r8[2]) +
              (_n0[0]*_r4[1] + _n0[1]*_r4[0] + _n0[2]*5*_r4[4] + _n0[3]*5*_r4[3] + _n0[4]*5*_r4[2]);

    mult[2] = (a[0]*_r8[2] + a[1]*_r8[1] + a[2]*_r8[0] + a[3]*5*_r8[4] + a[4]*5*_r8[3]) +
              (_n0[0]*_r4[2] + _n0[1]*_r4[1] + _n0[2]*_r4[0] + _n0[3]*5*_r4[4] + _n0[4]*5*_r4[3]);

    mult[3] = (a[0]*_r8[3] + a[1]*_r8[2] + a[2]*_r8[1] + a[3]*_r8[0] + a[4]*5*_r8[4]) +
              (_n0[0]*_r4[3] + _n0[1]*_r4[2] + _n0[2]*_r4[1] + _n0[3]*_r4[0] + _n0[4]*5*_r4[4]);

    mult[4] = (a[0]*_r8[4] + a[1]*_r8[3] + a[2]*_r8[2] + a[3]*_r8[1] + a[4]*_r8[0]) +
              (_n0[0]*_r4[4] + _n0[1]*_r4[3] + _n0[2]*_r4[2] + _n0[3]*_r4[1] + _n0[4]*_r4[0]);


    mult[0] += n_00[0];
    mult[1] += n_00[1];
    mult[2] += n_00[2];
    mult[3] += n_00[3];
    mult[4] += n_00[4];

    uint64_t carry;
    for(int i = 0; i < 4; i++){
        carry = mult[i] >> 26;
        acc_0[i] = (uint32_t)(mult[i] & mask_lowest_26bits);
        mult[i + 1] += carry;
    }

    carry = mult[4] >> 26;
    acc_0[4] = (uint32_t)(mult[4] & mask_lowest_26bits);


    acc_0[0] += (uint32_t)(carry * 5);
    carry = acc_0[0] >> 26;
    acc_0[0] &= mask_lowest_26bits;
    acc_0[1] += (uint32_t)carry;

    uint32_t g[5];
    carry = (uint64_t)acc_0[0] + 5;
    for (int i = 0; i < 4; i++){
        g[i] = (uint32_t)(carry & mask_lowest_26bits);
        carry >>= 26;
        carry += (uint64_t)acc_0[i+1];
    }
    g[4] = (uint32_t)(carry & mask_lowest_26bits);
    carry >>= 26;

    if (carry > 0) {
        memcpy(acc_0, g, 5 * sizeof(uint32_t));
    }
}

unsigned char* inlined_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    //precomputing key r per 5 and saving in cache
    uint64_t r0 = (uint64_t)r[0], r1 = (uint64_t)r[1], r2 = (uint64_t)r[2], r3 = (uint64_t)r[3], r4 = (uint64_t)r[4];
    uint64_t r0_5 = r0*5, r1_5 = r1*5, r2_5 = r2*5, r3_5 = r3*5, r4_5 = r4*5;

    uint64_t num_blocks = (data_len) / 16;
    uint64_t remainder = data_len % 16;

    const uint8_t* curr_data = data;
    uint8_t block[17];

    for(uint64_t i = 0; i < num_blocks; i++){

        uint64_t low = *(uint64_t*)(curr_data);
        uint64_t high = *(uint64_t*)(curr_data + 8);

        uint32_t n[5];
        n[0] = (uint32_t)low & 0x3FFFFFF;
        n[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;
        n[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        n[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;
        n[4] = (uint32_t)(high >> 40) | (1 << 24);

        for (int i = 0; i < 5; i++) acc[i] += n[i];



        uint64_t mult[5];

        mult[0] = (uint64_t)acc[0]*r0 + (uint64_t)acc[1]*r4_5 + (uint64_t)acc[2]*r3_5 + (uint64_t)acc[3]*r2_5 + (uint64_t)acc[4]*r1_5;
        mult[1] = (uint64_t)acc[0]*r1 + (uint64_t)acc[1]*r0   + (uint64_t)acc[2]*r4_5 + (uint64_t)acc[3]*r3_5 + (uint64_t)acc[4]*r2_5;
        mult[2] = (uint64_t)acc[0]*r2 + (uint64_t)acc[1]*r1   + (uint64_t)acc[2]*r0   + (uint64_t)acc[3]*r4_5 + (uint64_t)acc[4]*r3_5;
        mult[3] = (uint64_t)acc[0]*r3 + (uint64_t)acc[1]*r2   + (uint64_t)acc[2]*r1   + (uint64_t)acc[3]*r0   + (uint64_t)acc[4]*r4_5;
        mult[4] = (uint64_t)acc[0]*r4 + (uint64_t)acc[1]*r3   + (uint64_t)acc[2]*r2   + (uint64_t)acc[3]*r1   + (uint64_t)acc[4]*r0;

        uint64_t carry = 0;
        for(int i = 0; i < 4; i++){
            carry = mult[i] >> 26;
            acc[i] = (uint32_t)(mult[i]&mask_lowest_26bits);
            mult[i +1] += carry;
        }

        carry = mult[4] >> 26; 
        acc[4] = (uint32_t)(mult[4] & mask_lowest_26bits); 

        acc[0] += (uint32_t)(carry *5);
        carry = acc[0] >> 26; 
        acc[0] &= mask_lowest_26bits;
        acc[1] += (uint32_t)carry;

        curr_data += 16;
    }

    if(remainder > 0){
        memset(block, 0, 17);
        memcpy(block, curr_data, remainder);
        block[remainder] = 0x01;
        uint32_t n[5];
        to_large_num_rep(n, block, remainder + 1);
        add_large_nums_55(acc, n);
        mulmod_p(acc, r);
    }


    uint32_t g[5];

    uint64_t carry = 5;
    for (int i = 0; i < 5; i++){
        carry += (uint64_t)acc[0];
        g[i] = (uint32_t)(carry & mask_lowest_26bits);
        carry >>= 26;

    }
    
    // if last carry is > 0, set acc to g (which is normalized)
    if (carry > 0) {
        memcpy(acc, g, 5 * sizeof(uint32_t));
    }

    uint32_t addition[4];
    // add 5x32 bit repr. acc and 4x32 bit repr. s together, output is 4x32 bit representation
    uint32_t h[5];

    // write acc into h
    memcpy(h, acc, 5 * sizeof(uint32_t));

    // want final output in 4x32-bit, so need to shift 5x26 bits from h accordingly -> repack into 4x32 convert array
    uint64_t convert[4];
    int left_shift = 26;
    int right_shift = 0;
    for(unsigned int i = 0; i < 4; i++){
        convert[i] = ((uint64_t) h[i] >> right_shift) | ((uint64_t)h[i+1] << left_shift);
        left_shift -= 6;
        right_shift += 6;
    }
    
    // add s and convert  to carry, store carry in out[i], shift by 32 if overflow
    carry = 0;
    for(unsigned int i = 0; i < 4; i++){
        carry += (convert[i] & mask_lowest_32bits) + s[i]; // add s[i] and carry from previous addition
        addition[i] = (uint32_t) carry; // cast drops overflow
        carry >>= 32; // extract carry for next iteration
    }
    unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
    // convert addition (4x32-bit representation) to 16 bytes (LE format)
    for (int i = 0; i < 4; i++){
        tag[i*4] = (unsigned char)(addition[i] & 0xff); // extract lowest 8 bits (least significant byte)
        tag[i*4 + 1] = (unsigned char)((addition[i] >> 8) & 0xff); // shift by 8 and extract next 8 bits
        tag[i*4 + 2] = (unsigned char)((addition[i]>> 16) & 0xff); // etc.
        tag[i*4+ 3] = (unsigned char)((addition[i] >> 24) & 0xff);
    }
    
    return tag;
}


unsigned char* not_inlined_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
// 1. Process only the blocks that are GUARANTEED to be 16 bytes
    uint64_t full_blocks = (data_len) / 16;
    uint64_t remainder = data_len % 16;

    const uint8_t* curr_data = data;
    uint8_t block[17];

for(uint64_t i = 0; i < full_blocks; i++) {
    memcpy(block, curr_data, 16); 
    block[16] = 0x01;
    uint32_t n[5];
    to_large_num_rep(n, block, 17);
    add_large_nums_55(acc, n);
    mulmod_p(acc, r);

    curr_data += 16;
}

if(remainder > 0) {
    memset(block, 0, 17);
    memcpy(block, curr_data, remainder);
    block[remainder] = 0x01;
    uint32_t n[5];
    to_large_num_rep(n, block, remainder + 1);
    add_large_nums_55(acc, n);
    mulmod_p(acc, r);
}
    uint32_t addition[4];
    add_large_nums_54(addition, acc, s); // add 5x32 bit repr. acc and 4x32 bit repr. s together, output is 4x32 bit representation
    unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
    to_16_le_bytes(addition, tag); // convert addition (4x32-bit representation) to 16 bytes (LE format)
    return tag;
}

unsigned char* not_inlined_parallel_Horner_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
// 1. Process only the blocks that are GUARANTEED to be 16 bytes
    uint64_t full_blocks = (data_len) / 16;
    uint64_t parallel_calculations = full_blocks / PARALLEL_BLOCKS;
    uint64_t remainder = data_len % 16;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t r4_1[NUM_LIMBS];
    uint32_t r4_2[NUM_LIMBS];
    uint32_t r4_3[NUM_LIMBS];
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r2, r); // r2 = r * r mod p

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r3, r); // r3 = r^2 * r mod p

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r4, r); // r4 = r^3 * r mod p

    memcpy(r4_1, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_2, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_3, r4,  NUM_LIMBS * sizeof(uint32_t));

    uint32_t acc_0[5];
    uint32_t acc_1[5];
    uint32_t acc_2[5];
    uint32_t acc_3[5];

    memset(acc_0, 0, sizeof(acc_0));
    memset(acc_1, 0, sizeof(acc_1));
    memset(acc_2, 0, sizeof(acc_2));
    memset(acc_3, 0, sizeof(acc_3));

    const uint8_t* curr_data = data;
    uint8_t block_0[17];
    uint8_t block_1[17];
    uint8_t block_2[17];
    uint8_t block_3[17];

for(int i = 0; i < parallel_calculations; i++) {

    memcpy(block_0, curr_data, 16); 
    memcpy(block_1, curr_data+16, 16); 
    memcpy(block_2, curr_data+32, 16); 
    memcpy(block_3, curr_data+48, 16); 

    block_0[16] = 0x01;
    block_1[16] = 0x01;
    block_2[16] = 0x01;
    block_3[16] = 0x01;

    uint32_t n_0[5];
    uint32_t n_1[5];
    uint32_t n_2[5];
    uint32_t n_3[5];
    to_large_num_rep(n_0, block_0, 17);
    to_large_num_rep(n_1, block_1, 17);
    to_large_num_rep(n_2, block_2, 17);
    to_large_num_rep(n_3, block_3, 17);

    mulmod_p(acc_0, r4);
    mulmod_p(acc_1, r4_1);
    mulmod_p(acc_2, r4_2);
    mulmod_p(acc_3, r4_3);

    add_large_nums_55(acc_0, n_0);
    add_large_nums_55(acc_1, n_1);
    add_large_nums_55(acc_2, n_2);
    add_large_nums_55(acc_3, n_3);


    curr_data += 16*PARALLEL_BLOCKS;
}

uint32_t* align_powers[PARALLEL_BLOCKS] = {r4, r3, r2, r};
uint32_t* acc_array[PARALLEL_BLOCKS] = {acc_0, acc_1, acc_2, acc_3};

for(int i=0; i< PARALLEL_BLOCKS; i++){
    mulmod_p(acc_array[i], align_powers[i]);

    add_large_nums_55(acc, acc_array[i]);
}

uint64_t remaining_full = full_blocks % PARALLEL_BLOCKS;
for(int i =0; i<remaining_full; i++){
    memcpy(block_0, curr_data, 16); 

    block_0[16] = 0x01;

    uint32_t n_0[5];

    to_large_num_rep(n_0, block_0, 17);

    add_large_nums_55(acc, n_0); // acc += block

    mulmod_p(acc, r);            // acc = acc * r mod p


    curr_data += 16;
}

if(remainder > 0) {
    memset(block_0, 0, 17);
    memcpy(block_0, curr_data, remainder);
    block_0[remainder] = 0x01;
    uint32_t n[5];
    to_large_num_rep(n, block_0, remainder + 1);
    add_large_nums_55(acc, n);
    mulmod_p(acc, r);
}
    uint32_t addition[4];
    add_large_nums_54(addition, acc, s); // add 5x32 bit repr. acc and 4x32 bit repr. s together, output is 4x32 bit representation
    unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
    to_16_le_bytes(addition, tag); // convert addition (4x32-bit representation) to 16 bytes (LE format)
    return tag;
}

unsigned char* inlined_parallel_Horner_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    uint64_t full_blocks = (data_len) / 16;
    uint64_t parallel_calculations = full_blocks / PARALLEL_BLOCKS;
    uint64_t remainder = data_len % 16;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t r4_1[NUM_LIMBS];
    uint32_t r4_2[NUM_LIMBS];
    uint32_t r4_3[NUM_LIMBS];

    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r2, r); // r2 = r * r mod p
    uint64_t acc64_0[5], r64_0[5], mult_0[5];
    uint64_t carry_0;
    uint64_t g_0[5];

    for (int i = 0; i < 5; i++) {
        acc64_0[i] = (uint64_t) r2[i];
        r64_0[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_0, r64_0, mult_0);

    CARRY_PROPAGATION(carry_0,mult_0, r2);

    COMPUTE_MOD_P(carry_0, r2,g_0);

    if (carry_0 > 0) {
        memcpy( r2, g_0, 5 * sizeof(uint32_t));
    }

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r3, r); // r3 = r^2 * r mod p
        uint64_t acc64_1[5], r64_1[5], mult_1[5];
        uint64_t carry_1;
        uint64_t g_1[5];

        for (int i = 0; i < 5; i++) {
            acc64_1[i] = (uint64_t)r3[i];
            r64_1[i] = (uint64_t )r[i];
        }

        MUL_MOD_P(acc64_1, r64_1, mult_1);

        CARRY_PROPAGATION(carry_1,mult_1,r3);

        COMPUTE_MOD_P(carry_1,r3,g_1);

        if (carry_1 > 0) {
            memcpy(r3, g_1, 5 * sizeof(uint32_t));
        }

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r4, r); // r4 = r^3 * r mod p
    uint64_t acc64_2[5], r64_2[5], mult_2[5];
    uint64_t carry_2;
    uint64_t g_2[5];

    for (int i = 0; i < 5; i++) {
        acc64_2[i] = (uint64_t)r4[i];
        r64_2[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_2, r64_2, mult_2);

    CARRY_PROPAGATION(carry_2,mult_2,r4);

    COMPUTE_MOD_P(carry_2,r4,g_2);

    if (carry_2 > 0) {
        memcpy(r4, g_2, 5 * sizeof(uint32_t));
    }

    memcpy(r4_1, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_2, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_3, r4,  NUM_LIMBS * sizeof(uint32_t));

    uint32_t acc_0[5];
    uint32_t acc_1[5];
    uint32_t acc_2[5];
    uint32_t acc_3[5];

    memset(acc_0, 0, sizeof(acc_0));
    memset(acc_1, 0, sizeof(acc_1));
    memset(acc_2, 0, sizeof(acc_2));
    memset(acc_3, 0, sizeof(acc_3));

    const uint8_t* curr_data = data;
    uint8_t block_0[17];
    uint8_t block_1[17];
    uint8_t block_2[17];
    uint8_t block_3[17];

    for(int i = 0; i < parallel_calculations; i++) {

        memcpy(block_0, curr_data, 16); 
        memcpy(block_1, curr_data+16, 16); 
        memcpy(block_2, curr_data+32, 16); 
        memcpy(block_3, curr_data+48, 16); 

        block_0[16] = 0x01;
        block_1[16] = 0x01;
        block_2[16] = 0x01;
        block_3[16] = 0x01;

        uint32_t n_0[5];
        uint32_t n_1[5];
        uint32_t n_2[5];
        uint32_t n_3[5];
        //to_large_num_rep(n_0, block_0, 17);
        uint64_t low  = *(const uint64_t*)&block_0[0];
        uint64_t high = *(const uint64_t*)&block_0[8];
        uint64_t last = block_0[16];
        n_0[0] = (uint32_t)(low) & 0x3FFFFFF;
        n_0[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;

        n_0[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        
        n_0[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;

        n_0[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_1, block_1, 17);
        uint64_t low_1  = *(const uint64_t*)&block_1[0];
        uint64_t high_1 = *(const uint64_t*)&block_1[8];
        uint64_t last_1 = block_1[16];
        n_1[0] = (uint32_t)(low_1) & 0x3FFFFFF;
        n_1[1] = (uint32_t)(low_1 >> 26) & 0x3FFFFFF;

        n_1[2] = (uint32_t)((low_1 >> 52) | (high_1 << 12)) & 0x3FFFFFF;
        
        n_1[3] = (uint32_t)(high_1 >> 14) & 0x3FFFFFF;

        n_1[4] = (uint32_t)((high_1 >> 40) | (last_1 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_2, block_2, 17);
        uint64_t low_2  = *(const uint64_t*)&block_2[0];
        uint64_t high_2 = *(const uint64_t*)&block_2[8];
        uint64_t last_2 = block_2[16];
        n_2[0] = (uint32_t)(low_2) & 0x3FFFFFF;
        n_2[1] = (uint32_t)(low_2 >> 26) & 0x3FFFFFF;

        n_2[2] = (uint32_t)((low_2 >> 52) | (high_2 << 12)) & 0x3FFFFFF;
        
        n_2[3] = (uint32_t)(high_2 >> 14) & 0x3FFFFFF;

        n_2[4] = (uint32_t)((high_2 >> 40) | (last_2 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_3, block_3, 17);
        uint64_t low_3  = *(const uint64_t*)&block_3[0];
        uint64_t high_3 = *(const uint64_t*)&block_3[8];
        uint64_t last_3 = block_3[16];
        n_3[0] = (uint32_t)(low_3) & 0x3FFFFFF;
        n_3[1] = (uint32_t)(low_3 >> 26) & 0x3FFFFFF;

        n_3[2] = (uint32_t)((low_3 >> 52) | (high_3 << 12)) & 0x3FFFFFF;
        
        n_3[3] = (uint32_t)(high_3 >> 14) & 0x3FFFFFF;

        n_3[4] = (uint32_t)((high_3 >> 40) | (last_3 << 24)) & 0x3FFFFFF;

        //mulmod_p(acc_0, r4);
        uint64_t acc64_0[5], r64_0[5], mult_0[5];
        uint64_t carry_0;
        uint64_t g_0[5];

        for (int i = 0; i < 5; i++) {
            acc64_0[i] = (uint64_t)acc_0[i];
            r64_0[i] = (uint64_t )r4[i];
        }

        MUL_MOD_P(acc64_0, r64_0, mult_0);

        CARRY_PROPAGATION(carry_0,mult_0,acc_0);

        COMPUTE_MOD_P(carry_0,acc_0,g_0);

        if (carry_0 > 0) {
            memcpy(acc_0, g_0, 5 * sizeof(uint32_t));
        }

        //mulmod_p(acc_1, r4_1);
        uint64_t acc64_1[5], r64_1[5], mult_1[5];
        uint64_t carry_1;
        uint64_t g_1[5];

        for (int i = 0; i < 5; i++) {
            acc64_1[i] = (uint64_t)acc_1[i];
            r64_1[i] = (uint64_t )r4_1[i];
        }

        MUL_MOD_P(acc64_1, r64_1, mult_1);

        CARRY_PROPAGATION(carry_1,mult_1,acc_1);

        COMPUTE_MOD_P(carry_1,acc_1,g_1);

        if (carry_1 > 0) {
            memcpy(acc_1, g_1, 5 * sizeof(uint32_t));
        }

        //mulmod_p(acc_2, r4_2);
        uint64_t acc64_2[5], r64_2[5], mult_2[5];
        uint64_t carry_2;
        uint64_t g_2[5];

        for (int i = 0; i < 5; i++) {
            acc64_2[i] = (uint64_t)acc_2[i];
            r64_2[i] = (uint64_t )r4_2[i];
        }

        MUL_MOD_P(acc64_2, r64_2, mult_2);

        CARRY_PROPAGATION(carry_2,mult_2,acc_2);

        COMPUTE_MOD_P(carry_2,acc_2,g_2);

        if (carry_2 > 0) {
            memcpy(acc_2, g_2, 5 * sizeof(uint32_t));
        }

        //mulmod_p(acc_3, r4_3);
        uint64_t acc64_3[5], r64_3[5], mult_3[5];
        uint64_t carry_3;
        uint64_t g_3[5];

        for (int i = 0; i < 5; i++) {
            acc64_3[i] = (uint64_t)acc_3[i];
            r64_3[i] = (uint64_t )r4_3[i];
        }

        MUL_MOD_P(acc64_3, r64_3, mult_3);

        CARRY_PROPAGATION(carry_3,mult_3,acc_3);

        COMPUTE_MOD_P(carry_3,acc_3,g_3);

        if (carry_3 > 0) {
            memcpy(acc_3, g_3, 5 * sizeof(uint32_t));
        }

        //add_large_nums_55(acc_0, n_0);
        carry_0 = 0; 
        ADD_55(carry_0, acc_0, n_0);

        //add_large_nums_55(acc_1, n_1);
        carry_1 = 0; 
        ADD_55(carry_1, acc_1, n_1);
        //add_large_nums_55(acc_2, n_2);
        carry_2 = 0; 
        ADD_55(carry_2, acc_2, n_2);
        //add_large_nums_55(acc_3, n_3);
        carry_3 = 0; 
        ADD_55(carry_3, acc_3, n_3);

        curr_data += 16*PARALLEL_BLOCKS;
    }

    uint32_t* align_powers[PARALLEL_BLOCKS] = {r4, r3, r2, r};
    uint32_t* acc_array[PARALLEL_BLOCKS] = {acc_0, acc_1, acc_2, acc_3};

    for(int i=0; i< PARALLEL_BLOCKS; i++){
        //mulmod_p(acc_array[i], align_powers[i]);
        uint64_t acc64_align[5], r64_align[5], mult_align[5];
        uint64_t carry_align;
        uint64_t g_align[5];

        for (int j = 0; j < 5; j++) {
            acc64_align[j] = (uint64_t)acc_array[i][j];
            r64_align[j] = (uint64_t )align_powers[i][j];
        }

        MUL_MOD_P(acc64_align, r64_align, mult_align);

        CARRY_PROPAGATION(carry_align,mult_align,acc_array[i]);

        COMPUTE_MOD_P(carry_align,acc_array[i],g_align);

        if (carry_align > 0) {
            memcpy(acc_array[i], g_align, 5 * sizeof(uint32_t));
        }

        //add_large_nums_55(acc, acc_array[i]);
        carry_align = 0; 
        ADD_55(carry_align, acc, acc_array[i]);
    }

    uint64_t remaining_full = full_blocks % PARALLEL_BLOCKS;
    for(int i =0; i<remaining_full; i++){
        memcpy(block_0, curr_data, 16); 

        block_0[16] = 0x01;

        uint32_t n_0[5];

        //to_large_num_rep(n_0, block_0, 17);
        uint64_t low  = *(const uint64_t*)&block_0[0];
        uint64_t high = *(const uint64_t*)&block_0[8];
        uint64_t last = block_0[16];
        n_0[0] = (uint32_t)(low) & 0x3FFFFFF;
        n_0[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;

        n_0[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        
        n_0[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;

        n_0[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;

        //add_large_nums_55(acc, n_0); // acc += block
        uint64_t carry_0 = 0; 
        ADD_55(carry_0, acc, n_0);
        //mulmod_p(acc, r);            // acc = acc * r mod p
        uint64_t acc64_0[5], r64_0[5], mult_0[5];
        uint64_t g_0[5];

        for (int j = 0; j < 5; j++) {
            acc64_0[j] = (uint64_t)acc[j];
            r64_0[j] = (uint64_t )r[j];
        }

        MUL_MOD_P(acc64_0, r64_0, mult_0);

        CARRY_PROPAGATION(carry_0,mult_0,acc);

        COMPUTE_MOD_P(carry_0,acc,g_0);

        if (carry_0 > 0) {
            memcpy(acc, g_0, 5 * sizeof(uint32_t));
        }

        curr_data += 16;
    }

    if(remainder > 0) {
        memset(block_0, 0, 17);

        memcpy(block_0, curr_data, remainder);

        block_0[remainder] = 0x01; 

        block_0[16] = 0x00; 

        uint32_t n[5];

        uint64_t low  = *(const uint64_t*)&block_0[0];
        uint64_t high = *(const uint64_t*)&block_0[8];
        uint64_t last = block_0[16];
        
        n[0] = (uint32_t)(low) & 0x3FFFFFF;
        n[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;
        n[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        n[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;
        n[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;

        //add_large_nums_55(acc, n);
        uint64_t carry_0;
        ADD_55(carry_0, acc, n);

        //mulmod_p(acc, r);
        uint64_t acc64_0[5], r64_0[5], mult_0[5];
        
        uint64_t g_0[5];

        for (int i = 0; i < 5; i++) {
            acc64_0[i] = (uint64_t)acc[i];
            r64_0[i] = (uint64_t )r[i];
        }

        MUL_MOD_P(acc64_0, r64_0, mult_0);

        CARRY_PROPAGATION(carry_0,mult_0,acc);

        COMPUTE_MOD_P(carry_0,acc,g_0);

        if (carry_0 > 0) {
            memcpy(acc, g_0, 5 * sizeof(uint32_t));
        }
    }
        uint32_t addition[4];
        //add_large_nums_54(addition, acc, s);
        uint64_t convert[4];

        convert[0] = (uint64_t)acc[0]        | ((uint64_t)acc[1] << 26);
        convert[1] = (uint64_t)(acc[1] >> 6)  | ((uint64_t)acc[2] << 20);
        convert[2] = (uint64_t)(acc[2] >> 12) | ((uint64_t)acc[3] << 14);
        convert[3] = (uint64_t)(acc[3] >> 18) | ((uint64_t)acc[4] << 8);

        uint64_t carry = 0;
        for(unsigned int i = 0; i < 4; i++){
            carry += (uint32_t)convert[i] + (uint64_t)s[i]; 
            addition[i] = (uint32_t)carry; 
            carry >>= 32; 
        }  
        
        unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
        //to_16_le_bytes(addition, tag);
        for (int i = 0; i < 4; i++){
            tag[i*4] = (unsigned char)(addition[i] & 0xff); // extract lowest 8 bits (least significant byte)
            tag[i*4 + 1] = (unsigned char)((addition[i] >> 8) & 0xff);
            tag[i*4 + 2] = (unsigned char)((addition[i]>> 16) & 0xff);
            tag[i*4+ 3] = (unsigned char)((addition[i] >> 24) & 0xff);
        }
        return tag;
}


unsigned char* scalar_rep_inlined_parallel_Horner_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    uint64_t full_blocks = (data_len) / POLY_BLOCK;
    uint64_t paralle_calculations = full_blocks / PARALLEL_BLOCKS;
    uint64_t remainder = data_len % POLY_BLOCK;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t r4_1[NUM_LIMBS];
    uint32_t r4_2[NUM_LIMBS];
    uint32_t r4_3[NUM_LIMBS];
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    // r2 = r * r mod p

    uint64_t acc64_0[5], r64_0[5], mult_0[5];
    for (int i = 0; i < NUM_LIMBS; i++) {
        acc64_0[i] = (uint64_t)r2[i];
        r64_0[i] = (uint64_t )r[i];
    }

    mult_0[0] = acc64_0[0]*r64_0[0] + acc64_0[1]*5*r64_0[4] + acc64_0[2]*5*r64_0[3] + 5*acc64_0[3]*r64_0[2] + 5*acc64_0[4]*r64_0[1];
    mult_0[1] = acc64_0[0]*r64_0[1] + acc64_0[1]*r64_0[0] + acc64_0[2]*5*r64_0[4] + acc64_0[3]*5*r64_0[3] + acc64_0[4]*5*r64_0[2];
    mult_0[2] = acc64_0[0]*r64_0[2] + acc64_0[1]*r64_0[1] + acc64_0[2]*r64_0[0] + acc64_0[3]*5*r64_0[4] + acc64_0[4]*5*r64_0[3];
    mult_0[3] = acc64_0[0]*r64_0[3] + acc64_0[1]*r64_0[2] + acc64_0[2]*r64_0[1] + acc64_0[3]*r64_0[0] + acc64_0[4]*5*r64_0[4];
    mult_0[4] = acc64_0[0]*r64_0[4] + acc64_0[1]*r64_0[3] + acc64_0[2]*r64_0[2] + acc64_0[3]*r64_0[1] + acc64_0[4]*r64_0[0];

    uint64_t carry_0;

    for(int i = 0; i < 4; i++){
        carry_0 = mult_0[i] >> 26;
        r2[i] = (uint32_t)(mult_0[i]&mask_lowest_26bits);
        mult_0[i +1] += carry_0;
    }

    carry_0 = mult_0[4] >> 26;
    r2[4] = (uint32_t)(mult_0[4] & mask_lowest_26bits); 

    r2[0] += (uint32_t)(carry_0 *5);
    carry_0 = r2[0] >> 26; 
    r2[0] &= mask_lowest_26bits;
    r2[1] += (uint32_t)carry_0;

    uint32_t g_0[5];

    carry_0 = (uint64_t)r2[0] + 5;
    for (int i = 0; i < 4; i++){
        g_0[i] = (uint32_t)(carry_0 & mask_lowest_26bits);
        carry_0 >>= 26;
        carry_0 += (uint64_t)r2[i+1];
    }
    
    g_0[4] = (uint32_t)(carry_0 & mask_lowest_26bits);
    carry_0 >>= 26;

    if (carry_0 > 0) {
        memcpy(r2, g_0, 5 * sizeof(uint32_t));
    }

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));


    uint64_t acc64_1[5], r64_1[5], mult_1[5];
    for (int i = 0; i < 5; i++) {
        acc64_1[i] = (uint64_t)r3[i];
        r64_1[i] = (uint64_t )r[i];
    }

    mult_1[0] = acc64_1[0]*r64_1[0] + acc64_1[1]*5*r64_1[4] + acc64_1[2]*5*r64_1[3] + 5*acc64_1[3]*r64_1[2] + 5*acc64_1[4]*r64_1[1];
    mult_1[1] = acc64_1[0]*r64_1[1] + acc64_1[1]*r64_1[0] + acc64_1[2]*5*r64_1[4] + acc64_1[3]*5*r64_1[3] + acc64_1[4]*5*r64_1[2];
    mult_1[2] = acc64_1[0]*r64_1[2] + acc64_1[1]*r64_1[1] + acc64_1[2]*r64_1[0] + acc64_1[3]*5*r64_1[4] + acc64_1[4]*5*r64_1[3];
    mult_1[3] = acc64_1[0]*r64_1[3] + acc64_1[1]*r64_1[2] + acc64_1[2]*r64_1[1] + acc64_1[3]*r64_1[0] + acc64_1[4]*5*r64_1[4];
    mult_1[4] = acc64_1[0]*r64_1[4] + acc64_1[1]*r64_1[3] + acc64_1[2]*r64_1[2] + acc64_1[3]*r64_1[1] + acc64_1[4]*r64_1[0];

    uint64_t carry_1;

    for(int i = 0; i < 4; i++){
        carry_1 = mult_1[i] >> 26;
        r3[i] = (uint32_t)(mult_1[i]&mask_lowest_26bits);
        mult_1[i +1] += carry_1;
    }

    carry_1 = mult_1[4] >> 26; 
    r3[4] = (uint32_t)(mult_1[4] & mask_lowest_26bits); 

    r3[0] += (uint32_t)(carry_1 *5);
    carry_1 = r3[0] >> 26;
    r3[0] &= mask_lowest_26bits;
    r3[1] += (uint32_t)carry_1;

    uint32_t g_1[5];

    carry_1 = (uint64_t)r3[0] + 5; 
    for (int i = 0; i < 4; i++){
        g_1[i] = (uint32_t)(carry_1 & mask_lowest_26bits);
        carry_1 >>= 26;
        carry_1 += (uint64_t)r3[i+1];
    }
    
    g_1[4] = (uint32_t)(carry_1 & mask_lowest_26bits);
    carry_1 >>= 26;

    if (carry_1 > 0) {
        memcpy(r3, g_1, 5 * sizeof(uint32_t));
    }

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    // r4 = r^3 * r mod p

    uint64_t acc64_2[5], r64_2[5], mult_2[5];
    for (int i = 0; i < 5; i++) {
        acc64_2[i] = (uint64_t)r4[i];
        r64_2[i] = (uint64_t )r[i];
    }


    mult_2[0] = acc64_2[0]*r64_2[0] + acc64_2[1]*5*r64_2[4] + acc64_2[2]*5*r64_2[3] + 5*acc64_2[3]*r64_2[2] + 5*acc64_2[4]*r64_2[1];
    mult_2[1] = acc64_2[0]*r64_2[1] + acc64_2[1]*r64_2[0] + acc64_2[2]*5*r64_2[4] + acc64_2[3]*5*r64_2[3] + acc64_2[4]*5*r64_2[2];
    mult_2[2] = acc64_2[0]*r64_2[2] + acc64_2[1]*r64_2[1] + acc64_2[2]*r64_2[0] + acc64_2[3]*5*r64_2[4] + acc64_2[4]*5*r64_2[3];
    mult_2[3] = acc64_2[0]*r64_2[3] + acc64_2[1]*r64_2[2] + acc64_2[2]*r64_2[1] + acc64_2[3]*r64_2[0] + acc64_2[4]*5*r64_2[4];
    mult_2[4] = acc64_2[0]*r64_2[4] + acc64_2[1]*r64_2[3] + acc64_2[2]*r64_2[2] + acc64_2[3]*r64_2[1] + acc64_2[4]*r64_2[0];

    uint64_t carry_2;

    for(int i = 0; i < 4; i++){
        carry_2 = mult_2[i] >> 26;
        r4[i] = (uint32_t)(mult_2[i]&mask_lowest_26bits);
        mult_2[i +1] += carry_2;
    }

    carry_2 = mult_2[4] >> 26;
    r4[4] = (uint32_t)(mult_2[4] & mask_lowest_26bits); 
    
    r4[0] += (uint32_t)(carry_2 *5);
    carry_2 = r4_2[0] >> 26;
    r4_2[0] &= mask_lowest_26bits;
    r4_2[1] += (uint32_t)carry_2;

    uint32_t g_2[5];

    carry_2 = (uint64_t)r4[0] + 5;
    for (int i = 0; i < 4; i++){
        g_2[i] = (uint32_t)(carry_2 & mask_lowest_26bits);
        carry_2 >>= 26;
        carry_2 += (uint64_t)r4[i+1];
    }
    
    g_2[4] = (uint32_t)(carry_2 & mask_lowest_26bits);
    carry_2 >>= 26;

    if (carry_2 > 0) {
        memcpy(r4, g_2, 5 * sizeof(uint32_t));
    }

    memcpy(r4_1, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_2, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_3, r4,  NUM_LIMBS * sizeof(uint32_t));

    uint32_t acc_0[5];
    uint32_t acc_1[5];
    uint32_t acc_2[5];
    uint32_t acc_3[5];

    memset(acc_0, 0, sizeof(acc_0));
    memset(acc_1, 0, sizeof(acc_1));
    memset(acc_2, 0, sizeof(acc_2));
    memset(acc_3, 0, sizeof(acc_3));

    const uint8_t* curr_data = data;
    uint8_t block_0[17];
    uint8_t block_1[17];
    uint8_t block_2[17];
    uint8_t block_3[17];

    /*--------------------------SCALAR REPLACEMENT------------------------------------------------*/

    uint64_t r64_3[NUM_LIMBS];
    for (int i = 0; i < 5; i++) {
        r64_0[i] = (uint64_t )r4[i];
        r64_1[i] = (uint64_t )r4_1[i];
        r64_2[i] = (uint64_t )r4_2[i];
        r64_3[i] = (uint64_t )r4_3[i];
    }

/*------------------- STARTING COMPUTATION ON BLOCKS----------------------------*/

for(int i = 0; i < paralle_calculations; i++) {

    memcpy(block_0, curr_data, 16); 
    memcpy(block_1, curr_data+16, 16); 
    memcpy(block_2, curr_data+32, 16); 
    memcpy(block_3, curr_data+48, 16); 

    block_0[16] = 0x01;
    block_1[16] = 0x01;
    block_2[16] = 0x01;
    block_3[16] = 0x01;

    uint32_t n_0[5];
    uint32_t n_1[5];
    uint32_t n_2[5];
    uint32_t n_3[5];

    uint64_t len_bytes = 17;

    uint64_t t_0[5] = {0};
    for (uint64_t i = 0; i < len_bytes; i++){
        t_0[i/4] |= ((uint64_t)block_0[i] << ((i%4)*8)); 
    }

    n_0[0] = (uint32_t)(t_0[0]) & mask_lowest_26bits; 
    int left_shift_0 = 6;
    int right_shift_0 = 26;
    for(int i = 0; i < 4; i++){
        n_0[i+1] = (uint32_t)((t_0[i] >> right_shift_0) | (t_0[i+1] << left_shift_0)) & mask_lowest_26bits; // get next 26 bits

        left_shift_0 += 6;
        right_shift_0 -= 6;
    }   

    uint64_t t_1[5] = {0};
    for (uint64_t i = 0; i < len_bytes; i++){
        t_1[i/4] |= ((uint64_t)block_1[i] << ((i%4)*8)); 
    }

    n_1[0] = (uint32_t)(t_1[0]) & mask_lowest_26bits; 
    int left_shift_1 = 6;
    int right_shift_1 = 26;
    for(int i = 0; i < 4; i++){
        n_1[i+1] = (uint32_t)((t_1[i] >> right_shift_1) | (t_1[i+1] << left_shift_1)) & mask_lowest_26bits; // get next 26 bits

        left_shift_1 += 6;
        right_shift_1 -= 6;
    }   

    uint64_t t_2[5] = {0};
    for (uint64_t i = 0; i < len_bytes; i++){
        t_2[i/4] |= ((uint64_t)block_2[i] << ((i%4)*8)); 
    }

    n_2[0] = (uint32_t)(t_2[0]) & mask_lowest_26bits; 
    int left_shift_2 = 6;
    int right_shift_2 = 26;
    for(int i = 0; i < 4; i++){
        n_2[i+1] = (uint32_t)((t_2[i] >> right_shift_2) | (t_2[i+1] << left_shift_2)) & mask_lowest_26bits; // get next 26 bits

        left_shift_2 += 6;
        right_shift_2 -= 6;
    }   

    uint64_t t_3[5] = {0};
    for (uint64_t i = 0; i < len_bytes; i++){
        t_3[i/4] |= ((uint64_t)block_3[i] << ((i%4)*8)); 
    }

    n_3[0] = (uint32_t)(t_3[0]) & mask_lowest_26bits; 
    int left_shift_3 = 6;
    int right_shift_3 = 26;
    for(int i = 0; i < 4; i++){
        n_3[i+1] = (uint32_t)((t_3[i] >> right_shift_3) | (t_3[i+1] << left_shift_3)) & mask_lowest_26bits; // get next 26 bits

        left_shift_3 += 6;
        right_shift_3 -= 6;
    }   

    /*---------------STARTING MULTIPLICATION------------------------------*/

    uint64_t acc64_0[5], mult_0[5];
    for (int i = 0; i < NUM_LIMBS; i++) {
        acc64_0[i] = (uint64_t)acc_0[i];
    }

    mult_0[0] = acc64_0[0]*r64_0[0] + acc64_0[1]*5*r64_0[4] + acc64_0[2]*5*r64_0[3] + 5*acc64_0[3]*r64_0[2] + 5*acc64_0[4]*r64_0[1];
    mult_0[1] = acc64_0[0]*r64_0[1] + acc64_0[1]*r64_0[0] + acc64_0[2]*5*r64_0[4] + acc64_0[3]*5*r64_0[3] + acc64_0[4]*5*r64_0[2];
    mult_0[2] = acc64_0[0]*r64_0[2] + acc64_0[1]*r64_0[1] + acc64_0[2]*r64_0[0] + acc64_0[3]*5*r64_0[4] + acc64_0[4]*5*r64_0[3];
    mult_0[3] = acc64_0[0]*r64_0[3] + acc64_0[1]*r64_0[2] + acc64_0[2]*r64_0[1] + acc64_0[3]*r64_0[0] + acc64_0[4]*5*r64_0[4];
    mult_0[4] = acc64_0[0]*r64_0[4] + acc64_0[1]*r64_0[3] + acc64_0[2]*r64_0[2] + acc64_0[3]*r64_0[1] + acc64_0[4]*r64_0[0];

    uint64_t carry_0;

    for(int i = 0; i < 4; i++){
        carry_0 = mult_0[i] >> 26;
        acc_0[i] = (uint32_t)(mult_0[i]&mask_lowest_26bits);
        mult_0[i +1] += carry_0;
    }

    carry_0 = mult_0[4] >> 26; 
    acc_0[4] = (uint32_t)(mult_0[4] & mask_lowest_26bits); 

    acc_0[0] += (uint32_t)(carry_0 *5);
    carry_0 = acc_0[0] >> 26;
    acc_0[0] &= mask_lowest_26bits;
    acc_0[1] += (uint32_t)carry_0;


    uint32_t g_0[5];

    carry_0 = (uint64_t)acc_0[0] + 5; 
    for (int i = 0; i < 4; i++){
        g_0[i] = (uint32_t)(carry_0 & mask_lowest_26bits);
        carry_0 >>= 26;
        carry_0 += (uint64_t)acc_0[i+1];
    }
    
    g_0[4] = (uint32_t)(carry_0 & mask_lowest_26bits);
    carry_0 >>= 26;

    if (carry_0 > 0) {
        memcpy(acc_0, g_0, 5 * sizeof(uint32_t));
    }



    uint64_t acc64_1[5], mult_1[5];
    for (int i = 0; i < 5; i++) {
        acc64_1[i] = (uint64_t)acc_1[i];
    }


    mult_1[0] = acc64_1[0]*r64_1[0] + acc64_1[1]*5*r64_1[4] + acc64_1[2]*5*r64_1[3] + 5*acc64_1[3]*r64_1[2] + 5*acc64_1[4]*r64_1[1];
    mult_1[1] = acc64_1[0]*r64_1[1] + acc64_1[1]*r64_1[0] + acc64_1[2]*5*r64_1[4] + acc64_1[3]*5*r64_1[3] + acc64_1[4]*5*r64_1[2];
    mult_1[2] = acc64_1[0]*r64_1[2] + acc64_1[1]*r64_1[1] + acc64_1[2]*r64_1[0] + acc64_1[3]*5*r64_1[4] + acc64_1[4]*5*r64_1[3];
    mult_1[3] = acc64_1[0]*r64_1[3] + acc64_1[1]*r64_1[2] + acc64_1[2]*r64_1[1] + acc64_1[3]*r64_1[0] + acc64_1[4]*5*r64_1[4];
    mult_1[4] = acc64_1[0]*r64_1[4] + acc64_1[1]*r64_1[3] + acc64_1[2]*r64_1[2] + acc64_1[3]*r64_1[1] + acc64_1[4]*r64_1[0];

    uint64_t carry_1;

    for(int i = 0; i < 4; i++){
        carry_1 = mult_1[i] >> 26;
        acc_1[i] = (uint32_t)(mult_1[i]&mask_lowest_26bits);
        mult_1[i +1] += carry_1;
    }

    carry_1 = mult_1[4] >> 26; 
    acc_1[4] = (uint32_t)(mult_1[4] & mask_lowest_26bits); 

    acc_1[0] += (uint32_t)(carry_1 *5);
    carry_1 = acc_1[0] >> 26; 
    acc_1[0] &= mask_lowest_26bits;
    acc_1[1] += (uint32_t)carry_1;

    uint32_t g_1[5];

    carry_1 = (uint64_t)acc_1[0] + 5; 
    for (int i = 0; i < 4; i++){
        g_1[i] = (uint32_t)(carry_1 & mask_lowest_26bits);
        carry_1 >>= 26;
        carry_1 += (uint64_t)acc_1[i+1];
    }
    
    g_1[4] = (uint32_t)(carry_1 & mask_lowest_26bits);
    carry_1 >>= 26;

    if (carry_1 > 0) {
        memcpy(acc_1, g_1, 5 * sizeof(uint32_t));
    }


    uint64_t acc64_2[5], mult_2[5];
    for (int i = 0; i < 5; i++) {
        acc64_2[i] = (uint64_t)acc_2[i];
    }


    mult_2[0] = acc64_2[0]*r64_2[0] + acc64_2[1]*5*r64_2[4] + acc64_2[2]*5*r64_2[3] + 5*acc64_2[3]*r64_2[2] + 5*acc64_2[4]*r64_2[1];
    mult_2[1] = acc64_2[0]*r64_2[1] + acc64_2[1]*r64_2[0] + acc64_2[2]*5*r64_2[4] + acc64_2[3]*5*r64_2[3] + acc64_2[4]*5*r64_2[2];
    mult_2[2] = acc64_2[0]*r64_2[2] + acc64_2[1]*r64_2[1] + acc64_2[2]*r64_2[0] + acc64_2[3]*5*r64_2[4] + acc64_2[4]*5*r64_2[3];
    mult_2[3] = acc64_2[0]*r64_2[3] + acc64_2[1]*r64_2[2] + acc64_2[2]*r64_2[1] + acc64_2[3]*r64_2[0] + acc64_2[4]*5*r64_2[4];
    mult_2[4] = acc64_2[0]*r64_2[4] + acc64_2[1]*r64_2[3] + acc64_2[2]*r64_2[2] + acc64_2[3]*r64_2[1] + acc64_2[4]*r64_2[0];

    uint64_t carry_2;

    for(int i = 0; i < 4; i++){
        carry_2 = mult_2[i] >> 26;
        acc_2[i] = (uint32_t)(mult_2[i]&mask_lowest_26bits);
        mult_2[i +1] += carry_2;
    }

    carry_2 = mult_2[4] >> 26;
    acc_2[4] = (uint32_t)(mult_2[4] & mask_lowest_26bits); 

    acc_2[0] += (uint32_t)(carry_2 *5);
    carry_2 = r4_2[0] >> 26;
    r4_2[0] &= mask_lowest_26bits;
    r4_2[1] += (uint32_t)carry_2;


    uint32_t g_2[5];

    carry_2 = (uint64_t)acc_2[0] + 5; 
    for (int i = 0; i < 4; i++){
        g_2[i] = (uint32_t)(carry_2 & mask_lowest_26bits);
        carry_2 >>= 26;
        carry_2 += (uint64_t)acc_2[i+1];
    }
    
    g_2[4] = (uint32_t)(carry_2 & mask_lowest_26bits);
    carry_2 >>= 26;

    if (carry_2 > 0) {
        memcpy(acc_2, g_2, 5 * sizeof(uint32_t));
    }

    uint64_t acc64_3[5], mult_3[5];
    for (int i = 0; i < 5; i++) {
        acc64_3[i] = (uint64_t)acc_3[i];
    }

    mult_3[0] = acc64_3[0]*r64_3[0] + acc64_3[1]*5*r64_3[4] + acc64_3[2]*5*r64_3[3] + 5*acc64_3[3]*r64_3[2] + 5*acc64_3[4]*r64_3[1];
    mult_3[1] = acc64_3[0]*r64_3[1] + acc64_3[1]*r64_3[0] + acc64_3[2]*5*r64_3[4] + acc64_3[3]*5*r64_3[3] + acc64_3[4]*5*r64_3[2];
    mult_3[2] = acc64_3[0]*r64_3[2] + acc64_3[1]*r64_3[1] + acc64_3[2]*r64_3[0] + acc64_3[3]*5*r64_3[4] + acc64_3[4]*5*r64_3[3];
    mult_3[3] = acc64_3[0]*r64_3[3] + acc64_3[1]*r64_3[2] + acc64_3[2]*r64_3[1] + acc64_3[3]*r64_3[0] + acc64_3[4]*5*r64_3[4];
    mult_3[4] = acc64_3[0]*r64_3[4] + acc64_3[1]*r64_3[3] + acc64_3[2]*r64_3[2] + acc64_3[3]*r64_3[1] + acc64_3[4]*r64_3[0];

    uint64_t carry_3;

    for(int i = 0; i < 4; i++){
        carry_3 = mult_3[i] >> 26;
        acc_3[i] = (uint32_t)(mult_3[i]&mask_lowest_26bits);
        mult_3[i +1] += carry_3;
    }

    carry_3 = mult_3[4] >> 26; 
    acc_3[4] = (uint32_t)(mult_3[4] & mask_lowest_26bits); 

    acc_3[0] += (uint32_t)(carry_3 *5);
    carry_3 = r4_3[0] >> 26; 
    r4_3[0] &= mask_lowest_26bits;
    r4_3[1] += (uint32_t)carry_3;


    uint32_t g_3[5];

    carry_3 = (uint64_t)acc_3[0] + 5; 
    for (int i = 0; i < 4; i++){
        g_3[i] = (uint32_t)(carry_3 & mask_lowest_26bits);
        carry_3 >>= 26;
        carry_3 += (uint64_t)acc_3[i+1];
    }
    
    g_3[4] = (uint32_t)(carry_3 & mask_lowest_26bits);
    carry_3 >>= 26;

    if (carry_3 > 0) {
        memcpy(acc_3, g_3, 5 * sizeof(uint32_t));
    }

    /*--------------------ADDING 55---------------------------------------------*/

    //uint64_t carry_0 = 0;
    for (int i = 0; i < 5; i++){
        carry_0 = (uint64_t)acc_0[i] + n_0[i] + carry_0;
        acc_0[i] = (uint32_t)(carry_0 &mask_lowest_26bits);
        carry_0 >>= 26;
    }

    acc_0[0] += (uint32_t)(carry_0 * 5);

    //uint64_t carry_1 = 0;
    for (int i = 0; i < 5; i++){
        carry_1 = (uint64_t)acc_1[i] + n_1[i] + carry_1;
        acc_1[i] = (uint32_t)(carry_1 &mask_lowest_26bits);
        carry_1 >>= 26;
    }

    acc_1[0] += (uint32_t)(carry_1 * 5);

    //uint64_t carry_2 = 0;
    for (int i = 0; i < 5; i++){
        carry_2 = (uint64_t)acc_2[i] + n_2[i] + carry_2;
        acc_2[i] = (uint32_t)(carry_2 &mask_lowest_26bits);
        carry_2 >>= 26;
    }

    acc_2[0] += (uint32_t)(carry_2 * 5);

    //uint64_t carry_3 = 0;
    for (int i = 0; i < 5; i++){
        carry_3 = (uint64_t)acc_3[i] + n_3[i] + carry_3;
        acc_3[i] = (uint32_t)(carry_3 &mask_lowest_26bits);
        carry_3 >>= 26;
    }

    acc_3[0] += (uint32_t)(carry_3 * 5);

    /*-------------INCREASING POINTER-------------------------------*/

    curr_data += 16*PARALLEL_BLOCKS;
}

uint32_t* align_powers[PARALLEL_BLOCKS] = {r4, r3, r2, r};
uint32_t* acc_array[PARALLEL_BLOCKS] = {acc_0, acc_1, acc_2, acc_3};


/*--------------------   ALIGNING POWERS     ------------------------------------------------------*/
for(int j=0; j< PARALLEL_BLOCKS; j++){

    uint64_t acc64[5], r64[5], mult[5];
    for (int i = 0; i < 5; i++) {
        acc64[i] = (uint64_t)acc_array[j][i];
        r64[i] = (uint64_t )align_powers[j][i];
    }

    mult[0] = acc64[0]*r64[0] + acc64[1]*5*r64[4] + acc64[2]*5*r64[3] + 5*acc64[3]*r64[2] + 5*acc64[4]*r64[1];
    mult[1] = acc64[0]*r64[1] + acc64[1]*r64[0] + acc64[2]*5*r64[4] + acc64[3]*5*r64[3] + acc64[4]*5*r64[2];
    mult[2] = acc64[0]*r64[2] + acc64[1]*r64[1] + acc64[2]*r64[0] + acc64[3]*5*r64[4] + acc64[4]*5*r64[3];
    mult[3] = acc64[0]*r64[3] + acc64[1]*r64[2] + acc64[2]*r64[1] + acc64[3]*r64[0] + acc64[4]*5*r64[4];
    mult[4] = acc64[0]*r64[4] + acc64[1]*r64[3] + acc64[2]*r64[2] + acc64[3]*r64[1] + acc64[4]*r64[0];

    uint64_t carry;

    for(int i = 0; i < 4; i++){
        carry = mult[i] >> 26;
        acc_array[j][i] = (uint32_t)(mult[i]&mask_lowest_26bits);
        mult[i +1] += carry;
    }

    carry = mult[4] >> 26;
    acc_array[j][4] = (uint32_t)(mult[4] & mask_lowest_26bits);
    
    acc_array[j][0] += (uint32_t)(carry *5);
    carry = acc_array[j][0] >> 26; 
    acc_array[j][0] &= mask_lowest_26bits;
    acc_array[j][1] += (uint32_t)carry;

    uint32_t g[5];

    carry = (uint64_t)acc_array[j][0] + 5; 
    for (int i = 0; i < 4; i++){
        g[i] = (uint32_t)(carry & mask_lowest_26bits);
        carry >>= 26;
        carry += (uint64_t)acc_array[j][i+1];
    }
    
    g[4] = (uint32_t)(carry & mask_lowest_26bits);
    carry >>= 26;

    if (carry > 0) {
        memcpy(acc_array[j], g, 5 * sizeof(uint32_t));
    }

    /*--------------------ADDING 55----------------------------------------------*/

    //uint64_t carry = 0;
    for (int i = 0; i < 5; i++){
        carry = (uint64_t)acc[i] + acc_array[j][i] + carry;
        acc[i] = (uint32_t)(carry &mask_lowest_26bits);
        carry >>= 26;
    }

    acc[0] += (uint32_t)(carry * 5);
}

uint64_t remaining_full = full_blocks % PARALLEL_BLOCKS;
for(int i =0; i<remaining_full; i++){
    memcpy(block_0, curr_data, 16); 

    block_0[16] = 0x01;

    uint32_t n_0[5];

    uint64_t len_bytes = 17;

    uint64_t t[5] = {0}; 
    for (uint64_t i = 0; i < len_bytes; i++){
        t[i/4] |= ((uint64_t)block_0[i] << ((i%4)*8)); 
    }

    n_0[0] = (uint32_t)(t[0]) & mask_lowest_26bits;
    int left_shift = 6;
    int right_shift = 26;
    for(int i = 0; i < 4; i++){
        n_0[i+1] = (uint32_t)((t[i] >> right_shift) | (t[i+1] << left_shift)) & mask_lowest_26bits; // get next 26 bits

        left_shift += 6;
        right_shift -= 6;
    }

    /*--------------------ADDING 55------------------------------------------------*/

    // acc += block

    uint64_t carry;

    for (int i = 0; i < 5; i++){
        carry = (uint64_t)acc[i] + n_0[i] + carry;
        acc[i] = (uint32_t)(carry &mask_lowest_26bits);
        carry >>= 26; 
    }

    acc[0] += (uint32_t)(carry * 5);


    /*---------------MULTIPLICATION------------------------------------------------*/
    // acc = acc * r mod p
    uint64_t acc64[5], r64[5], mult[5];
    for (int i = 0; i < 5; i++) {
        acc64[i] = (uint64_t)acc[i];
        r64[i] = (uint64_t )r[i];
    }


    mult[0] = acc64[0]*r64[0] + acc64[1]*5*r64[4] + acc64[2]*5*r64[3] + 5*acc64[3]*r64[2] + 5*acc64[4]*r64[1];
    mult[1] = acc64[0]*r64[1] + acc64[1]*r64[0] + acc64[2]*5*r64[4] + acc64[3]*5*r64[3] + acc64[4]*5*r64[2];
    mult[2] = acc64[0]*r64[2] + acc64[1]*r64[1] + acc64[2]*r64[0] + acc64[3]*5*r64[4] + acc64[4]*5*r64[3];
    mult[3] = acc64[0]*r64[3] + acc64[1]*r64[2] + acc64[2]*r64[1] + acc64[3]*r64[0] + acc64[4]*5*r64[4];
    mult[4] = acc64[0]*r64[4] + acc64[1]*r64[3] + acc64[2]*r64[2] + acc64[3]*r64[1] + acc64[4]*r64[0];

    for(int i = 0; i < 4; i++){
        carry = mult[i] >> 26;
        acc[i] = (uint32_t)(mult[i]&mask_lowest_26bits);
        mult[i +1] += carry;
    }

    carry = mult[4] >> 26; 
    acc[4] = (uint32_t)(mult[4] & mask_lowest_26bits);

    acc[0] += (uint32_t)(carry *5);
    carry = acc[0] >> 26; 
    acc[0] &= mask_lowest_26bits;
    acc[1] += (uint32_t)carry;


    uint32_t g[5];

    carry = (uint64_t)acc[0] + 5; 
    for (int i = 0; i < 4; i++){
        g[i] = (uint32_t)(carry & mask_lowest_26bits);
        carry >>= 26;
        carry += (uint64_t)acc[i+1];
    }
    
    g[4] = (uint32_t)(carry & mask_lowest_26bits);
    carry >>= 26;

    if (carry > 0) {
        memcpy(acc, g, 5 * sizeof(uint32_t));
    }

    curr_data += 16;
}

if(remainder > 0) {
    memset(block_0, 0, 17);
    memcpy(block_0, curr_data, remainder);
    block_0[remainder] = 0x01;
    uint32_t n[5];

    uint64_t len_bytes = remainder+1;
    to_large_num_rep(n, block_0, remainder + 1);

    add_large_nums_55(acc, n);

    uint64_t acc64[5], r64[5], mult[5];
    for (int i = 0; i < 5; i++) {
        acc64[i] = (uint64_t)acc[i];
        r64[i] = (uint64_t )r[i];
    }

    mult[0] = acc64[0]*r64[0] + acc64[1]*5*r64[4] + acc64[2]*5*r64[3] + 5*acc64[3]*r64[2] + 5*acc64[4]*r64[1];
    mult[1] = acc64[0]*r64[1] + acc64[1]*r64[0] + acc64[2]*5*r64[4] + acc64[3]*5*r64[3] + acc64[4]*5*r64[2];
    mult[2] = acc64[0]*r64[2] + acc64[1]*r64[1] + acc64[2]*r64[0] + acc64[3]*5*r64[4] + acc64[4]*5*r64[3];
    mult[3] = acc64[0]*r64[3] + acc64[1]*r64[2] + acc64[2]*r64[1] + acc64[3]*r64[0] + acc64[4]*5*r64[4];
    mult[4] = acc64[0]*r64[4] + acc64[1]*r64[3] + acc64[2]*r64[2] + acc64[3]*r64[1] + acc64[4]*r64[0];

    uint64_t carry;

    for(int i = 0; i < 4; i++){
        carry = mult[i] >> 26;
        acc[i] = (uint32_t)(mult[i]&mask_lowest_26bits);
        mult[i +1] += carry;
    }

    carry = mult[4] >> 26; 
    acc[4] = (uint32_t)(mult[4] & mask_lowest_26bits);

    acc[0] += (uint32_t)(carry *5);
    carry = acc[0] >> 26; 
    acc[0] &= mask_lowest_26bits;
    acc[1] += (uint32_t)carry;


    uint32_t g[5];

    carry = (uint64_t)acc[0] + 5; 
    for (int i = 0; i < 4; i++){
        g[i] = (uint32_t)(carry & mask_lowest_26bits);
        carry >>= 26;
        carry += (uint64_t)acc[i+1];
    }
    
    g[4] = (uint32_t)(carry & mask_lowest_26bits);
    carry >>= 26;

    if (carry > 0) {
        memcpy(acc, g, 5 * sizeof(uint32_t));
    }
}

uint32_t addition[4];

uint32_t h[5];
uint64_t carry;

memcpy(h, acc, 5 * sizeof(uint32_t));

uint64_t convert[4];
int left_shift = 26;
int right_shift = 0;
for(unsigned int i = 0; i < 4; i++){
    convert[i] = ((uint64_t) h[i] >> right_shift) | ((uint64_t)h[i+1] << left_shift);
    left_shift -= 6;
    right_shift += 6;
}

carry = 0;
for(unsigned int i = 0; i < 4; i++){
    carry += (convert[i] & mask_lowest_32bits) + s[i];
    addition[i] = (uint32_t) carry;
    carry >>= 32;
}
unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
to_16_le_bytes(addition, tag);

return tag;
}


unsigned char* carry_delay(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    uint64_t full_blocks = (data_len) / POLY_BLOCK;
    uint64_t paralle_calculations = full_blocks / (PARALLEL_BLOCKS*2);
    uint64_t remainder = data_len % POLY_BLOCK;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t r5[NUM_LIMBS];
    uint32_t r6[NUM_LIMBS];
    uint32_t r7[NUM_LIMBS];
    uint32_t r8[NUM_LIMBS];

    uint32_t r4_1[NUM_LIMBS];
    uint32_t r4_2[NUM_LIMBS];
    uint32_t r4_3[NUM_LIMBS];
    uint32_t r8_1[NUM_LIMBS];
    uint32_t r8_2[NUM_LIMBS];
    uint32_t r8_3[NUM_LIMBS];

    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r2, r); // r2 = r^2 mod p

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r3, r); // r3 = r^3 mod p

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r4, r); // r4 = r^4 mod p
    
    memcpy(r5, r4,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r5, r); // r5 = r^5 mod p

    memcpy(r6, r5,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r6, r); // r6 = r^6 mod p

    memcpy(r7, r6,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r7, r); // r7 = r^7 mod p

    memcpy(r8, r7,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r8, r); // r8 = r^8 mod p

    memcpy(r4_1, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_2, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_3, r4,  NUM_LIMBS * sizeof(uint32_t));

    memcpy(r8_1, r8,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r8_2, r8,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r8_3, r8,  NUM_LIMBS * sizeof(uint32_t));

    uint32_t acc_0[5];
    uint32_t acc_1[5];
    uint32_t acc_2[5];
    uint32_t acc_3[5];

    memset(acc_0, 0, sizeof(acc_0));
    memset(acc_1, 0, sizeof(acc_1));
    memset(acc_2, 0, sizeof(acc_2));
    memset(acc_3, 0, sizeof(acc_3));

    const uint8_t* curr_data = data;
    uint8_t block_0[17];
    uint8_t block_1[17];
    uint8_t block_2[17];
    uint8_t block_3[17];

    uint8_t block_00[17];
    uint8_t block_11[17];
    uint8_t block_22[17];
    uint8_t block_33[17];

/*------------------- STARTING COMPUTATION ON BLOCKS----------------------------*/

    for(int i = 0; i < paralle_calculations; i++) {

        memcpy(block_0, curr_data, 16); 
        memcpy(block_1, curr_data+16, 16); 
        memcpy(block_2, curr_data+32, 16); 
        memcpy(block_3, curr_data+48, 16); 

        memcpy(block_00, curr_data+64, 16); 
        memcpy(block_11, curr_data+80, 16); 
        memcpy(block_22, curr_data+96, 16); 
        memcpy(block_33, curr_data+112, 16); 

        block_0[16] = 0x01;
        block_1[16] = 0x01;
        block_2[16] = 0x01;
        block_3[16] = 0x01;

        block_00[16] = 0x01;
        block_11[16] = 0x01;
        block_22[16] = 0x01;
        block_33[16] = 0x01;

        uint32_t n_0[5];
        uint32_t n_1[5];
        uint32_t n_2[5];
        uint32_t n_3[5];
        uint32_t n_00[5];
        uint32_t n_11[5];
        uint32_t n_22[5];
        uint32_t n_33[5];
        to_large_num_rep(n_0, block_0, 17);
        to_large_num_rep(n_1, block_1, 17);
        to_large_num_rep(n_2, block_2, 17);
        to_large_num_rep(n_3, block_3, 17);
        to_large_num_rep(n_00, block_00, 17);
        to_large_num_rep(n_11, block_11, 17);
        to_large_num_rep(n_22, block_22, 17);
        to_large_num_rep(n_33, block_33, 17);

        /*process_lane_8blocks_unified is performing these:
            mulmod_p(acc_0, r8);
            mulmod_p(n_0, r4);
            add_large_nums_55(acc_0, n_0);
            add_large_nums_55(acc_0, n_00);*/

        process_lane_8blocks_unified(acc_0, r8, n_0, r4, n_00);
        process_lane_8blocks_unified(acc_1, r8_1, n_1, r4_1, n_11);
        process_lane_8blocks_unified(acc_2, r8_2, n_2, r4_2, n_22);
        process_lane_8blocks_unified(acc_3, r8_3, n_3, r4_3, n_33);


        curr_data += 16*PARALLEL_BLOCKS*2;
    }

    uint32_t* align_powers[PARALLEL_BLOCKS] = {r4, r3, r2, r};
    uint32_t* acc_array[PARALLEL_BLOCKS] = {acc_0, acc_1, acc_2, acc_3};

    for(int i=0; i< PARALLEL_BLOCKS; i++){
        mulmod_p(acc_array[i], align_powers[i]);
        add_large_nums_55(acc, acc_array[i]);
    }

    uint64_t remaining_full = full_blocks % (PARALLEL_BLOCKS*2);
    for(int i =0; i<remaining_full; i++){
        memcpy(block_0, curr_data, 16); 
        block_0[16] = 0x01;

        uint32_t n_0[5];
        to_large_num_rep(n_0, block_0, 17);
        add_large_nums_55(acc, n_0); 
        mulmod_p(acc, r);            

        curr_data += 16;
    }

    if(remainder > 0) {
        memset(block_0, 0, 17);
        memcpy(block_0, curr_data, remainder);
        block_0[remainder] = 0x01;
        uint32_t n[5];
        to_large_num_rep(n, block_0, remainder + 1);
        add_large_nums_55(acc, n);
        mulmod_p(acc, r);
    }
    
    uint32_t addition[4];
    add_large_nums_54(addition, acc, s); 
    unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
    to_16_le_bytes(addition, tag); 
    return tag;
}


unsigned char* inlined_carry_delay_parallel_Horner(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    uint64_t full_blocks = (data_len) / POLY_BLOCK;
    uint64_t paralle_calculations = full_blocks / (PARALLEL_BLOCKS*2);
    uint64_t remainder = data_len % POLY_BLOCK;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t r5[NUM_LIMBS];
    uint32_t r6[NUM_LIMBS];
    uint32_t r7[NUM_LIMBS];
    uint32_t r8[NUM_LIMBS];

    uint32_t r4_1[NUM_LIMBS];
    uint32_t r4_2[NUM_LIMBS];
    uint32_t r4_3[NUM_LIMBS];
    uint32_t r8_1[NUM_LIMBS];
    uint32_t r8_2[NUM_LIMBS];
    uint32_t r8_3[NUM_LIMBS];

    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r2, r); // r2 = r * r mod p
    uint64_t acc64_0[5], r64_0[5], mult_0[5];
    uint64_t carry_0;
    uint64_t g_0[5];

    for (int i = 0; i < 5; i++) {
        acc64_0[i] = (uint64_t) r2[i];
        r64_0[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_0, r64_0, mult_0);

    CARRY_PROPAGATION(carry_0,mult_0, r2);

    COMPUTE_MOD_P(carry_0, r2,g_0);

    if (carry_0 > 0) {
        memcpy( r2, g_0, 5 * sizeof(uint32_t));
    }

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r3, r); // r3 = r^2 * r mod p
        uint64_t acc64_1[5], r64_1[5], mult_1[5];
        uint64_t carry_1;
        uint64_t g_1[5];

        for (int i = 0; i < 5; i++) {
            acc64_1[i] = (uint64_t)r3[i];
            r64_1[i] = (uint64_t )r[i];
        }

        MUL_MOD_P(acc64_1, r64_1, mult_1);

        CARRY_PROPAGATION(carry_1,mult_1,r3);

        COMPUTE_MOD_P(carry_1,r3,g_1);

        if (carry_1 > 0) {
            memcpy(r3, g_1, 5 * sizeof(uint32_t));
        }

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r4, r); // r4 = r^3 * r mod p
    uint64_t acc64_2[5], r64_2[5], mult_2[5];
    uint64_t carry_2;
    uint64_t g_2[5];

    for (int i = 0; i < 5; i++) {
        acc64_2[i] = (uint64_t)r4[i];
        r64_2[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_2, r64_2, mult_2);

    CARRY_PROPAGATION(carry_2,mult_2,r4);

    COMPUTE_MOD_P(carry_2,r4,g_2);

    if (carry_2 > 0) {
        memcpy(r4, g_2, 5 * sizeof(uint32_t));
    }
    
    memcpy(r5, r4,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r5, r); // r5 = r^5 mod p
    uint64_t acc64_5[5], r64_5[5], mult_5[5];
    uint64_t carry_5;
    uint64_t g_5[5];

    for (int i = 0; i < 5; i++) {
        acc64_5[i] = (uint64_t)r5[i];
        r64_5[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_5, r64_5, mult_5);

    CARRY_PROPAGATION(carry_5,mult_5,r5);

    COMPUTE_MOD_P(carry_5,r5,g_5);

    if (carry_5 > 0) {
        memcpy(r5, g_5, 5 * sizeof(uint32_t));
    }

    memcpy(r6, r5,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r6, r); // r6 = r^6 mod p
    uint64_t acc64_6[5], r64_6[5], mult_6[5];
    uint64_t carry_6;
    uint64_t g_6[5];

    for (int i = 0; i < 5; i++) {
        acc64_6[i] = (uint64_t)r6[i];
        r64_6[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_6, r64_6, mult_6);

    CARRY_PROPAGATION(carry_6,mult_6,r6);

    COMPUTE_MOD_P(carry_6,r6,g_6);

    if (carry_6 > 0) {
        memcpy(r6, g_6, 5 * sizeof(uint32_t));
    }

    memcpy(r7, r6,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r7, r); // r7 = r^7 mod p
    uint64_t acc64_7[5], r64_7[5], mult_7[5];
    uint64_t carry_7;
    uint64_t g_7[5];

    for (int i = 0; i < 5; i++) {
        acc64_7[i] = (uint64_t)r7[i];
        r64_7[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_7, r64_7, mult_7);

    CARRY_PROPAGATION(carry_7,mult_7,r7);

    COMPUTE_MOD_P(carry_7,r7,g_7);

    if (carry_7 > 0) {
        memcpy(r7, g_7, 5 * sizeof(uint32_t));
    }

    memcpy(r8, r7,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r8, r); // r8 = r^8 mod p
    uint64_t acc64_8[5], r64_8[5], mult_8[5];
    uint64_t carry_8;
    uint64_t g_8[5];

    for (int i = 0; i < 5; i++) {
        acc64_8[i] = (uint64_t)r8[i];
        r64_8[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_8, r64_8, mult_8);

    CARRY_PROPAGATION(carry_8,mult_8,r8);

    COMPUTE_MOD_P(carry_8,r8,g_8);

    if (carry_8 > 0) {
        memcpy(r8, g_8, 5 * sizeof(uint32_t));
    }

    memcpy(r4_1, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_2, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_3, r4,  NUM_LIMBS * sizeof(uint32_t));

    memcpy(r8_1, r8,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r8_2, r8,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r8_3, r8,  NUM_LIMBS * sizeof(uint32_t));

    uint32_t acc_0[5];
    uint32_t acc_1[5];
    uint32_t acc_2[5];
    uint32_t acc_3[5];

    memset(acc_0, 0, sizeof(acc_0));
    memset(acc_1, 0, sizeof(acc_1));
    memset(acc_2, 0, sizeof(acc_2));
    memset(acc_3, 0, sizeof(acc_3));

    const uint8_t* curr_data = data;
    uint8_t block_0[17];
    uint8_t block_1[17];
    uint8_t block_2[17];
    uint8_t block_3[17];

    uint8_t block_00[17];
    uint8_t block_11[17];
    uint8_t block_22[17];
    uint8_t block_33[17];

/*------------------- STARTING COMPUTATION ON BLOCKS----------------------------*/
    for(int i = 0; i < paralle_calculations; i++) {

        memcpy(block_0, curr_data, 16); 
        memcpy(block_1, curr_data+16, 16); 
        memcpy(block_2, curr_data+32, 16); 
        memcpy(block_3, curr_data+48, 16); 

        memcpy(block_00, curr_data+64, 16); 
        memcpy(block_11, curr_data+80, 16); 
        memcpy(block_22, curr_data+96, 16); 
        memcpy(block_33, curr_data+112, 16); 

        block_0[16] = 0x01;
        block_1[16] = 0x01;
        block_2[16] = 0x01;
        block_3[16] = 0x01;

        block_00[16] = 0x01;
        block_11[16] = 0x01;
        block_22[16] = 0x01;
        block_33[16] = 0x01;

        uint32_t n_0[5];
        uint32_t n_1[5];
        uint32_t n_2[5];
        uint32_t n_3[5];
        uint32_t n_00[5];
        uint32_t n_11[5];
        uint32_t n_22[5];
        uint32_t n_33[5];
        //to_large_num_rep(n_0, block_0, 17);
        uint64_t low_0  = *(const uint64_t*)&block_0[0];
        uint64_t high_0 = *(const uint64_t*)&block_0[8];
        uint64_t last_0 = block_0[16];

        n_0[0] = (uint32_t)(low_0) & 0x3FFFFFF;
        n_0[1] = (uint32_t)(low_0 >> 26) & 0x3FFFFFF;
        n_0[2] = (uint32_t)((low_0 >> 52) | (high_0 << 12)) & 0x3FFFFFF;
        n_0[3] = (uint32_t)(high_0 >> 14) & 0x3FFFFFF;
        n_0[4] = (uint32_t)((high_0 >> 40) | (last_0 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_1, block_1, 17);
        uint64_t low_1  = *(const uint64_t*)&block_1[0];
        uint64_t high_1 = *(const uint64_t*)&block_1[8];
        uint64_t last_1 = block_1[16];

        n_1[0] = (uint32_t)(low_1) & 0x3FFFFFF;
        n_1[1] = (uint32_t)(low_1 >> 26) & 0x3FFFFFF;
        n_1[2] = (uint32_t)((low_1 >> 52) | (high_1 << 12)) & 0x3FFFFFF;
        n_1[3] = (uint32_t)(high_1 >> 14) & 0x3FFFFFF;
        n_1[4] = (uint32_t)((high_1 >> 40) | (last_1 << 24)) & 0x3FFFFFF;
        
        //to_large_num_rep(n_2, block_2, 17);
        uint64_t low_2  = *(const uint64_t*)&block_2[0];
        uint64_t high_2 = *(const uint64_t*)&block_2[8];
        uint64_t last_2 = block_2[16];

        n_2[0] = (uint32_t)(low_2) & 0x3FFFFFF;
        n_2[1] = (uint32_t)(low_2 >> 26) & 0x3FFFFFF;
        n_2[2] = (uint32_t)((low_2 >> 52) | (high_2 << 12)) & 0x3FFFFFF;
        n_2[3] = (uint32_t)(high_2 >> 14) & 0x3FFFFFF;
        n_2[4] = (uint32_t)((high_2 >> 40) | (last_2 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_3, block_3, 17);
        uint64_t low_3  = *(const uint64_t*)&block_3[0];
        uint64_t high_3 = *(const uint64_t*)&block_3[8];
        uint64_t last_3 = block_3[16];

        n_3[0] = (uint32_t)(low_3) & 0x3FFFFFF;
        n_3[1] = (uint32_t)(low_3 >> 26) & 0x3FFFFFF;
        n_3[2] = (uint32_t)((low_3 >> 52) | (high_3 << 12)) & 0x3FFFFFF;
        n_3[3] = (uint32_t)(high_3 >> 14) & 0x3FFFFFF;
        n_3[4] = (uint32_t)((high_3 >> 40) | (last_3 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_00, block_00, 17);
        uint64_t low_00  = *(const uint64_t*)&block_00[0];
        uint64_t high_00 = *(const uint64_t*)&block_00[8];
        uint64_t last_00 = block_00[16];

        n_00[0] = (uint32_t)(low_00) & 0x3FFFFFF;
        n_00[1] = (uint32_t)(low_00 >> 26) & 0x3FFFFFF;
        n_00[2] = (uint32_t)((low_00 >> 52) | (high_00 << 12)) & 0x3FFFFFF;
        n_00[3] = (uint32_t)(high_00 >> 14) & 0x3FFFFFF;
        n_00[4] = (uint32_t)((high_00 >> 40) | (last_00 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_11, block_11, 17);
        uint64_t low_11  = *(const uint64_t*)&block_11[0];
        uint64_t high_11 = *(const uint64_t*)&block_11[8];
        uint64_t last_11 = block_11[16];

        n_11[0] = (uint32_t)(low_11) & 0x3FFFFFF;
        n_11[1] = (uint32_t)(low_11 >> 26) & 0x3FFFFFF;
        n_11[2] = (uint32_t)((low_11 >> 52) | (high_11 << 12)) & 0x3FFFFFF;
        n_11[3] = (uint32_t)(high_11 >> 14) & 0x3FFFFFF;
        n_11[4] = (uint32_t)((high_11 >> 40) | (last_11 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_22, block_22, 17);
        uint64_t low_22  = *(const uint64_t*)&block_22[0];
        uint64_t high_22 = *(const uint64_t*)&block_22[8];
        uint64_t last_22 = block_22[16];

        n_22[0] = (uint32_t)(low_22) & 0x3FFFFFF;
        n_22[1] = (uint32_t)(low_22 >> 26) & 0x3FFFFFF;
        n_22[2] = (uint32_t)((low_22 >> 52) | (high_22 << 12)) & 0x3FFFFFF;
        n_22[3] = (uint32_t)(high_22 >> 14) & 0x3FFFFFF;
        n_22[4] = (uint32_t)((high_22 >> 40) | (last_22 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_33, block_33, 17);
        uint64_t low_33  = *(const uint64_t*)&block_33[0];
        uint64_t high_33 = *(const uint64_t*)&block_33[8];
        uint64_t last_33 = block_33[16];

        n_33[0] = (uint32_t)(low_33) & 0x3FFFFFF;
        n_33[1] = (uint32_t)(low_33 >> 26) & 0x3FFFFFF;
        n_33[2] = (uint32_t)((low_33 >> 52) | (high_33 << 12)) & 0x3FFFFFF;
        n_33[3] = (uint32_t)(high_33 >> 14) & 0x3FFFFFF;
        n_33[4] = (uint32_t)((high_33 >> 40) | (last_33 << 24)) & 0x3FFFFFF;

        /*process_lane_8blocks_unified is performing these:
            mulmod_p(acc_0, r8);
            mulmod_p(n_0, r4);
            add_large_nums_55(acc_0, n_0);
            add_large_nums_55(acc_0, n_00);*/

        //process_lane_8blocks_unified(acc_0, r8, n_0, r4, n_00);
        uint64_t mult_0[5];
        uint64_t carry_0;
        uint32_t g_0[5];
        
        uint64_t a_0[5]   = {acc_0[0], acc_0[1], acc_0[2], acc_0[3], acc_0[4]};
        uint64_t _r8_0[5] = {r8[0],    r8[1],    r8[2],    r8[3],    r8[4]};
        uint64_t _n0_0[5] = {n_0[0],   n_0[1],   n_0[2],   n_0[3],   n_0[4]};
        uint64_t _r4_0[5] = {r4[0],    r4[1],    r4[2],    r4[3],    r4[4]};

        DOUBLE_MULTIPLICATION_ADDITION(mult_0, a_0, _r8_0, _n0_0, _r4_0, n_00);
        CARRY_PROP_DELAYED(carry_0, mult_0, acc_0);
        MOD_P_DELAYED(carry_0,g_0,acc_0);

        //process_lane_8blocks_unified(acc_1, r8_1, n_1, r4_1, n_11);
        uint64_t mult_1[5];
        uint64_t carry_1;
        uint32_t g_1[5];
        
        uint64_t a_1[5]   = {acc_1[0], acc_1[1], acc_1[2], acc_1[3], acc_1[4]};
        uint64_t _r8_1[5] = {r8_1[0],    r8_1[1],    r8_1[2],    r8_1[3],    r8_1[4]};
        uint64_t _n0_1[5] = {n_1[0],   n_1[1],   n_1[2],   n_1[3],   n_1[4]};
        uint64_t _r4_1[5] = {r4_1[0],    r4_1[1],    r4_1[2],    r4_1[3],    r4_1[4]};

        DOUBLE_MULTIPLICATION_ADDITION(mult_1, a_1, _r8_1, _n0_1, _r4_1, n_11);
        CARRY_PROP_DELAYED(carry_1, mult_1, acc_1);
        MOD_P_DELAYED(carry_1,g_1,acc_1);
    
        //process_lane_8blocks_unified(acc_2, r8_2, n_2, r4_2, n_22);
        uint64_t mult_2[5];
        uint64_t carry_2;
        uint32_t g_2[5];
        
        uint64_t a_2[5]   = {acc_2[0], acc_2[1], acc_2[2], acc_2[3], acc_2[4]};
        uint64_t _r8_2[5] = {r8_2[0],    r8_2[1],    r8_2[2],    r8_2[3],    r8_2[4]};
        uint64_t _n0_2[5] = {n_2[0],   n_2[1],   n_2[2],   n_2[3],   n_2[4]};
        uint64_t _r4_2[5] = {r4_2[0],    r4_2[1],    r4_2[2],    r4_2[3],    r4_2[4]};

        DOUBLE_MULTIPLICATION_ADDITION(mult_2, a_2, _r8_2, _n0_2, _r4_2, n_22);
        CARRY_PROP_DELAYED(carry_2, mult_2, acc_2);
        MOD_P_DELAYED(carry_2,g_2,acc_2);

        //process_lane_8blocks_unified(acc_3, r8_3, n_3, r4_3, n_33);
        uint64_t mult_3[5];
        uint64_t carry_3;
        uint32_t g_3[5];
        
        uint64_t a_3[5]   = {acc_3[0], acc_3[1], acc_3[2], acc_3[3], acc_3[4]};
        uint64_t _r8_3[5] = {r8_3[0],    r8_3[1],    r8_3[2],    r8_3[3],    r8_3[4]};
        uint64_t _n0_3[5] = {n_3[0],   n_3[1],   n_3[2],   n_3[3],   n_3[4]};
        uint64_t _r4_3[5] = {r4_3[0],    r4_3[1],    r4_3[2],    r4_3[3],    r4_3[4]};

        DOUBLE_MULTIPLICATION_ADDITION(mult_3, a_3, _r8_3, _n0_3, _r4_3, n_33);
        CARRY_PROP_DELAYED(carry_3, mult_3, acc_3);
        MOD_P_DELAYED(carry_3,g_3,acc_3);

        curr_data += 16*PARALLEL_BLOCKS*2;
    }

    uint32_t* align_powers[PARALLEL_BLOCKS] = {r4, r3, r2, r};
    uint32_t* acc_array[PARALLEL_BLOCKS] = {acc_0, acc_1, acc_2, acc_3};

    for(int i=0; i< PARALLEL_BLOCKS; i++){
        //mulmod_p(acc_array[i], align_powers[i]);
        uint64_t acc64_align[5], r64_align[5], mult_align[5];
        uint64_t carry_align;
        uint64_t g_align[5];

        for (int j = 0; j < 5; j++) {
            acc64_align[j] = (uint64_t)acc_array[i][j];
            r64_align[j] = (uint64_t )align_powers[i][j];
        }

        MUL_MOD_P(acc64_align, r64_align, mult_align);

        CARRY_PROPAGATION(carry_align,mult_align,acc_array[i]);

        COMPUTE_MOD_P(carry_align,acc_array[i],g_align);

        if (carry_align > 0) {
            memcpy(acc_array[i], g_align, 5 * sizeof(uint32_t));
        }

        //add_large_nums_55(acc, acc_array[i]);
        carry_align = 0; 
        ADD_55(carry_align, acc, acc_array[i]);
    }

    uint64_t remaining_full = full_blocks % (PARALLEL_BLOCKS*2);
    for(int i =0; i<remaining_full; i++){
        memcpy(block_0, curr_data, 16); 

        block_0[16] = 0x01;

        uint32_t n_0[5];

        //to_large_num_rep(n_0, block_0, 17);
        uint64_t low  = *(const uint64_t*)&block_0[0];
        uint64_t high = *(const uint64_t*)&block_0[8];
        uint64_t last = block_0[16];
        n_0[0] = (uint32_t)(low) & 0x3FFFFFF;
        n_0[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;

        n_0[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        
        n_0[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;

        n_0[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;

        //add_large_nums_55(acc, n_0); // acc += block
        uint64_t carry_0 = 0; 
        ADD_55(carry_0, acc, n_0);
        //mulmod_p(acc, r);            // acc = acc * r mod p
        uint64_t acc64_0[5], r64_0[5], mult_0[5];
        uint64_t g_0[5];

        for (int j = 0; j < 5; j++) {
            acc64_0[j] = (uint64_t)acc[j];
            r64_0[j] = (uint64_t )r[j];
        }

        MUL_MOD_P(acc64_0, r64_0, mult_0);

        CARRY_PROPAGATION(carry_0,mult_0,acc);

        COMPUTE_MOD_P(carry_0,acc,g_0);

        if (carry_0 > 0) {
            memcpy(acc, g_0, 5 * sizeof(uint32_t));
        }

        curr_data += 16;
    }

    if(remainder > 0) {
        memset(block_0, 0, 17);

        memcpy(block_0, curr_data, remainder);

        block_0[remainder] = 0x01; 

        block_0[16] = 0x00; 

        uint32_t n[5];

        uint64_t low  = *(const uint64_t*)&block_0[0];
        uint64_t high = *(const uint64_t*)&block_0[8];
        uint64_t last = block_0[16];
        
        n[0] = (uint32_t)(low) & 0x3FFFFFF;
        n[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;
        n[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        n[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;
        n[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;

        //add_large_nums_55(acc, n);
        uint64_t carry_0;
        ADD_55(carry_0, acc, n);

        //mulmod_p(acc, r);
        uint64_t acc64_0[5], r64_0[5], mult_0[5];
        
        uint64_t g_0[5];

        for (int i = 0; i < 5; i++) {
            acc64_0[i] = (uint64_t)acc[i];
            r64_0[i] = (uint64_t )r[i];
        }

        MUL_MOD_P(acc64_0, r64_0, mult_0);

        CARRY_PROPAGATION(carry_0,mult_0,acc);

        COMPUTE_MOD_P(carry_0,acc,g_0);

        if (carry_0 > 0) {
            memcpy(acc, g_0, 5 * sizeof(uint32_t));
        }
    }
        uint32_t addition[4];
        //add_large_nums_54(addition, acc, s);
        uint64_t convert[4];

        convert[0] = (uint64_t)acc[0]        | ((uint64_t)acc[1] << 26);
        convert[1] = (uint64_t)(acc[1] >> 6)  | ((uint64_t)acc[2] << 20);
        convert[2] = (uint64_t)(acc[2] >> 12) | ((uint64_t)acc[3] << 14);
        convert[3] = (uint64_t)(acc[3] >> 18) | ((uint64_t)acc[4] << 8);

        uint64_t carry = 0;
        for(unsigned int i = 0; i < 4; i++){
            carry += (uint32_t)convert[i] + (uint64_t)s[i]; 
            addition[i] = (uint32_t)carry; 
            carry >>= 32; 
        }  
        
        unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
        //to_16_le_bytes(addition, tag);
        for (int i = 0; i < 4; i++){
            tag[i*4] = (unsigned char)(addition[i] & 0xff); // extract lowest 8 bits (least significant byte)
            tag[i*4 + 1] = (unsigned char)((addition[i] >> 8) & 0xff);
            tag[i*4 + 2] = (unsigned char)((addition[i]>> 16) & 0xff);
            tag[i*4+ 3] = (unsigned char)((addition[i] >> 24) & 0xff);
        }
        return tag;
}


unsigned char* vect_inlined_carry_delay_parallel_Horner(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    uint64_t full_blocks = (data_len) / POLY_BLOCK;
    uint64_t paralle_calculations = full_blocks / (PARALLEL_BLOCKS*2);
    uint64_t remainder = data_len % POLY_BLOCK;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t r5[NUM_LIMBS];
    uint32_t r6[NUM_LIMBS];
    uint32_t r7[NUM_LIMBS];
    uint32_t r8[NUM_LIMBS];

    uint32_t r4_1[NUM_LIMBS];
    uint32_t r4_2[NUM_LIMBS];
    uint32_t r4_3[NUM_LIMBS];
    uint32_t r8_1[NUM_LIMBS];
    uint32_t r8_2[NUM_LIMBS];
    uint32_t r8_3[NUM_LIMBS];

    //

    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r2, r); // r2 = r * r mod p
    uint64_t acc64_0[5], r64_0[5], mult_0[5];
    uint64_t carry_0;
    uint64_t g_0[5];

    for (int i = 0; i < 5; i++) {
        acc64_0[i] = (uint64_t) r2[i];
        r64_0[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_0, r64_0, mult_0);

    CARRY_PROPAGATION(carry_0,mult_0, r2);

    COMPUTE_MOD_P(carry_0, r2,g_0);

    if (carry_0 > 0) {
        memcpy( r2, g_0, 5 * sizeof(uint32_t));
    }

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r3, r); // r3 = r^2 * r mod p
        uint64_t acc64_1[5], r64_1[5], mult_1[5];
        uint64_t carry_1;
        uint64_t g_1[5];

        for (int i = 0; i < 5; i++) {
            acc64_1[i] = (uint64_t)r3[i];
            r64_1[i] = (uint64_t )r[i];
        }

        MUL_MOD_P(acc64_1, r64_1, mult_1);

        CARRY_PROPAGATION(carry_1,mult_1,r3);

        COMPUTE_MOD_P(carry_1,r3,g_1);

        if (carry_1 > 0) {
            memcpy(r3, g_1, 5 * sizeof(uint32_t));
        }

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r4, r); // r4 = r^3 * r mod p
    uint64_t acc64_2[5], r64_2[5], mult_2[5];
    uint64_t carry_2;
    uint64_t g_2[5];

    for (int i = 0; i < 5; i++) {
        acc64_2[i] = (uint64_t)r4[i];
        r64_2[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_2, r64_2, mult_2);

    CARRY_PROPAGATION(carry_2,mult_2,r4);

    COMPUTE_MOD_P(carry_2,r4,g_2);

    if (carry_2 > 0) {
        memcpy(r4, g_2, 5 * sizeof(uint32_t));
    }
    
    memcpy(r5, r4,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r5, r); // r5 = r^5 mod p
    uint64_t acc64_5[5], r64_5[5], mult_5[5];
    uint64_t carry_5;
    uint64_t g_5[5];

    for (int i = 0; i < 5; i++) {
        acc64_5[i] = (uint64_t)r5[i];
        r64_5[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_5, r64_5, mult_5);

    CARRY_PROPAGATION(carry_5,mult_5,r5);

    COMPUTE_MOD_P(carry_5,r5,g_5);

    if (carry_5 > 0) {
        memcpy(r5, g_5, 5 * sizeof(uint32_t));
    }

    memcpy(r6, r5,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r6, r); // r6 = r^6 mod p
    uint64_t acc64_6[5], r64_6[5], mult_6[5];
    uint64_t carry_6;
    uint64_t g_6[5];

    for (int i = 0; i < 5; i++) {
        acc64_6[i] = (uint64_t)r6[i];
        r64_6[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_6, r64_6, mult_6);

    CARRY_PROPAGATION(carry_6,mult_6,r6);

    COMPUTE_MOD_P(carry_6,r6,g_6);

    if (carry_6 > 0) {
        memcpy(r6, g_6, 5 * sizeof(uint32_t));
    }

    memcpy(r7, r6,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r7, r); // r7 = r^7 mod p
    uint64_t acc64_7[5], r64_7[5], mult_7[5];
    uint64_t carry_7;
    uint64_t g_7[5];

    for (int i = 0; i < 5; i++) {
        acc64_7[i] = (uint64_t)r7[i];
        r64_7[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_7, r64_7, mult_7);

    CARRY_PROPAGATION(carry_7,mult_7,r7);

    COMPUTE_MOD_P(carry_7,r7,g_7);

    if (carry_7 > 0) {
        memcpy(r7, g_7, 5 * sizeof(uint32_t));
    }

    memcpy(r8, r7,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r8, r); // r8 = r^8 mod p
    uint64_t acc64_8[5], r64_8[5], mult_8[5];
    uint64_t carry_8;
    uint64_t g_8[5];

    for (int i = 0; i < 5; i++) {
        acc64_8[i] = (uint64_t)r8[i];
        r64_8[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_8, r64_8, mult_8);

    CARRY_PROPAGATION(carry_8,mult_8,r8);

    COMPUTE_MOD_P(carry_8,r8,g_8);

    if (carry_8 > 0) {
        memcpy(r8, g_8, 5 * sizeof(uint32_t));
    }

    memcpy(r4_1, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_2, r4,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_3, r4,  NUM_LIMBS * sizeof(uint32_t));

    memcpy(r8_1, r8,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r8_2, r8,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r8_3, r8,  NUM_LIMBS * sizeof(uint32_t));

    uint32_t acc_0[5];
    uint32_t acc_1[5];
    uint32_t acc_2[5];
    uint32_t acc_3[5];

    memset(acc_0, 0, sizeof(acc_0));
    memset(acc_1, 0, sizeof(acc_1));
    memset(acc_2, 0, sizeof(acc_2));
    memset(acc_3, 0, sizeof(acc_3));

    const uint8_t* curr_data = data;
    uint8_t block_0[17];
    uint8_t block_1[17];
    uint8_t block_2[17];
    uint8_t block_3[17];

    uint8_t block_00[17];
    uint8_t block_11[17];
    uint8_t block_22[17];
    uint8_t block_33[17];

    __m256i r4_vect[5];
    __m256i r8_vect[5];
    __m256i r8_mul5_vect[5];
    __m256i r4_mul5_vect[5];
    __m256i acc_vect[5];
    __m256i g_vect[5];

    g_vect[0] = _mm256_set1_epi64x(0);
    g_vect[1] = _mm256_set1_epi64x(0);
    g_vect[2] = _mm256_set1_epi64x(0);
    g_vect[3] = _mm256_set1_epi64x(0);
    g_vect[4] = _mm256_set1_epi64x(0);

    acc_vect[0] = _mm256_set1_epi64x(0);
    acc_vect[1] = _mm256_set1_epi64x(0);
    acc_vect[2] = _mm256_set1_epi64x(0);
    acc_vect[3] = _mm256_set1_epi64x(0);
    acc_vect[4] = _mm256_set1_epi64x(0);

    uint32_t array_5[5] = {5,0,0,0,0};
    uint32_t r4_mul5[NUM_LIMBS];
    uint32_t r8_mul5[NUM_LIMBS];
    memcpy(r8_mul5, r8,  NUM_LIMBS * sizeof(uint32_t));
    memcpy(r4_mul5, r4,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r8_mul5, array_5);
    mulmod_p(r4_mul5, array_5);

    for(int j=0; j<5; j++){
        r4_mul5_vect[j] = _mm256_set_epi64x( (uint64_t) r4_mul5[j], (uint64_t) r4_mul5[j], (uint64_t) r4_mul5[j], (uint64_t) r4_mul5[j]);
        r8_mul5_vect[j] =  _mm256_set_epi64x( (uint64_t) r8_mul5[j], (uint64_t) r8_mul5[j], (uint64_t) r8_mul5[j], (uint64_t) r8_mul5[j]);       
       }

    r4_vect[0] = _mm256_set_epi64x( (uint64_t) r4[0], (uint64_t) r4_1[0], (uint64_t) r4_2[0], (uint64_t) r4_3[0]);
    r4_vect[1] = _mm256_set_epi64x( (uint64_t) r4[1], (uint64_t) r4_1[1], (uint64_t) r4_2[1], (uint64_t) r4_3[1]);
    r4_vect[2] = _mm256_set_epi64x( (uint64_t) r4[2], (uint64_t) r4_1[2], (uint64_t) r4_2[2], (uint64_t) r4_3[2]);
    r4_vect[3] = _mm256_set_epi64x( (uint64_t) r4[3], (uint64_t) r4_1[3], (uint64_t) r4_2[3], (uint64_t) r4_3[3]);
    r4_vect[4] = _mm256_set_epi64x( (uint64_t) r4[4], (uint64_t) r4_1[4], (uint64_t) r4_2[4], (uint64_t) r4_3[4]);

    r8_vect[0] = _mm256_set_epi64x( (uint64_t) r8[0], (uint64_t) r8_1[0], (uint64_t) r8_2[0], (uint64_t) r8_3[0]);
    r8_vect[1] = _mm256_set_epi64x( (uint64_t) r8[1], (uint64_t) r8_1[1], (uint64_t) r8_2[1], (uint64_t) r8_3[1]);
    r8_vect[2] = _mm256_set_epi64x( (uint64_t) r8[2], (uint64_t) r8_1[2], (uint64_t) r8_2[2], (uint64_t) r8_3[2]);
    r8_vect[3] = _mm256_set_epi64x( (uint64_t) r8[3], (uint64_t) r8_1[3], (uint64_t) r8_2[3], (uint64_t) r8_3[3]);
    r8_vect[4] = _mm256_set_epi64x( (uint64_t) r8[4], (uint64_t) r8_1[4], (uint64_t) r8_2[4], (uint64_t) r8_3[4]);


/*------------------- STARTING COMPUTATION ON BLOCKS----------------------------*/
    for(int i = 0; i < paralle_calculations; i++) {

        memcpy(block_0, curr_data, 16); 
        memcpy(block_1, curr_data+16, 16); 
        memcpy(block_2, curr_data+32, 16); 
        memcpy(block_3, curr_data+48, 16); 

        memcpy(block_00, curr_data+64, 16); 
        memcpy(block_11, curr_data+80, 16); 
        memcpy(block_22, curr_data+96, 16); 
        memcpy(block_33, curr_data+112, 16); 

        block_0[16] = 0x01;
        block_1[16] = 0x01;
        block_2[16] = 0x01;
        block_3[16] = 0x01;

        block_00[16] = 0x01;
        block_11[16] = 0x01;
        block_22[16] = 0x01;
        block_33[16] = 0x01;

        uint32_t n_0[5];
        uint32_t n_1[5];
        uint32_t n_2[5];
        uint32_t n_3[5];
        uint32_t n_00[5];
        uint32_t n_11[5];
        uint32_t n_22[5];
        uint32_t n_33[5];

        //to_large_num_rep(n_0, block_0, 17);
        uint64_t low_0  = *(const uint64_t*)&block_0[0];
        uint64_t high_0 = *(const uint64_t*)&block_0[8];
        uint64_t last_0 = block_0[16];

        n_0[0] = (uint32_t)(low_0) & 0x3FFFFFF;
        n_0[1] = (uint32_t)(low_0 >> 26) & 0x3FFFFFF;
        n_0[2] = (uint32_t)((low_0 >> 52) | (high_0 << 12)) & 0x3FFFFFF;
        n_0[3] = (uint32_t)(high_0 >> 14) & 0x3FFFFFF;
        n_0[4] = (uint32_t)((high_0 >> 40) | (last_0 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_1, block_1, 17);
        uint64_t low_1  = *(const uint64_t*)&block_1[0];
        uint64_t high_1 = *(const uint64_t*)&block_1[8];
        uint64_t last_1 = block_1[16];

        n_1[0] = (uint32_t)(low_1) & 0x3FFFFFF;
        n_1[1] = (uint32_t)(low_1 >> 26) & 0x3FFFFFF;
        n_1[2] = (uint32_t)((low_1 >> 52) | (high_1 << 12)) & 0x3FFFFFF;
        n_1[3] = (uint32_t)(high_1 >> 14) & 0x3FFFFFF;
        n_1[4] = (uint32_t)((high_1 >> 40) | (last_1 << 24)) & 0x3FFFFFF;
        
        //to_large_num_rep(n_2, block_2, 17);
        uint64_t low_2  = *(const uint64_t*)&block_2[0];
        uint64_t high_2 = *(const uint64_t*)&block_2[8];
        uint64_t last_2 = block_2[16];

        n_2[0] = (uint32_t)(low_2) & 0x3FFFFFF;
        n_2[1] = (uint32_t)(low_2 >> 26) & 0x3FFFFFF;
        n_2[2] = (uint32_t)((low_2 >> 52) | (high_2 << 12)) & 0x3FFFFFF;
        n_2[3] = (uint32_t)(high_2 >> 14) & 0x3FFFFFF;
        n_2[4] = (uint32_t)((high_2 >> 40) | (last_2 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_3, block_3, 17);
        uint64_t low_3  = *(const uint64_t*)&block_3[0];
        uint64_t high_3 = *(const uint64_t*)&block_3[8];
        uint64_t last_3 = block_3[16];

        n_3[0] = (uint32_t)(low_3) & 0x3FFFFFF;
        n_3[1] = (uint32_t)(low_3 >> 26) & 0x3FFFFFF;
        n_3[2] = (uint32_t)((low_3 >> 52) | (high_3 << 12)) & 0x3FFFFFF;
        n_3[3] = (uint32_t)(high_3 >> 14) & 0x3FFFFFF;
        n_3[4] = (uint32_t)((high_3 >> 40) | (last_3 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_00, block_00, 17);
        uint64_t low_00  = *(const uint64_t*)&block_00[0];
        uint64_t high_00 = *(const uint64_t*)&block_00[8];
        uint64_t last_00 = block_00[16];

        n_00[0] = (uint32_t)(low_00) & 0x3FFFFFF;
        n_00[1] = (uint32_t)(low_00 >> 26) & 0x3FFFFFF;
        n_00[2] = (uint32_t)((low_00 >> 52) | (high_00 << 12)) & 0x3FFFFFF;
        n_00[3] = (uint32_t)(high_00 >> 14) & 0x3FFFFFF;
        n_00[4] = (uint32_t)((high_00 >> 40) | (last_00 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_11, block_11, 17);
        uint64_t low_11  = *(const uint64_t*)&block_11[0];
        uint64_t high_11 = *(const uint64_t*)&block_11[8];
        uint64_t last_11 = block_11[16];

        n_11[0] = (uint32_t)(low_11) & 0x3FFFFFF;
        n_11[1] = (uint32_t)(low_11 >> 26) & 0x3FFFFFF;
        n_11[2] = (uint32_t)((low_11 >> 52) | (high_11 << 12)) & 0x3FFFFFF;
        n_11[3] = (uint32_t)(high_11 >> 14) & 0x3FFFFFF;
        n_11[4] = (uint32_t)((high_11 >> 40) | (last_11 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_22, block_22, 17);
        uint64_t low_22  = *(const uint64_t*)&block_22[0];
        uint64_t high_22 = *(const uint64_t*)&block_22[8];
        uint64_t last_22 = block_22[16];

        n_22[0] = (uint32_t)(low_22) & 0x3FFFFFF;
        n_22[1] = (uint32_t)(low_22 >> 26) & 0x3FFFFFF;
        n_22[2] = (uint32_t)((low_22 >> 52) | (high_22 << 12)) & 0x3FFFFFF;
        n_22[3] = (uint32_t)(high_22 >> 14) & 0x3FFFFFF;
        n_22[4] = (uint32_t)((high_22 >> 40) | (last_22 << 24)) & 0x3FFFFFF;

        //to_large_num_rep(n_33, block_33, 17);
        uint64_t low_33  = *(const uint64_t*)&block_33[0];
        uint64_t high_33 = *(const uint64_t*)&block_33[8];
        uint64_t last_33 = block_33[16];

        n_33[0] = (uint32_t)(low_33) & 0x3FFFFFF;
        n_33[1] = (uint32_t)(low_33 >> 26) & 0x3FFFFFF;
        n_33[2] = (uint32_t)((low_33 >> 52) | (high_33 << 12)) & 0x3FFFFFF;
        n_33[3] = (uint32_t)(high_33 >> 14) & 0x3FFFFFF;
        n_33[4] = (uint32_t)((high_33 >> 40) | (last_33 << 24)) & 0x3FFFFFF;

        __m256i a_vect[5];
        __m256i n_vect[5];
        __m256i nn_vect[5];
        __m256i carry_vect;
        __m256i mult_vect[5];

        __m256i mask32 = _mm256_set1_epi64x(0xFFFFFFFFULL);
        for(int j=0; j<5; j++) {
            a_vect[j] = _mm256_and_si256(acc_vect[j], mask32);
            // Matched lane assignment order explicitly matching extract order below
            n_vect[j]  = _mm256_set_epi64x((uint64_t)n_3[j],  (uint64_t)n_2[j],  (uint64_t)n_1[j],  (uint64_t)n_0[j]);
            nn_vect[j] = _mm256_set_epi64x((uint64_t)n_33[j], (uint64_t)n_22[j], (uint64_t)n_11[j], (uint64_t)n_00[j]);
        }


        DOUBLE_MULTIPLICATION_ADDITION_VECT(mult_vect, a_vect, r8_vect, n_vect, r4_vect, nn_vect, r4_mul5_vect, r8_mul5_vect);
        CARRY_PROP_DELAYED_VECT(carry_vect, mult_vect, acc_vect);
        MOD_P_DELAYED_VECT(carry_vect,g_vect,acc_vect);

        curr_data += 16*PARALLEL_BLOCKS*2;
    }

    for(int i=0;i<5;i++){
        acc_0[i] = (uint32_t)_mm256_extract_epi64(acc_vect[i], 0);
        acc_1[i] = (uint32_t)_mm256_extract_epi64(acc_vect[i], 1);
        acc_2[i] = (uint32_t)_mm256_extract_epi64(acc_vect[i], 2);
        acc_3[i] = (uint32_t)_mm256_extract_epi64(acc_vect[i], 3);
    }

    uint32_t* align_powers[PARALLEL_BLOCKS] = {r4, r3, r2, r};
    uint32_t* acc_array[PARALLEL_BLOCKS] = {acc_0, acc_1, acc_2, acc_3};

    for(int i=0; i< PARALLEL_BLOCKS; i++){
        //mulmod_p(acc_array[i], align_powers[i]);
        uint64_t acc64_align[5], r64_align[5], mult_align[5];
        uint64_t carry_align;
        uint64_t g_align[5];

        for (int j = 0; j < 5; j++) {
            acc64_align[j] = (uint64_t)acc_array[i][j];
            r64_align[j] = (uint64_t )align_powers[i][j];
        }

        MUL_MOD_P(acc64_align, r64_align, mult_align);

        CARRY_PROPAGATION(carry_align,mult_align,acc_array[i]);

        COMPUTE_MOD_P(carry_align,acc_array[i],g_align);

        if (carry_align > 0) {
            memcpy(acc_array[i], g_align, 5 * sizeof(uint32_t));
        }

        //add_large_nums_55(acc, acc_array[i]);
        carry_align = 0; 
        ADD_55(carry_align, acc, acc_array[i]);
    }

    uint64_t remaining_full = full_blocks % (PARALLEL_BLOCKS*2);
    for(int i =0; i<remaining_full; i++){
        memcpy(block_0, curr_data, 16); 

        block_0[16] = 0x01;

        uint32_t n_0[5];

        //to_large_num_rep(n_0, block_0, 17);
        uint64_t low  = *(const uint64_t*)&block_0[0];
        uint64_t high = *(const uint64_t*)&block_0[8];
        uint64_t last = block_0[16];
        n_0[0] = (uint32_t)(low) & 0x3FFFFFF;
        n_0[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;

        n_0[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        
        n_0[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;

        n_0[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;

        //add_large_nums_55(acc, n_0); // acc += block
        uint64_t carry_0 = 0; 
        ADD_55(carry_0, acc, n_0);
        //mulmod_p(acc, r);            // acc = acc * r mod p
        uint64_t acc64_0[5], r64_0[5], mult_0[5];
        uint64_t g_0[5];

        for (int j = 0; j < 5; j++) {
            acc64_0[j] = (uint64_t)acc[j];
            r64_0[j] = (uint64_t )r[j];
        }

        MUL_MOD_P(acc64_0, r64_0, mult_0);

        CARRY_PROPAGATION(carry_0,mult_0,acc);

        COMPUTE_MOD_P(carry_0,acc,g_0);

        if (carry_0 > 0) {
            memcpy(acc, g_0, 5 * sizeof(uint32_t));
        }

        curr_data += 16;
    }

    if(remainder > 0) {
        memset(block_0, 0, 17);

        memcpy(block_0, curr_data, remainder);

        block_0[remainder] = 0x01; 

        block_0[16] = 0x00; 

        uint32_t n[5];

        uint64_t low  = *(const uint64_t*)&block_0[0];
        uint64_t high = *(const uint64_t*)&block_0[8];
        uint64_t last = block_0[16];
        
        n[0] = (uint32_t)(low) & 0x3FFFFFF;
        n[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;
        n[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        n[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;
        n[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;

        //add_large_nums_55(acc, n);
        uint64_t carry_0;
        ADD_55(carry_0, acc, n);

        //mulmod_p(acc, r);
        uint64_t acc64_0[5], r64_0[5], mult_0[5];
        
        uint64_t g_0[5];

        for (int i = 0; i < 5; i++) {
            acc64_0[i] = (uint64_t)acc[i];
            r64_0[i] = (uint64_t )r[i];
        }

        MUL_MOD_P(acc64_0, r64_0, mult_0);

        CARRY_PROPAGATION(carry_0,mult_0,acc);

        COMPUTE_MOD_P(carry_0,acc,g_0);

        if (carry_0 > 0) {
            memcpy(acc, g_0, 5 * sizeof(uint32_t));
        }
    }
        uint32_t addition[4];
        //add_large_nums_54(addition, acc, s);
        uint64_t convert[4];

        convert[0] = (uint64_t)acc[0]        | ((uint64_t)acc[1] << 26);
        convert[1] = (uint64_t)(acc[1] >> 6)  | ((uint64_t)acc[2] << 20);
        convert[2] = (uint64_t)(acc[2] >> 12) | ((uint64_t)acc[3] << 14);
        convert[3] = (uint64_t)(acc[3] >> 18) | ((uint64_t)acc[4] << 8);

        uint64_t carry = 0;
        for(unsigned int i = 0; i < 4; i++){
            carry += (uint32_t)convert[i] + (uint64_t)s[i]; 
            addition[i] = (uint32_t)carry; 
            carry >>= 32; 
        }  
        
        unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
        //to_16_le_bytes(addition, tag);
        for (int i = 0; i < 4; i++){
            tag[i*4] = (unsigned char)(addition[i] & 0xff); // extract lowest 8 bits (least significant byte)
            tag[i*4 + 1] = (unsigned char)((addition[i] >> 8) & 0xff);
            tag[i*4 + 2] = (unsigned char)((addition[i]>> 16) & 0xff);
            tag[i*4+ 3] = (unsigned char)((addition[i] >> 24) & 0xff);
        }
        return tag;
}


unsigned char* _2poly_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
// 1. Process only the blocks that are GUARANTEED to be 16 bytes
    uint64_t full_blocks = (data_len) / 16;
    uint64_t paralle_calculations = full_blocks / PARALLEL_BLOCKS;
    uint64_t remainder = data_len % 16;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r2, r); // r2 = r * r mod p

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r3, r); // r3 = r^2 * r mod p

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r4, r); // r4 = r^3 * r mod p


    const uint8_t* curr_data = data;
    uint8_t block_0[17];
    uint8_t block_1[17];
    uint8_t block_2[17];
    uint8_t block_3[17];

for(int i = 0; i < paralle_calculations; i++) {

    memcpy(block_0, curr_data, 16); 
    memcpy(block_1, curr_data+16, 16); 
    memcpy(block_2, curr_data+32, 16); 
    memcpy(block_3, curr_data+48, 16); 

    block_0[16] = 0x01;
    block_1[16] = 0x01;
    block_2[16] = 0x01;
    block_3[16] = 0x01;

    uint32_t n_0[5];
    uint32_t n_1[5];
    uint32_t n_2[5];
    uint32_t n_3[5];
    to_large_num_rep(n_0, block_0, 17);
    to_large_num_rep(n_1, block_1, 17);
    to_large_num_rep(n_2, block_2, 17);
    to_large_num_rep(n_3, block_3, 17);

    mulmod_p(n_0, r4);
    mulmod_p(n_1, r3);
    mulmod_p(n_2, r2);
    mulmod_p(n_3, r);

    add_large_nums_55(n_0, n_1); // n1 += n2
    add_large_nums_55(n_0, n_2); // n1 += n3
    add_large_nums_55(n_0, n_3); // n1 += n4

    mulmod_p(acc, r4); // acc = acc * r^4 mod p
    add_large_nums_55(acc, n_0); // acc += n1


    curr_data += 16*PARALLEL_BLOCKS;
}

uint64_t remaining_full = full_blocks % PARALLEL_BLOCKS;
for(int i =0; i<remaining_full; i++){
    memcpy(block_0, curr_data, 16); 

    block_0[16] = 0x01;

    uint32_t n_0[5];

    to_large_num_rep(n_0, block_0, 17);

    add_large_nums_55(acc, n_0); // acc += block

    mulmod_p(acc, r);            // acc = acc * r mod p


    curr_data += 16;
}

if(remainder > 0) {
    memset(block_0, 0, 17);
    memcpy(block_0, curr_data, remainder);
    block_0[remainder] = 0x01;
    uint32_t n[5];
    to_large_num_rep(n, block_0, remainder + 1);
    add_large_nums_55(acc, n);
    mulmod_p(acc, r);
}
    uint32_t addition[4];
    add_large_nums_54(addition, acc, s);
    unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
    to_16_le_bytes(addition, tag);
    return tag;
}

