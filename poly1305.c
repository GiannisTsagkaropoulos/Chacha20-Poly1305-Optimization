#include <stdint.h> // get uint32_t and uint64_t types, so is not platform dependent (unsigned int (32 bits) and unsigned long long (64 bits) could vary in size)
#include <string.h>
#include <stdlib.h>
#include "poly1305.h"

/*
we use 5x26-bit representations for acc and r, since 5*26 = 130 bits. 
In the specification, acc and r are 128 bits, but because they could exceed these 128 bits during computations, we chose 130 to be safe.
For s we use 4x32-bit representation since since s should be 128 bits (4*32 = 128) and is not involved in calculations which could exceed that limit.
*/ 

const uint32_t mask_lowest_26bits = 0x3ffffff; // mask to keep only lowest 26 bits (26 ones in binary)
const uint64_t mask_lowest_32bits = 0xffffffffULL; // mask to keep only lowest 32 bits (32 ones in binary)

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

// handles conversion from 4x32-bit representation to 16 bytes in LE format
void to_16_le_bytes(uint32_t in[4], unsigned char out[16]){
    for (int i = 0; i < 4; i++){
        out[i*4] = (unsigned char)(in[i] & 0xff); // extract lowest 8 bits (least significant byte)
        out[i*4 + 1] = (unsigned char)((in[i] >> 8) & 0xff); // shift by 8 and extract next 8 bits
        out[i*4 + 2] = (unsigned char)((in[i]>> 16) & 0xff); // etc.
        out[i*4+ 3] = (unsigned char)((in[i] >> 24) & 0xff);
    }
}

// keylength must be 32 bytes
void poly1305_init(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char key[32]) {
    // split key into two halves (first half into r, other in s)
    unsigned char r_bytes[16];
    memcpy(r_bytes, key, 16);
    
    // mask some bits of r 
    const uint8_t clear_top4_bits = 0x0f;
    const uint8_t clear_lowest2_bits = 0xfc;

    r_bytes[3]  &= clear_top4_bits;
    r_bytes[4]  &= clear_lowest2_bits;
    r_bytes[7]  &= clear_top4_bits;
    r_bytes[8]  &= clear_lowest2_bits;
    r_bytes[11] &= clear_top4_bits;
    r_bytes[12] &= clear_lowest2_bits;
    r_bytes[15] &= clear_top4_bits;

    // then convert to 5x26-bit representation
    to_large_num_rep(r, r_bytes, 16);
    
    // convert second half of key into 4x32-bit representation for s
    for (int i = 0; i < 4; i++) {
        s[i] = (uint32_t)key[16 + i*4] | ((uint32_t)key[17 + i*4] <<  8)| ((uint32_t)key[18 + i*4] << 16) | ((uint32_t)key[19 + i*4] << 24);
    }

    memset(acc, 0, 5*sizeof(uint32_t)); 
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