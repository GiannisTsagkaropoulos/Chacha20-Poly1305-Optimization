#include <stdint.h> // get uint32_t and uint64_t types, so is not platform dependent (unsigned int (32 bits) and unsigned long long (64 bits) could vary in size)
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "poly1305_opt.h"

#define B 2

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
   
    uint64_t len_bytes = 16;
    uint64_t t[5] = {0}; // initialize with zeros
    // convert the 16 bytes into the 5*64-bit integer representation (LE format)
    for (uint64_t i = 0; i < len_bytes; i++){
        t[i/4] |= ((uint64_t)r_bytes[i] << ((i%4)*8)); 
    }

    r[0] = (uint32_t)(t[0]) & mask_lowest_26bits; // get lowest 26 bits
    // (t[0] >> 26) only contains 6 non-zero bits (discarded the lowest 26 we saved before), 
    // thus shift t[1] by 6 bits, add them together 
    // and keep only lowest 26
    int left_shift = 6;
    int right_shift = 26;
    for(int i = 0; i < 4; i++){
        r[i+1] = (uint32_t)((t[i] >> right_shift) | (t[i+1] << left_shift)) & mask_lowest_26bits; // get next 26 bits

        left_shift += 6;
        right_shift -= 6;
    }
    
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

        // 2. Addition (Limbs may now exceed 26 bits)
        for (int i = 0; i < 5; i++) acc[i] += n[i];


        // acc = (acc * r) mod p
        uint64_t mult[5];

        // compute acc*r - if exceed 2^130 (= if indices i + j = 5), multiply by 5
        mult[0] = (uint64_t)acc[0]*r0 + (uint64_t)acc[1]*r4_5 + (uint64_t)acc[2]*r3_5 + (uint64_t)acc[3]*r2_5 + (uint64_t)acc[4]*r1_5;
        mult[1] = (uint64_t)acc[0]*r1 + (uint64_t)acc[1]*r0   + (uint64_t)acc[2]*r4_5 + (uint64_t)acc[3]*r3_5 + (uint64_t)acc[4]*r2_5;
        mult[2] = (uint64_t)acc[0]*r2 + (uint64_t)acc[1]*r1   + (uint64_t)acc[2]*r0   + (uint64_t)acc[3]*r4_5 + (uint64_t)acc[4]*r3_5;
        mult[3] = (uint64_t)acc[0]*r3 + (uint64_t)acc[1]*r2   + (uint64_t)acc[2]*r1   + (uint64_t)acc[3]*r0   + (uint64_t)acc[4]*r4_5;
        mult[4] = (uint64_t)acc[0]*r4 + (uint64_t)acc[1]*r3   + (uint64_t)acc[2]*r2   + (uint64_t)acc[3]*r1   + (uint64_t)acc[4]*r0;

        // distirbute the "overflow" of each mult[i] to the next one
        uint64_t carry = 0;
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

    // now check whether carry from mult caused acc array to represent number larger than p (=2^130 - 5) 
    // (can happen even if never exceed 26 bits) - if so, compute modulo p again
    //Putting this part out is not improving performance and I think he evaluation wouldn't be correct for bigger lengths
    uint32_t g[5];

    uint64_t carry = 5; // add 5 to acc, so if we surpass p, we will have 27 bits in last carry
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


unsigned char* no_brenches_not_inlined_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
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


unsigned char* parallel_inlined_create_tag(uint32_t final_acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len) {
    const uint32_t mask26 = 0x3ffffff;
    const uint64_t mask32 = 0xffffffffULL;
    
    memset(final_acc, 0, 5 * sizeof(uint32_t));

    uint64_t full_blocks = data_len / 16;
    uint64_t parallel_chunks = full_blocks / 4;
    uint64_t remainder = data_len % 16;

    // --- 1. Precompute r^2, r^3, r^4 ---
    uint32_t r_pow[4][5]; // [0]=r, [1]=r^2, [2]=r^3, [3]=r^4
    memcpy(r_pow[0], r, 5 * sizeof(uint32_t));
    
    for (int p = 1; p < 4; p++) {
        // r_pow[p] = r_pow[p-1] * r
        uint64_t a64[5], r64[5], m[5];
        for (int k = 0; k < 5; k++) { a64[k] = r_pow[p-1][k]; r64[k] = r[k]; }
        m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
        m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
        m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
        m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
        m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
        
        uint64_t c = 0;
        for(int k = 0; k < 4; k++) { c = m[k] >> 26; r_pow[p][k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
        c = m[4] >> 26; r_pow[p][4] = (uint32_t)(m[4] & mask26);
        r_pow[p][0] += (uint32_t)(c * 5);
        c = r_pow[p][0] >> 26; r_pow[p][0] &= mask26; r_pow[p][1] += (uint32_t)c;
    }

    // --- 2. Parallel Processing ---
    uint32_t acc[4][5] = {{0}};
    const uint8_t* curr_data = data;

    for (uint64_t i = 0; i < parallel_chunks; i++) {
        for (int j = 0; j < 4; j++) {
            const uint8_t* b = curr_data + (j * 16);
            uint32_t n[5];
            uint32_t w0 = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
            uint32_t w1 = (uint32_t)b[4] | ((uint32_t)b[5] << 8) | ((uint32_t)b[6] << 16) | ((uint32_t)b[7] << 24);
            uint32_t w2 = (uint32_t)b[8] | ((uint32_t)b[9] << 8) | ((uint32_t)b[10] << 16) | ((uint32_t)b[11] << 24);
            uint32_t w3 = (uint32_t)b[12] | ((uint32_t)b[13] << 8) | ((uint32_t)b[14] << 16) | ((uint32_t)b[15] << 24);

            n[0] = w0 & mask26;
            n[1] = ((w0 >> 26) | (w1 << 6)) & mask26;
            n[2] = ((w1 >> 20) | (w2 << 12)) & mask26;
            n[3] = ((w2 >> 14) | (w3 << 18)) & mask26;
            n[4] = (w3 >> 8) | (1u << 24);

            // Add block to accumulator
            uint64_t carry = 0;
            for (int k = 0; k < 5; k++) {
                carry = (uint64_t)acc[j][k] + n[k] + carry;
                acc[j][k] = (uint32_t)(carry & mask26);
                carry >>= 26;
            }
            acc[j][0] += (uint32_t)(carry * 5);

            // Multiply ONLY IF there is another chunk coming. 
            // If this is the last chunk, we multiply by the alignment powers in Section 3.
            if (i < parallel_chunks - 1) {
                uint64_t a64[5], r64[5], m[5];
                for (int k = 0; k < 5; k++) { a64[k] = acc[j][k]; r64[k] = r_pow[3][k]; } // r^4
                m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
                m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
                m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
                m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
                m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
                
                uint64_t c = 0;
                for(int k = 0; k < 4; k++) { c = m[k] >> 26; acc[j][k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
                c = m[4] >> 26; acc[j][4] = (uint32_t)(m[4] & mask26);
                acc[j][0] += (uint32_t)(c * 5);
                c = acc[j][0] >> 26; acc[j][0] &= mask26; acc[j][1] += (uint32_t)c;
            }
        }
        curr_data += 64;
    }

    // --- 3. Horizontal Summation ---
    // Align each stream: Stream 0 needs r^4, Stream 1 needs r^3, Stream 2 needs r^2, Stream 3 needs r^1
    uint32_t* align_powers[4] = {r_pow[3], r_pow[2], r_pow[1], r_pow[0]};
    for (int j = 0; j < 4 && parallel_chunks > 0; j++) {
        uint64_t a64[5], r64[5], m[5];
        for (int k = 0; k < 5; k++) { a64[k] = acc[j][k]; r64[k] = align_powers[j][k]; }
        m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
        m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
        m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
        m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
        m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
        
        uint64_t c = 0;
        for(int k = 0; k < 4; k++) { c = m[k] >> 26; acc[j][k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
        c = m[4] >> 26; acc[j][4] = (uint32_t)(m[4] & mask26);
        acc[j][0] += (uint32_t)(c * 5);
        c = acc[j][0] >> 26; acc[j][0] &= mask26; acc[j][1] += (uint32_t)c;

        // Sum into final_acc
        uint64_t carry = 0;
        for (int k = 0; k < 5; k++) {
            carry = (uint64_t)final_acc[k] + acc[j][k] + carry;
            final_acc[k] = (uint32_t)(carry & mask26);
            carry >>= 26;
        }
        final_acc[0] += (uint32_t)(carry * 5);
        c = final_acc[0] >> 26; final_acc[0] &= mask26; final_acc[1] += (uint32_t)c;
    }

    // --- 4. Handle remaining blocks ---
    uint64_t remaining_full = full_blocks % 4;
    for (uint64_t i = 0; i < remaining_full + (remainder > 0 ? 1 : 0); i++) {
        uint32_t n[5];
        uint8_t block[17] = {0};
        uint64_t len = 16;
        if (i < remaining_full) {
            memcpy(block, curr_data, 16);
            block[16] = 0x01;
            curr_data += 16;
        } else {
            memcpy(block, curr_data, remainder);
            block[remainder] = 0x01;
            len = remainder;
        }

        // Standard unpacking
        uint64_t t[5] = {0};
        for (int k = 0; k < 17; k++) t[k/4] |= ((uint64_t)block[k] << ((k%4)*8));
        n[0] = (uint32_t)t[0] & mask26;
        n[1] = (uint32_t)((t[0] >> 26) | (t[1] << 6)) & mask26;
        n[2] = (uint32_t)((t[1] >> 20) | (t[2] << 12)) & mask26;
        n[3] = (uint32_t)((t[2] >> 14) | (t[3] << 18)) & mask26;
        n[4] = (uint32_t)((t[3] >> 8) | (t[4] << 24)) & mask26;

        // final_acc = (final_acc + n) * r
        uint64_t carry = 0;
        for (int k = 0; k < 5; k++) {
            carry = (uint64_t)final_acc[k] + n[k] + carry;
            final_acc[k] = (uint32_t)(carry & mask26);
            carry >>= 26;
        }
        final_acc[0] += (uint32_t)(carry * 5);
        uint32_t c = final_acc[0] >> 26; final_acc[0] &= mask26; final_acc[1] += c;

        uint64_t a64[5], r64[5], m[5];
        for (int k = 0; k < 5; k++) { a64[k] = final_acc[k]; r64[k] = r[k]; }
        m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
        m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
        m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
        m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
        m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
        c = 0;
        for(int k = 0; k < 4; k++) { c = m[k] >> 26; final_acc[k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
        c = m[4] >> 26; final_acc[4] = (uint32_t)(m[4] & mask26);
        final_acc[0] += (uint32_t)(c * 5);
        c = final_acc[0] >> 26; final_acc[0] &= mask26; final_acc[1] += (uint32_t)c;
    }

    // --- 5. Final Reduce and Repack ---
    // (Ensure final_acc is normalized to < 2^130-5)
    uint32_t g[5];
    uint64_t carry = 5; 
    for (int i = 0; i < 5; i++) {
        carry += final_acc[i];
        g[i] = (uint32_t)(carry & mask26);
        carry >>= 26;
    }
    if (carry > 0) memcpy(final_acc, g, 5 * sizeof(uint32_t));

    uint64_t conv[4];
    conv[0] = ((uint64_t)final_acc[0]) | ((uint64_t)final_acc[1] << 26);
    conv[1] = ((uint64_t)final_acc[1] >> 6) | ((uint64_t)final_acc[2] << 20);
    conv[2] = ((uint64_t)final_acc[2] >> 12) | ((uint64_t)final_acc[3] << 14);
    conv[3] = ((uint64_t)final_acc[3] >> 18) | ((uint64_t)final_acc[4] << 8);

    unsigned char* tag = (unsigned char*)malloc(16);
    uint64_t c = 0;
    for(int i = 0; i < 4; i++){
        c += (conv[i] & mask32) + s[i];
        uint32_t val = (uint32_t)c;
        tag[i*4] = val & 0xff; tag[i*4+1] = (val>>8) & 0xff; tag[i*4+2] = (val>>16) & 0xff; tag[i*4+3] = (val>>24) & 0xff;
        c >>= 32;
    }
    return tag;
}


unsigned char* unrolled_parallel_inlined_create_tag(uint32_t final_acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len) {
    const uint32_t mask26 = 0x3ffffff;
    const uint64_t mask32 = 0xffffffffULL;
    
    memset(final_acc, 0, 5 * sizeof(uint32_t));

    uint64_t full_blocks = data_len / 16;
    uint64_t parallel_chunks = full_blocks / 4;
    uint64_t remainder = data_len % 16;


    uint32_t r_pow[4][5]; // [0]=r, [1]=r^2, [2]=r^3, [3]=r^4
    memcpy(r_pow[0], r, 5 * sizeof(uint32_t));
    
    for (int p = 1; p < 4; p++) {
        // r_pow[p] = r_pow[p-1] * r
        uint64_t a64[5], r64[5], m[5];
        for (int k = 0; k < 5; k++) { a64[k] = r_pow[p-1][k]; r64[k] = r[k]; }
        m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
        m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
        m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
        m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
        m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
        
        uint64_t c = 0;
        for(int k = 0; k < 4; k++) { c = m[k] >> 26; r_pow[p][k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
        c = m[4] >> 26; r_pow[p][4] = (uint32_t)(m[4] & mask26);
        r_pow[p][0] += (uint32_t)(c * 5);
        c = r_pow[p][0] >> 26; r_pow[p][0] &= mask26; r_pow[p][1] += (uint32_t)c;
    }

    uint32_t acc[4][5] = {{0}};
    const uint8_t* curr_data = data;

    
    for (int i = 0; i < parallel_chunks; i++) {
            const uint8_t* b_0 = curr_data + (0 * 16);
            //just calculating n_0 directly, without a loop since len_bytes is always the same
            //calculating w0_i already as uint32_t not as uint64_t
            uint32_t n_0[5];
            uint32_t w0_0 = (uint32_t)b_0[0] | ((uint32_t)b_0[1] << 8) | ((uint32_t)b_0[2] << 16) | ((uint32_t)b_0[3] << 24);
            uint32_t w1_0 = (uint32_t)b_0[4] | ((uint32_t)b_0[5] << 8) | ((uint32_t)b_0[6] << 16) | ((uint32_t)b_0[7] << 24);
            uint32_t w2_0 = (uint32_t)b_0[8] | ((uint32_t)b_0[9] << 8) | ((uint32_t)b_0[10] << 16) | ((uint32_t)b_0[11] << 24);
            uint32_t w3_0 = (uint32_t)b_0[12] | ((uint32_t)b_0[13] << 8) | ((uint32_t)b_0[14] << 16) | ((uint32_t)b_0[15] << 24);

            //right_shifts = 26; left_shift = 6
            //left_shift += 6; right_shift -= 6;
            n_0[0] = w0_0 & mask26;
            n_0[1] = ((w0_0 >> 26) | (w1_0 << 6)) & mask26;
            n_0[2] = ((w1_0 >> 20) | (w2_0 << 12)) & mask26;
            n_0[3] = ((w2_0 >> 14) | (w3_0 << 18)) & mask26;
            n_0[4] = (w3_0 >> 8) | (1u << 24);

            // Add block to accumulator
            uint64_t carry_0 = 0;
            for (int k = 0; k < 5; k++) {
                carry_0 = (uint64_t)acc[0][k] + n_0[k] + carry_0;
                acc[0][k] = (uint32_t)(carry_0 & mask26);
                carry_0 >>= 26;
            }
            acc[0][0] += (uint32_t)(carry_0 * 5);

            // Multiply ONLY IF there is another chunk coming. 
            if (i < parallel_chunks - 1) {
                uint64_t a64_0[5], m_0[5], r64_0[5];
                for (int k = 0; k < 5; k++) { a64_0[k] = acc[0][k]; r64_0[k] = r_pow[3][k]; } // r^4
                m_0[0] = a64_0[0]*r64_0[0] + 5*(a64_0[1]*r64_0[4] + a64_0[2]*r64_0[3] + a64_0[3]*r64_0[2] + a64_0[4]*r64_0[1]);
                m_0[1] = a64_0[0]*r64_0[1] + a64_0[1]*r64_0[0] + 5*(a64_0[2]*r64_0[4] + a64_0[3]*r64_0[3] + a64_0[4]*r64_0[2]);
                m_0[2] = a64_0[0]*r64_0[2] + a64_0[1]*r64_0[1] + a64_0[2]*r64_0[0] + 5*(a64_0[3]*r64_0[4] + a64_0[4]*r64_0[3]);
                m_0[3] = a64_0[0]*r64_0[3] + a64_0[1]*r64_0[2] + a64_0[2]*r64_0[1] + a64_0[3]*r64_0[0] + 5*(a64_0[4]*r64_0[4]);
                m_0[4] = a64_0[0]*r64_0[4] + a64_0[1]*r64_0[3] + a64_0[2]*r64_0[2] + a64_0[3]*r64_0[1] + a64_0[4]*r64_0[0];
                
                uint64_t c_0 = 0;
                for(int k = 0; k < 4; k++) { c_0 = m_0[k] >> 26; acc[0][k] = (uint32_t)(m_0[k] & mask26); m_0[k+1] += c_0; }
                c_0 = m_0[4] >> 26; acc[0][4] = (uint32_t)(m_0[4] & mask26);
                acc[0][0] += (uint32_t)(c_0 * 5);
                c_0 = acc[0][0] >> 26; acc[0][0] &= mask26; acc[0][1] += (uint32_t)c_0;
            }

            const uint8_t* b_1 = curr_data + (1 * 16);
            uint32_t n_1[5];
            uint32_t w0_1 = (uint32_t)b_1[0] | ((uint32_t)b_1[1] << 8) | ((uint32_t)b_1[2] << 16) | ((uint32_t)b_1[3] << 24);
            uint32_t w1_1 = (uint32_t)b_1[4] | ((uint32_t)b_1[5] << 8) | ((uint32_t)b_1[6] << 16) | ((uint32_t)b_1[7] << 24);
            uint32_t w2_1 = (uint32_t)b_1[8] | ((uint32_t)b_1[9] << 8) | ((uint32_t)b_1[10] << 16) | ((uint32_t)b_1[11] << 24);
            uint32_t w3_1 = (uint32_t)b_1[12] | ((uint32_t)b_1[13] << 8) | ((uint32_t)b_1[14] << 16) | ((uint32_t)b_1[15] << 24);

            n_1[0] = w0_1 & mask26;
            n_1[1] = ((w0_1 >> 26) | (w1_1 << 6)) & mask26;
            n_1[2] = ((w1_1 >> 20) | (w2_1 << 12)) & mask26;
            n_1[3] = ((w2_1 >> 14) | (w3_1 << 18)) & mask26;
            n_1[4] = (w3_1 >> 8) | (1u << 24);

            uint64_t carry_1 = 0;
            for (int k = 0; k < 5; k++) {
                carry_1 = (uint64_t)acc[1][k] + n_1[k] + carry_1;
                acc[1][k] = (uint32_t)(carry_1 & mask26);
                carry_1 >>= 26;
            }
            acc[1][0] += (uint32_t)(carry_1 * 5);

            if (i < parallel_chunks - 1) {
                uint64_t a64_1[5], r64_1[5], m_1[5];
                for (int k = 0; k < 5; k++) { a64_1[k] = acc[1][k]; r64_1[k] = r_pow[3][k]; } // r^4
                m_1[0] = a64_1[0]*r64_1[0] + 5*(a64_1[1]*r64_1[4] + a64_1[2]*r64_1[3] + a64_1[3]*r64_1[2] + a64_1[4]*r64_1[1]);
                m_1[1] = a64_1[0]*r64_1[1] + a64_1[1]*r64_1[0] + 5*(a64_1[2]*r64_1[4] + a64_1[3]*r64_1[3] + a64_1[4]*r64_1[2]);
                m_1[2] = a64_1[0]*r64_1[2] + a64_1[1]*r64_1[1] + a64_1[2]*r64_1[0] + 5*(a64_1[3]*r64_1[4] + a64_1[4]*r64_1[3]);
                m_1[3] = a64_1[0]*r64_1[3] + a64_1[1]*r64_1[2] + a64_1[2]*r64_1[1] + a64_1[3]*r64_1[0] + 5*(a64_1[4]*r64_1[4]);
                m_1[4] = a64_1[0]*r64_1[4] + a64_1[1]*r64_1[3] + a64_1[2]*r64_1[2] + a64_1[3]*r64_1[1] + a64_1[4]*r64_1[0];
                
                uint64_t c_1 = 0;
                for(int k = 0; k < 4; k++) { c_1 = m_1[k] >> 26; acc[1][k] = (uint32_t)(m_1[k] & mask26); m_1[k+1] += c_1; }
                c_1 = m_1[4] >> 26; acc[1][4] = (uint32_t)(m_1[4] & mask26);
                acc[1][0] += (uint32_t)(c_1 * 5);
                c_1 = acc[1][0] >> 26; acc[1][0] &= mask26; acc[1][1] += (uint32_t)c_1;
            }


            const uint8_t* b_2 = curr_data + 32;
            uint32_t w0_2 = (uint32_t)b_2[0] | ((uint32_t)b_2[1] << 8) | ((uint32_t)b_2[2] << 16) | ((uint32_t)b_2[3] << 24);
            uint32_t w1_2 = (uint32_t)b_2[4] | ((uint32_t)b_2[5] << 8) | ((uint32_t)b_2[6] << 16) | ((uint32_t)b_2[7] << 24);
            uint32_t w2_2 = (uint32_t)b_2[8] | ((uint32_t)b_2[9] << 8) | ((uint32_t)b_2[10] << 16) | ((uint32_t)b_2[11] << 24);
            uint32_t w3_2 = (uint32_t)b_2[12] | ((uint32_t)b_2[13] << 8) | ((uint32_t)b_2[14] << 16) | ((uint32_t)b_2[15] << 24);

            uint32_t n_2[5];
            n_2[0] = w0_2 & mask26;
            n_2[1] = ((w0_2 >> 26) | (w1_2 << 6)) & mask26;
            n_2[2] = ((w1_2 >> 20) | (w2_2 << 12)) & mask26;
            n_2[3] = ((w2_2 >> 14) | (w3_2 << 18)) & mask26;
            n_2[4] = (w3_2 >> 8) | (1u << 24);

            uint64_t carry_2 = 0;
            for (int k = 0; k < 5; k++) {
                carry_2 = (uint64_t)acc[2][k] + n_2[k] + carry_2;
                acc[2][k] = (uint32_t)(carry_2 & mask26);
                carry_2 >>= 26;
            }
            acc[2][0] += (uint32_t)(carry_2 * 5);

            if (i < parallel_chunks - 1) {
                uint64_t a64_2[5], r64_2[5], m_2[5];
                for (int k = 0; k < 5; k++) { a64_2[k] = acc[2][k]; r64_2[k] = r_pow[3][k]; } // r^4
                m_2[0] = a64_2[0]*r64_2[0] + 5*(a64_2[1]*r64_2[4] + a64_2[2]*r64_2[3] + a64_2[3]*r64_2[2] + a64_2[4]*r64_2[1]);
                m_2[1] = a64_2[0]*r64_2[1] + a64_2[1]*r64_2[0] + 5*(a64_2[2]*r64_2[4] + a64_2[3]*r64_2[3] + a64_2[4]*r64_2[2]);
                m_2[2] = a64_2[0]*r64_2[2] + a64_2[1]*r64_2[1] + a64_2[2]*r64_2[0] + 5*(a64_2[3]*r64_2[4] + a64_2[4]*r64_2[3]);
                m_2[3] = a64_2[0]*r64_2[3] + a64_2[1]*r64_2[2] + a64_2[2]*r64_2[1] + a64_2[3]*r64_2[0] + 5*(a64_2[4]*r64_2[4]);
                m_2[4] = a64_2[0]*r64_2[4] + a64_2[1]*r64_2[3] + a64_2[2]*r64_2[2] + a64_2[3]*r64_2[1] + a64_2[4]*r64_2[0];
                
                uint64_t c_2 = 0;
                for(int k = 0; k < 4; k++) { c_2 = m_2[k] >> 26; acc[2][k] = (uint32_t)(m_2[k] & mask26); m_2[k+1] += c_2; }
                c_2 = m_2[4] >> 26; acc[2][4] = (uint32_t)(m_2[4] & mask26);
                acc[2][0] += (uint32_t)(c_2 * 5);
                c_2 = acc[2][0] >> 26; acc[2][0] &= mask26; acc[2][1] += (uint32_t)c_2;
            }

            const uint8_t* b_3 = curr_data + 48;
            uint32_t w0_3 = (uint32_t)b_3[0] | ((uint32_t)b_3[1] << 8) | ((uint32_t)b_3[2] << 16) | ((uint32_t)b_3[3] << 24);
            uint32_t w1_3 = (uint32_t)b_3[4] | ((uint32_t)b_3[5] << 8) | ((uint32_t)b_3[6] << 16) | ((uint32_t)b_3[7] << 24);
            uint32_t w2_3 = (uint32_t)b_3[8] | ((uint32_t)b_3[9] << 8) | ((uint32_t)b_3[10] << 16) | ((uint32_t)b_3[11] << 24);
            uint32_t w3_3 = (uint32_t)b_3[12] | ((uint32_t)b_3[13] << 8) | ((uint32_t)b_3[14] << 16) | ((uint32_t)b_3[15] << 24);

            uint32_t n_3[5];
            n_3[0] = w0_3 & mask26;
            n_3[1] = ((w0_3 >> 26) | (w1_3 << 6)) & mask26;
            n_3[2] = ((w1_3 >> 20) | (w2_3 << 12)) & mask26;
            n_3[3] = ((w2_3 >> 14) | (w3_3 << 18)) & mask26;
            n_3[4] = (w3_3 >> 8) | (1u << 24);

            uint64_t carry_3 = 0;
            for (int k = 0; k < 5; k++) {
                carry_3 = (uint64_t)acc[3][k] + n_3[k] + carry_3;
                acc[3][k] = (uint32_t)(carry_3 & mask26);
                carry_3 >>= 26;
            }
            acc[3][0] += (uint32_t)(carry_3 * 5);

            if (i < parallel_chunks - 1) {
                uint64_t a64_3[5], r64_3[5], m_3[5];
                for (int k = 0; k < 5; k++) { a64_3[k] = acc[3][k]; r64_3[k] = r_pow[3][k]; } // r^4
                m_3[0] = a64_3[0]*r64_3[0] + 5*(a64_3[1]*r64_3[4] + a64_3[2]*r64_3[3] + a64_3[3]*r64_3[2] + a64_3[4]*r64_3[1]);
                m_3[1] = a64_3[0]*r64_3[1] + a64_3[1]*r64_3[0] + 5*(a64_3[2]*r64_3[4] + a64_3[3]*r64_3[3] + a64_3[4]*r64_3[2]);
                m_3[2] = a64_3[0]*r64_3[2] + a64_3[1]*r64_3[1] + a64_3[2]*r64_3[0] + 5*(a64_3[3]*r64_3[4] + a64_3[4]*r64_3[3]);
                m_3[3] = a64_3[0]*r64_3[3] + a64_3[1]*r64_3[2] + a64_3[2]*r64_3[1] + a64_3[3]*r64_3[0] + 5*(a64_3[4]*r64_3[4]);
                m_3[4] = a64_3[0]*r64_3[4] + a64_3[1]*r64_3[3] + a64_3[2]*r64_3[2] + a64_3[3]*r64_3[1] + a64_3[4]*r64_3[0];
                
                uint64_t c_3 = 0;
                for(int k = 0; k < 4; k++) { c_3 = m_3[k] >> 26; acc[3][k] = (uint32_t)(m_3[k] & mask26); m_3[k+1] += c_3; }
                c_3 = m_3[4] >> 26; acc[3][4] = (uint32_t)(m_3[4] & mask26);
                acc[3][0] += (uint32_t)(c_3 * 5);
                c_3 = acc[3][0] >> 26; acc[3][0] &= mask26; acc[3][1] += (uint32_t)c_3;
            }
        
        curr_data += 64;
    }

    // Align streams: Stream 0 needs r^4, Stream 1 needs r^3, Stream 2 needs r^2, Stream 3 needs r^1
    uint32_t* align_powers[4] = {r_pow[3], r_pow[2], r_pow[1], r_pow[0]};
    for (int j = 0; j < 4 && parallel_chunks > 0; j++) {
        uint64_t a64[5], r64[5], m[5];
        for (int k = 0; k < 5; k++) { a64[k] = acc[j][k]; r64[k] = align_powers[j][k]; }
        m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
        m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
        m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
        m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
        m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
        
        uint64_t c = 0;
        for(int k = 0; k < 4; k++) { c = m[k] >> 26; acc[j][k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
        c = m[4] >> 26; acc[j][4] = (uint32_t)(m[4] & mask26);
        acc[j][0] += (uint32_t)(c * 5);
        c = acc[j][0] >> 26; acc[j][0] &= mask26; acc[j][1] += (uint32_t)c;

        // Summ into final_acc
        uint64_t carry = 0;
        for (int k = 0; k < 5; k++) {
            carry = (uint64_t)final_acc[k] + acc[j][k] + carry;
            final_acc[k] = (uint32_t)(carry & mask26);
            carry >>= 26;
        }
        final_acc[0] += (uint32_t)(carry * 5);
        c = final_acc[0] >> 26; final_acc[0] &= mask26; final_acc[1] += (uint32_t)c;
    }

    //Remaining blocks
    uint64_t remaining_full = full_blocks % 4;
    for (uint64_t i = 0; i < remaining_full + (remainder > 0 ? 1 : 0); i++) {
        uint32_t n[5];
        uint8_t block[17] = {0};
        uint64_t len = 16;
        if (i < remaining_full) {
            memcpy(block, curr_data, 16);
            block[16] = 0x01;
            curr_data += 16;
        } else {
            memcpy(block, curr_data, remainder);
            block[remainder] = 0x01;
            len = remainder;
        }


        uint64_t t[5] = {0};
        for (int k = 0; k < 17; k++) t[k/4] |= ((uint64_t)block[k] << ((k%4)*8));
        n[0] = (uint32_t)t[0] & mask26;
        n[1] = (uint32_t)((t[0] >> 26) | (t[1] << 6)) & mask26;
        n[2] = (uint32_t)((t[1] >> 20) | (t[2] << 12)) & mask26;
        n[3] = (uint32_t)((t[2] >> 14) | (t[3] << 18)) & mask26;
        n[4] = (uint32_t)((t[3] >> 8) | (t[4] << 24)) & mask26;

        // final_acc = (final_acc + n) * r
        uint64_t carry = 0;
        for (int k = 0; k < 5; k++) {
            carry = (uint64_t)final_acc[k] + n[k] + carry;
            final_acc[k] = (uint32_t)(carry & mask26);
            carry >>= 26;
        }
        final_acc[0] += (uint32_t)(carry * 5);
        uint32_t c = final_acc[0] >> 26; final_acc[0] &= mask26; final_acc[1] += c;

        uint64_t a64[5], r64[5], m[5];
        for (int k = 0; k < 5; k++) { a64[k] = final_acc[k]; r64[k] = r[k]; }
        m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
        m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
        m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
        m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
        m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
        c = 0;
        for(int k = 0; k < 4; k++) { c = m[k] >> 26; final_acc[k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
        c = m[4] >> 26; final_acc[4] = (uint32_t)(m[4] & mask26);
        final_acc[0] += (uint32_t)(c * 5);
        c = final_acc[0] >> 26; final_acc[0] &= mask26; final_acc[1] += (uint32_t)c;
    }

    // Ensure final_acc < 2^130-5
    //no need to do it each time in the main loop, just once at the end
    uint32_t g[5];
    uint64_t carry = 5; 
    for (int i = 0; i < 5; i++) {
        carry += final_acc[i];
        g[i] = (uint32_t)(carry & mask26);
        carry >>= 26;
    }
    if (carry > 0) memcpy(final_acc, g, 5 * sizeof(uint32_t));

    uint64_t conv[4];
    conv[0] = ((uint64_t)final_acc[0]) | ((uint64_t)final_acc[1] << 26);
    conv[1] = ((uint64_t)final_acc[1] >> 6) | ((uint64_t)final_acc[2] << 20);
    conv[2] = ((uint64_t)final_acc[2] >> 12) | ((uint64_t)final_acc[3] << 14);
    conv[3] = ((uint64_t)final_acc[3] >> 18) | ((uint64_t)final_acc[4] << 8);

    unsigned char* tag = (unsigned char*)malloc(16);
    uint64_t c = 0;
    for(int i = 0; i < 4; i++){
        c += (conv[i] & mask32) + s[i];
        uint32_t val = (uint32_t)c;
        tag[i*4] = val & 0xff; tag[i*4+1] = (val>>8) & 0xff; tag[i*4+2] = (val>>16) & 0xff; tag[i*4+3] = (val>>24) & 0xff;
        c >>= 32;
    }
    return tag;
}




//Just doesn't work
/*unsigned char* delayed_carry_create_tag(uint32_t final_acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len) {
    const uint32_t mask26 = 0x3ffffff;
    const uint64_t mask32 = 0xffffffffULL;
    
    memset(final_acc, 0, 5 * sizeof(uint32_t));

    uint64_t full_blocks = data_len / 16;
    uint64_t parallel_chunks = full_blocks / 8;
    uint64_t remainder = data_len % 16;


    uint32_t r_pow[8][5]; // [0]=r, [1]=r^2, [2]=r^3, [3]=r^4
    memcpy(r_pow[0], r, 5 * sizeof(uint32_t));
    
    for (int p = 1; p < 8; p++) {
        // r_pow[p] = r_pow[p-1] * r
        uint64_t a64[5], r64[5], m[5];
        for (int k = 0; k < 5; k++) { a64[k] = r_pow[p-1][k]; r64[k] = r[k]; }
        m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
        m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
        m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
        m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
        m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
        
        uint64_t c = 0;
        for(int k = 0; k < 4; k++) { c = m[k] >> 26; r_pow[p][k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
        c = m[4] >> 26; r_pow[p][4] = (uint32_t)(m[4] & mask26);
        r_pow[p][0] += (uint32_t)(c * 5);
        c = r_pow[p][0] >> 26; r_pow[p][0] &= mask26; r_pow[p][1] += (uint32_t)c;
    }

    uint32_t acc[4][5] = {{0}}; //acc keeps track of computed 4 Hash values
    const uint8_t* curr_data = data;

    
    for (int i = 0; i < parallel_chunks; i++) {
            const uint8_t* b_0 = curr_data + (0 * 16);
            const uint8_t* d_0 = curr_data + (16*4);
            //just calculating n_0 directly, without a loop since len_bytes is always the same
            //calculating w0_i already as uint32_t not as uint64_t
            uint32_t n_0[5];
            uint32_t u_0[5];

            uint32_t w0_0 = (uint32_t)b_0[0] | ((uint32_t)b_0[1] << 8) | ((uint32_t)b_0[2] << 16) | ((uint32_t)b_0[3] << 24);
            uint32_t w1_0 = (uint32_t)b_0[4] | ((uint32_t)b_0[5] << 8) | ((uint32_t)b_0[6] << 16) | ((uint32_t)b_0[7] << 24);
            uint32_t w2_0 = (uint32_t)b_0[8] | ((uint32_t)b_0[9] << 8) | ((uint32_t)b_0[10] << 16) | ((uint32_t)b_0[11] << 24);
            uint32_t w3_0 = (uint32_t)b_0[12] | ((uint32_t)b_0[13] << 8) | ((uint32_t)b_0[14] << 16) | ((uint32_t)b_0[15] << 24);
        
            uint32_t v0_0 = (uint32_t)d_0[0] | ((uint32_t)d_0[1] << 8) | ((uint32_t)d_0[2] << 16) | ((uint32_t)d_0[3] << 24);
            uint32_t v1_0 = (uint32_t)d_0[4] | ((uint32_t)d_0[5] << 8) | ((uint32_t)d_0[6] << 16) | ((uint32_t)d_0[7] << 24);
            uint32_t v2_0 = (uint32_t)d_0[8] | ((uint32_t)d_0[9] << 8) | ((uint32_t)d_0[10] << 16) | ((uint32_t)d_0[11] << 24);
            uint32_t v3_0 = (uint32_t)d_0[12] | ((uint32_t)d_0[13] << 8) | ((uint32_t)d_0[14] << 16) | ((uint32_t)d_0[15] << 24);

            //right_shifts = 26; left_shift = 6
            //left_shift += 6; right_shift -= 6;
            n_0[0] = w0_0 & mask26;
            n_0[1] = ((w0_0 >> 26) | (w1_0 << 6)) & mask26;
            n_0[2] = ((w1_0 >> 20) | (w2_0 << 12)) & mask26;
            n_0[3] = ((w2_0 >> 14) | (w3_0 << 18)) & mask26;
            n_0[4] = (w3_0 >> 8) | (1u << 24);

            u_0[0] = v0_0 & mask26;
            u_0[1] = ((v0_0 >> 26) | (v1_0 << 6)) & mask26;
            u_0[2] = ((v1_0 >> 20) | (v2_0 << 12)) & mask26;
            u_0[3] = ((v2_0 >> 14) | (v3_0 << 18)) & mask26;
            u_0[4] = (v3_0 >> 8) | (1u << 24);
    

            uint64_t a64_0[5], m_0[5], r64_0[5];
            for (int k = 0; k < 5; k++) { a64_0[k] = acc[0][k]; r64_0[k] = r_pow[7][k]; } // r^8
            m_0[0] = a64_0[0]*r64_0[0] + 5*(a64_0[1]*r64_0[4] + a64_0[2]*r64_0[3] + a64_0[3]*r64_0[2] + a64_0[4]*r64_0[1]);
            m_0[1] = a64_0[0]*r64_0[1] + a64_0[1]*r64_0[0] + 5*(a64_0[2]*r64_0[4] + a64_0[3]*r64_0[3] + a64_0[4]*r64_0[2]);
            m_0[2] = a64_0[0]*r64_0[2] + a64_0[1]*r64_0[1] + a64_0[2]*r64_0[0] + 5*(a64_0[3]*r64_0[4] + a64_0[4]*r64_0[3]);
            m_0[3] = a64_0[0]*r64_0[3] + a64_0[1]*r64_0[2] + a64_0[2]*r64_0[1] + a64_0[3]*r64_0[0] + 5*(a64_0[4]*r64_0[4]);
            m_0[4] = a64_0[0]*r64_0[4] + a64_0[1]*r64_0[3] + a64_0[2]*r64_0[2] + a64_0[3]*r64_0[1] + a64_0[4]*r64_0[0];
            
            uint64_t c_0 = 0;
            for(int k = 0; k < 4; k++) { c_0 = m_0[k] >> 26; acc[0][k] = (uint32_t)(m_0[k] & mask26); m_0[k+1] += c_0; }
            c_0 = m_0[4] >> 26; acc[0][4] = (uint32_t)(m_0[4] & mask26);
            acc[0][0] += (uint32_t)(c_0 * 5);
            c_0 = acc[0][0] >> 26; acc[0][0] &= mask26; acc[0][1] += (uint32_t)c_0;
            

            // Multiply ONLY IF there is another chunk coming. 

            //uint64_t a64_0[5], m_0[5], r64_0[5];
            for (int k = 0; k < 5; k++) { a64_0[k] = n_0[k]; r64_0[k] = r_pow[3][k]; } // r^4
            m_0[0] = a64_0[0]*r64_0[0] + 5*(a64_0[1]*r64_0[4] + a64_0[2]*r64_0[3] + a64_0[3]*r64_0[2] + a64_0[4]*r64_0[1]);
            m_0[1] = a64_0[0]*r64_0[1] + a64_0[1]*r64_0[0] + 5*(a64_0[2]*r64_0[4] + a64_0[3]*r64_0[3] + a64_0[4]*r64_0[2]);
            m_0[2] = a64_0[0]*r64_0[2] + a64_0[1]*r64_0[1] + a64_0[2]*r64_0[0] + 5*(a64_0[3]*r64_0[4] + a64_0[4]*r64_0[3]);
            m_0[3] = a64_0[0]*r64_0[3] + a64_0[1]*r64_0[2] + a64_0[2]*r64_0[1] + a64_0[3]*r64_0[0] + 5*(a64_0[4]*r64_0[4]);
            m_0[4] = a64_0[0]*r64_0[4] + a64_0[1]*r64_0[3] + a64_0[2]*r64_0[2] + a64_0[3]*r64_0[1] + a64_0[4]*r64_0[0];
            
            c_0 = 0;
            for(int k = 0; k < 4; k++) { c_0 = m_0[k] >> 26; acc[0][k] += (uint32_t)(m_0[k] & mask26); m_0[k+1] += c_0; }
            c_0 = m_0[4] >> 26; acc[0][4] = (uint32_t)(m_0[4] & mask26);
            acc[0][0] += (uint32_t)(c_0 * 5);
            c_0 = acc[0][0] >> 26; acc[0][0] &= mask26; acc[0][1] += (uint32_t)c_0;
            

            // Add second block to accumulator
            uint64_t carry_0 = 0;
            for (int k = 0; k < 5; k++) {
                carry_0 = (uint64_t)acc[0][k] + u_0[k] + carry_0;
                acc[0][k] += (uint32_t)(carry_0 & mask26);
                carry_0 >>= 26;
            }
            acc[0][0] += (uint32_t)(carry_0 * 5);


            const uint8_t* b_1 = curr_data + (1 * 16);
            const uint8_t* d_1 = curr_data + (16*5);
            uint32_t n_1[5];
            uint32_t u_1[5];
            uint32_t w0_1 = (uint32_t)b_1[0] | ((uint32_t)b_1[1] << 8) | ((uint32_t)b_1[2] << 16) | ((uint32_t)b_1[3] << 24);
            uint32_t w1_1 = (uint32_t)b_1[4] | ((uint32_t)b_1[5] << 8) | ((uint32_t)b_1[6] << 16) | ((uint32_t)b_1[7] << 24);
            uint32_t w2_1 = (uint32_t)b_1[8] | ((uint32_t)b_1[9] << 8) | ((uint32_t)b_1[10] << 16) | ((uint32_t)b_1[11] << 24);
            uint32_t w3_1 = (uint32_t)b_1[12] | ((uint32_t)b_1[13] << 8) | ((uint32_t)b_1[14] << 16) | ((uint32_t)b_1[15] << 24);

            uint32_t v0_1 = (uint32_t)d_1[0] | ((uint32_t)d_1[1] << 8) | ((uint32_t)d_1[2] << 16) | ((uint32_t)d_1[3] << 24);
            uint32_t v1_1 = (uint32_t)d_1[4] | ((uint32_t)d_1[5] << 8) | ((uint32_t)d_1[6] << 16) | ((uint32_t)d_1[7] << 24);
            uint32_t v2_1 = (uint32_t)d_1[8] | ((uint32_t)d_1[9] << 8) | ((uint32_t)d_1[10] << 16) | ((uint32_t)d_1[11] << 24);
            uint32_t v3_1 = (uint32_t)d_1[12] | ((uint32_t)d_1[13] << 8) | ((uint32_t)d_1[14] << 16) | ((uint32_t)d_1[15] << 24);

            n_1[0] = w0_1 & mask26;
            n_1[1] = ((w0_1 >> 26) | (w1_1 << 6)) & mask26;
            n_1[2] = ((w1_1 >> 20) | (w2_1 << 12)) & mask26;
            n_1[3] = ((w2_1 >> 14) | (w3_1 << 18)) & mask26;
            n_1[4] = (w3_1 >> 8) | (1u << 24);

            u_1[0] = v0_1 & mask26;
            u_1[1] = ((v0_1 >> 26) | (v1_1 << 6)) & mask26;
            u_1[2] = ((v1_1 >> 20) | (v2_1 << 12)) & mask26;
            u_1[3] = ((v2_1 >> 14) | (v3_1 << 18)) & mask26;
            u_1[4] = (v3_1 >> 8) | (1u << 24);



            uint64_t a64_1[5], r64_1[5], m_1[5];
            for (int k = 0; k < 5; k++) { a64_1[k] = acc[1][k]; r64_1[k] = r_pow[7][k]; } // r^8
            m_1[0] = a64_1[0]*r64_1[0] + 5*(a64_1[1]*r64_1[4] + a64_1[2]*r64_1[3] + a64_1[3]*r64_1[2] + a64_1[4]*r64_1[1]);
            m_1[1] = a64_1[0]*r64_1[1] + a64_1[1]*r64_1[0] + 5*(a64_1[2]*r64_1[4] + a64_1[3]*r64_1[3] + a64_1[4]*r64_1[2]);
            m_1[2] = a64_1[0]*r64_1[2] + a64_1[1]*r64_1[1] + a64_1[2]*r64_1[0] + 5*(a64_1[3]*r64_1[4] + a64_1[4]*r64_1[3]);
            m_1[3] = a64_1[0]*r64_1[3] + a64_1[1]*r64_1[2] + a64_1[2]*r64_1[1] + a64_1[3]*r64_1[0] + 5*(a64_1[4]*r64_1[4]);
            m_1[4] = a64_1[0]*r64_1[4] + a64_1[1]*r64_1[3] + a64_1[2]*r64_1[2] + a64_1[3]*r64_1[1] + a64_1[4]*r64_1[0];
            
            uint64_t c_1 = 0;
            for(int k = 0; k < 4; k++) { c_1 = m_1[k] >> 26; acc[1][k] = (uint32_t)(m_1[k] & mask26); m_1[k+1] += c_1; }
            c_1 = m_1[4] >> 26; acc[1][4] = (uint32_t)(m_1[4] & mask26);
            acc[1][0] += (uint32_t)(c_1 * 5);
            c_1 = acc[1][0] >> 26; acc[1][0] &= mask26; acc[1][1] += (uint32_t)c_1;
            


            //uint64_t a64_1[5], r64_1[5], m_1[5];
            for (int k = 0; k < 5; k++) { a64_1[k] = n_1[k]; r64_1[k] = r_pow[3][k]; } // r^4
            m_1[0] = a64_1[0]*r64_1[0] + 5*(a64_1[1]*r64_1[4] + a64_1[2]*r64_1[3] + a64_1[3]*r64_1[2] + a64_1[4]*r64_1[1]);
            m_1[1] = a64_1[0]*r64_1[1] + a64_1[1]*r64_1[0] + 5*(a64_1[2]*r64_1[4] + a64_1[3]*r64_1[3] + a64_1[4]*r64_1[2]);
            m_1[2] = a64_1[0]*r64_1[2] + a64_1[1]*r64_1[1] + a64_1[2]*r64_1[0] + 5*(a64_1[3]*r64_1[4] + a64_1[4]*r64_1[3]);
            m_1[3] = a64_1[0]*r64_1[3] + a64_1[1]*r64_1[2] + a64_1[2]*r64_1[1] + a64_1[3]*r64_1[0] + 5*(a64_1[4]*r64_1[4]);
            m_1[4] = a64_1[0]*r64_1[4] + a64_1[1]*r64_1[3] + a64_1[2]*r64_1[2] + a64_1[3]*r64_1[1] + a64_1[4]*r64_1[0];
            
            c_1 = 0;
            for(int k = 0; k < 4; k++) { c_1 = m_1[k] >> 26; acc[1][k] += (uint32_t)(m_1[k] & mask26); m_1[k+1] += c_1; }
            c_1 = m_1[4] >> 26; acc[1][4] = (uint32_t)(m_1[4] & mask26);
            acc[1][0] += (uint32_t)(c_1 * 5);
            c_1 = acc[1][0] >> 26; acc[1][0] &= mask26; acc[1][1] += (uint32_t)c_1;
            

            uint64_t carry_1 = 0;
            for (int k = 0; k < 5; k++) {
                carry_1 = (uint64_t)acc[1][k] + u_1[k] + carry_1;
                acc[1][k] += (uint32_t)(carry_1 & mask26);
                carry_1 >>= 26;
            }
            acc[1][0] += (uint32_t)(carry_1 * 5);


            const uint8_t* b_2 = curr_data + 32;
            const uint8_t* d_2 = curr_data + (16*6);
            uint32_t w0_2 = (uint32_t)b_2[0] | ((uint32_t)b_2[1] << 8) | ((uint32_t)b_2[2] << 16) | ((uint32_t)b_2[3] << 24);
            uint32_t w1_2 = (uint32_t)b_2[4] | ((uint32_t)b_2[5] << 8) | ((uint32_t)b_2[6] << 16) | ((uint32_t)b_2[7] << 24);
            uint32_t w2_2 = (uint32_t)b_2[8] | ((uint32_t)b_2[9] << 8) | ((uint32_t)b_2[10] << 16) | ((uint32_t)b_2[11] << 24);
            uint32_t w3_2 = (uint32_t)b_2[12] | ((uint32_t)b_2[13] << 8) | ((uint32_t)b_2[14] << 16) | ((uint32_t)b_2[15] << 24);

            uint32_t v0_2 = (uint32_t)d_2[0] | ((uint32_t)d_2[1] << 8) | ((uint32_t)d_2[2] << 16) | ((uint32_t)d_2[3] << 24);
            uint32_t v1_2 = (uint32_t)d_2[4] | ((uint32_t)d_2[5] << 8) | ((uint32_t)d_2[6] << 16) | ((uint32_t)d_2[7] << 24);
            uint32_t v2_2 = (uint32_t)d_2[8] | ((uint32_t)d_2[9] << 8) | ((uint32_t)d_2[10] << 16) | ((uint32_t)d_2[11] << 24);
            uint32_t v3_2 = (uint32_t)d_2[12] | ((uint32_t)d_2[13] << 8) | ((uint32_t)d_2[14] << 16) | ((uint32_t)d_2[15] << 24);

            uint32_t n_2[5];
            uint32_t u_2[5];

            n_2[0] = w0_2 & mask26;
            n_2[1] = ((w0_2 >> 26) | (w1_2 << 6)) & mask26;
            n_2[2] = ((w1_2 >> 20) | (w2_2 << 12)) & mask26;
            n_2[3] = ((w2_2 >> 14) | (w3_2 << 18)) & mask26;
            n_2[4] = (w3_2 >> 8) | (1u << 24);

            u_2[0] = v0_2 & mask26;
            u_2[1] = ((v0_2 >> 26) | (v1_2 << 6)) & mask26;
            u_2[2] = ((v1_2 >> 20) | (v2_2 << 12)) & mask26;
            u_2[3] = ((v2_2 >> 14) | (v3_2 << 18)) & mask26;
            u_2[4] = (v3_2 >> 8) | (1u << 24);



            uint64_t a64_2[5], r64_2[5], m_2[5];
            for (int k = 0; k < 5; k++) { a64_2[k] = acc[2][k]; r64_2[k] = r_pow[7][k]; } // r^8
            m_2[0] = a64_2[0]*r64_2[0] + 5*(a64_2[1]*r64_2[4] + a64_2[2]*r64_2[3] + a64_2[3]*r64_2[2] + a64_2[4]*r64_2[1]);
            m_2[1] = a64_2[0]*r64_2[1] + a64_2[1]*r64_2[0] + 5*(a64_2[2]*r64_2[4] + a64_2[3]*r64_2[3] + a64_2[4]*r64_2[2]);
            m_2[2] = a64_2[0]*r64_2[2] + a64_2[1]*r64_2[1] + a64_2[2]*r64_2[0] + 5*(a64_2[3]*r64_2[4] + a64_2[4]*r64_2[3]);
            m_2[3] = a64_2[0]*r64_2[3] + a64_2[1]*r64_2[2] + a64_2[2]*r64_2[1] + a64_2[3]*r64_2[0] + 5*(a64_2[4]*r64_2[4]);
            m_2[4] = a64_2[0]*r64_2[4] + a64_2[1]*r64_2[3] + a64_2[2]*r64_2[2] + a64_2[3]*r64_2[1] + a64_2[4]*r64_2[0];
            
            uint64_t c_2 = 0;
            for(int k = 0; k < 4; k++) { c_2 = m_2[k] >> 26; acc[2][k] = (uint32_t)(m_2[k] & mask26); m_2[k+1] += c_2; }
            c_2 = m_2[4] >> 26; acc[2][4] = (uint32_t)(m_2[4] & mask26);
            acc[2][0] += (uint32_t)(c_2 * 5);
            c_2 = acc[2][0] >> 26; acc[2][0] &= mask26; acc[2][1] += (uint32_t)c_2;
            


            //uint64_t a64_2[5], r64_2[5], m_2[5];
            for (int k = 0; k < 5; k++) { a64_2[k] = n_2[k]; r64_2[k] = r_pow[3][k]; } // r^4
            m_2[0] = a64_2[0]*r64_2[0] + 5*(a64_2[1]*r64_2[4] + a64_2[2]*r64_2[3] + a64_2[3]*r64_2[2] + a64_2[4]*r64_2[1]);
            m_2[1] = a64_2[0]*r64_2[1] + a64_2[1]*r64_2[0] + 5*(a64_2[2]*r64_2[4] + a64_2[3]*r64_2[3] + a64_2[4]*r64_2[2]);
            m_2[2] = a64_2[0]*r64_2[2] + a64_2[1]*r64_2[1] + a64_2[2]*r64_2[0] + 5*(a64_2[3]*r64_2[4] + a64_2[4]*r64_2[3]);
            m_2[3] = a64_2[0]*r64_2[3] + a64_2[1]*r64_2[2] + a64_2[2]*r64_2[1] + a64_2[3]*r64_2[0] + 5*(a64_2[4]*r64_2[4]);
            m_2[4] = a64_2[0]*r64_2[4] + a64_2[1]*r64_2[3] + a64_2[2]*r64_2[2] + a64_2[3]*r64_2[1] + a64_2[4]*r64_2[0];
            
            c_2 = 0;
            for(int k = 0; k < 4; k++) { c_2 = m_2[k] >> 26; acc[2][k] += (uint32_t)(m_2[k] & mask26); m_2[k+1] += c_2; }
            c_2 = m_2[4] >> 26; acc[2][4] = (uint32_t)(m_2[4] & mask26);
            acc[2][0] += (uint32_t)(c_2 * 5);
            c_2 = acc[2][0] >> 26; acc[2][0] &= mask26; acc[2][1] += (uint32_t)c_2;
            

            uint64_t carry_2 = 0;
            for (int k = 0; k < 5; k++) {
                carry_2 = (uint64_t)acc[2][k] + u_2[k] + carry_2;
                acc[2][k] += (uint32_t)(carry_2 & mask26);
                carry_2 >>= 26;
            }
            acc[2][0] += (uint32_t)(carry_2 * 5);

            const uint8_t* b_3 = curr_data + 48;
            const uint8_t* d_3 = curr_data + (16*7);

            uint32_t w0_3 = (uint32_t)b_3[0] | ((uint32_t)b_3[1] << 8) | ((uint32_t)b_3[2] << 16) | ((uint32_t)b_3[3] << 24);
            uint32_t w1_3 = (uint32_t)b_3[4] | ((uint32_t)b_3[5] << 8) | ((uint32_t)b_3[6] << 16) | ((uint32_t)b_3[7] << 24);
            uint32_t w2_3 = (uint32_t)b_3[8] | ((uint32_t)b_3[9] << 8) | ((uint32_t)b_3[10] << 16) | ((uint32_t)b_3[11] << 24);
            uint32_t w3_3 = (uint32_t)b_3[12] | ((uint32_t)b_3[13] << 8) | ((uint32_t)b_3[14] << 16) | ((uint32_t)b_3[15] << 24);

            uint32_t v0_3 = (uint32_t)d_3[0] | ((uint32_t)d_3[1] << 8) | ((uint32_t)d_3[2] << 16) | ((uint32_t)d_3[3] << 24);
            uint32_t v1_3 = (uint32_t)d_3[4] | ((uint32_t)d_3[5] << 8) | ((uint32_t)d_3[6] << 16) | ((uint32_t)d_3[7] << 24);
            uint32_t v2_3 = (uint32_t)d_3[8] | ((uint32_t)d_3[9] << 8) | ((uint32_t)d_3[10] << 16) | ((uint32_t)d_3[11] << 24);
            uint32_t v3_3 = (uint32_t)d_3[12] | ((uint32_t)d_3[13] << 8) | ((uint32_t)d_3[14] << 16) | ((uint32_t)d_3[15] << 24);

            uint32_t n_3[5];
            uint32_t u_3[5];
            n_3[0] = w0_3 & mask26;
            n_3[1] = ((w0_3 >> 26) | (w1_3 << 6)) & mask26;
            n_3[2] = ((w1_3 >> 20) | (w2_3 << 12)) & mask26;
            n_3[3] = ((w2_3 >> 14) | (w3_3 << 18)) & mask26;
            n_3[4] = (w3_3 >> 8) | (1u << 24);

            u_3[0] = v0_3 & mask26;
            u_3[1] = ((v0_3 >> 26) | (v1_3 << 6)) & mask26;
            u_3[2] = ((v1_3 >> 20) | (v2_3 << 12)) & mask26;
            u_3[3] = ((v2_3 >> 14) | (v3_3 << 18)) & mask26;
            u_3[4] = (v3_3 >> 8) | (1u << 24);


            uint64_t a64_3[5], r64_3[5], m_3[5];
            for (int k = 0; k < 5; k++) { a64_3[k] = acc[3][k]; r64_3[k] = r_pow[7][k]; } // r^4
            m_3[0] = a64_3[0]*r64_3[0] + 5*(a64_3[1]*r64_3[4] + a64_3[2]*r64_3[3] + a64_3[3]*r64_3[2] + a64_3[4]*r64_3[1]);
            m_3[1] = a64_3[0]*r64_3[1] + a64_3[1]*r64_3[0] + 5*(a64_3[2]*r64_3[4] + a64_3[3]*r64_3[3] + a64_3[4]*r64_3[2]);
            m_3[2] = a64_3[0]*r64_3[2] + a64_3[1]*r64_3[1] + a64_3[2]*r64_3[0] + 5*(a64_3[3]*r64_3[4] + a64_3[4]*r64_3[3]);
            m_3[3] = a64_3[0]*r64_3[3] + a64_3[1]*r64_3[2] + a64_3[2]*r64_3[1] + a64_3[3]*r64_3[0] + 5*(a64_3[4]*r64_3[4]);
            m_3[4] = a64_3[0]*r64_3[4] + a64_3[1]*r64_3[3] + a64_3[2]*r64_3[2] + a64_3[3]*r64_3[1] + a64_3[4]*r64_3[0];
            
            uint64_t c_3 = 0;
            for(int k = 0; k < 4; k++) { c_3 = m_3[k] >> 26; acc[3][k] = (uint32_t)(m_3[k] & mask26); m_3[k+1] += c_3; }
            c_3 = m_3[4] >> 26; acc[3][4] = (uint32_t)(m_3[4] & mask26);
            acc[3][0] += (uint32_t)(c_3 * 5);
            c_3 = acc[3][0] >> 26; acc[3][0] &= mask26; acc[3][1] += (uint32_t)c_3;
        


            //uint64_t a64_3[5], r64_3[5], m_3[5];
            for (int k = 0; k < 5; k++) { a64_3[k] = n_3[k]; r64_3[k] = r_pow[3][k]; } // r^4
            m_3[0] = a64_3[0]*r64_3[0] + 5*(a64_3[1]*r64_3[4] + a64_3[2]*r64_3[3] + a64_3[3]*r64_3[2] + a64_3[4]*r64_3[1]);
            m_3[1] = a64_3[0]*r64_3[1] + a64_3[1]*r64_3[0] + 5*(a64_3[2]*r64_3[4] + a64_3[3]*r64_3[3] + a64_3[4]*r64_3[2]);
            m_3[2] = a64_3[0]*r64_3[2] + a64_3[1]*r64_3[1] + a64_3[2]*r64_3[0] + 5*(a64_3[3]*r64_3[4] + a64_3[4]*r64_3[3]);
            m_3[3] = a64_3[0]*r64_3[3] + a64_3[1]*r64_3[2] + a64_3[2]*r64_3[1] + a64_3[3]*r64_3[0] + 5*(a64_3[4]*r64_3[4]);
            m_3[4] = a64_3[0]*r64_3[4] + a64_3[1]*r64_3[3] + a64_3[2]*r64_3[2] + a64_3[3]*r64_3[1] + a64_3[4]*r64_3[0];
            
            c_3 = 0;
            for(int k = 0; k < 4; k++) { c_3 = m_3[k] >> 26; acc[3][k] += (uint32_t)(m_3[k] & mask26); m_3[k+1] += c_3; }
            c_3 = m_3[4] >> 26; acc[3][4] = (uint32_t)(m_3[4] & mask26);
            acc[3][0] += (uint32_t)(c_3 * 5);
            c_3 = acc[3][0] >> 26; acc[3][0] &= mask26; acc[3][1] += (uint32_t)c_3;
            

            uint64_t carry_3 = 0;
            for (int k = 0; k < 5; k++) {
                carry_3 = (uint64_t)acc[3][k] + u_3[k] + carry_3;
                acc[3][k] += (uint32_t)(carry_3 & mask26);
                carry_3 >>= 26;
            }
            acc[3][0] += (uint32_t)(carry_3 * 5);
        
        curr_data += 128;
    }

    // Align streams: Stream 0 needs r^4, Stream 1 needs r^3, Stream 2 needs r^2, Stream 3 needs r^1
    uint32_t* align_powers[4] = {r_pow[3], r_pow[2], r_pow[1], r_pow[0]};
    for (int j = 0; j < 4 && parallel_chunks > 0; j++) {
        uint64_t a64[5], r64[5], m[5];
        for (int k = 0; k < 5; k++) { a64[k] = acc[j][k]; r64[k] = align_powers[j][k]; }
        m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
        m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
        m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
        m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
        m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
        
        uint64_t c = 0;
        for(int k = 0; k < 4; k++) { c = m[k] >> 26; acc[j][k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
        c = m[4] >> 26; 
        acc[j][4] += (uint32_t)(m[4] & mask26);
        acc[j][0] += (uint32_t)(c * 5);
        c = acc[j][0] >> 26; acc[j][0] &= mask26; acc[j][1] += (uint32_t)c;

        // Summ into final_acc
        uint64_t carry = 0;
        for (int k = 0; k < 5; k++) {
            carry = (uint64_t)final_acc[k] + acc[j][k] + carry;
            final_acc[k] = (uint32_t)(carry & mask26);
            carry >>= 26;
        }
        final_acc[0] += (uint32_t)(carry * 5);
        c = final_acc[0] >> 26; final_acc[0] &= mask26; final_acc[1] += (uint32_t)c;
    }

    //Remaining blocks
    uint64_t remaining_full = full_blocks % 8;
    for (uint64_t i = 0; i < remaining_full + (remainder > 0 ? 1 : 0); i++) {
        uint32_t n[5];
        uint8_t block[17] = {0};
        uint64_t len = 16;
        if (i < remaining_full) {
            memcpy(block, curr_data, 16);
            block[16] = 0x01;
            curr_data += 16;
        } else {
            memcpy(block, curr_data, remainder);
            block[remainder] = 0x01;
            len = remainder;
        }


        uint64_t t[5] = {0};
        for (int k = 0; k < 17; k++) t[k/4] |= ((uint64_t)block[k] << ((k%4)*8));
        n[0] = (uint32_t)t[0] & mask26;
        n[1] = (uint32_t)((t[0] >> 26) | (t[1] << 6)) & mask26;
        n[2] = (uint32_t)((t[1] >> 20) | (t[2] << 12)) & mask26;
        n[3] = (uint32_t)((t[2] >> 14) | (t[3] << 18)) & mask26;
        n[4] = (uint32_t)((t[3] >> 8) | (t[4] << 24)) & mask26;

        // final_acc = (final_acc + n) * r
        uint64_t carry = 0;
        for (int k = 0; k < 5; k++) {
            carry = (uint64_t)final_acc[k] + n[k] + carry;
            final_acc[k] = (uint32_t)(carry & mask26);
            carry >>= 26;
        }
        final_acc[0] += (uint32_t)(carry * 5);
        uint32_t c = final_acc[0] >> 26; final_acc[0] &= mask26; final_acc[1] += c;

        uint64_t a64[5], r64[5], m[5];
        for (int k = 0; k < 5; k++) { a64[k] = final_acc[k]; r64[k] = r[k]; }
        m[0] = a64[0]*r64[0] + 5*(a64[1]*r64[4] + a64[2]*r64[3] + a64[3]*r64[2] + a64[4]*r64[1]);
        m[1] = a64[0]*r64[1] + a64[1]*r64[0] + 5*(a64[2]*r64[4] + a64[3]*r64[3] + a64[4]*r64[2]);
        m[2] = a64[0]*r64[2] + a64[1]*r64[1] + a64[2]*r64[0] + 5*(a64[3]*r64[4] + a64[4]*r64[3]);
        m[3] = a64[0]*r64[3] + a64[1]*r64[2] + a64[2]*r64[1] + a64[3]*r64[0] + 5*(a64[4]*r64[4]);
        m[4] = a64[0]*r64[4] + a64[1]*r64[3] + a64[2]*r64[2] + a64[3]*r64[1] + a64[4]*r64[0];
        c = 0;
        for(int k = 0; k < 4; k++) { c = m[k] >> 26; final_acc[k] = (uint32_t)(m[k] & mask26); m[k+1] += c; }
        c = m[4] >> 26; final_acc[4] = (uint32_t)(m[4] & mask26);
        final_acc[0] += (uint32_t)(c * 5);
        c = final_acc[0] >> 26; final_acc[0] &= mask26; final_acc[1] += (uint32_t)c;
    }

    // Ensure final_acc < 2^130-5
    //no need to do it each time in the main loop, just once at the end
    uint32_t g[5];
    uint64_t carry = 5; 
    for (int i = 0; i < 5; i++) {
        carry += final_acc[i];
        g[i] = (uint32_t)(carry & mask26);
        carry >>= 26;
    }
    if (carry > 0) memcpy(final_acc, g, 5 * sizeof(uint32_t));

    uint64_t conv[4];
    conv[0] = ((uint64_t)final_acc[0]) | ((uint64_t)final_acc[1] << 26);
    conv[1] = ((uint64_t)final_acc[1] >> 6) | ((uint64_t)final_acc[2] << 20);
    conv[2] = ((uint64_t)final_acc[2] >> 12) | ((uint64_t)final_acc[3] << 14);
    conv[3] = ((uint64_t)final_acc[3] >> 18) | ((uint64_t)final_acc[4] << 8);

    unsigned char* tag = (unsigned char*)malloc(16);
    uint64_t c = 0;
    for(int i = 0; i < 4; i++){
        c += (conv[i] & mask32) + s[i];
        uint32_t val = (uint32_t)c;
        tag[i*4] = val & 0xff; tag[i*4+1] = (val>>8) & 0xff; tag[i*4+2] = (val>>16) & 0xff; tag[i*4+3] = (val>>24) & 0xff;
        c >>= 32;
    }
    return tag;
}


