#include <stdint.h> // get uint32_t and uint64_t types, so is not platform dependent (unsigned int (32 bits) and unsigned long long (64 bits) could vary in size)
#include <string.h>
#include <stdlib.h>


/*
we use 9x26-bit representations for acc, r and s, since 7x28 + 17 = 213 bits = p = 2^213 - 3 (so we have a margin to handle overflow)
*/ 

const uint32_t mask_lowest_17bits = 0x1ffff;
const uint32_t mask_lowest_28bits = 0xfffffff; // mask to keep only lowest 28 bits (28 ones in binary)
const uint64_t mask_lowest_32bits = 0xffffffffULL; // mask to keep only lowest 32 bits (32 ones in binary)

// handle conversions from bytes to 7x28 + 17-bit representationfor length 26 and 27 
void to_large_num_rep(uint32_t out[8], const unsigned char *bytes, uint64_t len_bytes){
    uint64_t t[8] = {0}; // initialize with zeros
    // convert the bytes into the 9*64-bit integer representation (LE format)
    for (uint64_t i = 0; i < len_bytes; i++){
        t[i/4] |= ((uint64_t)bytes[i] << ((i%4)*8)); 
    }


    for(int i = 0; i < 7; i++){
        int bit_start = 28*i; // compute where next 28 bits start in t
        int t_idx = bit_start / 32; // get idx of t which contains start of next 28 bits
        int bit_in_t = bit_start % 32; // get bit offset within t[t_idx]
        out[i] = (uint32_t)((t[t_idx] >> bit_in_t) | (t[t_idx + 1] << (32 - bit_in_t))) & mask_lowest_28bits; // extrat next 28 bits

    }

    // only save the lowest 17 bits in the last entry since we chose a representation of 7x28 + 17 bits
    out[7] = (uint32_t)(t[6] >> 4) & mask_lowest_17bits; 
}

// handles conversion from 7x28 + 17-bit representation to 27 bytes in LE format
void to_27_le_bytes(uint32_t in[8], unsigned char out[27]){
    uint32_t t[7] = {0};

    for(int i = 0; i < 7; i++){
        int bit_start = 28*i; // compute where next 28 bits start in t
        int t_idx = bit_start / 32; // get idx of t which contains start of next 28 bits
        int bit_in_t = bit_start % 32; // get bit offset within t[t_idx]
        t[t_idx] |= (uint32_t)((uint64_t)in[i] << bit_in_t); // write lower bits into t[t_idx]

        // if we cross 32 bit boundary, write remaining bits into t[t_idx + 1]
        if (bit_in_t + 28 > 32){
            t[t_idx + 1] |= (uint32_t)((uint64_t)in[i] >> (32 - bit_in_t));
        }
    }
    // handle last 17 bits (out[7] = t[6] >> 4)
    t[6] |= (in[7] << 4);

    // write t into out in LE format
    for (int i = 0; i < 27; i++){
        out[i] = (unsigned char)((t[i / 4] >> ((i% 4)* 8)) & 0xff); 
    }

}

// keylength must be 54 bytes
void poly1305_init(uint32_t acc[8], uint32_t r[8], uint32_t s[8], const unsigned char key[54]) {
    // split key into two halves (first half into r, other in s)
    unsigned char r_bytes[27];
    memcpy(r_bytes, key, 27);
    
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

    // make sure r is not > p
    r_bytes[26] &= clear_top4_bits

    // then convert to 8x28 + 17-bit representation
    to_large_num_rep(r, r_bytes, 27);
    
    // convert second half of key into 8x28 + 17-bit representation for s
    unsigned char s_bytes[27];
    memcpy(s_bytes, key + 27, 27);

    // make sure s is not > p
    s_bytes[26] &= clear_top4_bits;

    to_large_num_rep(s, s_bytes, 27);

    memset(acc, 0, 8*sizeof(uint32_t)); 
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
// use block size of 26 bytes (maximal size still smaller p) 
// and tag will now be 27 bytes (just enough to represent a number in prime field)
unsigned char* create_tag(uint32_t acc[8], uint32_t r[8], uint32_t s[8], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + 26 - 1) / 26;
    for(uint64_t i = 0; i < num_blocks; i++){
        uint64_t offset = i*26;
        uint64_t block_len = (data_len - offset) < 26 ? (data_len - offset) : 26;
        unsigned char block[block_len + 1];
        memset(block, 0, block_len + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        uint32_t n[8];
        to_large_num_rep(n, block, block_len + 1); // convert representation of n to fit acc and r
        add_large_nums_88(acc, n); // acc += n  // TODO
        mulmod_p(acc, r); // acc = (acc * r) mod p // TODO
    }

    add_large_nums_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(27 * sizeof(unsigned char));
    to_27_le_bytes(acc, tag); // convert acc (7x28 + 17-bit representation) to 27 bytes (LE format) // TODO
    return tag;
}