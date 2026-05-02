#include <stdint.h> // get uint32_t and uint64_t types, so is not platform dependent (unsigned int (32 bits) and unsigned long long (64 bits) could vary in size)
#include <string.h>
#include <stdlib.h>


/*
we use 7x28 + 17-bit representations for acc, r and s, since 7x28 + 17 = 213 bits = p = 2^213 - 3 (so we have a margin to handle overflow)
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

    // then convert to 7x28 + 17-bit representation
    to_large_num_rep(r, r_bytes, 27);
    
    // convert second half of key into 7x28 + 17-bit representation for s
    unsigned char s_bytes[27];
    memcpy(s_bytes, key + 27, 27);

    // make sure s is not > p
    s_bytes[26] &= clear_top4_bits;

    to_large_num_rep(s, s_bytes, 27);

    memset(acc, 0, 8*sizeof(uint32_t)); 
}

// computes a = a + b (a and b need be in 5x26-bit representation)
static void add_large_nums_88(uint32_t a[8], const uint32_t b[8]){
    uint64_t carry = 0; // keeps track how much we exceeded 28 bits in each addition = carry
    // make the additions and keep track of carry
    for (int i = 0; i < 7; i++){
        carry = (uint64_t)a[i] + b[i] + carry; // add carry here as well
        a[i] = (uint32_t)(carry &mask_lowest_28bits); // keep lowest 28 bits
        carry >>= 28; // shift right by 28 bits (keep carry for next iteration)
    }

    // handle last 17 bits seperately
    carry = (uint64_t)a[7] + b[7] + carry;
    a[7] = (uint32_t)(carry & mask_lowest_17bits);
    carry >>= 17;

    // if carry is non-zero, we surpassed 2^213 -> need to compute mod (2^213 - 3) (specified by poly algorithm)
    a[0] += (uint32_t)(carry * 3);
}


// computes acc = acc * r mod p (where acc and r in 7x28 + 17 bit representation, p = 2^213 - 3)
static void mulmod_p(uint32_t acc[8], const uint32_t r[8]) {
    // use two seperate accumulators so we don't need uint128 
    uint64_t mult_small[8] = {0}; // handles all (i + j = k) contributions
    uint64_t mult_large[8] = {0}; // handles all (i + j = k + 8) contributions (where we wrap around, need to multiply by 3 and apply shift later)
    uint64_t mask_lowest_6bits = 0x3f; 

    for (int i = 0; i < 8; i++){
        for(int j = 0; j < 8; j++){
            int k = i+j;
            if (k < 8){
                mult_small[k] += (uint64_t)acc[i]* r[j];
            }
            else{
                mult_large[k - 8] += (uint64_t)acc[i]* 3*r[j];
            }
        }
    }

    uint64_t carry = 0;
    uint64_t wrap_carry = 0;

    // handle limbs 0 to 7, the last only contains 17 bits, so needs to be handled separately
    for(int i = 0; i < 7; i++){
        // wrap overflow might be larger 2^213 bits, so need to shift by 11
        uint64_t sum = mult_small[i] + ((mult_large[i] & mask_lowest_17bits) << 11) + wrap_carry + carry;
        acc[i] = (uint32_t)(sum & mask_lowest_28bits);
        carry = sum >> 28;
        wrap_carry = mult_large[i] >> 17;
    }

    // handle last limb separately
    // wrap overflow is shifted by 11 bits, so need to mask lowest 6 bits of mult_large so we don't add more than 6+11 = 17 bits to last limb
    uint64_t sum = mult_small[7] + ((mult_large[7] & mask_lowest_6bits) << 11) + wrap_carry + carry;
    acc[7] = (uint32_t)(sum & mask_lowest_17bits);
    carry = sum >> 17;
    wrap_carry = mult_large[7] >> 6;

    // if wrap_carry and/or carry are non-zero, multiply by 3 and add to acc[0], propagate up to acc[2] (since 3*2^213 < 2^28*3, we will never have to propagate further than acc[2])
    acc[0] += (uint32_t)((carry + wrap_carry) * 3);
    carry = acc[0] >> 28;
    acc[0] &= mask_lowest_28bits;
    acc[1] += (uint32_t)carry;
    carry = acc[1] >> 28;
    acc[1] &= mask_lowest_28bits;
    acc[2] += (uint32_t)carry;

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
        add_large_nums_88(acc, n); // acc += n 
        mulmod_p(acc, r); // acc = (acc * r) mod p
    }

    add_large_nums_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(27 * sizeof(unsigned char));
    to_27_le_bytes(acc, tag); // convert acc (7x28 + 17-bit representation) to 27 bytes (LE format)
    return tag;
}