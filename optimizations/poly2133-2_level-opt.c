#include <stdint.h> // get uint32_t and uint64_t types, so is not platform dependent (unsigned int (32 bits) and unsigned long long (64 bits) could vary in size)
#include <string.h>
#include <stdlib.h>

/* implements the 2-level approach from the paper with 4 accumulators (NUM_GROUPS = 4) */

/*
we use 7x28 + 17-bit representations for acc, r and s, since 7x28 + 17 = 213 bits = p = 2^213 - 3 (so we have a margin to handle overflow)
*/ 

#define NUM_LIMBS 8
#define BLOCK_SIZE 26
#define TAG_SIZE 26
#define KEY_SIZE 54
#define NUM_GROUPS 4

const uint32_t mask_lowest_17bits = 0x1ffff;
const uint32_t mask_lowest_28bits = 0xfffffff; // mask to keep only lowest 28 bits (28 ones in binary)

// handle conversions from bytes to 7x28 + 17-bit representationfor length 26 and 27 
static void to_large_num_rep(uint32_t out[NUM_LIMBS], const unsigned char *bytes, uint64_t len_bytes){
    uint64_t t[NUM_LIMBS] = {0}; // initialize with zeros
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

// handles conversion from 7x28 + 17-bit representation to 26 bytes in LE format
static void to_26_le_bytes(uint32_t in[NUM_LIMBS], unsigned char out[TAG_SIZE]){
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
    for (int i = 0; i < TAG_SIZE; i++){
        out[i] = (unsigned char)((t[i / 4] >> ((i% 4)* 8)) & 0xff); 
    }

}


// keylength must be 54 bytes
void poly2133_init(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    // split key into two halves (first half into r, other in s)
    int half_key_len = KEY_SIZE / 2;
    unsigned char r_bytes[half_key_len];
    memcpy(r_bytes, key, half_key_len);
    
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
    r_bytes[17] &= clear_lowest2_bits;
    r_bytes[22] &= clear_top4_bits;
    r_bytes[24] &= clear_lowest2_bits;
    r_bytes[25] &= clear_top4_bits;

    // make sure r is not > p
    r_bytes[half_key_len - 1] &= clear_top4_bits;

    // then convert to 7x28 + 17-bit representation
    to_large_num_rep(r, r_bytes, half_key_len);
    
    // convert second half of key into 7x28 + 17-bit representation for s
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;

    to_large_num_rep(s, s_bytes, half_key_len);
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

// computes a = a + b (a and b need be in 5x26-bit representation)
static void add_large_nums_88(uint32_t a[NUM_LIMBS], const uint32_t b[NUM_LIMBS]){
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
static void mulmod_p(uint32_t acc[NUM_LIMBS], const uint32_t r[NUM_LIMBS]) {
    // use two seperate accumulators so we don't need uint128 
    uint64_t mult_small[NUM_LIMBS] = {0}; // handles all (i + j = k) contributions
    uint64_t mult_large[NUM_LIMBS] = {0}; // handles all (i + j = k + 8) contributions (where we wrap around, need to multiply by 3 and apply shift later)
    uint64_t mask_lowest_6bits = 0x3f; 

    for (int i = 0; i < NUM_LIMBS; i++){
        for(int j = 0; j < NUM_LIMBS; j++){
            int k = i+j;
            if (k < NUM_LIMBS){
                mult_small[k] += (uint64_t)acc[i]* r[j];
            }
            else{
                mult_large[k - NUM_LIMBS] += (uint64_t)acc[i]* 3*r[j];
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
    uint64_t total_carry = (carry + wrap_carry) * 3;
    uint64_t sum0 = (uint64_t)acc[0] + total_carry;
    acc[0] = (uint32_t)(sum0 & mask_lowest_28bits);
    carry = sum0 >> 28;
    acc[0] &= mask_lowest_28bits;
    acc[1] += (uint32_t)carry;
    carry = acc[1] >> 28;
    acc[1] &= mask_lowest_28bits;
    acc[2] += (uint32_t)carry;

}


// calculate authentication tag for data
// use block size and tag size of 26 bytes (maximal size still smaller p) 
unsigned char* poly2133_create_tag(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint64_t num_full_blocks = num_blocks / NUM_GROUPS;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r2, r); // r2 = r * r mod p

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r3, r); // r3 = r^2 * r mod p

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r4, r); // r4 = r^3 * r mod p

    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE + 1];
        unsigned char block2[BLOCK_SIZE + 1];
        unsigned char block3[BLOCK_SIZE + 1];
        unsigned char block4[BLOCK_SIZE + 1];
        uint32_t n1[NUM_LIMBS];
        uint32_t n2[NUM_LIMBS];
        uint32_t n3[NUM_LIMBS];
        uint32_t n4[NUM_LIMBS];

        uint64_t offset1 = i*4 * BLOCK_SIZE;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE;


        memcpy(block1, data + offset1, BLOCK_SIZE);
        memcpy(block2, data + offset2, BLOCK_SIZE);
        memcpy(block3, data + offset3, BLOCK_SIZE);
        memcpy(block4, data + offset4, BLOCK_SIZE);
        block1[BLOCK_SIZE] = 0x01;
        block2[BLOCK_SIZE] = 0x01;
        block3[BLOCK_SIZE] = 0x01;
        block4[BLOCK_SIZE] = 0x01;
   
        to_large_num_rep(n1, block1, BLOCK_SIZE + 1); // convert representation of n to fit acc and r
        to_large_num_rep(n2, block2, BLOCK_SIZE + 1); 
        to_large_num_rep(n3, block3, BLOCK_SIZE + 1); 
        to_large_num_rep(n4, block4, BLOCK_SIZE + 1);

        mulmod_p(n1, r4); // n1 = n1 * r^4 mod p
        mulmod_p(n2, r3); // n2 = n2 * r^3 mod p
        mulmod_p(n3, r2); // n3 = n3 * r^2 mod p
        mulmod_p(n4, r); // n4 = n4 * r mod p
   
        add_large_nums_88(n1, n2); // n1 += n2
        add_large_nums_88(n1, n3); // n1 += n3
        add_large_nums_88(n1, n4); // n1 += n4

        mulmod_p(acc, r4); // acc = acc * r^4 mod p
        add_large_nums_88(acc, n1); // acc += n1

    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE ? (data_len - offset) : BLOCK_SIZE;
        unsigned char block[BLOCK_SIZE + 1];
        uint32_t n[NUM_LIMBS];
        memset(block, 0, BLOCK_SIZE + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        to_large_num_rep(n, block, block_len + 1); // convert representation of n to fit acc and r
        add_large_nums_88(acc, n); // acc += n
        mulmod_p(acc, r);
    }

    add_large_nums_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));
    to_26_le_bytes(acc, tag); // convert acc (7x28 + 17-bit representation) to 26 bytes (LE format)
    return tag;
}