#include <stdint.h> // get uint32_t and uint64_t types, so is not platform dependent (unsigned int (32 bits) and unsigned long long (64 bits) could vary in size)
#include <string.h>
#include <stdlib.h>

/* optimizations:
    - 2-level approach from the paper with 4 accumulators (NUM_GROUPS = 4) 
    - all functions inlined 
    - all loops with no carries unrolled 
    - carry delay (save mulmod carries in total carry and add in add_large_nums step to fold back)
    - precompute 3*r, 3*r^2, 3*r^3 and 3*r^4
*/

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
    // ------------------ to_large_num_rep(r, r_bytes, half_key_len) ------------------
    uint64_t tr[NUM_LIMBS] = {0}; 
    
    for (int i = 0; i+4 < half_key_len; i+= 4){
        uint64_t word = (uint64_t)r_bytes[i]
                  | ((uint64_t)r_bytes[i + 1] << 8)
                  | ((uint64_t)r_bytes[i + 2] << 16)
                  | ((uint64_t)r_bytes[i + 3] << 24);
        tr[i/4] = word;
    }
    tr[6] = (uint64_t)r_bytes[24]
        | ((uint64_t)r_bytes[25] << 8)
        | ((uint64_t)r_bytes[26] << 16);


    r[0] = (uint32_t)(tr[0] | (tr[1] << 32)) & mask_lowest_28bits;
    r[1] = (uint32_t)((tr[0] >> 28) | (tr[1] << 4)) & mask_lowest_28bits;
    r[2] = (uint32_t)((tr[1] >> 24) | (tr[2] << 8)) & mask_lowest_28bits;
    r[3] = (uint32_t)((tr[2] >> 20) | (tr[3] << 12)) & mask_lowest_28bits;
    r[4] = (uint32_t)((tr[3] >> 16) | (tr[4] << 16)) & mask_lowest_28bits;
    r[5] = (uint32_t)((tr[4] >> 12) | (tr[5] << 20)) & mask_lowest_28bits;
    r[6] = (uint32_t)((tr[5] >> 8) | (tr[6] << 24)) & mask_lowest_28bits;
    r[7] = (uint32_t)(tr[6] >> 4) & mask_lowest_17bits; 
    // --------------------------------------------------------------------------------
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    // convert second half of key into 7x28 + 17-bit representation for s
    // ---------------------- to_large_num_rep(s, s_bytes, half_key_len) ---------------
    uint64_t ts[NUM_LIMBS] = {0};
    
    for (int i = 0; i+4 < half_key_len; i+= 4){
        uint64_t word = (uint64_t)s_bytes[i]
                  | ((uint64_t)s_bytes[i + 1] << 8)
                  | ((uint64_t)s_bytes[i + 2] << 16)
                  | ((uint64_t)s_bytes[i + 3] << 24);
        ts[i/4] = word;
    }
    ts[6] = (uint64_t)s_bytes[24]
        | ((uint64_t)s_bytes[25] << 8)
        | ((uint64_t)s_bytes[26] << 16);

        
    s[0] = (uint32_t)(ts[0] | (ts[1] << 32)) & mask_lowest_28bits;
    s[1] = (uint32_t)((ts[0] >> 28) | (ts[1] << 4)) & mask_lowest_28bits;
    s[2] = (uint32_t)((ts[1] >> 24) | (ts[2] << 8)) & mask_lowest_28bits;
    s[3] = (uint32_t)((ts[2] >> 20) | (ts[3] << 12)) & mask_lowest_28bits;
    s[4] = (uint32_t)((ts[3] >> 16) | (ts[4] << 16)) & mask_lowest_28bits;
    s[5] = (uint32_t)((ts[4] >> 12) | (ts[5] << 20)) & mask_lowest_28bits;
    s[6] = (uint32_t)((ts[5] >> 8) | (ts[6] << 24)) & mask_lowest_28bits;
    s[7] = (uint32_t)(ts[6] >> 4) & mask_lowest_17bits;
    // --------------------------------------------------------------------------------
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

// calculate authentication tag for data
// use block size and tag size of 26 bytes (maximal size still smaller p) 
unsigned char* poly2133_create_tag(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint64_t num_full_blocks = num_blocks / NUM_GROUPS;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t three_r[NUM_LIMBS];
    uint32_t three_r2[NUM_LIMBS];
    uint32_t three_r3[NUM_LIMBS];
    uint32_t three_r4[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++){
        three_r[i] = 3*r[i];
    }
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    // --------------------- mulmod_p(r2, r) ----------------------
    uint64_t mult_small[NUM_LIMBS] = {0};
    uint64_t mult_large[NUM_LIMBS] = {0};
    uint64_t mask_lowest_6bits = 0x3f; 

    for (int i = 0; i < NUM_LIMBS; i++){
        for(int j = 0; j < NUM_LIMBS; j++){
            int k = i+j;
            if (k < NUM_LIMBS){
                mult_small[k] += (uint64_t)r2[i]* r[j];
            }
            else{
                mult_large[k - NUM_LIMBS] += (uint64_t)r2[i]* three_r[j];
            }
        }
    }

    uint64_t carry = 0;
    uint64_t wrap_carry = 0;
    uint64_t sum;

    for(int i = 0; i < 7; i++){
        
        sum = mult_small[i] + ((mult_large[i] & mask_lowest_17bits) << 11) + wrap_carry + carry;
        r2[i] = (uint32_t)(sum & mask_lowest_28bits);
        carry = sum >> 28;
        wrap_carry = mult_large[i] >> 17;
    }

    sum = mult_small[7] + ((mult_large[7] & mask_lowest_6bits) << 11) + wrap_carry + carry;
    r2[7] = (uint32_t)(sum & mask_lowest_17bits);
    carry = sum >> 17;
    wrap_carry = mult_large[7] >> 6;

    uint64_t total_carry = (carry + wrap_carry) * 3;
    sum = (uint64_t)r2[0] + total_carry;
    r2[0] = (uint32_t)(sum & mask_lowest_28bits);
    carry = sum >> 28;
    r2[0] &= mask_lowest_28bits;
    r2[1] += (uint32_t)carry;
    carry = r2[1] >> 28;
    r2[1] &= mask_lowest_28bits;
    r2[2] += (uint32_t)carry;
    // ------------------------------------------------------------

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    // --------------- mulmod_p(r3, r) ----------------------------
    memset(mult_small, 0, sizeof(mult_small));
    memset(mult_large, 0, sizeof(mult_large));

    for (int i = 0; i < NUM_LIMBS; i++){
        for(int j = 0; j < NUM_LIMBS; j++){
            int k = i+j;
            if (k < NUM_LIMBS){
                mult_small[k] += (uint64_t)r3[i]* r[j];
            }
            else{
                mult_large[k - NUM_LIMBS] += (uint64_t)r3[i]* three_r[j];
            }
        }
    }

    carry = 0;
    wrap_carry = 0;

    for(int i = 0; i < 7; i++){
        
        sum = mult_small[i] + ((mult_large[i] & mask_lowest_17bits) << 11) + wrap_carry + carry;
        r3[i] = (uint32_t)(sum & mask_lowest_28bits);
        carry = sum >> 28;
        wrap_carry = mult_large[i] >> 17;
    }

    sum = mult_small[7] + ((mult_large[7] & mask_lowest_6bits) << 11) + wrap_carry + carry;
    r3[7] = (uint32_t)(sum & mask_lowest_17bits);
    carry = sum >> 17;
    wrap_carry = mult_large[7] >> 6;

    total_carry = (carry + wrap_carry) * 3;
    sum = (uint64_t)r3[0] + total_carry;
    r3[0] = (uint32_t)(sum & mask_lowest_28bits);
    carry = sum >> 28;
    r3[0] &= mask_lowest_28bits;
    r3[1] += (uint32_t)carry;
    carry = r3[1] >> 28;
    r3[1] &= mask_lowest_28bits;
    r3[2] += (uint32_t)carry;
    // ------------------------------------------------------------
    for(int i = 0; i < NUM_LIMBS; i++){
        three_r2[i] = 3*r2[i];
    }

    memcpy(r4, r2,  NUM_LIMBS * sizeof(uint32_t));
    // ------------------- mulmod_p(r4, r2) -----------------------
    memset(mult_small, 0, sizeof(mult_small));
    memset(mult_large, 0, sizeof(mult_large));

    for (int i = 0; i < NUM_LIMBS; i++){
        for(int j = 0; j < NUM_LIMBS; j++){
            int k = i+j;
            if (k < NUM_LIMBS){
                mult_small[k] += (uint64_t)r4[i]* r2[j];
            }
            else{
                mult_large[k - NUM_LIMBS] += (uint64_t)r4[i]* three_r2[j];
            }
        }
    }

    carry = 0;
    wrap_carry = 0;

    for(int i = 0; i < 7; i++){
        
        sum = mult_small[i] + ((mult_large[i] & mask_lowest_17bits) << 11) + wrap_carry + carry;
        r4[i] = (uint32_t)(sum & mask_lowest_28bits);
        carry = sum >> 28;
        wrap_carry = mult_large[i] >> 17;
    }

    sum = mult_small[7] + ((mult_large[7] & mask_lowest_6bits) << 11) + wrap_carry + carry;
    r4[7] = (uint32_t)(sum & mask_lowest_17bits);
    carry = sum >> 17;
    wrap_carry = mult_large[7] >> 6;

    total_carry = (carry + wrap_carry) * 3;
    sum = (uint64_t)r4[0] + total_carry;
    r4[0] = (uint32_t)(sum & mask_lowest_28bits);
    carry = sum >> 28;
    r4[0] &= mask_lowest_28bits;
    r4[1] += (uint32_t)carry;
    carry = r4[1] >> 28;
    r4[1] &= mask_lowest_28bits;
    r4[2] += (uint32_t)carry;
    // ------------------------------------------------------------
    for(int i = 0; i < NUM_LIMBS; i++){
        three_r3[i] = 3*r3[i];
        three_r4[i] = 3*r4[i];
    }

    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE + 1];
        unsigned char block2[BLOCK_SIZE + 1];
        unsigned char block3[BLOCK_SIZE + 1];
        unsigned char block4[BLOCK_SIZE + 1];
        uint32_t n1[NUM_LIMBS];
        uint32_t n2[NUM_LIMBS];
        uint32_t n3[NUM_LIMBS];
        uint32_t n4[NUM_LIMBS];

        uint64_t fouri_time_block = i*4 * BLOCK_SIZE;
        uint64_t offset1 = fouri_time_block;
        uint64_t offset2 = fouri_time_block + BLOCK_SIZE;
        uint64_t offset3 = fouri_time_block + 2*BLOCK_SIZE;
        uint64_t offset4 = fouri_time_block + 3*BLOCK_SIZE;
        
        memcpy(block1, data + offset1, BLOCK_SIZE);
        memcpy(block2, data + offset2, BLOCK_SIZE);
        memcpy(block3, data + offset3, BLOCK_SIZE);
        memcpy(block4, data + offset4, BLOCK_SIZE);
        block1[BLOCK_SIZE] = 0x01;
        block2[BLOCK_SIZE] = 0x01;
        block3[BLOCK_SIZE] = 0x01;
        block4[BLOCK_SIZE] = 0x01;

        // ------------------ to_large_num_rep(n, block, BLOCK_SIZE + 1) ------------------
        // for n1, block1:
        uint64_t t[NUM_LIMBS] = {0}; 
        
        for (uint64_t i = 0; i+4 <= BLOCK_SIZE + 1; i+= 4){
            uint64_t word = (uint64_t)block1[i]
                  | ((uint64_t)block1[i + 1] << 8)
                  | ((uint64_t)block1[i + 2] << 16)
                  | ((uint64_t)block1[i + 3] << 24);
            t[i/4] = word; 
        }
        uint64_t remainder = (BLOCK_SIZE + 1) % 4;
        if (remainder != 0){
            uint64_t start = (BLOCK_SIZE + 1) - remainder;
            uint64_t word = 0;
            for (uint64_t j = 0; j < remainder; j++){
                word |= ((uint64_t)block1[start + j] << (8 * j));
            }
            t[start / 4] = word;
        }

        n1[0] = (uint32_t)(t[0] | (t[1] << 32)) & mask_lowest_28bits;
        n1[1] = (uint32_t)((t[0] >> 28) | (t[1] << 4)) & mask_lowest_28bits;
        n1[2] = (uint32_t)((t[1] >> 24) | (t[2] << 8)) & mask_lowest_28bits;
        n1[3] = (uint32_t)((t[2] >> 20) | (t[3] << 12)) & mask_lowest_28bits;
        n1[4] = (uint32_t)((t[3] >> 16) | (t[4] << 16)) & mask_lowest_28bits;
        n1[5] = (uint32_t)((t[4] >> 12) | (t[5] << 20)) & mask_lowest_28bits;
        n1[6] = (uint32_t)((t[5] >> 8) | (t[6] << 24)) & mask_lowest_28bits;
        n1[7] = (uint32_t)(t[6] >> 4) & mask_lowest_17bits; 
   
        // for n2, block2:
        for (uint64_t i = 0; i+4 <= BLOCK_SIZE + 1; i+= 4){
            uint64_t word = (uint64_t)block2[i]
                  | ((uint64_t)block2[i + 1] << 8)
                  | ((uint64_t)block2[i + 2] << 16)
                  | ((uint64_t)block2[i + 3] << 24);
            t[i/4] = word; 
        }
        remainder = (BLOCK_SIZE + 1) % 4;
        if (remainder != 0){
            uint64_t start = (BLOCK_SIZE + 1) - remainder;
            uint64_t word = 0;
            for (uint64_t j = 0; j < remainder; j++){
                word |= ((uint64_t)block2[start + j] << (8 * j));
            }
            t[start / 4] = word;
        }

        n2[0] = (uint32_t)(t[0] | (t[1] << 32)) & mask_lowest_28bits;
        n2[1] = (uint32_t)((t[0] >> 28) | (t[1] << 4)) & mask_lowest_28bits;
        n2[2] = (uint32_t)((t[1] >> 24) | (t[2] << 8)) & mask_lowest_28bits;
        n2[3] = (uint32_t)((t[2] >> 20) | (t[3] << 12)) & mask_lowest_28bits;
        n2[4] = (uint32_t)((t[3] >> 16) | (t[4] << 16)) & mask_lowest_28bits;
        n2[5] = (uint32_t)((t[4] >> 12) | (t[5] << 20)) & mask_lowest_28bits;
        n2[6] = (uint32_t)((t[5] >> 8) | (t[6] << 24)) & mask_lowest_28bits;
        n2[7] = (uint32_t)(t[6] >> 4) & mask_lowest_17bits; 

        // for n3, block3:
        for (uint64_t i = 0; i+4 <= BLOCK_SIZE + 1; i+= 4){
            uint64_t word = (uint64_t)block3[i]
                  | ((uint64_t)block3[i + 1] << 8)
                  | ((uint64_t)block3[i + 2] << 16)
                  | ((uint64_t)block3[i + 3] << 24);
            t[i/4] = word; 
        }
        remainder = (BLOCK_SIZE + 1) % 4;
        if (remainder != 0){
            uint64_t start = (BLOCK_SIZE + 1) - remainder;
            uint64_t word = 0;
            for (uint64_t j = 0; j < remainder; j++){
                word |= ((uint64_t)block3[start + j] << (8 * j));
            }
            t[start / 4] = word;
        }

        n3[0] = (uint32_t)(t[0] | (t[1] << 32)) & mask_lowest_28bits;
        n3[1] = (uint32_t)((t[0] >> 28) | (t[1] << 4)) & mask_lowest_28bits;
        n3[2] = (uint32_t)((t[1] >> 24) | (t[2] << 8)) & mask_lowest_28bits;
        n3[3] = (uint32_t)((t[2] >> 20) | (t[3] << 12)) & mask_lowest_28bits;
        n3[4] = (uint32_t)((t[3] >> 16) | (t[4] << 16)) & mask_lowest_28bits;
        n3[5] = (uint32_t)((t[4] >> 12) | (t[5] << 20)) & mask_lowest_28bits;
        n3[6] = (uint32_t)((t[5] >> 8) | (t[6] << 24)) & mask_lowest_28bits;
        n3[7] = (uint32_t)(t[6] >> 4) & mask_lowest_17bits;
        
        // for n4, block4:
        for (uint64_t i = 0; i+4 <= BLOCK_SIZE + 1; i+= 4){
            uint64_t word = (uint64_t)block4[i]
                  | ((uint64_t)block4[i + 1] << 8)
                  | ((uint64_t)block4[i + 2] << 16)
                  | ((uint64_t)block4[i + 3] << 24);
            t[i/4] = word; 
        }
        remainder = (BLOCK_SIZE + 1) % 4;
        if (remainder != 0){
            uint64_t start = (BLOCK_SIZE + 1) - remainder;
            uint64_t word = 0;
            for (uint64_t j = 0; j < remainder; j++){
                word |= ((uint64_t)block4[start + j] << (8 * j));
            }
            t[start / 4] = word;
        }

        n4[0] = (uint32_t)(t[0] | (t[1] << 32)) & mask_lowest_28bits;
        n4[1] = (uint32_t)((t[0] >> 28) | (t[1] << 4)) & mask_lowest_28bits;
        n4[2] = (uint32_t)((t[1] >> 24) | (t[2] << 8)) & mask_lowest_28bits;
        n4[3] = (uint32_t)((t[2] >> 20) | (t[3] << 12)) & mask_lowest_28bits;
        n4[4] = (uint32_t)((t[3] >> 16) | (t[4] << 16)) & mask_lowest_28bits;
        n4[5] = (uint32_t)((t[4] >> 12) | (t[5] << 20)) & mask_lowest_28bits;
        n4[6] = (uint32_t)((t[5] >> 8) | (t[6] << 24)) & mask_lowest_28bits;
        n4[7] = (uint32_t)(t[6] >> 4) & mask_lowest_17bits;

        // ------------------------------------------------------------------------------

        // -------------------------- mulmod_p(n, r) for n1, n2, n3, n4 and acc -----------------
        
        uint64_t mult_small[NUM_LIMBS] = {0};
        uint64_t mult_large[NUM_LIMBS] = {0};
        uint64_t mask_lowest_6bits = 0x3f; 

        for (int i = 0; i < NUM_LIMBS; i++){
            for(int j = 0; j < NUM_LIMBS; j++){
                int k = i+j;
                if (k < NUM_LIMBS){
                    mult_small[k] += (uint64_t)n1[i]* r4[j] + (uint64_t)n2[i]* r3[j] 
                                    + (uint64_t)n3[i]* r2[j] + (uint64_t)n4[i]* r[j] 
                                    + (uint64_t)acc[i]* r4[j];
                }
                else{
                    mult_large[k - NUM_LIMBS] += (uint64_t)n1[i]* three_r4[j] + (uint64_t)n2[i]* three_r3[j] 
                                                + (uint64_t)n3[i]* three_r2[j] + (uint64_t)n4[i]* three_r[j] 
                                                + (uint64_t)acc[i]* three_r4[j];
                }
            }
        }

        uint64_t carry = 0;
        uint64_t wrap_carry = 0;
        uint64_t sum;

        for(int i = 0; i < 7; i++){
            
            sum = mult_small[i] + ((mult_large[i] & mask_lowest_17bits) << 11) + wrap_carry + carry;
            acc[i] = (uint32_t)(sum & mask_lowest_28bits);
            carry = sum >> 28;
            wrap_carry = mult_large[i] >> 17;
        }

        sum = mult_small[7] + ((mult_large[7] & mask_lowest_6bits) << 11) + wrap_carry + carry;
        acc[7] = (uint32_t)(sum & mask_lowest_17bits);
        carry = sum >> 17;
        wrap_carry = mult_large[7] >> 6;

        total_carry = (carry + wrap_carry) * 3;
        // ------------------------------------------------------------------------------

        // --------------------- wrap around -----------------------------
        carry = (uint64_t)acc[0] + total_carry;
        acc[0] = (uint32_t)(carry &mask_lowest_28bits);
        carry >>= 28;
        acc[1] += (uint32_t)carry;
        carry = acc[1] >> 28;
        acc[1] &= mask_lowest_28bits;
        acc[2] += (uint32_t)carry;
        // ------------------------------------------------------------------------------
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
        // ----------------- to_large_num_rep(n, block, block_len + 1) ------------------
        uint64_t t[NUM_LIMBS] = {0}; 
        
        for (uint64_t i = 0; i+4 <= block_len + 1; i+= 4){
            uint64_t word = (uint64_t)block[i]
                  | ((uint64_t)block[i + 1] << 8)
                  | ((uint64_t)block[i + 2] << 16)
                  | ((uint64_t)block[i + 3] << 24);
            t[i/4] = word; 
        }
        uint64_t remainder = (block_len + 1) % 4;
        if (remainder != 0){
            uint64_t start = (block_len + 1) - remainder;
            uint64_t word = 0;
            for (uint64_t j = 0; j < remainder; j++){
                word |= ((uint64_t)block[start + j] << (8 * j));
            }
            t[start / 4] = word;
        }


        n[0] = (uint32_t)(t[0] | (t[1] << 32)) & mask_lowest_28bits;
        n[1] = (uint32_t)((t[0] >> 28) | (t[1] << 4)) & mask_lowest_28bits;
        n[2] = (uint32_t)((t[1] >> 24) | (t[2] << 8)) & mask_lowest_28bits;
        n[3] = (uint32_t)((t[2] >> 20) | (t[3] << 12)) & mask_lowest_28bits;
        n[4] = (uint32_t)((t[3] >> 16) | (t[4] << 16)) & mask_lowest_28bits;
        n[5] = (uint32_t)((t[4] >> 12) | (t[5] << 20)) & mask_lowest_28bits;
        n[6] = (uint32_t)((t[5] >> 8) | (t[6] << 24)) & mask_lowest_28bits;
        n[7] = (uint32_t)(t[6] >> 4) & mask_lowest_17bits; 
        // ------------------------------------------------------------------------------

        // acc += n
        // ----------------- add_large_nums_88(acc, n) ----------------------------------
        uint64_t carry = 0;
       
        for (int i = 0; i < 7; i++){
            carry = (uint64_t)acc[i] + n[i] + carry;
            acc[i] = (uint32_t)(carry &mask_lowest_28bits);
            carry >>= 28;
        }

        carry = (uint64_t)acc[7] + n[7] + carry;
        acc[7] = (uint32_t)(carry & mask_lowest_17bits);
        carry >>= 17;

        acc[0] += (uint32_t)(carry * 3);
        // ------------------------------------------------------------------------------

        // acc = (acc * r) mod p
        // ------------------------ mulmod_p(acc, r) ------------------------------------
        uint64_t mult_small[NUM_LIMBS] = {0};
        uint64_t mult_large[NUM_LIMBS] = {0};
        uint64_t mask_lowest_6bits = 0x3f; 

        for (int i = 0; i < NUM_LIMBS; i++){
            for(int j = 0; j < NUM_LIMBS; j++){
                int k = i+j;
                if (k < NUM_LIMBS){
                    mult_small[k] += (uint64_t)acc[i]* r[j];
                }
                else{
                    mult_large[k - NUM_LIMBS] += (uint64_t)acc[i]* three_r[j];
                }
            }
        }

        carry = 0;
        uint64_t wrap_carry = 0;

        for(int i = 0; i < 7; i++){
            
            uint64_t sum = mult_small[i] + ((mult_large[i] & mask_lowest_17bits) << 11) + wrap_carry + carry;
            acc[i] = (uint32_t)(sum & mask_lowest_28bits);
            carry = sum >> 28;
            wrap_carry = mult_large[i] >> 17;
        }

        uint64_t sum = mult_small[7] + ((mult_large[7] & mask_lowest_6bits) << 11) + wrap_carry + carry;
        acc[7] = (uint32_t)(sum & mask_lowest_17bits);
        carry = sum >> 17;
        wrap_carry = mult_large[7] >> 6;

        uint64_t total_carry = (carry + wrap_carry) * 3;
        uint64_t sum0 = (uint64_t)acc[0] + total_carry;
        acc[0] = (uint32_t)(sum0 & mask_lowest_28bits);
        carry = sum0 >> 28;
        acc[0] &= mask_lowest_28bits;
        acc[1] += (uint32_t)carry;
        carry = acc[1] >> 28;
        acc[1] &= mask_lowest_28bits;
        acc[2] += (uint32_t)carry;
        // -------------------------------------------------------------------------------
    }

    // ----------------------------- add_large_nums_88(acc, s) ---------------------------
    carry = 0;
    
    for (int i = 0; i < 7; i++){
        carry = (uint64_t)acc[i] + s[i] + carry;
        acc[i] = (uint32_t)(carry &mask_lowest_28bits);
        carry >>= 28;
    }

    carry = (uint64_t)acc[7] + s[7] + carry;
    acc[7] = (uint32_t)(carry & mask_lowest_17bits);
    carry >>= 17;

    acc[0] += (uint32_t)(carry * 3);
    // -----------------------------------------------------------------------------------
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    // ----------------------------- to_26_le_bytes(acc, tag) ----------------------------
    uint32_t t[7] = {0};

    t[0] =  (uint32_t)(acc[0]) | (uint32_t)(acc[1] << 28);
    t[1] =  (uint32_t)(acc[1] >> 4) | (uint32_t)(acc[2] << 24);
    t[2] =  (uint32_t)(acc[2] >> 8) | (uint32_t)(acc[3] << 20);
    t[3] =  (uint32_t)(acc[3] >> 12) | (uint32_t)(acc[4] << 16);
    t[4] =  (uint32_t)(acc[4] >> 16) | (uint32_t)(acc[5] << 12);
    t[5] =  (uint32_t)(acc[5] >> 20) | (uint32_t)(acc[6] << 8);
    t[6] =  (uint32_t)(acc[6] >> 24) | (uint32_t)(acc[7] << 4);

    
    tag[0]  = (unsigned char)(t[0]);
    tag[1]  = (unsigned char)(t[0] >> 8);
    tag[2]  = (unsigned char)(t[0] >> 16);
    tag[3]  = (unsigned char)(t[0] >> 24);
    tag[4]  = (unsigned char)(t[1]);
    tag[5]  = (unsigned char)(t[1] >> 8);
    tag[6]  = (unsigned char)(t[1] >> 16);
    tag[7]  = (unsigned char)(t[1] >> 24);
    tag[8]  = (unsigned char)(t[2]);
    tag[9]  = (unsigned char)(t[2] >> 8);
    tag[10] = (unsigned char)(t[2] >> 16);
    tag[11] = (unsigned char)(t[2] >> 24);
    tag[12] = (unsigned char)(t[3]);
    tag[13] = (unsigned char)(t[3] >> 8);
    tag[14] = (unsigned char)(t[3] >> 16);
    tag[15] = (unsigned char)(t[3] >> 24);
    tag[16] = (unsigned char)(t[4]);
    tag[17] = (unsigned char)(t[4] >> 8);
    tag[18] = (unsigned char)(t[4] >> 16);
    tag[19] = (unsigned char)(t[4] >> 24);
    tag[20] = (unsigned char)(t[5]);
    tag[21] = (unsigned char)(t[5] >> 8);
    tag[22] = (unsigned char)(t[5] >> 16);
    tag[23] = (unsigned char)(t[5] >> 24);
    tag[24] = (unsigned char)(t[6]);
    tag[25] = (unsigned char)(t[6] >> 8);
    // -----------------------------------------------------------------------------------
    return tag;
}