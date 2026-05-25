#include <stdint.h> 
#include <string.h>
#include <stdlib.h>

#define NUM_LIMBS 8
#define BLOCK_SIZE 26
#define TAG_SIZE 26
#define KEY_SIZE 54

const uint32_t mask_lowest_17bits = 0x1ffff;
const uint32_t mask_lowest_28bits = 0xfffffff;


#define TO_LARGE_NUM_REP(out, bytes, len) \
    do { \
        uint64_t _tr[NUM_LIMBS] = {0}; \
        for (uint64_t _i = 0; _i < (len); _i++) { \
            _tr[_i/4] |= ((uint64_t)(bytes)[_i] << ((_i%4)*8)); \
        } \
        \
        for (int _i = 0; _i < 7; _i++) { \
            int _bs = 28 * _i; \
            int _ti = _bs / 32; \
            int _bit = _bs % 32; \
            (out)[_i] = (uint32_t)((_tr[_ti] >> _bit) | \
                        (_tr[_ti + 1] << (32 - _bit))) & (mask_lowest_28bits); \
        } \
        (out)[7] = (uint32_t)(_tr[6] >> 4) & (mask_lowest_17bits); \
    } while (0)

#define TO_LARGE_NUM_REP_UNROLLED(out, bytes, len) \
    do { \
        uint64_t _tr[NUM_LIMBS] = {0}; \
        for (uint64_t _i = 0; _i < (len); _i+=4) { \
            uint64_t _word = (uint64_t)(bytes)[_i] \
                  | ((uint64_t)(bytes)[_i + 1] << 8) \
                  | ((uint64_t)(bytes)[_i + 2] << 16) \
                  | ((uint64_t)(bytes)[_i + 3] << 24); \
            _tr[_i/4] = _word; \
        } \
        \
        (out)[0] = (uint32_t)((_tr)[0] | ((_tr)[1] << 32)) & mask_lowest_28bits; \
        (out)[1] = (uint32_t)(((_tr)[0] >> 28) | ((_tr)[1] << 4)) & mask_lowest_28bits; \
        (out)[2] = (uint32_t)(((_tr)[1] >> 24) | ((_tr)[2] << 8)) & mask_lowest_28bits; \
        (out)[3] = (uint32_t)(((_tr)[2] >> 20) | ((_tr)[3] << 12)) & mask_lowest_28bits; \
        (out)[4] = (uint32_t)(((_tr)[3] >> 16) | ((_tr)[4] << 16)) & mask_lowest_28bits; \
        (out)[5] = (uint32_t)(((_tr)[4] >> 12) | ((_tr)[5] << 20)) & mask_lowest_28bits; \
        (out)[6] = (uint32_t)(((_tr)[5] >> 8) | ((_tr)[6] << 24)) & mask_lowest_28bits; \
        (out)[7] = (uint32_t)((_tr)[6] >> 4) & (mask_lowest_17bits); \
    } while (0)

// keylength must be 54 bytes
void poly2133_init_baseline(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
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

void poly2133_init_inlined(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    uint64_t half_key_len = KEY_SIZE / 2;
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
    TO_LARGE_NUM_REP(r, r_bytes, half_key_len);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    // convert second half of key into 7x28 + 17-bit representation for s
    TO_LARGE_NUM_REP(s, s_bytes, half_key_len);

    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

void poly2133_init_unrolled(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    // split key into two halves (first half into r, other in s)
    uint64_t half_key_len = KEY_SIZE / 2;
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
    TO_LARGE_NUM_REP_UNROLLED(r, r_bytes, half_key_len);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;

    // convert second half of key into 7x28 + 17-bit representation for s
    TO_LARGE_NUM_REP_UNROLLED(s, s_bytes, half_key_len);
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

