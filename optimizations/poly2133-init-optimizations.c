#include <stdint.h> 
#include <string.h>
#include <stdlib.h>

#define NUM_LIMBS 8
#define KEY_SIZE 54
#define SIZE_HALF_KEY 27

#define CLEAR_TOP_4_BITS 0x0f
#define CLEAR_LOW_2_BITS 0xfc

#define mask_lowest_28bits 0x0FFFFFFF
#define mask_lowest_17bits 0x0001FFFF

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

#define CREATE_LIMBS_32_BIT_TEMP(out, bytes) \
    do { \
        uint32_t _r0 = (uint32_t)(bytes)[0]     \
               | ((uint32_t)(bytes)[1]  << 8)   \
               | ((uint32_t)(bytes)[2]  << 16)  \
               | ((uint32_t)(bytes)[3]  << 24); \
        \
        uint32_t _r1 = (uint32_t)(bytes)[4]     \
               | ((uint32_t)(bytes)[5]  << 8)   \
               | ((uint32_t)(bytes)[6]  << 16)  \
               | ((uint32_t)(bytes)[7]  << 24); \
        \
        uint32_t _r2 = (uint32_t)(bytes)[8]     \
               | ((uint32_t)(bytes)[9]  << 8)   \
               | ((uint32_t)(bytes)[10] << 16)  \
               | ((uint32_t)(bytes)[11] << 24); \
        \
        uint32_t _r3 = (uint32_t)(bytes)[12]    \
               | ((uint32_t)(bytes)[13]  << 8)  \
               | ((uint32_t)(bytes)[14] << 16)  \
               | ((uint32_t)(bytes)[15] << 24); \
        \
        uint32_t _r4 = (uint32_t)(bytes)[16]    \
               | ((uint32_t)(bytes)[17] << 8)   \
               | ((uint32_t)(bytes)[18] << 16)  \
               | ((uint32_t)(bytes)[19] << 24); \
        \
        uint32_t _r5 = (uint32_t)(bytes)[20]    \
               | ((uint32_t)(bytes)[21] << 8)   \
               | ((uint32_t)(bytes)[22] << 16)  \
               | ((uint32_t)(bytes)[23] << 24); \
        \
        /* Key is 27 bytes long */ \
        uint32_t _r6 = (uint32_t)(bytes)[24]    \
               | ((uint32_t)(bytes)[25] << 8)   \
               | ((uint32_t)(bytes)[26] << 16); \
        \
        (out)[0] = _r0                         & mask_lowest_28bits; \
        (out)[1] = ((_r0 >> 28) | (_r1 << 4))  & mask_lowest_28bits; \
        (out)[2] = ((_r1 >> 24) | (_r2 << 8))  & mask_lowest_28bits; \
        (out)[3] = ((_r2 >> 20) | (_r3 << 12)) & mask_lowest_28bits; \
        (out)[4] = ((_r3 >> 16) | (_r4 << 16)) & mask_lowest_28bits; \
        (out)[5] = ((_r4 >> 12) | (_r5 << 20)) & mask_lowest_28bits; \
        (out)[6] = ((_r5 >> 8) | (_r6 << 24))  & mask_lowest_28bits; \
        (out)[7] = (_r6 >> 4)                  & mask_lowest_17bits; \
    } while (0)

#define CREATE_LIMBS_64_BIT_TEMP(out, bytes) \
    do { \
        uint64_t _r0 = (uint64_t)(bytes)[0] \
            | ((uint64_t)(bytes)[1] <<  8)  \
            | ((uint64_t)(bytes)[2] << 16)  \
            | ((uint64_t)(bytes)[3] << 24)  \
            | ((uint64_t)(bytes)[4] << 32)  \
            | ((uint64_t)(bytes)[5] << 40)  \
            | ((uint64_t)(bytes)[6] << 48)  \
            | ((uint64_t)(bytes)[7] << 56); \
        \
        uint64_t _r1 = (uint64_t)(bytes)[8]  \
            | ((uint64_t)(bytes)[9]  <<  8)  \
            | ((uint64_t)(bytes)[10] << 16)  \
            | ((uint64_t)(bytes)[11] << 24)  \
            | ((uint64_t)(bytes)[12] << 32)  \
            | ((uint64_t)(bytes)[13] << 40)  \
            | ((uint64_t)(bytes)[14] << 48)  \
            | ((uint64_t)(bytes)[15] << 56); \
        \
        uint64_t _r2 = (uint64_t)(bytes)[16] \
            | ((uint64_t)(bytes)[17] <<  8)  \
            | ((uint64_t)(bytes)[18] << 16)  \
            | ((uint64_t)(bytes)[19] << 24)  \
            | ((uint64_t)(bytes)[20] << 32)  \
            | ((uint64_t)(bytes)[21] << 40)  \
            | ((uint64_t)(bytes)[22] << 48)  \
            | ((uint64_t)(bytes)[23] << 56); \
        \
        uint64_t _r3 = (uint64_t)(bytes)[24] \
            | ((uint64_t)(bytes)[25] <<  8)  \
            | ((uint64_t)(bytes)[26] << 16); \
        \
        (out)[0] = (uint32_t)(_r0)                       & mask_lowest_28bits; \
        (out)[1] = (uint32_t)((_r0 >> 28))               & mask_lowest_28bits; \
        (out)[2] = (uint32_t)((_r0 >> 56) | (_r1 << 8))  & mask_lowest_28bits; \
        (out)[3] = (uint32_t)((_r1 >> 20))               & mask_lowest_28bits; \
        (out)[4] = (uint32_t)((_r1 >> 48) | (_r2 << 16)) & mask_lowest_28bits; \
        (out)[5] = (uint32_t)((_r2 >> 12))               & mask_lowest_28bits; \
        (out)[6] = (uint32_t)((_r2 >> 40) | (_r3 << 24)) & mask_lowest_28bits; \
        (out)[7] = (uint32_t)(_r3 >> 4)                  & mask_lowest_17bits; \
    } while (0) 
    
#define BYTE_PTR_TO_U32(byte_array)      \
    (                                    \
       (uint32_t)(byte_array)[0]         \
     | ((uint32_t)(byte_array)[1] <<  8) \
     | ((uint32_t)(byte_array)[2] << 16) \
     | ((uint32_t)(byte_array)[3] << 24) \
    )
        
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

void poly2133_init_unrolled_32(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    uint64_t half_key_len = KEY_SIZE / 2;
    unsigned char r_bytes[half_key_len];
    memcpy(r_bytes, key, half_key_len);
    
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

    CREATE_LIMBS_32_BIT_TEMP(r, r_bytes);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    s_bytes[half_key_len - 1] &= clear_top4_bits;

    CREATE_LIMBS_32_BIT_TEMP(s, s_bytes);
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

void poly2133_init_unrolled_64(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    uint64_t half_key_len = KEY_SIZE / 2;
    unsigned char r_bytes[half_key_len];
    memcpy(r_bytes, key, half_key_len);
    
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

    CREATE_LIMBS_64_BIT_TEMP(r, r_bytes);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    s_bytes[half_key_len - 1] &= clear_top4_bits;

    CREATE_LIMBS_64_BIT_TEMP(s, s_bytes);
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

void poly2133_init_scalar_replacement(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    unsigned char r_bytes[SIZE_HALF_KEY];
    unsigned char s_bytes[SIZE_HALF_KEY];

    memcpy(r_bytes, key, SIZE_HALF_KEY);

    r_bytes[3]  &= CLEAR_TOP_4_BITS;
    r_bytes[7]  &= CLEAR_TOP_4_BITS;
    r_bytes[11] &= CLEAR_TOP_4_BITS;
    r_bytes[15] &= CLEAR_TOP_4_BITS;
    r_bytes[22] &= CLEAR_TOP_4_BITS;
    r_bytes[25] &= CLEAR_TOP_4_BITS;
    r_bytes[26] &= CLEAR_TOP_4_BITS;

    r_bytes[4]  &= CLEAR_LOW_2_BITS;
    r_bytes[8]  &= CLEAR_LOW_2_BITS;
    r_bytes[12] &= CLEAR_LOW_2_BITS;
    r_bytes[17] &= CLEAR_LOW_2_BITS;
    r_bytes[24] &= CLEAR_LOW_2_BITS;

    CREATE_LIMBS_64_BIT_TEMP(r, r_bytes);
    
    
    memcpy(s_bytes, key + SIZE_HALF_KEY, SIZE_HALF_KEY);
    
    // make sure s is not > p
    s_bytes[SIZE_HALF_KEY - 1] &= CLEAR_TOP_4_BITS;
    CREATE_LIMBS_64_BIT_TEMP(s, s_bytes);

    memset(acc, 0, 32); 
}

void poly2133_init_precompute_clamp_masks(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    r[0] =  BYTE_PTR_TO_U32(key)           & 0x0FFFFFFF;
    r[1] = (BYTE_PTR_TO_U32(key + 3) >> 4) & 0x0FFFFFC0;
    r[2] =  BYTE_PTR_TO_U32(key + 7)       & 0x0FFFFC0F;
    r[3] = (BYTE_PTR_TO_U32(key + 10) >> 4)& 0x0FFFC0FF;
    r[4] =  BYTE_PTR_TO_U32(key + 14)      & 0x0CFF0FFF;
    r[5] = (BYTE_PTR_TO_U32(key + 17) >> 4)& 0x0FFFFFFF;
    r[6] =  BYTE_PTR_TO_U32(key + 21)      & 0x0CFF0FFF;
    r[7] = (BYTE_PTR_TO_U32(key + 24) >> 4)& 0x0000F0FF;

    s[0] =  BYTE_PTR_TO_U32(key + 27)      & 0x0FFFFFFF;
    s[1] = (BYTE_PTR_TO_U32(key + 30) >> 4)& 0x0FFFFFFF;
    s[2] =  BYTE_PTR_TO_U32(key + 34)      & 0x0FFFFFFF;
    s[3] = (BYTE_PTR_TO_U32(key + 37) >> 4)& 0x0FFFFFFF;
    s[4] =  BYTE_PTR_TO_U32(key + 41)      & 0x0FFFFFFF;
    s[5] = (BYTE_PTR_TO_U32(key + 44) >> 4)& 0x0FFFFFFF;
    s[6] =  BYTE_PTR_TO_U32(key + 48)      & 0x0FFFFFFF;

    
    uint32_t s7 = (uint32_t)key[51] | ((uint32_t)key[52] << 8) | ((uint32_t)key[53] << 16);
    
    s[7] = (s7 >> 4) & 0x0000FFFF;

    acc[0] = 0;
    acc[1] = 0;
    acc[2] = 0;
    acc[3] = 0;
    acc[4] = 0;
    acc[5] = 0;
    acc[6] = 0;
    acc[7] = 0;
}