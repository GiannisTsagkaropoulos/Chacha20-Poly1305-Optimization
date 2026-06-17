#include <stdint.h> 
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>
#include "constants.h"

#define TO_LARGE_NUM_REP_2133(out, bytes, len) \
    do { \
        uint64_t _tr[LIMBS_2133] = {0}; \
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

#define CREATE_LIMBS_32_BIT_TEMP_2133(out, bytes) \
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

#define CREATE_LIMBS_64_BIT_TEMP_2133(out, bytes) \
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
    
// handle conversions from bytes to 7x28 + 17-bit representation
static inline void to_large_num_rep_2133(uint32_t out[LIMBS_2133], const unsigned char *bytes, uint64_t len_bytes){
    uint64_t t[LIMBS_2133] = {0}; 
    for (uint64_t i = 0; i < len_bytes; i++){
        t[i/4] |= ((uint64_t)bytes[i] << ((i%4)*8)); 
    }

    for(int i = 0; i < 7; i++){
        int bit_start = 28*i; // compute where next 28 bits start in t
        int t_idx = bit_start / 32; // get idx of t which contains start of next 28 bits
        int bit_in_t = bit_start % 32; // get bit offset within t[t_idx]
        out[i] = (uint32_t)((t[t_idx] >> bit_in_t) | (t[t_idx + 1] << (32 - bit_in_t))) & mask_lowest_28bits; 

    }

    // only save the lowest 17 bits in the last entry since we chose a representation of 7x28 + 17 bits
    out[7] = (uint32_t)(t[6] >> 4) & mask_lowest_17bits; 
}


void poly2133_init_baseline(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]);
void poly2133_init_inlined(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]);
void poly2133_init_unrolled_64(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]);
void poly2133_init_unrolled_32(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]);
void poly2133_init_scalar_replacement(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]);
void poly2133_init_precompute_clamp_masks(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]);
void poly2133_init_vectorized(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]);


typedef void(*poly2133_init_func)(uint32_t *acc, uint32_t* r, uint32_t* s, const unsigned char *key);