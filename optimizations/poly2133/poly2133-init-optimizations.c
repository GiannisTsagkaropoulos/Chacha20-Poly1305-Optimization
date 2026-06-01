#include <stdint.h> 
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>
#include <poly2133_init_opts.h>

void poly2133_init_baseline(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]) {
    const uint8_t clear_top4_bits = 0b00001111;
    const uint8_t clear_lowest2_bits = 0b11111100;
    int half_key_len = KEY_SIZE_2133 / 2;

    unsigned char r_bytes[half_key_len];
    unsigned char s_bytes[half_key_len];

    memcpy(r_bytes, key, half_key_len);
    
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
    to_large_num_rep_2133(r, r_bytes, half_key_len);
    
    
    memcpy(s_bytes, key + half_key_len, half_key_len);

    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    to_large_num_rep_2133(s, s_bytes, half_key_len);

    memset(acc, 0, LIMBS_2133*sizeof(uint32_t)); 
}

void poly2133_init_inlined(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]) {
    const uint8_t clear_top4_bits = 0b00001111;
    const uint8_t clear_lowest2_bits = 0b11111100;
    uint64_t half_key_len = KEY_SIZE_2133 / 2;

    unsigned char r_bytes[half_key_len];
    unsigned char s_bytes[half_key_len];
    
    memcpy(r_bytes, key, half_key_len);
    
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

    r_bytes[half_key_len - 1] &= clear_top4_bits;
    TO_LARGE_NUM_REP_2133(r, r_bytes, half_key_len);
    

    memcpy(s_bytes, key + half_key_len, half_key_len);
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    TO_LARGE_NUM_REP_2133(s, s_bytes, half_key_len);

    memset(acc, 0, LIMBS_2133*sizeof(uint32_t)); 
}

void poly2133_init_unrolled_32(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]) {
    const uint8_t clear_top4_bits = 0b00001111;
    const uint8_t clear_lowest2_bits = 0b11111100;
    uint64_t half_key_len = KEY_SIZE_2133 / 2;

    unsigned char r_bytes[half_key_len];
    unsigned char s_bytes[half_key_len];

    memcpy(r_bytes, key, half_key_len);
    
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

    r_bytes[half_key_len - 1] &= clear_top4_bits;

    CREATE_LIMBS_32_BIT_TEMP_2133(r, r_bytes);
    
    memcpy(s_bytes, key + half_key_len, half_key_len);
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    CREATE_LIMBS_32_BIT_TEMP_2133(s, s_bytes);

    memset(acc, 0, LIMBS_2133*sizeof(uint32_t)); 
}

void poly2133_init_unrolled_64(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]) {
    const uint8_t clear_top4_bits = 0b00001111;
    const uint8_t clear_lowest2_bits = 0b11111100;
    uint64_t half_key_len = KEY_SIZE_2133 / 2;

    unsigned char r_bytes[half_key_len];
    unsigned char s_bytes[half_key_len];

    memcpy(r_bytes, key, half_key_len);

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

    r_bytes[half_key_len - 1] &= clear_top4_bits;
    CREATE_LIMBS_64_BIT_TEMP_2133(r, r_bytes);
    
    memcpy(s_bytes, key + half_key_len, half_key_len);
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    CREATE_LIMBS_64_BIT_TEMP_2133(s, s_bytes);

    memset(acc, 0, LIMBS_2133*sizeof(uint32_t)); 
}

void poly2133_init_scalar_replacement(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]) {
    unsigned char r_bytes[SIZE_HALF_KEY_2133];
    unsigned char s_bytes[SIZE_HALF_KEY_2133];

    memcpy(r_bytes, key, SIZE_HALF_KEY_2133);

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

    CREATE_LIMBS_64_BIT_TEMP_2133(r, r_bytes);
    
    
    memcpy(s_bytes, key + SIZE_HALF_KEY_2133, SIZE_HALF_KEY_2133);
    s_bytes[26] &= CLEAR_TOP_4_BITS;
    CREATE_LIMBS_64_BIT_TEMP_2133(s, s_bytes);

    memset(acc, 0, 32); 
}

void poly2133_init_precompute_clamp_masks(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]) {
    r[0] = (*(const uint32_t*)(key))            & 0x0FFFFFFF;
    r[1] = ((*(const uint32_t*)(key + 3)) >> 4) & 0x0FFFFFC0;
    r[2] = (*(const uint32_t*)(key + 7))        & 0x0FFFFC0F;
    r[3] = ((*(const uint32_t*)(key + 10)) >> 4)& 0x0FFFC0FF;
    r[4] = (*(const uint32_t*)(key + 14))       & 0x0CFF0FFF;
    r[5] = ((*(const uint32_t*)(key + 17)) >> 4)& 0x0FFFFFFF;
    r[6] = (*(const uint32_t*)(key + 21))       & 0x0CFF0FFF;
    r[7] = ((*(const uint32_t*)(key + 24)) >> 4)& 0x0000F0FF;

    s[0] = (*(const uint32_t*)(key + 27))       & 0x0FFFFFFF;
    s[1] = ((*(const uint32_t*)(key + 30)) >> 4)& 0x0FFFFFFF;
    s[2] = (*(const uint32_t*)(key + 34))       & 0x0FFFFFFF;
    s[3] = ((*(const uint32_t*)(key + 37)) >> 4)& 0x0FFFFFFF;
    s[4] = (*(const uint32_t*)(key + 41))       & 0x0FFFFFFF;
    s[5] = ((*(const uint32_t*)(key + 44)) >> 4)& 0x0FFFFFFF;
    s[6] = (*(const uint32_t*)(key + 48))       & 0x0FFFFFFF;

    
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

void poly2133_init_vectorized(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]) {    
    __m256i key_offsets = _mm256_setr_epi32(0, 3, 7, 10, 14, 17, 21, 24);

    __m256i r_vec = _mm256_i32gather_epi32((int *) key, key_offsets, 1);
    __m256i r_odd_shift = _mm256_srli_epi32(r_vec, 4);
    r_vec = _mm256_blend_epi32(r_vec, r_odd_shift, 0b10101010);

    __m256i r_mask =  _mm256_setr_epi32(0x0FFFFFFF, 0x0FFFFFC0, 0x0FFFFC0F, 0x0FFFC0FF, 0x0CFF0FFF, 0x0FFFFFFF, 0x0CFF0FFF, 0x0000F0FF);
    r_vec = _mm256_and_si256(r_vec, r_mask);


    __m256i s_vec = _mm256_i32gather_epi32((int *)(key + 27), key_offsets, 1);
    __m256i s_odd_shift = _mm256_srli_epi32(s_vec, 4);
    s_vec = _mm256_blend_epi32(s_vec, s_odd_shift, 0b10101010);

    __m256i s_mask = _mm256_setr_epi32(0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF,0x0FFFFFFF, 0x0FFFFFFF, 0x0FFFFFFF, 0x0000FFFF);
    s_vec = _mm256_and_si256(s_vec, s_mask);

    __m256i zero_vec = _mm256_setzero_si256();

    _mm256_store_si256((__m256i *)r,   r_vec);
    _mm256_store_si256((__m256i *)s,   s_vec);
    _mm256_store_si256((__m256i *)acc, zero_vec);
}