#include <immintrin.h>
#include <poly1305_init_opts.h>

void poly1305_init_baseline(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    const uint8_t clear_top4_bits = 0b00001111; 
    const uint8_t clear_lowest2_bits = 0b11111100;
    int half_key_len = KEY_SIZE / 2;

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

    create_limbs_64(r, r_bytes); 

    memcpy(s_bytes, key + half_key_len, half_key_len);
    create_limbs_64(s, s_bytes);

    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

void poly1305_init_inline_64(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    const uint8_t clear_top4_bits = 0b00001111; 
    const uint8_t clear_lowest2_bits = 0b11111100;
    int half_key_len = KEY_SIZE / 2;

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

    CREATE_LIMBS_64(r, r_bytes); 

    memcpy(s_bytes, key + half_key_len, half_key_len);
    CREATE_LIMBS_64(s, s_bytes);

    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

void poly1305_init_scalar_replacement(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    unsigned char r_bytes[HALF_KEY_SIZE];

    memcpy(r_bytes, key, HALF_KEY_SIZE);
    
    r_bytes[3]  &= CLEAR_TOP_4_BITS;
    r_bytes[7]  &= CLEAR_TOP_4_BITS;
    r_bytes[11] &= CLEAR_TOP_4_BITS;
    r_bytes[15] &= CLEAR_TOP_4_BITS;

    r_bytes[4]  &= CLEAR_LOW_2_BITS;
    r_bytes[8]  &= CLEAR_LOW_2_BITS;
    r_bytes[12] &= CLEAR_LOW_2_BITS;

    CREATE_LIMBS_64(r, r_bytes); 
    CREATE_LIMBS_64(s, key + HALF_KEY_SIZE);

    memset(acc, 0, 20); 
}

void poly1305_init_precompute_clamp_masks(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    r[0] =  BYTE_PTR_TO_U32(key)        & 0x3FFFFFF;
    r[1] = (BYTE_PTR_TO_U32(key + 3) >> 2)  & 0x3FFFF03;
    r[2] = (BYTE_PTR_TO_U32(key + 6) >> 4)  & 0x3FFC0FF;
    r[3] = (BYTE_PTR_TO_U32(key + 9) >> 6)  & 0x3F03FFF;
    r[4] = (BYTE_PTR_TO_U32(key + 12) >> 8) & 0x00FFFFF;

    CREATE_LIMBS_64(s, key + HALF_KEY_SIZE);

    acc[0] = 0;
    acc[1] = 0;
    acc[2] = 0;
    acc[3] = 0;
    acc[4] = 0;
}


void poly1305_init_vectorized(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    __m128i key_offsets     = _mm_set_epi32(9, 6, 3, 0);
    __m128i r_vec = _mm_i32gather_epi32((const int *)key, key_offsets, 1);

    __m128i r_shift_amounts = _mm_set_epi32(6, 4, 2, 0);
    __m128i r_mask          = _mm_set_epi32(0x3F03FFF, 0x3FFC0FF, 0x3FFFF03, 0x3FFFFFF);
    
    r_vec = _mm_srlv_epi32(r_vec, r_shift_amounts);
    r_vec = _mm_and_si128(r_vec, r_mask);
    _mm_storeu_si128((__m128i *)r, r_vec);
    r[4] = (BYTE_PTR_TO_U32(key + 12) >> 8) & 0x00FFFFF;


    const unsigned char *s_key = key + HALF_KEY_SIZE; 
    
    __m128i s_offsets       = _mm_set_epi32(9, 6, 3, 0);
    __m128i s_vec = _mm_i32gather_epi32((const int *)s_key, s_offsets, 1);

    __m128i s_shift_amounts = _mm_set_epi32(6, 4, 2, 0);
    __m128i s_mask          = _mm_set1_epi32(KEEP_LOWEST_26_BITS); 

    s_vec = _mm_srlv_epi32(s_vec, s_shift_amounts);
    s_vec = _mm_and_si128(s_vec, s_mask);
    uint32_t s4 = (uint32_t)(s_key)[13] | ((uint32_t)(s_key)[14]  <<  8) | ((uint32_t)(s_key)[15]  <<  16);

    _mm_storeu_si128((__m128i *)s, s_vec);
    s[4] = s4 & 0x3FFFFFF;

    
    __m128i zero_vec = _mm_setzero_si128();
    _mm_store_si128((__m128i *)acc, zero_vec);
    acc[4] = 0;
}
