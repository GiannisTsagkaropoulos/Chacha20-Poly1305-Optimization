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