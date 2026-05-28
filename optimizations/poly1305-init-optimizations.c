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
