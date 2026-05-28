 #include <stdint.h> 
#include <string.h>
#include <stdlib.h>

#define NUM_LIMBS 5
#define KEY_SIZE 32
#define HALF_KEY_SIZE 16
#define KEEP_LOWEST_26_BITS 0x3FFFFFF

#define CLEAR_TOP_4_BITS 0b00001111
#define CLEAR_LOW_2_BITS 0b11111100

#define CREATE_LIMBS_64(out, bytes) \
 do { \
     uint64_t _t0 = (uint64_t)(bytes)[0] \
            | ((uint64_t)(bytes)[1] <<  8)  \
            | ((uint64_t)(bytes)[2] << 16)  \
            | ((uint64_t)(bytes)[3] << 24)  \
            | ((uint64_t)(bytes)[4] << 32)  \
            | ((uint64_t)(bytes)[5] << 40)  \
            | ((uint64_t)(bytes)[6] << 48)  \
            | ((uint64_t)(bytes)[7] << 56); \
        \
        uint64_t _t1 = (uint64_t)(bytes)[8]  \
            | ((uint64_t)(bytes)[9]  <<  8)  \
            | ((uint64_t)(bytes)[10] << 16)  \
            | ((uint64_t)(bytes)[11] << 24)  \
            | ((uint64_t)(bytes)[12] << 32)  \
            | ((uint64_t)(bytes)[13] << 40)  \
            | ((uint64_t)(bytes)[14] << 48)  \
            | ((uint64_t)(bytes)[15] << 56); \
        \
        \
    (out)[0] = (uint32_t)(_t0)                      & KEEP_LOWEST_26_BITS; \
    (out)[1] = (uint32_t)(_t0 >> 26)                & KEEP_LOWEST_26_BITS; \
    (out)[2] = (uint32_t)((_t0 >> 52) | (_t1 << 12))& KEEP_LOWEST_26_BITS; \
    (out)[3] = (uint32_t)(_t1 >> 14)                & KEEP_LOWEST_26_BITS; \
    (out)[4] = (uint32_t)(_t1 >> 40)                & KEEP_LOWEST_26_BITS; \
    } while (0)    

static inline void create_limbs_64(uint32_t out[5], const unsigned char *bytes) {
    uint64_t t0 = (uint64_t)(bytes)[0] 
        | ((uint64_t)(bytes)[1] <<  8)  
        | ((uint64_t)(bytes)[2] << 16)  
        | ((uint64_t)(bytes)[3] << 24)  
        | ((uint64_t)(bytes)[4] << 32)  
        | ((uint64_t)(bytes)[5] << 40)  
        | ((uint64_t)(bytes)[6] << 48)  
        | ((uint64_t)(bytes)[7] << 56); 

    uint64_t t1 = (uint64_t)(bytes)[8]  
        | ((uint64_t)(bytes)[9]  <<  8)  
        | ((uint64_t)(bytes)[10] << 16)  
        | ((uint64_t)(bytes)[11] << 24)  
        | ((uint64_t)(bytes)[12] << 32)  
        | ((uint64_t)(bytes)[13] << 40)  
        | ((uint64_t)(bytes)[14] << 48)  
        | ((uint64_t)(bytes)[15] << 56); 

    out[0] = (uint32_t)(t0)                      & KEEP_LOWEST_26_BITS;
    out[1] = (uint32_t)(t0 >> 26)                & KEEP_LOWEST_26_BITS;
    out[2] = (uint32_t)((t0 >> 52) | (t1 << 12)) & KEEP_LOWEST_26_BITS;
    out[3] = (uint32_t)(t1 >> 14)                & KEEP_LOWEST_26_BITS;
    out[4] = (uint32_t)(t1 >> 40)                & KEEP_LOWEST_26_BITS;
}


void poly1305_init_baseline(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
void poly1305_init_inline_64(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
void poly1305_init_scalar_replacement(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);

typedef void(*poly1305_init_func)(uint32_t *acc, uint32_t* r, uint32_t* s, const unsigned char *key);