 #include <stdint.h> 
#include <string.h>
#include <stdlib.h>
#include "constants.h"
    
#define CREATE_LIMBS_32(out, bytes) \
 do { \
        uint32_t _t0 = *(const uint64_t*)(bytes);   \
        uint32_t _t1 = *(const uint64_t*)(bytes+4); \
        uint32_t _t2 = *(const uint64_t*)(bytes+8); \
        uint32_t _t3 = *(const uint64_t*)(bytes+12);\
       \
    (out)[0] = (uint32_t)(_t0)                        & KEEP_LOWEST_26_BITS; \
    (out)[1] = (uint32_t)((_t0 >> 26) | (_t1 << 6))   & KEEP_LOWEST_26_BITS; \
    (out)[2] = (uint32_t)((_t1 >> 20) | (_t2 << 12))  & KEEP_LOWEST_26_BITS; \
    (out)[3] = (uint32_t)((_t2 >> 14)  | (_t3 << 18)) & KEEP_LOWEST_26_BITS; \
    (out)[4] = (uint32_t)(_t3 >> 8)                   & KEEP_LOWEST_26_BITS; \
    } while (0)    

#define CREATE_LIMBS_64(out, bytes) \
 do { \
     uint64_t _t0 = *(const uint64_t*)(bytes);  \
     uint64_t _t1 = *(const uint64_t*)(bytes+8);\
        \
    (out)[0] = (uint32_t)(_t0)                      & KEEP_LOWEST_26_BITS; \
    (out)[1] = (uint32_t)(_t0 >> 26)                & KEEP_LOWEST_26_BITS; \
    (out)[2] = (uint32_t)((_t0 >> 52) | (_t1 << 12))& KEEP_LOWEST_26_BITS; \
    (out)[3] = (uint32_t)(_t1 >> 14)                & KEEP_LOWEST_26_BITS; \
    (out)[4] = (uint32_t)(_t1 >> 40)                & KEEP_LOWEST_26_BITS; \
    } while (0)  

static inline void create_limbs_64(uint32_t out[LIMBS_1305], const unsigned char *bytes) {
    uint64_t t0 = *(const uint64_t*)(bytes);
    uint64_t t1 = *(const uint64_t*)(bytes + 8);

    out[0] = (uint32_t)(t0)                      & KEEP_LOWEST_26_BITS;
    out[1] = (uint32_t)(t0 >> 26)                & KEEP_LOWEST_26_BITS;
    out[2] = (uint32_t)((t0 >> 52) | (t1 << 12)) & KEEP_LOWEST_26_BITS;
    out[3] = (uint32_t)(t1 >> 14)                & KEEP_LOWEST_26_BITS;
    out[4] = (uint32_t)(t1 >> 40)                & KEEP_LOWEST_26_BITS;
}

void poly1305_init_baseline(uint32_t acc[LIMBS_1305], uint32_t r[LIMBS_1305], uint32_t s[4], const unsigned char key[KEY_SIZE_1305]);
void poly1305_init_inline_64(uint32_t acc[LIMBS_1305], uint32_t r[LIMBS_1305], uint32_t s[4], const unsigned char key[KEY_SIZE_1305]);
void poly1305_init_scalar_replacement(uint32_t acc[LIMBS_1305], uint32_t r[LIMBS_1305], uint32_t s[4], const unsigned char key[KEY_SIZE_1305]);
void poly1305_init_precompute_clamp_masks(uint32_t acc[LIMBS_1305], uint32_t r[LIMBS_1305], uint32_t s[4], const unsigned char key[KEY_SIZE_1305]);
void poly1305_init_vectorized(uint32_t acc[LIMBS_1305], uint32_t r[LIMBS_1305], uint32_t s[4], const unsigned char key[KEY_SIZE_1305]);

typedef void(*poly1305_init_func)(uint32_t *acc, uint32_t* r, uint32_t* s, const unsigned char *key);