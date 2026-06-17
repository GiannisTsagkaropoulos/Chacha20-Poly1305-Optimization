#pragma once
#include <stdint.h> 
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>
#include "constants.h"

// https://stackoverflow.com/questions/51145636/why-does-shifting-a-variable-by-more-than-its-width-in-bits-zeroes-out
// CAUTION: This rotation would result in undefined behavior if c = 0 or c >= 32. 
// Here, it is only used with c = 16, 12, 8, 7.
#define ROTL32(v, n) \
    ( (v << (n)) | (v >> (32 - (n))) )
    
#define ROTL32_256(x, n) \
    _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n))

#define QUARTER_ROUND_256(a, b, c, d)    \
    (                                    \
        a = _mm256_add_epi32(a, b),      \
        d = _mm256_xor_si256(d, a),      \
        d = ROTL32_256(d, 16),           \
        c = _mm256_add_epi32(c, d),      \
        b = _mm256_xor_si256(b, c),      \
        b = ROTL32_256(b, 12),           \
        a = _mm256_add_epi32(a, b),      \
        d = _mm256_xor_si256(d, a),      \
        d = ROTL32_256(d, 8),            \
        c = _mm256_add_epi32(c, d),      \
        b = _mm256_xor_si256(b, c),      \
        b = ROTL32_256(b, 7)             \
    )

#define ROT16_MASK _mm256_set_epi8(\
    13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2,\
    13,12,15,14, 9,8,11,10, 5,4,7,6, 1,0,3,2)

#define ROT8_MASK _mm256_set_epi8(\
    14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3,\
    14,13,12,15, 10,9,8,11, 6,5,4,7, 2,1,0,3)

#define QUARTER_ROUND_256_2(a, b, c, d)         \
    (                                           \
        a = _mm256_add_epi32(a, b),             \
        d = _mm256_xor_si256(d, a),             \
        d = _mm256_shuffle_epi8(d, ROT16_MASK), \
        c = _mm256_add_epi32(c, d),             \
        b = _mm256_xor_si256(b, c),             \
        b = ROTL32_256(b, 12),                  \
        a = _mm256_add_epi32(a, b),             \
        d = _mm256_xor_si256(d, a),             \
        d = _mm256_shuffle_epi8(d, ROT8_MASK),  \
        c = _mm256_add_epi32(c, d),             \
        b = _mm256_xor_si256(b, c),             \
        b = ROTL32_256(b, 7)                    \
    )


#define QUARTER_ROUND(a, b, c, d)        \
        a += b;                          \
        d ^= a;                          \
        d = ROTL32(d,16);                \
        c += d;                          \
        b ^= c;                          \
        b = ROTL32(b,12);                \
        a += b;                          \
        d ^= a;                          \
        d = ROTL32(d,8);                 \
        c += d;                          \
        b ^= c;                          \
        b = ROTL32(b,7);                                 

static inline void quarter_round(uint32_t *state, int i0, int i1, int i2, int i3){
    uint32_t a, b, c, d;
    a = state[i0];
    b = state[i1];
    c = state[i2];
    d = state[i3];

    a += b; 
    d ^= a; 
    d = ROTL32(d,16);

    c += d; 
    b ^= c; 
    b = ROTL32(b,12);

    a += b; 
    d ^= a; 
    d = ROTL32(d,8);

    c += d; 
    b ^= c; 
    b = ROTL32(b,7);

    state[i0] = a;
    state[i1] = b;
    state[i2] = c;
    state[i3] = d;
};

static inline void double_round(uint32_t *state){
    // Column rounds
    quarter_round(state, 0, 4,  8, 12);
    quarter_round(state, 1, 5,  9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);

    // Diagonal Rounds
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7,  8, 13);
    quarter_round(state, 3, 4,  9, 14);
}    

//only works for little endian
static inline void initialize_chacha_state(uint32_t *state, const uint8_t *key_b, const uint8_t *nonce_b, uint32_t block_ctr){
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    const uint32_t* key_32 = (const uint32_t*)key_b;
    state[4] = key_32[0];
    state[5] = key_32[1];
    state[6] = key_32[2];
    state[7] = key_32[3];
    state[8] = key_32[4];
    state[9] = key_32[5];
    state[10] = key_32[6];
    state[11] = key_32[7];
    state[12] = block_ctr;

    const uint32_t* nonce_32 = (const uint32_t*)nonce_b;
    state[13] = nonce_32[0];
    state[14] = nonce_32[1];
    state[15] = nonce_32[2];
}

static inline void serialize_state(uint8_t *keystream_b, uint32_t* state_w){
    #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        memcpy(keystream_b, state_w, STATE_SIZE_B);
    #else
        size_t i4 = 0;
        for (size_t i = 0; i < STATE_SIZE_W; i++) {
            i4 += 4;
            keystream_b[i4]     = state[i] & 0xff;
            keystream_b[i4 + 1] = (state[i] >>  8) & 0xff;
            keystream_b[i4 + 2] = (state[i] >> 16) & 0xff;
            keystream_b[i4 + 3] = (state[i] >> 24) & 0xff;
        }
    #endif
}


typedef void(*chacha_block_func)(uint8_t *keystream_buffer, const uint32_t *input_state_w);
typedef int(*chacha20_encrypt_func)(
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len_ptxt,
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
);

void chacha_block_baseline(uint8_t *keystream_buffer, const uint32_t *input_state_w);
void chacha_block_ilp_final_add(uint8_t *keystream_buffer, const uint32_t *input_state_w);
void chacha_block_inline(uint8_t *keystream_buffer, const uint32_t *input_state_w);
void chacha_block_scalar_replacement(uint8_t *keystream_buffer, const uint32_t *input_state_w);

int chacha20_encrypt_baseline(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_strength_reduction(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_inline(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_scalar_replacement(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_unroll_ilp_ctxt(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_multiple_pt_blocks_at_once(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_multiple_pt_blocks_at_once2(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_2(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_vectorized2(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_vectorized3(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
int chacha20_encrypt_openssl(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr);
