#pragma once
#include <stdint.h> 
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>

#define STATE_SIZE_W  16
#define STATE_SIZE_B  64
#define BLOCK_CTR_IDX 12
#define KEY_SIZE_B    32
#define NONCE_SIZE_B  12
#define CONSTANTS_SIZE 4
#define DOUBLE_ROUNDS 10

#define STATE_0 0x61707865
#define STATE_1 0x3320646e
#define STATE_2 0x79622d32
#define STATE_3 0x6b206574

// https://stackoverflow.com/questions/51145636/why-does-shifting-a-variable-by-more-than-its-width-in-bits-zeroes-out
// CAUTION: This rotation would result in undefined behavior if c = 0 or c >= 32. 
// Here, it is only used with c = 16, 12, 8, 7.
#define ROTL32(v, n) \
    ( (v << (n)) | (v >> (32 - (n))) )
    
#define ROTL32_256(x, n) \
    _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n))

#define BYTE_PTR_TO_U32(byte_array)      \
    (                                    \
       (uint32_t)(byte_array)[0]         \
     | ((uint32_t)(byte_array)[1] <<  8) \
     | ((uint32_t)(byte_array)[2] << 16) \
     | ((uint32_t)(byte_array)[3] << 24) \
    )

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

static inline void initialize_chacha_state(uint32_t *state, const uint8_t *key_b, const uint8_t *nonce_b, uint32_t block_ctr){
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++){
        state[4 + i] = BYTE_PTR_TO_U32(key_b + i*4);
    }
    state[12] = block_ctr;
    state[13] = BYTE_PTR_TO_U32(nonce_b);
    state[14] = BYTE_PTR_TO_U32(nonce_b + 4);
    state[15] = BYTE_PTR_TO_U32(nonce_b + 8);
}

typedef void(*chacha_block_func)(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);
typedef int(*chacha20_encrypt_func)(
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len_ptxt,
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds
);

void chacha_block_baseline(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);
void chacha_block_ilp_final_add(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);
void chacha_block_inline(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);
void chacha_block_scalar_replacement(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);

int chacha20_encrypt_baseline(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
int chacha20_encrypt_strength_reduction(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
int chacha20_encrypt_inline(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
int chacha20_encrypt_scalar_replacement(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
int chacha20_encrypt_scalar_replacement2(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
int chacha20_encrypt_unroll_ilp_ctxt(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
int chacha20_encrypt_openssl(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
