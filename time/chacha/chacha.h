#pragma once
#include <string>
#include <stdint.h>
#include <emmintrin.h>
#include <immintrin.h>

#define STATE_SIZE_W  16
#define STATE_SIZE_B  64
#define BLOCK_CTR_IDX 12
#define KEY_SIZE_B    32
#define NONCE_SIZE_B  12
#define CONSTANTS_SIZE 4

// https://stackoverflow.com/questions/51145636/why-does-shifting-a-variable-by-more-than-its-width-in-bits-zeroes-out
// CAUTION: This rotation would result in undefined behavior if c = 0 or c >= 32. 
// Here, it is only used with c = 16, 12, 8, 7.
#define ROTL32(v, n) \
    ( (v << (n)) | (v >> (32 - (n))) )
    
#define BYTE_PTR_TO_U32(byte_array)      \
    (                                    \
       (uint32_t)(byte_array)[0]         \
     | ((uint32_t)(byte_array)[1] <<  8) \
     | ((uint32_t)(byte_array)[2] << 16) \
     | ((uint32_t)(byte_array)[3] << 24) \
    )

#define ROTL32_256(x, n) \
    _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n))

#define QUARTER_ROUND_256(a, b, c, d)                    \
    (                                                     \
        a = _mm256_add_epi32(a, b),                       \
        d = _mm256_xor_si256(d, a),                       \
        d = ROTL32_256(d, 16),                            \
        c = _mm256_add_epi32(c, d),                       \
        b = _mm256_xor_si256(b, c),                       \
        b = ROTL32_256(b, 12),                            \
        a = _mm256_add_epi32(a, b),                       \
        d = _mm256_xor_si256(d, a),                       \
        d = ROTL32_256(d, 8),                             \
        c = _mm256_add_epi32(c, d),                       \
        b = _mm256_xor_si256(b, c),                       \
        b = ROTL32_256(b, 7)                              \
    )

#define QUARTER_ROUND(a, b, c, d)        \
    (                                    \
        a += b,                          \
        d ^= a,                          \
        d = ROTL32(d,16),                \
        c += d,                          \
        b ^= c,                          \
        b = ROTL32(b,12),                \
        a += b,                          \
        d ^= a,                          \
        d = ROTL32(d,8),                 \
        c += d,                          \
        b ^= c,                          \
        b = ROTL32(b,7)                  \
    )


int chacha20_encrypt_base(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
int chacha20_encrypt_3(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
int chacha20_encrypt_best(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);
int chacha20_encrypt_openssl(uint8_t *ct, const uint8_t *pt, uint64_t len, const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds);

