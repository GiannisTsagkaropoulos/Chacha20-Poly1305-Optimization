#pragma once
#include <string>
#include <stdint.h>

#define STATE_SIZE_W  16
#define STATE_SIZE_B  64

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

typedef void(*chacha_block_func)(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);

void add_function(chacha_block_func f, std::string name);

void chacha_block_base(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);
void chacha_block_2(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);
void chacha_block_best(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);
void chacha_block_openssl(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);
