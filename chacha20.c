#include <stdint.h>
#include <string.h>
#include "chacha20.h"

static const uint32_t CONSTANTS[CONSTANTS_SIZE] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

// static_if_no_test idea from: https://stackoverflow.com/questions/593414/how-to-test-a-static-function
#if UNIT_TEST
#define static_if_no_test
#define static_inline_if_no_test static inline 
#else
#define static_if_no_test        static
#define static_inline_if_no_test static inline
#endif

// https://stackoverflow.com/questions/51145636/why-does-shifting-a-variable-by-more-than-its-width-in-bits-zeroes-out
// CAUTION: This rotation would result in undefined behavior if c = 0 or c >= 32. 
// Here, it is only used with c = 16, 12, 8, 7.
#define ROTL32(v, n) \
    ( (v << (n)) | (v >> (32 - (n))) )

static_inline_if_no_test uint32_t byte_ptr_to_word(const uint8_t *byte_array);
static_if_no_test void initialize_chacha_state(uint32_t *state, const uint8_t *key_b, const uint8_t *nonce_b, uint32_t block_ctr);
static_if_no_test void quarter_round(uint32_t *x, int i0, int i1, int i2, int i3);
static_if_no_test void double_round(uint32_t *x);
static_if_no_test void chacha_block(const uint32_t *input_state_w, int rounds, uint32_t *out_state_w);
static_if_no_test void serialize_state(uint8_t *keystream_b, uint32_t* state_w);

                
static_inline_if_no_test uint32_t byte_ptr_to_word(const uint8_t *byte_array){
    return (uint32_t)byte_array[0]
        | ((uint32_t)byte_array[1] <<  8)
        | ((uint32_t)byte_array[2] << 16)
        | ((uint32_t)byte_array[3] << 24);
}
 

static_if_no_test void initialize_chacha_state(uint32_t *state, const uint8_t *key_b, const uint8_t *nonce_b, uint32_t block_ctr){
    state[0] = CONSTANTS[0];
    state[1] = CONSTANTS[1];
    state[2] = CONSTANTS[2];
    state[3] = CONSTANTS[3];
    for (int i = 0; i < 8; i++){
        state[4 + i] = byte_ptr_to_word(key_b + i*4);
    }
    state[12] = block_ctr;
    state[13] = byte_ptr_to_word(nonce_b);
    state[14] = byte_ptr_to_word(nonce_b + 4);
    state[15] = byte_ptr_to_word(nonce_b + 8);
}

static_if_no_test void quarter_round(uint32_t *state, int i0, int i1, int i2, int i3){
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

static_if_no_test void double_round(uint32_t *state){
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

static_if_no_test void chacha_block(const uint32_t *input_state_w, int rounds, uint32_t *out_state_w){
    int double_rounds = rounds / 2;
    for (int i = 0; i < double_rounds; i++) {
        double_round(out_state_w);
    }

    for (int i = 0; i < STATE_SIZE_W; i++) {
        out_state_w[i] += input_state_w[i] ;
    }
}

static_if_no_test void serialize_state(uint8_t *keystream_b, uint32_t* state_w){
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

int chacha20_encrypt(
    const uint8_t *key_b,       
    const uint8_t *nonce_b,      
    uint32_t       block_ctr,    
    const uint8_t *plaintext_b,
    uint64_t       p_length,    
    int            rounds, 
    uint8_t       *ciphertext_b     
){
    uint32_t initial_state_w[STATE_SIZE_W];
    uint32_t output_state_w[STATE_SIZE_W];
    uint8_t  keystream_b[BLOCK_SIZE_B];

    initialize_chacha_state(initial_state_w, key_b, nonce_b, block_ctr);

    uint64_t num_full_blocks = p_length / BLOCK_SIZE_B;
    uint64_t remainder       = p_length % BLOCK_SIZE_B;

    uint64_t idx_start = 0; 
    for (uint64_t b = 0; b < num_full_blocks; b++) {
        memcpy(output_state_w, initial_state_w, STATE_SIZE_B);
        chacha_block(initial_state_w, rounds, output_state_w);
        serialize_state(keystream_b, output_state_w);

        for (int i = 0; i < BLOCK_SIZE_B; i++)
            ciphertext_b[idx_start + i] = plaintext_b[idx_start + i] ^ keystream_b[i];

        initial_state_w[BLOCK_CTR_IDX]++;
        idx_start += BLOCK_SIZE_B;
    }

    if (remainder != 0) {
        memcpy(output_state_w, initial_state_w, STATE_SIZE_B);
        chacha_block(initial_state_w, rounds, output_state_w);
        serialize_state(keystream_b, output_state_w);

        for (uint64_t i = 0; i < remainder; i++)
            ciphertext_b[idx_start + i] = plaintext_b[idx_start + i] ^ keystream_b[i];
    }

    return 0;
}