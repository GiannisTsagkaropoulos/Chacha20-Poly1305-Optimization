#include <stdint.h>
#include <cstring>
#include "chacha.h"

static void quarter_round(uint32_t *state, int i0, int i1, int i2, int i3){
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

static void double_round(uint32_t *state){
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

void chacha_block_base(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds){
    uint32_t working_state[STATE_SIZE_W];
    memcpy(working_state, input_state_w, STATE_SIZE_B);

    int double_rounds = rounds / 2;
    for (int i = 0; i < double_rounds; i++) {
        double_round(working_state);
    }

    for (int i = 0; i < STATE_SIZE_W; i++) {
        working_state[i] += input_state_w[i];
    }

    #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        memcpy(keystream_buffer, working_state, STATE_SIZE_B);
    #else
        for (size_t i = 0; i < STATE_SIZE_W; i++) {
            size_t i4 = i * 4;
            keystream_buffer[i4]     = (uint8_t)(working_state[i] & 0xff);
            keystream_buffer[i4 + 1] = (uint8_t)((working_state[i] >> 8) & 0xff);
            keystream_buffer[i4 + 2] = (uint8_t)((working_state[i] >> 16) & 0xff);
            keystream_buffer[i4 + 3] = (uint8_t)((working_state[i] >> 24) & 0xff);
        }
    #endif
}

void chacha_block_best(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds) {
    chacha_block_base(keystream_buffer, input_state_w, rounds);
}

//TODO: replace with actual implementation of OpenSSL
void chacha_block_openssl(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds) {
    chacha_block_base(keystream_buffer, input_state_w, rounds);
}