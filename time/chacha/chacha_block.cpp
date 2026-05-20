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

/*
* Optimizations: 
* 1. Scalar replacement for chacha state 
* 2. Use macro for quarter_round so ILP is exploited since families of 4 quarter rounds 
* are independent from each other
*/
void chacha_block_2(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds){
    uint32_t working_state[STATE_SIZE_W];
    memcpy(working_state, input_state_w, STATE_SIZE_B);

    int double_rounds = rounds / 2;
    for (int i = 0; i < double_rounds; i++) {
        uint32_t out0 = working_state[0];
        uint32_t out1 = working_state[1];
        uint32_t out2 = working_state[2];
        uint32_t out3 = working_state[3];
        uint32_t out4 = working_state[4];
        uint32_t out5 = working_state[5];
        uint32_t out6 = working_state[6];
        uint32_t out7 = working_state[7];
        uint32_t out8 = working_state[8];
        uint32_t out9 = working_state[9];
        uint32_t out10 = working_state[10];
        uint32_t out11 = working_state[11];
        uint32_t out12 = working_state[12];
        uint32_t out13 = working_state[13];
        uint32_t out14 = working_state[14];
        uint32_t out15 = working_state[15];

        // Column Rounds
        QUARTER_ROUND(out0, out4, out8, out12);
        QUARTER_ROUND(out1, out5, out9, out13);
        QUARTER_ROUND(out2, out6, out10, out14);
        QUARTER_ROUND(out3, out7, out11, out15);

        // Diagonal Rounds
        QUARTER_ROUND(out0, out5, out10, out15);
        QUARTER_ROUND(out1, out6, out11, out12);
        QUARTER_ROUND(out2, out7, out8, out13);
        QUARTER_ROUND(out3, out4, out9, out14);

        working_state[0] = out0;
        working_state[1] = out1;
        working_state[2] = out2;
        working_state[3] = out3;
        working_state[4] = out4;
        working_state[5] = out5;
        working_state[6] = out6;
        working_state[7] = out7;
        working_state[8] = out8;
        working_state[9] = out9;
        working_state[10] = out10;
        working_state[11] = out11;
        working_state[12] = out12;
        working_state[13] = out13;
        working_state[14] = out14;
        working_state[15] = out15;
    }

    working_state[0] += input_state_w[0];
    working_state[1] += input_state_w[1];
    working_state[2] += input_state_w[2];
    working_state[3] += input_state_w[3];
    working_state[4] += input_state_w[4];
    working_state[5] += input_state_w[5];
    working_state[6] += input_state_w[6];
    working_state[7] += input_state_w[7];
    working_state[8] += input_state_w[8];
    working_state[9] += input_state_w[9];
    working_state[10] += input_state_w[10];
    working_state[11] += input_state_w[11];
    working_state[12] += input_state_w[12];
    working_state[13] += input_state_w[13];
    working_state[14] += input_state_w[14];
    working_state[15] += input_state_w[15];

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