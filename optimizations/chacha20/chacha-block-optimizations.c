#include "chacha_opts.h"

void chacha_block_baseline(uint8_t *keystream_buffer, const uint32_t *input_state_w){
    uint32_t working_state[STATE_SIZE_W];
    memcpy(working_state, input_state_w, STATE_SIZE_B);

    for (int i = 0; i < DOUBLE_ROUNDS; i++) {
        double_round(working_state);
    }

    for (int i = 0; i < STATE_SIZE_W; i++) {
        working_state[i] += input_state_w[i];
    }

    memcpy(keystream_buffer, working_state, STATE_SIZE_B);
}


/*
* Optimizations: 
* 1. Unroll final state addition loop and use ILP since all additions are independent
*/
void chacha_block_ilp_final_add(uint8_t *keystream_buffer, const uint32_t *input_state_w){
    uint32_t working_state[STATE_SIZE_W];
    memcpy(working_state, input_state_w, STATE_SIZE_B);

    for (int i = 0; i < DOUBLE_ROUNDS; i++) {
        double_round(working_state);
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

    memcpy(keystream_buffer, working_state, STATE_SIZE_B);
}


/*
* Optimizations: 
* 1. Scalar replacement for chacha state 
* 2. Use macro for quarter_round so ILP is exploited since families of 4 quarter rounds 
* are independent from each other
*/
void chacha_block_inline(uint8_t *keystream_buffer, const uint32_t *input_state_w){
    uint32_t working_state[STATE_SIZE_W];
    memcpy(working_state, input_state_w, STATE_SIZE_B);

    for (int i = 0; i < DOUBLE_ROUNDS; i++) {
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

    memcpy(keystream_buffer, working_state, STATE_SIZE_B);
}

/*
* Optimizations: 
* 1. Scalar replacement now put to actual use, no reads and writes to working state on every double round we process
*/
void chacha_block_scalar_replacement(uint8_t *keystream_buffer, const uint32_t *input_state_w){
    uint32_t out0 = input_state_w[0];
    uint32_t out1 = input_state_w[1];
    uint32_t out2 = input_state_w[2];
    uint32_t out3 = input_state_w[3];
    uint32_t out4 = input_state_w[4];
    uint32_t out5 = input_state_w[5];
    uint32_t out6 = input_state_w[6];
    uint32_t out7 = input_state_w[7];
    uint32_t out8 = input_state_w[8];
    uint32_t out9 = input_state_w[9];
    uint32_t out10 = input_state_w[10];
    uint32_t out11 = input_state_w[11];
    uint32_t out12 = input_state_w[12];
    uint32_t out13 = input_state_w[13];
    uint32_t out14 = input_state_w[14];
    uint32_t out15 = input_state_w[15];
    for (int i = 0; i < DOUBLE_ROUNDS; i++) {
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
    }

    uint32_t working_state[STATE_SIZE_W];
    memcpy(working_state, input_state_w, STATE_SIZE_B);

    working_state[0] += out0;
    working_state[1] += out1;
    working_state[2] += out2;
    working_state[3] += out3;
    working_state[4] += out4;
    working_state[5] += out5;
    working_state[6] += out6;
    working_state[7] += out7;
    working_state[8] += out8;
    working_state[9] += out9;
    working_state[10] += out10;
    working_state[11] += out11;
    working_state[12] += out12;
    working_state[13] += out13;
    working_state[14] += out14;
    working_state[15] += out15;

    memcpy(keystream_buffer, working_state, STATE_SIZE_B);
}
