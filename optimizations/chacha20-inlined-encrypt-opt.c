#include <stdint.h>
#include <string.h>
#include "chacha20.h"


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

void chacha_block(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds){
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

int chacha20_encrypt(
    uint8_t       *ciphertext_buffer,   
    const uint8_t *plaintext_b,
    uint64_t       len_plaintext,       
    const uint8_t *key_b,       
    const uint8_t *nonce_b,        
    uint32_t       block_ctr,      
    int rounds
){
    uint32_t initial_state_w_0[STATE_SIZE_W];
    
    uint8_t  keystream_buffer_0[BLOCK_SIZE_B];
    uint8_t  keystream_buffer_1[BLOCK_SIZE_B];
    uint8_t  keystream_buffer_2[BLOCK_SIZE_B];
    uint8_t  keystream_buffer_3[BLOCK_SIZE_B];

    ///////////////////////////////////////////////////
    // Initialize state, block number and rounds
    ///////////////////////////////////////////////////
    initial_state_w_0[0] = 0x61707865;
    initial_state_w_0[1] = 0x3320646e;
    initial_state_w_0[2] = 0x79622d32;
    initial_state_w_0[3] = 0x6b206574;
    initial_state_w_0[4] = BYTE_PTR_TO_U32(key_b);
    initial_state_w_0[5] = BYTE_PTR_TO_U32(key_b + 4);
    initial_state_w_0[6] = BYTE_PTR_TO_U32(key_b + 8);
    initial_state_w_0[7] = BYTE_PTR_TO_U32(key_b + 12);
    initial_state_w_0[8] = BYTE_PTR_TO_U32(key_b + 16);
    initial_state_w_0[9] = BYTE_PTR_TO_U32(key_b + 20);
    initial_state_w_0[10] = BYTE_PTR_TO_U32(key_b + 24);
    initial_state_w_0[11] = BYTE_PTR_TO_U32(key_b + 28);
    initial_state_w_0[12] = block_ctr;
    initial_state_w_0[13] = BYTE_PTR_TO_U32(nonce_b);
    initial_state_w_0[14] = BYTE_PTR_TO_U32(nonce_b + 4);
    initial_state_w_0[15] = BYTE_PTR_TO_U32(nonce_b + 8);

    // create 3 copies of the initial state with incremented block counters
    uint32_t initial_state_w_1[STATE_SIZE_W];
    uint32_t initial_state_w_2[STATE_SIZE_W];
    uint32_t initial_state_w_3[STATE_SIZE_W];

    memcpy(initial_state_w_1, initial_state_w_0, STATE_SIZE_B);
    memcpy(initial_state_w_2, initial_state_w_0, STATE_SIZE_B);
    memcpy(initial_state_w_3, initial_state_w_0, STATE_SIZE_B);

    initial_state_w_1[BLOCK_CTR_IDX] += 1;
    initial_state_w_2[BLOCK_CTR_IDX] += 2;
    initial_state_w_3[BLOCK_CTR_IDX] += 3;

    uint64_t num_full_blocks = len_plaintext / BLOCK_SIZE_B;
    uint64_t remainder       = len_plaintext % BLOCK_SIZE_B;
    uint64_t num_quad_blocks = num_full_blocks / 4; // number of 4 blocks of plaintext (256 byte each)
    uint64_t leftover_full   = num_full_blocks % 4;
    
    int double_rounds = rounds / 2;
    ///////////////////////////////////////////////////
    
    
    uint32_t working_state_0[STATE_SIZE_W];
    uint32_t working_state_1[STATE_SIZE_W];
    uint32_t working_state_2[STATE_SIZE_W];
    uint32_t working_state_3[STATE_SIZE_W];

    uint64_t idx_start = 0; 
    ///////////////////////////////////////////////////
    // Iterate over blocks of 4 
    ///////////////////////////////////////////////////
    for (uint64_t b = 0; b < num_quad_blocks; b++) {
        memcpy(working_state_0, initial_state_w_0, STATE_SIZE_B);     
        memcpy(working_state_1, initial_state_w_1, STATE_SIZE_B);    
        memcpy(working_state_2, initial_state_w_2, STATE_SIZE_B);    
        memcpy(working_state_3, initial_state_w_3, STATE_SIZE_B);    
        
        ///////////////////////////////////////////////////
        // Call chacha block to produce keystream
        ///////////////////////////////////////////////////
        for (int i = 0; i < double_rounds; i++) {

            // Chacha block for first block of quad
            uint32_t out0_0 = working_state_0[0];
            uint32_t out0_1 = working_state_0[1];
            uint32_t out0_2 = working_state_0[2];
            uint32_t out0_3 = working_state_0[3];
            uint32_t out0_4 = working_state_0[4];
            uint32_t out0_5 = working_state_0[5];
            uint32_t out0_6 = working_state_0[6];
            uint32_t out0_7 = working_state_0[7];
            uint32_t out0_8 = working_state_0[8];
            uint32_t out0_9 = working_state_0[9];
            uint32_t out0_10 = working_state_0[10];
            uint32_t out0_11 = working_state_0[11];
            uint32_t out0_12 = working_state_0[12];
            uint32_t out0_13 = working_state_0[13];
            uint32_t out0_14 = working_state_0[14];
            uint32_t out0_15 = working_state_0[15];

            // Column Rounds
            QUARTER_ROUND(out0_0, out0_4, out0_8, out0_12);
            QUARTER_ROUND(out0_1, out0_5, out0_9, out0_13);
            QUARTER_ROUND(out0_2, out0_6, out0_10, out0_14);
            QUARTER_ROUND(out0_3, out0_7, out0_11, out0_15);

            // Diagonal Rounds
            QUARTER_ROUND(out0_0, out0_5, out0_10, out0_15);
            QUARTER_ROUND(out0_1, out0_6, out0_11, out0_12);
            QUARTER_ROUND(out0_2, out0_7, out0_8, out0_13);
            QUARTER_ROUND(out0_3, out0_4, out0_9, out0_14);

            working_state_0[0] = out0_0;
            working_state_0[1] = out0_1;
            working_state_0[2] = out0_2;
            working_state_0[3] = out0_3;
            working_state_0[4] = out0_4;
            working_state_0[5] = out0_5;
            working_state_0[6] = out0_6;
            working_state_0[7] = out0_7;
            working_state_0[8] = out0_8;
            working_state_0[9] = out0_9;
            working_state_0[10] = out0_10;
            working_state_0[11] = out0_11;
            working_state_0[12] = out0_12;
            working_state_0[13] = out0_13;
            working_state_0[14] = out0_14;
            working_state_0[15] = out0_15;

            // Chacha block for second block of quad

            uint32_t out1_0 = working_state_1[0];
            uint32_t out1_1 = working_state_1[1];
            uint32_t out1_2 = working_state_1[2];
            uint32_t out1_3 = working_state_1[3];
            uint32_t out1_4 = working_state_1[4];
            uint32_t out1_5 = working_state_1[5];
            uint32_t out1_6 = working_state_1[6];
            uint32_t out1_7 = working_state_1[7];
            uint32_t out1_8 = working_state_1[8];
            uint32_t out1_9 = working_state_1[9];
            uint32_t out1_10 = working_state_1[10];
            uint32_t out1_11 = working_state_1[11];
            uint32_t out1_12 = working_state_1[12];
            uint32_t out1_13 = working_state_1[13];
            uint32_t out1_14 = working_state_1[14];
            uint32_t out1_15 = working_state_1[15];

            // Column Rounds
            QUARTER_ROUND(out1_0, out1_4, out1_8, out1_12);
            QUARTER_ROUND(out1_1, out1_5, out1_9, out1_13);
            QUARTER_ROUND(out1_2, out1_6, out1_10, out1_14);
            QUARTER_ROUND(out1_3, out1_7, out1_11, out1_15);

            // Diagonal Rounds
            QUARTER_ROUND(out1_0, out1_5, out1_10, out1_15);
            QUARTER_ROUND(out1_1, out1_6, out1_11, out1_12);
            QUARTER_ROUND(out1_2, out1_7, out1_8, out1_13);
            QUARTER_ROUND(out1_3, out1_4, out1_9, out1_14);

            working_state_1[0] = out1_0;
            working_state_1[1] = out1_1;
            working_state_1[2] = out1_2;
            working_state_1[3] = out1_3;
            working_state_1[4] = out1_4;
            working_state_1[5] = out1_5;
            working_state_1[6] = out1_6;
            working_state_1[7] = out1_7;
            working_state_1[8] = out1_8;
            working_state_1[9] = out1_9;
            working_state_1[10] = out1_10;
            working_state_1[11] = out1_11;
            working_state_1[12] = out1_12;
            working_state_1[13] = out1_13;
            working_state_1[14] = out1_14;
            working_state_1[15] = out1_15;

            // Chacha block for third block of quad

            uint32_t out2_0 = working_state_2[0];
            uint32_t out2_1 = working_state_2[1];
            uint32_t out2_2 = working_state_2[2];
            uint32_t out2_3 = working_state_2[3];
            uint32_t out2_4 = working_state_2[4];
            uint32_t out2_5 = working_state_2[5];
            uint32_t out2_6 = working_state_2[6];
            uint32_t out2_7 = working_state_2[7];
            uint32_t out2_8 = working_state_2[8];
            uint32_t out2_9 = working_state_2[9];
            uint32_t out2_10 = working_state_2[10];
            uint32_t out2_11 = working_state_2[11];
            uint32_t out2_12 = working_state_2[12];
            uint32_t out2_13 = working_state_2[13];
            uint32_t out2_14 = working_state_2[14];
            uint32_t out2_15 = working_state_2[15];

            // Column Rounds
            QUARTER_ROUND(out2_0, out2_4, out2_8, out2_12);
            QUARTER_ROUND(out2_1, out2_5, out2_9, out2_13);
            QUARTER_ROUND(out2_2, out2_6, out2_10, out2_14);
            QUARTER_ROUND(out2_3, out2_7, out2_11, out2_15);

            // Diagonal Rounds
            QUARTER_ROUND(out2_0, out2_5, out2_10, out2_15);
            QUARTER_ROUND(out2_1, out2_6, out2_11, out2_12);
            QUARTER_ROUND(out2_2, out2_7, out2_8, out2_13);
            QUARTER_ROUND(out2_3, out2_4, out2_9, out2_14);

            working_state_2[0] = out2_0;
            working_state_2[1] = out2_1;
            working_state_2[2] = out2_2;
            working_state_2[3] = out2_3;
            working_state_2[4] = out2_4;
            working_state_2[5] = out2_5;
            working_state_2[6] = out2_6;
            working_state_2[7] = out2_7;
            working_state_2[8] = out2_8;
            working_state_2[9] = out2_9;
            working_state_2[10] = out2_10;
            working_state_2[11] = out2_11;
            working_state_2[12] = out2_12;
            working_state_2[13] = out2_13;
            working_state_2[14] = out2_14;
            working_state_2[15] = out2_15;

            // Chacha block for fourth block of quad

            uint32_t out3_0 = working_state_3[0];
            uint32_t out3_1 = working_state_3[1];
            uint32_t out3_2 = working_state_3[2];
            uint32_t out3_3 = working_state_3[3];
            uint32_t out3_4 = working_state_3[4];
            uint32_t out3_5 = working_state_3[5];
            uint32_t out3_6 = working_state_3[6];
            uint32_t out3_7 = working_state_3[7];
            uint32_t out3_8 = working_state_3[8];
            uint32_t out3_9 = working_state_3[9];
            uint32_t out3_10 = working_state_3[10];
            uint32_t out3_11 = working_state_3[11];
            uint32_t out3_12 = working_state_3[12];
            uint32_t out3_13 = working_state_3[13];
            uint32_t out3_14 = working_state_3[14];
            uint32_t out3_15 = working_state_3[15];

            // Column Rounds
            QUARTER_ROUND(out3_0, out3_4, out3_8, out3_12);
            QUARTER_ROUND(out3_1, out3_5, out3_9, out3_13);
            QUARTER_ROUND(out3_2, out3_6, out3_10, out3_14);
            QUARTER_ROUND(out3_3, out3_7, out3_11, out3_15);

            // Diagonal Rounds
            QUARTER_ROUND(out3_0, out3_5, out3_10, out3_15);
            QUARTER_ROUND(out3_1, out3_6, out3_11, out3_12);
            QUARTER_ROUND(out3_2, out3_7, out3_8, out3_13);
            QUARTER_ROUND(out3_3, out3_4, out3_9, out3_14);

            working_state_3[0] = out3_0;
            working_state_3[1] = out3_1;
            working_state_3[2] = out3_2;
            working_state_3[3] = out3_3;
            working_state_3[4] = out3_4;
            working_state_3[5] = out3_5;
            working_state_3[6] = out3_6;
            working_state_3[7] = out3_7;
            working_state_3[8] = out3_8;
            working_state_3[9] = out3_9;
            working_state_3[10] = out3_10;
            working_state_3[11] = out3_11;
            working_state_3[12] = out3_12;
            working_state_3[13] = out3_13;
            working_state_3[14] = out3_14;
            working_state_3[15] = out3_15;
        }
        
        for (int i = 0; i < STATE_SIZE_W; i++) {
            working_state_0[i] += initial_state_w_0[i];
            working_state_1[i] += initial_state_w_1[i];
            working_state_2[i] += initial_state_w_2[i];
            working_state_3[i] += initial_state_w_3[i];
        }

        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer_0, working_state_0, STATE_SIZE_B);
            memcpy(keystream_buffer_1, working_state_1, STATE_SIZE_B);
            memcpy(keystream_buffer_2, working_state_2, STATE_SIZE_B);
            memcpy(keystream_buffer_3, working_state_3, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 = i * 4;
                keystream_buffer_0[i4]     = working_state_0[i] & 0xff;
                keystream_buffer_0[i4 + 1] = (working_state_0[i] >>  8) & 0xff;
                keystream_buffer_0[i4 + 2] = (working_state_0[i] >> 16) & 0xff;
                keystream_buffer_0[i4 + 3] = (working_state_0[i] >> 24) & 0xff;

                keystream_buffer_1[i4]     = working_state_1[i] & 0xff;
                keystream_buffer_1[i4 + 1] = (working_state_1[i] >>  8) & 0xff;
                keystream_buffer_1[i4 + 2] = (working_state_1[i] >> 16) & 0xff;
                keystream_buffer_1[i4 + 3] = (working_state_1[i] >> 24) & 0xff;

                keystream_buffer_2[i4]     = working_state_2[i] & 0xff;
                keystream_buffer_2[i4 + 1] = (working_state_2[i] >>  8) & 0xff;
                keystream_buffer_2[i4 + 2] = (working_state_2[i] >> 16) & 0xff;
                keystream_buffer_2[i4 + 3] = (working_state_2[i] >> 24) & 0xff;

                keystream_buffer_3[i4]     = working_state_3[i] & 0xff;
                keystream_buffer_3[i4 + 1] = (working_state_3[i] >>  8) & 0xff;
                keystream_buffer_3[i4 + 2] = (working_state_3[i] >> 16) & 0xff;
                keystream_buffer_3[i4 + 3] = (working_state_3[i] >> 24) & 0xff;
            }
        #endif
        ///////////////////////////////////////////////////
    
        
        ///////////////////////////////////////////////////
        // Compute cipher text and increment block ctr
        ///////////////////////////////////////////////////
        for (int i = 0; i < BLOCK_SIZE_B; i++){
            ciphertext_buffer[idx_start + i]                  = plaintext_b[idx_start + i]                  ^ keystream_buffer_0[i];
            ciphertext_buffer[idx_start +   BLOCK_SIZE_B + i] = plaintext_b[idx_start +   BLOCK_SIZE_B + i] ^ keystream_buffer_1[i];
            ciphertext_buffer[idx_start + 2*BLOCK_SIZE_B + i] = plaintext_b[idx_start + 2*BLOCK_SIZE_B + i] ^ keystream_buffer_2[i];
            ciphertext_buffer[idx_start + 3*BLOCK_SIZE_B + i] = plaintext_b[idx_start + 3*BLOCK_SIZE_B + i] ^ keystream_buffer_3[i];
        }
        
        initial_state_w_0[BLOCK_CTR_IDX] += 4;
        initial_state_w_1[BLOCK_CTR_IDX] += 4;
        initial_state_w_2[BLOCK_CTR_IDX] += 4;
        initial_state_w_3[BLOCK_CTR_IDX] += 4;

        idx_start += 4 * BLOCK_SIZE_B;
        ///////////////////////////////////////////////////
    }

    ///////////////////////////////////////////////////
    // Cleanup of remaining blocks (num_full_blocks % 4)
    ///////////////////////////////////////////////////

    for (uint64_t b = 0; b < leftover_full; b++) {
        memcpy(working_state_0, initial_state_w_0, STATE_SIZE_B);     
        
        ///////////////////////////////////////////////////
        // Call chacha block to produce keystream
        ///////////////////////////////////////////////////
        for (int i = 0; i < double_rounds; i++) {
            uint32_t out0 = working_state_0[0];
            uint32_t out1 = working_state_0[1];
            uint32_t out2 = working_state_0[2];
            uint32_t out3 = working_state_0[3];
            uint32_t out4 = working_state_0[4];
            uint32_t out5 = working_state_0[5];
            uint32_t out6 = working_state_0[6];
            uint32_t out7 = working_state_0[7];
            uint32_t out8 = working_state_0[8];
            uint32_t out9 = working_state_0[9];
            uint32_t out10 = working_state_0[10];
            uint32_t out11 = working_state_0[11];
            uint32_t out12 = working_state_0[12];
            uint32_t out13 = working_state_0[13];
            uint32_t out14 = working_state_0[14];
            uint32_t out15 = working_state_0[15];

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

            working_state_0[0] = out0;
            working_state_0[1] = out1;
            working_state_0[2] = out2;
            working_state_0[3] = out3;
            working_state_0[4] = out4;
            working_state_0[5] = out5;
            working_state_0[6] = out6;
            working_state_0[7] = out7;
            working_state_0[8] = out8;
            working_state_0[9] = out9;
            working_state_0[10] = out10;
            working_state_0[11] = out11;
            working_state_0[12] = out12;
            working_state_0[13] = out13;
            working_state_0[14] = out14;
            working_state_0[15] = out15;
        }
        
        for (int i = 0; i < STATE_SIZE_W; i++) {
            working_state_0[i] += initial_state_w_0[i];
        }

        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer_0, working_state_0, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 += 4;
                keystream_buffer_0[i4]     = working_state_0[i] & 0xff;
                keystream_buffer_0[i4 + 1] = (working_state_0[i] >>  8) & 0xff;
                keystream_buffer_0[i4 + 2] = (working_state_0[i] >> 16) & 0xff;
                keystream_buffer_0[i4 + 3] = (working_state_0[i] >> 24) & 0xff;
            }
        #endif
        ///////////////////////////////////////////////////
    
        
        ///////////////////////////////////////////////////
        // Compute cipher text and increment block ctr
        ///////////////////////////////////////////////////
        for (int i = 0; i < BLOCK_SIZE_B; i++){
            ciphertext_buffer[idx_start + i] = plaintext_b[idx_start + i] ^ keystream_buffer_0[i];
        }
        
        initial_state_w_0[BLOCK_CTR_IDX]++;
        idx_start += BLOCK_SIZE_B;
        ///////////////////////////////////////////////////
    }

    ///////////////////////////////////////////////////
    // Cleanup of partial block (<64 bytes)
    ///////////////////////////////////////////////////
        
    if (remainder != 0) {
        memcpy(working_state_0, initial_state_w_0, STATE_SIZE_B);     
        for (int i = 0; i < double_rounds; i++) {
            uint32_t out0 = working_state_0[0];
            uint32_t out1 = working_state_0[1];
            uint32_t out2 = working_state_0[2];
            uint32_t out3 = working_state_0[3];
            uint32_t out4 = working_state_0[4];
            uint32_t out5 = working_state_0[5];
            uint32_t out6 = working_state_0[6];
            uint32_t out7 = working_state_0[7];
            uint32_t out8 = working_state_0[8];
            uint32_t out9 = working_state_0[9];
            uint32_t out10 = working_state_0[10];
            uint32_t out11 = working_state_0[11];
            uint32_t out12 = working_state_0[12];
            uint32_t out13 = working_state_0[13];
            uint32_t out14 = working_state_0[14];
            uint32_t out15 = working_state_0[15];

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

            working_state_0[0] = out0;
            working_state_0[1] = out1;
            working_state_0[2] = out2;
            working_state_0[3] = out3;
            working_state_0[4] = out4;
            working_state_0[5] = out5;
            working_state_0[6] = out6;
            working_state_0[7] = out7;
            working_state_0[8] = out8;
            working_state_0[9] = out9;
            working_state_0[10] = out10;
            working_state_0[11] = out11;
            working_state_0[12] = out12;
            working_state_0[13] = out13;
            working_state_0[14] = out14;
            working_state_0[15] = out15;
        }
        
        for (int i = 0; i < STATE_SIZE_W; i++) {
            working_state_0[i] += initial_state_w_0[i];
        }

        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer_0, working_state_0, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 += 4;
                keystream_buffer_0[i4]     = state[i] & 0xff;
                keystream_buffer_0[i4 + 1] = (state[i] >>  8) & 0xff;
                keystream_buffer_0[i4 + 2] = (state[i] >> 16) & 0xff;
                keystream_buffer_0[i4 + 3] = (state[i] >> 24) & 0xff;
            }
        #endif

        for (uint64_t i = 0; i < remainder; i++)
            ciphertext_buffer[idx_start + i] = plaintext_b[idx_start + i] ^ keystream_buffer_0[i];
    }

    return 0;
}