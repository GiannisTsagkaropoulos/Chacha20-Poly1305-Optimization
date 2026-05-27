#include <stdint.h>
#include "chacha_opts.h"


int chacha20_encrypt_baseline( 
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds
){
    uint32_t initial_state_w[STATE_SIZE_W];
    uint8_t  keystream_buffer[STATE_SIZE_B];

    initialize_chacha_state(initial_state_w, key, nonce, ctr);

    uint64_t num_full_blocks = len / STATE_SIZE_B;
    uint64_t remainder       = len % STATE_SIZE_B;

    uint64_t idx_start = 0; 
    for (uint64_t b = 0; b < num_full_blocks; b++) {
        chacha_block_baseline(keystream_buffer, initial_state_w, rounds);

        for (int i = 0; i < STATE_SIZE_B; i++)
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];

        initial_state_w[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
    }

    if (remainder != 0) {
        chacha_block_baseline(keystream_buffer, initial_state_w, rounds);

        for (uint64_t i = 0; i < remainder; i++)
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];
    }
    return 0;
}


int chacha20_encrypt_1(
   uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds
){
    uint32_t initial_state_w[STATE_SIZE_W];
    uint8_t  keystream_buffer[STATE_SIZE_B];
    
    ///////////////////////////////////////////////////
    // Initialize state, block number and rounds
    ///////////////////////////////////////////////////
    initial_state_w[0] = 0x61707865;
    initial_state_w[1] = 0x3320646e;
    initial_state_w[2] = 0x79622d32;
    initial_state_w[3] = 0x6b206574;
    initial_state_w[4] = BYTE_PTR_TO_U32(key);
    initial_state_w[5] = BYTE_PTR_TO_U32(key + 4);
    initial_state_w[6] = BYTE_PTR_TO_U32(key + 8);
    initial_state_w[7] = BYTE_PTR_TO_U32(key + 12);
    initial_state_w[8] = BYTE_PTR_TO_U32(key + 16);
    initial_state_w[9] = BYTE_PTR_TO_U32(key + 20);
    initial_state_w[10] = BYTE_PTR_TO_U32(key + 24);
    initial_state_w[11] = BYTE_PTR_TO_U32(key + 28);
    initial_state_w[12] = ctr;
    initial_state_w[13] = BYTE_PTR_TO_U32(nonce);
    initial_state_w[14] = BYTE_PTR_TO_U32(nonce + 4);
    initial_state_w[15] = BYTE_PTR_TO_U32(nonce + 8);
    
    uint64_t num_full_blocks = len / STATE_SIZE_B;
    uint64_t remainder       = len % STATE_SIZE_B;
    
    int double_rounds = rounds / 2;
    ///////////////////////////////////////////////////
    
    
    uint32_t working_state[STATE_SIZE_W];
    uint64_t idx_start = 0; 
    for (uint64_t b = 0; b < num_full_blocks; b++) {
        memcpy(working_state, initial_state_w, STATE_SIZE_B);     
        
        ///////////////////////////////////////////////////
        // Call chacha block to produce keystream
        ///////////////////////////////////////////////////
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
        
        working_state[0] += initial_state_w[0];
        working_state[1] += initial_state_w[1];
        working_state[2] += initial_state_w[2];
        working_state[3] += initial_state_w[3];
        working_state[4] += initial_state_w[4];
        working_state[5] += initial_state_w[5];
        working_state[6] += initial_state_w[6];
        working_state[7] += initial_state_w[7];
        working_state[8] += initial_state_w[8];
        working_state[9] += initial_state_w[9];
        working_state[10] += initial_state_w[10];
        working_state[11] += initial_state_w[11];
        working_state[12] += initial_state_w[12];
        working_state[13] += initial_state_w[13];
        working_state[14] += initial_state_w[14];
        working_state[15] += initial_state_w[15];

        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer, working_state, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 += 4;
                keystream_buffer[i4]     = working_state[i] & 0xff;
                keystream_buffer[i4 + 1] = (working_state[i] >>  8) & 0xff;
                keystream_buffer[i4 + 2] = (working_state[i] >> 16) & 0xff;
                keystream_buffer[i4 + 3] = (working_state[i] >> 24) & 0xff;
            }
        #endif
        ///////////////////////////////////////////////////
    
        
        ///////////////////////////////////////////////////
        // Compute cipher text and increment block ctr
        ///////////////////////////////////////////////////
        for (int i = 0; i < STATE_SIZE_B; i++){
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];
        }
        
        initial_state_w[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
        ///////////////////////////////////////////////////
    }
        
    if (remainder != 0) {
        memcpy(working_state, initial_state_w, STATE_SIZE_B);     
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
        
        working_state[0] += initial_state_w[0];
        working_state[1] += initial_state_w[1];
        working_state[2] += initial_state_w[2];
        working_state[3] += initial_state_w[3];
        working_state[4] += initial_state_w[4];
        working_state[5] += initial_state_w[5];
        working_state[6] += initial_state_w[6];
        working_state[7] += initial_state_w[7];
        working_state[8] += initial_state_w[8];
        working_state[9] += initial_state_w[9];
        working_state[10] += initial_state_w[10];
        working_state[11] += initial_state_w[11];
        working_state[12] += initial_state_w[12];
        working_state[13] += initial_state_w[13];
        working_state[14] += initial_state_w[14];
        working_state[15] += initial_state_w[15];

        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer, working_state, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 += 4;
                keystream_buffer[i4]     = working_state[i] & 0xff;
                keystream_buffer[i4 + 1] = (working_state[i] >>  8) & 0xff;
                keystream_buffer[i4 + 2] = (working_state[i] >> 16) & 0xff;
                keystream_buffer[i4 + 3] = (working_state[i] >> 24) & 0xff;
            }
        #endif

        for (uint64_t i = 0; i < remainder; i++)
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];
    }

    return 0;
}

// Computes 8 blocks at once to fill 256 bit vectors
int chacha20_encrypt_2(
    uint8_t       *ciphertext_buffer,   
    const uint8_t *plaintext_b,
    uint64_t       len_plaintext,       
    const uint8_t *key_b,       
    const uint8_t *nonce_b,        
    uint32_t       block_ctr,      
    int rounds
){
    uint32_t initial_state_w_0[STATE_SIZE_W];
    
    uint8_t  keystream_buffer_0[STATE_SIZE_B];
    uint8_t  keystream_buffer_1[STATE_SIZE_B];
    uint8_t  keystream_buffer_2[STATE_SIZE_B];
    uint8_t  keystream_buffer_3[STATE_SIZE_B];
    uint8_t  keystream_buffer_4[STATE_SIZE_B];
    uint8_t  keystream_buffer_5[STATE_SIZE_B];
    uint8_t  keystream_buffer_6[STATE_SIZE_B];
    uint8_t  keystream_buffer_7[STATE_SIZE_B];

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

    // create 7 copies of the initial state with incremented block counters
    uint32_t initial_state_w_1[STATE_SIZE_W];
    uint32_t initial_state_w_2[STATE_SIZE_W];
    uint32_t initial_state_w_3[STATE_SIZE_W];
    uint32_t initial_state_w_4[STATE_SIZE_W];
    uint32_t initial_state_w_5[STATE_SIZE_W];
    uint32_t initial_state_w_6[STATE_SIZE_W];
    uint32_t initial_state_w_7[STATE_SIZE_W];

    memcpy(initial_state_w_1, initial_state_w_0, STATE_SIZE_B);
    memcpy(initial_state_w_2, initial_state_w_0, STATE_SIZE_B);
    memcpy(initial_state_w_3, initial_state_w_0, STATE_SIZE_B);
    memcpy(initial_state_w_4, initial_state_w_0, STATE_SIZE_B);
    memcpy(initial_state_w_5, initial_state_w_0, STATE_SIZE_B);
    memcpy(initial_state_w_6, initial_state_w_0, STATE_SIZE_B);
    memcpy(initial_state_w_7, initial_state_w_0, STATE_SIZE_B);

    initial_state_w_1[BLOCK_CTR_IDX] += 1;
    initial_state_w_2[BLOCK_CTR_IDX] += 2;
    initial_state_w_3[BLOCK_CTR_IDX] += 3;
    initial_state_w_4[BLOCK_CTR_IDX] += 4;
    initial_state_w_5[BLOCK_CTR_IDX] += 5;
    initial_state_w_6[BLOCK_CTR_IDX] += 6;
    initial_state_w_7[BLOCK_CTR_IDX] += 7;

    uint64_t num_full_blocks = len_plaintext / STATE_SIZE_B;
    uint64_t remainder       = len_plaintext % STATE_SIZE_B;
    uint64_t num_octa_blocks = num_full_blocks / 8; // number of 8 blocks of plaintext (512 byte each)
    uint64_t leftover_full   = num_full_blocks % 8;
    
    int double_rounds = rounds / 2;
    ///////////////////////////////////////////////////
    
    
    uint32_t working_state_0[STATE_SIZE_W];
    uint32_t working_state_1[STATE_SIZE_W];
    uint32_t working_state_2[STATE_SIZE_W];
    uint32_t working_state_3[STATE_SIZE_W];
    uint32_t working_state_4[STATE_SIZE_W];
    uint32_t working_state_5[STATE_SIZE_W];
    uint32_t working_state_6[STATE_SIZE_W];
    uint32_t working_state_7[STATE_SIZE_W];

    uint64_t idx_start = 0; 
    ///////////////////////////////////////////////////
    // Iterate over blocks of 8 
    ///////////////////////////////////////////////////
    for (uint64_t b = 0; b < num_octa_blocks; b++) {
        memcpy(working_state_0, initial_state_w_0, STATE_SIZE_B);     
        memcpy(working_state_1, initial_state_w_1, STATE_SIZE_B);    
        memcpy(working_state_2, initial_state_w_2, STATE_SIZE_B);    
        memcpy(working_state_3, initial_state_w_3, STATE_SIZE_B);    
        memcpy(working_state_4, initial_state_w_4, STATE_SIZE_B);    
        memcpy(working_state_5, initial_state_w_5, STATE_SIZE_B);    
        memcpy(working_state_6, initial_state_w_6, STATE_SIZE_B);    
        memcpy(working_state_7, initial_state_w_7, STATE_SIZE_B);    
        
        ///////////////////////////////////////////////////
        // Call chacha block to produce keystream
        ///////////////////////////////////////////////////

        // Load all 8 states into AVX2 registers
        // _mm256_set_epi32 takes lanes from high (7) to low (0)
        __m256i v0  = _mm256_set_epi32(working_state_7[0],  working_state_6[0],  working_state_5[0],  working_state_4[0],
                                       working_state_3[0],  working_state_2[0],  working_state_1[0],  working_state_0[0]);
        __m256i v1  = _mm256_set_epi32(working_state_7[1],  working_state_6[1],  working_state_5[1],  working_state_4[1],
                                       working_state_3[1],  working_state_2[1],  working_state_1[1],  working_state_0[1]);
        __m256i v2  = _mm256_set_epi32(working_state_7[2],  working_state_6[2],  working_state_5[2],  working_state_4[2],
                                       working_state_3[2],  working_state_2[2],  working_state_1[2],  working_state_0[2]);
        __m256i v3  = _mm256_set_epi32(working_state_7[3],  working_state_6[3],  working_state_5[3],  working_state_4[3],
                                       working_state_3[3],  working_state_2[3],  working_state_1[3],  working_state_0[3]);
        __m256i v4  = _mm256_set_epi32(working_state_7[4],  working_state_6[4],  working_state_5[4],  working_state_4[4],
                                       working_state_3[4],  working_state_2[4],  working_state_1[4],  working_state_0[4]);
        __m256i v5  = _mm256_set_epi32(working_state_7[5],  working_state_6[5],  working_state_5[5],  working_state_4[5],
                                       working_state_3[5],  working_state_2[5],  working_state_1[5],  working_state_0[5]);
        __m256i v6  = _mm256_set_epi32(working_state_7[6],  working_state_6[6],  working_state_5[6],  working_state_4[6],
                                       working_state_3[6],  working_state_2[6],  working_state_1[6],  working_state_0[6]);
        __m256i v7  = _mm256_set_epi32(working_state_7[7],  working_state_6[7],  working_state_5[7],  working_state_4[7],
                                       working_state_3[7],  working_state_2[7],  working_state_1[7],  working_state_0[7]);
        __m256i v8  = _mm256_set_epi32(working_state_7[8],  working_state_6[8],  working_state_5[8],  working_state_4[8],
                                       working_state_3[8],  working_state_2[8],  working_state_1[8],  working_state_0[8]);
        __m256i v9  = _mm256_set_epi32(working_state_7[9],  working_state_6[9],  working_state_5[9],  working_state_4[9],
                                       working_state_3[9],  working_state_2[9],  working_state_1[9],  working_state_0[9]);
        __m256i v10 = _mm256_set_epi32(working_state_7[10], working_state_6[10], working_state_5[10], working_state_4[10],
                                       working_state_3[10], working_state_2[10], working_state_1[10], working_state_0[10]);
        __m256i v11 = _mm256_set_epi32(working_state_7[11], working_state_6[11], working_state_5[11], working_state_4[11],
                                       working_state_3[11], working_state_2[11], working_state_1[11], working_state_0[11]);
        __m256i v12 = _mm256_set_epi32(working_state_7[12], working_state_6[12], working_state_5[12], working_state_4[12],
                                       working_state_3[12], working_state_2[12], working_state_1[12], working_state_0[12]);
        __m256i v13 = _mm256_set_epi32(working_state_7[13], working_state_6[13], working_state_5[13], working_state_4[13],
                                       working_state_3[13], working_state_2[13], working_state_1[13], working_state_0[13]);
        __m256i v14 = _mm256_set_epi32(working_state_7[14], working_state_6[14], working_state_5[14], working_state_4[14],
                                       working_state_3[14], working_state_2[14], working_state_1[14], working_state_0[14]);
        __m256i v15 = _mm256_set_epi32(working_state_7[15], working_state_6[15], working_state_5[15], working_state_4[15],
                                       working_state_3[15], working_state_2[15], working_state_1[15], working_state_0[15]);
        
        for (int i = 0; i < double_rounds; i++) {
            // Column Rounds
            QUARTER_ROUND_256(v0, v4, v8,  v12);
            QUARTER_ROUND_256(v1, v5, v9,  v13);
            QUARTER_ROUND_256(v2, v6, v10, v14);
            QUARTER_ROUND_256(v3, v7, v11, v15);

            // Diagonal Rounds
            QUARTER_ROUND_256(v0, v5, v10, v15);
            QUARTER_ROUND_256(v1, v6, v11, v12);
            QUARTER_ROUND_256(v2, v7, v8,  v13);
            QUARTER_ROUND_256(v3, v4, v9,  v14);
        }
        // Extract results back — lane j = state j
        #define EXTRACT(v, i) ((uint32_t)_mm256_extract_epi32(v, i))

        working_state_0[0]  = EXTRACT(v0,  0); working_state_1[0]  = EXTRACT(v0,  1);
        working_state_2[0]  = EXTRACT(v0,  2); working_state_3[0]  = EXTRACT(v0,  3);
        working_state_4[0]  = EXTRACT(v0,  4); working_state_5[0]  = EXTRACT(v0,  5);
        working_state_6[0]  = EXTRACT(v0,  6); working_state_7[0]  = EXTRACT(v0,  7);
        working_state_0[1]  = EXTRACT(v1,  0); working_state_1[1]  = EXTRACT(v1,  1);
        working_state_2[1]  = EXTRACT(v1,  2); working_state_3[1]  = EXTRACT(v1,  3);
        working_state_4[1]  = EXTRACT(v1,  4); working_state_5[1]  = EXTRACT(v1,  5);
        working_state_6[1]  = EXTRACT(v1,  6); working_state_7[1]  = EXTRACT(v1,  7);
        working_state_0[2]  = EXTRACT(v2,  0); working_state_1[2]  = EXTRACT(v2,  1);
        working_state_2[2]  = EXTRACT(v2,  2); working_state_3[2]  = EXTRACT(v2,  3);
        working_state_4[2]  = EXTRACT(v2,  4); working_state_5[2]  = EXTRACT(v2,  5);
        working_state_6[2]  = EXTRACT(v2,  6); working_state_7[2]  = EXTRACT(v2,  7);
        working_state_0[3]  = EXTRACT(v3,  0); working_state_1[3]  = EXTRACT(v3,  1);
        working_state_2[3]  = EXTRACT(v3,  2); working_state_3[3]  = EXTRACT(v3,  3);
        working_state_4[3]  = EXTRACT(v3,  4); working_state_5[3]  = EXTRACT(v3,  5);
        working_state_6[3]  = EXTRACT(v3,  6); working_state_7[3]  = EXTRACT(v3,  7);
        working_state_0[4]  = EXTRACT(v4,  0); working_state_1[4]  = EXTRACT(v4,  1);
        working_state_2[4]  = EXTRACT(v4,  2); working_state_3[4]  = EXTRACT(v4,  3);
        working_state_4[4]  = EXTRACT(v4,  4); working_state_5[4]  = EXTRACT(v4,  5);
        working_state_6[4]  = EXTRACT(v4,  6); working_state_7[4]  = EXTRACT(v4,  7);
        working_state_0[5]  = EXTRACT(v5,  0); working_state_1[5]  = EXTRACT(v5,  1);
        working_state_2[5]  = EXTRACT(v5,  2); working_state_3[5]  = EXTRACT(v5,  3);
        working_state_4[5]  = EXTRACT(v5,  4); working_state_5[5]  = EXTRACT(v5,  5);
        working_state_6[5]  = EXTRACT(v5,  6); working_state_7[5]  = EXTRACT(v5,  7);
        working_state_0[6]  = EXTRACT(v6,  0); working_state_1[6]  = EXTRACT(v6,  1);
        working_state_2[6]  = EXTRACT(v6,  2); working_state_3[6]  = EXTRACT(v6,  3);
        working_state_4[6]  = EXTRACT(v6,  4); working_state_5[6]  = EXTRACT(v6,  5);
        working_state_6[6]  = EXTRACT(v6,  6); working_state_7[6]  = EXTRACT(v6,  7);
        working_state_0[7]  = EXTRACT(v7,  0); working_state_1[7]  = EXTRACT(v7,  1);
        working_state_2[7]  = EXTRACT(v7,  2); working_state_3[7]  = EXTRACT(v7,  3);
        working_state_4[7]  = EXTRACT(v7,  4); working_state_5[7]  = EXTRACT(v7,  5);
        working_state_6[7]  = EXTRACT(v7,  6); working_state_7[7]  = EXTRACT(v7,  7);
        working_state_0[8]  = EXTRACT(v8,  0); working_state_1[8]  = EXTRACT(v8,  1);
        working_state_2[8]  = EXTRACT(v8,  2); working_state_3[8]  = EXTRACT(v8,  3);
        working_state_4[8]  = EXTRACT(v8,  4); working_state_5[8]  = EXTRACT(v8,  5);
        working_state_6[8]  = EXTRACT(v8,  6); working_state_7[8]  = EXTRACT(v8,  7);
        working_state_0[9]  = EXTRACT(v9,  0); working_state_1[9]  = EXTRACT(v9,  1);
        working_state_2[9]  = EXTRACT(v9,  2); working_state_3[9]  = EXTRACT(v9,  3);
        working_state_4[9]  = EXTRACT(v9,  4); working_state_5[9]  = EXTRACT(v9,  5);
        working_state_6[9]  = EXTRACT(v9,  6); working_state_7[9]  = EXTRACT(v9,  7);
        working_state_0[10] = EXTRACT(v10, 0); working_state_1[10] = EXTRACT(v10, 1);
        working_state_2[10] = EXTRACT(v10, 2); working_state_3[10] = EXTRACT(v10, 3);
        working_state_4[10] = EXTRACT(v10, 4); working_state_5[10] = EXTRACT(v10, 5);
        working_state_6[10] = EXTRACT(v10, 6); working_state_7[10] = EXTRACT(v10, 7);
        working_state_0[11] = EXTRACT(v11, 0); working_state_1[11] = EXTRACT(v11, 1);
        working_state_2[11] = EXTRACT(v11, 2); working_state_3[11] = EXTRACT(v11, 3);
        working_state_4[11] = EXTRACT(v11, 4); working_state_5[11] = EXTRACT(v11, 5);
        working_state_6[11] = EXTRACT(v11, 6); working_state_7[11] = EXTRACT(v11, 7);
        working_state_0[12] = EXTRACT(v12, 0); working_state_1[12] = EXTRACT(v12, 1);
        working_state_2[12] = EXTRACT(v12, 2); working_state_3[12] = EXTRACT(v12, 3);
        working_state_4[12] = EXTRACT(v12, 4); working_state_5[12] = EXTRACT(v12, 5);
        working_state_6[12] = EXTRACT(v12, 6); working_state_7[12] = EXTRACT(v12, 7);
        working_state_0[13] = EXTRACT(v13, 0); working_state_1[13] = EXTRACT(v13, 1);
        working_state_2[13] = EXTRACT(v13, 2); working_state_3[13] = EXTRACT(v13, 3);
        working_state_4[13] = EXTRACT(v13, 4); working_state_5[13] = EXTRACT(v13, 5);
        working_state_6[13] = EXTRACT(v13, 6); working_state_7[13] = EXTRACT(v13, 7);
        working_state_0[14] = EXTRACT(v14, 0); working_state_1[14] = EXTRACT(v14, 1);
        working_state_2[14] = EXTRACT(v14, 2); working_state_3[14] = EXTRACT(v14, 3);
        working_state_4[14] = EXTRACT(v14, 4); working_state_5[14] = EXTRACT(v14, 5);
        working_state_6[14] = EXTRACT(v14, 6); working_state_7[14] = EXTRACT(v14, 7);
        working_state_0[15] = EXTRACT(v15, 0); working_state_1[15] = EXTRACT(v15, 1);
        working_state_2[15] = EXTRACT(v15, 2); working_state_3[15] = EXTRACT(v15, 3);
        working_state_4[15] = EXTRACT(v15, 4); working_state_5[15] = EXTRACT(v15, 5);
        working_state_6[15] = EXTRACT(v15, 6); working_state_7[15] = EXTRACT(v15, 7);

        #undef EXTRACT
        
        for (int i = 0; i < STATE_SIZE_W; i++) {
            working_state_0[i] += initial_state_w_0[i];
            working_state_1[i] += initial_state_w_1[i];
            working_state_2[i] += initial_state_w_2[i];
            working_state_3[i] += initial_state_w_3[i];
            working_state_4[i] += initial_state_w_4[i];
            working_state_5[i] += initial_state_w_5[i];
            working_state_6[i] += initial_state_w_6[i];
            working_state_7[i] += initial_state_w_7[i];
        }

        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer_0, working_state_0, STATE_SIZE_B);
            memcpy(keystream_buffer_1, working_state_1, STATE_SIZE_B);
            memcpy(keystream_buffer_2, working_state_2, STATE_SIZE_B);
            memcpy(keystream_buffer_3, working_state_3, STATE_SIZE_B);
            memcpy(keystream_buffer_4, working_state_4, STATE_SIZE_B);
            memcpy(keystream_buffer_5, working_state_5, STATE_SIZE_B);
            memcpy(keystream_buffer_6, working_state_6, STATE_SIZE_B);
            memcpy(keystream_buffer_7, working_state_7, STATE_SIZE_B);
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

                keystream_buffer_4[i4]     = working_state_4[i] & 0xff;
                keystream_buffer_4[i4 + 1] = (working_state_4[i] >>  8) & 0xff;
                keystream_buffer_4[i4 + 2] = (working_state_4[i] >> 16) & 0xff;
                keystream_buffer_4[i4 + 3] = (working_state_4[i] >> 24) & 0xff;

                keystream_buffer_5[i4]     = working_state_5[i] & 0xff;
                keystream_buffer_5[i4 + 1] = (working_state_5[i] >>  8) & 0xff;
                keystream_buffer_5[i4 + 2] = (working_state_5[i] >> 16) & 0xff;
                keystream_buffer_5[i4 + 3] = (working_state_5[i] >> 24) & 0xff;

                keystream_buffer_6[i4]     = working_state_6[i] & 0xff;
                keystream_buffer_6[i4 + 1] = (working_state_6[i] >>  8) & 0xff;
                keystream_buffer_6[i4 + 2] = (working_state_6[i] >> 16) & 0xff;
                keystream_buffer_6[i4 + 3] = (working_state_6[i] >> 24) & 0xff;

                keystream_buffer_7[i4]     = working_state_7[i] & 0xff;
                keystream_buffer_7[i4 + 1] = (working_state_7[i] >>  8) & 0xff;
                keystream_buffer_7[i4 + 2] = (working_state_7[i] >> 16) & 0xff;
                keystream_buffer_7[i4 + 3] = (working_state_7[i] >> 24) & 0xff;
            }
        #endif
        ///////////////////////////////////////////////////
    
        
        ///////////////////////////////////////////////////
        // Compute cipher text and increment block ctr
        ///////////////////////////////////////////////////
        for (int i = 0; i < STATE_SIZE_B; i++){
            ciphertext_buffer[idx_start + 0*STATE_SIZE_B + i] = plaintext_b[idx_start + 0*STATE_SIZE_B + i] ^ keystream_buffer_0[i];
            ciphertext_buffer[idx_start + 1*STATE_SIZE_B + i] = plaintext_b[idx_start + 1*STATE_SIZE_B + i] ^ keystream_buffer_1[i];
            ciphertext_buffer[idx_start + 2*STATE_SIZE_B + i] = plaintext_b[idx_start + 2*STATE_SIZE_B + i] ^ keystream_buffer_2[i];
            ciphertext_buffer[idx_start + 3*STATE_SIZE_B + i] = plaintext_b[idx_start + 3*STATE_SIZE_B + i] ^ keystream_buffer_3[i];
            ciphertext_buffer[idx_start + 4*STATE_SIZE_B + i] = plaintext_b[idx_start + 4*STATE_SIZE_B + i] ^ keystream_buffer_4[i];
            ciphertext_buffer[idx_start + 5*STATE_SIZE_B + i] = plaintext_b[idx_start + 5*STATE_SIZE_B + i] ^ keystream_buffer_5[i];
            ciphertext_buffer[idx_start + 6*STATE_SIZE_B + i] = plaintext_b[idx_start + 6*STATE_SIZE_B + i] ^ keystream_buffer_6[i];
            ciphertext_buffer[idx_start + 7*STATE_SIZE_B + i] = plaintext_b[idx_start + 7*STATE_SIZE_B + i] ^ keystream_buffer_7[i];
        }
        
        initial_state_w_0[BLOCK_CTR_IDX] += 8;
        initial_state_w_1[BLOCK_CTR_IDX] += 8;
        initial_state_w_2[BLOCK_CTR_IDX] += 8;
        initial_state_w_3[BLOCK_CTR_IDX] += 8;
        initial_state_w_4[BLOCK_CTR_IDX] += 8;
        initial_state_w_5[BLOCK_CTR_IDX] += 8;
        initial_state_w_6[BLOCK_CTR_IDX] += 8;
        initial_state_w_7[BLOCK_CTR_IDX] += 8;

        idx_start += 8 * STATE_SIZE_B;
        ///////////////////////////////////////////////////
    }

    ///////////////////////////////////////////////////
    // Cleanup of remaining blocks (num_full_blocks % 8)
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
        for (int i = 0; i < STATE_SIZE_B; i++){
            ciphertext_buffer[idx_start + i] = plaintext_b[idx_start + i] ^ keystream_buffer_0[i];
        }
        
        initial_state_w_0[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
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

// TODO: replace with actual implementation of OpenSSL
// int chacha20_encrypt_openssl(uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
//     const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds) {
//     return chacha20_encrypt_base(ctxt, ptxt, len, key, nonce, ctr, rounds);
// }