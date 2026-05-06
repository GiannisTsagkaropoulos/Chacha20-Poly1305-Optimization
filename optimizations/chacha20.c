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
    uint32_t initial_state_w[STATE_SIZE_W];
    uint8_t  keystream_buffer[BLOCK_SIZE_B];
    
    ///////////////////////////////////////////////////
    // Initialize state, block number and rounds
    ///////////////////////////////////////////////////
    initial_state_w[0] = 0x61707865;
    initial_state_w[1] = 0x3320646e;
    initial_state_w[2] = 0x79622d32;
    initial_state_w[3] = 0x6b206574;
    initial_state_w[4] = BYTE_PTR_TO_U32(key_b);
    initial_state_w[5] = BYTE_PTR_TO_U32(key_b + 4);
    initial_state_w[6] = BYTE_PTR_TO_U32(key_b + 8);
    initial_state_w[7] = BYTE_PTR_TO_U32(key_b + 12);
    initial_state_w[8] = BYTE_PTR_TO_U32(key_b + 16);
    initial_state_w[9] = BYTE_PTR_TO_U32(key_b + 20);
    initial_state_w[10] = BYTE_PTR_TO_U32(key_b + 24);
    initial_state_w[11] = BYTE_PTR_TO_U32(key_b + 28);
    initial_state_w[12] = block_ctr;
    initial_state_w[13] = BYTE_PTR_TO_U32(nonce_b);
    initial_state_w[14] = BYTE_PTR_TO_U32(nonce_b + 4);
    initial_state_w[15] = BYTE_PTR_TO_U32(nonce_b + 8);
    
    uint64_t num_full_blocks = len_plaintext / BLOCK_SIZE_B;
    uint64_t remainder       = len_plaintext % BLOCK_SIZE_B;
    
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
        
        for (int i = 0; i < STATE_SIZE_W; i++) {
            working_state[i] += initial_state_w[i];
        }

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
        for (int i = 0; i < BLOCK_SIZE_B; i++){
            ciphertext_buffer[idx_start + i] = plaintext_b[idx_start + i] ^ keystream_buffer[i];
        }
        
        initial_state_w[BLOCK_CTR_IDX]++;
        idx_start += BLOCK_SIZE_B;
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
        
        for (int i = 0; i < STATE_SIZE_W; i++) {
            working_state[i] += initial_state_w[i];
        }

        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer, working_state, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 += 4;
                keystream_buffer[i4]     = state[i] & 0xff;
                keystream_buffer[i4 + 1] = (state[i] >>  8) & 0xff;
                keystream_buffer[i4 + 2] = (state[i] >> 16) & 0xff;
                keystream_buffer[i4 + 3] = (state[i] >> 24) & 0xff;
            }
        #endif

        for (uint64_t i = 0; i < remainder; i++)
            ciphertext_buffer[idx_start + i] = plaintext_b[idx_start + i] ^ keystream_buffer[i];
    }

    return 0;
}