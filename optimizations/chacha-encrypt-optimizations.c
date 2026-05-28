#include <openssl/evp.h>
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

int chacha20_encrypt_strength_reduction( 
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds
){
    uint32_t initial_state_w[STATE_SIZE_W];
    uint8_t  keystream_buffer[STATE_SIZE_B];

    initialize_chacha_state(initial_state_w, key, nonce, ctr);

    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;

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



int chacha20_encrypt_inline(
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
    
    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;
    
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

/*
* Optimizations:
* 1. Scalar replacement now put to actual use, no reads and writes to working state on every double round we process
*/
int chacha20_encrypt_scalar_replacement(
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds
){
    uint32_t state[STATE_SIZE_W];
    uint8_t  keystream_buffer[STATE_SIZE_B];

    ///////////////////////////////////////////////////
    // Initialize state, block number and rounds
    ///////////////////////////////////////////////////
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = BYTE_PTR_TO_U32(key);
    state[5] = BYTE_PTR_TO_U32(key + 4);
    state[6] = BYTE_PTR_TO_U32(key + 8);
    state[7] = BYTE_PTR_TO_U32(key + 12);
    state[8] = BYTE_PTR_TO_U32(key + 16);
    state[9] = BYTE_PTR_TO_U32(key + 20);
    state[10] = BYTE_PTR_TO_U32(key + 24);
    state[11] = BYTE_PTR_TO_U32(key + 28);
    state[12] = ctr;
    state[13] = BYTE_PTR_TO_U32(nonce);
    state[14] = BYTE_PTR_TO_U32(nonce + 4);
    state[15] = BYTE_PTR_TO_U32(nonce + 8);
    
    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;
    
    int double_rounds = rounds / 2;
    ///////////////////////////////////////////////////
    
    
    uint32_t working_state[STATE_SIZE_W];
    uint64_t idx_start = 0; 
    for (uint64_t b = 0; b < num_full_blocks; b++) {
        memcpy(working_state, state, STATE_SIZE_B);     
        
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

        for (int i = 0; i < double_rounds; i++) {
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
        
        working_state[0]= out0 + state[0];
        working_state[1]= out1 + state[1];
        working_state[2]= out2 + state[2];
        working_state[3]= out3 + state[3];
        working_state[4]= out4 + state[4];
        working_state[5]= out5 + state[5];
        working_state[6]= out6 + state[6];
        working_state[7]= out7 + state[7];
        working_state[8]= out8 + state[8];
        working_state[9]= out9 + state[9];
        working_state[10] = out10 + state[10];
        working_state[11] = out11 + state[11];
        working_state[12] = out12 + state[12];
        working_state[13] = out13 + state[13];
        working_state[14] = out14 + state[14];
        working_state[15] = out15 + state[15];

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
        
        state[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
        ///////////////////////////////////////////////////
    }
        
    if (remainder != 0) {
        memcpy(working_state, state, STATE_SIZE_B);     
        
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

        for (int i = 0; i < double_rounds; i++) {
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
        
        working_state[0]= out0 + state[0];
        working_state[1]= out1 + state[1];
        working_state[2]= out2 + state[2];
        working_state[3]= out3 + state[3];
        working_state[4]= out4 + state[4];
        working_state[5]= out5 + state[5];
        working_state[6]= out6 + state[6];
        working_state[7]= out7 + state[7];
        working_state[8]= out8 + state[8];
        working_state[9]= out9 + state[9];
        working_state[10] = out10 + state[10];
        working_state[11] = out11 + state[11];
        working_state[12] = out12 + state[12];
        working_state[13] = out13 + state[13];
        working_state[14] = out14 + state[14];
        working_state[15] = out15 + state[15];

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


int chacha20_encrypt_scalar_replacement2(
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds
){
    uint32_t state[STATE_SIZE_W];
    uint32_t ws[STATE_SIZE_W];
    uint32_t keystream_buffer[STATE_SIZE_B];
    
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = BYTE_PTR_TO_U32(key);
    state[5] = BYTE_PTR_TO_U32(key + 4);
    state[6] = BYTE_PTR_TO_U32(key + 8);
    state[7] = BYTE_PTR_TO_U32(key + 12);
    state[8] = BYTE_PTR_TO_U32(key + 16);
    state[9] = BYTE_PTR_TO_U32(key + 20);
    state[10] = BYTE_PTR_TO_U32(key + 24);
    state[11] = BYTE_PTR_TO_U32(key + 28);
    state[12] = ctr;
    state[13] = BYTE_PTR_TO_U32(nonce);
    state[14] = BYTE_PTR_TO_U32(nonce + 4);
    state[15] = BYTE_PTR_TO_U32(nonce + 8);
    
    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;
    

    uint64_t idx_start = 0; 
    uint32_t o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15;
    for (uint64_t b = 0; b < num_full_blocks; b++) {
        o0 = state[0];   o1 = state[1];   o2 = state[2];   o3 = state[3];
        o4 = state[4];   o5 = state[5];   o6 = state[6];   o7 = state[7];
        o8 = state[8];   o9 = state[9];   o10= state[10];  o11= state[11];
        o12= state[12];  o13= state[13];  o14= state[14];  o15= state[15];

        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            // Column Rounds
            QUARTER_ROUND(o0, o4, o8, o12);
            QUARTER_ROUND(o1, o5, o9, o13);
            QUARTER_ROUND(o2, o6, o10, o14);
            QUARTER_ROUND(o3, o7, o11, o15);

            // Diagonal Rounds
            QUARTER_ROUND(o0, o5, o10, o15);
            QUARTER_ROUND(o1, o6, o11, o12);
            QUARTER_ROUND(o2, o7, o8, o13);
            QUARTER_ROUND(o3, o4, o9, o14);
        }
        
        o0 += state[0];   o1 += state[1];   o2 += state[2];   o3 += state[3];
        o4 += state[4];   o5 += state[5];   o6 += state[6];   o7 += state[7];
        o8 += state[8];   o9 += state[9];   o10+= state[10];  o11+= state[11];
        o12+= state[12];  o13+= state[13];  o14+= state[14];  o15+= state[15];

        ws[0] = o0;    ws[1] = o1;    ws[2] = o2;    ws[3] = o3;
        ws[4] = o4;    ws[5] = o5;    ws[6] = o6;    ws[7] = o7;
        ws[8] = o8;    ws[9] = o9;    ws[10] = o10;  ws[11] = o11;
        ws[12] = o12;  ws[13] = o13;  ws[14] = o14;  ws[15] = o15;
        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer, ws, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 += 4;
                keystream_buffer[i4]     = ws[i] & 0xff;
                keystream_buffer[i4 + 1] = (ws[i] >>  8) & 0xff;
                keystream_buffer[i4 + 2] = (ws[i] >> 16) & 0xff;
                keystream_buffer[i4 + 3] = (ws[i] >> 24) & 0xff;
            }
        #endif

        for (uint64_t i = 0; i < remainder; i++){
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];
        }

        state[12]++;
        idx_start += 64; 
    }
        
    if (remainder != 0) {
        o0 = state[0];   o1 = state[1];   o2 = state[2];   o3 = state[3];
        o4 = state[4];   o5 = state[5];   o6 = state[6];   o7 = state[7];
        o8 = state[8];   o9 = state[9];   o10= state[10];  o11= state[11];
        o12= state[12];  o13= state[13];  o14= state[14];  o15= state[15];

        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            QUARTER_ROUND(o0, o4, o8, o12);
            QUARTER_ROUND(o1, o5, o9, o13);
            QUARTER_ROUND(o2, o6, o10, o14);
            QUARTER_ROUND(o3, o7, o11, o15);

            QUARTER_ROUND(o0, o5, o10, o15);
            QUARTER_ROUND(o1, o6, o11, o12);
            QUARTER_ROUND(o2, o7, o8, o13);
            QUARTER_ROUND(o3, o4, o9, o14);
        }
        
        o0 += state[0];   o1 += state[1];   o2 += state[2];   o3 += state[3];
        o4 += state[4];   o5 += state[5];   o6 += state[6];   o7 += state[7];
        o8 += state[8];   o9 += state[9];   o10+= state[10];  o11+= state[11];
        o12+= state[12];  o13+= state[13];  o14+= state[14];  o15+= state[15];

        ws[0] = o0;    ws[1] = o1;    ws[2] = o2;    ws[3] = o3;
        ws[4] = o4;    ws[5] = o5;    ws[6] = o6;    ws[7] = o7;
        ws[8] = o8;    ws[9] = o9;    ws[10] = o10;  ws[11] = o11;
        ws[12] = o12;  ws[13] = o13;  ws[14] = o14;  ws[15] = o15;
        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer, ws, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 += 4;
                keystream_buffer[i4]     = ws[i] & 0xff;
                keystream_buffer[i4 + 1] = (ws[i] >>  8) & 0xff;
                keystream_buffer[i4 + 2] = (ws[i] >> 16) & 0xff;
                keystream_buffer[i4 + 3] = (ws[i] >> 24) & 0xff;
            }
        #endif

        for (uint64_t i = 0; i < remainder; i++) {
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];
        }
    }

    return 0;
}

/*
* Optimizations:
* 1. Scalar replacement now put to actual use, no reads and writes to working state on every double round we process
*/
int chacha20_encrypt_unroll_ilp_ctxt(
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds
){
    uint32_t state[STATE_SIZE_W];
    uint32_t ws[STATE_SIZE_W];
    uint32_t keystream_buffer[STATE_SIZE_B];
    
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = BYTE_PTR_TO_U32(key);
    state[5] = BYTE_PTR_TO_U32(key + 4);
    state[6] = BYTE_PTR_TO_U32(key + 8);
    state[7] = BYTE_PTR_TO_U32(key + 12);
    state[8] = BYTE_PTR_TO_U32(key + 16);
    state[9] = BYTE_PTR_TO_U32(key + 20);
    state[10] = BYTE_PTR_TO_U32(key + 24);
    state[11] = BYTE_PTR_TO_U32(key + 28);
    state[12] = ctr;
    state[13] = BYTE_PTR_TO_U32(nonce);
    state[14] = BYTE_PTR_TO_U32(nonce + 4);
    state[15] = BYTE_PTR_TO_U32(nonce + 8);
    
    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;
    

    uint64_t idx_start = 0; 
    uint32_t o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15;
    for (uint64_t b = 0; b < num_full_blocks; b++) {
        o0 = state[0];   o1 = state[1];   o2 = state[2];   o3 = state[3];
        o4 = state[4];   o5 = state[5];   o6 = state[6];   o7 = state[7];
        o8 = state[8];   o9 = state[9];   o10= state[10];  o11= state[11];
        o12= state[12];  o13= state[13];  o14= state[14];  o15= state[15];

        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            // Column Rounds
            QUARTER_ROUND(o0, o4, o8, o12);
            QUARTER_ROUND(o1, o5, o9, o13);
            QUARTER_ROUND(o2, o6, o10, o14);
            QUARTER_ROUND(o3, o7, o11, o15);

            // Diagonal Rounds
            QUARTER_ROUND(o0, o5, o10, o15);
            QUARTER_ROUND(o1, o6, o11, o12);
            QUARTER_ROUND(o2, o7, o8, o13);
            QUARTER_ROUND(o3, o4, o9, o14);
        }
        
        o0 += state[0];   o1 += state[1];   o2 += state[2];   o3 += state[3];
        o4 += state[4];   o5 += state[5];   o6 += state[6];   o7 += state[7];
        o8 += state[8];   o9 += state[9];   o10+= state[10];  o11+= state[11];
        o12+= state[12];  o13+= state[13];  o14+= state[14];  o15+= state[15];

        ws[0] = o0;    ws[1] = o1;    ws[2] = o2;    ws[3] = o3;
        ws[4] = o4;    ws[5] = o5;    ws[6] = o6;    ws[7] = o7;
        ws[8] = o8;    ws[9] = o9;    ws[10] = o10;  ws[11] = o11;
        ws[12] = o12;  ws[13] = o13;  ws[14] = o14;  ws[15] = o15;
        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer, ws, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 += 4;
                keystream_buffer[i4]     = ws[i] & 0xff;
                keystream_buffer[i4 + 1] = (ws[i] >>  8) & 0xff;
                keystream_buffer[i4 + 2] = (ws[i] >> 16) & 0xff;
                keystream_buffer[i4 + 3] = (ws[i] >> 24) & 0xff;
            }
        #endif
        
        uint64_t j;   
        for (uint64_t i = 0; i < remainder; i+=8){
            j = idx_start + i;
            ctxt[j]      = ptxt[j]     ^ keystream_buffer[0];
            ctxt[j + 1]  = ptxt[j + 1] ^ keystream_buffer[1];
            ctxt[j + 2]  = ptxt[j + 2] ^ keystream_buffer[2];
            ctxt[j + 3]  = ptxt[j + 3] ^ keystream_buffer[3];
            ctxt[j + 4]  = ptxt[j + 4] ^ keystream_buffer[4];
            ctxt[j + 5]  = ptxt[j + 5] ^ keystream_buffer[5];
            ctxt[j + 6]  = ptxt[j + 6] ^ keystream_buffer[6];
            ctxt[j + 7]  = ptxt[j + 7] ^ keystream_buffer[7];
        }

        state[12]++;
        idx_start += 64; 
    }
        
    if (remainder != 0) {
        o0 = state[0];   o1 = state[1];   o2 = state[2];   o3 = state[3];
        o4 = state[4];   o5 = state[5];   o6 = state[6];   o7 = state[7];
        o8 = state[8];   o9 = state[9];   o10= state[10];  o11= state[11];
        o12= state[12];  o13= state[13];  o14= state[14];  o15= state[15];

        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            QUARTER_ROUND(o0, o4, o8, o12);
            QUARTER_ROUND(o1, o5, o9, o13);
            QUARTER_ROUND(o2, o6, o10, o14);
            QUARTER_ROUND(o3, o7, o11, o15);

            QUARTER_ROUND(o0, o5, o10, o15);
            QUARTER_ROUND(o1, o6, o11, o12);
            QUARTER_ROUND(o2, o7, o8, o13);
            QUARTER_ROUND(o3, o4, o9, o14);
        }
        
        o0 += state[0];   o1 += state[1];   o2 += state[2];   o3 += state[3];
        o4 += state[4];   o5 += state[5];   o6 += state[6];   o7 += state[7];
        o8 += state[8];   o9 += state[9];   o10+= state[10];  o11+= state[11];
        o12+= state[12];  o13+= state[13];  o14+= state[14];  o15+= state[15];

        ws[0] = o0;    ws[1] = o1;    ws[2] = o2;    ws[3] = o3;
        ws[4] = o4;    ws[5] = o5;    ws[6] = o6;    ws[7] = o7;
        ws[8] = o8;    ws[9] = o9;    ws[10] = o10;  ws[11] = o11;
        ws[12] = o12;  ws[13] = o13;  ws[14] = o14;  ws[15] = o15;
        #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            memcpy(keystream_buffer, ws, STATE_SIZE_B);
        #else
            size_t i4 = 0;
            for (size_t i = 0; i < STATE_SIZE_W; i++) {
                i4 += 4;
                keystream_buffer[i4]     = ws[i] & 0xff;
                keystream_buffer[i4 + 1] = (ws[i] >>  8) & 0xff;
                keystream_buffer[i4 + 2] = (ws[i] >> 16) & 0xff;
                keystream_buffer[i4 + 3] = (ws[i] >> 24) & 0xff;
            }
        #endif

        for (uint64_t i = 0; i < remainder; i++) {
            ctxt[idx_start + i + 0]  = ptxt[idx_start + i + 0] ^ keystream_buffer[0];
        }
    }

    return 0;
}

/*
* Optimizations:
* 1. Unroll by 4 and use multiple accumulators in working state, keystream, ciphertext_idx to process 4 plaintext blocks in every iteration
*/
int chacha20_encrypt_multiple_pt_blocks_at_once(
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds
){
    uint32_t s[STATE_SIZE_W]; 
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    s[4] = BYTE_PTR_TO_U32(key);
    s[5] = BYTE_PTR_TO_U32(key + 4);
    s[6] = BYTE_PTR_TO_U32(key + 8);
    s[7] = BYTE_PTR_TO_U32(key + 12);
    s[8] = BYTE_PTR_TO_U32(key + 16);
    s[9] = BYTE_PTR_TO_U32(key + 20);
    s[10] = BYTE_PTR_TO_U32(key + 24);
    s[11] = BYTE_PTR_TO_U32(key + 28);
    s[12] = ctr;
    s[13] = BYTE_PTR_TO_U32(nonce);
    s[14] = BYTE_PTR_TO_U32(nonce + 4);
    s[15] = BYTE_PTR_TO_U32(nonce + 8);
    
    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;

    uint32_t ws0[STATE_SIZE_W], ks0[STATE_SIZE_B];
    uint32_t ws1[STATE_SIZE_W], ks1[STATE_SIZE_B];
    uint32_t ws2[STATE_SIZE_W], ks2[STATE_SIZE_B];
    uint32_t ws3[STATE_SIZE_W], ks3[STATE_SIZE_B];

    uint32_t ctr0 = ctr;
    uint32_t ctr1 = ctr+1;
    uint32_t ctr2 = ctr+2;
    uint32_t ctr3 = ctr+3;


    uint64_t ct_idx0 = 0; 
    uint64_t ct_idx1 = 64; 
    uint64_t ct_idx2 = 128; 
    uint64_t ct_idx3 = 192; 

    uint64_t ct_idx_jump = 256;

    uint32_t o_0_0, o_0_1, o_0_2, o_0_3, o_0_4, o_0_5, o_0_6, o_0_7, o_0_8, o_0_9, o_0_10, o_0_11, o_0_12, o_0_13, o_0_14, o_0_15;
    uint32_t o_1_0, o_1_1, o_1_2, o_1_3, o_1_4, o_1_5, o_1_6, o_1_7, o_1_8, o_1_9, o_1_10, o_1_11, o_1_12, o_1_13, o_1_14, o_1_15;
    uint32_t o_2_0, o_2_1, o_2_2, o_2_3, o_2_4, o_2_5, o_2_6, o_2_7, o_2_8, o_2_9, o_2_10, o_2_11, o_2_12, o_2_13, o_2_14, o_2_15;
    uint32_t o_3_0, o_3_1, o_3_2, o_3_3, o_3_4, o_3_5, o_3_6, o_3_7, o_3_8, o_3_9, o_3_10, o_3_11, o_3_12, o_3_13, o_3_14, o_3_15;
    for (uint64_t b = 0; b < num_full_blocks; b+=4) {
        o_0_0 = s[0]; o_1_0 = s[0]; o_2_0 = s[0]; o_3_0 = s[0];
        o_0_1 = s[1]; o_1_1 = s[1]; o_2_1 = s[1]; o_3_1 = s[1];
        o_0_2 = s[2]; o_1_2 = s[2]; o_2_2 = s[2]; o_3_2 = s[2];
        o_0_3 = s[3]; o_1_3 = s[3]; o_2_3 = s[3]; o_3_3 = s[3];

        o_0_4 = s[4]; o_1_4 = s[4]; o_2_4 = s[4]; o_3_4 = s[4];
        o_0_5 = s[5]; o_1_5 = s[5]; o_2_5 = s[5]; o_3_5 = s[5];
        o_0_6 = s[6]; o_1_6 = s[6]; o_2_6 = s[6]; o_3_6 = s[6];
        o_0_7 = s[7]; o_1_7 = s[7]; o_2_7 = s[7]; o_3_7 = s[7];
        o_0_8 = s[8]; o_1_8 = s[8]; o_2_8 = s[8]; o_3_8 = s[8];
        o_0_9 = s[9]; o_1_9 = s[9]; o_2_9 = s[9]; o_3_9 = s[9];
        o_0_10 = s[10]; o_1_10 = s[10]; o_2_10 = s[10]; o_3_10 = s[10];
        o_0_11 = s[11]; o_1_11 = s[11]; o_2_11 = s[11]; o_3_11 = s[11];

        o_0_12 = ctr0; o_1_12 = ctr1; o_2_12 = ctr2; o_3_12 = ctr3;

        o_0_13 = s[13]; o_1_13 = s[13]; o_2_13 = s[13]; o_3_13 = s[13]; 
        o_0_14 = s[14]; o_1_14 = s[14]; o_2_14 = s[14]; o_3_14 = s[14]; 
        o_0_15 = s[15]; o_1_15 = s[15]; o_2_15 = s[15]; o_3_15 = s[15];

        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            // 0
            QUARTER_ROUND(o_0_0, o_0_4, o_0_8, o_0_12); 
            QUARTER_ROUND(o_1_0, o_1_4, o_1_8, o_1_12); 
            QUARTER_ROUND(o_2_0, o_2_4, o_2_8, o_2_12); 
            QUARTER_ROUND(o_3_0, o_3_4, o_3_8, o_3_12); 


            // 1
            QUARTER_ROUND(o_0_1, o_0_5, o_0_9, o_0_13); 
            QUARTER_ROUND(o_1_1, o_1_5, o_1_9, o_1_13); 
            QUARTER_ROUND(o_2_1, o_2_5, o_2_9, o_2_13); 
            QUARTER_ROUND(o_3_1, o_3_5, o_3_9, o_3_13); 


            // 2
            QUARTER_ROUND(o_0_2, o_0_6, o_0_10, o_0_14); 
            QUARTER_ROUND(o_1_2, o_1_6, o_1_10, o_1_14); 
            QUARTER_ROUND(o_2_2, o_2_6, o_2_10, o_2_14); 
            QUARTER_ROUND(o_3_2, o_3_6, o_3_10, o_3_14); 

            // 3
            QUARTER_ROUND(o_0_3, o_0_7, o_0_11, o_0_15); 
            QUARTER_ROUND(o_1_3, o_1_7, o_1_11, o_1_15); 
            QUARTER_ROUND(o_2_3, o_2_7, o_2_11, o_2_15); 
            QUARTER_ROUND(o_3_3, o_3_7, o_3_11, o_3_15); 
          

            // 4
            QUARTER_ROUND(o_0_0, o_0_5, o_0_10, o_0_15); 
            QUARTER_ROUND(o_1_0, o_1_5, o_1_10, o_1_15); 
            QUARTER_ROUND(o_2_0, o_2_5, o_2_10, o_2_15); 
            QUARTER_ROUND(o_3_0, o_3_5, o_3_10, o_3_15); 


            // 5
            QUARTER_ROUND(o_0_1, o_0_6, o_0_11, o_0_12); 
            QUARTER_ROUND(o_1_1, o_1_6, o_1_11, o_1_12); 
            QUARTER_ROUND(o_2_1, o_2_6, o_2_11, o_2_12); 
            QUARTER_ROUND(o_3_1, o_3_6, o_3_11, o_3_12); 


            // 6
            QUARTER_ROUND(o_0_2, o_0_7, o_0_8, o_0_13); 
            QUARTER_ROUND(o_1_2, o_1_7, o_1_8, o_1_13); 
            QUARTER_ROUND(o_2_2, o_2_7, o_2_8, o_2_13); 
            QUARTER_ROUND(o_3_2, o_3_7, o_3_8, o_3_13); 


            // 7
            QUARTER_ROUND(o_0_3, o_0_4, o_0_9, o_0_14); 
            QUARTER_ROUND(o_1_3, o_1_4, o_1_9, o_1_14); 
            QUARTER_ROUND(o_2_3, o_2_4, o_2_9, o_2_14); 
            QUARTER_ROUND(o_3_3, o_3_4, o_3_9, o_3_14); 
        }
        
        // 8 adds in each row
        o_0_0 += s[0]; o_1_0 += s[0]; o_2_0 += s[0]; o_3_0 += s[0]; 
        o_0_1 += s[1]; o_1_1 += s[1]; o_2_1 += s[1]; o_3_1 += s[1]; 
        o_0_2 += s[2]; o_1_2 += s[2]; o_2_2 += s[2]; o_3_2 += s[2]; 
        o_0_3 += s[3]; o_1_3 += s[3]; o_2_3 += s[3]; o_3_3 += s[3]; 
        o_0_4 += s[4]; o_1_4 += s[4]; o_2_4 += s[4]; o_3_4 += s[4]; 
        o_0_5 += s[5]; o_1_5 += s[5]; o_2_5 += s[5]; o_3_5 += s[5]; 
        o_0_6 += s[6]; o_1_6 += s[6]; o_2_6 += s[6]; o_3_6 += s[6];
        o_0_7 += s[7]; o_1_7 += s[7]; o_2_7 += s[7]; o_3_7 += s[7]; 
        o_0_8 += s[8]; o_1_8 += s[8]; o_2_8 += s[8]; o_3_8 += s[8]; 
        o_0_9 += s[9]; o_1_9 += s[9]; o_2_9 += s[9]; o_3_9 += s[9]; 
        o_0_10 += s[10]; o_1_10 += s[10]; o_2_10 += s[10]; o_3_10 += s[10]; 
        o_0_11 += s[11]; o_1_11 += s[11]; o_2_11 += s[11]; o_3_11 += s[11]; 

        o_0_12 += ctr0; o_1_12 += ctr1; o_2_12 += ctr2; o_3_12 += ctr3;
        o_0_13 += s[13]; o_1_13 += s[13]; o_2_13 += s[13]; o_3_13 += s[13];
        o_0_14 += s[14]; o_1_14 += s[14]; o_2_14 += s[14]; o_3_14 += s[14]; 
        o_0_15 += s[15]; o_1_15 += s[15]; o_2_15 += s[15]; o_3_15 += s[15]; 

        ws0[0] = o_0_0; ws1[0] = o_1_0; ws2[0] = o_2_0; ws3[0] = o_3_0;
        ws0[1] = o_0_1; ws1[1] = o_1_1; ws2[1] = o_2_1; ws3[1] = o_3_1;
        ws0[2] = o_0_2; ws1[2] = o_1_2; ws2[2] = o_2_2; ws3[2] = o_3_2;
        ws0[3] = o_0_3; ws1[3] = o_1_3; ws2[3] = o_2_3; ws3[3] = o_3_3;
        ws0[4] = o_0_4; ws1[4] = o_1_4; ws2[4] = o_2_4; ws3[4] = o_3_4;
        ws0[5] = o_0_5; ws1[5] = o_1_5; ws2[5] = o_2_5; ws3[5] = o_3_5; 
        ws0[6] = o_0_6; ws1[6] = o_1_6; ws2[6] = o_2_6; ws3[6] = o_3_6; 
        ws0[7] = o_0_7; ws1[7] = o_1_7; ws2[7] = o_2_7; ws3[7] = o_3_7; 
        ws0[8] = o_0_8; ws1[8] = o_1_8; ws2[8] = o_2_8; ws3[8] = o_3_8; 
        ws0[9] = o_0_9; ws1[9] = o_1_9; ws2[9] = o_2_9; ws3[9] = o_3_9;
        ws0[10] = o_0_10; ws1[10] = o_1_10; ws2[10] = o_2_10; ws3[10] = o_3_10; 
        ws0[11] = o_0_11; ws1[11] = o_1_11; ws2[11] = o_2_11; ws3[11] = o_3_11; 
        ws0[12] = o_0_12; ws1[12] = o_1_12; ws2[12] = o_2_12; ws3[12] = o_3_12; 
        ws0[13] = o_0_13; ws1[13] = o_1_13; ws2[13] = o_2_13; ws3[13] = o_3_13; 
        ws0[14] = o_0_14; ws1[14] = o_1_14; ws2[14] = o_2_14; ws3[14] = o_3_14; 
        ws0[15] = o_0_15; ws1[15] = o_1_15; ws2[15] = o_2_15; ws3[15] = o_3_15;

        //  only for little endian
        memcpy(ks0, ws0, STATE_SIZE_B);
        memcpy(ks1, ws1, STATE_SIZE_B);
        memcpy(ks2, ws2, STATE_SIZE_B);
        memcpy(ks3, ws3, STATE_SIZE_B);

        uint64_t j0, j1, j2, j3;
        for (uint64_t i = 0; i < remainder; i+=8){
            j0 = ct_idx0 + i;
            j1 = ct_idx1 + i;
            j2 = ct_idx2 + i;
            j3 = ct_idx3 + i;

            ctxt[j0]      = ptxt[j0]     ^ ks0[0];
            ctxt[j0 + 1]  = ptxt[j0 + 1] ^ ks0[1];
            ctxt[j0 + 2]  = ptxt[j0 + 2] ^ ks0[2];
            ctxt[j0 + 3]  = ptxt[j0 + 3] ^ ks0[3];
            ctxt[j0 + 4]  = ptxt[j0 + 4] ^ ks0[4];
            ctxt[j0 + 5]  = ptxt[j0 + 5] ^ ks0[5];
            ctxt[j0 + 6]  = ptxt[j0 + 6] ^ ks0[6];
            ctxt[j0 + 7]  = ptxt[j0 + 7] ^ ks0[7];

            ctxt[j1]      = ptxt[j1]     ^ ks1[0];
            ctxt[j1 + 1]  = ptxt[j1 + 1] ^ ks1[1];
            ctxt[j1 + 2]  = ptxt[j1 + 2] ^ ks1[2];
            ctxt[j1 + 3]  = ptxt[j1 + 3] ^ ks1[3];
            ctxt[j1 + 4]  = ptxt[j1 + 4] ^ ks1[4];
            ctxt[j1 + 5]  = ptxt[j1 + 5] ^ ks1[5];
            ctxt[j1 + 6]  = ptxt[j1 + 6] ^ ks1[6];
            ctxt[j1 + 7]  = ptxt[j1 + 7] ^ ks1[7];

            ctxt[j2]      = ptxt[j2]     ^ ks2[0];
            ctxt[j2 + 1]  = ptxt[j2 + 1] ^ ks2[1];
            ctxt[j2 + 2]  = ptxt[j2 + 2] ^ ks2[2];
            ctxt[j2 + 3]  = ptxt[j2 + 3] ^ ks2[3];
            ctxt[j2 + 4]  = ptxt[j2 + 4] ^ ks2[4];
            ctxt[j2 + 5]  = ptxt[j2 + 5] ^ ks2[5];
            ctxt[j2 + 6]  = ptxt[j2 + 6] ^ ks2[6];
            ctxt[j2 + 7]  = ptxt[j2 + 7] ^ ks2[7];

            ctxt[j3]      = ptxt[j3]     ^ ks3[0];
            ctxt[j3 + 1]  = ptxt[j3 + 1] ^ ks3[1];
            ctxt[j3 + 2]  = ptxt[j3 + 2] ^ ks3[2];
            ctxt[j3 + 3]  = ptxt[j3 + 3] ^ ks3[3];
            ctxt[j3 + 4]  = ptxt[j3 + 4] ^ ks3[4];
            ctxt[j3 + 5]  = ptxt[j3 + 5] ^ ks3[5];
            ctxt[j3 + 6]  = ptxt[j3 + 6] ^ ks3[6];
            ctxt[j3 + 7]  = ptxt[j3 + 7] ^ ks3[7];
        }

        ctr0 += 1;
        ctr1 += 1;
        ctr2 += 1;
        ctr3 += 1;

        ct_idx0 += ct_idx_jump; 
        ct_idx1 += ct_idx_jump; 
        ct_idx2 += ct_idx_jump; 
        ct_idx3 += ct_idx_jump; 
    }
        
    if (remainder != 0) {
        o_0_0 = s[0];   o_0_1 = s[1];   o_0_2 = s[2];   o_0_3 = s[3];
        o_0_4 = s[4];   o_0_5 = s[5];   o_0_6 = s[6];   o_0_7 = s[7];
        o_0_8 = s[8];   o_0_9 = s[9];   o_0_10= s[10];  o_0_11= s[11];
        o_0_12= s[12];  o_0_13= s[13];  o_0_14= s[14];  o_0_15= s[15];

        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            QUARTER_ROUND(o_0_0, o_0_4, o_0_8, o_0_12);
            QUARTER_ROUND(o_0_1, o_0_5, o_0_9, o_0_13);
            QUARTER_ROUND(o_0_2, o_0_6, o_0_10, o_0_14);
            QUARTER_ROUND(o_0_3, o_0_7, o_0_11, o_0_15);

            QUARTER_ROUND(o_0_0, o_0_5, o_0_10, o_0_15);
            QUARTER_ROUND(o_0_1, o_0_6, o_0_11, o_0_12);
            QUARTER_ROUND(o_0_2, o_0_7, o_0_8, o_0_13);
            QUARTER_ROUND(o_0_3, o_0_4, o_0_9, o_0_14);
        }
        
        o_0_0 += s[0];   o_0_1 += s[1];   o_0_2 += s[2];   o_0_3 += s[3];
        o_0_4 += s[4];   o_0_5 += s[5];   o_0_6 += s[6];   o_0_7 += s[7];
        o_0_8 += s[8];   o_0_9 += s[9];   o_0_10+= s[10];  o_0_11+= s[11];
        o_0_12+= s[12];  o_0_13+= s[13];  o_0_14+= s[14];  o_0_15+= s[15];

        ws0[0] = o_0_0;    ws0[1] = o_0_1;    ws0[2] = o_0_2;    ws0[3] = o_0_3;
        ws0[4] = o_0_4;    ws0[5] = o_0_5;    ws0[6] = o_0_6;    ws0[7] = o_0_7;
        ws0[8] = o_0_8;    ws0[9] = o_0_9;    ws0[10] = o_0_10;  ws0[11] = o_0_11;
        ws0[12] = o_0_12;  ws0[13] = o_0_13;  ws0[14] = o_0_14;  ws0[15] = o_0_15;
        memcpy(ks0, ws0, STATE_SIZE_B);
        
        for (uint64_t i = 0; i < remainder; i++) {
            ctxt[ct_idx0 + i]  = ptxt[ct_idx0 + i] ^ ks0[0];
        }
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


int chacha20_encrypt_openssl(uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds)
{
    // RFC 7539 IV layout for OpenSSL's ChaCha20: [ctr_le (4 B)] || [nonce (12 B)]
    uint8_t iv[16];
    iv[0] = (uint8_t)( ctr        & 0xff);
    iv[1] = (uint8_t)((ctr >>  8) & 0xff);
    iv[2] = (uint8_t)((ctr >> 16) & 0xff);
    iv[3] = (uint8_t)((ctr >> 24) & 0xff);
    memcpy(iv + 4, nonce, 12);

    EVP_CIPHER_CTX *ctxctx = EVP_CIPHER_CTX_new();
    if (!ctxctx) return -1;

    int outl = 0, finl = 0;
    if (EVP_EncryptInit_ex(ctxctx, EVP_chacha20(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctxctx, ctxt, &outl, ptxt, (int)len) != 1 ||
        EVP_EncryptFinal_ex(ctxctx, ctxt + outl, &finl) != 1)
    {
        EVP_CIPHER_CTX_free(ctxctx);
        return -1;
    }
    EVP_CIPHER_CTX_free(ctxctx);
    return 0;
}
