#include <openssl/evp.h>
#include "chacha_opts.h"


int chacha20_encrypt_baseline( 
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
){
    uint32_t initial_state_w[STATE_SIZE_W];
    uint8_t  keystream_buffer[STATE_SIZE_B];

    initialize_chacha_state(initial_state_w, key, nonce, ctr);

    uint64_t num_full_blocks = len / STATE_SIZE_B;
    uint64_t remainder       = len % STATE_SIZE_B;

    uint64_t idx_start = 0; 
    for (uint64_t b = 0; b < num_full_blocks; b++) {
        chacha_block_baseline(keystream_buffer, initial_state_w);

        for (int i = 0; i < STATE_SIZE_B; i++)
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];

        initial_state_w[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
    }

    if (remainder != 0) {
        chacha_block_baseline(keystream_buffer, initial_state_w);

        for (uint64_t i = 0; i < remainder; i++)
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];
    }
    return 0;
}

int chacha20_encrypt_strength_reduction( 
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
){
    uint32_t initial_state_w[STATE_SIZE_W];
    uint8_t  keystream_buffer[STATE_SIZE_B];

    initialize_chacha_state(initial_state_w, key, nonce, ctr);

    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;

    uint64_t idx_start = 0; 
    for (uint64_t b = 0; b < num_full_blocks; b++) {
        chacha_block_baseline(keystream_buffer, initial_state_w);

        uint64_t *ctxt_64 = (uint64_t *)(ctxt + idx_start);
        const uint64_t *ptxt_64 = (const uint64_t *)(ptxt + idx_start);
        const uint64_t *ks_64 = (const uint64_t *)keystream_buffer;
        for (uint64_t i = 0; i < 8; i++) {
            ctxt_64[i] = ptxt_64[i] ^ ks_64[i];
        }
        
        initial_state_w[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
    }

    if (remainder != 0) {
        chacha_block_baseline(keystream_buffer, initial_state_w);

       for (int i = 0; i < STATE_SIZE_B; i++)
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];

    }
    return 0;
}

int chacha20_encrypt_inline(
   uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
){
    uint32_t initial_state_w[STATE_SIZE_W];
    uint8_t  keystream_buffer[STATE_SIZE_B];
    
    initial_state_w[0] = 0x61707865;
    initial_state_w[1] = 0x3320646e;
    initial_state_w[2] = 0x79622d32;
    initial_state_w[3] = 0x6b206574;

    const uint32_t* key_32 = (const uint32_t*)key;
    initial_state_w[4] = key_32[0];
    initial_state_w[5] = key_32[1];
    initial_state_w[6] = key_32[2];
    initial_state_w[7] = key_32[3];
    initial_state_w[8] = key_32[4];
    initial_state_w[9] = key_32[5];
    initial_state_w[10] = key_32[6];
    initial_state_w[11] = key_32[7];
    initial_state_w[12] = ctr;

    const uint32_t* nonce_32 = (const uint32_t*)nonce;
    initial_state_w[13] = nonce_32[0];
    initial_state_w[14] = nonce_32[1];
    initial_state_w[15] = nonce_32[2];

    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;
        
    uint32_t working_state[STATE_SIZE_W];
    uint64_t idx_start = 0; 
    for (uint64_t b = 0; b < num_full_blocks; b++) {
        memcpy(working_state, initial_state_w, STATE_SIZE_B);     
    
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

            QUARTER_ROUND(out0, out4, out8, out12);
            QUARTER_ROUND(out1, out5, out9, out13);
            QUARTER_ROUND(out2, out6, out10, out14);
            QUARTER_ROUND(out3, out7, out11, out15);

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

        
        memcpy(keystream_buffer, working_state, STATE_SIZE_B);
        
        uint64_t *ctxt_64 = (uint64_t *)(ctxt + idx_start);
        const uint64_t *ptxt_64 = (const uint64_t *)(ptxt + idx_start);
        const uint64_t *ks_64 = (const uint64_t *)keystream_buffer;
        for (uint64_t i = 0; i < 8; i++) {
            ctxt_64[i] = ptxt_64[i] ^ ks_64[i];
        }
        
        initial_state_w[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
    }
        
    if (remainder != 0) {
        memcpy(working_state, initial_state_w, STATE_SIZE_B);     
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

            QUARTER_ROUND(out0, out4, out8, out12);
            QUARTER_ROUND(out1, out5, out9, out13);
            QUARTER_ROUND(out2, out6, out10, out14);
            QUARTER_ROUND(out3, out7, out11, out15);

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

        
        memcpy(keystream_buffer, working_state, STATE_SIZE_B);

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
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
){
    uint32_t state[STATE_SIZE_W];
    uint32_t ws[STATE_SIZE_W];
    uint8_t keystream_buffer[STATE_SIZE_B];

    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    const uint32_t* key_32 = (const uint32_t*)key;
    state[4] = key_32[0];
    state[5] = key_32[1];
    state[6] = key_32[2];
    state[7] = key_32[3];
    state[8] = key_32[4];
    state[9] = key_32[5];
    state[10] = key_32[6];
    state[11] = key_32[7];
    state[12] = ctr;

    const uint32_t* nonce_32 = (const uint32_t*)nonce;
    state[13] = nonce_32[0];
    state[14] = nonce_32[1];
    state[15] = nonce_32[2];
    
    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;
    uint64_t idx_start = 0; 


    uint64_t idx;
    uint32_t o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15;
    for (uint64_t b = 0; b < num_full_blocks; b++) {
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

        memcpy(keystream_buffer, ws, STATE_SIZE_B);
        
        uint64_t *ctxt_64 = (uint64_t *)(ctxt + idx_start);
        const uint64_t *ptxt_64 = (const uint64_t *)(ptxt + idx_start);
        const uint64_t *ks_64 = (const uint64_t *)keystream_buffer;
        for (uint64_t i = 0; i < 8; i++) {
            ctxt_64[i] = ptxt_64[i] ^ ks_64[i];
        }
        
        state[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
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

        memcpy(keystream_buffer, ws, STATE_SIZE_B);

        for (uint64_t i = 0; i < remainder; i++) {
            idx = idx_start + i;
            ctxt[idx] = ptxt[idx] ^ keystream_buffer[i];
        }
    }    
    return 0;
}

int chacha20_encrypt_unroll_ilp_ctxt(
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
){
    uint32_t state[STATE_SIZE_W];
    uint32_t ws[STATE_SIZE_W];
    uint8_t keystream_buffer[STATE_SIZE_B];
    
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    const uint32_t* key_32 = (const uint32_t*)key;
    state[4] = key_32[0];
    state[5] = key_32[1];
    state[6] = key_32[2];
    state[7] = key_32[3];
    state[8] = key_32[4];
    state[9] = key_32[5];
    state[10] = key_32[6];
    state[11] = key_32[7];
    state[12] = ctr;

    const uint32_t* nonce_32 = (const uint32_t*)nonce;
    state[13] = nonce_32[0];
    state[14] = nonce_32[1];
    state[15] = nonce_32[2];
    
    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;
    

    uint64_t idx_start = 0; 
    uint64_t idx;

    uint32_t o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15;
    for (uint64_t b = 0; b < num_full_blocks; b++) {
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
        
        memcpy(keystream_buffer, ws, STATE_SIZE_B);
        
        uint64_t *ctxt_64 = (uint64_t *)(ctxt + idx_start);
        const uint64_t *ptxt_64 = (const uint64_t *)(ptxt + idx_start);
        const uint64_t *ks_64 = (const uint64_t *)keystream_buffer;
        
        ctxt_64[0] = ptxt_64[0] ^ ks_64[0];
        ctxt_64[1] = ptxt_64[1] ^ ks_64[1];
        ctxt_64[2] = ptxt_64[2] ^ ks_64[2];
        ctxt_64[3] = ptxt_64[3] ^ ks_64[3];
        ctxt_64[4] = ptxt_64[4] ^ ks_64[4];
        ctxt_64[5] = ptxt_64[5] ^ ks_64[5];
        ctxt_64[6] = ptxt_64[6] ^ ks_64[6];
        ctxt_64[7] = ptxt_64[7] ^ ks_64[7];

        state[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
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

        memcpy(keystream_buffer, ws, STATE_SIZE_B);

        for (uint64_t i = 0; i < remainder; i++) {
            idx = idx_start + i;
            ctxt[idx]  = ptxt[idx] ^ keystream_buffer[i];
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
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
){
    uint32_t s[STATE_SIZE_W]; 

    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    const uint32_t* key_32 = (const uint32_t*)key;
    s[4] = key_32[0];
    s[5] = key_32[1];
    s[6] = key_32[2];
    s[7] = key_32[3];
    s[8] = key_32[4];
    s[9] = key_32[5];
    s[10] = key_32[6];
    s[11] = key_32[7];
    s[12] = ctr;

    const uint32_t* nonce_32 = (const uint32_t*)nonce;
    s[13] = nonce_32[0];
    s[14] = nonce_32[1];
    s[15] = nonce_32[2];
    
    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;

    uint32_t ws0[STATE_SIZE_W];
    uint32_t ws1[STATE_SIZE_W];
    uint32_t ws2[STATE_SIZE_W];
    uint32_t ws3[STATE_SIZE_W];

    uint8_t ks0[STATE_SIZE_B];
    uint8_t ks1[STATE_SIZE_B];
    uint8_t ks2[STATE_SIZE_B];
    uint8_t ks3[STATE_SIZE_B];

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
            QUARTER_ROUND(o_0_0, o_0_4, o_0_8, o_0_12); 
            QUARTER_ROUND(o_0_1, o_0_5, o_0_9, o_0_13); 
            QUARTER_ROUND(o_0_2, o_0_6, o_0_10, o_0_14); 
            QUARTER_ROUND(o_0_3, o_0_7, o_0_11, o_0_15); 
            QUARTER_ROUND(o_0_0, o_0_5, o_0_10, o_0_15); 
            QUARTER_ROUND(o_0_1, o_0_6, o_0_11, o_0_12); 
            QUARTER_ROUND(o_0_2, o_0_7, o_0_8, o_0_13); 
            QUARTER_ROUND(o_0_3, o_0_4, o_0_9, o_0_14); 

            QUARTER_ROUND(o_1_0, o_1_4, o_1_8, o_1_12); 
            QUARTER_ROUND(o_1_1, o_1_5, o_1_9, o_1_13); 
            QUARTER_ROUND(o_1_2, o_1_6, o_1_10, o_1_14); 
            QUARTER_ROUND(o_1_3, o_1_7, o_1_11, o_1_15); 
            QUARTER_ROUND(o_1_0, o_1_5, o_1_10, o_1_15); 
            QUARTER_ROUND(o_1_1, o_1_6, o_1_11, o_1_12); 
            QUARTER_ROUND(o_1_2, o_1_7, o_1_8, o_1_13); 
            QUARTER_ROUND(o_1_3, o_1_4, o_1_9, o_1_14); 

            QUARTER_ROUND(o_2_0, o_2_4, o_2_8, o_2_12); 
            QUARTER_ROUND(o_2_1, o_2_5, o_2_9, o_2_13); 
            QUARTER_ROUND(o_2_2, o_2_6, o_2_10, o_2_14); 
            QUARTER_ROUND(o_2_3, o_2_7, o_2_11, o_2_15); 
            QUARTER_ROUND(o_2_0, o_2_5, o_2_10, o_2_15); 
            QUARTER_ROUND(o_2_1, o_2_6, o_2_11, o_2_12); 
            QUARTER_ROUND(o_2_2, o_2_7, o_2_8, o_2_13); 
            QUARTER_ROUND(o_2_3, o_2_4, o_2_9, o_2_14); 

            QUARTER_ROUND(o_3_0, o_3_4, o_3_8, o_3_12); 
            QUARTER_ROUND(o_3_1, o_3_5, o_3_9, o_3_13); 
            QUARTER_ROUND(o_3_2, o_3_6, o_3_10, o_3_14); 
            QUARTER_ROUND(o_3_3, o_3_7, o_3_11, o_3_15); 
            QUARTER_ROUND(o_3_0, o_3_5, o_3_10, o_3_15); 
            QUARTER_ROUND(o_3_1, o_3_6, o_3_11, o_3_12); 
            QUARTER_ROUND(o_3_2, o_3_7, o_3_8, o_3_13); 
            QUARTER_ROUND(o_3_3, o_3_4, o_3_9, o_3_14); 
        }
        
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

        memcpy(ks0, ws0, STATE_SIZE_B);
        memcpy(ks1, ws1, STATE_SIZE_B);
        memcpy(ks2, ws2, STATE_SIZE_B);
        memcpy(ks3, ws3, STATE_SIZE_B);
        
        uint64_t *c0 = (uint64_t *)(ctxt + ct_idx0);
        const uint64_t *p0 = (const uint64_t *)(ptxt + ct_idx0);
        const uint64_t *k0 = (const uint64_t *)ks0;

        uint64_t *c1 = (uint64_t *)(ctxt + ct_idx1);
        const uint64_t *p1 = (const uint64_t *)(ptxt + ct_idx1);
        const uint64_t *k1 = (const uint64_t *)ks1;

        uint64_t *c2 = (uint64_t *)(ctxt + ct_idx2);
        const uint64_t *p2 = (const uint64_t *)(ptxt + ct_idx2);
        const uint64_t *k2 = (const uint64_t *)ks2;

        uint64_t *c3 = (uint64_t *)(ctxt + ct_idx3);
        const uint64_t *p3 = (const uint64_t *)(ptxt + ct_idx3);
        const uint64_t *k3 = (const uint64_t *)ks3;

        for (uint64_t i = 0; i < 8; i++) {
            c0[i] = p0[i] ^ k0[i];
            c1[i] = p1[i] ^ k1[i];
            c2[i] = p2[i] ^ k2[i];
            c3[i] = p3[i] ^ k3[i];
        }
        ctr0 += 4;
        ctr1 += 4;
        ctr2 += 4;
        ctr3 += 4;

        ct_idx0 += ct_idx_jump;  
        ct_idx1 += ct_idx_jump;  
        ct_idx2 += ct_idx_jump;  
        ct_idx3 += ct_idx_jump;  
    }
        
    if (remainder != 0) {
        o_0_0 = s[0];   o_0_1 = s[1];   o_0_2 = s[2];   o_0_3 = s[3];
        o_0_4 = s[4];   o_0_5 = s[5];   o_0_6 = s[6];   o_0_7 = s[7];
        o_0_8 = s[8];   o_0_9 = s[9];   o_0_10= s[10];  o_0_11= s[11];
        o_0_12= ctr0;  o_0_13= s[13];  o_0_14= s[14];  o_0_15= s[15];

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
        o_0_12+= ctr0;  o_0_13+= s[13];  o_0_14+= s[14];  o_0_15+= s[15];

        ws0[0] = o_0_0;    ws0[1] = o_0_1;    ws0[2] = o_0_2;    ws0[3] = o_0_3;
        ws0[4] = o_0_4;    ws0[5] = o_0_5;    ws0[6] = o_0_6;    ws0[7] = o_0_7;
        ws0[8] = o_0_8;    ws0[9] = o_0_9;    ws0[10] = o_0_10;  ws0[11] = o_0_11;
        ws0[12] = o_0_12;  ws0[13] = o_0_13;  ws0[14] = o_0_14;  ws0[15] = o_0_15;
        memcpy(ks0, ws0, STATE_SIZE_B);
        
        for (uint64_t i = 0; i < remainder; i++) {
           ctxt[ct_idx0 + i]  = ptxt[ct_idx0 + i] ^ ks0[i];
        }
    }

    return 0;
}

/*
* Optimizations:
* 1. Unroll by 8 and use multiple accumulators in working state, keystream, ciphertext_idx to process 8 plaintext blocks in every iteration
*/
int chacha20_encrypt_multiple_pt_blocks_at_once2( 
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
){
    uint32_t s[STATE_SIZE_W]; 
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;
    const uint32_t* key_32 = (const uint32_t*)key;
    s[4] = key_32[0];
    s[5] = key_32[1];
    s[6] = key_32[2];
    s[7] = key_32[3];
    s[8] = key_32[4];
    s[9] = key_32[5];
    s[10] = key_32[6];
    s[11] = key_32[7];
    s[12] = ctr;

    const uint32_t* nonce_32 = (const uint32_t*)nonce;
    s[13] = nonce_32[0];
    s[14] = nonce_32[1];
    s[15] = nonce_32[2];
    
    uint64_t num_full_blocks = len >> 6;
    uint64_t remainder       = len & 63;

    uint32_t ws0[STATE_SIZE_W];
    uint32_t ws1[STATE_SIZE_W];
    uint32_t ws2[STATE_SIZE_W];
    uint32_t ws3[STATE_SIZE_W];
    uint32_t ws4[STATE_SIZE_W];
    uint32_t ws5[STATE_SIZE_W];
    uint32_t ws6[STATE_SIZE_W];
    uint32_t ws7[STATE_SIZE_W];

    uint8_t ks0[STATE_SIZE_B];
    uint8_t ks1[STATE_SIZE_B];
    uint8_t ks2[STATE_SIZE_B];
    uint8_t ks3[STATE_SIZE_B];
    uint8_t ks4[STATE_SIZE_B];
    uint8_t ks5[STATE_SIZE_B];
    uint8_t ks6[STATE_SIZE_B];
    uint8_t ks7[STATE_SIZE_B];

    uint32_t ctr0 = ctr;
    uint32_t ctr1 = ctr+1;
    uint32_t ctr2 = ctr+2;
    uint32_t ctr3 = ctr+3;
    uint32_t ctr4 = ctr+4;
    uint32_t ctr5 = ctr+5;
    uint32_t ctr6 = ctr+6;
    uint32_t ctr7 = ctr+7;

    uint64_t ct_idx0 = 0; 
    uint64_t ct_idx1 = 64; 
    uint64_t ct_idx2 = 128; 
    uint64_t ct_idx3 = 192; 
    uint64_t ct_idx4 = 256; 
    uint64_t ct_idx5 = 320; 
    uint64_t ct_idx6 = 384; 
    uint64_t ct_idx7 = 448;

    uint64_t ct_idx_jump = 512;

    uint32_t o_0_0, o_0_1, o_0_2, o_0_3, o_0_4, o_0_5, o_0_6, o_0_7, o_0_8, o_0_9, o_0_10, o_0_11, o_0_12, o_0_13, o_0_14, o_0_15;
    uint32_t o_1_0, o_1_1, o_1_2, o_1_3, o_1_4, o_1_5, o_1_6, o_1_7, o_1_8, o_1_9, o_1_10, o_1_11, o_1_12, o_1_13, o_1_14, o_1_15;
    uint32_t o_2_0, o_2_1, o_2_2, o_2_3, o_2_4, o_2_5, o_2_6, o_2_7, o_2_8, o_2_9, o_2_10, o_2_11, o_2_12, o_2_13, o_2_14, o_2_15;
    uint32_t o_3_0, o_3_1, o_3_2, o_3_3, o_3_4, o_3_5, o_3_6, o_3_7, o_3_8, o_3_9, o_3_10, o_3_11, o_3_12, o_3_13, o_3_14, o_3_15;
    uint32_t o_4_0, o_4_1, o_4_2, o_4_3, o_4_4, o_4_5, o_4_6, o_4_7, o_4_8, o_4_9, o_4_10, o_4_11, o_4_12, o_4_13, o_4_14, o_4_15;
    uint32_t o_5_0, o_5_1, o_5_2, o_5_3, o_5_4, o_5_5, o_5_6, o_5_7, o_5_8, o_5_9, o_5_10, o_5_11, o_5_12, o_5_13, o_5_14, o_5_15;
    uint32_t o_6_0, o_6_1, o_6_2, o_6_3, o_6_4, o_6_5, o_6_6, o_6_7, o_6_8, o_6_9, o_6_10, o_6_11, o_6_12, o_6_13, o_6_14, o_6_15;
    uint32_t o_7_0, o_7_1, o_7_2, o_7_3, o_7_4, o_7_5, o_7_6, o_7_7, o_7_8, o_7_9, o_7_10, o_7_11, o_7_12, o_7_13, o_7_14, o_7_15;
    for (uint64_t b = 0; b < num_full_blocks; b+=8) {
        o_0_0 = s[0]; o_1_0 = s[0]; o_2_0 = s[0]; o_3_0 = s[0]; o_4_0 = s[0]; o_5_0 = s[0]; o_6_0 = s[0]; o_7_0 = s[0]; 
        o_0_1 = s[1]; o_1_1 = s[1]; o_2_1 = s[1]; o_3_1 = s[1]; o_4_1 = s[1]; o_5_1 = s[1]; o_6_1 = s[1]; o_7_1 = s[1]; 
        o_0_2 = s[2]; o_1_2 = s[2]; o_2_2 = s[2]; o_3_2 = s[2]; o_4_2 = s[2]; o_5_2 = s[2]; o_6_2 = s[2]; o_7_2 = s[2]; 
        o_0_3 = s[3]; o_1_3 = s[3]; o_2_3 = s[3]; o_3_3 = s[3]; o_4_3 = s[3]; o_5_3 = s[3]; o_6_3 = s[3]; o_7_3 = s[3]; 

        o_0_4 = s[4]; o_1_4 = s[4]; o_2_4 = s[4]; o_3_4 = s[4]; o_4_4 = s[4]; o_5_4 = s[4]; o_6_4 = s[4]; o_7_4 = s[4]; 
        o_0_5 = s[5]; o_1_5 = s[5]; o_2_5 = s[5]; o_3_5 = s[5]; o_4_5 = s[5]; o_5_5 = s[5]; o_6_5 = s[5]; o_7_5 = s[5]; 
        o_0_6 = s[6]; o_1_6 = s[6]; o_2_6 = s[6]; o_3_6 = s[6]; o_4_6 = s[6]; o_5_6 = s[6]; o_6_6 = s[6]; o_7_6 = s[6]; 
        o_0_7 = s[7]; o_1_7 = s[7]; o_2_7 = s[7]; o_3_7 = s[7]; o_4_7 = s[7]; o_5_7 = s[7]; o_6_7 = s[7]; o_7_7 = s[7]; 
        o_0_8 = s[8]; o_1_8 = s[8]; o_2_8 = s[8]; o_3_8 = s[8]; o_4_8 = s[8]; o_5_8 = s[8]; o_6_8 = s[8]; o_7_8 = s[8]; 
        o_0_9 = s[9]; o_1_9 = s[9]; o_2_9 = s[9]; o_3_9 = s[9]; o_4_9 = s[9]; o_5_9 = s[9]; o_6_9 = s[9]; o_7_9 = s[9]; 
        o_0_10 = s[10]; o_1_10 = s[10]; o_2_10 = s[10]; o_3_10 = s[10]; o_4_10 = s[10]; o_5_10 = s[10]; o_6_10 = s[10]; o_7_10 = s[10]; 
        o_0_11 = s[11]; o_1_11 = s[11]; o_2_11 = s[11]; o_3_11 = s[11]; o_4_11 = s[11]; o_5_11 = s[11]; o_6_11 = s[11]; o_7_11 = s[11]; 

        o_0_12 = ctr0; o_1_12 = ctr1; o_2_12 = ctr2; o_3_12 = ctr3; o_4_12 = ctr4; o_5_12 = ctr5; o_6_12 = ctr6; o_7_12 = ctr7; 

        o_0_13 = s[13]; o_1_13 = s[13]; o_2_13 = s[13]; o_3_13 = s[13]; o_4_13 = s[13]; o_5_13 = s[13]; o_6_13 = s[13]; o_7_13 = s[13]; 
        o_0_14 = s[14]; o_1_14 = s[14]; o_2_14 = s[14]; o_3_14 = s[14]; o_4_14 = s[14]; o_5_14 = s[14]; o_6_14 = s[14]; o_7_14 = s[14]; 
        o_0_15 = s[15]; o_1_15 = s[15]; o_2_15 = s[15]; o_3_15 = s[15]; o_4_15 = s[15]; o_5_15 = s[15]; o_6_15 = s[15]; o_7_15 = s[15]; 

        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            QUARTER_ROUND(o_0_0, o_0_4, o_0_8, o_0_12); 
            QUARTER_ROUND(o_0_1, o_0_5, o_0_9, o_0_13); 
            QUARTER_ROUND(o_0_2, o_0_6, o_0_10, o_0_14); 
            QUARTER_ROUND(o_0_3, o_0_7, o_0_11, o_0_15); 
            QUARTER_ROUND(o_0_0, o_0_5, o_0_10, o_0_15); 
            QUARTER_ROUND(o_0_1, o_0_6, o_0_11, o_0_12); 
            QUARTER_ROUND(o_0_2, o_0_7, o_0_8, o_0_13); 
            QUARTER_ROUND(o_0_3, o_0_4, o_0_9, o_0_14); 

            QUARTER_ROUND(o_1_0, o_1_4, o_1_8, o_1_12); 
            QUARTER_ROUND(o_1_1, o_1_5, o_1_9, o_1_13); 
            QUARTER_ROUND(o_1_2, o_1_6, o_1_10, o_1_14); 
            QUARTER_ROUND(o_1_3, o_1_7, o_1_11, o_1_15); 
            QUARTER_ROUND(o_1_0, o_1_5, o_1_10, o_1_15); 
            QUARTER_ROUND(o_1_1, o_1_6, o_1_11, o_1_12); 
            QUARTER_ROUND(o_1_2, o_1_7, o_1_8, o_1_13); 
            QUARTER_ROUND(o_1_3, o_1_4, o_1_9, o_1_14); 

            QUARTER_ROUND(o_2_0, o_2_4, o_2_8, o_2_12); 
            QUARTER_ROUND(o_2_1, o_2_5, o_2_9, o_2_13); 
            QUARTER_ROUND(o_2_2, o_2_6, o_2_10, o_2_14); 
            QUARTER_ROUND(o_2_3, o_2_7, o_2_11, o_2_15); 
            QUARTER_ROUND(o_2_0, o_2_5, o_2_10, o_2_15); 
            QUARTER_ROUND(o_2_1, o_2_6, o_2_11, o_2_12); 
            QUARTER_ROUND(o_2_2, o_2_7, o_2_8, o_2_13); 
            QUARTER_ROUND(o_2_3, o_2_4, o_2_9, o_2_14); 

            QUARTER_ROUND(o_3_0, o_3_4, o_3_8, o_3_12); 
            QUARTER_ROUND(o_3_1, o_3_5, o_3_9, o_3_13); 
            QUARTER_ROUND(o_3_2, o_3_6, o_3_10, o_3_14); 
            QUARTER_ROUND(o_3_3, o_3_7, o_3_11, o_3_15); 
            QUARTER_ROUND(o_3_0, o_3_5, o_3_10, o_3_15); 
            QUARTER_ROUND(o_3_1, o_3_6, o_3_11, o_3_12); 
            QUARTER_ROUND(o_3_2, o_3_7, o_3_8, o_3_13); 
            QUARTER_ROUND(o_3_3, o_3_4, o_3_9, o_3_14); 

            QUARTER_ROUND(o_4_0, o_4_4, o_4_8, o_4_12); 
            QUARTER_ROUND(o_4_1, o_4_5, o_4_9, o_4_13); 
            QUARTER_ROUND(o_4_2, o_4_6, o_4_10, o_4_14); 
            QUARTER_ROUND(o_4_3, o_4_7, o_4_11, o_4_15); 
            QUARTER_ROUND(o_4_0, o_4_5, o_4_10, o_4_15); 
            QUARTER_ROUND(o_4_1, o_4_6, o_4_11, o_4_12); 
            QUARTER_ROUND(o_4_2, o_4_7, o_4_8, o_4_13); 
            QUARTER_ROUND(o_4_3, o_4_4, o_4_9, o_4_14); 

            QUARTER_ROUND(o_5_0, o_5_4, o_5_8, o_5_12); 
            QUARTER_ROUND(o_5_1, o_5_5, o_5_9, o_5_13); 
            QUARTER_ROUND(o_5_2, o_5_6, o_5_10, o_5_14); 
            QUARTER_ROUND(o_5_3, o_5_7, o_5_11, o_5_15); 
            QUARTER_ROUND(o_5_0, o_5_5, o_5_10, o_5_15); 
            QUARTER_ROUND(o_5_1, o_5_6, o_5_11, o_5_12); 
            QUARTER_ROUND(o_5_2, o_5_7, o_5_8, o_5_13); 
            QUARTER_ROUND(o_5_3, o_5_4, o_5_9, o_5_14); 

            QUARTER_ROUND(o_6_0, o_6_4, o_6_8, o_6_12); 
            QUARTER_ROUND(o_6_1, o_6_5, o_6_9, o_6_13); 
            QUARTER_ROUND(o_6_2, o_6_6, o_6_10, o_6_14); 
            QUARTER_ROUND(o_6_3, o_6_7, o_6_11, o_6_15); 
            QUARTER_ROUND(o_6_0, o_6_5, o_6_10, o_6_15); 
            QUARTER_ROUND(o_6_1, o_6_6, o_6_11, o_6_12); 
            QUARTER_ROUND(o_6_2, o_6_7, o_6_8, o_6_13); 
            QUARTER_ROUND(o_6_3, o_6_4, o_6_9, o_6_14); 

            QUARTER_ROUND(o_7_0, o_7_4, o_7_8, o_7_12); 
            QUARTER_ROUND(o_7_1, o_7_5, o_7_9, o_7_13); 
            QUARTER_ROUND(o_7_2, o_7_6, o_7_10, o_7_14); 
            QUARTER_ROUND(o_7_3, o_7_7, o_7_11, o_7_15); 
            QUARTER_ROUND(o_7_0, o_7_5, o_7_10, o_7_15); 
            QUARTER_ROUND(o_7_1, o_7_6, o_7_11, o_7_12); 
            QUARTER_ROUND(o_7_2, o_7_7, o_7_8, o_7_13); 
            QUARTER_ROUND(o_7_3, o_7_4, o_7_9, o_7_14);
        }

        
        o_0_0 += s[0]; o_1_0 += s[0]; o_2_0 += s[0]; o_3_0 += s[0]; o_4_0 += s[0]; o_5_0 += s[0]; o_6_0 += s[0]; o_7_0 += s[0]; 
        o_0_1 += s[1]; o_1_1 += s[1]; o_2_1 += s[1]; o_3_1 += s[1]; o_4_1 += s[1]; o_5_1 += s[1]; o_6_1 += s[1]; o_7_1 += s[1]; 
        o_0_2 += s[2]; o_1_2 += s[2]; o_2_2 += s[2]; o_3_2 += s[2]; o_4_2 += s[2]; o_5_2 += s[2]; o_6_2 += s[2]; o_7_2 += s[2]; 
        o_0_3 += s[3]; o_1_3 += s[3]; o_2_3 += s[3]; o_3_3 += s[3]; o_4_3 += s[3]; o_5_3 += s[3]; o_6_3 += s[3]; o_7_3 += s[3]; 
        o_0_4 += s[4]; o_1_4 += s[4]; o_2_4 += s[4]; o_3_4 += s[4]; o_4_4 += s[4]; o_5_4 += s[4]; o_6_4 += s[4]; o_7_4 += s[4]; 
        o_0_5 += s[5]; o_1_5 += s[5]; o_2_5 += s[5]; o_3_5 += s[5]; o_4_5 += s[5]; o_5_5 += s[5]; o_6_5 += s[5]; o_7_5 += s[5]; 
        o_0_6 += s[6]; o_1_6 += s[6]; o_2_6 += s[6]; o_3_6 += s[6]; o_4_6 += s[6]; o_5_6 += s[6]; o_6_6 += s[6]; o_7_6 += s[6]; 
        o_0_7 += s[7]; o_1_7 += s[7]; o_2_7 += s[7]; o_3_7 += s[7]; o_4_7 += s[7]; o_5_7 += s[7]; o_6_7 += s[7]; o_7_7 += s[7]; 
        o_0_8 += s[8]; o_1_8 += s[8]; o_2_8 += s[8]; o_3_8 += s[8]; o_4_8 += s[8]; o_5_8 += s[8]; o_6_8 += s[8]; o_7_8 += s[8]; 
        o_0_9 += s[9]; o_1_9 += s[9]; o_2_9 += s[9]; o_3_9 += s[9]; o_4_9 += s[9]; o_5_9 += s[9]; o_6_9 += s[9]; o_7_9 += s[9]; 
        o_0_10 += s[10]; o_1_10 += s[10]; o_2_10 += s[10]; o_3_10 += s[10]; o_4_10 += s[10]; o_5_10 += s[10]; o_6_10 += s[10]; o_7_10 += s[10]; 
        o_0_11 += s[11]; o_1_11 += s[11]; o_2_11 += s[11]; o_3_11 += s[11]; o_4_11 += s[11]; o_5_11 += s[11]; o_6_11 += s[11]; o_7_11 += s[11]; 
        o_0_12 += ctr0; o_1_12 += ctr1; o_2_12 += ctr2; o_3_12 += ctr3; o_4_12 += ctr4; o_5_12 += ctr5; o_6_12 += ctr6; o_7_12 += ctr7;
        o_0_13 += s[13]; o_1_13 += s[13]; o_2_13 += s[13]; o_3_13 += s[13]; o_4_13 += s[13]; o_5_13 += s[13]; o_6_13 += s[13]; o_7_13 += s[13]; 
        o_0_14 += s[14]; o_1_14 += s[14]; o_2_14 += s[14]; o_3_14 += s[14]; o_4_14 += s[14]; o_5_14 += s[14]; o_6_14 += s[14]; o_7_14 += s[14]; 
        o_0_15 += s[15]; o_1_15 += s[15]; o_2_15 += s[15]; o_3_15 += s[15]; o_4_15 += s[15]; o_5_15 += s[15]; o_6_15 += s[15]; o_7_15 += s[15]; 

        ws0[0] = o_0_0; ws1[0] = o_1_0; ws2[0] = o_2_0; ws3[0] = o_3_0; ws4[0] = o_4_0; ws5[0] = o_5_0; ws6[0] = o_6_0; ws7[0] = o_7_0; 
        ws0[1] = o_0_1; ws1[1] = o_1_1; ws2[1] = o_2_1; ws3[1] = o_3_1; ws4[1] = o_4_1; ws5[1] = o_5_1; ws6[1] = o_6_1; ws7[1] = o_7_1; 
        ws0[2] = o_0_2; ws1[2] = o_1_2; ws2[2] = o_2_2; ws3[2] = o_3_2; ws4[2] = o_4_2; ws5[2] = o_5_2; ws6[2] = o_6_2; ws7[2] = o_7_2; 
        ws0[3] = o_0_3; ws1[3] = o_1_3; ws2[3] = o_2_3; ws3[3] = o_3_3; ws4[3] = o_4_3; ws5[3] = o_5_3; ws6[3] = o_6_3; ws7[3] = o_7_3; 
        ws0[4] = o_0_4; ws1[4] = o_1_4; ws2[4] = o_2_4; ws3[4] = o_3_4; ws4[4] = o_4_4; ws5[4] = o_5_4; ws6[4] = o_6_4; ws7[4] = o_7_4; 
        ws0[5] = o_0_5; ws1[5] = o_1_5; ws2[5] = o_2_5; ws3[5] = o_3_5; ws4[5] = o_4_5; ws5[5] = o_5_5; ws6[5] = o_6_5; ws7[5] = o_7_5; 
        ws0[6] = o_0_6; ws1[6] = o_1_6; ws2[6] = o_2_6; ws3[6] = o_3_6; ws4[6] = o_4_6; ws5[6] = o_5_6; ws6[6] = o_6_6; ws7[6] = o_7_6; 
        ws0[7] = o_0_7; ws1[7] = o_1_7; ws2[7] = o_2_7; ws3[7] = o_3_7; ws4[7] = o_4_7; ws5[7] = o_5_7; ws6[7] = o_6_7; ws7[7] = o_7_7; 
        ws0[8] = o_0_8; ws1[8] = o_1_8; ws2[8] = o_2_8; ws3[8] = o_3_8; ws4[8] = o_4_8; ws5[8] = o_5_8; ws6[8] = o_6_8; ws7[8] = o_7_8; 
        ws0[9] = o_0_9; ws1[9] = o_1_9; ws2[9] = o_2_9; ws3[9] = o_3_9; ws4[9] = o_4_9; ws5[9] = o_5_9; ws6[9] = o_6_9; ws7[9] = o_7_9; 
        ws0[10] = o_0_10; ws1[10] = o_1_10; ws2[10] = o_2_10; ws3[10] = o_3_10; ws4[10] = o_4_10; ws5[10] = o_5_10; ws6[10] = o_6_10; ws7[10] = o_7_10; 
        ws0[11] = o_0_11; ws1[11] = o_1_11; ws2[11] = o_2_11; ws3[11] = o_3_11; ws4[11] = o_4_11; ws5[11] = o_5_11; ws6[11] = o_6_11; ws7[11] = o_7_11; 
        ws0[12] = o_0_12; ws1[12] = o_1_12; ws2[12] = o_2_12; ws3[12] = o_3_12; ws4[12] = o_4_12; ws5[12] = o_5_12; ws6[12] = o_6_12; ws7[12] = o_7_12; 
        ws0[13] = o_0_13; ws1[13] = o_1_13; ws2[13] = o_2_13; ws3[13] = o_3_13; ws4[13] = o_4_13; ws5[13] = o_5_13; ws6[13] = o_6_13; ws7[13] = o_7_13; 
        ws0[14] = o_0_14; ws1[14] = o_1_14; ws2[14] = o_2_14; ws3[14] = o_3_14; ws4[14] = o_4_14; ws5[14] = o_5_14; ws6[14] = o_6_14; ws7[14] = o_7_14; 
        ws0[15] = o_0_15; ws1[15] = o_1_15; ws2[15] = o_2_15; ws3[15] = o_3_15; ws4[15] = o_4_15; ws5[15] = o_5_15; ws6[15] = o_6_15; ws7[15] = o_7_15;

        memcpy(ks0, ws0, STATE_SIZE_B);
        memcpy(ks1, ws1, STATE_SIZE_B);
        memcpy(ks2, ws2, STATE_SIZE_B);
        memcpy(ks3, ws3, STATE_SIZE_B);
        memcpy(ks4, ws4, STATE_SIZE_B);
        memcpy(ks5, ws5, STATE_SIZE_B);
        memcpy(ks6, ws6, STATE_SIZE_B);
        memcpy(ks7, ws7, STATE_SIZE_B);

        uint64_t *c0 = (uint64_t *)(ctxt + ct_idx0);
        const uint64_t *p0 = (const uint64_t *)(ptxt + ct_idx0);
        const uint64_t *k0 = (const uint64_t *)ks0;

        uint64_t *c1 = (uint64_t *)(ctxt + ct_idx1);
        const uint64_t *p1 = (const uint64_t *)(ptxt + ct_idx1);
        const uint64_t *k1 = (const uint64_t *)ks1;

        uint64_t *c2 = (uint64_t *)(ctxt + ct_idx2);
        const uint64_t *p2 = (const uint64_t *)(ptxt + ct_idx2);
        const uint64_t *k2 = (const uint64_t *)ks2;

        uint64_t *c3 = (uint64_t *)(ctxt + ct_idx3);
        const uint64_t *p3 = (const uint64_t *)(ptxt + ct_idx3);
        const uint64_t *k3 = (const uint64_t *)ks3;

        uint64_t *c4 = (uint64_t *)(ctxt + ct_idx4);
        const uint64_t *p4 = (const uint64_t *)(ptxt + ct_idx4);
        const uint64_t *k4 = (const uint64_t *)ks4;

        uint64_t *c5 = (uint64_t *)(ctxt + ct_idx5);
        const uint64_t *p5 = (const uint64_t *)(ptxt + ct_idx5);
        const uint64_t *k5 = (const uint64_t *)ks5;

        uint64_t *c6 = (uint64_t *)(ctxt + ct_idx6);
        const uint64_t *p6 = (const uint64_t *)(ptxt + ct_idx6);
        const uint64_t *k6 = (const uint64_t *)ks6;

        uint64_t *c7 = (uint64_t *)(ctxt + ct_idx7);
        const uint64_t *p7 = (const uint64_t *)(ptxt + ct_idx7);
        const uint64_t *k7 = (const uint64_t *)ks7;

        
        for (uint64_t i = 0; i < 8; i++) {
            c0[i] = p0[i] ^ k0[i];
            c1[i] = p1[i] ^ k1[i];
            c2[i] = p2[i] ^ k2[i];
            c3[i] = p3[i] ^ k3[i];
            c4[i] = p4[i] ^ k4[i];
            c5[i] = p5[i] ^ k5[i];
            c6[i] = p6[i] ^ k6[i];
            c7[i] = p7[i] ^ k7[i];
        }
         
        ctr0 += 8;
        ctr1 += 8;
        ctr2 += 8;
        ctr3 += 8;
        ctr4 += 8;
        ctr5 += 8;
        ctr6 += 8;
        ctr7 += 8;

        ct_idx0 += ct_idx_jump; 
        ct_idx1 += ct_idx_jump; 
        ct_idx2 += ct_idx_jump; 
        ct_idx3 += ct_idx_jump; 
        ct_idx4 += ct_idx_jump; 
        ct_idx5 += ct_idx_jump; 
        ct_idx6 += ct_idx_jump; 
        ct_idx7 += ct_idx_jump; 
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
            ctxt[ct_idx0 + i]  = ptxt[ct_idx0 + i] ^ ks0[i];
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
    uint32_t       block_ctr
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

    initial_state_w_0[0] = 0x61707865;
    initial_state_w_0[1] = 0x3320646e;
    initial_state_w_0[2] = 0x79622d32;
    initial_state_w_0[3] = 0x6b206574;
    
    const uint32_t* key_32 = (const uint32_t*)key_b;
    initial_state_w_0[4] = key_32[0];
    initial_state_w_0[5] = key_32[1];
    initial_state_w_0[6] = key_32[2];
    initial_state_w_0[7] = key_32[3];
    initial_state_w_0[8] = key_32[4];
    initial_state_w_0[9] = key_32[5];
    initial_state_w_0[10] = key_32[6];
    initial_state_w_0[11] = key_32[7];
    
    const uint32_t* nonce_32 = (const uint32_t*)nonce_b;
    initial_state_w_0[12] = block_ctr;
    initial_state_w_0[13] = nonce_32[0];
    initial_state_w_0[14] = nonce_32[1];
    initial_state_w_0[15] = nonce_32[2];

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
    

    uint32_t working_state_0[STATE_SIZE_W];
    uint32_t working_state_1[STATE_SIZE_W];
    uint32_t working_state_2[STATE_SIZE_W];
    uint32_t working_state_3[STATE_SIZE_W];
    uint32_t working_state_4[STATE_SIZE_W];
    uint32_t working_state_5[STATE_SIZE_W];
    uint32_t working_state_6[STATE_SIZE_W];
    uint32_t working_state_7[STATE_SIZE_W];

    uint64_t idx_start = 0; 
    uint64_t tmp;
    for (uint64_t b = 0; b < num_octa_blocks; b++) {
        memcpy(working_state_0, initial_state_w_0, STATE_SIZE_B);     
        memcpy(working_state_1, initial_state_w_1, STATE_SIZE_B);    
        memcpy(working_state_2, initial_state_w_2, STATE_SIZE_B);    
        memcpy(working_state_3, initial_state_w_3, STATE_SIZE_B);    
        memcpy(working_state_4, initial_state_w_4, STATE_SIZE_B);    
        memcpy(working_state_5, initial_state_w_5, STATE_SIZE_B);    
        memcpy(working_state_6, initial_state_w_6, STATE_SIZE_B);    
        memcpy(working_state_7, initial_state_w_7, STATE_SIZE_B);    
        

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
        
        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            QUARTER_ROUND_256(v0, v4, v8,  v12);
            QUARTER_ROUND_256(v1, v5, v9,  v13);
            QUARTER_ROUND_256(v2, v6, v10, v14);
            QUARTER_ROUND_256(v3, v7, v11, v15);

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
        
        memcpy(keystream_buffer_0, working_state_0, STATE_SIZE_B);
        memcpy(keystream_buffer_1, working_state_1, STATE_SIZE_B);
        memcpy(keystream_buffer_2, working_state_2, STATE_SIZE_B);
        memcpy(keystream_buffer_3, working_state_3, STATE_SIZE_B);
        memcpy(keystream_buffer_4, working_state_4, STATE_SIZE_B);
        memcpy(keystream_buffer_5, working_state_5, STATE_SIZE_B);
        memcpy(keystream_buffer_6, working_state_6, STATE_SIZE_B);
        memcpy(keystream_buffer_7, working_state_7, STATE_SIZE_B);
        

        for (int i = 0; i < STATE_SIZE_B; i++){
            tmp = idx_start + i;
            ciphertext_buffer[tmp] = plaintext_b[tmp] ^ keystream_buffer_0[i];
            ciphertext_buffer[tmp + 1*STATE_SIZE_B] = plaintext_b[tmp + 1*STATE_SIZE_B] ^ keystream_buffer_1[i];
            ciphertext_buffer[tmp + 2*STATE_SIZE_B] = plaintext_b[tmp + 2*STATE_SIZE_B] ^ keystream_buffer_2[i];
            ciphertext_buffer[tmp + 3*STATE_SIZE_B] = plaintext_b[tmp + 3*STATE_SIZE_B] ^ keystream_buffer_3[i];
            ciphertext_buffer[tmp + 4*STATE_SIZE_B] = plaintext_b[tmp + 4*STATE_SIZE_B] ^ keystream_buffer_4[i];
            ciphertext_buffer[tmp + 5*STATE_SIZE_B] = plaintext_b[tmp + 5*STATE_SIZE_B] ^ keystream_buffer_5[i];
            ciphertext_buffer[tmp + 6*STATE_SIZE_B] = plaintext_b[tmp + 6*STATE_SIZE_B] ^ keystream_buffer_6[i];
            ciphertext_buffer[tmp + 7*STATE_SIZE_B] = plaintext_b[tmp + 7*STATE_SIZE_B] ^ keystream_buffer_7[i];
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
    }

    for (uint64_t b = 0; b < leftover_full; b++) {
        memcpy(working_state_0, initial_state_w_0, STATE_SIZE_B);     
        
        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
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

            QUARTER_ROUND(out0, out4, out8, out12);
            QUARTER_ROUND(out1, out5, out9, out13);
            QUARTER_ROUND(out2, out6, out10, out14);
            QUARTER_ROUND(out3, out7, out11, out15);

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

        
        memcpy(keystream_buffer_0, working_state_0, STATE_SIZE_B);

        for (int i = 0; i < STATE_SIZE_B; i++){
            idx_start = idx_start + i;
            ciphertext_buffer[idx_start] = plaintext_b[idx_start] ^ keystream_buffer_0[i];
        }
        
        initial_state_w_0[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
    }

    if (remainder != 0) {
        memcpy(working_state_0, initial_state_w_0, STATE_SIZE_B);     
        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
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

            QUARTER_ROUND(out0, out4, out8, out12);
            QUARTER_ROUND(out1, out5, out9, out13);
            QUARTER_ROUND(out2, out6, out10, out14);
            QUARTER_ROUND(out3, out7, out11, out15);

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


        memcpy(keystream_buffer_0, working_state_0, STATE_SIZE_B);

        for (uint64_t i = 0; i < remainder; i++){
            ciphertext_buffer[idx_start + i] = plaintext_b[idx_start + i] ^ keystream_buffer_0[i];
        }
    }

    return 0;
}

int chacha20_encrypt_vectorized2( 
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
) {
    uint64_t blocks_8 = len >> 9;   // len / 512
    uint64_t remainder = len & 511; // len % 512;
    
    __m256i state0  = _mm256_set1_epi32(STATE_0);
    __m256i state1  = _mm256_set1_epi32(STATE_1);
    __m256i state2  = _mm256_set1_epi32(STATE_2);
    __m256i state3  = _mm256_set1_epi32(STATE_3);

    const uint32_t* key_32 = (const uint32_t*)key;
    __m256i state4  = _mm256_set1_epi32(key_32[0]);
    __m256i state5  = _mm256_set1_epi32(key_32[1]);
    __m256i state6  = _mm256_set1_epi32(key_32[2]);
    __m256i state7  = _mm256_set1_epi32(key_32[3]);
    __m256i state8  = _mm256_set1_epi32(key_32[4]);
    __m256i state9  = _mm256_set1_epi32(key_32[5]);
    __m256i state10 = _mm256_set1_epi32(key_32[6]);
    __m256i state11 = _mm256_set1_epi32(key_32[7]);

    __m256i ctrs = _mm256_set1_epi32(ctr);
    __m256i ctrs_offset = _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0);
    __m256i ctr_progression = _mm256_set1_epi32(8);

    __m256i state12 = _mm256_add_epi32(ctrs, ctrs_offset);

    const uint32_t* nonce_32 = (const uint32_t*)nonce;
    __m256i state13 = _mm256_set1_epi32(nonce_32[0]);
    __m256i state14 = _mm256_set1_epi32(nonce_32[1]);
    __m256i state15 = _mm256_set1_epi32(nonce_32[2]);

    uint64_t ct_idx = 0;

    __m256i w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;
    for (uint64_t b = 0; b < blocks_8; b++) {
        w0 = state0;   w1 = state1;   w2 = state2;   w3 = state3;
        w4 = state4;   w5 = state5;   w6 = state6;   w7 = state7;
        w8 = state8;   w9 = state9;   w10 = state10; w11 = state11;
        w12 = state12; w13 = state13; w14 = state14; w15 = state15;
        
        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            QUARTER_ROUND_256(w0, w4, w8,  w12);
            QUARTER_ROUND_256(w1, w5, w9,  w13);
            QUARTER_ROUND_256(w2, w6, w10, w14);
            QUARTER_ROUND_256(w3, w7, w11, w15);

            QUARTER_ROUND_256(w0, w5, w10, w15);
            QUARTER_ROUND_256(w1, w6, w11, w12);
            QUARTER_ROUND_256(w2, w7, w8,  w13);
            QUARTER_ROUND_256(w3, w4, w9,  w14);            
        }

        // If we assume LSB is on the far right, the j-th column (counting from right to left, from LSB to MSB),
        // of w0, w1, ..., w15 stacked on top of each other, will contain the final state corresponding to the
        // j-th plaintext block we are currently processing. To be able to use the vectorization to xor the 
        // serialized final state with the plaintext, we would like to have the final state in 2 vectors ()
        // Why 2 instead of 1? Because the final state is 512 bits long and we don't have avx512, so we would need 2
        // vectors to store the state. So, if we could achieve to have the column j of the stacked vectors w0, ... ,w15,
        // e.g. ks_j_l, ks_j_h (pictorially: keysteram_j_high | keystream_j_low with keystream_j_{} being a vector),
        // we could do (assuming a block of plaintext of 512 bits is split in 2 vectors plaintext_j_high|plaintext_j_low):
        //  ciphertext_j_low  = xor(plaintext_j_low, keystream_j_low)
        //  ciphertext_j_high = xor(plaintext_j_high, keystream_j_high)

        /////////////////////////////////////////////////
        // Lower state vectors and ciphertext computation
        /////////////////////////////////////////////////
        w0 = _mm256_add_epi32(w0, state0);
        w1 = _mm256_add_epi32(w1, state1);
        w2 = _mm256_add_epi32(w2, state2);
        w3 = _mm256_add_epi32(w3, state3);
        w4 = _mm256_add_epi32(w4, state4);
        w5 = _mm256_add_epi32(w5, state5);
        w6 = _mm256_add_epi32(w6, state6);
        w7 = _mm256_add_epi32(w7, state7);

        __m256i l0 = _mm256_unpacklo_epi32(w0, w1);
        __m256i l1 = _mm256_unpacklo_epi32(w2, w3);
        __m256i l2 = _mm256_unpacklo_epi32(w4, w5);
        __m256i l3 = _mm256_unpacklo_epi32(w6, w7);

        __m256i h0 = _mm256_unpackhi_epi32(w0, w1);
        __m256i h1 = _mm256_unpackhi_epi32(w2, w3);
        __m256i h2 = _mm256_unpackhi_epi32(w4, w5);
        __m256i h3 = _mm256_unpackhi_epi32(w6, w7);


        __m256i l_l01 = _mm256_unpacklo_epi64(l0, l1);
        __m256i l_l23 = _mm256_unpacklo_epi64(l2, l3);
        
        __m256i h_l01 = _mm256_unpackhi_epi64(l0, l1);
        __m256i h_l23 = _mm256_unpackhi_epi64(l2, l3);

        __m256i l_h01 = _mm256_unpacklo_epi64(h0, h1);
        __m256i l_h23 = _mm256_unpacklo_epi64(h2, h3);

        __m256i h_h01 = _mm256_unpackhi_epi64(h0, h1);
        __m256i h_h23 = _mm256_unpackhi_epi64(h2, h3);

        
        __m256i ks0_l = _mm256_permute2x128_si256(l_l01, l_l23, 0b00100000);
        __m256i ks4_l = _mm256_permute2x128_si256(l_l01, l_l23, 0b00110001);
        
        __m256i ks1_l = _mm256_permute2x128_si256(h_l01, h_l23, 0b00100000);
        __m256i ks5_l = _mm256_permute2x128_si256(h_l01, h_l23, 0b00110001);
        
        __m256i ks2_l = _mm256_permute2x128_si256(l_h01, l_h23, 0b00100000);
        __m256i ks6_l = _mm256_permute2x128_si256(l_h01, l_h23, 0b00110001);

        __m256i ks3_l = _mm256_permute2x128_si256(h_h01, h_h23, 0b00100000);
        __m256i ks7_l = _mm256_permute2x128_si256(h_h01, h_h23, 0b00110001);


        const uint8_t* ptxt_ptr = ptxt + ct_idx;
        uint8_t *ctxt_ptr = ctxt + ct_idx;

        
        __m256i p0_l = _mm256_load_si256((const __m256i*)ptxt_ptr); // 0*64: plainext block number 0, lower part
        __m256i c0_l = _mm256_xor_si256(p0_l, ks0_l);
        _mm256_store_si256((__m256i*)ctxt_ptr, c0_l);

        __m256i p1_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 64)); // 1*64: plainext block number 1, lower part
        __m256i c1_l = _mm256_xor_si256(p1_l, ks1_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 64), c1_l);

        __m256i p2_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 128));
        __m256i c2_l = _mm256_xor_si256(p2_l, ks2_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 128), c2_l);

        __m256i p3_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 192));
        __m256i c3_l = _mm256_xor_si256(p3_l, ks3_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 192), c3_l);

        __m256i p4_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 256));
        __m256i c4_l = _mm256_xor_si256(p4_l, ks4_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 256), c4_l);

        __m256i p5_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 320));
        __m256i c5_l = _mm256_xor_si256(p5_l, ks5_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 320), c5_l);

        __m256i p6_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 384));
        __m256i c6_l = _mm256_xor_si256(p6_l, ks6_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 384), c6_l);

        __m256i p7_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 448));
        __m256i c7_l = _mm256_xor_si256(p7_l, ks7_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 448), c7_l);

        /////////////////////////////////////////////////
        // Higher state vectors and ciphertext computation
        /////////////////////////////////////////////////
        w8 = _mm256_add_epi32(w8, state8);
        w9 = _mm256_add_epi32(w9, state9);
        w10 = _mm256_add_epi32(w10, state10);
        w11 = _mm256_add_epi32(w11, state11);
        w12 = _mm256_add_epi32(w12, state12);
        w13 = _mm256_add_epi32(w13, state13);
        w14 = _mm256_add_epi32(w14, state14);
        w15 = _mm256_add_epi32(w15, state15);

        __m256i l4 = _mm256_unpacklo_epi32(w8, w9);
        __m256i l5 = _mm256_unpacklo_epi32(w10, w11);
        __m256i l6 = _mm256_unpacklo_epi32(w12, w13);
        __m256i l7 = _mm256_unpacklo_epi32(w14, w15);

        __m256i h4 = _mm256_unpackhi_epi32(w8, w9);
        __m256i h5 = _mm256_unpackhi_epi32(w10, w11);
        __m256i h6 = _mm256_unpackhi_epi32(w12, w13);
        __m256i h7 = _mm256_unpackhi_epi32(w14, w15);

        
        __m256i l_l45 = _mm256_unpacklo_epi64(l4, l5);
        __m256i l_l67 = _mm256_unpacklo_epi64(l6, l7);
        
        __m256i h_l45 = _mm256_unpackhi_epi64(l4, l5);
        __m256i h_l67 = _mm256_unpackhi_epi64(l6, l7);

        __m256i l_h45 = _mm256_unpacklo_epi64(h4, h5);
        __m256i l_h67 = _mm256_unpacklo_epi64(h6, h7);

        __m256i h_h45 = _mm256_unpackhi_epi64(h4, h5);
        __m256i h_h67 = _mm256_unpackhi_epi64(h6, h7);


        __m256i ks0_h = _mm256_permute2x128_si256(l_l45, l_l67, 0b00100000);
        __m256i ks4_h = _mm256_permute2x128_si256(l_l45, l_l67, 0b00110001);
        
        __m256i ks1_h = _mm256_permute2x128_si256(h_l45, h_l67, 0b00100000);
        __m256i ks5_h = _mm256_permute2x128_si256(h_l45, h_l67, 0b00110001);

        __m256i ks2_h = _mm256_permute2x128_si256(l_h45, l_h67, 0b00100000);
        __m256i ks6_h = _mm256_permute2x128_si256(l_h45, l_h67, 0b00110001);

        __m256i ks3_h = _mm256_permute2x128_si256(h_h45, h_h67, 0b00100000);
        __m256i ks7_h = _mm256_permute2x128_si256(h_h45, h_h67, 0b00110001);


        __m256i p0_h = _mm256_load_si256((const __m256i*)(ptxt_ptr+  32)); // 32 + 1*64: plainext block number 0, higher part
        __m256i c0_h = _mm256_xor_si256(p0_h, ks0_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr+ 32), c0_h);

        __m256i p1_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 96)); // 32 + 1*64: plainext block number 1, higher part
        __m256i c1_h = _mm256_xor_si256(p1_h, ks1_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 96), c1_h); 

        __m256i p2_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 160)); // 32 + 2*64
        __m256i c2_h = _mm256_xor_si256(p2_h, ks2_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 160), c2_h);

        __m256i p3_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 224)); // 32 + 3*64
        __m256i c3_h = _mm256_xor_si256(p3_h, ks3_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 224), c3_h);

        __m256i p4_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 288)); // 32 + 4*64
        __m256i c4_h = _mm256_xor_si256(p4_h, ks4_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 288), c4_h);

        __m256i p5_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 352)); // 32 + 5*64
        __m256i c5_h = _mm256_xor_si256(p5_h, ks5_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 352), c5_h);

        __m256i p6_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 416)); // 32 + 6*64
        __m256i c6_h = _mm256_xor_si256(p6_h, ks6_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 416), c6_h);

        __m256i p7_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 480)); // 32 + 7*64
        __m256i c7_h = _mm256_xor_si256(p7_h, ks7_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 480), c7_h);

        state12 = _mm256_add_epi32(state12, ctr_progression);
        ct_idx += 512;
    }

    if (remainder != 0) {
        uint32_t current_ctr = ctr + (blocks_8 * 8);
        uint64_t leftover_bytes = remainder;
        
        while (leftover_bytes > 0) {
            uint32_t state[STATE_SIZE_W];
            uint32_t working_state[STATE_SIZE_W];
            uint8_t ks[STATE_SIZE_B];

            state[0] = STATE_0;
            state[1] = STATE_1;
            state[2] = STATE_2;
            state[3] = STATE_3;
            state[4] = key_32[0];
            state[5] = key_32[1];
            state[6] = key_32[2];
            state[7] = key_32[3];
            state[8] = key_32[4];
            state[9] = key_32[5];
            state[10] = key_32[6];
            state[11] = key_32[7];
            state[12] = current_ctr;       
            state[13] = nonce_32[0];
            state[14] = nonce_32[1];
            state[15] = nonce_32[2];
        
            memcpy(working_state, state, STATE_SIZE_B);

            for (int i = 0; i < DOUBLE_ROUNDS; i++) {
                QUARTER_ROUND(working_state[0],  working_state[4],  working_state[8],  working_state[12]);
                QUARTER_ROUND(working_state[1],  working_state[5],  working_state[9],  working_state[13]);
                QUARTER_ROUND(working_state[2],  working_state[6],  working_state[10], working_state[14]);
                QUARTER_ROUND(working_state[3],  working_state[7],  working_state[11], working_state[15]);

                QUARTER_ROUND(working_state[0],  working_state[5],  working_state[10], working_state[15]);
                QUARTER_ROUND(working_state[1],  working_state[6],  working_state[11], working_state[12]);
                QUARTER_ROUND(working_state[2],  working_state[7],  working_state[8],  working_state[13]);
                QUARTER_ROUND(working_state[3],  working_state[4],  working_state[9],  working_state[14]);
            }

            working_state[0] += state[0];
            working_state[1] += state[1];
            working_state[2] += state[2];
            working_state[3] += state[3];
            working_state[4] += state[4];
            working_state[5] += state[5];
            working_state[6] += state[6];
            working_state[7] += state[7];
            working_state[8] += state[8];
            working_state[9] += state[9];
            working_state[10] += state[10];
            working_state[11] += state[11];
            working_state[12] += state[12];
            working_state[13] += state[13];
            working_state[14] += state[14];
            working_state[15] += state[15];

            memcpy(ks, working_state, STATE_SIZE_B);

            uint64_t bytes_to_process = (leftover_bytes < STATE_SIZE_B) ? leftover_bytes : STATE_SIZE_B;

            for (uint64_t i = 0; i < bytes_to_process; i++) {
                ctxt[ct_idx + i] = ptxt[ct_idx + i] ^ ks[i];
            }

            ct_idx += bytes_to_process;
            leftover_bytes -= bytes_to_process;
            current_ctr++; 
        }
    }
    return 0;
}


int chacha20_encrypt_vectorized3( 
    uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr
) {
    uint64_t blocks_8 = len >> 9;   // len / 512
    uint64_t remainder = len & 511; // len % 512;
    
    __m256i state0  = _mm256_set1_epi32(STATE_0);
    __m256i state1  = _mm256_set1_epi32(STATE_1);
    __m256i state2  = _mm256_set1_epi32(STATE_2);
    __m256i state3  = _mm256_set1_epi32(STATE_3);

    const uint32_t* key_32 = (const uint32_t*)key;
    __m256i state4  = _mm256_set1_epi32(key_32[0]);
    __m256i state5  = _mm256_set1_epi32(key_32[1]);
    __m256i state6  = _mm256_set1_epi32(key_32[2]);
    __m256i state7  = _mm256_set1_epi32(key_32[3]);
    __m256i state8  = _mm256_set1_epi32(key_32[4]);
    __m256i state9  = _mm256_set1_epi32(key_32[5]);
    __m256i state10 = _mm256_set1_epi32(key_32[6]);
    __m256i state11 = _mm256_set1_epi32(key_32[7]);

    __m256i ctrs = _mm256_set1_epi32(ctr);
    __m256i ctrs_offset = _mm256_set_epi32(7, 6, 5, 4, 3, 2, 1, 0);
    __m256i ctr_progression = _mm256_set1_epi32(8);

    __m256i state12 = _mm256_add_epi32(ctrs, ctrs_offset);

    const uint32_t* nonce_32 = (const uint32_t*)nonce;
    __m256i state13 = _mm256_set1_epi32(nonce_32[0]);
    __m256i state14 = _mm256_set1_epi32(nonce_32[1]);
    __m256i state15 = _mm256_set1_epi32(nonce_32[2]);

    uint64_t ct_idx = 0;

    __m256i w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;
    for (uint64_t b = 0; b < blocks_8; b++) {
        w0 = state0;   w1 = state1;   w2 = state2;   w3 = state3;
        w4 = state4;   w5 = state5;   w6 = state6;   w7 = state7;
        w8 = state8;   w9 = state9;   w10 = state10; w11 = state11;
        w12 = state12; w13 = state13; w14 = state14; w15 = state15;
        
        for (int i = 0; i < DOUBLE_ROUNDS; i++) {
            QUARTER_ROUND_256_2(w0, w4, w8,  w12);
            QUARTER_ROUND_256_2(w1, w5, w9,  w13);
            QUARTER_ROUND_256_2(w2, w6, w10, w14);
            QUARTER_ROUND_256_2(w3, w7, w11, w15);

            QUARTER_ROUND_256_2(w0, w5, w10, w15);
            QUARTER_ROUND_256_2(w1, w6, w11, w12);
            QUARTER_ROUND_256_2(w2, w7, w8,  w13);
            QUARTER_ROUND_256_2(w3, w4, w9,  w14);            
        }

        // If we assume LSB is on the far right, the j-th column (counting from right to left, from LSB to MSB),
        // of w0, w1, ..., w15 stacked on top of each other, will contain the final state corresponding to the
        // j-th plaintext block we are currently processing. To be able to use the vectorization to xor the 
        // serialized final state with the plaintext, we would like to have the final state in 2 vectors ()
        // Why 2 instead of 1? Because the final state is 512 bits long and we don't have avx512, so we would need 2
        // vectors to store the state. So, if we could achieve to have the column j of the stacked vectors w0, ... ,w15,
        // e.g. ks_j_l, ks_j_h (pictorially: keysteram_j_high | keystream_j_low with keystream_j_{} being a vector),
        // we could do (assuming a block of plaintext of 512 bits is split in 2 vectors plaintext_j_high|plaintext_j_low):
        //  ciphertext_j_low  = xor(plaintext_j_low, keystream_j_low)
        //  ciphertext_j_high = xor(plaintext_j_high, keystream_j_high)

        /////////////////////////////////////////////////
        // Lower state vectors and ciphertext computation
        /////////////////////////////////////////////////
        w0 = _mm256_add_epi32(w0, state0);
        w1 = _mm256_add_epi32(w1, state1);
        w2 = _mm256_add_epi32(w2, state2);
        w3 = _mm256_add_epi32(w3, state3);
        w4 = _mm256_add_epi32(w4, state4);
        w5 = _mm256_add_epi32(w5, state5);
        w6 = _mm256_add_epi32(w6, state6);
        w7 = _mm256_add_epi32(w7, state7);

        __m256i l0 = _mm256_unpacklo_epi32(w0, w1);
        __m256i l1 = _mm256_unpacklo_epi32(w2, w3);
        __m256i l2 = _mm256_unpacklo_epi32(w4, w5);
        __m256i l3 = _mm256_unpacklo_epi32(w6, w7);

        __m256i h0 = _mm256_unpackhi_epi32(w0, w1);
        __m256i h1 = _mm256_unpackhi_epi32(w2, w3);
        __m256i h2 = _mm256_unpackhi_epi32(w4, w5);
        __m256i h3 = _mm256_unpackhi_epi32(w6, w7);


        __m256i l_l01 = _mm256_unpacklo_epi64(l0, l1);
        __m256i l_l23 = _mm256_unpacklo_epi64(l2, l3);
        
        __m256i h_l01 = _mm256_unpackhi_epi64(l0, l1);
        __m256i h_l23 = _mm256_unpackhi_epi64(l2, l3);

        __m256i l_h01 = _mm256_unpacklo_epi64(h0, h1);
        __m256i l_h23 = _mm256_unpacklo_epi64(h2, h3);

        __m256i h_h01 = _mm256_unpackhi_epi64(h0, h1);
        __m256i h_h23 = _mm256_unpackhi_epi64(h2, h3);

        
        __m256i ks0_l = _mm256_permute2x128_si256(l_l01, l_l23, 0b00100000);
        __m256i ks4_l = _mm256_permute2x128_si256(l_l01, l_l23, 0b00110001);
        
        __m256i ks1_l = _mm256_permute2x128_si256(h_l01, h_l23, 0b00100000);
        __m256i ks5_l = _mm256_permute2x128_si256(h_l01, h_l23, 0b00110001);
        
        __m256i ks2_l = _mm256_permute2x128_si256(l_h01, l_h23, 0b00100000);
        __m256i ks6_l = _mm256_permute2x128_si256(l_h01, l_h23, 0b00110001);

        __m256i ks3_l = _mm256_permute2x128_si256(h_h01, h_h23, 0b00100000);
        __m256i ks7_l = _mm256_permute2x128_si256(h_h01, h_h23, 0b00110001);


        const uint8_t* ptxt_ptr = ptxt + ct_idx;
        uint8_t *ctxt_ptr = ctxt + ct_idx;

        
        __m256i p0_l = _mm256_load_si256((const __m256i*)ptxt_ptr); // 0*64: plainext block number 0, lower part
        __m256i c0_l = _mm256_xor_si256(p0_l, ks0_l);
        _mm256_store_si256((__m256i*)ctxt_ptr, c0_l);

        __m256i p1_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 64)); // 1*64: plainext block number 1, lower part
        __m256i c1_l = _mm256_xor_si256(p1_l, ks1_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 64), c1_l);

        __m256i p2_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 128));
        __m256i c2_l = _mm256_xor_si256(p2_l, ks2_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 128), c2_l);

        __m256i p3_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 192));
        __m256i c3_l = _mm256_xor_si256(p3_l, ks3_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 192), c3_l);

        __m256i p4_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 256));
        __m256i c4_l = _mm256_xor_si256(p4_l, ks4_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 256), c4_l);

        __m256i p5_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 320));
        __m256i c5_l = _mm256_xor_si256(p5_l, ks5_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 320), c5_l);

        __m256i p6_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 384));
        __m256i c6_l = _mm256_xor_si256(p6_l, ks6_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 384), c6_l);

        __m256i p7_l = _mm256_load_si256((const __m256i*)(ptxt_ptr + 448));
        __m256i c7_l = _mm256_xor_si256(p7_l, ks7_l);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 448), c7_l);

        /////////////////////////////////////////////////
        // Higher state vectors and ciphertext computation
        /////////////////////////////////////////////////
        w8 = _mm256_add_epi32(w8, state8);
        w9 = _mm256_add_epi32(w9, state9);
        w10 = _mm256_add_epi32(w10, state10);
        w11 = _mm256_add_epi32(w11, state11);
        w12 = _mm256_add_epi32(w12, state12);
        w13 = _mm256_add_epi32(w13, state13);
        w14 = _mm256_add_epi32(w14, state14);
        w15 = _mm256_add_epi32(w15, state15);

        __m256i l4 = _mm256_unpacklo_epi32(w8, w9);
        __m256i l5 = _mm256_unpacklo_epi32(w10, w11);
        __m256i l6 = _mm256_unpacklo_epi32(w12, w13);
        __m256i l7 = _mm256_unpacklo_epi32(w14, w15);

        __m256i h4 = _mm256_unpackhi_epi32(w8, w9);
        __m256i h5 = _mm256_unpackhi_epi32(w10, w11);
        __m256i h6 = _mm256_unpackhi_epi32(w12, w13);
        __m256i h7 = _mm256_unpackhi_epi32(w14, w15);

        
        __m256i l_l45 = _mm256_unpacklo_epi64(l4, l5);
        __m256i l_l67 = _mm256_unpacklo_epi64(l6, l7);
        
        __m256i h_l45 = _mm256_unpackhi_epi64(l4, l5);
        __m256i h_l67 = _mm256_unpackhi_epi64(l6, l7);

        __m256i l_h45 = _mm256_unpacklo_epi64(h4, h5);
        __m256i l_h67 = _mm256_unpacklo_epi64(h6, h7);

        __m256i h_h45 = _mm256_unpackhi_epi64(h4, h5);
        __m256i h_h67 = _mm256_unpackhi_epi64(h6, h7);


        __m256i ks0_h = _mm256_permute2x128_si256(l_l45, l_l67, 0b00100000);
        __m256i ks4_h = _mm256_permute2x128_si256(l_l45, l_l67, 0b00110001);
        
        __m256i ks1_h = _mm256_permute2x128_si256(h_l45, h_l67, 0b00100000);
        __m256i ks5_h = _mm256_permute2x128_si256(h_l45, h_l67, 0b00110001);

        __m256i ks2_h = _mm256_permute2x128_si256(l_h45, l_h67, 0b00100000);
        __m256i ks6_h = _mm256_permute2x128_si256(l_h45, l_h67, 0b00110001);

        __m256i ks3_h = _mm256_permute2x128_si256(h_h45, h_h67, 0b00100000);
        __m256i ks7_h = _mm256_permute2x128_si256(h_h45, h_h67, 0b00110001);


        __m256i p0_h = _mm256_load_si256((const __m256i*)(ptxt_ptr+  32)); // 32 + 1*64: plainext block number 0, higher part
        __m256i c0_h = _mm256_xor_si256(p0_h, ks0_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr+ 32), c0_h);

        __m256i p1_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 96)); // 32 + 1*64: plainext block number 1, higher part
        __m256i c1_h = _mm256_xor_si256(p1_h, ks1_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 96), c1_h); 

        __m256i p2_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 160)); // 32 + 2*64
        __m256i c2_h = _mm256_xor_si256(p2_h, ks2_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 160), c2_h);

        __m256i p3_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 224)); // 32 + 3*64
        __m256i c3_h = _mm256_xor_si256(p3_h, ks3_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 224), c3_h);

        __m256i p4_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 288)); // 32 + 4*64
        __m256i c4_h = _mm256_xor_si256(p4_h, ks4_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 288), c4_h);

        __m256i p5_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 352)); // 32 + 5*64
        __m256i c5_h = _mm256_xor_si256(p5_h, ks5_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 352), c5_h);

        __m256i p6_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 416)); // 32 + 6*64
        __m256i c6_h = _mm256_xor_si256(p6_h, ks6_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 416), c6_h);

        __m256i p7_h = _mm256_load_si256((const __m256i*)(ptxt_ptr + 480)); // 32 + 7*64
        __m256i c7_h = _mm256_xor_si256(p7_h, ks7_h);
        _mm256_store_si256((__m256i*)(ctxt_ptr + 480), c7_h);

        state12 = _mm256_add_epi32(state12, ctr_progression);
        ct_idx += 512;
    }

    if (remainder != 0) {
        uint32_t current_ctr = ctr + (blocks_8 * 8);
        uint64_t leftover_bytes = remainder;
        
        while (leftover_bytes > 0) {
            uint32_t state[STATE_SIZE_W];
            uint32_t working_state[STATE_SIZE_W];
            uint8_t ks[STATE_SIZE_B];

            state[0] = STATE_0;
            state[1] = STATE_1;
            state[2] = STATE_2;
            state[3] = STATE_3;
            state[4] = key_32[0];
            state[5] = key_32[1];
            state[6] = key_32[2];
            state[7] = key_32[3];
            state[8] = key_32[4];
            state[9] = key_32[5];
            state[10] = key_32[6];
            state[11] = key_32[7];
            state[12] = current_ctr;       
            state[13] = nonce_32[0];
            state[14] = nonce_32[1];
            state[15] = nonce_32[2];
        
            memcpy(working_state, state, STATE_SIZE_B);

            for (int i = 0; i < DOUBLE_ROUNDS; i++) {
                QUARTER_ROUND(working_state[0],  working_state[4],  working_state[8],  working_state[12]);
                QUARTER_ROUND(working_state[1],  working_state[5],  working_state[9],  working_state[13]);
                QUARTER_ROUND(working_state[2],  working_state[6],  working_state[10], working_state[14]);
                QUARTER_ROUND(working_state[3],  working_state[7],  working_state[11], working_state[15]);

                QUARTER_ROUND(working_state[0],  working_state[5],  working_state[10], working_state[15]);
                QUARTER_ROUND(working_state[1],  working_state[6],  working_state[11], working_state[12]);
                QUARTER_ROUND(working_state[2],  working_state[7],  working_state[8],  working_state[13]);
                QUARTER_ROUND(working_state[3],  working_state[4],  working_state[9],  working_state[14]);
            }

            working_state[0] += state[0];
            working_state[1] += state[1];
            working_state[2] += state[2];
            working_state[3] += state[3];
            working_state[4] += state[4];
            working_state[5] += state[5];
            working_state[6] += state[6];
            working_state[7] += state[7];
            working_state[8] += state[8];
            working_state[9] += state[9];
            working_state[10] += state[10];
            working_state[11] += state[11];
            working_state[12] += state[12];
            working_state[13] += state[13];
            working_state[14] += state[14];
            working_state[15] += state[15];

            memcpy(ks, working_state, STATE_SIZE_B);

            uint64_t bytes_to_process = (leftover_bytes < STATE_SIZE_B) ? leftover_bytes : STATE_SIZE_B;

            for (uint64_t i = 0; i < bytes_to_process; i++) {
                ctxt[ct_idx + i] = ptxt[ct_idx + i] ^ ks[i];
            }

            ct_idx += bytes_to_process;
            leftover_bytes -= bytes_to_process;
            current_ctr++; 
        }
    }
    return 0;
}

int chacha20_encrypt_openssl(uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr)
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
