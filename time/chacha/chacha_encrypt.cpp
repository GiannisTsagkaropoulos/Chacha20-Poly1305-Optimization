#include <stdint.h>
#include <cstring>
#include "chacha.h"

static const uint32_t CONSTANTS[CONSTANTS_SIZE] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

static void initialize_chacha_state(uint32_t *state, const uint8_t *key_b, const uint8_t *nonce_b, uint32_t block_ctr){
    state[0] = CONSTANTS[0];
    state[1] = CONSTANTS[1];
    state[2] = CONSTANTS[2];
    state[3] = CONSTANTS[3];
    for (int i = 0; i < 8; i++){
        state[4 + i] = BYTE_PTR_TO_U32(key_b + i*4);
    }
    state[12] = block_ctr;
    state[13] = BYTE_PTR_TO_U32(nonce_b);
    state[14] = BYTE_PTR_TO_U32(nonce_b + 4);
    state[15] = BYTE_PTR_TO_U32(nonce_b + 8);
}

int chacha20_encrypt_base( 
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
        chacha_block_base(keystream_buffer, initial_state_w, rounds);

        for (int i = 0; i < STATE_SIZE_B; i++)
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];

        initial_state_w[BLOCK_CTR_IDX]++;
        idx_start += STATE_SIZE_B;
    }

    if (remainder != 0) {
        chacha_block_base(keystream_buffer, initial_state_w, rounds);

        for (uint64_t i = 0; i < remainder; i++)
            ctxt[idx_start + i] = ptxt[idx_start + i] ^ keystream_buffer[i];
    }
    return 0;
}

int chacha20_encrypt_best(uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds) {
    return chacha20_encrypt_base(ctxt, ptxt, len, key, nonce, ctr, rounds);
}

// TODO: add correct implementation
int chacha20_encrypt_openssl(uint8_t *ctxt, const uint8_t *ptxt, uint64_t len,       
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds) {
    return chacha20_encrypt_base(ctxt, ptxt, len, key, nonce, ctr, rounds);
}