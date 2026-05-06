/*
* ChaCha20 stream cipher (RFC 8439)
*/
#include <stdint.h>

#define TAG_LENGTH         16

#define CONSTANTS_SIZE 4
#define QR_PER_ROUND 8

#define BLOCK_CTR_IDX 12
#define ROUNDS        20

#define COUNTER       0
#define KEY_SIZE_B    32
#define KEY_SIZE_W    8
#define NONCE_SIZE_B  12
#define NONCE_SIZE_W  3
#define STATE_SIZE_B   64
#define STATE_SIZE_W   16
#define BLOCK_SIZE_B   64


void chacha_block(uint8_t *keystream_buffer, const uint32_t *input_state_w, int rounds);
void chacha20_block(uint8_t *keystream_buffer, const uint8_t *key_b, const uint8_t *nonce_b, uint32_t block_ctr);

int chacha20_encrypt(
    uint8_t       *ciphertext_buffer,   
    const uint8_t *plaintext_b,
    uint64_t       len_plaintext,       
    const uint8_t *key_b,       
    const uint8_t *nonce_b,        
    uint32_t       block_ctr,      
    int rounds
);