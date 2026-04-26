/*
* ChaCha20 stream cipher (RFC 8439)
*/

#define TAG_LENGTH    16

#define CONSTANTS_SIZE 4
#define QR_PER_ROUND 8
#define INDICES_PER_STEP 4

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

#include <stdint.h>

int chacha20_encrypt(
    const uint8_t *key_b,       
    const uint8_t *nonce_b,        /* 32 bytes */
    uint32_t       block_ctr,      /* 12 bytes */
    const uint8_t *plaintext_b,
    uint64_t       p_length,       /* maximum plaintext size is 274,877,906,880 bytes (as per RFC 8439).*/
    int            rounds,         /* recommended number of rounds is 20 (as per RFC 8439)*/ 
    uint8_t        *ciphertext_b   /* caller-allocated. Needs to be at laest >= p_length bytes in size */
);