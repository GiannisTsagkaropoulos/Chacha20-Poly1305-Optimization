#include "constants.h"

// If byte_len is factor of 16 bytes we want the result to be 0.
#define LEN_PAD16(byte_len) \
    (16 - (byte_len % 16)) % 16;

void poly2133_key_gen(uint8_t *poly_key, const uint8_t *chacha_key, const uint8_t *nonce);

typedef uint64_t(*chacha20_poly2133_encrypt_func)(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len, 
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b 
);


uint64_t chacha20_poly2133_encrypt_baseline(uint8_t *c, const uint8_t *p, uint64_t p_len, const uint8_t *aad, uint64_t aad_len, const uint8_t *key, const uint8_t *nonce);
uint64_t chacha20_poly2133_encrypt_strength_reduction( uint8_t *c, const uint8_t *p, uint64_t p_len, const uint8_t *aad, uint64_t aad_len, const uint8_t *key, const uint8_t *nonce);

uint64_t chacha20_poly2133_decrypt_baseline(
    uint8_t *plaintext_b, const uint8_t *ciphertext_b, uint64_t ciphertext_len,
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b
);


