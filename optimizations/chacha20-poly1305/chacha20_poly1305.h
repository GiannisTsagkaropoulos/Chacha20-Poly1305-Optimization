#include "constants.h"

// If byte_len is factor of 16 bytes we want the result to be 0.
#define LEN_PAD16(byte_len) \
    (16 - (byte_len % 16)) % 16;

void poly1305_key_gen(uint8_t poly_key[32], const uint8_t chacha_key[32], const uint8_t nonce[12]);

typedef uint64_t(*aead_encrypt_func)(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len, 
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b 
);

typedef uint64_t(*aead_decrypt_func)(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len, 
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b 
);

/* Encrypts and authenticates plaintext using nonce and data. 
Stores the ciphertext (consisting of the encrypted plaintext and tag concatenated) in ciphertext_b
key 32 bytes
nonce 12 bytes
*/
uint64_t aead_encrypt_baseline( uint8_t *c, const uint8_t *p, uint64_t p_len, const uint8_t *aad, uint64_t aad_len, const uint8_t *key, const uint8_t *nonce);
uint64_t aead_encrypt_strength_reduction(uint8_t *c, const uint8_t *p, uint64_t len, const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b);
uint64_t aead_encrypt_best_scalar(uint8_t *c, const uint8_t *p, uint64_t len, const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b);
uint64_t aead_encrypt_best_vectorized(uint8_t *c, const uint8_t *p, uint64_t len, const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b);
uint64_t aead_encrypt_openssl(uint8_t *c, const uint8_t *p, uint64_t len, const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b);


/* Verifies and decrypts (ciphertext || tag) using nonce and AAD. 
 on success, stores plaintext in plaintext_b and returns its length
 on authentication faliour, returns AEAD_AUTH_FAIL without changing plaintext*/
uint64_t aead_decrypt_baseline(
    uint8_t *plaintext_b, const uint8_t *ciphertext_b, uint64_t ciphertext_len,
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b
);


