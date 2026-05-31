/*
* ChaCha20-Poly1305 AEAD (RFC 8439)
*/

#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stddef.h>
#include <stdint.h>
#include "chacha20.h"

#define AEAD_AUTH_FAIL ((size_t)-1)
#define POLY1305_KEY_SIZE  32

typedef int (*aead_cipher_func)(
    uint8_t *ct, const uint8_t *pt, uint64_t len,
    const uint8_t *key, const uint8_t *nonce, uint32_t ctr, int rounds
);
typedef unsigned char *(*aead_mac_func)(
    uint32_t acc[5], uint32_t r[5], uint32_t s[4],
    const unsigned char *data, uint64_t data_len
);

typedef struct {
    aead_cipher_func chacha_encrypt;
    aead_mac_func    create_tag;
} aead_engine_t;

/* named presets, one per optimization tier (defined in chacha_poly_combination.c). */
extern const aead_engine_t AEAD_BASELINE;
extern const aead_engine_t AEAD_SCALAR;
extern const aead_engine_t AEAD_VECTORIZED;
extern const aead_engine_t AEAD_OPENSSL;

/* generates the key for the poly authenticator, stores it in poly_key_b*/
void poly1305_key_gen(
    uint8_t *poly_key_buffer, 
    const uint8_t *key_b, 
    const uint8_t *nonce_b
);

size_t encrypt(uint8_t *ciphertext_b,
    const uint8_t *plaintext_b, size_t plaintext_len, 
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b, /*32 bytes*/
    const uint8_t *nonce_b /*12 bytes*/ 
);

size_t decrypt(
    uint8_t       *plaintext_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad,          size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
);

size_t encrypt_with(const aead_engine_t *e,
    uint8_t *ciphertext_b,
    const uint8_t *plaintext_b, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
);

size_t decrypt_with(const aead_engine_t *e,
    uint8_t       *plaintext_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad,          size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
);


#endif