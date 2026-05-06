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

#endif
