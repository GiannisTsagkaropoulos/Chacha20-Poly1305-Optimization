/*
* ChaCha20-Poly1305 AEAD (RFC 8439)
*/

#ifndef CHACHA20_POLY1305_H
#define CHACHA20_POLY1305_H

#include <stddef.h>
#include <stdint.h>
#include "chacha20.h"

#define AEAD_AUTH_FAIL ((size_t)-1)

void poly1305_key_gen(
    const uint8_t *key_b,
    const uint8_t *nonce_b,
    uint8_t        poly_key_b[POLY1305_KEY_SIZE]
);

size_t encrypt(
    const uint8_t *key_b,
    const uint8_t *nonce_b,
    const uint8_t *plaintext_b,  size_t plaintext_len,
    const uint8_t *aad,          size_t aad_len,
    uint8_t       *ciphertext_b
);

size_t decrypt(
    const uint8_t *key_b,
    const uint8_t *nonce_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad,          size_t aad_len,
    uint8_t       *plaintext_b
);

#endif
