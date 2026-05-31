size_t encrypt_poly2133_with(const aead_engine_t *e,
    uint8_t *ciphertext_b,
    const uint8_t *plaintext_b, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
);

size_t decrypt_poly2133_with(const aead_engine_t *e,
    uint8_t       *plaintext_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad,          size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
);

size_t encrypt_poly2133(uint8_t *ciphertext_b,
    const uint8_t *plaintext_b, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
);

size_t decrypt_poly2133(uint8_t *plaintext_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
);