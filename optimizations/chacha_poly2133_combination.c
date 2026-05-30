/*
 * ChaCha20-Poly2133 AEAD.
 *
 * Same construction as chacha_poly_combination.c (ChaCha20-Poly1305) but with
 * the Poly2133 authenticator instead of Poly1305. Poly2133 uses a 54-byte
 * one-time key and produces a 26-byte tag, so the AEAD is parameterized over
 * mac_key_size / tag_size via the shared aead_engine_t.
 *
 * poly2133-optimizations.c is textually included for the create_tag variants
 * (it is self-contained: defines its own NUM_LIMBS/mask constants). The init
 * functions live in poly2133-init-optimizations.c and are forward-declared
 * below to avoid pulling in poly2133_init_opts.h, whose macros/static-inline
 * to_large_num_rep collide with poly2133-optimizations.c.
 */
#include "chacha20.h"
#include "chacha20-poly1305.h"
#include "chacha_opts.h"
#include "poly2133-optimizations.c"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// If byte_len is factor of 16 bytes we want the result to be 0.
#define LEN_PAD16(byte_len) \
    (16 - (byte_len % 16)) % 16;

#define POLY2133_KEY_SIZE 54
#define POLY2133_TAG_SIZE 26

/* Poly2133 key-expansion variants (defined in poly2133-init-optimizations.c). */
void poly2133_init_baseline(uint32_t *acc, uint32_t *r, uint32_t *s, const unsigned char *key);
void poly2133_init_vectorized(uint32_t *acc, uint32_t *r, uint32_t *s, const unsigned char *key);

/*
 * Engine presets for the Poly2133 AEAD. Each pairs a ChaCha20 tier with a
 * matching Poly2133 init + create_tag tier. (Poly2133: 54-byte one-time key,
 * 26-byte tag.)
 */
const aead_engine_t AEAD_POLY2133_BASELINE = {
    chacha20_encrypt_baseline,
    poly2133_init_baseline,
    poly2133_create_tag_baseline,
    POLY2133_KEY_SIZE,
    POLY2133_TAG_SIZE
};
const aead_engine_t AEAD_POLY2133 = {
    chacha20_encrypt_vectorized3,
    poly2133_init_vectorized,
    poly2133_create_tag_vec,
    POLY2133_KEY_SIZE,
    POLY2133_TAG_SIZE
};

/* Derives the one-time MAC key using block counter 0. The first mac_key_size keystream bytes are the MAC key. */
static void mac_key_gen_with(const aead_engine_t *e,
    uint8_t *mac_key_buffer, const uint8_t *key_b, const uint8_t *nonce_b){
    uint8_t zeros[AEAD_MAX_MAC_KEY_SIZE] = {0};
    e->chacha_encrypt(mac_key_buffer, zeros, e->mac_key_size, key_b, nonce_b, 0, ROUNDS);
}

/* Encrypts and authenticates plaintext with the given Poly2133 engine. Stores
 * the ciphertext (encrypted plaintext and tag concatenated) in ciphertext_b. */
size_t encrypt_poly2133_with(const aead_engine_t *e,
    uint8_t *ciphertext_b,
    const uint8_t *plaintext_b, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b, /*32 bytes*/
    const uint8_t *nonce_b /*12 bytes*/
){
    uint8_t mac_key_buffer[AEAD_MAX_MAC_KEY_SIZE];
    mac_key_gen_with(e, mac_key_buffer, key_b, nonce_b);

    uint32_t block_ctr = 1;
    e->chacha_encrypt(ciphertext_b, plaintext_b, plaintext_len, key_b, nonce_b, block_ctr, ROUNDS);

    // If aad is not provided (=NULL), pass on the empty string
    const uint8_t *aad_or_empty = (aad != NULL) ? aad : (const uint8_t *)"";
    aad_len = (aad != NULL) ? aad_len : 0;

    size_t pad_aad_len = LEN_PAD16(aad_len);
    size_t pad_ctxt_len = LEN_PAD16(plaintext_len);

    size_t offset = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len;
    size_t mac_data_len = offset + 16;

    // mac_data = aad | aad_pad | ctxt | ctxt_pad | |aad_len|_{64} | |ctxt_len|_{64}
    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);
    memcpy(mac_data, aad_or_empty, aad_len);
    memset(mac_data + aad_len, 0, pad_aad_len);
    memcpy(mac_data + aad_len + pad_aad_len, ciphertext_b, plaintext_len);
    memset(mac_data + aad_len + pad_aad_len + plaintext_len, 0, pad_ctxt_len);

    uint64_t aad_len_le = (uint64_t)aad_len;
    for (int i = 0; i < 8; i++) {
        mac_data[offset + i] = (uint8_t)(aad_len_le >> (8 * i));
    }
    offset += 8;

    uint64_t ctxt_len_le = (uint64_t)plaintext_len;
    for (int i = 0; i < 8; i++) {
        mac_data[offset + i] = (uint8_t)(ctxt_len_le >> (8 * i));
    }
    offset += 8;

    uint32_t acc[AEAD_MAX_MAC_LIMBS], r[AEAD_MAX_MAC_LIMBS], s[AEAD_MAX_MAC_LIMBS];
    e->mac_init(acc, r, s, mac_key_buffer);
    uint8_t *tag = e->create_tag(acc, r, s, mac_data, mac_data_len);

    memcpy(ciphertext_b + plaintext_len, tag, e->tag_size);

    free(tag);
    free(mac_data);

    return plaintext_len + e->tag_size;
}

/* Verifies and decrypts (ciphertext || tag) with the given Poly2133 engine.
 * On success, stores plaintext in plaintext_b and returns its length.
 * On authentication failure, returns AEAD_AUTH_FAIL without changing plaintext. */
size_t decrypt_poly2133_with(const aead_engine_t *e,
    uint8_t *plaintext_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
) {
    if (ciphertext_len < e->tag_size){
        return AEAD_AUTH_FAIL;
    }

    size_t ctxt_len = ciphertext_len - e->tag_size;
    const uint8_t *expected_tag = ciphertext_b + ctxt_len;
    uint8_t mac_key_buffer[AEAD_MAX_MAC_KEY_SIZE];
    mac_key_gen_with(e, mac_key_buffer, key_b, nonce_b);

    // If aad is not provided (=NULL), pass on the empty string
    const uint8_t *aad_or_empty = (aad != NULL) ? aad : (const uint8_t *)"";
    aad_len = (aad != NULL) ? aad_len : 0;

    // mac_data = aad | aad_pad | ctxt | ctxt_pad | |aad_len|_{64} | |ctxt_len|_{64}
    size_t pad_aad_len = LEN_PAD16(aad_len);
    size_t pad_ctxt_len = LEN_PAD16(ctxt_len);

    size_t offset = aad_len + pad_aad_len + ctxt_len + pad_ctxt_len;
    size_t mac_data_len = offset + 16;

    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);
    memcpy(mac_data, aad_or_empty, aad_len);
    memset(mac_data + aad_len, 0, pad_aad_len);
    memcpy(mac_data + aad_len + pad_aad_len, ciphertext_b, ctxt_len);
    memset(mac_data + aad_len + pad_aad_len + ctxt_len, 0, pad_ctxt_len);

    uint64_t aad_len_le = (uint64_t)aad_len;
    for (int i = 0; i < 8; i++) {
        mac_data[offset + i] = (uint8_t)(aad_len_le >> (8 * i));
    }
    offset += 8;

    uint64_t ctxt_len_le = (uint64_t)ctxt_len;
    for (int i = 0; i < 8; i++) {
        mac_data[offset + i] = (uint8_t)(ctxt_len_le >> (8 * i));
    }
    offset += 8;

    uint32_t acc[AEAD_MAX_MAC_LIMBS], r[AEAD_MAX_MAC_LIMBS], s[AEAD_MAX_MAC_LIMBS];
    e->mac_init(acc, r, s, mac_key_buffer);
    uint8_t *tag = e->create_tag(acc, r, s, mac_data, mac_data_len);

    int mismatch = memcmp(tag, expected_tag, e->tag_size); // Insecure: memcmp simplifies side channel attacks

    free(tag);
    free(mac_data);

    if (mismatch != 0) {
        return AEAD_AUTH_FAIL;
    }

    e->chacha_encrypt(plaintext_b, ciphertext_b, ctxt_len, key_b, nonce_b, 1, ROUNDS);

    return ctxt_len;
}

/* Default ChaCha20-Poly2133 encrypt: uses the vectorized engine. */
size_t encrypt_poly2133(uint8_t *ciphertext_b,
    const uint8_t *plaintext_b, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
){
    return encrypt_poly2133_with(&AEAD_POLY2133, ciphertext_b, plaintext_b, plaintext_len,
                                 aad, aad_len, key_b, nonce_b);
}

/* Default ChaCha20-Poly2133 decrypt: uses the vectorized engine. */
size_t decrypt_poly2133(uint8_t *plaintext_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
) {
    return decrypt_poly2133_with(&AEAD_POLY2133, plaintext_b, ciphertext_b, ciphertext_len,
                                 aad, aad_len, key_b, nonce_b);
}
