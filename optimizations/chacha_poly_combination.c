#include "chacha20.h"
#include "chacha20-poly1305.h"
#include "chacha_opts.h"
#include "poly1305_tag_opt.h"
#include "poly1305_init_opts.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// If byte_len is factor of 16 bytes we want the result to be 0.
#define LEN_PAD16(byte_len) \
    (16 - (byte_len % 16)) % 16;

// engines, with pairs of chacha20 and poly1305 implementations. 
// Each pair is from the same optimization tier, so the whole AEAD stays on a single tier.
const aead_engine_t AEAD_BASELINE = {
    chacha20_encrypt_baseline,
    poly1305_init_baseline,
    create_tag
};
const aead_engine_t AEAD_SCALAR = {
    chacha20_encrypt_scalar_replacement,
    poly1305_init_scalar_replacement,
    inlined_carry_delay_parallel_Horner
};
const aead_engine_t AEAD_VECTORIZED = {
    chacha20_encrypt_vectorized3,
    poly1305_init_vectorized,
    vect_inlined_carry_delay_parallel_Horner
};
// TODO: CHANGE TO OPENSSL
const aead_engine_t AEAD_OPENSSL = {
    chacha20_encrypt_openssl,
    poly1305_init_vectorized,
    vect_inlined_carry_delay_parallel_Horner
};

void poly1305_key_gen(uint8_t *poly_key_buffer, const uint8_t *key_b, const uint8_t *nonce_b){
    uint32_t block_ctr = 0; 

    uint8_t keystream_b[STATE_SIZE_B];
    chacha20_block(keystream_b, key_b, nonce_b, block_ctr);
    memcpy(poly_key_buffer, keystream_b, POLY1305_KEY_SIZE);  

    memset(keystream_b, 0, STATE_SIZE_B);
}

/* Derives the Poly1305 one-time key using block counter 0*/
static void poly1305_key_gen_with(const aead_engine_t *e,
    uint8_t *poly_key_buffer, const uint8_t *key_b, const uint8_t *nonce_b){
    uint8_t zeros[POLY1305_KEY_SIZE] = {0};
    e->chacha_encrypt(poly_key_buffer, zeros, POLY1305_KEY_SIZE, key_b, nonce_b, 0, ROUNDS);
}

size_t encrypt_with(const aead_engine_t *e,
    uint8_t *ciphertext_b,
    const uint8_t *plaintext_b, size_t plaintext_len, 
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b, /*32 bytes*/
    const uint8_t *nonce_b /*12 bytes*/ 
){
    uint8_t poly_key_buffer[POLY1305_KEY_SIZE];
    poly1305_key_gen_with(e, poly_key_buffer, key_b, nonce_b);

    uint32_t block_ctr = 1;
    e->chacha_encrypt(ciphertext_b, plaintext_b, plaintext_len, key_b, nonce_b, block_ctr, ROUNDS);

    // If aad is not provided (=NULL), pass on the empty string
    const uint8_t *aad_or_empty   = (aad != NULL) ? aad  : (const uint8_t *)"";
    aad_len = (aad != NULL) ? aad_len : 0;

    size_t pad_aad_len = LEN_PAD16(aad_len);
    size_t pad_ctxt_len = LEN_PAD16(plaintext_len);

    size_t offset = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len;
    size_t mac_data_len = offset + 16;

    // mac_data = aad | aad_pad | ctxt | ctxt_pad | |aad_len|_{64} | |ctxt_len|_{64}
    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);
    memcpy(mac_data, aad_or_empty, aad_len);
    memset(mac_data + aad_len , 0, pad_aad_len);
    memcpy(mac_data + aad_len + pad_aad_len, ciphertext_b, plaintext_len);
    memset(mac_data + aad_len + pad_aad_len + plaintext_len, 0, pad_ctxt_len);

    // Poly1305 input has to be 8-byte little endian int (RFC 7539 §2.8.1)
    uint64_t aad_len_le = (uint64_t)aad_len;
    for (int i = 0; i < 8; i++) {
        // shifts data length to the right and casts it to uint8_t, only capturing the least significant bits each time
        mac_data[offset + i] = (uint8_t)(aad_len_le >> (8 * i));
    } 
    offset += 8;


    uint64_t ctxt_len_le  = (uint64_t)plaintext_len;
    for (int i = 0; i < 8; i++) {
        mac_data[offset + i] = (uint8_t)(ctxt_len_le  >> (8 * i));
    }
    offset += 8;

    uint32_t acc[5], r[5], s[4];
    e->mac_init(acc, r, s, poly_key_buffer);
    uint8_t *tag = e->create_tag(acc, r, s, mac_data, mac_data_len);

    memcpy(ciphertext_b + plaintext_len, tag, TAG_LENGTH);

    free(tag);
    free(mac_data);

    size_t ciphertext_len = plaintext_len + TAG_LENGTH;

    return ciphertext_len;
}

/* Default AEAD encrypt: uses the vectorized engine. */
size_t encrypt(uint8_t *ciphertext_b,
    const uint8_t *plaintext_b, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
){
    return encrypt_with(&AEAD_VECTORIZED, ciphertext_b, plaintext_b, plaintext_len,
                        aad, aad_len, key_b, nonce_b);
}

/* Verifies and decrypts (ciphertext || tag) using nonce and AAD with the given
 engine.*/
size_t decrypt_with(const aead_engine_t *e,
    uint8_t *plaintext_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
) {
    if (ciphertext_len < TAG_LENGTH){
        return AEAD_AUTH_FAIL;
    }

    size_t ctxt_len = ciphertext_len - TAG_LENGTH;
    const uint8_t *expected_tag = ciphertext_b + ctxt_len;
    uint8_t poly_key_buffer[POLY1305_KEY_SIZE];
    poly1305_key_gen_with(e, poly_key_buffer, key_b, nonce_b);

    // If aad is not provided (=NULL), pass on the empty string
    const uint8_t *aad_or_empty   = (aad != NULL) ? aad  : (const uint8_t *)"";
    aad_len = (aad != NULL) ? aad_len : 0;

    // mac_data = aad | aad_pad | ctxt | ctxt_pad | |aad_len|_{64} | |ctxt_len|_{64}
    size_t pad_aad_len = LEN_PAD16(aad_len);
    size_t pad_ctxt_len = LEN_PAD16(ctxt_len);

    size_t offset = aad_len + pad_aad_len + ctxt_len + pad_ctxt_len;
    size_t mac_data_len = offset + 16;

    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);
    memcpy(mac_data, aad_or_empty, aad_len);
    memset(mac_data + aad_len , 0, pad_aad_len);
    memcpy(mac_data + aad_len + pad_aad_len, ciphertext_b, ctxt_len);
    memset(mac_data + aad_len + pad_aad_len + ctxt_len, 0, pad_ctxt_len);

    uint64_t aad_len_le = (uint64_t)aad_len;
    for (int i = 0; i < 8; i++) {
        mac_data[offset + i] = (uint8_t)(aad_len_le >> (8 * i));
    }
    offset += 8;

    /* struct.pack('<Q', len(ciphertext)) */
    uint64_t ctxt_len_le = (uint64_t)ctxt_len;
    for (int i = 0; i < 8; i++) {
        mac_data[offset + i] = (uint8_t)(ctxt_len_le >> (8 * i));
    }
    offset += 8;

    uint32_t acc[5], r[5], s[5];
    e->mac_init(acc, r, s, poly_key_buffer);
    uint8_t *tag = e->create_tag(acc, r, s, mac_data, mac_data_len);

    int mismatch = memcmp(tag, expected_tag, TAG_LENGTH); // Insecure: memcmp simplifies side channel attacks

    free(tag);
    free(mac_data);

    if (mismatch != 0) {
        return AEAD_AUTH_FAIL;
    }

    e->chacha_encrypt(plaintext_b, ciphertext_b, ctxt_len, key_b, nonce_b, 1, ROUNDS);

    return ctxt_len;
}

/* Default chacha-poly1305 decrypt: uses the vectorized engine. */
size_t decrypt(uint8_t *plaintext_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *key_b,
    const uint8_t *nonce_b
) {
    return decrypt_with(&AEAD_VECTORIZED, plaintext_b, ciphertext_b, ciphertext_len,
                        aad, aad_len, key_b, nonce_b);
}