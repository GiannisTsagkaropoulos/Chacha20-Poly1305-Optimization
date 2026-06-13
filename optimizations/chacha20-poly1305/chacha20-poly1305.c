#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include "chacha20_poly1305.h"
#include "poly1305_tag_opt.h"
#include "poly1305_init_opts.h"
#include "chacha_opts.h"


void poly1305_key_gen(uint8_t poly_key[32], const uint8_t chacha_key[32], const uint8_t nonce[12]) {
    uint8_t zeros[32];
    memset(zeros, 0, 32);

    chacha20_encrypt_baseline(poly_key, zeros, 32, chacha_key, nonce, 0);
}


uint64_t aead_encrypt_baseline(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len, 
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b 
){
    uint8_t poly_key_buffer[KEY_SIZE_1305];
    poly1305_key_gen(poly_key_buffer, key_b, nonce_b);

    uint32_t block_ctr = 1;
    chacha20_encrypt_baseline(ciphertext_b, plaintext_b, plaintext_len, key_b, nonce_b, block_ctr);

    // If aad is not provided (=NULL), pass on the empty string
    const uint8_t *aad_or_empty   = (aad != NULL) ? aad  : (const uint8_t *)"";
    aad_len = (aad != NULL) ? aad_len : 0;

    uint64_t pad_aad_len = LEN_PAD16(aad_len);
    uint64_t pad_ctxt_len = LEN_PAD16(plaintext_len);

    uint64_t offset = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len;
    uint64_t mac_data_len = offset + 16;

    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);    
    memcpy(mac_data, aad_or_empty, aad_len);
    memset(mac_data + aad_len, 0, pad_aad_len);
    
    uint64_t ctxt_offset = aad_len + pad_aad_len;
    memcpy(mac_data + ctxt_offset, ciphertext_b, plaintext_len);
    memset(mac_data + ctxt_offset + plaintext_len, 0, pad_ctxt_len);

    uint64_t aad_len_le = (uint64_t)aad_len;
    uint64_t ctxt_len_le = (uint64_t)plaintext_len;
    memcpy(mac_data + offset, &aad_len_le, 8);
    memcpy(mac_data + offset + 8, &ctxt_len_le, 8);
    
    uint32_t acc[5], r[5], s[4];
    poly1305_init_baseline(acc, r, s, poly_key_buffer);
    uint8_t *tag = create_tag1305_baseline(acc, r, s, mac_data, mac_data_len);

    memcpy(ciphertext_b + plaintext_len, tag, TAG_SIZE_1305);

    free(tag);
    free(mac_data);

    uint64_t ciphertext_len = plaintext_len + TAG_SIZE_1305;

    return ciphertext_len;
}


uint64_t aead_encrypt_strength_reduction(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len, 
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b 
){
    uint8_t poly_key_buffer[KEY_SIZE_1305];
    poly1305_key_gen(poly_key_buffer, key_b, nonce_b);

    chacha20_encrypt_baseline(ciphertext_b, plaintext_b, plaintext_len, key_b, nonce_b, 1);

    bool aad_is_null = aad != NULL;
    const uint8_t *aad_or_empty   = aad_is_null ? aad  : (const uint8_t *)"";
    aad_len = aad_is_null ? aad_len : 0;

    uint64_t pad_aad_len = (-(aad_len)) & 15;
    uint64_t pad_ctxt_len = (-(plaintext_len)) & 15;
    uint64_t offset = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len;
    uint64_t mac_data_len = offset + 16;

    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);    
    memcpy(mac_data, aad_or_empty, aad_len);
    memset(mac_data + aad_len, 0, pad_aad_len);
    
    uint64_t ctxt_offset = aad_len + pad_aad_len;
    memcpy(mac_data + ctxt_offset, ciphertext_b, plaintext_len);
    memset(mac_data + ctxt_offset + plaintext_len, 0, pad_ctxt_len);

    uint64_t aad_len_le = (uint64_t)aad_len;
    uint64_t ctxt_len_le = (uint64_t)plaintext_len;
    memcpy(mac_data + offset, &aad_len_le, 8);
    memcpy(mac_data + offset + 8, &ctxt_len_le, 8);
    
    uint32_t acc[5], r[5], s[4];
    poly1305_init_baseline(acc, r, s, poly_key_buffer);
    uint8_t *tag = create_tag1305_baseline(acc, r, s, mac_data, mac_data_len);

    memcpy(ciphertext_b + plaintext_len, tag, TAG_SIZE_1305);

    free(tag);
    free(mac_data);

    return plaintext_len + TAG_SIZE_1305;
}

uint64_t aead_encrypt_best_scalar(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len, 
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b 
){
    uint8_t poly_key_buffer[KEY_SIZE_1305];
    poly1305_key_gen(poly_key_buffer, key_b, nonce_b);

    chacha20_encrypt_unroll_ilp_ctxt(ciphertext_b, plaintext_b, plaintext_len, key_b, nonce_b, 1);

    bool aad_is_null = aad != NULL;
    const uint8_t *aad_or_empty   = aad_is_null ? aad  : (const uint8_t *)"";
    aad_len = aad_is_null ? aad_len : 0;

    uint64_t pad_aad_len = (-(aad_len)) & 15;
    uint64_t pad_ctxt_len = (-(plaintext_len)) & 15;
    uint64_t offset = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len;
    uint64_t mac_data_len = offset + 16;

    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);    
    memcpy(mac_data, aad_or_empty, aad_len);
    memset(mac_data + aad_len, 0, pad_aad_len);
    
    uint64_t ctxt_offset = aad_len + pad_aad_len;
    memcpy(mac_data + ctxt_offset, ciphertext_b, plaintext_len);
    memset(mac_data + ctxt_offset + plaintext_len, 0, pad_ctxt_len);

    uint64_t aad_len_le = (uint64_t)aad_len;
    uint64_t ctxt_len_le = (uint64_t)plaintext_len;
    memcpy(mac_data + offset, &aad_len_le, 8);
    memcpy(mac_data + offset + 8, &ctxt_len_le, 8);
    
    uint32_t acc[5], r[5], s[4];
    poly1305_init_precompute_clamp_masks(acc, r, s, poly_key_buffer);
    uint8_t *tag = inlined_carry_delay_parallel_Horner(acc, r, s, mac_data, mac_data_len);

    memcpy(ciphertext_b + plaintext_len, tag, TAG_SIZE_1305);

    free(tag);
    free(mac_data);

    return plaintext_len + TAG_SIZE_1305;
}

uint64_t aead_encrypt_best_vectorized(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len, 
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b 
){
    uint8_t poly_key_buffer[KEY_SIZE_1305];
    poly1305_key_gen(poly_key_buffer, key_b, nonce_b);

    chacha20_encrypt_vectorized3(ciphertext_b, plaintext_b, plaintext_len, key_b, nonce_b, 1);

    bool aad_is_null = aad != NULL;
    const uint8_t *aad_or_empty   = aad_is_null ? aad  : (const uint8_t *)"";
    aad_len = aad_is_null ? aad_len : 0;

    uint64_t pad_aad_len = (-(aad_len)) & 15;
    uint64_t pad_ctxt_len = (-(plaintext_len)) & 15;
    uint64_t offset = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len;
    uint64_t mac_data_len = offset + 16;

    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);    
    memcpy(mac_data, aad_or_empty, aad_len);
    memset(mac_data + aad_len, 0, pad_aad_len);
    
    uint64_t ctxt_offset = aad_len + pad_aad_len;
    memcpy(mac_data + ctxt_offset, ciphertext_b, plaintext_len);
    memset(mac_data + ctxt_offset + plaintext_len, 0, pad_ctxt_len);

    uint64_t aad_len_le = (uint64_t)aad_len;
    uint64_t ctxt_len_le = (uint64_t)plaintext_len;
    memcpy(mac_data + offset, &aad_len_le, 8);
    memcpy(mac_data + offset + 8, &ctxt_len_le, 8);
    
    uint32_t acc[5], r[5], s[4];
    poly1305_init_vectorized(acc, r, s, poly_key_buffer);
    uint8_t *tag = memory_vect_inlined_carry_delay_parallel_Horner(acc, r, s, mac_data, mac_data_len);

    memcpy(ciphertext_b + plaintext_len, tag, TAG_SIZE_1305);

    free(tag);
    free(mac_data);

    return plaintext_len + TAG_SIZE_1305;
}

uint64_t aead_encrypt_openssl(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len,
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b
) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL);

    // Key and nonce must be set after cipher init, before encrypt
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, NONCE_SIZE_AEAD, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key_b, nonce_b);

    int outl = 0;
    if (aad && aad_len > 0)
        EVP_EncryptUpdate(ctx, NULL, &outl, aad, (int)aad_len);

    EVP_EncryptUpdate(ctx, ciphertext_b, &outl, plaintext_b, (int)plaintext_len);

    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext_b + outl, &final_len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_SIZE_1305, ciphertext_b + plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len + TAG_SIZE_1305;
}




uint64_t aead_decrypt_baseline(
    uint8_t *plaintext_b, const uint8_t *ciphertext_b, uint64_t ciphertext_len,
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b
){
    if (ciphertext_len < TAG_SIZE_1305){
        return AEAD_AUTH_FAIL;
    }

    uint64_t ctxt_len = ciphertext_len - TAG_SIZE_1305;
    const uint8_t *expected_tag = ciphertext_b + ctxt_len;
    uint8_t poly_key_buffer[KEY_SIZE_1305];
    poly1305_key_gen(poly_key_buffer, key_b, nonce_b);

    // If aad is not provided (=NULL), pass on the empty string
    const uint8_t *aad_or_empty   = (aad != NULL) ? aad  : (const uint8_t *)"";
    aad_len = (aad != NULL) ? aad_len : 0;

    // mac_data = aad | aad_pad | ctxt | ctxt_pad | |aad_len|_{64} | |ctxt_len|_{64}
    uint64_t pad_aad_len = LEN_PAD16(aad_len);
    uint64_t pad_ctxt_len = LEN_PAD16(ctxt_len);

    uint64_t offset = aad_len + pad_aad_len + ctxt_len + pad_ctxt_len;
    uint64_t mac_data_len = offset + 16;

    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);
    memcpy(mac_data, aad_or_empty, aad_len);
    memset(mac_data + aad_len , 0, pad_aad_len);
    memcpy(mac_data + aad_len + pad_aad_len, ciphertext_b, ctxt_len);
    memset(mac_data + aad_len + pad_aad_len + ctxt_len, 0, pad_ctxt_len);

    uint64_t aad_len_le = (uint64_t)aad_len;
    uint64_t ctxt_len_le = (uint64_t)ctxt_len;
    memcpy(mac_data + offset, &aad_len_le, 8);
    memcpy(mac_data + offset + 8, &ctxt_len_le, 8);

    uint32_t acc[5], r[5], s[4];
    poly1305_init_baseline(acc, r, s, poly_key_buffer);
    uint8_t *tag = create_tag1305_baseline(acc, r, s, mac_data, mac_data_len);

    int mismatch = memcmp(tag, expected_tag, TAG_SIZE_1305);

    free(tag);
    free(mac_data);

    if (mismatch != 0) {
        return AEAD_AUTH_FAIL;
    }

    chacha20_encrypt_baseline(plaintext_b, ciphertext_b, ctxt_len, key_b, nonce_b, 1);

    return ctxt_len;
}