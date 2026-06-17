#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include "poly2133_opt.h"
#include "poly2133_init_opts.h"
#include "chacha_opts.h"
#include "chacha20_poly2133.h"


void poly2133_key_gen(uint8_t poly_key[KEY_SIZE_2133], const uint8_t chacha_key[32], const uint8_t nonce[12]) {
    uint8_t zeros[KEY_SIZE_2133];
    memset(zeros, 0, KEY_SIZE_2133);

    chacha20_encrypt_baseline(poly_key, zeros, KEY_SIZE_2133, chacha_key, nonce, 0);
}


uint64_t chacha20_poly2133_encrypt_baseline(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len, 
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b 
){
    uint8_t poly_key_buffer[KEY_SIZE_2133];
    poly2133_key_gen(poly_key_buffer, key_b, nonce_b);

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
    
    uint32_t acc[LIMBS_2133], r[LIMBS_2133], s[LIMBS_2133];
    poly2133_init_baseline(acc, r, s, poly_key_buffer);
    uint8_t *tag = poly2133_create_tag_baseline(acc, r, s, mac_data, mac_data_len);

    memcpy(ciphertext_b + plaintext_len, tag, TAG_SIZE_2133);

    free(tag);
    free(mac_data);

    uint64_t ciphertext_len = plaintext_len + TAG_SIZE_2133;

    return ciphertext_len;
}


uint64_t chacha20_poly2133_encrypt_strength_reduction(
    uint8_t *ciphertext_b, const uint8_t *plaintext_b, uint64_t plaintext_len, 
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b 
){
    uint8_t poly_key_buffer[KEY_SIZE_2133];
    poly2133_key_gen(poly_key_buffer, key_b, nonce_b);

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
    
    uint32_t acc[LIMBS_2133], r[LIMBS_2133], s[LIMBS_2133];
    poly2133_init_baseline(acc, r, s, poly_key_buffer);
    uint8_t *tag = poly2133_create_tag_baseline(acc, r, s, mac_data, mac_data_len);

    memcpy(ciphertext_b + plaintext_len, tag, TAG_SIZE_2133);

    free(tag);
    free(mac_data);

    uint64_t ciphertext_len = plaintext_len + TAG_SIZE_2133;

    return ciphertext_len;
}



uint64_t chacha20_poly2133_decrypt_baseline(
    uint8_t *plaintext_b, const uint8_t *ciphertext_b, uint64_t ciphertext_len,
    const uint8_t *aad, uint64_t aad_len, const uint8_t *key_b, const uint8_t *nonce_b
){
    if (ciphertext_len < TAG_SIZE_2133){
        return AEAD_AUTH_FAIL;
    }

    uint64_t ctxt_len = ciphertext_len - TAG_SIZE_2133;
    const uint8_t *expected_tag = ciphertext_b + ctxt_len;
    uint8_t poly_key_buffer[KEY_SIZE_2133];
    poly2133_key_gen(poly_key_buffer, key_b, nonce_b);

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
    poly2133_init_baseline(acc, r, s, poly_key_buffer);
    uint8_t *tag = poly2133_create_tag_baseline(acc, r, s, mac_data, mac_data_len);

    int mismatch = memcmp(tag, expected_tag, TAG_SIZE_2133);

    free(tag);
    free(mac_data);

    if (mismatch != 0) {
        return AEAD_AUTH_FAIL;
    }

    chacha20_encrypt_baseline(plaintext_b, ciphertext_b, ctxt_len, key_b, nonce_b, 1);

    return ctxt_len;
}