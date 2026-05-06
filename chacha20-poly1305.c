#include "chacha20.h"
#include "chacha20-poly1305.h"
#include "poly1305.c"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

void poly1305_key_gen(uint8_t *poly_key_buffer, const uint8_t *key_b, const uint8_t *nonce_b){
    uint32_t block_ctr = 0; 

    uint8_t keystream_b[STATE_SIZE_B];
    chacha20_block(keystream_b, key_b, nonce_b, block_ctr);
    memcpy(poly_key_buffer, keystream_b, POLY1305_KEY_SIZE);  

    memset(keystream_b, 0, STATE_SIZE_B);
}

/* creates zero-padding for Associated Authenticated Data and stores it in padding*, returns size of padding*/
size_t pad16(size_t data_len, uint8_t *padding){
    size_t pad = (16 - (data_len % 16)) % 16;
    memset(padding, 0, pad);
    return pad;
}   

/* Encrypts and authenticates plaintext using nonce and data. Stores the ciphertext (consisting of the encrypted plaintext and tag concatenated) in ciphertext_b*/
size_t seal(const uint8_t *key_b, /*32 bytes*/
    const uint8_t *nonce_b, /*12 bytes*/ 
    const uint8_t *plaintext_b, size_t plaintext_len, 
    const uint8_t *data, size_t data_len,
    uint8_t *ciphertext_b){

    uint8_t otk[POLY1305_KEY_SIZE];
    poly1305_key_gen(key_b, nonce_b, otk);

    // block counter = 1
    chacha20_encrypt(key_b, nonce_b, 1,
                        plaintext_b, plaintext_len, ROUNDS,
                        ciphertext_b);

    size_t pad1 = (16 - (data_len % 16)) % 16;
    size_t pad2 = (16 - (plaintext_len % 16)) % 16;

    size_t mac_data_len = data_len + pad1 + plaintext_len + pad2 + 16;

    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);
    
    size_t off = 0; // offset in memory from beginning of mac_data array
    memcpy(mac_data + off, data, data_len);
    off += data_len;
    pad16(data_len,mac_data + off);                     
    off += pad1;
    memcpy(mac_data + off, ciphertext_b, plaintext_len);     
    off += plaintext_len;
    pad16(plaintext_len, mac_data + off);
    off += pad2;  

    // Poly1305 input has to be 8-byte little endian int (RFC 7539 §2.8.1)
    // struct.pack('<Q', len(data))
    uint64_t aad_len_le = (uint64_t)data_len;
    for (int i = 0; i < 8; i++) {
        // shifts data length to the right and casts it to uint8_t, only capturing the least significant bits each time
        mac_data[off + i] = (uint8_t)(aad_len_le >> (8 * i));
    } 
    off += 8;

    // struct.pack('<Q', len(ciphertext))
    uint64_t ct_len_le  = (uint64_t)plaintext_len;
    for (int i = 0; i < 8; i++) {
        mac_data[off + i] = (uint8_t)(ct_len_le  >> (8 * i));
    }
    off += 8;

    // tag = Poly1305(otk).create_tag(mac_data)
    uint32_t acc[5], r[5], s[4];
    poly1305_init(acc, r, s, otk);
    uint8_t *tag = create_tag(acc, r, s, mac_data, mac_data_len);

    memcpy(ciphertext_b + plaintext_len, tag, TAG_LENGTH);

    free(tag);
    free(mac_data);

    size_t ciphertext_len = plaintext_len + TAG_LENGTH;

    return ciphertext_len;
}

// wrapper function for the seal function
size_t encrypt(const uint8_t *key_b, const uint8_t *nonce_b,
    const uint8_t *plaintext_b, size_t plaintext_len,
    const uint8_t *aad,         size_t aad_len,
    uint8_t       *ciphertext_b) {

    //if aad is not provided (=NULL), pass on the empty string
    const uint8_t *aad_or_empty;
    if (aad != NULL) {
        aad_or_empty = aad;
    } else {
        aad_or_empty = (const uint8_t *)"";
    }

    return seal(key_b, nonce_b, plaintext_b, plaintext_len, aad_or_empty, aad_len, ciphertext_b);
}

#define AEAD_AUTH_FAIL ((size_t)-1)



/* Verifies and decrypts (ciphertext || tag) using nonce and AAD. 
 on success, stores plaintext in plaintext_b and returns its length
 on authentication faliour, returns AEAD_AUTH_FAIL without changing plaintext*/
size_t open(const uint8_t *key_b,
    const uint8_t *nonce_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *data, size_t data_len,
    uint8_t *plaintext_b) {

    if (ciphertext_len < TAG_LENGTH){
        return AEAD_AUTH_FAIL;
    }

    size_t ct_len = ciphertext_len - TAG_LENGTH;
    const uint8_t *expected_tag = ciphertext_b + ct_len;

    /* otk = poly1305_key_gen(key, nonce) */
    uint8_t otk[POLY1305_KEY_SIZE];
    poly1305_key_gen(key_b, nonce_b, otk);

    // mac_data = data || pad1 || ct || pad2 || data_len || ct_len
    size_t pad1 = (16 - (data_len % 16)) % 16;
    size_t pad2 = (16 - (ct_len   % 16)) % 16;
    size_t mac_data_len = data_len + pad1 + ct_len + pad2 + 16;

    uint8_t *mac_data = (uint8_t *)malloc(mac_data_len);

    size_t off = 0;
    memcpy(mac_data + off, data, data_len);            
    off += data_len;
    pad16(data_len, mac_data + off);                   
    off += pad1;
    memcpy(mac_data + off, ciphertext_b, ct_len);      
    off += ct_len;
    pad16(ct_len, mac_data + off);                     
    off += pad2;

    /* struct.pack('<Q', len(data)) */
    uint64_t aad_len_le = (uint64_t)data_len;
    for (int i = 0; i < 8; i++) {
        mac_data[off + i] = (uint8_t)(aad_len_le >> (8 * i));
    }
    off += 8;

    /* struct.pack('<Q', len(ciphertext)) */
    uint64_t ct_len_le = (uint64_t)ct_len;
    for (int i = 0; i < 8; i++) {
        mac_data[off + i] = (uint8_t)(ct_len_le >> (8 * i));
    }
    off += 8;

    /* tag = Poly1305(otk).create_tag(mac_data) */
    uint32_t acc[5], r[5], s[4];
    poly1305_init(acc, r, s, otk);
    uint8_t *tag = create_tag(acc, r, s, mac_data, mac_data_len);

    int mismatch = memcmp(tag, expected_tag, TAG_LENGTH); // memcmp simplifys side channel attacks

    free(tag);
    free(mac_data);

    if (mismatch != 0) {
        return AEAD_AUTH_FAIL;
    }

    chacha20_encrypt(key_b, nonce_b, 1, ciphertext_b, ct_len, ROUNDS, plaintext_b);

    return ct_len;
}



//wrapper function for the open function
size_t decrypt(const uint8_t *key_b, const uint8_t *nonce_b,
    const uint8_t *ciphertext_b, size_t ciphertext_len,
    const uint8_t *aad,           size_t aad_len,
    uint8_t       *plaintext_b) {

    //if aad is not provided (=NULL), pass on the empty string
    const uint8_t *aad_or_empty;
    if (aad != NULL) {
        aad_or_empty = aad;
    } else {
        aad_or_empty = (const uint8_t *)"";
    }

    return open(key_b, nonce_b, ciphertext_b, ciphertext_len, aad_or_empty, aad_len, plaintext_b);
}