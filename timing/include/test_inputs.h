#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "chacha20.h"
#include <time.h>
#include "poly1305.h"
#include "poly2133.h"
#include "chacha20-poly1305.h"

//p_length represents the length of plaintext in bytes
uint8_t* create_random_bytes(int p_length);

//key is 32 bytes
uint8_t* create_random_key();

//nonce is 12 bytes
uint8_t* create_random_nonce();

int chacha20_encryption_chosen_len(uint64_t p_length, uint8_t* plaintext_b, uint8_t* key_b, uint8_t* nonce_b);

void fill_random_key(uint8_t key[32]);

void fill_random_key_54(uint8_t key[54]);

//in chacha the data is written as uint8_t while in poly as char, remenber to correct it
int poly1305_test(uint64_t data_length, uint8_t* key, uint8_t* data);

//in chacha the data is written as uint8_t while in poly as char, remenber to correct it
int poly2133_test(uint64_t data_length, uint8_t* key, uint8_t* data);

void seal_test(const uint8_t *key_b, /*32 bytes*/
    const uint8_t *nonce_b, /*12 bytes*/ 
    const uint8_t *plaintext_b, size_t plaintext_len, 
    const uint8_t *data, size_t data_len,
    uint8_t *ciphertext_b);