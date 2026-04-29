#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "chacha20.h"
#include <time.h>
#include "poly1305.h"
#include "chacha20-poly1305.h"

//p_length represents the length of plaintext in bytes
uint8_t* create_random_bytes(int p_length);

//key is 32 bytes
uint8_t* create_random_key();

//nonce is 12 bytes
uint8_t* create_random_nonce();

void chacha20_encryption_chosen_len(uint64_t p_length, uint8_t* plaintext_b, uint8_t* key_b, uint8_t* nonce_b);

void fill_random_key(uint8_t key[32]);

//in chacha the data is written as uint8_t while in poly as char, remenber to correct it
void poly1305_test(uint8_t key[32], uint8_t* data, uint64_t data_length);