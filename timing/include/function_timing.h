#include <stdint.h>

typedef struct {
    uint64_t p_length;
    uint8_t* plaintext;
    uint8_t* key;
    uint8_t* nonce;
} chacha_args_t;

typedef struct {
    int* tests;
    int* fails;
} test_args_t;

typedef struct {
    uint64_t data_length;
    uint8_t* key;
    uint8_t* data;
} poly_args_t;

typedef struct {
    uint8_t* key_b;
    uint8_t* nonce_b;
    uint8_t* plaintext_b;
    uint64_t plaintext_len;
    uint8_t* data;
    size_t data_len;
    uint8_t *ciphertext_b;
} seal_args_t;