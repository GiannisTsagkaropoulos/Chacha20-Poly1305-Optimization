#include <stdint.h>

typedef struct {
    uint64_t i_ops;
    uint64_t byte_transfer;
} complexity_t;

complexity_t get_chacha_complexity(int rounds);
complexity_t get_chacha_cipher_complexity(int rounds, uint64_t p_length);
