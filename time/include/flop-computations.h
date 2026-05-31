#include <stdint.h>

typedef struct {
    uint64_t i_ops;
    uint64_t byte_transfer;
} complexity_t;

complexity_t get_chacha_baseline_complexity(int rounds, uint64_t p_length);
complexity_t get_chacha_inline_complexity(int rounds, uint64_t p_length);
complexity_t get_chacha_scalar_replacement_complexity(int rounds, uint64_t p_length);
complexity_t get_chacha_unroll_ilp_ctxt_complexity(int rounds, uint64_t p_length);
complexity_t chacha_encrypt_multiple_pt_blocks_at_once_complexity(int rounds, uint64_t p_length);
complexity_t chacha_encrypt_multiple_pt_blocks_at_once2_complexity(int rounds, uint64_t p_length);
complexity_t get_chacha_chacha_encrypt_2_complexity(int rounds, uint64_t p_length);
complexity_t get_chacha_chacha_encrypt_vectorized2_complexity(int rounds, uint64_t p_length);
complexity_t get_chacha_chacha_encrypt_vectorized3_complexity(int rounds, uint64_t p_length);
