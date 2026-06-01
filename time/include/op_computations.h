#include <stdint.h>

typedef struct {
    uint64_t i_ops;
    uint64_t byte_transfer;
} complexity_t;

uint64_t count_MUL_MOD_P();
uint64_t count_CARRY_PROPAGATION();
uint64_t count_COMPUTE_MOD_P();
uint64_t count_ADD_55();
uint64_t count_DOUBLE_MULTIPLICATION_ADDITION();
uint64_t count_DOUBLE_MULTIPLICATION_ADDITION_VECT();
uint64_t count_CARRY_PROP_DELAYED();
uint64_t count_CARRY_PROP_DELAYED_VECT();
uint64_t count_MOD_P_DELAYED();
uint64_t count_MOD_P_DELAYED_VECT();
uint64_t count_to_large_num_rep();
uint64_t count_add_large_nums_55();
uint64_t count_mulmod_p();
uint64_t count_add_large_nums_54();
uint64_t count_to_16_le_bytes();

complexity_t get_chacha_baseline_complexity(uint64_t p_length);
complexity_t get_chacha_inline_complexity(uint64_t p_length);
complexity_t get_chacha_scalar_replacement_complexity(uint64_t p_length);
complexity_t get_chacha_unroll_ilp_ctxt_complexity(uint64_t p_length);
complexity_t chacha_encrypt_multiple_pt_blocks_at_once_complexity(uint64_t p_length);
complexity_t chacha_encrypt_multiple_pt_blocks_at_once2_complexity(uint64_t p_length);
complexity_t get_chacha_chacha_encrypt_2_complexity(uint64_t p_length);
complexity_t get_chacha_chacha_encrypt_vectorized2_complexity(uint64_t p_length);
complexity_t get_chacha_chacha_encrypt_vectorized3_complexity(uint64_t p_length);


complexity_t get_create_tag_baseline_complexity(uint64_t data_len);
complexity_t get_create_tag_not_inlined_complexity(uint64_t data_len);
complexity_t get_create_tag_inlined_complexity(uint64_t data_len);
complexity_t get_create_tag_not_inlined_parallel_Horner_complexity(uint64_t data_len);
complexity_t get_create_tag_inlined_parallel_Horner_complexity(uint64_t data_len);
complexity_t get_create_tag_carry_delay_complexity(uint64_t data_len);
complexity_t get_create_tag_inlined_carry_delay_parallel_Horner_complexity(uint64_t data_len);
complexity_t get_create_tag_vect_inlined_carry_delay_parallel_Horner_complexity(uint64_t data_len);
complexity_t get_create_tag_memory_vect_inlined_carry_delay_parallel_Horner_complexity(uint64_t data_len);

