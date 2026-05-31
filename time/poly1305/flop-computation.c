#include "flop-computations.h"
#include "poly1305_tag_opt.h"

#define QR_PER_ROUND 8
#define LOADS_PER_QR   4
#define STORES_PER_QR  4
#define ADDS_PER_QR    4 
#define XORS_PER_QR    4
#define ROT_PER_QR     4
#define SHIFTS_PER_QR_VEC1   2
#define ORS_PER_QR_VEC1      1



complexity_t get_create_tag_baseline_complexity(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    complexity_t c;

    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;

    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_not_inlined_complexity(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_inlined_complexity(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_not_inlined_parallel_Horner_complexity(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_inlined_parallel_Horner_complexity(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_carry_delay_complexity(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_inlined_carry_delay_parallel_Horner_complexity(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_vect_inlined_carry_delay_parallel_Horner_complexity(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_memory_vect_inlined_carry_delay_parallel_Horner_complexity(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}




// complexity_t c;
// uint64_t num_of_blocks = p_length / STATE_SIZE_B;

// // 3 ops for (num_full_blocks, remainder)
// // num_full_blocks INC
// // for every plaintext block:
//     // 1 DIV (compute double rounds)
//     // 10 INC (1 for every double round)
//     // 80 QR = 80*(4 ADD + 4 XOR + 4 ROT) = 80*(4 ADD + 4 XOR + 4*(2 SHIFT + 1 SUB + 1 OR) ) =  80*24 = 1920 ops 
//     // 16 INC (working state)
//     // 16 ADD (working state)
//     // 64 INC  (compute ctxts)
//     // 64*2 ADD (array indices in ciphertext)
//     // 64 XOR
//     // 1 INC + 1 ADD in the end
// uint64_t main_ops = 1 + 10 + 1920 + 16 + 16 + 64 + 2*64 + 64 + 1 + 1;
// uint64_t i_ops = 3 + num_of_blocks + num_of_blocks * main_ops;

// // 44 B (key and nonce) 
// // 2*p_length B (load full plaintext and ciphertext)
// uint64_t byte_transfer = 44 + 2*p_length;

// c.i_ops = i_ops;
// c.byte_transfer = byte_transfer;
// return c;
