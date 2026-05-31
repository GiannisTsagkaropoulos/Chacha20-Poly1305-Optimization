#include "op_computations.h"
#include "poly1305_tag_opt.h"

#define QR_PER_ROUND 8
#define LOADS_PER_QR   4
#define STORES_PER_QR  4
#define ADDS_PER_QR    4 
#define XORS_PER_QR    4
#define ROT_PER_QR     4
#define SHIFTS_PER_QR_VEC1   2
#define ORS_PER_QR_VEC1      1



complexity_t get_create_tag_baseline_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t byte_transfer;

/*  1 ADD , 1 DIV
    For loop on :
      1 MUL 
      1 SUB
      to_large_num_rep()
      add_large_nums_55()
      mulmod_p()
      1 INCREASE
    
    add_large_nums_54()
    to_16_le_bytes()
*/
    uint64_t i_ops = (data_len/BLOCK_SIZE) * (2 + compute_to_large_num_rep(17) + compute_add_large_nums_55() + compute_mulmod_p() +1)
    + compute_add_large_nums_54() + compute_to_16_le_bytes();
    

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_not_inlined_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_inlined_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t byte_transfer;
    /* 5 ADDS
   1 DIV, 1 DIV
*/
    uint64_t before_loop = 7;
/*
   For loop on data_len/16:
      1 ADD, 4 ANDS, 6 SHIFTS, 2 ORS

      For loop on 5 ---> 5*(1 ADD + 1 INCREASE)

      mult[0] = 4 ADDS, 5 MULTS
      mult[1] = 4 ADDS, 5 MULTS
      mult[2] = 4 ADDS, 5 MULTS
      mult[3] = 4 ADDS, 5 MULTS
      mult[4] = 4 ADDS, 5 MULTS

      For loop on 4
        1 RSHIFT, 1 AND, 2 ADDS
        1 INCREASE
     
      1 RSHIFT, 1 AND, 1 ADD, 1 MUL, 1 RSHIFT, 1 AND, 1 ADD
      -----> TOTAL = 7
*/
    uint64_t loop = (data_len/16)*(1+4+6+2 + 5*(2) + 4*(4+5) + 4*(1+1+2+1)) + 7;

/* for loop on 5:
    1 ADD, 1 AND, 1 RSHIFT
    1 INCREASE
    -----> 5*4

    For loop on 4:
      1 RSHIFT, 1 OR, 1 ADD, 1 LSHIFT
       1 SUB, 1 ADD
      1 INCREASE
    -----> 4*(7)

    For loop on 4:
        1 ADD, 1 AND, 1 ADD
        1 RSHIFT
        1 INCREASE
    ----> 4*(5)

    For loop on 4:
        4 MUL, 3 ADDS, 4 ANDS, 3 RSHIFTS
        1 INCREASE
    ---> 4*(15)

*/
    uint64_t i_ops = 5*4 + 4*7 + 4*(5) + 4*(15) + loop + before_loop;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_not_inlined_parallel_Horner_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_inlined_parallel_Horner_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t byte_transfer;

    /*  3 DIVS

    3 * (count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P()) 

    For loop on data_len/(16*4):
        4 * (  1 AND, 1 RSHIFT, 1 AND, 2 SHIFTS, 1 OR, 1 AND, 1 RSHIFT, 1 AND
               2 SHIFTS, 1 OR, 1 AND )
        
        4*(count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P())

        4*(count_ADD_55())

        1 INCREASE
                                     
*/
    uint64_t ops_loop = 3 + (data_len/(16*4)) * (4*(13) + 4*(count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P()) + 4*(count_ADD_55()) + 1 );

/* For loop on 4:
        4* count_mulmod_p()
        4* count_add_large_nums_55()
        1 INCREASE

    4 ORS, 7 SHIFTS

    For loop on 4:
        2 ADDS
        1 RSHIFT
        1 INCREASE

    For loop on 4:
        1 MUL, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 increases
*/
    uint64_t after_loop = 4*(4*count_mulmod_p()+ 4* count_add_large_nums_55() +1) + 4 + 7 + 4*(4) + 4*(15);

    uint64_t i_ops = after_loop + ops_loop;

    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_carry_delay_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_inlined_carry_delay_parallel_Horner_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_vect_inlined_carry_delay_parallel_Horner_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t byte_transfer;

    /*  3 DIVS, 1 MUL

    7* (count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P())

    For loop on (data_len/(16*8)):
        8 * (  1 AND, 1 RSHIFT, 1 AND, 2 SHIFTS, 1 OR, 1 AND, 1 RSHIFT, 1 AND
               2 SHIFTS, 1 OR, 1 AND )

        4*(count_DOUBLE_MULTIPLICATION_ADDITION + count_CARRY_PROP_DELAYED + count_MOD_P_DELAYED)
*/
    uint64_t ops_loop = 3 + 1 + (data_len/(16*8))*(8*(13) + 4*(count_DOUBLE_MULTIPLICATION_ADDITION() + count_CARRY_PROP_DELAYED() + count_MOD_P_DELAYED()));

    /* For loop on 4:
        4* count_mulmod_p()
        4* count_add_large_nums_55()
        1 INCREASE

    4 ORS, 7 SHIFTS

    For loop on 4:
        2 ADDS
        1 RSHIFT
        1 INCREASE

    For loop on 4:
        1 MUL, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 increases
*/
    uint64_t after_loop = 4*(4*count_mulmod_p()+ 4* count_add_large_nums_55() +1) + 4 + 7 + 4*(4) + 4*(15);

    uint64_t i_ops = after_loop + ops_loop;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_memory_vect_inlined_carry_delay_parallel_Horner_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t num_of_blocks;

    uint64_t main_ops;
    uint64_t i_ops;
    
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

