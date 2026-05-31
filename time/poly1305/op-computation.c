#include "op_computations.h"

#define BLOCK_SIZE 16

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
    uint64_t num_of_blocks = data_len / 16;

    // 2 ops for (init)
    // num_full_blocks INC
    // for every block: (main_ops)
        // to_large_num_rep(17)
        // add_large_nums_55
        // mulmod_p
        // 1 ADD
    // add_large_nums_54
    // 1 MUL
    // to_16_le_bytes

    uint64_t main_ops = count_to_large_num_rep(17) + count_add_large_nums_55() + count_mulmod_p() + 1;
    uint64_t i_ops = 2 + num_of_blocks + num_of_blocks * main_ops + 1 + count_to_16_le_bytes();
    
    //TODO: add byte transfer
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
    uint64_t full_blocks = (data_len) / 16;
    uint64_t parallel_calc = full_blocks / 4;
    uint64_t num_of_blocks;

    // 3 ops for (init)
    // 6 MUL (memcpy)
    // parallel_calc INC
    // for every block: (main_ops)
        // 3 ADD
        // 4 * to_large_num_rep(17)
        // 4 * add_large_nums_55
        // 4 * mulmod_p
        // 1 ADD
        // 1 MUL
    // PARALLEL_BLOCKS INC = 4 INC (main_ops2)
    // for each: (main_ops2)
        // mulmod_p
        // add_large_nums_55
    //
    // (rest):
    // 1 MOD
    // 1 MUL
    // add_large_nums_54
    // 1 MUL (malloc)
    // to_16_le_bytes

    uint64_t main_ops0 = 3 + 4 * (count_to_large_num_rep(17) + count_add_large_nums_55() + count_mulmod_p()) + 1 + 1;
    uint64_t main_ops1 = 4 + 4 *(count_mulmod_p() + count_add_large_nums_55());
    uint64_t rest = 1 + 1 + count_add_large_nums_54() + 1 + count_to_16_le_bytes();
    uint64_t i_ops = 3 + 6 + parallel_calc + parallel_calc * main_ops0 + main_ops1 + rest;
    
    //TODO: add byte transfer
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
    uint64_t full_blocks = (data_len) / 16;
    uint64_t parallel_calc = full_blocks / 4;
    uint64_t num_of_blocks;

    // 4 ops for (init)
    // 13 MUL (memcpy)
    // parallel_calc INC
    // for every block: (main_ops)
        // 7 ADD
        // 8 * to_large_num_rep(17)
        // 8 * add_large_nums_55
        // 8 * mulmod_p
        // 2 MUL
        // 1 ADD
    // PARALLEL_BLOCKS INC = 4 INC (main_ops2)
    // for every block: (main_ops2)
        // mulmod_p
        // add_large_nums_55    
    // (rest):    
    // 1 MOD
    // 1 MUL
    // add_large_nums_54
    // 1 MUL (malloc)
    // to_16_le_bytes


    uint64_t main_ops0  = 7 + 8*(count_to_large_num_rep(17) + count_add_large_nums_55() + count_mulmod_p()) + 2 + 1;
    uint64_t main_ops1 = 4 + 4*(count_mulmod_p() + count_add_large_nums_55());
    uint64_t rest = 1 + 1 + count_add_large_nums_54() + 1 + count_to_16_le_bytes();

    uint64_t i_ops = 4 + 13 + parallel_calc + parallel_calc * main_ops0 + main_ops1 + rest;
    
    //TODO: add byte transfer
    uint64_t byte_transfer;


    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_create_tag_inlined_carry_delay_parallel_Horner_complexity(uint64_t data_len){
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

complexity_t get_create_tag_vect_inlined_carry_delay_parallel_Horner_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t full_blocks = (data_len) / 16;
    uint64_t parallel_calc = full_blocks / 4;
    uint64_t num_of_blocks;

    // 4 ops for (init)
    
    // 7 runs: (main_ops0)
        // 1 MUL (memcpy)
        // 5 INC (limbs)
        // MUL_MOD_P
        // CARRY_PROPAGATION
        // COMPUTE_MOD_P
        // 1 MUL (memcpy)
    //    
    // parallel_calc INC (main_ops1)
    // for every block: (main_ops1)
        // 7 ADD
        // 4 AND
        // 6 SHIFT
        // 2 OR
        // 8 INC
        // DOUBLE_MULTIPLICATION_ADDITION_VECT
        // CARRY_PROP_DELAYED_VECT
        // MOD_P_DELAYED_VECT
        // 2 MUL
        // 1 ADD
    //
    // PARALLEL_BLOCKS INC = 4 INC (main_ops2)
    // for every block:  (main_ops2)
        // 8 INC (limbs)
        // MUL_MOD_P
        // CARRY_PROPAGATION
        // COMPUTE_MOD_P
        // ADD_55 
    // 
    // (rest):
    // 1 MUL
    // 1 MOD
    // 4 OR
    // 7 SHIFT
    // 4 INC
    // for every inc:
        // 2 ADD
        // 1 SHIFT
    // 1 MUL (malloc)
    // 4 INC
    // for every inc:
        // 4 MUL
        // 3 ADD
        // 3 SHIFT
        // 4 AND

    uint64_t main_ops0 = 1 + 5 + count_MUL_MOD_P() + count_CARRY_PROPAGATION() + count_COMPUTE_MOD_P() + 1;
    uint64_t main_ops1 = parallel_calc + parallel_calc*(7+4+6+2+8 + count_DOUBLE_MULTIPLICATION_ADDITION_VECT() + count_CARRY_PROP_DELAYED_VECT() + count_MOD_P_DELAYED_VECT() + 2 + 1);
    uint64_t main_ops2 = 4 + 4*(8 + count_MUL_MOD_P() + count_CARRY_PROPAGATION() + count_COMPUTE_MOD_P() + count_ADD_55());
    uint64_t rest = 1 + 1 + 4 + 7 + 4 + 4*(2+1) + 1 + 4 + 4*(4+3+3+4);

    uint64_t i_ops = 4 + 7*main_ops0 + main_ops1 + main_ops2 + rest;
    
    //TODO: add byte transfer
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;

}    

complexity_t get_create_tag_memory_vect_inlined_carry_delay_parallel_Horner_complexity(uint64_t data_len){
    complexity_t c;
    uint64_t full_blocks = (data_len) / 16;
    uint64_t parallel_calc = full_blocks / 4;
    uint64_t num_of_blocks;

    // 4 ops for (init)
    
    // 7 runs: (main_ops0)
        // 1 MUL (memcpy)
        // 5 INC (limbs)
        // MUL_MOD_P
        // CARRY_PROPAGATION
        // COMPUTE_MOD_P
    //    
    // parallel_calc INC (main_ops1)
    // for every block: (main_ops1)
        // 8 ADD (array indices)
        // 20 AND256
        // 8 SRLI_64 = 8*4 SHIFT = 32 SHIFT
        // 4 SLLI_64 = 4*4 SHIFT = 16 SHIFT
        // 4 OR_SI256 
        // DOUBLE_MULTIPLICATION_ADDITION_VECT
        // CARRY_PROP_DELAYED_VECT
        // MOD_P_DELAYED_VECT
        // 2 MUL
        // 1 ADD
    //
    // NUM_LIMBS INC = 8 INC
    // PARALLEL_BLOCKS INC = 4 INC (main_ops2)
    // for every block:  (main_ops2)
        // 8 INC (limbs)
        // MUL_MOD_P
        // CARRY_PROPAGATION
        // COMPUTE_MOD_P
        // ADD_55 
    // 
    // (rest):
    // 1 MUL
    // 1 MOD
    // 4 OR
    // 7 SHIFT
    // 4 INC
    // for every inc:
        // 2 ADD
        // 1 SHIFT
    // 1 MUL (malloc)
    // 4 INC
    // for every inc:
        // 4 MUL
        // 3 ADD
        // 3 SHIFT
        // 4 AND


    uint64_t main_ops0 = 1 + 5 + count_MUL_MOD_P() + count_CARRY_PROPAGATION() + count_COMPUTE_MOD_P();
    uint64_t main_ops1 = parallel_calc + parallel_calc*(8 + 20 + 32 + 16 + 4 \
        + count_DOUBLE_MULTIPLICATION_ADDITION_VECT() + count_CARRY_PROP_DELAYED_VECT() + count_MOD_P_DELAYED_VECT() + 2 + 1);
    uint64_t main_ops2 = 4 + 4*(8 + count_MUL_MOD_P() + count_CARRY_PROPAGATION() + count_COMPUTE_MOD_P() + count_ADD_55());
    uint64_t rest = 1 + 1 + 4 + 7 + 4 + 4*(2+1) + 1 + 4 + 4*(4+3+3+4);

    uint64_t i_ops = 4 + 7*main_ops0 + 8 + main_ops1 + 8 + main_ops2 + rest;
    
    //TODO: add byte transfer
    uint64_t byte_transfer;

    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;

}    
