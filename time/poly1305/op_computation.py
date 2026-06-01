#!/usr/bin/env python3

BLOCK_SIZE = 16

def count_MUL_MOD_P():
    # mult[0] = 4 ADDS, 9 MULTS
    # mult[1] = 4 ADDS, 8 MULTS
    # mult[2] = 4 ADDS, 7 MULTS
    # mult[3] = 4 ADDS, 6 MULTS
    # mult[4] = 4 ADDS, 5 MULTS
    ops = 4 + 9 + 4 + 8 + 4 + 7 + 4 + 6 + 4 + 5
    return ops

def count_CARRY_PROPAGATION():
    # For loop on 4:
    #   1 SRIGHT, 1 AND, 2 ADDS
    #   1 INCREASE
    # ------> TOTAL = 4*(1+1+2) + 4
    # 1 SRIGHT, 1 AND
    # 1 ADD, 1 MULT, 1 SRIGHT, 1 AND, 1 ADD
    ops = 4 * (1 + 1 + 2) + 4 + 7
    return ops

def count_COMPUTE_MOD_P():
    # 1 ADD
    # For loop on 4:
    #   1 AND, 1 SRIGHT, 2 ADDS
    # ------> TOTAL = 4*(1+1+2) + 4 increases
    # 1 AND, 1 SRIGHT
    ops = 4 * (1 + 1 + 2) + 4 + 1 + 1
    return ops

def count_DOUBLE_MULTIPLICATION_ADDITION():
    # mult[0] = 18 MULTS, 9 ADDS
    # mult[1] = 16 MULTS, 9 ADDS
    # mult[2] = 14 MULTS, 9 ADDS
    # mult[3] = 12 MULTS, 9 ADDS
    # mult[4] = 10 MULTS, 9 ADDS
    # 4 ADDS
    ops = 18 + 9 + 16 + 9 + 14 + 9 + 12 + 9 + 10 + 9 + 4 + 4
    return ops

def count_CARRY_PROP_DELAYED():
    # For loop on 4
    #     1 RSHIFT, 1 AND, 2 ADDS
    #     1 INCREASE
    # 1 RSHIFT, 1 AND, 1 ADD, 1 MUL, 1 RSHIFT, 1 AND, 1 ADD
    ops = 4 * (5) + 1 + 1 + 1 + 1 + 1 + 1 + 1
    return ops

def count_MOD_P_DELAYED():
    # 1 ADD
    # For loop on 4:
    #     1 AND, 1 RSHIFT, 2 ADDS
    #     1 INCREASE
    # 1 ADD 1 RSHIFT
    ops = 4 * (5) + 2
    return ops

def count_ADD_55():
    # For loop on 5:
    #     2 ADDS
    #     1 AND
    #     1 RSHIFT
    #     1 INCREASE
    # 1 ADD, 1 MUL
    ops = 5 * (2 + 1 + 1 + 1) + 1 + 1
    return ops

def count_to_large_num_rep():
    # For loop on len_bytes:
    #     1 DIV
    #     1 OR
    #     1 LSHIFT
    #     1 DIV
    #     1 MUL
    # -----------> TOT = 17*5 + 17 increases
    # 1 AND
    # For loop on 4:
    #     1 ADD
    #     2 RSHIFT 
    #     1 OR
    #     1 AND
    #     1 ADD
    #     1 ADD
    #     1 SUB
    # -------------> TOTAL = 4*8 + 4 increases
    # //len_bytes always 17
    ops = 32 + 5 + 17 + 17 * 5
    return ops

def count_add_large_nums_55():
    # For loop on 5:
    #     2 ADDS
    #     1 AND
    #     1 RSHIFT
    # ------------> 5*4 + 5 INCREASES
    # 1 ADD
    # 1 MUL
    ops = 5 * 4 + 5 + 2
    return ops

def count_mulmod_p():
    # 5 INCR
    # mult[0] = 4 ADDS, 9 MULTS
    # ...
    ops_mult = 5 + 4 + 9 + 4 + 8 + 4 + 7 + 4 + 4 + 6 + 4 + 5
    ops_after = 4 * (1 + 1 + 2) + 4 + 8 + 4 * (1 + 1 + 2) + 4 + 1 + 1
    total_ops = ops_mult + ops_after
    return total_ops

def count_add_large_nums_54():
    # 1 MUL
    # For loop on 4:
    #   1 RSHIFT, 1 OR, 1 ADD, 1 LSHIFT
    #   1 ADD, 1 SUB
    # ---------------> TOTAL = 4*(6) + 4
    # For loop on 4:
    #   1 ADD, 1 AND, 1 ADD
    #   1 RSHIFT
    # ------------> TOTAL = 4*(4) + 4
    ops = 4 * (6) + 4 + 4 * (4) + 4
    return ops

def count_to_16_le_bytes():
    # For loop on 4:
    #  1 MUL, 1 AND...
    # ------> + 4 increases
    ops = 4 * (2 + 4 + 4 + 4) + 4
    return ops

def count_DOUBLE_MULTIPLICATION_ADDITION_VECT():
    # 50 ADD64 = 50 * 4 ADD = 200 ADD
    # 70 MUL32 = 79 * 8 MUL = 560 MUL
    ops = 200 + 560
    return ops

def count_CARRY_PROP_DELAYED_VECT():
    # 6 SHIFT_R64 = 6 * 4 SHIFT = 24 SHIFT
    # 6 ADD64 = 6 * 4 ADD = 24 ADD
    # 6 AND256
    ops = 24 + 24 + 6
    return ops

def count_MOD_P_DELAYED_VECT():
    # 4 INC
    # 5 ADD64 = 5 * 4 ADD = 20 ADD
    # 4 ADD (index ops)
    # 5 AND256
    # 5 SHIFT_R64 = 5 * 4 SHIFT = 20 SHIFT 
    ops = 4 + 20 + 4 + 5 + 20
    return ops


def get_poly1305_init_baseline_complexity():
    # 1 DIV
    # 7 AND
    # 1 ADD (array index create_limbs_64)
    # 5 SHIFT
    # 1 OR
    # 5 AND
    i_ops = 1 + 7 + 1 + 5 + 1 +5
    return i_ops

def get_poly1305_init_precompute_clamp_masks_complexity():
    # 5 ADD (array indices key and s)
    # 4 SHIFT
    # 5 AND
    i_ops = 5 + 4 + 5
    return i_ops


def get_poly1305_init_vectorized_complexity():
    # 1 SHIFT32 = 8 SHIFT
    # 1 AND128 = 2 AND
    # 2 ADD (index ops)
    # 1 SHIFT
    # 1 AND
    
    i_ops = 8 + 2 + 2 + 1 + 1
    return i_ops


def get_create_tag1305_baseline_complexity(data_len: int):  

    # 1 ADD , 1 DIV
    # For loop on :
    #   1 MUL 
    #   1 SUB
    #   to_large_num_rep()
    #   add_large_nums_55()
    #   mulmod_p()
    #   1 INCREASE
    
    # add_large_nums_54()
    # to_16_le_bytes()

    i_ops = (data_len // BLOCK_SIZE) * (2 + count_to_large_num_rep() + count_add_large_nums_55() + count_mulmod_p() + 1) \
            + count_add_large_nums_54() + count_to_16_le_bytes()
            
    return i_ops

def get_not_inlined_create_tag_complexity(data_len: int):
    num_of_blocks = data_len // 16

    # 2 ops for (init)
    # num_full_blocks INC
    # for every block: (main_ops)
        # to_large_num_rep(17)
        # add_large_nums_55
        # mulmod_p
        # 1 ADD
    # add_large_nums_54
    # 1 MUL
    # to_16_le_bytes

    main_ops = count_to_large_num_rep() + count_add_large_nums_55() + count_mulmod_p() + 1
    i_ops = 2 + num_of_blocks + num_of_blocks * main_ops + 1 + count_to_16_le_bytes()
    
    return i_ops

def get_inlined_create_tag_complexity(data_len: int):
    # 5 ADDS
    # 1 DIV
    # 1 DIV

    before_loop = 7
    
    
    # For loop on data_len/16:
    #     1 ADD, 4 ANDS, 6 SHIFTS, 2 ORS
    #
    #     For loop on 5 ---> 5*(1 ADD + 1 INCREASE)
    #
    #     mult[0] = 4 ADDS, 5 MULTS
    #     mult[1] = 4 ADDS, 5 MULTS
    #     mult[2] = 4 ADDS, 5 MULTS
    #     mult[3] = 4 ADDS, 5 MULTS
    #     mult[4] = 4 ADDS, 5 MULTS
    #
    #     For loop on 4
    #     1 RSHIFT, 1 AND, 2 ADDS
    #     1 INCREASE
    #   
    #     1 RSHIFT, 1 AND, 1 ADD, 1 MUL, 1 RSHIFT, 1 AND, 1 ADD
    #     -----> TOTAL = 7

    loop = (data_len // 16) * (1 + 4 + 6 + 2 + 5 * (2) + 4 * (4 + 5) + 4 * (1 + 1 + 2 + 1)) + 7

    # for loop on 5:
    #     1 ADD, 1 AND, 1 RSHIFT
    #     1 INCREASE
    #     -----> 5*4

    #     For loop on 4:
    #       1 RSHIFT, 1 OR, 1 ADD, 1 LSHIFT
    #        1 SUB, 1 ADD
    #       1 INCREASE
    #     -----> 4*(7)

    #     For loop on 4:
    #         1 ADD, 1 AND, 1 ADD
    #         1 RSHIFT
    #         1 INCREASE
    #     ----> 4*(5)

    #     For loop on 4:
    #         4 MUL, 3 ADDS, 4 ANDS, 3 RSHIFTS
    #         1 INCREASE
    #     ---> 4*(15)


    i_ops = 5 * 4 + 4 * 7 + 4 * (5) + 4 * (15) + loop + before_loop
    
    return i_ops

def get_not_inlined_parallel_Horner_create_tag_complexity(data_len: int):
    full_blocks = data_len // 16
    parallel_calc = full_blocks // 4
    
    # 3 ops for (init)
    # 6 MUL (memcpy)
    # parallel_calc INC
    # for every block: (main_ops)
        # 3 ADD
        # 4 * to_large_num_rep(17)
        # 4 * add_large_nums_55
        # 4 * mulmod_p
        # 1 ADD
        # 1 MUL
    # PARALLEL_BLOCKS INC = 4 INC (main_ops2)
    # for each: (main_ops2)
        # mulmod_p
        # add_large_nums_55
    #
    # (rest):
    # 1 MOD
    # 1 MUL
    # add_large_nums_54
    # 1 MUL (malloc)
    # to_16_le_bytes

    main_ops0 = 3 + 4 * (count_to_large_num_rep() + count_add_large_nums_55() + count_mulmod_p()) + 1 + 1
    main_ops1 = 4 + 4 * (count_mulmod_p() + count_add_large_nums_55())
    rest = 1 + 1 + count_add_large_nums_54() + 1 + count_to_16_le_bytes()
    
    i_ops = 3 + 6 + parallel_calc + parallel_calc * main_ops0 + main_ops1 + rest
    
    return i_ops

def get_inlined_parallel_Horner_create_tag_complexity(data_len: int):

    # 3 DIVS
    # 3 * (count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P()) 
    # For loop on data_len/(16*4):
    #     4 * (  1 AND, 1 RSHIFT, 1 AND, 2 SHIFTS, 1 OR, 1 AND, 1 RSHIFT, 1 AND
    #            2 SHIFTS, 1 OR, 1 AND )
    #     4*(count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P())
    #     4*(count_ADD_55())
    #     1 INCREASE
                                    
    
    ops_loop = 3 + (data_len // (16 * 4)) * (4 * (13) + 4 * (count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P()) + 4 * (count_ADD_55()) + 1)

    # For loop on 4:
    #     4* count_mulmod_p()
    #     4* count_add_large_nums_55()
    #     1 INCREASE

    # 4 ORS, 7 SHIFTS

    # For loop on 4:
    #     2 ADDS
    #     1 RSHIFT
    #     1 INCREASE

    # For loop on 4:
    #     1 MUL, 1 AND
    #     1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    #     1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    #     1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    #     1 increases



    after_loop = 4 * (4 * count_mulmod_p() + 4 * count_add_large_nums_55() + 1) + 4 + 7 + 4 * (4) + 4 * (15)
    
    i_ops = after_loop + ops_loop
    return i_ops

def get_carry_delay_complexity(data_len: int):
    full_blocks = data_len // 16
    parallel_calc = full_blocks // 4
    
    # 4 ops for (init)
    # 13 MUL (memcpy)
    # parallel_calc INC
    # for every block: (main_ops)
        # 7 ADD
        # 8 * to_large_num_rep(17)
        # 8 * add_large_nums_55
        # 8 * mulmod_p
        # 2 MUL
        # 1 ADD
    # PARALLEL_BLOCKS INC = 4 INC (main_ops2)
    # for every block: (main_ops2)
        # mulmod_p
        # add_large_nums_55    
    # (rest):    
    # 1 MOD
    # 1 MUL
    # add_large_nums_54
    # 1 MUL (malloc)
    # to_16_le_bytes

    main_ops0 = 7 + 8 * (count_to_large_num_rep() + count_add_large_nums_55() + count_mulmod_p()) + 2 + 1
    main_ops1 = 4 + 4 * (count_mulmod_p() + count_add_large_nums_55())
    rest = 1 + 1 + count_add_large_nums_54() + 1 + count_to_16_le_bytes()
    
    i_ops = 4 + 13 + parallel_calc + parallel_calc * main_ops0 + main_ops1 + rest
    
    return i_ops

def get_inlined_carry_delay_parallel_Horner_complexity(data_len: int):

    # 3 DIVS, 1 MUL
    # 7* (count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P())
    # For loop on (data_len/(16*8)):
    #     8 * (  1 AND, 1 RSHIFT, 1 AND, 2 SHIFTS, 1 OR, 1 AND, 1 RSHIFT, 1 AND
    #             2 SHIFTS, 1 OR, 1 AND )
    #     4*(count_DOUBLE_MULTIPLICATION_ADDITION + count_CARRY_PROP_DELAYED + count_MOD_P_DELAYED)
    ops_loop = 3 + 1 + (data_len // (16 * 8)) * (8 * (13) + 4 * (count_DOUBLE_MULTIPLICATION_ADDITION() + count_CARRY_PROP_DELAYED() + count_MOD_P_DELAYED()))

    # For loop on 4:
    #     4* count_mulmod_p()
    #     4* count_add_large_nums_55()
    #     1 INCREASE

    # 4 ORS, 7 SHIFTS

    # For loop on 4:
    #     2 ADDS
    #     1 RSHIFT
    #     1 INCREASE

    # For loop on 4:
    #     1 MUL, 1 AND
    #     1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    #     1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    #     1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    #     1 increases

    after_loop = 4 * (4 * count_mulmod_p() + 4 * count_add_large_nums_55() + 1) + 4 + 7 + 4 * (4) + 4 * (15)
    
    i_ops = after_loop + ops_loop
    return i_ops

def get_vect_inlined_carry_delay_parallel_Horner_complexity(data_len: int):
    full_blocks = data_len // 16
    parallel_calc = full_blocks // 4

        # 4 ops for (init)
    # 7 runs: (main_ops0)
        # 1 MUL (memcpy)
        # 5 INC (limbs)
        # MUL_MOD_P
        # CARRY_PROPAGATION
        # COMPUTE_MOD_P
        # 1 MUL (memcpy)
    #    
    # parallel_calc INC (main_ops1)
    # for every block: (main_ops1)
        # 7 ADD
        # 4 AND
        # 6 SHIFT
        # 2 OR
        # 8 INC
        # DOUBLE_MULTIPLICATION_ADDITION_VECT
        # CARRY_PROP_DELAYED_VECT
        # MOD_P_DELAYED_VECT
        # 2 MUL
        # 1 ADD
    #
    # PARALLEL_BLOCKS INC = 4 INC (main_ops2)
    # for every block:  (main_ops2)
        # 8 INC (limbs)
        # MUL_MOD_P
        # CARRY_PROPAGATION
        # COMPUTE_MOD_P
        # ADD_55 
    # 
    # (rest):
    # 1 MUL
    # 1 MOD
    # 4 OR
    # 7 SHIFT
    # 4 INC
    # for every inc:
        # 2 ADD
        # 1 SHIFT
    # 1 MUL (malloc)
    # 4 INC
    # for every inc:
        # 4 MUL
        # 3 ADD
        # 3 SHIFT
        # 4 AND
    
    main_ops0 = 1 + 5 + count_MUL_MOD_P() + count_CARRY_PROPAGATION() + count_COMPUTE_MOD_P() + 1
    main_ops1 = parallel_calc + parallel_calc * (7 + 4 + 6 + 2 + 8 + count_DOUBLE_MULTIPLICATION_ADDITION_VECT() + count_CARRY_PROP_DELAYED_VECT() + count_MOD_P_DELAYED_VECT() + 2 + 1)
    main_ops2 = 4 + 4 * (8 + count_MUL_MOD_P() + count_CARRY_PROPAGATION() + count_COMPUTE_MOD_P() + count_ADD_55())
    rest = 1 + 1 + 4 + 7 + 4 + 4 * (2 + 1) + 1 + 4 + 4 * (4 + 3 + 3 + 4)
    
    i_ops = 4 + 7 * main_ops0 + main_ops1 + main_ops2 + rest
    
    return i_ops

def get_memory_vect_inlined_carry_delay_parallel_Horner_complexity(data_len: int):
    full_blocks = data_len // 16
    parallel_calc = full_blocks // 4
    
    # 4 ops for (init)
    
    # 7 runs: (main_ops0)
        # 1 MUL (memcpy)
        # 5 INC (limbs)
        # MUL_MOD_P
        # CARRY_PROPAGATION
        # COMPUTE_MOD_P
    #    
    # parallel_calc INC (main_ops1)
    # for every block: (main_ops1)
        # 8 ADD (array indices)
        # 20 AND256
        # 8 SRLI_64 = 8*4 SHIFT = 32 SHIFT
        # 4 SLLI_64 = 4*4 SHIFT = 16 SHIFT
        # 4 OR_SI256 
        # DOUBLE_MULTIPLICATION_ADDITION_VECT
        # CARRY_PROP_DELAYED_VECT
        # MOD_P_DELAYED_VECT
        # 2 MUL
        # 1 ADD
    #
    # NUM_LIMBS INC = 8 INC
    # PARALLEL_BLOCKS INC = 4 INC (main_ops2)
    # for every block:  (main_ops2)
        # 8 INC (limbs)
        # MUL_MOD_P
        # CARRY_PROPAGATION
        # COMPUTE_MOD_P
        # ADD_55 
    # 
    # (rest):
    # 1 MUL
    # 1 MOD
    # 4 OR
    # 7 SHIFT
    # 4 INC
    # for every inc:
        # 2 ADD
        # 1 SHIFT
    # 1 MUL (malloc)
    # 4 INC
    # for every inc:
        # 4 MUL
        # 3 ADD
        # 3 SHIFT
        # 4 AND
    main_ops0 = 1 + 5 + count_MUL_MOD_P() + count_CARRY_PROPAGATION() + count_COMPUTE_MOD_P()
    main_ops1 = parallel_calc + parallel_calc * (8 + 20 + 32 + 16 + 4 + count_DOUBLE_MULTIPLICATION_ADDITION_VECT() + count_CARRY_PROP_DELAYED_VECT() + count_MOD_P_DELAYED_VECT() + 2 + 1)
    main_ops2 = 4 + 4 * (8 + count_MUL_MOD_P() + count_CARRY_PROPAGATION() + count_COMPUTE_MOD_P() + count_ADD_55())
    rest = 1 + 1 + 4 + 7 + 4 + 4 * (2 + 1) + 1 + 4 + 4 * (4 + 3 + 3 + 4)
    
    i_ops = 4 + 7 * main_ops0 + 8 + main_ops1 + 8 + main_ops2 + rest
    
    return i_ops

def get_poly1305_create_tag_openssl_complexity(p_length: int):
    # 4 OR
    # 5 SHIFTS
    our_wrapper = 4 + 5

    vec_ops = get_memory_vect_inlined_carry_delay_parallel_Horner_complexity(p_length)
    i_ops = our_wrapper + vec_ops

    return i_ops