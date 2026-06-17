#!/usr/bin/env python3

def count_MULMOD_P_REMIF():
    # 8 ADD (Loop increments)
    # for each:
        # 1st loop runs 36 times
        # 2nd loop runs 28 times
        

    # 8 ADD (Loop increments)
    # for each
        # 3 ADD 
        # 2 AND
        # 3 SHIFT

    # 1 ADD
    # 1 AND
    # 1 SHIFT
    # 1 ADD
    # 1 ADD
    # 1 SHFT
    # 1 SHIFT
    # 1 SHIFT

    # 1 ADD
    # 1 MUL
    # 1 ADD
    # 1 AND
    # 1 SHIFT
    # 1 ADD
    # 1 SHIFT
    # 1 AND
    # 1 ADD

    return 8 + 36 + 36*3 + 28 + 28*4 + 8*(3+2+3) + 17


def count_TO_LARGE_NUM_REP_MSG27_UNROLLED():
    # 27 LEFT SHIFT
    # 7 RIGHT SHIFT
    # 8 AND
    # 27 OR

    return 27+7+8+27



def count_MULMOD_P_VEC_SCALREP_4BLOCKS():
    # 8 ADD
    # 64 mul_epu32 = 64*4 MUL = 256 MUL
    # 49 add64 = 49*4 ADD = 196 ADD
    # 42 ADD
    # 8 LEFT SHIFT
    # 18 RIGHT SHIFT
    # 18 AND
    # 1 MUL
    return 8 + 256 + 196 + 42 + 8 + 18 + 18 + 1
    

def count_MULMOD_P_VEC_SCALREP_8BLOCKS():
    # 51 ADD
    # 128 mul32 = 128*4 MUL = 512 MUL
    # 113 add64 = 113*4 ADD = 452 ADD
    # 8 LEFT SHIFT
    # 18 RIGHT SHIFT
    # 18 AND
    # 1 MUL
    return 8 + 512 + 452 + 8 + 18 + 18 + 1
    

def count_ADD_LARGE_NUMS_88():
    # 8 ADD (loop increments)
    # for each:
        # 2 ADD
        # 1 AND
        # 1 SHIFT
    # 2 ADD    
    # 1 AND    
    # 1 SHIFT    
    # 1 ADD    
    # 1 MUL

    return 8 + 8*(2+1+1) + 2+1+1+1+1    



def count_TO_26_LE_BYTES():
    # 8 ADD (loop increments)
    # for each:
        # 1 ADD
        # 1 DIV
        # 1 MOD
        # 1 OR
        # 1 SHIFT
        # 1 ADD
        # 1 CMP
        # 1 ADD
        # 1 OR
        # 1 SHIFT
        # 1 SUB
    # 1 OR
    # 1 SHIFT
    # 26 ADD (loop increment)
        # for each:
        # 1 DIV
        # 1 MOD
        # 1 ADD
        # 1 AND

    return 8 + 8*(1+1+1+1+1+1+1+1+1+1+1) + 1 +1 + 26 + 26*(1+1+1+1)    






def get_poly2133_create_tag_baseline_complexity(ctxt_len: int):
    num_of_blocks = ctxt_len // 26 
    
    return num_of_blocks * 1057

def get_poly2133_create_tag_inlined_complexity(ctxt_len: int):
    num_of_blocks = ctxt_len // 26 
    
    return num_of_blocks * 1057

def get_poly2133_create_tag_unrolled_complexity(ctxt_len: int):
    num_of_blocks = ctxt_len // 26 
    
    return num_of_blocks * 950

def get_poly2133_create_tag_2level_basic_complexity(ctxt_len: int):
    num_of_blocks = ctxt_len // 26 
    
    return num_of_blocks * 1226

def get_poly2133_create_tag_2level_inl_unr_complexity(ctxt_len: int):
    num_of_blocks = ctxt_len // 26 
    
    return num_of_blocks * 1043

def get_poly2133_create_tag_delcarry_complexity(ctxt_len: int):
    num_of_blocks = ctxt_len // 26 
    
    return num_of_blocks * 496

def get_poly2133_create_tag_precomp_complexity(ctxt_len: int):
    num_of_blocks = ctxt_len // 26 
    
    return num_of_blocks * 398

def get_poly2133_create_tag_remif_complexity(ctxt_len: int):
    num_of_blocks = ctxt_len // 26 
    
    return num_of_blocks * 247

def get_poly2133_create_tag_scalrep_complexity(ctxt_len: int):
    num_of_blocks = ctxt_len // 26 
    
    return num_of_blocks * 722

def get_poly2133_create_tag_vec_complexity(ctxt_len: int):
    num_full_blocks = ctxt_len // 26 

    # init
    # 1 ADD
    # 1 SUB
    # 3 DIV
    # 3*8 ADD (loop increments)
    # 4*8 MUL (in loop)
    # 3*MULMOD_P_REMIF()
    # 1 ADD 
    # 1 MUL 

    # num_full_blocks ADD (num_full_block increments)
        # for each:  
        # 7 ADD
        # 4*TO_LARGE_NUM_REP_MSG27_UNROLLED()
        # 1*MULMOD_P_VEC_SCALREP_4BLOCKS()
        # 1 ADD

    # 1*ADD_LARGE_NUMS_88()
    # 1 MUL
    # 1*TO_26_LE_BYTES()


    init_ops = 1 + 1 + 3 + 3*8 + 4*8 + 3*count_MULMOD_P_REMIF() + 1 + 1
    main_ops = num_full_blocks + num_full_blocks*( 7 + 4*count_TO_LARGE_NUM_REP_MSG27_UNROLLED() + count_MULMOD_P_VEC_SCALREP_4BLOCKS() + 1 )
    final_ops = count_ADD_LARGE_NUMS_88() + 1 + count_TO_26_LE_BYTES()

    
    return init_ops + main_ops + final_ops

def get_poly2133_create_tag_vec_8b_complexity(ctxt_len: int):
    num_full_blocks = (ctxt_len // 26 )/2
    # init
    # 1 ADD
    # 1 SUB
    # 3 DIV
    # 4*8 ADD (loop increments)
    # 8*8 MUL (in loop)
    # 7*MULMOD_P_REMIF()
    # 1 ADD 
    # 1 MUL 

    # num_full_blocks ADD (num_full_block increments)
        # for each:  
        # 15 ADD
        # 8*TO_LARGE_NUM_REP_MSG27_UNROLLED()
        # 1*MULMOD_P_VEC_SCALREP_8BLOCKS()
        # 1 ADD

    # 1*ADD_LARGE_NUMS_88()
    # 1 MUL
    # 1*TO_26_LE_BYTES()


    init_ops = 1 + 1 + 3 + 4*8 + 8*8 + 7*count_MULMOD_P_REMIF() + 1 + 1
    main_ops = num_full_blocks + num_full_blocks*( 15 + 8*count_TO_LARGE_NUM_REP_MSG27_UNROLLED() + count_MULMOD_P_VEC_SCALREP_8BLOCKS() + 1 )
    final_ops = count_ADD_LARGE_NUMS_88() + 1 + count_TO_26_LE_BYTES()

    
    return init_ops + main_ops + final_ops
