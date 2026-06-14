QR_PER_ROUND = 8
LOADS_PER_QR = 4
STORES_PER_QR = 4
ADDS_PER_QR = 4 
XORS_PER_QR = 4
ROT_PER_QR = 4
SHIFTS_PER_QR_VEC1 = 2
ORS_PER_QR_VEC1 = 1

STATE_SIZE_B = 64

def get_chacha20_encrypt_baseline_complexity(p_length: int):
    num_of_blocks = p_length // STATE_SIZE_B

    # 2 ops for (num_full_blocks, remainder)
    # num_full_blocks INC
    # for every plaintext block:
        # 10 INC (1 for every double round)
        # 80 QR = 80*(4 ADD + 4 XOR + 4 ROT) = 80*(4 ADD + 4 XOR + 4*(2 SHIFT + 1 SUB + 1 OR) ) =  80*24 = 1920 ops 
        # 16 INC (working state)
        # 16 ADD (working state)
        # 64 INC  (compute ctxts)
        # 64*2 ADD (array indices in ciphertext)
        # 64 XOR
        # 1 INC + 1 ADD in the end
    main_ops = 10 + 1920 + 16 + 16 + 64 + 2*64 + 64 + 1 + 1
    i_ops = 2 + num_of_blocks + num_of_blocks * main_ops

    return i_ops

def get_chacha20_encrypt_strength_reduction_complexity(p_length: int):
    num_of_blocks = p_length // STATE_SIZE_B

    # 2 ops for (num_full_blocks, remainder)
    # num_full_blocks INC
    # for every plaintext block:
        # 10 INC (1 for every double round)
        # 80 QR = 80*(4 ADD + 4 XOR + 4 ROT) = 80*(4 ADD + 4 XOR + 4*(2 SHIFT + 1 SUB + 1 OR) ) =  80*24 = 1920 ops 
        # 16 INC (working state)
        # 16 ADD (working state)
        # 2 ADD  (array indices)
        # 8 INC  (compute ctxts)
        # 8 XOR
        # 1 INC + 1 ADD in the end
    main_ops =  10 + 1920 + 16 + 16 + 2 + 8 + 8 + 1 + 1
    i_ops = 2 + num_of_blocks + num_of_blocks * main_ops

    return i_ops

def get_chacha20_encrypt_inline_complexity(p_length: int):
    num_of_blocks = p_length // STATE_SIZE_B

    # 2 ops for (num_full_blocks, remainder)
    # num_full_blocks INC
    # for every plaintext block:
        # 10 INC (1 for every double round)
        # 80 QR = 80*(4 ADD + 4 XOR + 4 ROT) = 80*(4 ADD + 4 XOR + 4*(2 SHIFT + 1 SUB + 1 OR) ) =  80*24 = 1920 ops 
        # 16 ADD
        # 2 ADD  (array indices)
        # 8 INC  (compute ctxts)
        # 8 XOR
        # 1 INC + 1 ADD in the end
    main_ops = 10 + 1920 + 16 + 2 + 8 + 8 + 1 + 1
    i_ops = 2 + num_of_blocks + num_of_blocks * main_ops

    return i_ops


def get_chacha20_encrypt_scalar_replacement_complexity(p_length: int):
    num_of_blocks = p_length // STATE_SIZE_B

    # 2 ops for (num_full_blocks, remainder)
    # num_full_blocks INC
    # for every full block:
        # 10 INC (1 for every double round)
        # 80 QR = 8*(4 ADD + 4 XOR + 4 ROT) = 80*(4 ADD + 4 XOR + 4*(2 SHIFT + 1 SUB + 1 OR) ) =  80*24 = 1920 ops 
        # 16 ADD
        # 2 ADD  (array indices)
        # 8 INC  (compute ctxts)
        # 8 XOR
        # 1 INC + 1 ADD in the end
    main_ops = 10 + 1920 + 16 + 2 + 8 + 8 + 1 + 1
    i_ops = 2 + num_of_blocks + num_of_blocks * main_ops

    return i_ops


def get_chacha20_encrypt_unroll_ilp_ctxt_complexity(p_length: int):
    num_of_blocks = p_length // STATE_SIZE_B

    # 2 ops for (num_full_blocks, remainder)
    # num_full_blocks INC
    # for every full block:
        # 10 INC (1 for every double round)
        # 80 QR = 8*(4 ADD + 4 XOR + 4 ROT) = 80*(4 ADD + 4 XOR + 4*(2 SHIFT + 1 SUB + 1 OR) ) =  80*24 = 1920 ops 
        # 16 ADD
        # 2 ADD (array indices)
        # 8 XOR
        # 1 INC + 1 ADD in the end
    main_ops = 10 + 1920 + 16 + 2 + 8 + 1 + 1
    i_ops = 2 + num_of_blocks + num_of_blocks * main_ops

    return i_ops


def get_chacha20_encrypt_multiple_pt_blocks_at_once_complexity(p_length: int):
    num_of_blocks = p_length // STATE_SIZE_B
    block_inc = num_of_blocks // 4

    # 2 ops for (num_full_blocks, remainder)
    # 3 ADD for counters
    # block_inc INC
    # for every block increment:
        # 10 INC (1 for every double round)
        # 320 QR = 320*(4 ADD + 4 XOR + 4 ROT) = 320*(4 ADD + 4 XOR + 4*(2 SHIFT + 1 SUB + 1 OR) ) =  320*24 = 7680 ops 
        # 4*16 ADD
        # 8 ADD (load plaintext and ciphertexts)
        # 8 INC (compute ctxts)
        # For every counter
            # 4 XOR (compute ctxts)
        # 4 + 4 ADD (counter progress)
    main_ops = 10 + 7680 + 4*16 + 8 + 8 + 8*4 + 4 + 4
    i_ops = 2 + 3 + block_inc + block_inc * main_ops

    return i_ops


def get_chacha20_encrypt_multiple_pt_blocks_at_once2_complexity(p_length: int):
    num_of_blocks = p_length // STATE_SIZE_B
    block_inc = num_of_blocks // 8

    # 2 ops for (num_full_blocks, remainder)
    # 7 ADD for counters
    # block_inc INC
    # for every block increment:
        # 10 INC (1 for every double round)
        # 640 QR = 640*(4 ADD + 4 XOR + 4 ROT) = 640*(4 ADD + 4 XOR + 4*(2 SHIFT + 1 SUB + 1 OR) ) =  640*24 = 15360 ops 
        # 8*16 ADD
        # 16 ADD (load plaintext and ciphertexts)
        # 8 INC (compute ctxts)
        # For every counter
            # 8 XOR (compute ctxts)
        # 8 + 8 ADD (counter progress)
    main_ops = 10 + 15360 + 8*16 + 16 + 8 + 8*8 + 8 + 8
    i_ops = 2 + 7 + block_inc + block_inc * main_ops

    return i_ops


def get_chacha20_encrypt_2_complexity(p_length: int):
    num_of_blocks = p_length // STATE_SIZE_B
    num_octa_blocks = num_of_blocks // 8

    # 4 ops for (num_full_blocks, remainder, num_octa_blocks, leftover_full)
    # 7 ADD for counters
    # num_octa_blocks INC
    # for every block increment:
        # 10 INC (1 for every double round)
        # 80 QR_256 = 80*(4*8 ADD_256 + 4*8 XOR_256 + 4 ROT_256) = 80*(4*8 ADD + 4*8 XOR + 4*(1 SUB + 16 SHIFT + 8 OR) ) =  80*164 = 13120 ops 
            # EXTRACT could count as 2 iops each, but we don't count them since is just reorganizing data
        # 16 INC (state computatation)
        # For each inc
            # 8 ADDs
        # 16 ADD (load plaintext and ciphertexts)
        # 64 INC (compute ctxts)
        # For every counter
            # 15 ADD 
            # 14 MUL 
            # 8 XOR 
        # 8 ADD (counter progress)
        # 1 ADD + 1 MUL (idx start progress)
    main_ops = 10 + 13120 + 8*16 + 16 + 16*8 + 64 + 64*(15 + 14 + 8) + 8 + 1 + 1
    i_ops = 4 + 7 + num_octa_blocks + num_octa_blocks * main_ops

    return i_ops


def get_chacha20_encrypt_vectorized2_complexity(p_length: int):
    blocks_8 = p_length >> 9

    # 2 ops for (num_full_blocks, remainder)
    # 8 ADD (counters)
    # blocks_8 INC
    # for every block increment:
        # 10 INC (1 for every double round)
        # 80 QR_256 = 80*(4 ADD_256 + 4 XOR_256 + 4 ROT_256) = 80*(4*8 ADD + 4*8 XOR + 4*(1 SUB + 16 SHIFT + 8 OR) ) =  80*164 = 13120 ops 
            # EXTRACT could count as 2 iops each, but we don't count them since is just reorganizing data
        # 8 ADD_256 = 64 ADD (state)
        # 2 ADD (get ptxt and ctxt pointers) 
        # 14 ADD (plaintext and ctxt pointers for lower state comps)
        # 8 XOR_256 = 64 XOR (lower level ciphertext)
        #
        # 8 ADD_256 = 64 ADD (state)
        # 16 ADD (plaintext and ctxt pointers for higher state comps)
        # 8 XOR_256 = 64 XOR (higher level ciphertext)
        # 8 ADD (state add)
        # 1 ADD (ctr)
    main_ops = 10 + 13120 + 64 + 2 + 14 + 64 + 65 + 16 + 64 + 8 + 1
    i_ops = 2 + 8 + blocks_8 + blocks_8 * main_ops

    return i_ops


def get_chacha20_encrypt_vectorized3_complexity(p_length: int):
    blocks_8 = p_length >> 9

    # 2 ops for (num_full_blocks, remainder)
    # 8 ADD (counters)
    # num_reps INC
    # for every block increment:
        # 10 INC (1 for every double round)
        # 80 QR_256_2 = 80*(4 ADD_256 + 4 XOR_256 + 4 ROT_256_2) = 80*(4*8 ADD + 4*8 XOR + 2*8 SHIFT + 2*(1 SUB + 16 SHIFT + 8 OR) ) =  80*130 = 10400 ops 
            # EXTRACT could count as 2 iops each, but we don't count them since is just reorganizing data
        # 8 ADD_256 = 64 ADD (state)
        # 2 ADD (get ptxt and ctxt pointers) 
        # 14 ADD (plaintext and ctxt pointers for lower state comps)
        # 8 XOR_256 = 64 XOR (lower level ciphertext)
        #
        # 8 ADD_256 = 64 ADD (state)
        # 16 ADD (plaintext and ctxt pointers for higher state comps)
        # 8 XOR_256 = 64 XOR (higher level ciphertext)
        # 8 ADD (state add)
        # 1 ADD (ctr)
    main_ops = 10 + 10400 + 64 + 2 + 14 + 64 + 65 + 16 + 64 + 8 + 1
    i_ops = 2 + 8 + blocks_8 + blocks_8 * main_ops

    return i_ops

def get_chacha20_encrypt_openssl_complexity(p_length: int):
    # 4 AND
    # 3 SHIFTS
    # 1 ADD
    our_wrapper = 4 + 3 + 1

    vec_ops = get_chacha20_encrypt_vectorized3_complexity(p_length)
    i_ops = our_wrapper + vec_ops

    return i_ops