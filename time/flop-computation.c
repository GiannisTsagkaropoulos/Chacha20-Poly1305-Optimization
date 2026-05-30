#include "flop-computations.h"
#include "chacha20.h"

#define LOADS_PER_QR   4
#define STORES_PER_QR  4
#define ADDS_PER_QR    4 
#define XORS_PER_QR    4
#define ROT_PER_QR     4
#define SHIFTS_PER_QR_VEC1   2
#define ORS_PER_QR_VEC1      1

complexity_t get_chacha_complexity(int rounds) {
    complexity_t c;
    
    uint64_t double_rounds = rounds/2;
    uint64_t total_qrs = QR_PER_ROUND * double_rounds;
    

    uint64_t adds       = (ADDS_PER_QR * total_qrs) + STATE_SIZE_W;
    uint64_t xors       = XORS_PER_QR * total_qrs;
    uint64_t rotations  = ROT_PER_QR  * total_qrs;
    uint64_t increments = total_qrs + STATE_SIZE_W;

    uint64_t loads_b, stores_b; 
    loads_b  = sizeof(uint32_t) * LOADS_PER_QR  * total_qrs;
    stores_b = sizeof(uint32_t) * STORES_PER_QR * total_qrs;


    c.i_ops = adds + xors + rotations + increments;
    c.byte_transfer = loads_b + stores_b;
    return c;
}

complexity_t get_chacha_inline_complexity(int rounds, uint64_t p_length) {
    complexity_t c;
    uint64_t double_rounds = rounds/2;
    uint64_t num_of_blocks = p_length / BLOCK_SIZE_B;

    uint64_t i_ops = 0;
    i_ops += 2;
    i_ops += num_of_blocks * (1 + double_rounds * (1 + 8 * 4*4 + 8) + 16 + STATE_SIZE_B * 3 + 2);

    uint64_t initial_state = num_of_blocks * STATE_SIZE_B;
    uint64_t working_state = num_of_blocks * STATE_SIZE_B;
    uint64_t keystream_buffer = num_of_blocks * BLOCK_SIZE_B;
    uint64_t byte_transfer = initial_state + working_state + keystream_buffer;


    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}

complexity_t get_chacha_chacha20_encrypt_2_complexity(int rounds, uint64_t p_length){
    complexity_t c;
    uint64_t double_rounds = rounds/2;
    uint64_t num_of_blocks = p_length / BLOCK_SIZE_B;

    uint64_t i_ops = 0;
    i_ops += 7 + 4;
    uint64_t qr256_iops = (8 + 4 * 3) * 8 + 4;
    i_ops += num_of_blocks * (1 + double_rounds * (1 + 8 * qr256_iops) + STATE_SIZE_W * (1 + 8) + STATE_SIZE_B * (1 + 8 + 7 + 8) + 8 + 2);

    uint64_t initial_state = num_of_blocks * STATE_SIZE_W;
    uint64_t working_state = num_of_blocks * STATE_SIZE_W;
    uint64_t keystream_buffer = num_of_blocks * BLOCK_SIZE_B;
    uint64_t byte_transfer = initial_state + working_state + keystream_buffer;


    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;
    return c;
}


complexity_t get_chacha_vector1_complexity(int rounds) {
    complexity_t c;
    
    uint64_t double_rounds = rounds/2;
    uint64_t total_qrs = QR_PER_ROUND * double_rounds;

    uint64_t adds       = (ADDS_PER_QR * total_qrs) + STATE_SIZE_W;
    uint64_t xors       = XORS_PER_QR * total_qrs;
    uint64_t shifts  = SHIFTS_PER_QR_VEC1  * total_qrs;
    uint64_t ors = ORS_PER_QR_VEC1 * total_qrs;
    uint64_t increments = total_qrs + STATE_SIZE_W;

    uint64_t loads_b, stores_b; 
    loads_b  = sizeof(uint32_t) * LOADS_PER_QR  * total_qrs;
    stores_b = sizeof(uint32_t) * STORES_PER_QR * total_qrs;


    c.i_ops = adds + xors + ors + shifts + increments;
    c.byte_transfer = loads_b + stores_b;
    return c;
}

complexity_t get_chacha_cipher_complexity(int rounds, uint64_t p_length) {
    complexity_t c;
    complexity_t chacha_c = get_chacha_complexity(rounds);
    
    uint64_t i_ops = 2; // block number and remainder
    uint64_t byte_transfer = STATE_SIZE_W * sizeof(uint32_t);  // initialize state

    uint64_t blocks_num = p_length / 64; 
    uint64_t remainder  = p_length % 64;


    // Each block involves: 1 copy of state, 1 chachablock, 1 key serialization, 1 xor loop for ctxt, 1 block counter increment
    uint64_t i_ops_per_block  = 
        chacha_c.i_ops +         // chacha block call
        2 * BLOCK_SIZE_B +       // computation of ciphertext block (1 index increment and 1 XOR per byte of ctxt)
        2;                       // increment of block ctr and offset in ciphertext


    uint64_t byte_transfer_per_block = 
        BLOCK_SIZE_B +                  // serialize state to keystream
        2 * STATE_SIZE_B;               // load plaintext and store ciphertext


    i_ops         += blocks_num * i_ops_per_block; 
    byte_transfer += blocks_num * byte_transfer_per_block; 

    if (remainder > 0) {
        i_ops += chacha_c.i_ops + (2 * remainder);
        byte_transfer += 
            BLOCK_SIZE_B + 
            (2 * remainder);
    }
    
    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;

    return c;
}
