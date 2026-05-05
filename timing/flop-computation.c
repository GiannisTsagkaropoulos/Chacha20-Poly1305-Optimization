#include "flop-computations.h"
#include "chacha20.h"

#define LOADS_PER_QR   4
#define STORES_PER_QR  4
#define ADDS_PER_QR    4 
#define XORS_PER_QR    4
#define ROT_PER_QR     4

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

complexity_t get_chacha_cipher_complexity(int rounds, uint64_t p_length) {
    complexity_t c;
    complexity_t chacha_c = get_chacha_complexity(rounds);
    
    uint64_t i_ops = 0;
    uint64_t byte_transfer = 0;

    uint64_t blocks_num = p_length / 64; 
    uint64_t remainder  = p_length % 64;

    // Inititalize: state, block number and remainder
    byte_transfer += STATE_SIZE_W * sizeof(uint32_t); 
    i_ops += 2; 

    // Each block involves: 1 copy of state, 1 chachablock, 1 key serialization, 1 xor loop for ctxt, 1 block counter increment
    uint64_t i_ops_per_block  = 
        chacha_c.i_ops +         // chacha block call
        2 * BLOCK_SIZE_B +       // computation of ciphertext block (1 index increment and 1 XOR per byte of ctxt)
        2;                       // increment of block ctr and offset in ciphertext


    uint64_t byte_transfer_per_block = 
        STATE_SIZE_B +                  // init state
        chacha_c.byte_transfer +        // chacha block call
        BLOCK_SIZE_B +                  // serialize state to keystream
        2 * STATE_SIZE_B;               // load plaintext and store ciphertext


    i_ops         += blocks_num * i_ops_per_block; 
    byte_transfer += blocks_num * byte_transfer_per_block; 

    if (remainder > 0) {
        i_ops += chacha_c.i_ops + (2 * remainder);
        byte_transfer += 
            STATE_SIZE_B + 
            chacha_c.byte_transfer + 
            BLOCK_SIZE_B + 
            (2 * remainder);
    }
    
    c.i_ops = i_ops;
    c.byte_transfer = byte_transfer;

    return c;
}
