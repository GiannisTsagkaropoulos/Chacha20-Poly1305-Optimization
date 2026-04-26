#include <stdint.h>
#include <string.h>

#define TAG_LENGTH    16

#define CONSTANTS_SIZE 4
#define QR_PER_ROUND 8
#define INDICES_PER_STEP 4

#define BLOCK_CTR_IDX 12
#define ROUNDS        20

#define COUNTER       0
#define KEY_SIZE_B    32
#define KEY_SIZE_W    8
#define NONCE_SIZE_B  12
#define NONCE_SIZE_W  3
#define STATE_SIZE_B   64
#define STATE_SIZE_W   16
#define BLOCK_SIZE_B   64

static const uint32_t CONSTANTS[CONSTANTS_SIZE] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

static const uint8_t round_mixup_box[QR_PER_ROUND][INDICES_PER_STEP] = {
    {0, 4,  8, 12},
    {1, 5,  9, 13},
    {2, 6, 10, 14},
    {3, 7, 11, 15},
    {0, 5, 10, 15},
    {1, 6, 11, 12},
    {2, 7,  8, 13},
    {3, 4,  9, 14}
};

static inline uint32_t rotl32(uint32_t v, int c);
static inline uint32_t byte_ptr_to_word(const uint8_t *byte_array);
static void initialize_chacha_state(uint32_t *state, const uint8_t *key_w, const uint8_t *nonce_w, uint32_t block_ctr);
static void quarter_round(uint32_t *x, int a, int b, int c, int d);
static void double_round(uint32_t *x);
static void chacha_block(const uint32_t *input_state_w, int rounds, uint32_t *out_state_w);
static void serialize_state(uint8_t *keystream_b, uint32_t* state_w);

                  
static inline uint32_t rotl32(uint32_t v, int c){
    return (v << c) | (v >> (32 - c));
}

static inline uint32_t byte_ptr_to_word(const uint8_t *byte_array){
    return (uint32_t)byte_array[0]
        | ((uint32_t)byte_array[1] <<  8)
        | ((uint32_t)byte_array[2] << 16)
        | ((uint32_t)byte_array[3] << 24);
}
 

static void initialize_chacha_state(uint32_t *state, const uint8_t *key_w, const uint8_t *nonce_w, uint32_t block_ctr){
    state[0] = CONSTANTS[0];
    state[1] = CONSTANTS[1];
    state[2] = CONSTANTS[2];
    state[3] = CONSTANTS[3];
    for (int i = 0; i < 8; i++){
        state[4 + i] = byte_ptr_to_word(key_w + i*4);
    }
    state[12] = block_ctr;
    state[13] = byte_ptr_to_word(nonce_w);
    state[14] = byte_ptr_to_word(nonce_w + 4);
    state[15] = byte_ptr_to_word(nonce_w + 8);
}

static void quarter_round(uint32_t *state, int i0, int i1, int i2, int i3){
    uint32_t a, b, c, d;
    a = state[i0];
    b = state[i1];
    c = state[i2];
    d = state[i3];

    a += b; 
    d ^= a; 
    d = rotl32(d,16);

    c += d; 
    b ^= c; 
    b = rotl32(b,12);

    a += b; 
    d ^= a; 
    d = rotl32(d,8);

    c += d; 
    b ^= c; 
    b = rotl32(b,7);

    state[i0] = a;
    state[i1] = b;
    state[i2] = c;
    state[i3] = d;
};

static void double_round(uint32_t *state){
    for (int i = 0; i < QR_PER_ROUND; i++) {
        quarter_round(state,
                      round_mixup_box[i][0],
                      round_mixup_box[i][1],
                      round_mixup_box[i][2],
                      round_mixup_box[i][3]);
    }
}

void chacha_block(const uint32_t *input_state_w, int rounds, uint32_t *out_state_w){
    // the total rounds comprise of rounds/2 number of double rounds with 
    // 1 round of columnal and 1 round of diagonal state transformations
    int max_iter = rounds / 2;
    for (int i = 0; i < max_iter; i++) {
        double_round(out_state_w);
    }

    for (int i = 0; i < STATE_SIZE_W; i++) {
        out_state_w[i] += input_state_w[i] ;
    }
}

static void serialize_state(uint8_t *keystream_b, uint32_t* state_w){
    #if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        memcpy(keystream_b, state_w, STATE_SIZE_B);
    #else
        size_t i4 = 0;
        for (size_t i = 0; i < STATE_SIZE_W; i++) {
            i4 += 4;
            keystream_b[i4]     = state[i] & 0xff;
            keystream_b[i4 + 1] = (state[i] >>  8) & 0xff;
            keystream_b[i4 + 2] = (state[i] >> 16) & 0xff;
            keystream_b[i4 + 3] = (state[i] >> 24) & 0xff;
        }
    #endif
}