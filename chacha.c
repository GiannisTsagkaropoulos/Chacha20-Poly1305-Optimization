#include <stdint.h>
#include <string.h>

#define IS_BLOCK_CIPHER false
#define IS_AEAD true
#define TAG_LENGTH    16
#define NONCE_LENGTH  12
#define KEY_LENGTH    32
#define COUNTER       0
#define ROUNDS        20
#define STATE_WORDS   16
#define BLOCK_BYTES   64

uint8_t key[KEY_LENGTH];
uint8_t nonce[NONCE_LENGTH];
uint8_t tag[TAG_LENGTH];

static const uint32_t constants[4] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
};

static const uint8_t _round_mixup_box[8][4] = {
    {0, 4,  8, 12},
    {1, 5,  9, 13},
    {2, 6, 10, 14},
    {3, 7, 11, 15},
    {0, 5, 10, 15},
    {1, 6, 11, 12},
    {2, 7,  8, 13},
    {3, 4,  9, 14}
};

// function definitions
static inline uint32_t rotl32(uint32_t v, int c);
static void quarter_round(uint32_t *x, int a, int b, int c, int d);
static void double_round(uint32_t *x);
void chacha_block(const uint32_t key_words[8],
                  uint32_t counter,
                  const uint32_t nonce_words[3],
                  int rounds,
                  uint32_t out_state[STATE_WORDS]);
void word_to_bytearray(const uint32_t state[STATE_WORDS],
                       uint8_t out[BLOCK_BYTES]);

static inline uint32_t rotl32(uint32_t v, int c) {
    /*rotate v left for c bits*/
    return (v << c) | (v >> (32 - c));
}

static void quarter_round(uint32_t *x, int a, int b, int c, int d) {
    /*perform chacha quarter round*/
    uint32_t xa = x[a];
    uint32_t xb = x[b];
    uint32_t xc = x[c];
    uint32_t xd = x[d];

    xa = xa + xb;
    xd = xd ^ xa;
    xd = rotl32(xd, 16);

    xc = xc + xd;
    xb = xb ^ xc;
    xb = rotl32(xb, 12);

    xa = xa + xb;
    xd = xd ^ xa;
    xd = rotl32(xd, 8);

    xc = xc + xd;
    xb = xb ^ xc;
    xb = rotl32(xb, 7);

    x[a] = xa;
    x[b] = xb;
    x[c] = xc;
    x[d] = xd;
}

static void double_round(uint32_t *x) {
    /*perform two rounds of ChaCha cipher*/
    for (int i = 0; i < 8; i++) {
        quarter_round(x,
                      _round_mixup_box[i][0],
                      _round_mixup_box[i][1],
                      _round_mixup_box[i][2],
                      _round_mixup_box[i][3]);
    }
}

void chacha_block(const uint32_t key_words[8],
                  uint32_t counter,
                  const uint32_t nonce_words[3],
                  int rounds,
                  uint32_t out_state[STATE_WORDS]) {
    uint32_t state[STATE_WORDS];
    state[0] = constants[0];
    state[1] = constants[1];
    state[2] = constants[2];
    state[3] = constants[3];
    for (int i = 0; i < 8; i++) {
        state[4 + i] = key_words[i];
    }
    state[12] = counter;
    state[13] = nonce_words[0];
    state[14] = nonce_words[1];
    state[15] = nonce_words[2];

    uint32_t working_state[STATE_WORDS];
    memcpy(working_state, state, sizeof(working_state));

    for (int i = 0; i < rounds / 2; i++) {
        double_round(working_state);
    }

    for (int i = 0; i < STATE_WORDS; i++) {
        out_state[i] = state[i] + working_state[i];
    }
}

void word_to_bytearray(const uint32_t state[STATE_WORDS],
                       uint8_t out[BLOCK_BYTES]) {
    for (int i = 0; i < STATE_WORDS; i++) {
        uint32_t v = state[i];
        out[i * 4 + 0] = (uint8_t)(v       & 0xff);
        out[i * 4 + 1] = (uint8_t)((v >> 8)  & 0xff);
        out[i * 4 + 2] = (uint8_t)((v >> 16) & 0xff);
        out[i * 4 + 3] = (uint8_t)((v >> 24) & 0xff);
    }
}
