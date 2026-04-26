#include <stdint.h>
#include "chacha20.h"

typedef struct {
    char *test_name;
    uint8_t key_b[KEY_SIZE_B];
    uint8_t nonce_b[NONCE_SIZE_B];
    uint32_t block_ctr;
    uint32_t expected_output_w[STATE_SIZE_W];
} TestInitializeState;

typedef struct {
    char *test_name;
    int indices[4];
    uint32_t state_w[STATE_SIZE_W];
    uint32_t expected_output_w[STATE_SIZE_W];
} TestQuarterRound;

typedef struct {
    char *test_name;
    uint32_t input_state_w[STATE_SIZE_W];
    uint32_t expected_output_w[STATE_SIZE_W];
    int rounds;
} TestChachaBlock;


typedef struct {
    char *test_name;
    uint32_t input_state_w[STATE_SIZE_W];
    uint8_t expected_output_b[BLOCK_SIZE_B];
} TestSerialization;

typedef struct {
    char *test_name;
    uint8_t key_b[KEY_SIZE_B];
    uint8_t nonce_b[NONCE_SIZE_B];
    uint32_t block_ctr;
    uint8_t *plaintext_b;
    uint64_t plaintext_length;
    uint8_t *expected_output_b;
    int rounds;
} TestChachaEncryption;


extern TestInitializeState  TESTS_INITIALIZE_STATE[];
extern const int            TESTS_INITIALIZE_STATE_COUNT;

extern TestQuarterRound     TESTS_QUARTER_ROUND[];
extern const int            TESTS_QUARTER_ROUND_COUNT;

extern TestChachaBlock      TESTS_CHACHA_BLOCK[];
extern const int            TESTS_CHACHA_BLOCK_COUNT;

extern TestSerialization    TESTS_SERIALIZATION[];
extern const int            TESTS_SERIALIZATION_COUNT;

extern TestChachaEncryption TESTS_CHACHA_ENCRYPTION[];
extern const int            TESTS_CHACHA_ENCRYPTION_COUNT;