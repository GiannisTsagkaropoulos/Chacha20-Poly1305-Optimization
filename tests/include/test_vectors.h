#include <stdint.h>
#include "constants.h"

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
    uint8_t expected_output_b[BLOCK_SIZE_B];
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

typedef struct {
    char    *test_name;
    uint8_t  key_b[KEY_SIZE_B];
    uint8_t  nonce_b[NONCE_SIZE_B];
    uint8_t  expected_otk_b[KEY_SIZE_B];
} TestPoly1305KeyGen;

typedef struct {
    char     *test_name;
    uint8_t   key_b[KEY_SIZE_B];
    uint8_t   nonce_b[NONCE_SIZE_B];
    uint8_t  *aad_b;
    uint64_t  aad_len;
    uint8_t  *plaintext_b;
    uint64_t  plaintext_len;
    uint8_t  *expected_ciphertext_b;
    uint8_t   expected_tag_b[TAG_SIZE_1305];
} TestAEADEncryption;

typedef struct {
    char     *test_name;
    uint8_t   key_b[KEY_SIZE_B];
    uint8_t   nonce_b[NONCE_SIZE_B];
    uint8_t  *aad_b;
    uint64_t  aad_len;
    uint8_t  *ciphertext_with_tag_b;
    uint64_t  ciphertext_with_tag_len;
    uint8_t  *expected_plaintext_b;
    uint64_t  expected_plaintext_len;
} TestAEADDecryption;

typedef struct {
    char *test_name;
    const unsigned char key_b[KEY_SIZE_B];
    const unsigned char *data;
    uint64_t data_len;
    const unsigned char true_tag_b[TAG_SIZE_1305];
} TestPoly1305TagGen;

typedef struct {
    char *test_name;
    const unsigned char key_b[KEY_SIZE_2133];
    const unsigned char *data;
    uint64_t data_len;
    const unsigned char true_tag_b[TAG_SIZE_2133];
} TestPoly2133TagGen;


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

extern TestPoly1305KeyGen   TESTS_POLY1305_KEY_GEN[];
extern const int            TESTS_POLY1305_KEY_GEN_COUNT;

extern TestAEADEncryption   TESTS_AEAD_ENCRYPTION[];
extern const int            TESTS_AEAD_ENCRYPTION_COUNT;

extern TestAEADDecryption   TESTS_AEAD_DECRYPTION[];
extern const int            TESTS_AEAD_DECRYPTION_COUNT;

extern TestPoly1305TagGen   TESTS_POLY1305_TAG_GEN[];
extern const int            TESTS_POLY1305_TAG_GEN_COUNT;

extern TestPoly2133TagGen   TESTS_POLY2133_TAG_GEN[];
extern const int            TESTS_POLY2133_TAG_GEN_COUNT;