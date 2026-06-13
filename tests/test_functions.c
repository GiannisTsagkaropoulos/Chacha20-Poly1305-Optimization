#include <stdlib.h>
#include <string.h>
#include "test_vectors.h"
#include "test_helpers.h"
#include "chacha_opts.h"
#include "poly1305_init_opts.h"
#include "poly1305_tag_opt.h"
#include "poly2133_opt.h"
#include "poly2133_init_opts.h"
#include "chacha20_poly1305.h"

void test_state_initialization(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_INITIALIZE_STATE_COUNT; i++) {
        TestInitializeState *p_test_state = &TESTS_INITIALIZE_STATE[i];

        char *test_name = p_test_state->test_name;
        uint8_t* key = p_test_state->key_b;
        uint8_t* nonce = p_test_state->nonce_b;
        uint32_t block_ctr = p_test_state->block_ctr;
        
        uint32_t state_w[STATE_SIZE_W];
        initialize_chacha_state(state_w, key, nonce, block_ctr);
        
        uint32_t* expected_output_w = p_test_state->expected_output_w;

        int test_passed = u32_arrays_are_same(state_w, expected_output_w, STATE_SIZE_B);
        print_test_result(test_name, test_passed, total_tests_ptr, fails_ptr);
    }   
}

void test_quarter_rounds(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_QUARTER_ROUND_COUNT; i++) {
        TestQuarterRound *p_test_state = &TESTS_QUARTER_ROUND[i];

        char *test_name = p_test_state->test_name;
        uint32_t* state_w = p_test_state->state_w;
        int* indices = p_test_state->indices;
        int i0 = indices[0], i1 = indices[1], i2 = indices[2], i3 = indices[3];
        
        quarter_round(state_w, i0, i1, i2, i3);
        
        uint32_t* expected_output_w = p_test_state->expected_output_w;

        int test_passed = u32_arrays_are_same(state_w, expected_output_w, STATE_SIZE_B);
        print_test_result(test_name, test_passed, total_tests_ptr, fails_ptr);
    }
}

void test_apply_chacha_block(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_CHACHA_BLOCK_COUNT; i++) {
        TestChachaBlock *p_test_state = &TESTS_CHACHA_BLOCK[i];
        
        char *test_name = p_test_state->test_name;
        uint8_t *expected_output_b = p_test_state->expected_output_b;
        uint32_t *input_state_w = p_test_state->input_state_w;
        
        uint8_t keystream_buffer[STATE_SIZE_B];
        chacha_block_baseline(keystream_buffer, input_state_w);
        
        int test_passed = u8_arrays_are_same(keystream_buffer, expected_output_b, STATE_SIZE_B);
        print_test_result(test_name, test_passed, total_tests_ptr, fails_ptr);
    }   
}

void test_serialization(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_SERIALIZATION_COUNT; i++) {
        TestSerialization *p_test_state = &TESTS_SERIALIZATION[i];

        char *test_name = p_test_state->test_name;
        uint32_t *input_state_w = p_test_state->input_state_w;
        
        uint8_t keystream_output_b[BLOCK_SIZE_B];
        serialize_state(keystream_output_b, input_state_w);
        
        uint8_t *expected_output_b = p_test_state->expected_output_b;

        int test_passed = u8_arrays_are_same(keystream_output_b, expected_output_b, STATE_SIZE_B);
        print_test_result(test_name, test_passed, total_tests_ptr, fails_ptr);
    }   
}

void test_chacha_encryption(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_CHACHA_ENCRYPTION_COUNT; i++) {
        TestChachaEncryption *p_test_state = &TESTS_CHACHA_ENCRYPTION[i];

        char *test_name = p_test_state->test_name;
        uint8_t* key_b = p_test_state->key_b;
        uint8_t* nonce_b = p_test_state->nonce_b;
        uint32_t block_ctr = p_test_state->block_ctr;
        uint8_t* plaintext_b = p_test_state->plaintext_b;
        uint64_t length = p_test_state->plaintext_length;
        
        uint8_t ciphertext_b[length];
        
        chacha20_encrypt_baseline(ciphertext_b, plaintext_b, length, key_b, nonce_b, block_ctr);
        
        uint8_t *expected_output_b = p_test_state->expected_output_b;

        int test_passed = u8_arrays_are_same(ciphertext_b, expected_output_b, length);
        print_test_result(test_name, test_passed, total_tests_ptr, fails_ptr);            

    }   
}

void test_poly1305_key_gen(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_POLY1305_KEY_GEN_COUNT; i++) {
        TestPoly1305KeyGen *p_test_state = &TESTS_POLY1305_KEY_GEN[i];

        char *test_name = p_test_state->test_name;
        uint8_t* key_b = p_test_state->key_b;
        uint8_t* nonce_b = p_test_state->nonce_b;

        uint8_t poly_key_buffer[KEY_SIZE_1305];
        poly1305_key_gen(poly_key_buffer, key_b, nonce_b);

        uint8_t *expected_output_b = p_test_state->expected_otk_b;

        int test_passed = u8_arrays_are_same(poly_key_buffer, expected_output_b, KEY_SIZE_1305);
        print_test_result(test_name, test_passed, total_tests_ptr, fails_ptr);
    }
}

void test_aead_encryption(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_AEAD_ENCRYPTION_COUNT; i++) {
        TestAEADEncryption *p_test_state = &TESTS_AEAD_ENCRYPTION[i];

        char *test_name = p_test_state->test_name;
        uint8_t* key_b = p_test_state->key_b;
        uint8_t* nonce_b = p_test_state->nonce_b;
        uint8_t* aad_b = p_test_state->aad_b;
        uint64_t aad_len = p_test_state->aad_len;
        uint8_t* plaintext_b = p_test_state->plaintext_b;
        uint64_t plaintext_len = p_test_state->plaintext_len;

        // encrypt() writes (ciphertext || tag) into a single buffer.
        uint8_t output_b[plaintext_len + TAG_SIZE_1305];
        aead_encrypt_baseline(output_b, plaintext_b, plaintext_len, aad_b, aad_len, key_b, nonce_b);

        uint8_t *expected_ciphertext_b = p_test_state->expected_ciphertext_b;
        uint8_t *expected_tag_b = p_test_state->expected_tag_b;

        int ct_passed = u8_arrays_are_same(output_b, expected_ciphertext_b, plaintext_len);
        int tag_passed = u8_arrays_are_same(output_b + plaintext_len, expected_tag_b, TAG_SIZE_1305);

        print_test_result(test_name, ct_passed && tag_passed, total_tests_ptr, fails_ptr);
    }
}

void test_aead_decryption(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_AEAD_DECRYPTION_COUNT; i++) {
        TestAEADDecryption *p_test_state = &TESTS_AEAD_DECRYPTION[i];

        char *test_name = p_test_state->test_name;
        uint8_t* key_b = p_test_state->key_b;
        uint8_t* nonce_b = p_test_state->nonce_b;
        uint8_t* aad_b = p_test_state->aad_b;
        uint64_t aad_len = p_test_state->aad_len;
        uint8_t* ciphertext_with_tag_b = p_test_state->ciphertext_with_tag_b;
        uint64_t ciphertext_with_tag_len = p_test_state->ciphertext_with_tag_len;
        uint64_t expected_plaintext_len = p_test_state->expected_plaintext_len;

        uint8_t plaintext_b[expected_plaintext_len];
        size_t plaintext_len = aead_decrypt_baseline(plaintext_b,
                                       ciphertext_with_tag_b, ciphertext_with_tag_len,
                                       aad_b, aad_len,
                                       key_b, nonce_b);

        uint8_t *expected_plaintext_b = p_test_state->expected_plaintext_b;

        int len_passed = (plaintext_len == expected_plaintext_len);
        int pt_passed = len_passed &&
            u8_arrays_are_same(plaintext_b, expected_plaintext_b, expected_plaintext_len);

        print_test_result(test_name, pt_passed, total_tests_ptr, fails_ptr);
    }
}

void test_poly1305_tag_gen(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_POLY1305_TAG_GEN_COUNT; i++) {
    TestPoly1305TagGen *p_test_state = &TESTS_POLY1305_TAG_GEN[i];

    char *test_name = p_test_state->test_name;
    const unsigned char *key_b = p_test_state->key_b;
    const unsigned char *data = p_test_state->data;
    uint64_t data_len = p_test_state->data_len;
    const unsigned char *true_tag = p_test_state->true_tag_b;

    uint32_t acc[LIMBS_1305], r[LIMBS_1305], s[LIMBS_1305];
    unsigned char* tag;

    poly1305_init_baseline(acc, r, s, key_b);
    tag = create_tag1305_baseline(acc, r, s, data, data_len);

    int tag_passed = (memcmp(tag, true_tag, TAG_SIZE_1305) == 0);
    print_test_result(test_name, tag_passed, total_tests_ptr, fails_ptr);

    free(tag);
    }
}

void test_poly2133_tag_gen(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_POLY2133_TAG_GEN_COUNT; i++) {
    TestPoly2133TagGen *p_test_state = &TESTS_POLY2133_TAG_GEN[i];

    char *test_name = p_test_state->test_name;
    const unsigned char *key_b = p_test_state->key_b;
    const unsigned char *data = p_test_state->data;
    uint64_t data_len = p_test_state->data_len;
    const unsigned char *true_tag = p_test_state->true_tag_b;

    uint32_t acc[LIMBS_2133], r[LIMBS_2133], s[LIMBS_2133];
    unsigned char* tag;

    poly2133_init_baseline(acc, r, s, key_b);
    tag = poly2133_create_tag_baseline(acc, r, s, data, data_len);

    int tag_passed = (memcmp(tag, true_tag, TAG_SIZE_2133) == 0);
    print_test_result(test_name, tag_passed, total_tests_ptr, fails_ptr);

    free(tag);
    }
}