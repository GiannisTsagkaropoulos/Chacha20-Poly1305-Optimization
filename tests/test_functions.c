#include <stdlib.h>
#include <string.h>
#include "test_vectors.h"
#include "test_helpers.h"
#include "chacha20.h"
#include "chacha20_priv.h"

void test_state_initialization(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_INITIALIZE_STATE_COUNT; i++) {
        TestInitializeState *p_test_state = &TESTS_INITIALIZE_STATE[i];

        char *test_name = p_test_state->test_name;
        uint8_t* key = p_test_state->key_b;
        uint8_t* nonce = p_test_state->nonce_b;
        uint32_t block_ctr = p_test_state->block_ctr;
        
        uint32_t state_w[STATE_SIZE_W];
        initialize_chacha_state(state_w, key, nonce, block_ctr);
        
        uint64_t output_size_b = STATE_SIZE_W*sizeof(uint32_t);
        uint32_t* expected_output_w = p_test_state->expected_output_w;

        int test_passed = u32_arrays_are_same(state_w, expected_output_w, output_size_b);
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
        
        uint64_t output_size_b = STATE_SIZE_W*sizeof(uint32_t);
        uint32_t* expected_output_w = p_test_state->expected_output_w;

        int test_passed = u32_arrays_are_same(state_w, expected_output_w, output_size_b);
        print_test_result(test_name, test_passed, total_tests_ptr, fails_ptr);
    }
}

void test_apply_chacha_block(int *total_tests_ptr, int *fails_ptr) {
    for (int i = 0; i < TESTS_CHACHA_BLOCK_COUNT; i++) {
        TestChachaBlock *p_test_state = &TESTS_CHACHA_BLOCK[i];

        char *test_name = p_test_state->test_name;
        uint32_t *input_state_w = p_test_state->input_state_w;
        int rounds = p_test_state->rounds;
        
        uint32_t output_block_w[STATE_SIZE_W];
        memcpy(output_block_w, input_state_w, STATE_SIZE_B);

        chacha_block(input_state_w, rounds, output_block_w);
        
        uint64_t output_size_b = STATE_SIZE_W*sizeof(uint32_t);
        uint32_t *expected_output_w = p_test_state->expected_output_w;

        int test_passed = u32_arrays_are_same(output_block_w, expected_output_w, output_size_b);
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
        
        uint64_t output_size_b = BLOCK_SIZE_B*sizeof(uint8_t);
        uint8_t *expected_output_b = p_test_state->expected_output_b;

        int test_passed = u8_arrays_are_same(keystream_output_b, expected_output_b, output_size_b);
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
        uint64_t rounds = p_test_state->rounds;
        
        uint8_t ciphertext_b[length];
        
        chacha20_encrypt(key_b, nonce_b, block_ctr, plaintext_b, length, rounds, ciphertext_b);
        
        uint64_t output_size_b = length*sizeof(uint8_t);
        uint8_t *expected_output_b = p_test_state->expected_output_b;

        int test_passed = u8_arrays_are_same(ciphertext_b, expected_output_b, output_size_b);
        print_test_result(test_name, test_passed, total_tests_ptr, fails_ptr);            

    }   
}
 