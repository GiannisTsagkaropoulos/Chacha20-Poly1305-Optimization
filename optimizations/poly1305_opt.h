#include <string.h>
#include <stdint.h>
#include <emmintrin.h>
#include <immintrin.h>
#include <stdio.h>
#include <stdlib.h>

#define NUM_LIMBS 5
#define BLOCK_SIZE 16
#define TAG_SIZE 16
#define KEY_SIZE 32

extern const uint32_t mask_lowest_26bits; // mask to keep only lowest 26 bits (26 ones in binary)
extern const uint64_t mask_lowest_32bits; // mask to keep only lowest 32 bits (32 ones in binary)

void to_large_num_rep(uint32_t out[5], const unsigned char *bytes, uint64_t len_bytes);

void to_16_le_bytes(uint32_t in[4], unsigned char out[16]);

void poly1305_init(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char key[32]);

static void add_large_nums_55(uint32_t a[5], const uint32_t b[5]);

static void mulmod_p(uint32_t acc[5], const uint32_t r[5]);

static void add_large_nums_54(uint32_t out[4], const uint32_t acc[5], const uint32_t s[4]);

static void process_lane_8blocks_unified(uint32_t acc_0[5], const uint32_t r8[5], const uint32_t n_0[5], const uint32_t r4[5], const uint32_t n_00[5]);

unsigned char* create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* inlined_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* not_inlined_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* inlined_parallel_Horner_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* _2poly_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* not_inlined_parallel_Horner_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* carry_delay(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* inlined_carry_delay_parallel_Horner(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* scalar_rep_inlined_parallel_Horner_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* vect_inlined_carry_delay_parallel_Horner(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* memory_vect_inlined_carry_delay_parallel_Horner(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);



//for benchmarks
typedef unsigned char*(*poly1305_create_tag_func)(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);
