#include <stdint.h>

#define NUM_LIMBS 8
#define BLOCK_SIZE 26
#define TAG_SIZE 26
#define KEY_SIZE 54

// baseline
void poly2133_init_baseline(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_baseline(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// inlineds
void poly2133_init_inlined(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_inlined(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// unrolled
void poly2133_init_unrolled(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_unrolled(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// 2-level without inlining & unrolling
void poly2133_init_2level_basic(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_2level_basic(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// 2-level with inlining & unrolling
void poly2133_init_2level_inl_unr(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_2level_inl_unr(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// delayed carry + 2-level + inlining & unrolling
void poly2133_init_delcarry(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_delcarry(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// precomputation + 2-level + delayed carry + inlining & unrolling
void poly2133_init_precomp(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_precomp(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// remove if/else + precomputation + 2-level + delayed carry + inlining & unrolling
void poly2133_init_remif(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_remif(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// scalar replacement + remove if/else + precomputation + 2-level + delayed carry + inlining & unrolling
void poly2133_init_scalrep(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_scalrep(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// vectorized + remove if/else + precomputation + 2-level + delayed carry + inlining & unrolling
void poly2133_init_vec(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_vec(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);

// vectorized (8 Blocks) + remove if/else + precomputation + 2-level + delayed carry + inlining & unrolling
void poly2133_init_vec_8b(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
unsigned char* poly2133_create_tag_vec_8b(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);