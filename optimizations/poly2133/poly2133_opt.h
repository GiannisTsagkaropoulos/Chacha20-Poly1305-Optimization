#include <stdint.h>
#include "constants.h"

unsigned char* poly2133_create_tag_baseline(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);
unsigned char* poly2133_create_tag_inlined(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);
unsigned char* poly2133_create_tag_unrolled(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);

// 2-level without inlining & unrolling
unsigned char* poly2133_create_tag_2level_basic(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);

// 2-level with inlining & unrolling
unsigned char* poly2133_create_tag_2level_inl_unr(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);

// delayed carry + 2-level + inlining & unrolling
unsigned char* poly2133_create_tag_delcarry(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);

// precomputation + 2-level + delayed carry + inlining & unrolling
unsigned char* poly2133_create_tag_precomp(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);

// remove if/else + precomputation + 2-level + delayed carry + inlining & unrolling
unsigned char* poly2133_create_tag_remif(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);

// scalar replacement + remove if/else + precomputation + 2-level + delayed carry + inlining & unrolling
void poly2133_init_scalrep(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]);
unsigned char* poly2133_create_tag_scalrep(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);

// vectorized + remove if/else + precomputation + 2-level + delayed carry + inlining & unrolling
unsigned char* poly2133_create_tag_vec(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);

// vectorized (8 Blocks) + remove if/else + precomputation + 2-level + delayed carry + inlining & unrolling
unsigned char* poly2133_create_tag_vec_8b(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);


//for benchmarks
typedef unsigned char*(*poly2133_create_tag_func)(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len);

void poly2133_init(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]);