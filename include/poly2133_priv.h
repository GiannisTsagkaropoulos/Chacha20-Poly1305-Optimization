#include <stdint.h>

#define NUM_LIMBS 8
#define TAG_SIZE 26

// handle conversions from bytes to 7x28 + 17-bit representation
void to_large_num_rep(uint32_t out[NUM_LIMBS], const unsigned char *bytes, uint64_t len_bytes);

// handles conversion from 7x28 + 17-bit representation to 26 bytes in LE format
void to_26_le_bytes(uint32_t in[NUM_LIMBS], unsigned char out[TAG_SIZE]);

// computes a = a + b (a and b need be in 7x28 + 17-bit representation)
void add_large_nums_88(uint32_t a[NUM_LIMBS], const uint32_t b[NUM_LIMBS]);

// computes acc = acc * r mod p (where acc and r in 7x28 + 17-bit representation, p = 2^213 - 3)
void mulmod_p(uint32_t acc[NUM_LIMBS], const uint32_t r[NUM_LIMBS]);

