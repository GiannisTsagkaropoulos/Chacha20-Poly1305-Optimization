#include <stdint.h>

#define NUM_LIMBS 8
#define BLOCK_SIZE 26
#define TAG_SIZE 27
#define KEY_SIZE 54


extern const uint32_t mask_lowest_17bits = 0x1ffff; // mask to keep only lowest 17 bits (17 ones in binary)
extern const uint32_t mask_lowest_28bits = 0xfffffff; // mask to keep only lowest 28 bits (28 ones in binary)
extern const uint64_t mask_lowest_32bits = 0xffffffffULL; // mask to keep only lowest 32 bits (32 ones in binary)

// handle conversions from bytes to 7x28 + 17-bit representation
void to_large_num_rep(uint32_t out[NUM_LIMBS], const unsigned char *bytes, uint64_t len_bytes);

// handles conversion from 7x28 + 17-bit representation to 27 bytes in LE format
void to_27_le_bytes(uint32_t in[NUM_LIMBS], unsigned char out[TAG_SIZE]);

// keylength must be 32 bytes
void poly1305_init(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]);
// computes a = a + b (a and b need be in 7x28 + 17-bit representation)
static void add_large_nums_88(uint32_t a[NUM_LIMBS], const uint32_t b[NUM_LIMBS]);

// computes acc = acc * r mod p (where acc and r in 7x28 + 17-bit representation, p = 2^213 - 3)
static void mulmod_p(uint32_t acc[NUM_LIMBS], const uint32_t r[NUM_LIMBS]);

// calculate authentication tag for data
unsigned char* create_tag(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len);
