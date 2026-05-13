#include <stdint.h>

extern const uint32_t mask_lowest_26bits; // mask to keep only lowest 26 bits (26 ones in binary)
extern const uint64_t mask_lowest_32bits; // mask to keep only lowest 32 bits (32 ones in binary)

// handle conversions from bytes to 5x26-bit representationfor length 16 and 17 
void to_large_num_rep(uint32_t out[5], const unsigned char *bytes, uint64_t len_bytes);

// handles conversion from 4x32-bit representation to 16 bytes in LE format
void to_16_le_bytes(uint32_t in[4], unsigned char out[16]);

// keylength must be 32 bytes
void poly1305_init(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char key[32]);
// computes a = a + b (a and b need be in 5x26-bit representation)
static void add_large_nums_55(uint32_t a[5], const uint32_t b[5]);

// computes acc = acc * r mod p (where acc and r in 5x26 bit representation, p = 2^130 - 5)
static void mulmod_p(uint32_t acc[5], const uint32_t r[5]);

// same as add_large_nums_55 but takes 4x32-bit and 5x26-bit and outputs 4x32-bit representation of their sum (acc = acc + s)
static void add_large_nums_54(uint32_t out[4], const uint32_t acc[5], const uint32_t s[4]);

unsigned char* inlined_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* no_brenches_not_inlined_create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* parallel_inlined_create_tag(uint32_t final_acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

unsigned char* unrolled_parallel_inlined_create_tag(uint32_t final_acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);