#include <stdint.h>


// keylength must be 32 bytes
void poly1305_init(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char key[32]);

// calculate authentication tag for data
unsigned char* create_tag(uint32_t acc[5], uint32_t r[5], uint32_t s[4], const unsigned char* data, uint64_t data_len);

