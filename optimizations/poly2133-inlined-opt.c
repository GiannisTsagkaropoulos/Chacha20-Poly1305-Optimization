#include <stdint.h> // get uint32_t and uint64_t types, so is not platform dependent (unsigned int (32 bits) and unsigned long long (64 bits) could vary in size)
#include <string.h>
#include <stdlib.h>

/*Inlines all function calls*/
/*
we use 7x28 + 17-bit representations for acc, r and s, since 7x28 + 17 = 213 bits = p = 2^213 - 3 (so we have a margin to handle overflow)
*/ 

#define NUM_LIMBS 8
#define BLOCK_SIZE 26
#define TAG_SIZE 26
#define KEY_SIZE 54

const uint32_t mask_lowest_17bits = 0x1ffff;
const uint32_t mask_lowest_28bits = 0xfffffff;

#define TO_LARGE_NUM_REP(out, bytes, len) \
    do { \
        uint64_t _tr[NUM_LIMBS] = {0}; \
        for (uint64_t _i = 0; _i < (len); _i++) { \
            _tr[_i/4] |= ((uint64_t)(bytes)[_i] << ((_i%4)*8)); \
        } \
        for (int _i = 0; _i < 7; _i++) { \
            int _bs = 28 * _i; \
            int _ti = _bs / 32; \
            int _bit = _bs % 32; \
            (out)[_i] = (uint32_t)((_tr[_ti] >> _bit) | \
                        (_tr[_ti + 1] << (32 - _bit))) & (mask_lowest_28bits); \
        } \
        (out)[7] = (uint32_t)(_tr[6] >> 4) & (mask_lowest_17bits); \
    } while (0)

#define ADD_LARGE_NUMS_88(acc, n) \
    do { \
        uint64_t _carry = 0; \
        for (int _i = 0; _i < 7; _i++) { \
            _carry = (uint64_t)(acc)[_i] + (n)[_i] + _carry; \
            (acc)[_i] = (uint32_t)(_carry & mask_lowest_28bits); \
            _carry >>= 28; \
        } \
        _carry = (uint64_t)(acc)[7] + (n)[7] + _carry; \
        (acc)[7] = (uint32_t)(_carry & mask_lowest_17bits); \
        _carry >>= 17; \
        (acc)[0] += (uint32_t)(_carry * 3); \
    } while (0)

#define MULMOD_P(acc, r) \
    do{ \
        uint64_t _mult_small[NUM_LIMBS] = {0}; \
        uint64_t _mult_large[NUM_LIMBS] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < NUM_LIMBS; _i++){ \
            for(int _j = 0; _j < NUM_LIMBS; _j++){ \
                int _k = _i+_j; \
                if (_k < NUM_LIMBS){ \
                    (_mult_small)[_k] += (uint64_t)(acc)[_i]* (r)[_j]; \
                } \
                else{ \
                    (_mult_large)[_k - NUM_LIMBS] += (uint64_t)(acc)[_i]* 3*(r)[_j]; \
                } \
            } \
        } \
        uint64_t _carry = 0; \
        uint64_t _wrap_carry = 0; \
        for(int _i = 0; _i < 7; _i++){ \
            uint64_t _sum = _mult_small[_i] + (((_mult_large)[_i] & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
            (acc)[_i] = (uint32_t)(_sum & mask_lowest_28bits); \
            _carry = _sum >> 28; \
            _wrap_carry = (_mult_large)[_i] >> 17; \
        } \
        uint64_t _sum = _mult_small[7] + (((_mult_large)[7] & mask_lowest_6bits) << 11) + _wrap_carry + _carry; \
        (acc)[7] = (uint32_t)(_sum & mask_lowest_17bits); \
        _carry = _sum >> 17; \
        _wrap_carry = (_mult_large)[7] >> 6; \
        uint64_t _total_carry = (_carry + _wrap_carry) * 3; \
        uint64_t _sum0 = (uint64_t)(acc)[0] + _total_carry; \
        (acc)[0] = (uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry = _sum0 >> 28; \
        (acc)[0] &= mask_lowest_28bits; \
        (acc)[1] += (uint32_t)_carry; \
        _carry = (acc)[1] >> 28; \
        (acc)[1] &= mask_lowest_28bits; \
        (acc)[2] += (uint32_t)_carry; \
    } while(0)

#define TO_26_LE_BYTES(out, in) \
    do { \
        uint32_t _t[7] = {0}; \
        for (int _i = 0; _i < 7; _i++) { \
            int _bs  = 28 * _i; \
            int _ti  = _bs / 32; \
            int _bit = _bs % 32; \
            _t[_ti] |= (uint32_t)((uint64_t)(in)[_i] << _bit); \
            if (_bit + 28 > 32) { \
                _t[_ti + 1] |= (uint32_t)((uint64_t)(in)[_i] >> (32 - _bit)); \
            } \
        } \
        _t[6] |= ((in)[7] << 4); \
        for (int _i = 0; _i < TAG_SIZE; _i++) { \
            (out)[_i] = (unsigned char)((_t[_i / 4] >> ((_i % 4) * 8)) & 0xff); \
        } \
    } while (0)

// keylength must be 54 bytes
void poly2133_init(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    // split key into two halves (first half into r, other in s)
    uint64_t half_key_len = KEY_SIZE / 2;
    unsigned char r_bytes[half_key_len];
    memcpy(r_bytes, key, half_key_len);
    
    // mask some bits of r 
    const uint8_t clear_top4_bits = 0x0f;
    const uint8_t clear_lowest2_bits = 0xfc;

    r_bytes[3]  &= clear_top4_bits;
    r_bytes[4]  &= clear_lowest2_bits;
    r_bytes[7]  &= clear_top4_bits;
    r_bytes[8]  &= clear_lowest2_bits;
    r_bytes[11] &= clear_top4_bits;
    r_bytes[12] &= clear_lowest2_bits;
    r_bytes[15] &= clear_top4_bits;
    r_bytes[17] &= clear_lowest2_bits;
    r_bytes[22] &= clear_top4_bits;
    r_bytes[24] &= clear_lowest2_bits;
    r_bytes[25] &= clear_top4_bits;

    // make sure r is not > p
    r_bytes[half_key_len - 1] &= clear_top4_bits;

    // then convert to 7x28 + 17-bit representation
    TO_LARGE_NUM_REP(r, r_bytes, half_key_len);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    // convert second half of key into 7x28 + 17-bit representation for s
    TO_LARGE_NUM_REP(s, s_bytes, half_key_len);

    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

// calculate authentication tag for data
// use block and tag size of 26 bytes (maximal size still smaller p) 
unsigned char* poly2133_create_tag(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for(uint64_t i = 0; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE ? (data_len - offset) : BLOCK_SIZE;
        unsigned char block[block_len + 1];
        memset(block, 0, block_len + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        uint32_t n[NUM_LIMBS];
        // convert block to 7x28 + 17-bit representation
        TO_LARGE_NUM_REP(n, block, block_len + 1);
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        // acc = (acc * r) mod p
        MULMOD_P(acc, r);    
    }
    
    // acc += s
     ADD_LARGE_NUMS_88(acc, s);
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    
    return tag;
}