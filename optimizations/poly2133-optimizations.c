#include <stdint.h> // get uint32_t and uint64_t types, so is not platform dependent (unsigned int (32 bits) and unsigned long long (64 bits) could vary in size)
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>

/*Inlines all function calls*/
/*
we use 7x28 + 17-bit representations for acc, r and s, since 7x28 + 17 = 213 bits = p = 2^213 - 3 (so we have a margin to handle overflow)
*/ 

#define NUM_LIMBS 8
#define BLOCK_SIZE 26
#define TAG_SIZE 26
#define KEY_SIZE 54
#define NUM_GROUPS 4

const uint32_t mask_lowest_17bits = 0x1ffff;
const uint32_t mask_lowest_28bits = 0xfffffff;

// ---------------  TO_LARGE_NUM_REP variations ------------------
#define TO_LARGE_NUM_REP(out, bytes, len) \
    do { \
        uint64_t _tr[NUM_LIMBS] = {0}; \
        for (uint64_t _i = 0; _i < (len); _i++) { \
            _tr[_i/4] |= ((uint64_t)(bytes)[_i] << ((_i%4)*8)); \
        } \
        \
        for (int _i = 0; _i < 7; _i++) { \
            int _bs = 28 * _i; \
            int _ti = _bs / 32; \
            int _bit = _bs % 32; \
            (out)[_i] = (uint32_t)((_tr[_ti] >> _bit) | \
                        (_tr[_ti + 1] << (32 - _bit))) & (mask_lowest_28bits); \
        } \
        (out)[7] = (uint32_t)(_tr[6] >> 4) & (mask_lowest_17bits); \
    } while (0)

#define TO_LARGE_NUM_REP_UNROLLED(out, bytes, len) \
    do { \
        uint64_t _tr[NUM_LIMBS] = {0}; \
        for (uint64_t _i = 0; _i < (len); _i+=4) { \
            uint64_t _word = (uint64_t)(bytes)[_i] \
                  | ((uint64_t)(bytes)[_i + 1] << 8) \
                  | ((uint64_t)(bytes)[_i + 2] << 16) \
                  | ((uint64_t)(bytes)[_i + 3] << 24); \
            _tr[_i/4] = _word; \
        } \
        \
        (out)[0] = (uint32_t)((_tr)[0] | ((_tr)[1] << 32)) & mask_lowest_28bits; \
        (out)[1] = (uint32_t)(((_tr)[0] >> 28) | ((_tr)[1] << 4)) & mask_lowest_28bits; \
        (out)[2] = (uint32_t)(((_tr)[1] >> 24) | ((_tr)[2] << 8)) & mask_lowest_28bits; \
        (out)[3] = (uint32_t)(((_tr)[2] >> 20) | ((_tr)[3] << 12)) & mask_lowest_28bits; \
        (out)[4] = (uint32_t)(((_tr)[3] >> 16) | ((_tr)[4] << 16)) & mask_lowest_28bits; \
        (out)[5] = (uint32_t)(((_tr)[4] >> 12) | ((_tr)[5] << 20)) & mask_lowest_28bits; \
        (out)[6] = (uint32_t)(((_tr)[5] >> 8) | ((_tr)[6] << 24)) & mask_lowest_28bits; \
        (out)[7] = (uint32_t)((_tr)[6] >> 4) & (mask_lowest_17bits); \
    } while (0)

//use this in loop handling remaining blocks (might not all be 27 bytes)
#define TO_LARGE_NUM_REP_MSG_UNROLLED(out, bytes, len) \
    do { \
        uint64_t _tr[NUM_LIMBS] = {0}; \
        for (uint64_t _i = 0; _i < (len); _i+=4) { \
            uint64_t _word = (uint64_t)(bytes)[_i] \
                  | ((uint64_t)(bytes)[_i + 1] << 8) \
                  | ((uint64_t)(bytes)[_i + 2] << 16) \
                  | ((uint64_t)(bytes)[_i + 3] << 24); \
            _tr[_i/4] = _word; \
        } \
        \
        uint64_t _remainder = (len) % 4; \
        if (_remainder != 0){ \
            uint64_t _start = (len) - _remainder; \
            uint64_t _word = 0; \
            for (uint64_t _j = 0; _j < _remainder; _j++){ \
                _word |= ((uint64_t)(bytes)[_start + _j] << (8 * _j)); \
            } \
            _tr[_start / 4] = _word; \
        } \
        \
        (out)[0] = (uint32_t)((_tr)[0] | ((_tr)[1] << 32)) & mask_lowest_28bits; \
        (out)[1] = (uint32_t)(((_tr)[0] >> 28) | ((_tr)[1] << 4)) & mask_lowest_28bits; \
        (out)[2] = (uint32_t)(((_tr)[1] >> 24) | ((_tr)[2] << 8)) & mask_lowest_28bits; \
        (out)[3] = (uint32_t)(((_tr)[2] >> 20) | ((_tr)[3] << 12)) & mask_lowest_28bits; \
        (out)[4] = (uint32_t)(((_tr)[3] >> 16) | ((_tr)[4] << 16)) & mask_lowest_28bits; \
        (out)[5] = (uint32_t)(((_tr)[4] >> 12) | ((_tr)[5] << 20)) & mask_lowest_28bits; \
        (out)[6] = (uint32_t)(((_tr)[5] >> 8) | ((_tr)[6] << 24)) & mask_lowest_28bits; \
        (out)[7] = (uint32_t)((_tr)[6] >> 4) & (mask_lowest_17bits); \
    } while (0)

// this is for fixed size of len = 27 (TO-DO: VECTORIZE FIRST LOOP?)
#define TO_LARGE_NUM_REP_MSG27_UNROLLED(out, bytes, len) \
    do { \
        uint64_t _tr[NUM_LIMBS] = {0}; \
        for (uint64_t _i = 0; _i < (len); _i+=4) { \
            uint64_t _word = (uint64_t)(bytes)[_i] \
                  | ((uint64_t)(bytes)[_i + 1] << 8) \
                  | ((uint64_t)(bytes)[_i + 2] << 16) \
                  | ((uint64_t)(bytes)[_i + 3] << 24); \
            _tr[_i/4] = _word; \
        } \
        \
        (out)[0] = (uint32_t)((_tr)[0] | ((_tr)[1] << 32)) & mask_lowest_28bits; \
        (out)[1] = (uint32_t)(((_tr)[0] >> 28) | ((_tr)[1] << 4)) & mask_lowest_28bits; \
        (out)[2] = (uint32_t)(((_tr)[1] >> 24) | ((_tr)[2] << 8)) & mask_lowest_28bits; \
        (out)[3] = (uint32_t)(((_tr)[2] >> 20) | ((_tr)[3] << 12)) & mask_lowest_28bits; \
        (out)[4] = (uint32_t)(((_tr)[3] >> 16) | ((_tr)[4] << 16)) & mask_lowest_28bits; \
        (out)[5] = (uint32_t)(((_tr)[4] >> 12) | ((_tr)[5] << 20)) & mask_lowest_28bits; \
        (out)[6] = (uint32_t)(((_tr)[5] >> 8) | ((_tr)[6] << 24)) & mask_lowest_28bits; \
        (out)[7] = (uint32_t)((_tr)[6] >> 4) & (mask_lowest_17bits); \
    } while (0)


// --------------------------------------------------------------------

// --------------- ADD_LARGE_NUMS_88 variations ------------------
#define ADD_LARGE_NUMS_88(acc, n) \
    do { \
        uint64_t _carry = 0; \
        for (int _i = 0; _i < 7; _i++) { \
            _carry = (uint64_t)(acc)[_i] + (n)[_i] + _carry; \
            (acc)[_i] = (uint32_t)(_carry & mask_lowest_28bits); \
            _carry >>= 28; \
        } \
        \
        _carry = (uint64_t)(acc)[7] + (n)[7] + _carry; \
        (acc)[7] = (uint32_t)(_carry & mask_lowest_17bits); \
        _carry >>= 17; \
        (acc)[0] += (uint32_t)(_carry * 3); \
    } while (0)

// --------------------------------------------------------------------

// --------------- MULMOD_P variations ------------------
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
        \
        uint64_t _sum = _mult_small[7] + (((_mult_large)[7] & mask_lowest_6bits) << 11) + _wrap_carry + _carry; \
        (acc)[7] = (uint32_t)(_sum & mask_lowest_17bits); \
        _carry = _sum >> 17; \
        _wrap_carry = (_mult_large)[7] >> 6; \
        \
        uint64_t _total_carry = (_carry + _wrap_carry) * 3; \
        uint64_t _sum0 = (uint64_t)(acc)[0] + _total_carry; \
        (acc)[0] = (uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry = _sum0 >> 28; \
        (acc)[1] += (uint32_t)_carry; \
        _carry = (acc)[1] >> 28; \
        (acc)[1] &= mask_lowest_28bits; \
        (acc)[2] += (uint32_t)_carry; \
    } while(0)

#define MULMOD_P_PRECOMP(acc, r, three_r) \
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
                    (_mult_large)[_k - NUM_LIMBS] += (uint64_t)(acc)[_i]* (three_r)[_j]; \
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
        \
        uint64_t _sum = _mult_small[7] + (((_mult_large)[7] & mask_lowest_6bits) << 11) + _wrap_carry + _carry; \
        (acc)[7] = (uint32_t)(_sum & mask_lowest_17bits); \
        _carry = _sum >> 17; \
        _wrap_carry = (_mult_large)[7] >> 6; \
        \
        uint64_t _total_carry = (_carry + _wrap_carry) * 3; \
        uint64_t _sum0 = (uint64_t)(acc)[0] + _total_carry; \
        (acc)[0] = (uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry = _sum0 >> 28; \
        (acc)[1] += (uint32_t)_carry; \
        _carry = (acc)[1] >> 28; \
        (acc)[1] &= mask_lowest_28bits; \
        (acc)[2] += (uint32_t)_carry; \
    } while(0)

#define MULMOD_P_REMIF(acc, r, three_r) \
    do{ \
        uint64_t _mult_small[NUM_LIMBS] = {0}; \
        uint64_t _mult_large[NUM_LIMBS] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < NUM_LIMBS; _i++){ \
            for (int _j = 0; _j < NUM_LIMBS - _i; _j++){ \
                _mult_small[_i+_j] += (uint64_t)(acc)[_i] * (r)[_j]; \
            } \
            for (int _j = NUM_LIMBS - _i; _j < NUM_LIMBS; _j++){ \
                _mult_large[_i+_j - NUM_LIMBS] += (uint64_t)(acc)[_i] * (three_r)[_j]; \
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
        \
        uint64_t _sum = _mult_small[7] + (((_mult_large)[7] & mask_lowest_6bits) << 11) + _wrap_carry + _carry; \
        (acc)[7] = (uint32_t)(_sum & mask_lowest_17bits); \
        _carry = _sum >> 17; \
        _wrap_carry = (_mult_large)[7] >> 6; \
        \
        uint64_t _total_carry = (_carry + _wrap_carry) * 3; \
        uint64_t _sum0 = (uint64_t)(acc)[0] + _total_carry; \
        (acc)[0] = (uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry = _sum0 >> 28; \
        (acc)[1] += (uint32_t)_carry; \
        _carry = (acc)[1] >> 28; \
        (acc)[1] &= mask_lowest_28bits; \
        (acc)[2] += (uint32_t)_carry; \
    } while(0)

#define MULMOD_P_DELCARRY_4BLOCKS(acc, n1, n2, n3, n4) \
    do{ \
        uint64_t _mult_small[NUM_LIMBS] = {0}; \
        uint64_t _mult_large[NUM_LIMBS] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < NUM_LIMBS; _i++){ \
            for(int _j = 0; _j < NUM_LIMBS; _j++){ \
                int _k = _i+_j; \
                if (_k < NUM_LIMBS){ \
                    (_mult_small)[_k] += (uint64_t)(n1)[_i]* (r4)[_j] + (uint64_t)(n2)[_i]* (r3)[_j] \
                                    + (uint64_t)(n3)[_i]* (r2)[_j] + (uint64_t)(n4)[_i]* (r)[_j] \
                                    + (uint64_t)(acc)[_i]* (r4)[_j]; \
                } \
                else{ \
                    (_mult_large)[_k - NUM_LIMBS] += (uint64_t)(n1)[_i]* 3*(r4)[_j] + (uint64_t)(n2)[_i]* 3*(r3)[_j] \
                                                + (uint64_t)(n3)[_i]* 3*(r2)[_j] + (uint64_t)(n4)[_i]* 3*(r)[_j] \
                                                + (uint64_t)(acc)[_i]* 3*(r4)[_j]; \
                } \
            } \
        } \
        uint64_t _carry = 0; \
        uint64_t _wrap_carry = 0; \
        uint64_t _sum; \
        for(int _i = 0; _i < 7; _i++){ \
            _sum = _mult_small[_i] + (((_mult_large)[_i] & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
            (acc)[_i] = (uint32_t)(_sum & mask_lowest_28bits); \
            _carry = _sum >> 28; \
            _wrap_carry = (_mult_large)[_i] >> 17; \
        } \
        \
        _sum = _mult_small[7] + (((_mult_large)[7] & mask_lowest_6bits) << 11) + _wrap_carry + _carry; \
        (acc)[7] = (uint32_t)(_sum & mask_lowest_17bits); \
        _carry = _sum >> 17; \
        _wrap_carry = (_mult_large)[7] >> 6; \
        \
        uint64_t _total_carry = (_carry + _wrap_carry) * 3; \
        uint64_t _sum0 = (uint64_t)(acc)[0] + _total_carry; \
        (acc)[0] = (uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry = _sum0 >> 28; \
        (acc)[1] += (uint32_t)_carry; \
        _carry = (acc)[1] >> 28; \
        (acc)[1] &= mask_lowest_28bits; \
        (acc)[2] += (uint32_t)_carry; \
    } while(0)

#define MULMOD_P_PRECOMP_4BLOCKS(acc, n1, n2, n3, n4) \
    do{ \
        uint64_t _mult_small[NUM_LIMBS] = {0}; \
        uint64_t _mult_large[NUM_LIMBS] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < NUM_LIMBS; _i++){ \
            uint64_t _n1_plus_acc_i = (uint64_t)((n1)[_i] + (acc)[_i]); \
            for(int _j = 0; _j < NUM_LIMBS; _j++){ \
                int _k = _i+_j; \
                if (_k < NUM_LIMBS){ \
                    (_mult_small)[_k] += _n1_plus_acc_i* (r4)[_j] + (uint64_t)(n2)[_i]* (r3)[_j] \
                                    + (uint64_t)(n3)[_i]* (r2)[_j] + (uint64_t)(n4)[_i]* (r)[_j]; \
                } \
                else{ \
                    (_mult_large)[_k - NUM_LIMBS] += _n1_plus_acc_i* (three_r4)[_j] + (uint64_t)(n2)[_i]* (three_r3)[_j] \
                                                + (uint64_t)(n3)[_i]* (three_r2)[_j] + (uint64_t)(n4)[_i]* (three_r)[_j]; \
                } \
            } \
        } \
        uint64_t _carry = 0; \
        uint64_t _wrap_carry = 0; \
        uint64_t _sum; \
        for(int _i = 0; _i < 7; _i++){ \
            _sum = _mult_small[_i] + (((_mult_large)[_i] & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
            (acc)[_i] = (uint32_t)(_sum & mask_lowest_28bits); \
            _carry = _sum >> 28; \
            _wrap_carry = (_mult_large)[_i] >> 17; \
        } \
        \
        _sum = _mult_small[7] + (((_mult_large)[7] & mask_lowest_6bits) << 11) + _wrap_carry + _carry; \
        (acc)[7] = (uint32_t)(_sum & mask_lowest_17bits); \
        _carry = _sum >> 17; \
        _wrap_carry = (_mult_large)[7] >> 6; \
        \
        uint64_t _total_carry = (_carry + _wrap_carry) * 3; \
        uint64_t _sum0 = (uint64_t)(acc)[0] + _total_carry; \
        (acc)[0] = (uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry = _sum0 >> 28; \
        (acc)[1] += (uint32_t)_carry; \
        _carry = (acc)[1] >> 28; \
        (acc)[1] &= mask_lowest_28bits; \
        (acc)[2] += (uint32_t)_carry; \
    } while(0)

#define MULMOD_P_REMIF_4BLOCKS(acc, n1, n2, n3, n4) \
    do{ \
        uint64_t _mult_small[NUM_LIMBS] = {0}; \
        uint64_t _mult_large[NUM_LIMBS] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < NUM_LIMBS; _i++){ \
            uint64_t _n1_plus_acc_i = (uint64_t)((n1)[_i] + (acc)[_i]); \
            for (int _j = 0; _j < NUM_LIMBS - _i; _j++){ \
                (_mult_small)[_i+_j] += _n1_plus_acc_i* (r4)[_j] + (uint64_t)(n2)[_i]* (r3)[_j] \
                                    + (uint64_t)(n3)[_i]* (r2)[_j] + (uint64_t)(n4)[_i]* (r)[_j]; \
            } \
            for (int _j = NUM_LIMBS - _i; _j < NUM_LIMBS; _j++){ \
                (_mult_large)[_i+_j - NUM_LIMBS] += _n1_plus_acc_i* (three_r4)[_j] + (uint64_t)(n2)[_i]* (three_r3)[_j] \
                                                + (uint64_t)(n3)[_i]* (three_r2)[_j] + (uint64_t)(n4)[_i]* (three_r)[_j]; \
            } \
        } \
        \
        uint64_t _carry = 0; \
        uint64_t _wrap_carry = 0; \
        uint64_t _sum; \
        for(int _i = 0; _i < 7; _i++){ \
            _sum = _mult_small[_i] + (((_mult_large)[_i] & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
            (acc)[_i] = (uint32_t)(_sum & mask_lowest_28bits); \
            _carry = _sum >> 28; \
            _wrap_carry = (_mult_large)[_i] >> 17; \
        } \
        \
        _sum = _mult_small[7] + (((_mult_large)[7] & mask_lowest_6bits) << 11) + _wrap_carry + _carry; \
        (acc)[7] = (uint32_t)(_sum & mask_lowest_17bits); \
        _carry = _sum >> 17; \
        _wrap_carry = (_mult_large)[7] >> 6; \
        \
        uint64_t _total_carry = (_carry + _wrap_carry) * 3; \
        uint64_t _sum0 = (uint64_t)(acc)[0] + _total_carry; \
        (acc)[0] = (uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry = _sum0 >> 28; \
        (acc)[1] += (uint32_t)_carry; \
        _carry = (acc)[1] >> 28; \
        (acc)[1] &= mask_lowest_28bits; \
        (acc)[2] += (uint32_t)_carry; \
    } while(0)

#define MULMOD_P_VEC_4BLOCKS(acc, n1, n2, n3, n4) \
    do{ \
        uint64_t _mult_small[NUM_LIMBS] = {0}; \
        uint64_t _mult_large[NUM_LIMBS] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        __m256i vec_n[NUM_LIMBS]; \
        __m256i vec_r[NUM_LIMBS]; \
        __m256i vec_three_r[NUM_LIMBS]; \
        __m256i vec_mult_small[NUM_LIMBS]; \
        __m256i vec_mult_large[NUM_LIMBS]; \
        for (int _i = 0; _i < NUM_LIMBS; _i++) { \
            vec_mult_small[_i] = _mm256_setzero_si256(); \
            vec_mult_large[_i] = _mm256_setzero_si256(); \
            vec_r[_i] = _mm256_set_epi64x((r)[_i], (r2)[_i], (r3)[_i], (r4)[_i]); \
            vec_three_r[_i] = _mm256_set_epi64x((three_r)[_i], (three_r2)[_i], (three_r3)[_i], (three_r4)[_i]); \
            vec_n[_i] = _mm256_set_epi64x((uint64_t)(n4)[_i], (uint64_t)(n3)[_i], (uint64_t)(n2)[_i], (uint64_t)(n1)[_i] + (acc)[_i]); \
        } \
        for (int _i = 0; _i < NUM_LIMBS; _i++){ \
            \
            for (int _j = 0; _j < NUM_LIMBS - _i; _j++){ \
                (vec_mult_small)[_i+_j] = _mm256_add_epi64((vec_mult_small)[_i+_j], _mm256_mul_epu32(vec_n[_i], vec_r[_j])); \
            } \
            for (int _j = NUM_LIMBS - _i; _j < NUM_LIMBS; _j++){ \
                (vec_mult_large)[_i+_j - NUM_LIMBS] = _mm256_add_epi64((vec_mult_large)[_i+_j - NUM_LIMBS], _mm256_mul_epu32(vec_n[_i], vec_three_r[_j])); \
            } \
        } \
        \
        for(int _i = 0; _i < NUM_LIMBS; _i++){ \
            __m128i lo = _mm256_castsi256_si128(vec_mult_small[_i]); \
            __m128i hi = _mm256_extracti128_si256(vec_mult_small[_i], 1); \
            __m128i _sum_small = _mm_add_epi64(lo, hi); \
            _mult_small[_i] = (uint64_t)_mm_extract_epi64(_sum_small, 0) + (uint64_t)_mm_extract_epi64(_sum_small, 1); \
            \
            __m128i lo_l = _mm256_castsi256_si128(vec_mult_large[_i]); \
            __m128i hi_l = _mm256_extracti128_si256(vec_mult_large[_i], 1); \
            __m128i _sum_large = _mm_add_epi64(lo_l, hi_l); \
            _mult_large[_i] = (uint64_t)_mm_extract_epi64(_sum_large, 0) + (uint64_t)_mm_extract_epi64(_sum_large, 1); \
        } \
        uint64_t _carry = 0; \
        uint64_t _wrap_carry = 0; \
        uint64_t _sum; \
        for(int _i = 0; _i < 7; _i++){ \
            _sum = _mult_small[_i] + (((_mult_large)[_i] & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
            (acc)[_i] = (uint32_t)(_sum & mask_lowest_28bits); \
            _carry = _sum >> 28; \
            _wrap_carry = (_mult_large)[_i] >> 17; \
        } \
        \
        _sum = _mult_small[7] + (((_mult_large)[7] & mask_lowest_6bits) << 11) + _wrap_carry + _carry; \
        (acc)[7] = (uint32_t)(_sum & mask_lowest_17bits); \
        _carry = _sum >> 17; \
        _wrap_carry = (_mult_large)[7] >> 6; \
        \
        uint64_t _total_carry = (_carry + _wrap_carry) * 3; \
        uint64_t _sum0 = (uint64_t)(acc)[0] + _total_carry; \
        (acc)[0] = (uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry = _sum0 >> 28; \
        (acc)[1] += (uint32_t)_carry; \
        _carry = (acc)[1] >> 28; \
        (acc)[1] &= mask_lowest_28bits; \
        (acc)[2] += (uint32_t)_carry; \
    } while(0)

// --------------------------------------------------------------------
// --------------- TO_26_LE_BYTES variations ------------------
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
        \
        _t[6] |= ((in)[7] << 4); \
        for (int _i = 0; _i < TAG_SIZE; _i++) { \
            (out)[_i] = (unsigned char)((_t[_i / 4] >> ((_i % 4) * 8)) & 0xff); \
        } \
    } while (0)

#define TO_26_LE_BYTES_UNROLLED(out, in) \
    do { \
        uint32_t _t[7] = {0}; \
        _t[0] =  (uint32_t)((in)[0]) | (uint32_t)((in)[1] << 28); \
        _t[1] =  (uint32_t)((in)[1] >> 4) | (uint32_t)((in)[2] << 24); \
        _t[2] =  (uint32_t)((in)[2] >> 8) | (uint32_t)((in)[3] << 20); \
        _t[3] =  (uint32_t)((in)[3] >> 12) | (uint32_t)((in)[4] << 16); \
        _t[4] =  (uint32_t)((in)[4] >> 16) | (uint32_t)((in)[5] << 12); \
        _t[5] =  (uint32_t)((in)[5] >> 20) | (uint32_t)((in)[6] << 8); \
        _t[6] =  (uint32_t)((in)[6] >> 24) | (uint32_t)((in)[7] << 4); \
        \
        (out)[0]  = (unsigned char)(_t[0]); \
        (out)[1]  = (unsigned char)(_t[0] >> 8); \
        (out)[2]  = (unsigned char)(_t[0] >> 16); \
        (out)[3]  = (unsigned char)(_t[0] >> 24); \
        (out)[4]  = (unsigned char)(_t[1]); \
        (out)[5]  = (unsigned char)(_t[1] >> 8); \
        (out)[6]  = (unsigned char)(_t[1] >> 16); \
        (out)[7]  = (unsigned char)(_t[1] >> 24); \
        (out)[8]  = (unsigned char)(_t[2]); \
        (out)[9]  = (unsigned char)(_t[2] >> 8); \
        (out)[10] = (unsigned char)(_t[2] >> 16); \
        (out)[11] = (unsigned char)(_t[2] >> 24); \
        (out)[12] = (unsigned char)(_t[3]); \
        (out)[13] = (unsigned char)(_t[3] >> 8); \
        (out)[14] = (unsigned char)(_t[3] >> 16); \
        (out)[15] = (unsigned char)(_t[3] >> 24); \
        (out)[16] = (unsigned char)(_t[4]); \
        (out)[17] = (unsigned char)(_t[4] >> 8); \
        (out)[18] = (unsigned char)(_t[4] >> 16); \
        (out)[19] = (unsigned char)(_t[4] >> 24); \
        (out)[20] = (unsigned char)(_t[5]); \
        (out)[21] = (unsigned char)(_t[5] >> 8); \
        (out)[22] = (unsigned char)(_t[5] >> 16); \
        (out)[23] = (unsigned char)(_t[5] >> 24); \
        (out)[24] = (unsigned char)(_t[6]); \
        (out)[25] = (unsigned char)(_t[6] >> 8); \
    } while(0)
// --------------------------------------------------------------------



// ----------------------------- Baseline Version ------------------------------

// handle conversions from bytes to 7x28 + 17-bit representationfor length 26 and 27 
static void to_large_num_rep(uint32_t out[NUM_LIMBS], const unsigned char *bytes, uint64_t len_bytes){
    uint64_t t[NUM_LIMBS] = {0}; // initialize with zeros
    // convert the bytes into the 9*64-bit integer representation (LE format)
    for (uint64_t i = 0; i < len_bytes; i++){
        t[i/4] |= ((uint64_t)bytes[i] << ((i%4)*8)); 
    }


    for(int i = 0; i < 7; i++){
        int bit_start = 28*i; // compute where next 28 bits start in t
        int t_idx = bit_start / 32; // get idx of t which contains start of next 28 bits
        int bit_in_t = bit_start % 32; // get bit offset within t[t_idx]
        out[i] = (uint32_t)((t[t_idx] >> bit_in_t) | (t[t_idx + 1] << (32 - bit_in_t))) & mask_lowest_28bits; // extrat next 28 bits

    }

    // only save the lowest 17 bits in the last entry since we chose a representation of 7x28 + 17 bits
    out[7] = (uint32_t)(t[6] >> 4) & mask_lowest_17bits; 
}

// handles conversion from 7x28 + 17-bit representation to 26 bytes in LE format
static void to_26_le_bytes(uint32_t in[NUM_LIMBS], unsigned char out[TAG_SIZE]){
    uint32_t t[7] = {0};

    for(int i = 0; i < 7; i++){
        int bit_start = 28*i; // compute where next 28 bits start in t
        int t_idx = bit_start / 32; // get idx of t which contains start of next 28 bits
        int bit_in_t = bit_start % 32; // get bit offset within t[t_idx]
        t[t_idx] |= (uint32_t)((uint64_t)in[i] << bit_in_t); // write lower bits into t[t_idx]

        // if we cross 32 bit boundary, write remaining bits into t[t_idx + 1]
        if (bit_in_t + 28 > 32){
            t[t_idx + 1] |= (uint32_t)((uint64_t)in[i] >> (32 - bit_in_t));
        }
    }
    // handle last 17 bits (out[7] = t[6] >> 4)
    t[6] |= (in[7] << 4);

    // write t into out in LE format
    for (int i = 0; i < TAG_SIZE; i++){
        out[i] = (unsigned char)((t[i / 4] >> ((i% 4)* 8)) & 0xff); 
    }

}


// keylength must be 54 bytes
void poly2133_init_baseline(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    // split key into two halves (first half into r, other in s)
    int half_key_len = KEY_SIZE / 2;
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
    to_large_num_rep(r, r_bytes, half_key_len);
    
    // convert second half of key into 7x28 + 17-bit representation for s
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;

    to_large_num_rep(s, s_bytes, half_key_len);
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

// computes a = a + b (a and b need be in 5x26-bit representation)
static void add_large_nums_88(uint32_t a[NUM_LIMBS], const uint32_t b[NUM_LIMBS]){
    uint64_t carry = 0; // keeps track how much we exceeded 28 bits in each addition = carry
    // make the additions and keep track of carry
    for (int i = 0; i < 7; i++){
        carry = (uint64_t)a[i] + b[i] + carry; // add carry here as well
        a[i] = (uint32_t)(carry &mask_lowest_28bits); // keep lowest 28 bits
        carry >>= 28; // shift right by 28 bits (keep carry for next iteration)
    }

    // handle last 17 bits seperately
    carry = (uint64_t)a[7] + b[7] + carry;
    a[7] = (uint32_t)(carry & mask_lowest_17bits);
    carry >>= 17;

    // if carry is non-zero, we surpassed 2^213 -> need to compute mod (2^213 - 3) (specified by poly algorithm)
    a[0] += (uint32_t)(carry * 3);
}


// computes acc = acc * r mod p (where acc and r in 7x28 + 17 bit representation, p = 2^213 - 3)
static void mulmod_p(uint32_t acc[NUM_LIMBS], const uint32_t r[NUM_LIMBS]) {
    // use two seperate accumulators so we don't need uint128 
    uint64_t mult_small[NUM_LIMBS] = {0}; // handles all (i + j = k) contributions
    uint64_t mult_large[NUM_LIMBS] = {0}; // handles all (i + j = k + 8) contributions (where we wrap around, need to multiply by 3 and apply shift later)
    uint64_t mask_lowest_6bits = 0x3f; 

    for (int i = 0; i < NUM_LIMBS; i++){
        for(int j = 0; j < NUM_LIMBS; j++){
            int k = i+j;
            if (k < NUM_LIMBS){
                mult_small[k] += (uint64_t)acc[i]* r[j];
            }
            else{
                mult_large[k - NUM_LIMBS] += (uint64_t)acc[i]* 3*r[j];
            }
        }
    }

    uint64_t carry = 0;
    uint64_t wrap_carry = 0;

    // handle limbs 0 to 7, the last only contains 17 bits, so needs to be handled separately
    for(int i = 0; i < 7; i++){
        // wrap overflow might be larger 2^213 bits, so need to shift by 11
        uint64_t sum = mult_small[i] + ((mult_large[i] & mask_lowest_17bits) << 11) + wrap_carry + carry;
        acc[i] = (uint32_t)(sum & mask_lowest_28bits);
        carry = sum >> 28;
        wrap_carry = mult_large[i] >> 17;
    }

    // handle last limb separately
    // wrap overflow is shifted by 11 bits, so need to mask lowest 6 bits of mult_large so we don't add more than 6+11 = 17 bits to last limb
    uint64_t sum = mult_small[7] + ((mult_large[7] & mask_lowest_6bits) << 11) + wrap_carry + carry;
    acc[7] = (uint32_t)(sum & mask_lowest_17bits);
    carry = sum >> 17;
    wrap_carry = mult_large[7] >> 6;

    // if wrap_carry and/or carry are non-zero, multiply by 3 and add to acc[0], propagate up to acc[2] (since 3*2^213 < 2^28*3, we will never have to propagate further than acc[2])
    uint64_t total_carry = (carry + wrap_carry) * 3;
    uint64_t sum0 = (uint64_t)acc[0] + total_carry;
    acc[0] = (uint32_t)(sum0 & mask_lowest_28bits);
    carry = sum0 >> 28;
    acc[0] &= mask_lowest_28bits;
    acc[1] += (uint32_t)carry;
    carry = acc[1] >> 28;
    acc[1] &= mask_lowest_28bits;
    acc[2] += (uint32_t)carry;

}


// calculate authentication tag for data
// use block size of 26 bytes (maximal size still smaller p) 
// and tag will now be 27 bytes (just enough to represent a number in prime field)
unsigned char* poly2133_create_tag_baseline(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    for(uint64_t i = 0; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE ? (data_len - offset) : BLOCK_SIZE;
        unsigned char block[block_len + 1];
        memset(block, 0, block_len + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        uint32_t n[NUM_LIMBS];
        to_large_num_rep(n, block, block_len + 1); // convert representation of n to fit acc and r
        add_large_nums_88(acc, n); // acc += n 
        mulmod_p(acc, r); // acc = (acc * r) mod p
    }

    add_large_nums_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));
    to_26_le_bytes(acc, tag); // convert acc (7x28 + 17-bit representation) to 26 bytes (LE format)
    return tag;
}


// --------------------------------------------------------------------

// ----------------------------- Inlined Version ------------------------------
void poly2133_init_inlined(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
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
unsigned char* poly2133_create_tag_inlined(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
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
// --------------------------------------------------------------------

// ---------------------------- Unrolled Verion ----------------------------
void poly2133_init_unrolled(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
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
    TO_LARGE_NUM_REP_UNROLLED(r, r_bytes, half_key_len);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;

    // convert second half of key into 7x28 + 17-bit representation for s
    TO_LARGE_NUM_REP_UNROLLED(s, s_bytes, half_key_len);
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

// calculate authentication tag for data
// use block and tag size of 26 bytes (maximal size still smaller p) 
unsigned char* poly2133_create_tag_unrolled(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
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
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);

        // acc += n
        ADD_LARGE_NUMS_88(acc, n);

        // acc = (acc * r) mod p
        MULMOD_P(acc, r);
    }
    
    // acc += s
    ADD_LARGE_NUMS_88(acc, s);
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES_UNROLLED(tag, acc);
    return tag;
}
// --------------------------------------------------------------------

// -------------------------- 2-level approach without unrolling --------------------------
void poly2133_init_2level_basic(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
    // split key into two halves (first half into r, other in s)
    int half_key_len = KEY_SIZE / 2;
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
    to_large_num_rep(r, r_bytes, half_key_len);
    
    // convert second half of key into 7x28 + 17-bit representation for s
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;

    to_large_num_rep(s, s_bytes, half_key_len);
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}

unsigned char* poly2133_create_tag_2level_basic(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint64_t num_full_blocks = num_blocks / NUM_GROUPS;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r2, r); // r2 = r * r mod p

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r3, r); // r3 = r^2 * r mod p

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    mulmod_p(r4, r); // r4 = r^3 * r mod p

    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE + 1];
        unsigned char block2[BLOCK_SIZE + 1];
        unsigned char block3[BLOCK_SIZE + 1];
        unsigned char block4[BLOCK_SIZE + 1];
        uint32_t n1[NUM_LIMBS];
        uint32_t n2[NUM_LIMBS];
        uint32_t n3[NUM_LIMBS];
        uint32_t n4[NUM_LIMBS];

        uint64_t offset1 = i*4 * BLOCK_SIZE;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE;


        memcpy(block1, data + offset1, BLOCK_SIZE);
        memcpy(block2, data + offset2, BLOCK_SIZE);
        memcpy(block3, data + offset3, BLOCK_SIZE);
        memcpy(block4, data + offset4, BLOCK_SIZE);
        block1[BLOCK_SIZE] = 0x01;
        block2[BLOCK_SIZE] = 0x01;
        block3[BLOCK_SIZE] = 0x01;
        block4[BLOCK_SIZE] = 0x01;
   
        to_large_num_rep(n1, block1, BLOCK_SIZE + 1); // convert representation of n to fit acc and r
        to_large_num_rep(n2, block2, BLOCK_SIZE + 1); 
        to_large_num_rep(n3, block3, BLOCK_SIZE + 1); 
        to_large_num_rep(n4, block4, BLOCK_SIZE + 1);

        mulmod_p(n1, r4); // n1 = n1 * r^4 mod p
        mulmod_p(n2, r3); // n2 = n2 * r^3 mod p
        mulmod_p(n3, r2); // n3 = n3 * r^2 mod p
        mulmod_p(n4, r); // n4 = n4 * r mod p
   
        add_large_nums_88(n1, n2); // n1 += n2
        add_large_nums_88(n1, n3); // n1 += n3
        add_large_nums_88(n1, n4); // n1 += n4

        mulmod_p(acc, r4); // acc = acc * r^4 mod p
        add_large_nums_88(acc, n1); // acc += n1

    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE ? (data_len - offset) : BLOCK_SIZE;
        unsigned char block[BLOCK_SIZE + 1];
        uint32_t n[NUM_LIMBS];
        memset(block, 0, BLOCK_SIZE + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        to_large_num_rep(n, block, block_len + 1); // convert representation of n to fit acc and r
        add_large_nums_88(acc, n); // acc += n
        mulmod_p(acc, r);
    }

    add_large_nums_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));
    to_26_le_bytes(acc, tag); // convert acc (7x28 + 17-bit representation) to 26 bytes (LE format)
    return tag;
}

// --------------------------------------------------------------------

// -------------------------- 2-level approach inlined & unrolled --------------------------
void poly2133_init_2level_inl_unr(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
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
    TO_LARGE_NUM_REP_UNROLLED(r, r_bytes, half_key_len);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    // convert second half of key into 7x28 + 17-bit representation for s
    TO_LARGE_NUM_REP_UNROLLED(s, s_bytes, half_key_len);
    
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}


unsigned char* poly2133_create_tag_2level_inl_unr(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint64_t num_full_blocks = num_blocks / NUM_GROUPS;

    // precompute r^2, r^3 and r^4
    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P(r2, r);
    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P(r3, r);
    memcpy(r4, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P(r4, r2);
    
    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE + 1];
        unsigned char block2[BLOCK_SIZE + 1];
        unsigned char block3[BLOCK_SIZE + 1];
        unsigned char block4[BLOCK_SIZE + 1];
        uint32_t n1[NUM_LIMBS];
        uint32_t n2[NUM_LIMBS];
        uint32_t n3[NUM_LIMBS];
        uint32_t n4[NUM_LIMBS];

        uint64_t offset1 = i*4 * BLOCK_SIZE;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE;

        memcpy(block1, data + offset1, BLOCK_SIZE);
        memcpy(block2, data + offset2, BLOCK_SIZE);
        memcpy(block3, data + offset3, BLOCK_SIZE);
        memcpy(block4, data + offset4, BLOCK_SIZE);
        block1[BLOCK_SIZE] = 0x01;
        block2[BLOCK_SIZE] = 0x01;
        block3[BLOCK_SIZE] = 0x01;
        block4[BLOCK_SIZE] = 0x01;

        TO_LARGE_NUM_REP_MSG_UNROLLED(n1, block1, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG_UNROLLED(n2, block2, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG_UNROLLED(n3, block3, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG_UNROLLED(n4, block4, BLOCK_SIZE + 1);

        // n1 = n1 * r^4 mod p:
        MULMOD_P(n1, r4);

        // n2 = n2 * r^3 mod p:
        MULMOD_P(n2, r3);

        // n3 = n3 * r^2 mod p
        MULMOD_P(n3, r2);
        
        // n4 = n4 * r mod p
        MULMOD_P(n4, r);
        
        // n1 += n2 + n3 + n4
        ADD_LARGE_NUMS_88(n1, n2);
        ADD_LARGE_NUMS_88(n1, n3);
        ADD_LARGE_NUMS_88(n1, n4);
 
        // acc = acc * r^4 mod p (increase acc in steps of r^NUM_GROUPS)
        MULMOD_P(acc, r4);

        // acc += n1
        ADD_LARGE_NUMS_88(acc, n1);
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE ? (data_len - offset) : BLOCK_SIZE;
        unsigned char block[BLOCK_SIZE + 1];
        uint32_t n[NUM_LIMBS];
        memset(block, 0, BLOCK_SIZE + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P(acc, r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s

    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- 2-level approach + delayed carry + inlined + unrolled --------------------------
void poly2133_init_delcarry(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
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
    TO_LARGE_NUM_REP_UNROLLED(r, r_bytes, half_key_len);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    // convert second half of key into 7x28 + 17-bit representation for s
    TO_LARGE_NUM_REP_UNROLLED(s, s_bytes, half_key_len);
    
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}


unsigned char* poly2133_create_tag_delcarry(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint64_t num_full_blocks = num_blocks / NUM_GROUPS;

    // precompute r^2, r^3 and r^4
    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P(r2, r);
    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P(r3, r);
    memcpy(r4, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P(r4, r2);
    
    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE + 1];
        unsigned char block2[BLOCK_SIZE + 1];
        unsigned char block3[BLOCK_SIZE + 1];
        unsigned char block4[BLOCK_SIZE + 1];
        uint32_t n1[NUM_LIMBS];
        uint32_t n2[NUM_LIMBS];
        uint32_t n3[NUM_LIMBS];
        uint32_t n4[NUM_LIMBS];

        uint64_t offset1 = i*4 * BLOCK_SIZE;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE;

        memcpy(block1, data + offset1, BLOCK_SIZE);
        memcpy(block2, data + offset2, BLOCK_SIZE);
        memcpy(block3, data + offset3, BLOCK_SIZE);
        memcpy(block4, data + offset4, BLOCK_SIZE);
        block1[BLOCK_SIZE] = 0x01;
        block2[BLOCK_SIZE] = 0x01;
        block3[BLOCK_SIZE] = 0x01;
        block4[BLOCK_SIZE] = 0x01;

        TO_LARGE_NUM_REP_MSG_UNROLLED(n1, block1, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG_UNROLLED(n2, block2, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG_UNROLLED(n3, block3, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG_UNROLLED(n4, block4, BLOCK_SIZE + 1);

        MULMOD_P_DELCARRY_4BLOCKS(acc, n1, n2, n3, n4);
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE ? (data_len - offset) : BLOCK_SIZE;
        unsigned char block[BLOCK_SIZE + 1];
        uint32_t n[NUM_LIMBS];
        memset(block, 0, BLOCK_SIZE + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P(acc, r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- precomputation + 2-level approach + delayed carry + inlined + unrolled --------------------------
void poly2133_init_precomp(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
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
    TO_LARGE_NUM_REP_UNROLLED(r, r_bytes, half_key_len);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    // convert second half of key into 7x28 + 17-bit representation for s
    TO_LARGE_NUM_REP_UNROLLED(s, s_bytes, half_key_len);
    
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}


unsigned char* poly2133_create_tag_precomp(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint64_t num_full_blocks = num_blocks / NUM_GROUPS;

    // precompute r^2, r^3 and r^4
    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t three_r[NUM_LIMBS];
    uint32_t three_r2[NUM_LIMBS];
    uint32_t three_r3[NUM_LIMBS];
    uint32_t three_r4[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++){
        three_r[i] = 3*r[i];
    }
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P_PRECOMP(r2, r, three_r);
    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P_PRECOMP(r3, r, three_r);
    for(int i = 0; i < NUM_LIMBS; i++){
        three_r2[i] = 3*r2[i];
    }
    memcpy(r4, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P_PRECOMP(r4, r2, three_r2);
    for(int i = 0; i < NUM_LIMBS; i++){
        three_r3[i] = 3*r3[i];
        three_r4[i] = 3*r4[i];
    }
    
    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE + 1];
        unsigned char block2[BLOCK_SIZE + 1];
        unsigned char block3[BLOCK_SIZE + 1];
        unsigned char block4[BLOCK_SIZE + 1];
        uint32_t n1[NUM_LIMBS];
        uint32_t n2[NUM_LIMBS];
        uint32_t n3[NUM_LIMBS];
        uint32_t n4[NUM_LIMBS];

        uint64_t offset1 = i*4 * BLOCK_SIZE;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE;

        memcpy(block1, data + offset1, BLOCK_SIZE);
        memcpy(block2, data + offset2, BLOCK_SIZE);
        memcpy(block3, data + offset3, BLOCK_SIZE);
        memcpy(block4, data + offset4, BLOCK_SIZE);
        block1[BLOCK_SIZE] = 0x01;
        block2[BLOCK_SIZE] = 0x01;
        block3[BLOCK_SIZE] = 0x01;
        block4[BLOCK_SIZE] = 0x01;

        TO_LARGE_NUM_REP_MSG_UNROLLED(n1, block1, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG_UNROLLED(n2, block2, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG_UNROLLED(n3, block3, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG_UNROLLED(n4, block4, BLOCK_SIZE + 1);

        MULMOD_P_PRECOMP_4BLOCKS(acc, n1, n2, n3, n4);
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE ? (data_len - offset) : BLOCK_SIZE;
        unsigned char block[BLOCK_SIZE + 1];
        uint32_t n[NUM_LIMBS];
        memset(block, 0, BLOCK_SIZE + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P_PRECOMP(acc, r, three_r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- remove if/else + precomputation + 2-level approach + delayed carry + inlined + unrolled --------------------------
void poly2133_init_remif(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
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
    TO_LARGE_NUM_REP_UNROLLED(r, r_bytes, half_key_len);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    // convert second half of key into 7x28 + 17-bit representation for s
    TO_LARGE_NUM_REP_UNROLLED(s, s_bytes, half_key_len);
    
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}


unsigned char* poly2133_create_tag_remif(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint64_t num_full_blocks = num_blocks / NUM_GROUPS;

    // precompute r^2, r^3 and r^4
    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t three_r[NUM_LIMBS];
    uint32_t three_r2[NUM_LIMBS];
    uint32_t three_r3[NUM_LIMBS];
    uint32_t three_r4[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++){
        three_r[i] = 3*r[i];
    }
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P_REMIF(r2, r, three_r);
    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P_REMIF(r3, r, three_r);
    for(int i = 0; i < NUM_LIMBS; i++){
        three_r2[i] = 3*r2[i];
    }
    memcpy(r4, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P_REMIF(r4, r2, three_r2);
    for(int i = 0; i < NUM_LIMBS; i++){
        three_r3[i] = 3*r3[i];
        three_r4[i] = 3*r4[i];
    }
    
    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE + 1];
        unsigned char block2[BLOCK_SIZE + 1];
        unsigned char block3[BLOCK_SIZE + 1];
        unsigned char block4[BLOCK_SIZE + 1];
        uint32_t n1[NUM_LIMBS];
        uint32_t n2[NUM_LIMBS];
        uint32_t n3[NUM_LIMBS];
        uint32_t n4[NUM_LIMBS];

        uint64_t offset1 = i*4 * BLOCK_SIZE;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE;

        memcpy(block1, data + offset1, BLOCK_SIZE);
        memcpy(block2, data + offset2, BLOCK_SIZE);
        memcpy(block3, data + offset3, BLOCK_SIZE);
        memcpy(block4, data + offset4, BLOCK_SIZE);
        block1[BLOCK_SIZE] = 0x01;
        block2[BLOCK_SIZE] = 0x01;
        block3[BLOCK_SIZE] = 0x01;
        block4[BLOCK_SIZE] = 0x01;

        TO_LARGE_NUM_REP_MSG27_UNROLLED(n1, block1, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n2, block2, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n3, block3, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n4, block4, BLOCK_SIZE + 1);

        MULMOD_P_REMIF_4BLOCKS(acc, n1, n2, n3, n4);
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE ? (data_len - offset) : BLOCK_SIZE;
        unsigned char block[BLOCK_SIZE + 1];
        uint32_t n[NUM_LIMBS];
        memset(block, 0, BLOCK_SIZE + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P_REMIF(acc, r, three_r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- vectorized + remove if/else + precomputation + 2-level approach + delayed carry + inlined + unrolled --------------------------
void poly2133_init_vec(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char key[KEY_SIZE]) {
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
    TO_LARGE_NUM_REP_UNROLLED(r, r_bytes, half_key_len);
    
    unsigned char s_bytes[half_key_len];
    memcpy(s_bytes, key + half_key_len, half_key_len);
    // make sure s is not > p
    s_bytes[half_key_len - 1] &= clear_top4_bits;
    // convert second half of key into 7x28 + 17-bit representation for s
    TO_LARGE_NUM_REP_UNROLLED(s, s_bytes, half_key_len);
    
    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 
}


unsigned char* poly2133_create_tag_vec(uint32_t acc[NUM_LIMBS], uint32_t r[NUM_LIMBS], uint32_t s[NUM_LIMBS], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE - 1) / BLOCK_SIZE;
    uint64_t num_full_blocks = num_blocks / NUM_GROUPS;

    // precompute r^2, r^3 and r^4
    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t three_r[NUM_LIMBS];
    uint32_t three_r2[NUM_LIMBS];
    uint32_t three_r3[NUM_LIMBS];
    uint32_t three_r4[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++){
        three_r[i] = 3*r[i];
    }
    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P_REMIF(r2, r, three_r);
    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P_REMIF(r3, r, three_r);
    for(int i = 0; i < NUM_LIMBS; i++){
        three_r2[i] = 3*r2[i];
    }
    memcpy(r4, r2,  NUM_LIMBS * sizeof(uint32_t));
    MULMOD_P_REMIF(r4, r2, three_r2);
    for(int i = 0; i < NUM_LIMBS; i++){
        three_r3[i] = 3*r3[i];
        three_r4[i] = 3*r4[i];
    }
    
    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE + 1];
        unsigned char block2[BLOCK_SIZE + 1];
        unsigned char block3[BLOCK_SIZE + 1];
        unsigned char block4[BLOCK_SIZE + 1];
        uint32_t n1[NUM_LIMBS];
        uint32_t n2[NUM_LIMBS];
        uint32_t n3[NUM_LIMBS];
        uint32_t n4[NUM_LIMBS];

        uint64_t offset1 = i*4 * BLOCK_SIZE;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE;

        memcpy(block1, data + offset1, BLOCK_SIZE);
        memcpy(block2, data + offset2, BLOCK_SIZE);
        memcpy(block3, data + offset3, BLOCK_SIZE);
        memcpy(block4, data + offset4, BLOCK_SIZE);
        block1[BLOCK_SIZE] = 0x01;
        block2[BLOCK_SIZE] = 0x01;
        block3[BLOCK_SIZE] = 0x01;
        block4[BLOCK_SIZE] = 0x01;

        TO_LARGE_NUM_REP_MSG27_UNROLLED(n1, block1, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n2, block2, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n3, block3, BLOCK_SIZE + 1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n4, block4, BLOCK_SIZE + 1);

        MULMOD_P_VEC_4BLOCKS(acc, n1, n2, n3, n4);
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE ? (data_len - offset) : BLOCK_SIZE;
        unsigned char block[BLOCK_SIZE + 1];
        uint32_t n[NUM_LIMBS];
        memset(block, 0, BLOCK_SIZE + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P_REMIF(acc, r, three_r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------