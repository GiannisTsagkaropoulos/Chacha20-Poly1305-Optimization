#include <stdint.h> 
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>
#include "poly2133_opt.h"


// ---------------  TO_LARGE_NUM_REP variations ------------------
#define TO_LARGE_NUM_REP(out, bytes, len) \
    do { \
        uint64_t _tr[LIMBS_2133] = {0}; \
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
        uint64_t _tr[LIMBS_2133] = {0}; \
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
        uint64_t _tr[LIMBS_2133] = {0}; \
        uint64_t bound = (len) - 3; \
        for (uint64_t _i = 0; _i < bound; _i+=4) { \
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

// this is for fixed size of len = 27
#define TO_LARGE_NUM_REP_MSG27_UNROLLED(out, bytes) \
    do { \
        uint64_t _tr[LIMBS_2133] = {0}; \
        \
        _tr[0] = (uint64_t)(bytes)[0] \
              | ((uint64_t)(bytes)[1] << 8) \
              | ((uint64_t)(bytes)[2] << 16) \
              | ((uint64_t)(bytes)[3] << 24); \
        \
        _tr[1] = (uint64_t)(bytes)[4] \
              | ((uint64_t)(bytes)[5] << 8) \
              | ((uint64_t)(bytes)[6] << 16) \
              | ((uint64_t)(bytes)[7] << 24); \
        \
        _tr[2] = (uint64_t)(bytes)[8] \
              | ((uint64_t)(bytes)[9] << 8) \
              | ((uint64_t)(bytes)[10] << 16) \
              | ((uint64_t)(bytes)[11] << 24); \
        \
        _tr[3] = (uint64_t)(bytes)[12] \
              | ((uint64_t)(bytes)[13] << 8) \
              | ((uint64_t)(bytes)[14] << 16) \
              | ((uint64_t)(bytes)[15] << 24); \
        \
        _tr[4] = (uint64_t)(bytes)[16] \
              | ((uint64_t)(bytes)[17] << 8) \
              | ((uint64_t)(bytes)[18] << 16) \
              | ((uint64_t)(bytes)[19] << 24); \
        \
        _tr[5] = (uint64_t)(bytes)[20] \
              | ((uint64_t)(bytes)[21] << 8) \
              | ((uint64_t)(bytes)[22] << 16) \
              | ((uint64_t)(bytes)[23] << 24); \
        \
        _tr[6] = (uint64_t)(bytes)[24] \
              | ((uint64_t)(bytes)[25] << 8) \
              | ((uint64_t)(bytes)[26] << 16); \
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

#define TO_LARGE_NUM_REP_MSG27_VEC(out, bytes, len) \
    do { \
        __m128i _bytes16_lo = _mm_loadu_si128((__m128i*)(bytes)); \
        __m128i _bytes16_hi = _mm_loadu_si128((__m128i*)((bytes) + 11)); \
        __m128i _bytes16_hi_shifted = _mm_srli_si128(_bytes16_hi, 1); \
        \
        __m256i _tr_low = _mm256_cvtepu32_epi64(_bytes16_lo); \
        __m256i _tr_high = _mm256_cvtepu32_epi64(_bytes16_hi_shifted); \
        \
        uint64_t _tr[LIMBS_2133] = {0}; \
        _mm256_storeu_si256((__m256i*)&_tr[0], _tr_low); \
        _mm256_storeu_si256((__m256i*)&_tr[3], _tr_high); \
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
        uint64_t _mult_small[LIMBS_2133] = {0}; \
        uint64_t _mult_large[LIMBS_2133] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < LIMBS_2133; _i++){ \
            for(int _j = 0; _j < LIMBS_2133; _j++){ \
                int _k = _i+_j; \
                if (_k < LIMBS_2133){ \
                    (_mult_small)[_k] += (uint64_t)(acc)[_i]* (r)[_j]; \
                } \
                else{ \
                    (_mult_large)[_k - LIMBS_2133] += (uint64_t)(acc)[_i]* 3*(r)[_j]; \
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
        uint64_t _mult_small[LIMBS_2133] = {0}; \
        uint64_t _mult_large[LIMBS_2133] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < LIMBS_2133; _i++){ \
            for(int _j = 0; _j < LIMBS_2133; _j++){ \
                int _k = _i+_j; \
                if (_k < LIMBS_2133){ \
                    (_mult_small)[_k] += (uint64_t)(acc)[_i]* (r)[_j]; \
                } \
                else{ \
                    (_mult_large)[_k - LIMBS_2133] += (uint64_t)(acc)[_i]* (three_r)[_j]; \
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
        uint64_t _mult_small[LIMBS_2133] = {0}; \
        uint64_t _mult_large[LIMBS_2133] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < LIMBS_2133; _i++){ \
            for (int _j = 0; _j < LIMBS_2133 - _i; _j++){ \
                _mult_small[_i+_j] += (uint64_t)(acc)[_i] * (r)[_j]; \
            } \
            for (int _j = LIMBS_2133 - _i; _j < LIMBS_2133; _j++){ \
                _mult_large[_i+_j - LIMBS_2133] += (uint64_t)(acc)[_i] * (three_r)[_j]; \
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
        uint64_t _mult_small[LIMBS_2133] = {0}; \
        uint64_t _mult_large[LIMBS_2133] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < LIMBS_2133; _i++){ \
            for(int _j = 0; _j < LIMBS_2133; _j++){ \
                int _k = _i+_j; \
                if (_k < LIMBS_2133){ \
                    (_mult_small)[_k] += (uint64_t)(n1)[_i]* (r4)[_j] + (uint64_t)(n2)[_i]* (r3)[_j] \
                                    + (uint64_t)(n3)[_i]* (r2)[_j] + (uint64_t)(n4)[_i]* (r)[_j] \
                                    + (uint64_t)(acc)[_i]* (r4)[_j]; \
                } \
                else{ \
                    (_mult_large)[_k - LIMBS_2133] += (uint64_t)(n1)[_i]* 3*(r4)[_j] + (uint64_t)(n2)[_i]* 3*(r3)[_j] \
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
        uint64_t _mult_small[LIMBS_2133] = {0}; \
        uint64_t _mult_large[LIMBS_2133] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < LIMBS_2133; _i++){ \
            uint64_t _n1_plus_acc_i = (uint64_t)((n1)[_i] + (acc)[_i]); \
            for(int _j = 0; _j < LIMBS_2133; _j++){ \
                int _k = _i+_j; \
                if (_k < LIMBS_2133){ \
                    (_mult_small)[_k] += _n1_plus_acc_i* (r4)[_j] + (uint64_t)(n2)[_i]* (r3)[_j] \
                                    + (uint64_t)(n3)[_i]* (r2)[_j] + (uint64_t)(n4)[_i]* (r)[_j]; \
                } \
                else{ \
                    (_mult_large)[_k - LIMBS_2133] += _n1_plus_acc_i* (three_r4)[_j] + (uint64_t)(n2)[_i]* (three_r3)[_j] \
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
        uint64_t _mult_small[LIMBS_2133] = {0}; \
        uint64_t _mult_large[LIMBS_2133] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        for (int _i = 0; _i < LIMBS_2133; _i++){ \
            uint64_t _n1_plus_acc_i = (uint64_t)((n1)[_i] + (acc)[_i]); \
            for (int _j = 0; _j < LIMBS_2133 - _i; _j++){ \
                (_mult_small)[_i+_j] += _n1_plus_acc_i* (r4)[_j] + (uint64_t)(n2)[_i]* (r3)[_j] \
                                    + (uint64_t)(n3)[_i]* (r2)[_j] + (uint64_t)(n4)[_i]* (r)[_j]; \
            } \
            for (int _j = LIMBS_2133 - _i; _j < LIMBS_2133; _j++){ \
                (_mult_large)[_i+_j - LIMBS_2133] += _n1_plus_acc_i* (three_r4)[_j] + (uint64_t)(n2)[_i]* (three_r3)[_j] \
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

// need to do computations limb for limb and propagate carry immediately, so we use as little registers as possible (does not get faster then delcarry though (with -O3))
#define MULMOD_P_SCALREP_4BLOCKS(acc, n1, n2, n3, n4) \
    do{ \
        uint64_t mask_lowest_6bits = 0x3f; \
        /* store the limbs of all accumulators in scalars (also precompute n1 + acc) */ \
        uint64_t _a0 = (uint64_t)((n1)[0] + (acc)[0]), _b0 = (uint64_t)(n2)[0], _c0 = (uint64_t)(n3)[0], _d0 = (uint64_t)(n4)[0]; \
        uint64_t _a1 = (uint64_t)((n1)[1] +(acc)[1]), _b1 = (uint64_t)(n2)[1], _c1 = (uint64_t)(n3)[1], _d1 = (uint64_t)(n4)[1]; \
        uint64_t _a2 = (uint64_t)((n1)[2] + (acc)[2]), _b2 = (uint64_t)(n2)[2], _c2 = (uint64_t)(n3)[2], _d2 = (uint64_t)(n4)[2]; \
        uint64_t _a3 = (uint64_t)((n1)[3] + (acc)[3]), _b3 = (uint64_t)(n2)[3], _c3 = (uint64_t)(n3)[3], _d3 = (uint64_t)(n4)[3]; \
        uint64_t _a4 = (uint64_t)((n1)[4] + (acc)[4]), _b4 = (uint64_t)(n2)[4], _c4 = (uint64_t)(n3)[4], _d4 = (uint64_t)(n4)[4]; \
        uint64_t _a5 = (uint64_t)((n1)[5] + (acc)[5]), _b5 = (uint64_t)(n2)[5], _c5 = (uint64_t)(n3)[5], _d5 = (uint64_t)(n4)[5]; \
        uint64_t _a6 = (uint64_t)((n1)[6] + (acc)[6]), _b6 = (uint64_t)(n2)[6], _c6 = (uint64_t)(n3)[6], _d6 = (uint64_t)(n4)[6]; \
        uint64_t _a7 = (uint64_t)((n1)[7] + (acc)[7]), _b7 = (uint64_t)(n2)[7], _c7 = (uint64_t)(n3)[7], _d7 = (uint64_t)(n4)[7]; \
        \
        uint64_t _carry = 0, _wrap_carry = 0, _sum, _ms, _ml; \
        /* compute mult_small and mutl_large for limb 0 and immediately store in acc[0] and handle carry */ \
        _ms = _a0*(r4)[0] + _b0*(r3)[0] + _c0*(r2)[0] + _d0*(r)[0]; \
        _ml = _a1*(three_r4)[7] + _b1*(three_r3)[7] + _c1*(three_r2)[7] + _d1*(three_r)[7] \
            + _a2*(three_r4)[6] + _b2*(three_r3)[6] + _c2*(three_r2)[6] + _d2*(three_r)[6] \
            + _a3*(three_r4)[5] + _b3*(three_r3)[5] + _c3*(three_r2)[5] + _d3*(three_r)[5] \
            + _a4*(three_r4)[4] + _b4*(three_r3)[4] + _c4*(three_r2)[4] + _d4*(three_r)[4] \
            + _a5*(three_r4)[3] + _b5*(three_r3)[3] + _c5*(three_r2)[3] + _d5*(three_r)[3] \
            + _a6*(three_r4)[2] + _b6*(three_r3)[2] + _c6*(three_r2)[2] + _d6*(three_r)[2] \
            + _a7*(three_r4)[1] + _b7*(three_r3)[1] + _c7*(three_r2)[1] + _d7*(three_r)[1]; \
        _sum = _ms + ((_ml & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
        (acc)[0] = (uint32_t)(_sum & mask_lowest_28bits); \
        _carry = _sum >> 28; _wrap_carry = _ml >> 17; \
        /* do same for limb 1 */ \
        _ms = _a0*(r4)[1] + _b0*(r3)[1] + _c0*(r2)[1] + _d0*(r)[1] \
            + _a1*(r4)[0] + _b1*(r3)[0] + _c1*(r2)[0] + _d1*(r)[0]; \
        _ml = _a2*(three_r4)[7] + _b2*(three_r3)[7] + _c2*(three_r2)[7] + _d2*(three_r)[7] \
            + _a3*(three_r4)[6] + _b3*(three_r3)[6] + _c3*(three_r2)[6] + _d3*(three_r)[6] \
            + _a4*(three_r4)[5] + _b4*(three_r3)[5] + _c4*(three_r2)[5] + _d4*(three_r)[5] \
            + _a5*(three_r4)[4] + _b5*(three_r3)[4] + _c5*(three_r2)[4] + _d5*(three_r)[4] \
            + _a6*(three_r4)[3] + _b6*(three_r3)[3] + _c6*(three_r2)[3] + _d6*(three_r)[3] \
            + _a7*(three_r4)[2] + _b7*(three_r3)[2] + _c7*(three_r2)[2] + _d7*(three_r)[2]; \
        _sum = _ms + ((_ml & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
        (acc)[1] = (uint32_t)(_sum & mask_lowest_28bits); \
        _carry = _sum >> 28; _wrap_carry = _ml >> 17; \
        /* limb 2 */ \
        _ms = _a0*(r4)[2] + _b0*(r3)[2] + _c0*(r2)[2] + _d0*(r)[2] \
            + _a1*(r4)[1] + _b1*(r3)[1] + _c1*(r2)[1] + _d1*(r)[1] \
            + _a2*(r4)[0] + _b2*(r3)[0] + _c2*(r2)[0] + _d2*(r)[0]; \
        _ml = _a3*(three_r4)[7] + _b3*(three_r3)[7] + _c3*(three_r2)[7] + _d3*(three_r)[7] \
            + _a4*(three_r4)[6] + _b4*(three_r3)[6] + _c4*(three_r2)[6] + _d4*(three_r)[6] \
            + _a5*(three_r4)[5] + _b5*(three_r3)[5] + _c5*(three_r2)[5] + _d5*(three_r)[5] \
            + _a6*(three_r4)[4] + _b6*(three_r3)[4] + _c6*(three_r2)[4] + _d6*(three_r)[4] \
            + _a7*(three_r4)[3] + _b7*(three_r3)[3] + _c7*(three_r2)[3] + _d7*(three_r)[3]; \
        _sum = _ms + ((_ml & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
        (acc)[2] = (uint32_t)(_sum & mask_lowest_28bits); \
        _carry = _sum >> 28; _wrap_carry = _ml >> 17; \
        /* limb 3 */ \
        _ms = _a0*(r4)[3] + _b0*(r3)[3] + _c0*(r2)[3] + _d0*(r)[3] \
            + _a1*(r4)[2] + _b1*(r3)[2] + _c1*(r2)[2] + _d1*(r)[2] \
            + _a2*(r4)[1] + _b2*(r3)[1] + _c2*(r2)[1] + _d2*(r)[1] \
            + _a3*(r4)[0] + _b3*(r3)[0] + _c3*(r2)[0] + _d3*(r)[0]; \
        _ml = _a4*(three_r4)[7] + _b4*(three_r3)[7] + _c4*(three_r2)[7] + _d4*(three_r)[7] \
            + _a5*(three_r4)[6] + _b5*(three_r3)[6] + _c5*(three_r2)[6] + _d5*(three_r)[6] \
            + _a6*(three_r4)[5] + _b6*(three_r3)[5] + _c6*(three_r2)[5] + _d6*(three_r)[5] \
            + _a7*(three_r4)[4] + _b7*(three_r3)[4] + _c7*(three_r2)[4] + _d7*(three_r)[4]; \
        _sum = _ms + ((_ml & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
        (acc)[3] = (uint32_t)(_sum & mask_lowest_28bits); \
        _carry = _sum >> 28; _wrap_carry = _ml >> 17; \
        /* limb 4 */ \
        _ms = _a0*(r4)[4] + _b0*(r3)[4] + _c0*(r2)[4] + _d0*(r)[4] \
            + _a1*(r4)[3] + _b1*(r3)[3] + _c1*(r2)[3] + _d1*(r)[3] \
            + _a2*(r4)[2] + _b2*(r3)[2] + _c2*(r2)[2] + _d2*(r)[2] \
            + _a3*(r4)[1] + _b3*(r3)[1] + _c3*(r2)[1] + _d3*(r)[1] \
            + _a4*(r4)[0] + _b4*(r3)[0] + _c4*(r2)[0] + _d4*(r)[0]; \
        _ml = _a5*(three_r4)[7] + _b5*(three_r3)[7] + _c5*(three_r2)[7] + _d5*(three_r)[7] \
            + _a6*(three_r4)[6] + _b6*(three_r3)[6] + _c6*(three_r2)[6] + _d6*(three_r)[6] \
            + _a7*(three_r4)[5] + _b7*(three_r3)[5] + _c7*(three_r2)[5] + _d7*(three_r)[5]; \
        _sum = _ms + ((_ml & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
        (acc)[4] = (uint32_t)(_sum & mask_lowest_28bits); \
        _carry = _sum >> 28; _wrap_carry = _ml >> 17; \
        /* limb 5 */ \
        _ms = _a0*(r4)[5] + _b0*(r3)[5] + _c0*(r2)[5] + _d0*(r)[5] \
            + _a1*(r4)[4] + _b1*(r3)[4] + _c1*(r2)[4] + _d1*(r)[4] \
            + _a2*(r4)[3] + _b2*(r3)[3] + _c2*(r2)[3] + _d2*(r)[3] \
            + _a3*(r4)[2] + _b3*(r3)[2] + _c3*(r2)[2] + _d3*(r)[2] \
            + _a4*(r4)[1] + _b4*(r3)[1] + _c4*(r2)[1] + _d4*(r)[1] \
            + _a5*(r4)[0] + _b5*(r3)[0] + _c5*(r2)[0] + _d5*(r)[0]; \
        _ml = _a6*(three_r4)[7] + _b6*(three_r3)[7] + _c6*(three_r2)[7] + _d6*(three_r)[7] \
            + _a7*(three_r4)[6] + _b7*(three_r3)[6] + _c7*(three_r2)[6] + _d7*(three_r)[6]; \
        _sum = _ms + ((_ml & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
        (acc)[5] = (uint32_t)(_sum & mask_lowest_28bits); \
        _carry = _sum >> 28; _wrap_carry = _ml >> 17; \
        /* limb 6 */ \
        _ms = _a0*(r4)[6] + _b0*(r3)[6] + _c0*(r2)[6] + _d0*(r)[6] \
            + _a1*(r4)[5] + _b1*(r3)[5] + _c1*(r2)[5] + _d1*(r)[5] \
            + _a2*(r4)[4] + _b2*(r3)[4] + _c2*(r2)[4] + _d2*(r)[4] \
            + _a3*(r4)[3] + _b3*(r3)[3] + _c3*(r2)[3] + _d3*(r)[3] \
            + _a4*(r4)[2] + _b4*(r3)[2] + _c4*(r2)[2] + _d4*(r)[2] \
            + _a5*(r4)[1] + _b5*(r3)[1] + _c5*(r2)[1] + _d5*(r)[1] \
            + _a6*(r4)[0] + _b6*(r3)[0] + _c6*(r2)[0] + _d6*(r)[0]; \
        _ml = _a7*(three_r4)[7] + _b7*(three_r3)[7] + _c7*(three_r2)[7] + _d7*(three_r)[7]; \
        _sum = _ms + ((_ml & mask_lowest_17bits) << 11) + _wrap_carry + _carry; \
        (acc)[6] = (uint32_t)(_sum & mask_lowest_28bits); \
        _carry = _sum >> 28; _wrap_carry = _ml >> 17; \
        /* limb 7 */ \
        _ms = _a0*(r4)[7] + _b0*(r3)[7] + _c0*(r2)[7] + _d0*(r)[7] \
            + _a1*(r4)[6] + _b1*(r3)[6] + _c1*(r2)[6] + _d1*(r)[6] \
            + _a2*(r4)[5] + _b2*(r3)[5] + _c2*(r2)[5] + _d2*(r)[5] \
            + _a3*(r4)[4] + _b3*(r3)[4] + _c3*(r2)[4] + _d3*(r)[4] \
            + _a4*(r4)[3] + _b4*(r3)[3] + _c4*(r2)[3] + _d4*(r)[3] \
            + _a5*(r4)[2] + _b5*(r3)[2] + _c5*(r2)[2] + _d5*(r)[2] \
            + _a6*(r4)[1] + _b6*(r3)[1] + _c6*(r2)[1] + _d6*(r)[1] \
            + _a7*(r4)[0] + _b7*(r3)[0] + _c7*(r2)[0] + _d7*(r)[0]; \
        _ml = 0; \
        _sum = _ms + ((_ml & mask_lowest_6bits) << 11) + _wrap_carry + _carry; \
        (acc)[7] = (uint32_t)(_sum & mask_lowest_17bits); \
        _carry = _sum >> 17; _wrap_carry = _ml >> 6; \
        /* propagate carry */ \
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
        uint64_t _mult_small[LIMBS_2133] = {0}; \
        uint64_t _mult_large[LIMBS_2133] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        __m256i vec_n[LIMBS_2133]; \
        __m256i vec_r[LIMBS_2133]; \
        __m256i vec_three_r[LIMBS_2133]; \
        __m256i vec_mult_small[LIMBS_2133]; \
        __m256i vec_mult_large[LIMBS_2133]; \
        for (int _i = 0; _i < LIMBS_2133; _i++) { \
            vec_mult_small[_i] = _mm256_setzero_si256(); \
            vec_mult_large[_i] = _mm256_setzero_si256(); \
            vec_r[_i] = _mm256_set_epi64x((r)[_i], (r2)[_i], (r3)[_i], (r4)[_i]); \
            vec_three_r[_i] = _mm256_set_epi64x((three_r)[_i], (three_r2)[_i], (three_r3)[_i], (three_r4)[_i]); \
            vec_n[_i] = _mm256_set_epi64x((uint64_t)(n4)[_i], (uint64_t)(n3)[_i], (uint64_t)(n2)[_i], (uint64_t)(n1)[_i] + (acc)[_i]); \
        } \
        for (int _i = 0; _i < LIMBS_2133; _i++){ \
            \
            for (int _j = 0; _j < LIMBS_2133 - _i; _j++){ \
                (vec_mult_small)[_i+_j] = _mm256_add_epi64((vec_mult_small)[_i+_j], _mm256_mul_epu32(vec_n[_i], vec_r[_j])); \
            } \
            for (int _j = LIMBS_2133 - _i; _j < LIMBS_2133; _j++){ \
                (vec_mult_large)[_i+_j - LIMBS_2133] = _mm256_add_epi64((vec_mult_large)[_i+_j - LIMBS_2133], _mm256_mul_epu32(vec_n[_i], vec_three_r[_j])); \
            } \
        } \
        \
        for(int _i = 0; _i < LIMBS_2133; _i++){ \
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

// same as MULOD_P_VEC_4BLOCKS but we do all computations limb for limb and store result in mult_small for each limb immediately
#define MULMOD_P_VEC_4BLOCKS_LESS_REGS(acc, n1, n2, n3, n4) \
    do{ \
        uint64_t _mult_small[LIMBS_2133] = {0}; \
        uint64_t _mult_large[LIMBS_2133] = {0}; \
        uint64_t mask_lowest_6bits = 0x3f; \
        __m256i vec_n[LIMBS_2133]; \
        \
        for (int _i = 0; _i < LIMBS_2133; _i++) { \
            vec_n[_i] = _mm256_set_epi64x((uint64_t)(n4)[_i], (uint64_t)(n3)[_i], (uint64_t)(n2)[_i], (uint64_t)(n1)[_i] + (acc)[_i]); \
        } \
        for (int _k = 0; _k < LIMBS_2133; _k++){ \
            __m256i vec_mult_small_i = _mm256_setzero_si256(); \
            /* compute mult_small for limb _k */ \
            for (int _i = 0; _i <= _k; _i++){ \
                int _j = _k - _i; \
                __m256i vec_r_j = _mm256_set_epi64x((uint64_t)r[_j], (uint64_t)r2[_j], (uint64_t)r3[_j], (uint64_t)r4[_j]); \
                vec_mult_small_i = _mm256_add_epi64(vec_mult_small_i, _mm256_mul_epu32(vec_n[_i], vec_r_j)); \
            } \
            /* save the result of mult_small for limb _k */ \
            __m128i lo = _mm256_castsi256_si128(vec_mult_small_i); \
            __m128i hi = _mm256_extracti128_si256(vec_mult_small_i, 1); \
            __m128i _sum_small = _mm_add_epi64(lo, hi); \
            _mult_small[_k] = (uint64_t)_mm_extract_epi64(_sum_small, 0) + (uint64_t)_mm_extract_epi64(_sum_small, 1); \
            /* now do same for mult_large */ \
            __m256i vec_mult_large_i = _mm256_setzero_si256(); \
            for (int _i = _k+1; _i < LIMBS_2133; _i++){ \
                int _j = _k + LIMBS_2133 - _i; \
                __m256i vec_three_r_j = _mm256_set_epi64x((uint64_t)three_r[_j], (uint64_t)three_r2[_j], (uint64_t)three_r3[_j], (uint64_t)three_r4[_j]); \
                vec_mult_large_i = _mm256_add_epi64(vec_mult_large_i, _mm256_mul_epu32(vec_n[_i], vec_three_r_j)); \
            } \
            __m128i lo_l = _mm256_castsi256_si128(vec_mult_large_i); \
            __m128i hi_l = _mm256_extracti128_si256(vec_mult_large_i, 1); \
            __m128i _sum_large = _mm_add_epi64(lo_l, hi_l); \
            _mult_large[_k] = (uint64_t)_mm_extract_epi64(_sum_large, 0) + (uint64_t)_mm_extract_epi64(_sum_large, 1); \
        } \
        /* repack into acc array and handle carry */ \
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

#define MULMOD_P_VEC_SCALREP_4BLOCKS(acc, n1, n2, n3, n4) \
    do{ \
        uint64_t mask_lowest_6bits = 0x3f; \
        \
        /* store the limbs of all accumulators in scalars (also precompute n1 + acc) */ \
        uint64_t _a0 = (uint64_t)((n1)[0] + (acc)[0]), _b0 = (uint64_t)(n2)[0], _c0 = (uint64_t)(n3)[0], _d0 = (uint64_t)(n4)[0]; \
        uint64_t _a1 = (uint64_t)((n1)[1] +(acc)[1]), _b1 = (uint64_t)(n2)[1], _c1 = (uint64_t)(n3)[1], _d1 = (uint64_t)(n4)[1]; \
        uint64_t _a2 = (uint64_t)((n1)[2] + (acc)[2]), _b2 = (uint64_t)(n2)[2], _c2 = (uint64_t)(n3)[2], _d2 = (uint64_t)(n4)[2]; \
        uint64_t _a3 = (uint64_t)((n1)[3] + (acc)[3]), _b3 = (uint64_t)(n2)[3], _c3 = (uint64_t)(n3)[3], _d3 = (uint64_t)(n4)[3]; \
        uint64_t _a4 = (uint64_t)((n1)[4] + (acc)[4]), _b4 = (uint64_t)(n2)[4], _c4 = (uint64_t)(n3)[4], _d4 = (uint64_t)(n4)[4]; \
        uint64_t _a5 = (uint64_t)((n1)[5] + (acc)[5]), _b5 = (uint64_t)(n2)[5], _c5 = (uint64_t)(n3)[5], _d5 = (uint64_t)(n4)[5]; \
        uint64_t _a6 = (uint64_t)((n1)[6] + (acc)[6]), _b6 = (uint64_t)(n2)[6], _c6 = (uint64_t)(n3)[6], _d6 = (uint64_t)(n4)[6]; \
        uint64_t _a7 = (uint64_t)((n1)[7] + (acc)[7]), _b7 = (uint64_t)(n2)[7], _c7 = (uint64_t)(n3)[7], _d7 = (uint64_t)(n4)[7]; \
        \
        uint64_t _carry=0, _wrap_carry=0, _sum, _ms, _ml; \
        __m256i _vs, _vl; \
        __m128i _low, _high, _sum_vec; \
        \
        \
        /* limb 0 */ \
        /* mult_small computes _ms = (n1+acc)r^4 + n2*r^3 + n3*r^2 + n4*r) (for all (i,j) pairs for limb0 mult_small)*/ \
        _vs = _mm256_mul_epu32( \
            _mm256_set_epi64x(_d0,_c0,_b0,_a0), \
            _mm256_set_epi64x((r)[0],(r2)[0],(r3)[0],(r4)[0])); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        /* mult_large computes _ml = (n1+acc)*3*r^4 + 3*n2*r^3 + 3*n3*r^2 + 3*n4*r) (for all (i,j) pairs for limb0 mult_large)*/ \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((three_r)[7],(three_r2)[7],(three_r3)[7],(three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((three_r)[6],(three_r2)[6],(three_r3)[6],(three_r4)[6]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((three_r)[5],(three_r2)[5],(three_r3)[5],(three_r4)[5]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((three_r)[4],(three_r2)[4],(three_r3)[4],(three_r4)[4]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r)[3],(three_r2)[3],(three_r3)[3],(three_r4)[3]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r)[2],(three_r2)[2],(three_r3)[2],(three_r4)[2]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r)[1],(three_r2)[1],(three_r3)[1],(three_r4)[1]))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[0]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 1 */ \
        /* mult_small */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r)[1],(r2)[1],(r3)[1],(r4)[1])); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r)[0],(r2)[0],(r3)[0],(r4)[0]))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        /* mult_large */ \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((three_r)[7],(three_r2)[7],(three_r3)[7],(three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((three_r)[6],(three_r2)[6],(three_r3)[6],(three_r4)[6]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((three_r)[5],(three_r2)[5],(three_r3)[5],(three_r4)[5]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r)[4],(three_r2)[4],(three_r3)[4],(three_r4)[4]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r)[3],(three_r2)[3],(three_r3)[3],(three_r4)[3]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r)[2],(three_r2)[2],(three_r3)[2],(three_r4)[2]))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[1]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 2 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r)[2],(r2)[2],(r3)[2],(r4)[2])); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r)[1],(r2)[1],(r3)[1],(r4)[1]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r)[0],(r2)[0],(r3)[0],(r4)[0]))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((three_r)[7],(three_r2)[7],(three_r3)[7],(three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((three_r)[6],(three_r2)[6],(three_r3)[6],(three_r4)[6]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r)[5],(three_r2)[5],(three_r3)[5],(three_r4)[5]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r)[4],(three_r2)[4],(three_r3)[4],(three_r4)[4]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r)[3],(three_r2)[3],(three_r3)[3],(three_r4)[3]))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[2]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 3 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r)[3],(r2)[3],(r3)[3],(r4)[3])); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r)[2],(r2)[2],(r3)[2],(r4)[2]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r)[1],(r2)[1],(r3)[1],(r4)[1]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r)[0],(r2)[0],(r3)[0],(r4)[0]))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((three_r)[7],(three_r2)[7],(three_r3)[7],(three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r)[6],(three_r2)[6],(three_r3)[6],(three_r4)[6]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r)[5],(three_r2)[5],(three_r3)[5],(three_r4)[5]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r)[4],(three_r2)[4],(three_r3)[4],(three_r4)[4]))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[3]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 4 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r)[4],(r2)[4],(r3)[4],(r4)[4])); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r)[3],(r2)[3],(r3)[3],(r4)[3]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r)[2],(r2)[2],(r3)[2],(r4)[2]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r)[1],(r2)[1],(r3)[1],(r4)[1]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((r)[0],(r2)[0],(r3)[0],(r4)[0]))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r)[7],(three_r2)[7],(three_r3)[7],(three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r)[6],(three_r2)[6],(three_r3)[6],(three_r4)[6]))); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r)[5],(three_r2)[5],(three_r3)[5],(three_r4)[5]))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[4]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 5 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r)[5],(r2)[5],(r3)[5],(r4)[5])); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r)[4],(r2)[4],(r3)[4],(r4)[4]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r)[3],(r2)[3],(r3)[3],(r4)[3]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r)[2],(r2)[2],(r3)[2],(r4)[2]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((r)[1],(r2)[1],(r3)[1],(r4)[1]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((r)[0],(r2)[0],(r3)[0],(r4)[0]))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r)[7],(three_r2)[7],(three_r3)[7],(three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r)[6],(three_r2)[6],(three_r3)[6],(three_r4)[6]))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[5]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 6 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r)[6],(r2)[6],(r3)[6],(r4)[6])); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r)[5],(r2)[5],(r3)[5],(r4)[5]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r)[4],(r2)[4],(r3)[4],(r4)[4]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r)[3],(r2)[3],(r3)[3],(r4)[3]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((r)[2],(r2)[2],(r3)[2],(r4)[2]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((r)[1],(r2)[1],(r3)[1],(r4)[1]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((r)[0],(r2)[0],(r3)[0],(r4)[0]))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r)[7],(three_r2)[7],(three_r3)[7],(three_r4)[7])); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[6]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 7 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r)[7],(r2)[7],(r3)[7],(r4)[7])); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r)[6],(r2)[6],(r3)[6],(r4)[6]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r)[5],(r2)[5],(r3)[5],(r4)[5]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r)[4],(r2)[4],(r3)[4],(r4)[4]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((r)[3],(r2)[3],(r3)[3],(r4)[3]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((r)[2],(r2)[2],(r3)[2],(r4)[2]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((r)[1],(r2)[1],(r3)[1],(r4)[1]))); \
        _vs = _mm256_add_epi64(_vs, _mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((r)[0],(r2)[0],(r3)[0],(r4)[0]))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _ml=0; \
        _sum=_ms+((_ml & mask_lowest_6bits)<<11)+_wrap_carry+_carry; \
        (acc)[7]=(uint32_t)(_sum & mask_lowest_17bits); \
        _carry=_sum>>17; _wrap_carry=_ml>>6; \
        \
        uint64_t _total_carry=(_carry+_wrap_carry)*3; \
        uint64_t _sum0=(uint64_t)(acc)[0]+_total_carry; \
        (acc)[0]=(uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry=_sum0>>28; \
        (acc)[1]+=(uint32_t)_carry; \
        _carry=(acc)[1]>>28; \
        (acc)[1]&=mask_lowest_28bits; \
        (acc)[2]+=(uint32_t)_carry; \
    } while(0)

// same as MULMOD_P_VEC_SCALREP_4BLOCKS but now with 8 blocks
#define MULMOD_P_VEC_SCALREP_8BLOCKS(acc, n1, n2, n3, n4, n5, n6, n7, n8) \
        do{ \
        uint64_t mask_lowest_6bits = 0x3f; \
        /* load variables n1 to n8 and add n1 + acc again*/\
        uint64_t _a0 = (uint64_t)((n1)[0]+(acc)[0]), _b0 = (uint64_t)(n2)[0], _c0 = (uint64_t)(n3)[0], _d0 = (uint64_t)(n4)[0]; \
        uint64_t _a1 = (uint64_t)((n1)[1]+(acc)[1]), _b1 = (uint64_t)(n2)[1], _c1 = (uint64_t)(n3)[1], _d1 = (uint64_t)(n4)[1]; \
        uint64_t _a2 = (uint64_t)((n1)[2]+(acc)[2]), _b2 = (uint64_t)(n2)[2], _c2 = (uint64_t)(n3)[2], _d2 = (uint64_t)(n4)[2]; \
        uint64_t _a3 = (uint64_t)((n1)[3]+(acc)[3]), _b3 = (uint64_t)(n2)[3], _c3 = (uint64_t)(n3)[3], _d3 = (uint64_t)(n4)[3]; \
        uint64_t _a4 = (uint64_t)((n1)[4]+(acc)[4]), _b4 = (uint64_t)(n2)[4], _c4 = (uint64_t)(n3)[4], _d4 = (uint64_t)(n4)[4]; \
        uint64_t _a5 = (uint64_t)((n1)[5]+(acc)[5]), _b5 = (uint64_t)(n2)[5], _c5 = (uint64_t)(n3)[5], _d5 = (uint64_t)(n4)[5]; \
        uint64_t _a6 = (uint64_t)((n1)[6]+(acc)[6]), _b6 = (uint64_t)(n2)[6], _c6 = (uint64_t)(n3)[6], _d6 = (uint64_t)(n4)[6]; \
        uint64_t _a7 = (uint64_t)((n1)[7]+(acc)[7]), _b7 = (uint64_t)(n2)[7], _c7 = (uint64_t)(n3)[7], _d7 = (uint64_t)(n4)[7]; \
        uint64_t _e0 = (uint64_t)(n5)[0], _f0 = (uint64_t)(n6)[0], _g0 = (uint64_t)(n7)[0], _h0 = (uint64_t)(n8)[0]; \
        uint64_t _e1 = (uint64_t)(n5)[1], _f1 = (uint64_t)(n6)[1], _g1 = (uint64_t)(n7)[1], _h1 = (uint64_t)(n8)[1]; \
        uint64_t _e2 = (uint64_t)(n5)[2], _f2 = (uint64_t)(n6)[2], _g2 = (uint64_t)(n7)[2], _h2 = (uint64_t)(n8)[2]; \
        uint64_t _e3 = (uint64_t)(n5)[3], _f3 = (uint64_t)(n6)[3], _g3 = (uint64_t)(n7)[3], _h3 = (uint64_t)(n8)[3]; \
        uint64_t _e4 = (uint64_t)(n5)[4], _f4 = (uint64_t)(n6)[4], _g4 = (uint64_t)(n7)[4], _h4 = (uint64_t)(n8)[4]; \
        uint64_t _e5 = (uint64_t)(n5)[5], _f5 = (uint64_t)(n6)[5], _g5 = (uint64_t)(n7)[5], _h5 = (uint64_t)(n8)[5]; \
        uint64_t _e6 = (uint64_t)(n5)[6], _f6 = (uint64_t)(n6)[6], _g6 = (uint64_t)(n7)[6], _h6 = (uint64_t)(n8)[6]; \
        uint64_t _e7 = (uint64_t)(n5)[7], _f7 = (uint64_t)(n6)[7], _g7 = (uint64_t)(n7)[7], _h7 = (uint64_t)(n8)[7]; \
        \
        uint64_t _carry = 0, _wrap_carry = 0, _sum, _ms, _ml; \
        __m256i _vs, _vl, _vs2, _vl2; \
        __m128i _low, _high, _sum_vec; \
        \
        /* limb 0 */ \
        /* mult_small computes _ms = ((n1+acc)r^8 + n2*r^7 + n3*r^6 + n4*r^5) + (n5*r^4 + n6*r^3 + n7*r^2 + n8*r)) (for all (i,j) pairs for limb0 mult_small)*/ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r5)[0],(r6)[0],(r7)[0],(r8)[0])); \
        _vs2 = _mm256_mul_epu32(_mm256_set_epi64x(_h0, _g0, _f0, _e0), _mm256_set_epi64x((r)[0], (r2)[0], (r3)[0], (r4)[0])); \
        _vs = _mm256_add_epi64(_vs, _vs2); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        /* mult_large computes _ml = ((n1+acc)*3*r^8 + 3*n2*r^7 + 3*n3*r^6 + 3*n4*r^5) + (3*n5*r^4 + 3*n6*r^3 + 3*n7*r^2 + 3*n8*r)) (for all (i,j) pairs for limb0 mult_large)*/ \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((three_r5)[7],(three_r6)[7],(three_r7)[7],(three_r8)[7])); \
        _vl2 = _mm256_mul_epu32(_mm256_set_epi64x(_h1, _g1, _f1, _e1), _mm256_set_epi64x((three_r)[7], (three_r2)[7], (three_r3)[7], (three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _vl2); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((three_r5)[6],(three_r6)[6],(three_r7)[6],(three_r8)[6])), _mm256_mul_epu32(_mm256_set_epi64x(_h2, _g2, _f2, _e2), _mm256_set_epi64x((three_r)[6], (three_r2)[6], (three_r3)[6], (three_r4)[6])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((three_r5)[5],(three_r6)[5],(three_r7)[5],(three_r8)[5])),_mm256_mul_epu32(_mm256_set_epi64x(_h3, _g3, _f3, _e3), _mm256_set_epi64x((three_r)[5], (three_r2)[5], (three_r3)[5], (three_r4)[5])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((three_r5)[4],(three_r6)[4],(three_r7)[4],(three_r8)[4])), _mm256_mul_epu32(_mm256_set_epi64x(_h4, _g4, _f4, _e4), _mm256_set_epi64x((three_r)[4], (three_r2)[4], (three_r3)[4], (three_r4)[4])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r5)[3],(three_r6)[3],(three_r7)[3],(three_r8)[3])), _mm256_mul_epu32(_mm256_set_epi64x(_h5, _g5, _f5, _e5), _mm256_set_epi64x((three_r)[3], (three_r2)[3], (three_r3)[3], (three_r4)[3])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r5)[2],(three_r6)[2],(three_r7)[2],(three_r8)[2])),_mm256_mul_epu32(_mm256_set_epi64x(_h6, _g6, _f6, _e6), _mm256_set_epi64x((three_r)[2], (three_r2)[2], (three_r3)[2], (three_r4)[2])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r5)[1],(three_r6)[1],(three_r7)[1],(three_r8)[1])),_mm256_mul_epu32(_mm256_set_epi64x(_h7, _g7, _f7, _e7), _mm256_set_epi64x((three_r)[1], (three_r2)[1], (three_r3)[1], (three_r4)[1])))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[0]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 1 */ \
        /* mult_small */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r5)[1],(r6)[1],(r7)[1],(r8)[1])); \
        _vs2 = _mm256_mul_epu32(_mm256_set_epi64x(_h0, _g0, _f0, _e0), _mm256_set_epi64x((r)[1], (r2)[1], (r3)[1], (r4)[1])); \
        _vs = _mm256_add_epi64(_vs, _vs2); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r5)[0],(r6)[0],(r7)[0],(r8)[0])), _mm256_mul_epu32(_mm256_set_epi64x(_h1, _g1, _f1, _e1), _mm256_set_epi64x((r)[0], (r2)[0], (r3)[0], (r4)[0])))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        /* mult_large */ \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((three_r5)[7],(three_r6)[7],(three_r7)[7],(three_r8)[7])); \
        _vl2 = _mm256_mul_epu32(_mm256_set_epi64x(_h2, _g2, _f2, _e2), _mm256_set_epi64x((three_r)[7], (three_r2)[7], (three_r3)[7], (three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _vl2); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((three_r5)[6],(three_r6)[6],(three_r7)[6],(three_r8)[6])), _mm256_mul_epu32(_mm256_set_epi64x(_h3, _g3, _f3, _e3), _mm256_set_epi64x((three_r)[6], (three_r2)[6], (three_r3)[6], (three_r4)[6])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((three_r5)[5],(three_r6)[5],(three_r7)[5],(three_r8)[5])), _mm256_mul_epu32(_mm256_set_epi64x(_h4, _g4, _f4, _e4), _mm256_set_epi64x((three_r)[5], (three_r2)[5], (three_r3)[5], (three_r4)[5])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r5)[4],(three_r6)[4],(three_r7)[4],(three_r8)[4])), _mm256_mul_epu32(_mm256_set_epi64x(_h5, _g5, _f5, _e5), _mm256_set_epi64x((three_r)[4], (three_r2)[4], (three_r3)[4], (three_r4)[4])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r5)[3],(three_r6)[3],(three_r7)[3],(three_r8)[3])), _mm256_mul_epu32(_mm256_set_epi64x(_h6, _g6, _f6, _e6), _mm256_set_epi64x((three_r)[3], (three_r2)[3], (three_r3)[3], (three_r4)[3])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r5)[2],(three_r6)[2],(three_r7)[2],(three_r8)[2])),_mm256_mul_epu32(_mm256_set_epi64x(_h7, _g7, _f7, _e7), _mm256_set_epi64x((three_r)[2], (three_r2)[2], (three_r3)[2], (three_r4)[2])))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[1]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 2 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r5)[2],(r6)[2],(r7)[2],(r8)[2])); \
        _vs2 = _mm256_mul_epu32(_mm256_set_epi64x(_h0, _g0, _f0, _e0), _mm256_set_epi64x((r)[2], (r2)[2], (r3)[2], (r4)[2])); \
        _vs = _mm256_add_epi64(_vs, _vs2); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r5)[1],(r6)[1],(r7)[1],(r8)[1])), _mm256_mul_epu32(_mm256_set_epi64x(_h1, _g1, _f1, _e1), _mm256_set_epi64x((r)[1], (r2)[1], (r3)[1], (r4)[1])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r5)[0],(r6)[0],(r7)[0],(r8)[0])),_mm256_mul_epu32(_mm256_set_epi64x(_h2, _g2, _f2, _e2), _mm256_set_epi64x((r)[0], (r2)[0], (r3)[0], (r4)[0])))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((three_r5)[7],(three_r6)[7],(three_r7)[7],(three_r8)[7])); \
        _vl2 = _mm256_mul_epu32(_mm256_set_epi64x(_h3, _g3, _f3, _e3), _mm256_set_epi64x((three_r)[7], (three_r2)[7], (three_r3)[7], (three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _vl2); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((three_r5)[6],(three_r6)[6],(three_r7)[6],(three_r8)[6])), _mm256_mul_epu32(_mm256_set_epi64x(_h4, _g4, _f4, _e4), _mm256_set_epi64x((three_r)[6], (three_r2)[6], (three_r3)[6], (three_r4)[6])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r5)[5],(three_r6)[5],(three_r7)[5],(three_r8)[5])), _mm256_mul_epu32(_mm256_set_epi64x(_h5, _g5, _f5, _e5), _mm256_set_epi64x((three_r)[5], (three_r2)[5], (three_r3)[5], (three_r4)[5])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r5)[4],(three_r6)[4],(three_r7)[4],(three_r8)[4])), _mm256_mul_epu32(_mm256_set_epi64x(_h6, _g6, _f6, _e6), _mm256_set_epi64x((three_r)[4], (three_r2)[4], (three_r3)[4], (three_r4)[4])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r5)[3],(three_r6)[3],(three_r7)[3],(three_r8)[3])),_mm256_mul_epu32(_mm256_set_epi64x(_h7, _g7, _f7, _e7), _mm256_set_epi64x((three_r)[3], (three_r2)[3], (three_r3)[3], (three_r4)[3])))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[2]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 3 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r5)[3],(r6)[3],(r7)[3],(r8)[3])); \
        _vs2 = _mm256_mul_epu32(_mm256_set_epi64x(_h0, _g0, _f0, _e0), _mm256_set_epi64x((r)[3], (r2)[3], (r3)[3], (r4)[3])); \
        _vs = _mm256_add_epi64(_vs, _vs2); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r5)[2],(r6)[2],(r7)[2],(r8)[2])), _mm256_mul_epu32(_mm256_set_epi64x(_h1, _g1, _f1, _e1), _mm256_set_epi64x((r)[2], (r2)[2], (r3)[2], (r4)[2])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r5)[1],(r6)[1],(r7)[1],(r8)[1])), _mm256_mul_epu32(_mm256_set_epi64x(_h2, _g2, _f2, _e2), _mm256_set_epi64x((r)[1], (r2)[1], (r3)[1], (r4)[1])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r5)[0],(r6)[0],(r7)[0],(r8)[0])),_mm256_mul_epu32(_mm256_set_epi64x(_h3, _g3, _f3, _e3), _mm256_set_epi64x((r)[0], (r2)[0], (r3)[0], (r4)[0])))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((three_r5)[7],(three_r6)[7],(three_r7)[7],(three_r8)[7])); \
        _vl2 = _mm256_mul_epu32(_mm256_set_epi64x(_h4, _g4, _f4, _e4), _mm256_set_epi64x((three_r)[7], (three_r2)[7], (three_r3)[7], (three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _vl2); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r5)[6],(three_r6)[6],(three_r7)[6],(three_r8)[6])), _mm256_mul_epu32(_mm256_set_epi64x(_h5, _g5, _f5, _e5), _mm256_set_epi64x((three_r)[6], (three_r2)[6], (three_r3)[6], (three_r4)[6])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r5)[5],(three_r6)[5],(three_r7)[5],(three_r8)[5])), _mm256_mul_epu32(_mm256_set_epi64x(_h6, _g6, _f6, _e6), _mm256_set_epi64x((three_r)[5], (three_r2)[5], (three_r3)[5], (three_r4)[5])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r5)[4],(three_r6)[4],(three_r7)[4],(three_r8)[4])), _mm256_mul_epu32(_mm256_set_epi64x(_h7, _g7, _f7, _e7), _mm256_set_epi64x((three_r)[4], (three_r2)[4], (three_r3)[4], (three_r4)[4])))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[3]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 4 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r5)[4],(r6)[4],(r7)[4],(r8)[4])); \
        _vs2 = _mm256_mul_epu32(_mm256_set_epi64x(_h0, _g0, _f0, _e0), _mm256_set_epi64x((r)[4], (r2)[4], (r3)[4], (r4)[4])); \
        _vs = _mm256_add_epi64(_vs, _vs2); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r5)[3],(r6)[3],(r7)[3],(r8)[3])),_mm256_mul_epu32(_mm256_set_epi64x(_h1, _g1, _f1, _e1), _mm256_set_epi64x((r)[3], (r2)[3], (r3)[3], (r4)[3])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r5)[2],(r6)[2],(r7)[2],(r8)[2])),_mm256_mul_epu32(_mm256_set_epi64x(_h2, _g2, _f2, _e2), _mm256_set_epi64x((r)[2], (r2)[2], (r3)[2], (r4)[2])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r5)[1],(r6)[1],(r7)[1],(r8)[1])), _mm256_mul_epu32(_mm256_set_epi64x(_h3, _g3, _f3, _e3), _mm256_set_epi64x((r)[1], (r2)[1], (r3)[1], (r4)[1])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((r5)[0],(r6)[0],(r7)[0],(r8)[0])), _mm256_mul_epu32(_mm256_set_epi64x(_h4, _g4, _f4, _e4), _mm256_set_epi64x((r)[0], (r2)[0], (r3)[0], (r4)[0])))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((three_r5)[7],(three_r6)[7],(three_r7)[7],(three_r8)[7])); \
        _vl2 = _mm256_mul_epu32(_mm256_set_epi64x(_h5, _g5, _f5, _e5), _mm256_set_epi64x((three_r)[7], (three_r2)[7], (three_r3)[7], (three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _vl2); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r5)[6],(three_r6)[6],(three_r7)[6],(three_r8)[6])),_mm256_mul_epu32(_mm256_set_epi64x(_h6, _g6, _f6, _e6), _mm256_set_epi64x((three_r)[6], (three_r2)[6], (three_r3)[6], (three_r4)[6])))); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r5)[5],(three_r6)[5],(three_r7)[5],(three_r8)[5])),_mm256_mul_epu32(_mm256_set_epi64x(_h7, _g7, _f7, _e7), _mm256_set_epi64x((three_r)[5], (three_r2)[5], (three_r3)[5], (three_r4)[5])))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[4]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 5 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r5)[5],(r6)[5],(r7)[5],(r8)[5])); \
        _vs2 = _mm256_mul_epu32(_mm256_set_epi64x(_h0, _g0, _f0, _e0), _mm256_set_epi64x((r)[5], (r2)[5], (r3)[5], (r4)[5])); \
        _vs = _mm256_add_epi64(_vs, _vs2); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r5)[4],(r6)[4],(r7)[4],(r8)[4])),_mm256_mul_epu32(_mm256_set_epi64x(_h1, _g1, _f1, _e1), _mm256_set_epi64x((r)[4], (r2)[4], (r3)[4], (r4)[4])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r5)[3],(r6)[3],(r7)[3],(r8)[3])),_mm256_mul_epu32(_mm256_set_epi64x(_h2, _g2, _f2, _e2), _mm256_set_epi64x((r)[3], (r2)[3], (r3)[3], (r4)[3])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r5)[2],(r6)[2],(r7)[2],(r8)[2])),_mm256_mul_epu32(_mm256_set_epi64x(_h3, _g3, _f3, _e3), _mm256_set_epi64x((r)[2], (r2)[2], (r3)[2], (r4)[2])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((r5)[1],(r6)[1],(r7)[1],(r8)[1])),_mm256_mul_epu32(_mm256_set_epi64x(_h4, _g4, _f4, _e4), _mm256_set_epi64x((r)[1], (r2)[1], (r3)[1], (r4)[1])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((r5)[0],(r6)[0],(r7)[0],(r8)[0])), _mm256_mul_epu32(_mm256_set_epi64x(_h5, _g5, _f5, _e5), _mm256_set_epi64x((r)[0], (r2)[0], (r3)[0], (r4)[0])))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((three_r5)[7],(three_r6)[7],(three_r7)[7],(three_r8)[7])); \
        _vl2 = _mm256_mul_epu32(_mm256_set_epi64x(_h6, _g6, _f6, _e6), _mm256_set_epi64x((three_r)[7], (three_r2)[7], (three_r3)[7], (three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _vl2); \
        _vl = _mm256_add_epi64(_vl, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r5)[6],(three_r6)[6],(three_r7)[6],(three_r8)[6])),_mm256_mul_epu32(_mm256_set_epi64x(_h7, _g7, _f7, _e7), _mm256_set_epi64x((three_r)[6], (three_r2)[6], (three_r3)[6], (three_r4)[6])))); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[5]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 6 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r5)[6],(r6)[6],(r7)[6],(r8)[6])); \
        _vs2 = _mm256_mul_epu32(_mm256_set_epi64x(_h0, _g0, _f0, _e0), _mm256_set_epi64x((r)[6], (r2)[6], (r3)[6], (r4)[6])); \
        _vs = _mm256_add_epi64(_vs, _vs2); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r5)[5],(r6)[5],(r7)[5],(r8)[5])),_mm256_mul_epu32(_mm256_set_epi64x(_h1, _g1, _f1, _e1), _mm256_set_epi64x((r)[5], (r2)[5], (r3)[5], (r4)[5])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r5)[4],(r6)[4],(r7)[4],(r8)[4])),_mm256_mul_epu32(_mm256_set_epi64x(_h2, _g2, _f2, _e2), _mm256_set_epi64x((r)[4], (r2)[4], (r3)[4], (r4)[4])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r5)[3],(r6)[3],(r7)[3],(r8)[3])),_mm256_mul_epu32(_mm256_set_epi64x(_h3, _g3, _f3, _e3), _mm256_set_epi64x((r)[3], (r2)[3], (r3)[3], (r4)[3])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((r5)[2],(r6)[2],(r7)[2],(r8)[2])),_mm256_mul_epu32(_mm256_set_epi64x(_h4, _g4, _f4, _e4), _mm256_set_epi64x((r)[2], (r2)[2], (r3)[2], (r4)[2])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((r5)[1],(r6)[1],(r7)[1],(r8)[1])),_mm256_mul_epu32(_mm256_set_epi64x(_h5, _g5, _f5, _e5), _mm256_set_epi64x((r)[1], (r2)[1], (r3)[1], (r4)[1])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((r5)[0],(r6)[0],(r7)[0],(r8)[0])),_mm256_mul_epu32(_mm256_set_epi64x(_h6, _g6, _f6, _e6), _mm256_set_epi64x((r)[0], (r2)[0], (r3)[0], (r4)[0])))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _vl = _mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((three_r5)[7],(three_r6)[7],(three_r7)[7],(three_r8)[7])); \
        _vl2 = _mm256_mul_epu32(_mm256_set_epi64x(_h7, _g7, _f7, _e7), _mm256_set_epi64x((three_r)[7], (three_r2)[7], (three_r3)[7], (three_r4)[7])); \
        _vl = _mm256_add_epi64(_vl, _vl2); \
        _low=_mm256_castsi256_si128(_vl); _high=_mm256_extracti128_si256(_vl,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ml=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _sum=_ms+((_ml & mask_lowest_17bits)<<11)+_wrap_carry+_carry; \
        (acc)[6]=(uint32_t)(_sum & mask_lowest_28bits); \
        _carry=_sum>>28; _wrap_carry=_ml>>17; \
        \
        /* limb 7 */ \
        _vs = _mm256_mul_epu32(_mm256_set_epi64x(_d0,_c0,_b0,_a0), _mm256_set_epi64x((r5)[7],(r6)[7],(r7)[7],(r8)[7])); \
        _vs2 = _mm256_mul_epu32(_mm256_set_epi64x(_h0, _g0, _f0, _e0), _mm256_set_epi64x((r)[7], (r2)[7], (r3)[7], (r4)[7])); \
        _vs = _mm256_add_epi64(_vs, _vs2); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d1,_c1,_b1,_a1), _mm256_set_epi64x((r5)[6],(r6)[6],(r7)[6],(r8)[6])), _mm256_mul_epu32(_mm256_set_epi64x(_h1,_g1,_f1,_e1), _mm256_set_epi64x((r)[6],(r2)[6],(r3)[6],(r4)[6])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d2,_c2,_b2,_a2), _mm256_set_epi64x((r5)[5],(r6)[5],(r7)[5],(r8)[5])), _mm256_mul_epu32(_mm256_set_epi64x(_h2,_g2,_f2,_e2), _mm256_set_epi64x((r)[5],(r2)[5],(r3)[5],(r4)[5])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d3,_c3,_b3,_a3), _mm256_set_epi64x((r5)[4],(r6)[4],(r7)[4],(r8)[4])), _mm256_mul_epu32(_mm256_set_epi64x(_h3,_g3,_f3,_e3), _mm256_set_epi64x((r)[4],(r2)[4],(r3)[4],(r4)[4])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d4,_c4,_b4,_a4), _mm256_set_epi64x((r5)[3],(r6)[3],(r7)[3],(r8)[3])), _mm256_mul_epu32(_mm256_set_epi64x(_h4,_g4,_f4,_e4), _mm256_set_epi64x((r)[3],(r2)[3],(r3)[3],(r4)[3])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d5,_c5,_b5,_a5), _mm256_set_epi64x((r5)[2],(r6)[2],(r7)[2],(r8)[2])), _mm256_mul_epu32(_mm256_set_epi64x(_h5,_g5,_f5,_e5), _mm256_set_epi64x((r)[2],(r2)[2],(r3)[2],(r4)[2])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d6,_c6,_b6,_a6), _mm256_set_epi64x((r5)[1],(r6)[1],(r7)[1],(r8)[1])),  _mm256_mul_epu32(_mm256_set_epi64x(_h6,_g6,_f6,_e6), _mm256_set_epi64x((r)[1],(r2)[1],(r3)[1],(r4)[1])))); \
        _vs = _mm256_add_epi64(_vs, _mm256_add_epi64(_mm256_mul_epu32(_mm256_set_epi64x(_d7,_c7,_b7,_a7), _mm256_set_epi64x((r5)[0],(r6)[0],(r7)[0],(r8)[0])), _mm256_mul_epu32(_mm256_set_epi64x(_h7,_g7,_f7,_e7), _mm256_set_epi64x((r)[0],(r2)[0],(r3)[0],(r4)[0])))); \
        _low=_mm256_castsi256_si128(_vs); _high=_mm256_extracti128_si256(_vs,1); \
        _sum_vec=_mm_add_epi64(_low,_high); \
        _ms=(uint64_t)_mm_extract_epi64(_sum_vec,0)+(uint64_t)_mm_extract_epi64(_sum_vec,1); \
        _ml=0; \
        _sum=_ms+((_ml & mask_lowest_6bits)<<11)+_wrap_carry+_carry; \
        (acc)[7]=(uint32_t)(_sum & mask_lowest_17bits); \
        _carry=_sum>>17; _wrap_carry=_ml>>6; \
        /* handle last carry and wrap-around carry*/ \
        uint64_t _total_carry=(_carry+_wrap_carry)*3; \
        uint64_t _sum0=(uint64_t)(acc)[0]+_total_carry; \
        (acc)[0]=(uint32_t)(_sum0 & mask_lowest_28bits); \
        _carry=_sum0>>28; \
        (acc)[1]+=(uint32_t)_carry; \
        _carry=(acc)[1]>>28; \
        (acc)[1]&=mask_lowest_28bits; \
        (acc)[2]+=(uint32_t)_carry; \
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
        for (int _i = 0; _i < TAG_SIZE_2133; _i++) { \
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
static void to_large_num_rep(uint32_t out[LIMBS_2133], const unsigned char *bytes, uint64_t len_bytes){
    uint64_t t[LIMBS_2133] = {0}; // initialize with zeros
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
static void to_26_le_bytes(uint32_t in[LIMBS_2133], unsigned char out[TAG_SIZE_2133]){
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
    for (int i = 0; i < TAG_SIZE_2133; i++){
        out[i] = (unsigned char)((t[i / 4] >> ((i% 4)* 8)) & 0xff); 
    }

}

// computes a = a + b (a and b need be in 5x26-bit representation)
static void add_large_nums_88(uint32_t a[LIMBS_2133], const uint32_t b[LIMBS_2133]){
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
static void mulmod_p(uint32_t acc[LIMBS_2133], const uint32_t r[LIMBS_2133]) {
    // use two seperate accumulators so we don't need uint128 
    uint64_t mult_small[LIMBS_2133] = {0}; // handles all (i + j = k) contributions
    uint64_t mult_large[LIMBS_2133] = {0}; // handles all (i + j = k + 8) contributions (where we wrap around, need to multiply by 3 and apply shift later)
    uint64_t mask_lowest_6bits = 0x3f; 

    for (int i = 0; i < LIMBS_2133; i++){
        for(int j = 0; j < LIMBS_2133; j++){
            int k = i+j;
            if (k < LIMBS_2133){
                mult_small[k] += (uint64_t)acc[i]* r[j];
            }
            else{
                mult_large[k - LIMBS_2133] += (uint64_t)acc[i]* 3*r[j];
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
unsigned char* poly2133_create_tag_baseline(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    for(uint64_t i = 0; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[block_len + 1];
        memset(block, 0, block_len + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        uint32_t n[LIMBS_2133];
        to_large_num_rep(n, block, block_len + 1); // convert representation of n to fit acc and r
        add_large_nums_88(acc, n); // acc += n 
        mulmod_p(acc, r); // acc = (acc * r) mod p
    }

    add_large_nums_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));
    to_26_le_bytes(acc, tag); // convert acc (7x28 + 17-bit representation) to 26 bytes (LE format)
    return tag;
}
// --------------------------------------------------------------------

// ----------------------------- Inlined Version ------------------------------

// calculate authentication tag for data
// use block and tag size of 26 bytes (maximal size still smaller p) 
unsigned char* poly2133_create_tag_inlined(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    for(uint64_t i = 0; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[block_len + 1];
        memset(block, 0, block_len + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        uint32_t n[LIMBS_2133];
        // convert block to 7x28 + 17-bit representation
        TO_LARGE_NUM_REP(n, block, block_len + 1);
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        // acc = (acc * r) mod p
        MULMOD_P(acc, r);    
    }
    
    // acc += s
     ADD_LARGE_NUMS_88(acc, s);
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    
    return tag;
}
// --------------------------------------------------------------------

// ---------------------------- Unrolled Verion ----------------------------
// calculate authentication tag for data
// use block and tag size of 26 bytes (maximal size still smaller p) 
unsigned char* poly2133_create_tag_unrolled(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    for(uint64_t i = 0; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[block_len + 1];
        memset(block, 0, block_len + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        uint32_t n[LIMBS_2133];
        // convert block to 7x28 + 17-bit representation
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);

        // acc += n
        ADD_LARGE_NUMS_88(acc, n);

        // acc = (acc * r) mod p
        MULMOD_P(acc, r);
    }
    
    // acc += s
    ADD_LARGE_NUMS_88(acc, s);
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES_UNROLLED(tag, acc);
    return tag;
}
// --------------------------------------------------------------------

unsigned char* poly2133_create_tag_2level_basic(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    uint64_t num_full_blocks = (data_len / BLOCK_SIZE_2133) / NUM_GROUPS_2133;

    uint32_t r2[LIMBS_2133];
    uint32_t r3[LIMBS_2133];
    uint32_t r4[LIMBS_2133];
    memcpy(r2, r, 32);
    mulmod_p(r2, r); // r2 = r * r mod p

    memcpy(r3, r2, 32);
    mulmod_p(r3, r); // r3 = r^2 * r mod p

    memcpy(r4, r3, 32);
    mulmod_p(r4, r); // r4 = r^3 * r mod p

    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE_2133 + 1];
        unsigned char block2[BLOCK_SIZE_2133 + 1];
        unsigned char block3[BLOCK_SIZE_2133 + 1];
        unsigned char block4[BLOCK_SIZE_2133 + 1];
        uint32_t n1[LIMBS_2133];
        uint32_t n2[LIMBS_2133];
        uint32_t n3[LIMBS_2133];
        uint32_t n4[LIMBS_2133];

        uint64_t offset1 = i*4 * BLOCK_SIZE_2133;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE_2133;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE_2133;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE_2133;


        memcpy(block1, data + offset1, BLOCK_SIZE_2133);
        memcpy(block2, data + offset2, BLOCK_SIZE_2133);
        memcpy(block3, data + offset3, BLOCK_SIZE_2133);
        memcpy(block4, data + offset4, BLOCK_SIZE_2133);
        block1[BLOCK_SIZE_2133] = 0x01;
        block2[BLOCK_SIZE_2133] = 0x01;
        block3[BLOCK_SIZE_2133] = 0x01;
        block4[BLOCK_SIZE_2133] = 0x01;
   
        to_large_num_rep(n1, block1, BLOCK_SIZE_2133 + 1); // convert representation of n to fit acc and r
        to_large_num_rep(n2, block2, BLOCK_SIZE_2133 + 1); 
        to_large_num_rep(n3, block3, BLOCK_SIZE_2133 + 1); 
        to_large_num_rep(n4, block4, BLOCK_SIZE_2133 + 1);

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
    for (uint64_t i = num_full_blocks*NUM_GROUPS_2133; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[BLOCK_SIZE_2133 + 1];
        uint32_t n[LIMBS_2133];
        memset(block, 0, BLOCK_SIZE_2133 + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        to_large_num_rep(n, block, block_len + 1); // convert representation of n to fit acc and r
        add_large_nums_88(acc, n); // acc += n
        mulmod_p(acc, r);
    }

    add_large_nums_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));
    to_26_le_bytes(acc, tag); // convert acc (7x28 + 17-bit representation) to 26 bytes (LE format)
    return tag;
}

// --------------------------------------------------------------------

// -------------------------- 2-level approach inlined & unrolled --------------------------
unsigned char* poly2133_create_tag_2level_inl_unr(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    uint64_t num_full_blocks = (data_len / BLOCK_SIZE_2133) / NUM_GROUPS_2133;

    // precompute r^2, r^3 and r^4
    uint32_t r2[LIMBS_2133];
    uint32_t r3[LIMBS_2133];
    uint32_t r4[LIMBS_2133];
    memcpy(r2, r, 32);
    MULMOD_P(r2, r);
    memcpy(r3, r2, 32);
    MULMOD_P(r3, r);
    memcpy(r4, r2, 32);
    MULMOD_P(r4, r2);
    
    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE_2133 + 1];
        unsigned char block2[BLOCK_SIZE_2133 + 1];
        unsigned char block3[BLOCK_SIZE_2133 + 1];
        unsigned char block4[BLOCK_SIZE_2133 + 1];
        uint32_t n1[LIMBS_2133];
        uint32_t n2[LIMBS_2133];
        uint32_t n3[LIMBS_2133];
        uint32_t n4[LIMBS_2133];

        uint64_t offset1 = i*4 * BLOCK_SIZE_2133;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE_2133;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE_2133;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE_2133;

        memcpy(block1, data + offset1, BLOCK_SIZE_2133);
        memcpy(block2, data + offset2, BLOCK_SIZE_2133);
        memcpy(block3, data + offset3, BLOCK_SIZE_2133);
        memcpy(block4, data + offset4, BLOCK_SIZE_2133);
        block1[BLOCK_SIZE_2133] = 0x01;
        block2[BLOCK_SIZE_2133] = 0x01;
        block3[BLOCK_SIZE_2133] = 0x01;
        block4[BLOCK_SIZE_2133] = 0x01;

        TO_LARGE_NUM_REP_MSG27_UNROLLED(n1, block1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n2, block2);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n3, block3);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n4, block4);

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
 
        // acc = acc * r^4 mod p (increase acc in steps of r^NUM_GROUPS_2133)
        MULMOD_P(acc, r4);

        // acc += n1
        ADD_LARGE_NUMS_88(acc, n1);
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS_2133; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[BLOCK_SIZE_2133 + 1];
        uint32_t n[LIMBS_2133];
        memset(block, 0, BLOCK_SIZE_2133 + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P(acc, r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s

    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- 2-level approach + delayed carry + inlined + unrolled --------------------------
unsigned char* poly2133_create_tag_delcarry(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    uint64_t num_full_blocks = (data_len / BLOCK_SIZE_2133) / NUM_GROUPS_2133;

    // precompute r^2, r^3 and r^4
    uint32_t r2[LIMBS_2133];
    uint32_t r3[LIMBS_2133];
    uint32_t r4[LIMBS_2133];
    memcpy(r2, r, 32);
    MULMOD_P(r2, r);
    memcpy(r3, r2, 32);
    MULMOD_P(r3, r);
    memcpy(r4, r2, 32);
    MULMOD_P(r4, r2);
    
    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[BLOCK_SIZE_2133 + 1];
        unsigned char block2[BLOCK_SIZE_2133 + 1];
        unsigned char block3[BLOCK_SIZE_2133 + 1];
        unsigned char block4[BLOCK_SIZE_2133 + 1];
        uint32_t n1[LIMBS_2133];
        uint32_t n2[LIMBS_2133];
        uint32_t n3[LIMBS_2133];
        uint32_t n4[LIMBS_2133];

        uint64_t offset1 = i*4 * BLOCK_SIZE_2133;
        uint64_t offset2 = (i*4 + 1)*BLOCK_SIZE_2133;
        uint64_t offset3 = (i*4 + 2)*BLOCK_SIZE_2133;
        uint64_t offset4 = (i*4 + 3)*BLOCK_SIZE_2133;

        memcpy(block1, data + offset1, BLOCK_SIZE_2133);
        memcpy(block2, data + offset2, BLOCK_SIZE_2133);
        memcpy(block3, data + offset3, BLOCK_SIZE_2133);
        memcpy(block4, data + offset4, BLOCK_SIZE_2133);
        block1[BLOCK_SIZE_2133] = 0x01;
        block2[BLOCK_SIZE_2133] = 0x01;
        block3[BLOCK_SIZE_2133] = 0x01;
        block4[BLOCK_SIZE_2133] = 0x01;

        TO_LARGE_NUM_REP_MSG27_UNROLLED(n1, block1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n2, block2);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n3, block3);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n4, block4);

        MULMOD_P_DELCARRY_4BLOCKS(acc, n1, n2, n3, n4);
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS_2133; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[BLOCK_SIZE_2133 + 1];
        uint32_t n[LIMBS_2133];
        memset(block, 0, BLOCK_SIZE_2133 + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P(acc, r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- precomputation + 2-level approach + delayed carry + inlined + unrolled --------------------------
unsigned char* poly2133_create_tag_precomp(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    uint64_t num_full_blocks = (data_len / BLOCK_SIZE_2133) / NUM_GROUPS_2133;

    // precompute r^2, r^3 and r^4
    uint32_t r2[LIMBS_2133];
    uint32_t r3[LIMBS_2133];
    uint32_t r4[LIMBS_2133];
    uint32_t three_r[LIMBS_2133];
    uint32_t three_r2[LIMBS_2133];
    uint32_t three_r3[LIMBS_2133];
    uint32_t three_r4[LIMBS_2133];

    for (int i = 0; i < LIMBS_2133; i++){
        three_r[i] = 3*r[i];
    }
    memcpy(r2, r, 32);
    MULMOD_P_PRECOMP(r2, r, three_r);
    memcpy(r3, r2, 32);
    MULMOD_P_PRECOMP(r3, r, three_r);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r2[i] = 3*r2[i];
    }
    memcpy(r4, r2, 32);
    MULMOD_P_PRECOMP(r4, r2, three_r2);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r3[i] = 3*r3[i];
        three_r4[i] = 3*r4[i];
    }
    uint64_t block_size_plus_1 = BLOCK_SIZE_2133 + 1;
    uint64_t four_block_size = 4 * BLOCK_SIZE_2133;
    uint64_t four_i_block_size = 0;
    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[block_size_plus_1];
        unsigned char block2[block_size_plus_1];
        unsigned char block3[block_size_plus_1];
        unsigned char block4[block_size_plus_1];
        uint32_t n1[LIMBS_2133];
        uint32_t n2[LIMBS_2133];
        uint32_t n3[LIMBS_2133];
        uint32_t n4[LIMBS_2133];

        uint64_t offset1 = four_i_block_size;
        uint64_t offset2 = offset1 + BLOCK_SIZE_2133;
        uint64_t offset3 = offset2 + BLOCK_SIZE_2133;
        uint64_t offset4 = offset3 + BLOCK_SIZE_2133;
        memcpy(block1, data + offset1, BLOCK_SIZE_2133);
        memcpy(block2, data + offset2, BLOCK_SIZE_2133);
        memcpy(block3, data + offset3, BLOCK_SIZE_2133);
        memcpy(block4, data + offset4, BLOCK_SIZE_2133);
        block1[BLOCK_SIZE_2133] = 0x01;
        block2[BLOCK_SIZE_2133] = 0x01;
        block3[BLOCK_SIZE_2133] = 0x01;
        block4[BLOCK_SIZE_2133] = 0x01;

        TO_LARGE_NUM_REP_MSG27_UNROLLED(n1, block1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n2, block2);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n3, block3);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n4, block4);

        MULMOD_P_PRECOMP_4BLOCKS(acc, n1, n2, n3, n4);
        four_i_block_size += four_block_size;
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS_2133; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[BLOCK_SIZE_2133 + 1];
        uint32_t n[LIMBS_2133];
        memset(block, 0, BLOCK_SIZE_2133 + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P_PRECOMP(acc, r, three_r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- remove if/else + precomputation + 2-level approach + delayed carry + inlined + unrolled --------------------------

unsigned char* poly2133_create_tag_remif(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    uint64_t num_full_blocks = (data_len / BLOCK_SIZE_2133) / NUM_GROUPS_2133;

    // precompute r^2, r^3 and r^4
    uint32_t r2[LIMBS_2133];
    uint32_t r3[LIMBS_2133];
    uint32_t r4[LIMBS_2133];
    uint32_t three_r[LIMBS_2133];
    uint32_t three_r2[LIMBS_2133];
    uint32_t three_r3[LIMBS_2133];
    uint32_t three_r4[LIMBS_2133];

    for (int i = 0; i < LIMBS_2133; i++){
        three_r[i] = 3*r[i];
    }
    memcpy(r2, r, 32);
    MULMOD_P_REMIF(r2, r, three_r);
    memcpy(r3, r2, 32);
    MULMOD_P_REMIF(r3, r, three_r);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r2[i] = 3*r2[i];
    }
    memcpy(r4, r2, 32);
    MULMOD_P_REMIF(r4, r2, three_r2);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r3[i] = 3*r3[i];
        three_r4[i] = 3*r4[i];
    }
    uint64_t block_size_plus_1 = BLOCK_SIZE_2133 + 1;
    uint64_t four_block_size = 4 * BLOCK_SIZE_2133;
    uint64_t four_i_block_size = 0;

    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[block_size_plus_1];
        unsigned char block2[block_size_plus_1];
        unsigned char block3[block_size_plus_1];
        unsigned char block4[block_size_plus_1];
        uint32_t n1[LIMBS_2133];
        uint32_t n2[LIMBS_2133];
        uint32_t n3[LIMBS_2133];
        uint32_t n4[LIMBS_2133];

        uint64_t offset1 = four_i_block_size;
        uint64_t offset2 = offset1 + BLOCK_SIZE_2133;
        uint64_t offset3 = offset2 + BLOCK_SIZE_2133;
        uint64_t offset4 = offset3 + BLOCK_SIZE_2133;

        memcpy(block1, data + offset1, BLOCK_SIZE_2133);
        memcpy(block2, data + offset2, BLOCK_SIZE_2133);
        memcpy(block3, data + offset3, BLOCK_SIZE_2133);
        memcpy(block4, data + offset4, BLOCK_SIZE_2133);
        block1[BLOCK_SIZE_2133] = 0x01;
        block2[BLOCK_SIZE_2133] = 0x01;
        block3[BLOCK_SIZE_2133] = 0x01;
        block4[BLOCK_SIZE_2133] = 0x01;

        TO_LARGE_NUM_REP_MSG27_UNROLLED(n1, block1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n2, block2);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n3, block3);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n4, block4);

        MULMOD_P_REMIF_4BLOCKS(acc, n1, n2, n3, n4);
        four_i_block_size += four_block_size;
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS_2133; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[BLOCK_SIZE_2133 + 1];
        uint32_t n[LIMBS_2133];
        memset(block, 0, BLOCK_SIZE_2133 + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P_REMIF(acc, r, three_r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- remove if/else + precomputation + 2-level approach + delayed carry + inlined + unrolled --------------------------
unsigned char* poly2133_create_tag_scalrep(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    uint64_t num_full_blocks = (data_len / BLOCK_SIZE_2133) / NUM_GROUPS_2133;

    // precompute r^2, r^3 and r^4
    uint32_t r2[LIMBS_2133];
    uint32_t r3[LIMBS_2133];
    uint32_t r4[LIMBS_2133];
    uint32_t three_r[LIMBS_2133];
    uint32_t three_r2[LIMBS_2133];
    uint32_t three_r3[LIMBS_2133];
    uint32_t three_r4[LIMBS_2133];

    for (int i = 0; i < LIMBS_2133; i++){
        three_r[i] = 3*r[i];
    }
    memcpy(r2, r, 32);
    MULMOD_P_REMIF(r2, r, three_r);
    memcpy(r3, r2, 32);
    MULMOD_P_REMIF(r3, r, three_r);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r2[i] = 3*r2[i];
    }
    memcpy(r4, r2, 32);
    MULMOD_P_REMIF(r4, r2, three_r2);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r3[i] = 3*r3[i];
        three_r4[i] = 3*r4[i];
    }
    uint64_t block_size_plus_1 = BLOCK_SIZE_2133 + 1;
    uint64_t four_block_size = 4 * BLOCK_SIZE_2133;
    uint64_t four_i_block_size = 0;
    
    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[block_size_plus_1];
        unsigned char block2[block_size_plus_1];
        unsigned char block3[block_size_plus_1];
        unsigned char block4[block_size_plus_1];
        uint32_t n1[LIMBS_2133];
        uint32_t n2[LIMBS_2133];
        uint32_t n3[LIMBS_2133];
        uint32_t n4[LIMBS_2133];

        uint64_t offset1 = four_i_block_size;
        uint64_t offset2 = offset1 + BLOCK_SIZE_2133;
        uint64_t offset3 = offset2 + BLOCK_SIZE_2133;
        uint64_t offset4 = offset3 + BLOCK_SIZE_2133;

        memcpy(block1, data + offset1, BLOCK_SIZE_2133);
        memcpy(block2, data + offset2, BLOCK_SIZE_2133);
        memcpy(block3, data + offset3, BLOCK_SIZE_2133);
        memcpy(block4, data + offset4, BLOCK_SIZE_2133);
        block1[BLOCK_SIZE_2133] = 0x01;
        block2[BLOCK_SIZE_2133] = 0x01;
        block3[BLOCK_SIZE_2133] = 0x01;
        block4[BLOCK_SIZE_2133] = 0x01;

        TO_LARGE_NUM_REP_MSG27_UNROLLED(n1, block1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n2, block2);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n3, block3);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n4, block4);

        MULMOD_P_SCALREP_4BLOCKS(acc, n1, n2, n3, n4);
        four_i_block_size += four_block_size;
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS_2133; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[BLOCK_SIZE_2133 + 1];
        uint32_t n[LIMBS_2133];
        memset(block, 0, BLOCK_SIZE_2133 + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P_REMIF(acc, r, three_r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- vectorized + remove if/else + precomputation + 2-level approach + delayed carry + inlined + unrolled --------------------------
unsigned char* poly2133_create_tag_vec(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    uint64_t num_full_blocks = (data_len / BLOCK_SIZE_2133) / NUM_GROUPS_2133;

    // precompute r^2, r^3 and r^4
    uint32_t r2[LIMBS_2133];
    uint32_t r3[LIMBS_2133];
    uint32_t r4[LIMBS_2133];
    uint32_t three_r[LIMBS_2133];
    uint32_t three_r2[LIMBS_2133];
    uint32_t three_r3[LIMBS_2133];
    uint32_t three_r4[LIMBS_2133];

    for (int i = 0; i < LIMBS_2133; i++){
        three_r[i] = 3*r[i];
    }
    memcpy(r2, r, 32);
    MULMOD_P_REMIF(r2, r, three_r);
    memcpy(r3, r2, 32);
    MULMOD_P_REMIF(r3, r, three_r);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r2[i] = 3*r2[i];
    }
    memcpy(r4, r2, 32);
    MULMOD_P_REMIF(r4, r2, three_r2);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r3[i] = 3*r3[i];
        three_r4[i] = 3*r4[i];
    }

    uint64_t block_size_plus_1 = BLOCK_SIZE_2133 + 1;
    uint64_t four_block_size = 4 * BLOCK_SIZE_2133;
    uint64_t four_i_block_size = 0;

    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[block_size_plus_1];
        unsigned char block2[block_size_plus_1];
        unsigned char block3[block_size_plus_1];
        unsigned char block4[block_size_plus_1];
        uint32_t n1[LIMBS_2133];
        uint32_t n2[LIMBS_2133];
        uint32_t n3[LIMBS_2133];
        uint32_t n4[LIMBS_2133];

        uint64_t offset1 = four_i_block_size;
        uint64_t offset2 = offset1 + BLOCK_SIZE_2133;
        uint64_t offset3 = offset2 + BLOCK_SIZE_2133;
        uint64_t offset4 = offset3 + BLOCK_SIZE_2133;

        memcpy(block1, data + offset1, BLOCK_SIZE_2133);
        memcpy(block2, data + offset2, BLOCK_SIZE_2133);
        memcpy(block3, data + offset3, BLOCK_SIZE_2133);
        memcpy(block4, data + offset4, BLOCK_SIZE_2133);
        block1[BLOCK_SIZE_2133] = 0x01;
        block2[BLOCK_SIZE_2133] = 0x01;
        block3[BLOCK_SIZE_2133] = 0x01;
        block4[BLOCK_SIZE_2133] = 0x01;

        TO_LARGE_NUM_REP_MSG27_UNROLLED(n1, block1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n2, block2);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n3, block3);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n4, block4);

        MULMOD_P_VEC_SCALREP_4BLOCKS(acc, n1, n2, n3, n4);
        four_i_block_size += four_block_size;
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*NUM_GROUPS_2133; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[BLOCK_SIZE_2133 + 1];
        uint32_t n[LIMBS_2133];
        memset(block, 0, BLOCK_SIZE_2133 + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P_REMIF(acc, r, three_r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------

// -------------------------- vectorized (8 blocks) + remove if/else + precomputation + 2-level approach + delayed carry + inlined + unrolled --------------------------
unsigned char* poly2133_create_tag_vec_8b(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char* data, uint64_t data_len){
    uint64_t num_blocks = (data_len + BLOCK_SIZE_2133 - 1) / BLOCK_SIZE_2133;
    uint64_t num_full_blocks = (data_len / BLOCK_SIZE_2133) / 8;

    // precompute r^2, r^3 and r^4
    uint32_t r2[LIMBS_2133];
    uint32_t r3[LIMBS_2133];
    uint32_t r4[LIMBS_2133];
    uint32_t r5[LIMBS_2133];
    uint32_t r6[LIMBS_2133];
    uint32_t r7[LIMBS_2133];
    uint32_t r8[LIMBS_2133];
    uint32_t three_r[LIMBS_2133];
    uint32_t three_r2[LIMBS_2133];
    uint32_t three_r3[LIMBS_2133];
    uint32_t three_r4[LIMBS_2133];
    uint32_t three_r5[LIMBS_2133];
    uint32_t three_r6[LIMBS_2133];
    uint32_t three_r7[LIMBS_2133];
    uint32_t three_r8[LIMBS_2133];

    for (int i = 0; i < LIMBS_2133; i++){
        three_r[i] = 3*r[i];
    }
    memcpy(r2, r, 32);
    MULMOD_P_REMIF(r2, r, three_r);
    memcpy(r3, r2, 32);
    MULMOD_P_REMIF(r3, r, three_r);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r2[i] = 3*r2[i];
    }
    memcpy(r4, r2, 32);
    MULMOD_P_REMIF(r4, r2, three_r2);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r3[i] = 3*r3[i];
        three_r4[i] = 3*r4[i];
    }
    memcpy(r5, r2, 32);
    MULMOD_P_REMIF(r5, r3, three_r3);
    memcpy(r6, r4, 32);
    MULMOD_P_REMIF(r6, r2, three_r2);
    memcpy(r7, r4, 32);
    MULMOD_P_REMIF(r7, r3, three_r3);
    memcpy(r8, r4, 32);
    MULMOD_P_REMIF(r8, r4, three_r4);
    for(int i = 0; i < LIMBS_2133; i++){
        three_r5[i] = 3*r5[i];
        three_r6[i] = 3*r6[i];
        three_r7[i] = 3*r7[i];
        three_r8[i] = 3*r8[i];
    }
    
    uint64_t block_size_plus_1 = BLOCK_SIZE_2133 + 1;
    uint64_t eight_block_size = 8 * BLOCK_SIZE_2133;
    uint64_t eight_i_block_size = 0;

    for(uint64_t i = 0; i < num_full_blocks; i++){
        unsigned char block1[block_size_plus_1];
        unsigned char block2[block_size_plus_1];
        unsigned char block3[block_size_plus_1];
        unsigned char block4[block_size_plus_1];
        unsigned char block5[block_size_plus_1];
        unsigned char block6[block_size_plus_1];
        unsigned char block7[block_size_plus_1];
        unsigned char block8[block_size_plus_1];
        uint32_t n1[LIMBS_2133];
        uint32_t n2[LIMBS_2133];
        uint32_t n3[LIMBS_2133];
        uint32_t n4[LIMBS_2133];
        uint32_t n5[LIMBS_2133];
        uint32_t n6[LIMBS_2133];
        uint32_t n7[LIMBS_2133];
        uint32_t n8[LIMBS_2133];

        uint64_t offset1 = eight_i_block_size;
        uint64_t offset2 = offset1 + BLOCK_SIZE_2133;
        uint64_t offset3 = offset2 + BLOCK_SIZE_2133;
        uint64_t offset4 = offset3 + BLOCK_SIZE_2133;
        uint64_t offset5 = offset4 + BLOCK_SIZE_2133;
        uint64_t offset6 = offset5 + BLOCK_SIZE_2133;
        uint64_t offset7 = offset6 + BLOCK_SIZE_2133;
        uint64_t offset8 = offset7 + BLOCK_SIZE_2133;

        memcpy(block1, data + offset1, BLOCK_SIZE_2133);
        memcpy(block2, data + offset2, BLOCK_SIZE_2133);
        memcpy(block3, data + offset3, BLOCK_SIZE_2133);
        memcpy(block4, data + offset4, BLOCK_SIZE_2133);
        memcpy(block5, data + offset5, BLOCK_SIZE_2133);
        memcpy(block6, data + offset6, BLOCK_SIZE_2133);
        memcpy(block7, data + offset7, BLOCK_SIZE_2133);
        memcpy(block8, data + offset8, BLOCK_SIZE_2133);
        block1[BLOCK_SIZE_2133] = 0x01;
        block2[BLOCK_SIZE_2133] = 0x01;
        block3[BLOCK_SIZE_2133] = 0x01;
        block4[BLOCK_SIZE_2133] = 0x01;
        block5[BLOCK_SIZE_2133] = 0x01;
        block6[BLOCK_SIZE_2133] = 0x01;
        block7[BLOCK_SIZE_2133] = 0x01;
        block8[BLOCK_SIZE_2133] = 0x01;

        TO_LARGE_NUM_REP_MSG27_UNROLLED(n1, block1);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n2, block2);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n3, block3);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n4, block4);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n5, block5);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n6, block6);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n7, block7);
        TO_LARGE_NUM_REP_MSG27_UNROLLED(n8, block8);

        MULMOD_P_VEC_SCALREP_8BLOCKS(acc, n1, n2, n3, n4, n5, n6, n7, n8);
        eight_i_block_size += eight_block_size;
    }

    // handle remaining blocks
    for (uint64_t i = num_full_blocks*8; i < num_blocks; i++){
        uint64_t offset = i*BLOCK_SIZE_2133;
        uint64_t block_len = (data_len - offset) < BLOCK_SIZE_2133 ? (data_len - offset) : BLOCK_SIZE_2133;
        unsigned char block[BLOCK_SIZE_2133 + 1];
        uint32_t n[LIMBS_2133];
        memset(block, 0, BLOCK_SIZE_2133 + 1);
        memcpy(block, data + offset, block_len);
        block[block_len] = 0x01;
        TO_LARGE_NUM_REP_MSG_UNROLLED(n, block, block_len + 1);
        
        // acc += n
        ADD_LARGE_NUMS_88(acc, n);
        
        // acc = (acc * r) mod p
        MULMOD_P_REMIF(acc, r, three_r);
    }

    ADD_LARGE_NUMS_88(acc, s); // acc += s
    
    unsigned char* tag = (unsigned char*)malloc(TAG_SIZE_2133 * sizeof(unsigned char));

    // convert acc to 26 bytes (LE format)
    TO_26_LE_BYTES(tag, acc);
    return tag;
}
// -----------------------------------------------------------------------


// keylength must be 54 bytes
void poly2133_init(uint32_t acc[LIMBS_2133], uint32_t r[LIMBS_2133], uint32_t s[LIMBS_2133], const unsigned char key[KEY_SIZE_2133]) {
    // split key into two halves (first half into r, other in s)
    int half_key_len = KEY_SIZE_2133 / 2;
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
    memset(acc, 0, LIMBS_2133*sizeof(uint32_t)); 
}