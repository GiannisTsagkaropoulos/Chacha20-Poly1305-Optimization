#include <stdint.h> 
#include <string.h>
#include <stdlib.h>
#include <immintrin.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define NUM_LIMBS 5
#define BLOCK_SIZE 16
#define TAG_SIZE 16
#define KEY_SIZE 32
#define HALF_KEY_SIZE 16
#define B 2
#define PARALLEL_BLOCKS 4
#define NUM_LIMBS 5


const uint32_t mask_lowest_26bits = 0x3ffffff; 
const uint64_t mask_lowest_32bits = 0xffffffffULL;

#define KEEP_LOWEST_26_BITS 0x3FFFFFF
#define CLEAR_TOP_4_BITS 0b00001111
#define CLEAR_LOW_2_BITS 0b11111100

#define BYTE_PTR_TO_U32(byte_array)      \
    (                                    \
       (uint32_t)(byte_array)[0]         \
     | ((uint32_t)(byte_array)[1] <<  8) \
     | ((uint32_t)(byte_array)[2] << 16) \
     | ((uint32_t)(byte_array)[3] << 24) \
    )

#define CREATE_LIMBS_64(out, bytes) \
 do { \
     uint64_t _t0 = (uint64_t)(bytes)[0] \
            | ((uint64_t)(bytes)[1] <<  8)  \
            | ((uint64_t)(bytes)[2] << 16)  \
            | ((uint64_t)(bytes)[3] << 24)  \
            | ((uint64_t)(bytes)[4] << 32)  \
            | ((uint64_t)(bytes)[5] << 40)  \
            | ((uint64_t)(bytes)[6] << 48)  \
            | ((uint64_t)(bytes)[7] << 56); \
        \
        uint64_t _t1 = (uint64_t)(bytes)[8]  \
            | ((uint64_t)(bytes)[9]  <<  8)  \
            | ((uint64_t)(bytes)[10] << 16)  \
            | ((uint64_t)(bytes)[11] << 24)  \
            | ((uint64_t)(bytes)[12] << 32)  \
            | ((uint64_t)(bytes)[13] << 40)  \
            | ((uint64_t)(bytes)[14] << 48)  \
            | ((uint64_t)(bytes)[15] << 56); \
        \
        \
    (out)[0] = (uint32_t)(_t0)                      & KEEP_LOWEST_26_BITS; \
    (out)[1] = (uint32_t)(_t0 >> 26)                & KEEP_LOWEST_26_BITS; \
    (out)[2] = (uint32_t)((_t0 >> 52) | (_t1 << 12))& KEEP_LOWEST_26_BITS; \
    (out)[3] = (uint32_t)(_t1 >> 14)                & KEEP_LOWEST_26_BITS; \
    (out)[4] = (uint32_t)(_t1 >> 40)                & KEEP_LOWEST_26_BITS; \
    } while (0) 


/*-----------MACROS FOR CREATE TAG--------------------*/
#define MUL_MOD_P(acc64, r64, mult) do{ \
    mult[0] = acc64[0]*r64[0] + acc64[1]*5*r64[4] + acc64[2]*5*r64[3] + 5*acc64[3]*r64[2] + 5*acc64[4]*r64[1];\
    mult[1] = acc64[0]*r64[1] + acc64[1]*r64[0] + acc64[2]*5*r64[4] + acc64[3]*5*r64[3] + acc64[4]*5*r64[2];\
    mult[2] = acc64[0]*r64[2] + acc64[1]*r64[1] + acc64[2]*r64[0] + acc64[3]*5*r64[4] + acc64[4]*5*r64[3];\
    mult[3] = acc64[0]*r64[3] + acc64[1]*r64[2] + acc64[2]*r64[1] + acc64[3]*r64[0] + acc64[4]*5*r64[4];\
    mult[4] = acc64[0]*r64[4] + acc64[1]*r64[3] + acc64[2]*r64[2] + acc64[3]*r64[1] + acc64[4]*r64[0];\
}while(0)

#define CARRY_PROPAGATION(carry,mult,acc) do{ \
    for(int j = 0; j < 4; j++){\
        carry = (mult[j]) >> 26;\
        acc[j] = (uint32_t)(mult[j]&mask_lowest_26bits);\
        mult[j +1] += carry;\
    }\
    carry = mult[4] >> 26; \
    (acc[4]) = (uint32_t)((mult[4]) & mask_lowest_26bits);\
    \
    (acc[0]) += (uint32_t)(carry *5);\
    carry =(acc[0]) >> 26;\
    (acc[0]) &= mask_lowest_26bits;\
    (acc[1]) += (uint32_t)carry;\
}while(0)

#define COMPUTE_MOD_P(carry,acc,g) do{\
    carry = (uint64_t)acc[0] + 5; \
    for (int j = 0; j < 4; j++){\
        g[j] = (uint32_t)(carry & mask_lowest_26bits);\
        carry >>= 26;\
        carry += (uint64_t)acc[j+1];\
    }\
    \
    g[4] = (uint32_t)(carry & mask_lowest_26bits);\
    carry >>= 26;\
}while(0)

#define ADD_55(carry, a, b) do{ \
    for (int j = 0; j < 5; j++){    \
        carry = (uint64_t)a[j] + b[j] + carry;   \
        a[j] = (uint32_t)(carry &mask_lowest_26bits);   \
        carry >>= 26;     \
    }    \
    \
    a[0] += (uint32_t)(carry * 5);   \
}while(0)


#define DOUBLE_MULTIPLICATION_ADDITION_VECT(mult_v, a_v, r8_v, n0_v, r4_v, n00_v) do { \
    \
    __m256i v5 = _mm256_set1_epi64x(5); \
    \
    /* --- Limb 0 --- */ \
    (mult_v)[0] = _mm256_add_epi64( \
        _mm256_add_epi64( \
            _mm256_add_epi64(_mm256_mul_epu32((a_v)[0], (r8_v)[0]), _mm256_mul_epu32(_mm256_mul_epu32((a_v)[1], v5), (r8_v)[4])), \
            _mm256_add_epi64(_mm256_mul_epu32(_mm256_mul_epu32((a_v)[2], v5), (r8_v)[3]), _mm256_mul_epu32(_mm256_mul_epu32((a_v)[3], v5), (r8_v)[2])) \
        ), \
        _mm256_add_epi64( \
            _mm256_mul_epu32(_mm256_mul_epu32((a_v)[4], v5), (r8_v)[1]), \
            _mm256_add_epi64( \
                _mm256_add_epi64(_mm256_mul_epu32((n0_v)[0], (r4_v)[0]), _mm256_mul_epu32(_mm256_mul_epu32((n0_v)[1], v5), (r4_v)[4])), \
                _mm256_add_epi64(_mm256_mul_epu32(_mm256_mul_epu32((n0_v)[2], v5), (r4_v)[3]), _mm256_mul_epu32(_mm256_mul_epu32((n0_v)[3], v5), (r4_v)[2])) \
            ) \
        ) \
    ); \
    (mult_v)[0] = _mm256_add_epi64((mult_v)[0], _mm256_mul_epu32(_mm256_mul_epu32((n0_v)[4], v5), (r4_v)[1])); \
    \
    /* --- Limb 1 --- */ \
    (mult_v)[1] = _mm256_add_epi64( \
        _mm256_add_epi64( \
            _mm256_add_epi64(_mm256_mul_epu32((a_v)[0], (r8_v)[1]), _mm256_mul_epu32((a_v)[1], (r8_v)[0])), \
            _mm256_add_epi64(_mm256_mul_epu32(_mm256_mul_epu32((a_v)[2], v5), (r8_v)[4]), _mm256_mul_epu32(_mm256_mul_epu32((a_v)[3], v5), (r8_v)[3])) \
        ), \
        _mm256_add_epi64( \
            _mm256_mul_epu32(_mm256_mul_epu32((a_v)[4], v5), (r8_v)[2]), \
            _mm256_add_epi64( \
                _mm256_add_epi64(_mm256_mul_epu32((n0_v)[0], (r4_v)[1]), _mm256_mul_epu32((n0_v)[1], (r4_v)[0])), \
                _mm256_add_epi64(_mm256_mul_epu32(_mm256_mul_epu32((n0_v)[2], v5), (r4_v)[4]), _mm256_mul_epu32(_mm256_mul_epu32((n0_v)[3], v5), (r4_v)[3])) \
            ) \
        ) \
    ); \
    (mult_v)[1] = _mm256_add_epi64((mult_v)[1], _mm256_mul_epu32(_mm256_mul_epu32((n0_v)[4], v5), (r4_v)[2])); \
    \
    /* --- Limb 2 --- */ \
    (mult_v)[2] = _mm256_add_epi64( \
        _mm256_add_epi64( \
            _mm256_add_epi64(_mm256_mul_epu32((a_v)[0], (r8_v)[2]), _mm256_mul_epu32((a_v)[1], (r8_v)[1])), \
            _mm256_add_epi64(_mm256_mul_epu32((a_v)[2], (r8_v)[0]), _mm256_mul_epu32(_mm256_mul_epu32((a_v)[3], v5), (r8_v)[4])) \
        ), \
        _mm256_add_epi64( \
            _mm256_mul_epu32(_mm256_mul_epu32((a_v)[4], v5), (r8_v)[3]), \
            _mm256_add_epi64( \
                _mm256_add_epi64(_mm256_mul_epu32((n0_v)[0], (r4_v)[2]), _mm256_mul_epu32((n0_v)[1], (r4_v)[1])), \
                _mm256_add_epi64(_mm256_mul_epu32((n0_v)[2], (r4_v)[0]), _mm256_mul_epu32(_mm256_mul_epu32((n0_v)[3], v5), (r4_v)[4])) \
            ) \
        ) \
    ); \
    (mult_v)[2] = _mm256_add_epi64((mult_v)[2], _mm256_mul_epu32(_mm256_mul_epu32((n0_v)[4], v5), (r4_v)[3])); \
    \
    /* --- Limb 3 --- */ \
    (mult_v)[3] = _mm256_add_epi64( \
        _mm256_add_epi64( \
            _mm256_add_epi64(_mm256_mul_epu32((a_v)[0], (r8_v)[3]), _mm256_mul_epu32((a_v)[1], (r8_v)[2])), \
            _mm256_add_epi64(_mm256_mul_epu32((a_v)[2], (r8_v)[1]), _mm256_mul_epu32((a_v)[3], (r8_v)[0])) \
        ), \
        _mm256_add_epi64( \
            _mm256_mul_epu32(_mm256_mul_epu32((a_v)[4], v5), (r8_v)[4]), \
            _mm256_add_epi64( \
                _mm256_add_epi64(_mm256_mul_epu32((n0_v)[0], (r4_v)[3]), _mm256_mul_epu32((n0_v)[1], (r4_v)[2])), \
                _mm256_add_epi64(_mm256_mul_epu32((n0_v)[2], (r4_v)[1]), _mm256_mul_epu32((n0_v)[3], (r4_v)[0])) \
            ) \
        ) \
    ); \
    (mult_v)[3] = _mm256_add_epi64((mult_v)[3], _mm256_mul_epu32(_mm256_mul_epu32((n0_v)[4], v5), (r4_v)[4])); \
    \
    /* --- Limb 4 --- */ \
    (mult_v)[4] = _mm256_add_epi64( \
        _mm256_add_epi64( \
            _mm256_add_epi64(_mm256_mul_epu32((a_v)[0], (r8_v)[4]), _mm256_mul_epu32((a_v)[1], (r8_v)[3])), \
            _mm256_add_epi64(_mm256_mul_epu32((a_v)[2], (r8_v)[2]), _mm256_mul_epu32((a_v)[3], (r8_v)[1])) \
        ), \
        _mm256_add_epi64( \
            _mm256_mul_epu32((a_v)[4], (r8_v)[0]), \
            _mm256_add_epi64( \
                _mm256_add_epi64(_mm256_mul_epu32((n0_v)[0], (r4_v)[4]), _mm256_mul_epu32((n0_v)[1], (r4_v)[3])), \
                _mm256_add_epi64(_mm256_mul_epu32((n0_v)[2], (r4_v)[2]), _mm256_mul_epu32((n0_v)[3], (r4_v)[1])) \
            ) \
        ) \
    ); \
    (mult_v)[4] = _mm256_add_epi64((mult_v)[4], _mm256_mul_epu32((n0_v)[4], (r4_v)[0])); \
    \
    /* --- Add n_00 blocks --- */ \
    (mult_v)[0] = _mm256_add_epi64((mult_v)[0], (n00_v)[0]); \
    (mult_v)[1] = _mm256_add_epi64((mult_v)[1], (n00_v)[1]); \
    (mult_v)[2] = _mm256_add_epi64((mult_v)[2], (n00_v)[2]); \
    (mult_v)[3] = _mm256_add_epi64((mult_v)[3], (n00_v)[3]); \
    (mult_v)[4] = _mm256_add_epi64((mult_v)[4], (n00_v)[4]); \
} while(0)


#define CARRY_PROP_DELAYED_VECT(carry, mult, acc) do{ \
    __m256i v_mask_26 = _mm256_set1_epi64x(0x3FFFFFF); \
    for(int j = 0; j < 4; j++){   \
        carry = _mm256_srli_epi64(mult[j], 26);   \
        acc[j] = _mm256_and_si256(mult[j], v_mask_26);  \
        mult[j + 1] = _mm256_add_epi64(mult[j+1] , carry); \
    }\
    \
    carry = _mm256_srli_epi64(mult[4], 26);   \
    acc[4] = _mm256_and_si256(mult[4], v_mask_26);  \
    \
    __m256i five = _mm256_set1_epi64x(5); \
    __m256i carry5 = _mm256_mul_epu32(five, carry); \
    acc[0] = _mm256_add_epi64(acc[0], carry5);  \
    carry = _mm256_srli_epi64(acc[0], 26);   \
    acc[0] = _mm256_and_si256(acc[0], v_mask_26);  \
    acc[1] = _mm256_add_epi64(acc[1], carry);  \
}while(0)

#define MOD_P_DELAYED_VECT(carry,g,acc) do{ \
    __m256i five = _mm256_set1_epi64x(5); \
    __m256i v_mask_26 = _mm256_set1_epi64x(0x3FFFFFF); \
    carry = _mm256_add_epi64(acc[0], five);   \
    for (int j = 0; j < 4; j++){    \
        g[j] = _mm256_and_si256(carry , v_mask_26);  \
        carry = _mm256_srli_epi64(carry, 26);    \
        carry = _mm256_add_epi64(carry, acc[j+1]);   \
    }\
    g[4] = _mm256_and_si256(carry , v_mask_26); \
    carry = _mm256_srli_epi64(carry, 26);     \
    \
}while(0)



unsigned char* base_poly1305(uint32_t acc[5], uint32_t r[5], uint32_t s[4], uint8_t key[32], const unsigned char* data, uint64_t data_len);

unsigned char* best_poly1305(uint32_t acc[5], uint32_t r[5], uint32_t s[4], uint8_t key[32], const unsigned char* data, uint64_t data_len);

unsigned char* openssl_poly1305(uint32_t acc[5], uint32_t r[5], uint32_t s[4], uint8_t key[32], const unsigned char* data, uint64_t data_len);


//for benchmarks
typedef unsigned char*(*poly1305_func)(uint32_t acc[5], uint32_t r[5], uint32_t s[4], uint8_t key[32], const unsigned char* data, uint64_t data_len);