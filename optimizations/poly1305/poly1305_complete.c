#include "poly1305_complete.h"

unsigned char* base_poly1305(uint32_t acc[5], uint32_t r[5], uint32_t s[4], uint8_t key[32], const unsigned char* data, uint64_t data_len){
    const uint8_t clear_top4_bits = 0b00001111; 
    const uint8_t clear_lowest2_bits = 0b11111100;
    int half_key_len = KEY_SIZE / 2;

    unsigned char r_bytes[half_key_len];
    unsigned char s_bytes[half_key_len];

    memcpy(r_bytes, key, half_key_len);
    
    r_bytes[3]  &= clear_top4_bits;
    r_bytes[4]  &= clear_lowest2_bits;
    r_bytes[7]  &= clear_top4_bits;
    r_bytes[8]  &= clear_lowest2_bits;
    r_bytes[11] &= clear_top4_bits;
    r_bytes[12] &= clear_lowest2_bits;
    r_bytes[15] &= clear_top4_bits;

    CREATE_LIMBS_64(r, r_bytes); 

    memcpy(s_bytes, key + half_key_len, half_key_len);
    CREATE_LIMBS_64(s, s_bytes);

    memset(acc, 0, NUM_LIMBS*sizeof(uint32_t)); 

    uint64_t r0 = (uint64_t)r[0], r1 = (uint64_t)r[1], r2 = (uint64_t)r[2], r3 = (uint64_t)r[3], r4 = (uint64_t)r[4];
    uint64_t r0_5 = r0*5, r1_5 = r1*5, r2_5 = r2*5, r3_5 = r3*5, r4_5 = r4*5;

    uint64_t num_blocks = (data_len) / 16;
    uint64_t remainder = data_len % 16;

    const uint8_t* curr_data = data;
    uint8_t block[17];

    for(uint64_t i = 0; i < num_blocks; i++){

        uint64_t low = *(uint64_t*)(curr_data);
        uint64_t high = *(uint64_t*)(curr_data + 8);

        uint32_t n[5];
        n[0] = (uint32_t)low & 0x3FFFFFF;
        n[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;
        n[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        n[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;
        n[4] = (uint32_t)(high >> 40) | (1 << 24);

        for (int i = 0; i < 5; i++) acc[i] += n[i];


        uint64_t mult[5];

        mult[0] = (uint64_t)acc[0]*r0 + (uint64_t)acc[1]*r4_5 + (uint64_t)acc[2]*r3_5 + (uint64_t)acc[3]*r2_5 + (uint64_t)acc[4]*r1_5;
        mult[1] = (uint64_t)acc[0]*r1 + (uint64_t)acc[1]*r0   + (uint64_t)acc[2]*r4_5 + (uint64_t)acc[3]*r3_5 + (uint64_t)acc[4]*r2_5;
        mult[2] = (uint64_t)acc[0]*r2 + (uint64_t)acc[1]*r1   + (uint64_t)acc[2]*r0   + (uint64_t)acc[3]*r4_5 + (uint64_t)acc[4]*r3_5;
        mult[3] = (uint64_t)acc[0]*r3 + (uint64_t)acc[1]*r2   + (uint64_t)acc[2]*r1   + (uint64_t)acc[3]*r0   + (uint64_t)acc[4]*r4_5;
        mult[4] = (uint64_t)acc[0]*r4 + (uint64_t)acc[1]*r3   + (uint64_t)acc[2]*r2   + (uint64_t)acc[3]*r1   + (uint64_t)acc[4]*r0;  

        uint64_t carry = 0;
        for(int i = 0; i < 4; i++){
            carry = mult[i] >> 26;
            acc[i] = (uint32_t)(mult[i]&mask_lowest_26bits);
            mult[i +1] += carry;
        }


        carry = mult[4] >> 26; 
        acc[4] = (uint32_t)(mult[4] & mask_lowest_26bits); 

        acc[0] += (uint32_t)(carry *5);
        carry = acc[0] >> 26; 
        acc[0] &= mask_lowest_26bits;
        acc[1] += (uint32_t)carry;

        curr_data += 16;

    }

    if(remainder > 0){
        memset(block, 0, 17);
        memcpy(block, curr_data, remainder);
        block[remainder] = 0x01;

        uint64_t low = *(uint64_t*)(curr_data);
        uint64_t high = *(uint64_t*)(curr_data + 8);

        uint32_t n[5];
        n[0] = (uint32_t)low & 0x3FFFFFF;
        n[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;
        n[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        n[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;
        n[4] = (uint32_t)(high >> 40) | (1 << 24);

        for (int i = 0; i < 5; i++) acc[i] += n[i];


        uint64_t mult[5];

        mult[0] = (uint64_t)acc[0]*r0 + (uint64_t)acc[1]*r4_5 + (uint64_t)acc[2]*r3_5 + (uint64_t)acc[3]*r2_5 + (uint64_t)acc[4]*r1_5;
        mult[1] = (uint64_t)acc[0]*r1 + (uint64_t)acc[1]*r0   + (uint64_t)acc[2]*r4_5 + (uint64_t)acc[3]*r3_5 + (uint64_t)acc[4]*r2_5;
        mult[2] = (uint64_t)acc[0]*r2 + (uint64_t)acc[1]*r1   + (uint64_t)acc[2]*r0   + (uint64_t)acc[3]*r4_5 + (uint64_t)acc[4]*r3_5;
        mult[3] = (uint64_t)acc[0]*r3 + (uint64_t)acc[1]*r2   + (uint64_t)acc[2]*r1   + (uint64_t)acc[3]*r0   + (uint64_t)acc[4]*r4_5;
        mult[4] = (uint64_t)acc[0]*r4 + (uint64_t)acc[1]*r3   + (uint64_t)acc[2]*r2   + (uint64_t)acc[3]*r1   + (uint64_t)acc[4]*r0;  

        uint64_t carry = 0;
        for(int i = 0; i < 4; i++){
            carry = mult[i] >> 26;
            acc[i] = (uint32_t)(mult[i]&mask_lowest_26bits);
            mult[i +1] += carry;
        }


        carry = mult[4] >> 26; 
        acc[4] = (uint32_t)(mult[4] & mask_lowest_26bits); 

        acc[0] += (uint32_t)(carry *5);
        carry = acc[0] >> 26; 
        acc[0] &= mask_lowest_26bits;
        acc[1] += (uint32_t)carry;
    }


    uint32_t g[5];

    uint64_t carry = 5;
    for (int i = 0; i < 5; i++){
        carry += (uint64_t)acc[0];
        g[i] = (uint32_t)(carry & mask_lowest_26bits);
        carry >>= 26;

    }
    
    if (carry > 0) {
        memcpy(acc, g, 5 * sizeof(uint32_t));
    }

    uint32_t addition[4];

    uint32_t h[5];


    memcpy(h, acc, 5 * sizeof(uint32_t));

    uint64_t convert[4];
    int left_shift = 26;
    int right_shift = 0;
    for(unsigned int i = 0; i < 4; i++){
        convert[i] = ((uint64_t) h[i] >> right_shift) | ((uint64_t)h[i+1] << left_shift);
        left_shift -= 6;
        right_shift += 6;
    }
    

    carry = 0;
    for(unsigned int i = 0; i < 4; i++){
        carry += (convert[i] & mask_lowest_32bits) + s[i]; 
        addition[i] = (uint32_t) carry; 
        carry >>= 32; 
    }
    unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));

    for (int i = 0; i < 4; i++){
        tag[i*4] = (unsigned char)(addition[i] & 0xff); 
        tag[i*4 + 1] = (unsigned char)((addition[i] >> 8) & 0xff); 
        tag[i*4 + 2] = (unsigned char)((addition[i]>> 16) & 0xff); 
        tag[i*4+ 3] = (unsigned char)((addition[i] >> 24) & 0xff);
    }
    
    return tag;
}


//used poly1305_init_vectorized and memory_vect_inlined_carry_delay_parallel_Horner
unsigned char* best_poly1305(uint32_t acc[5], uint32_t r[5], uint32_t s[4], uint8_t key[32], const unsigned char* data, uint64_t data_len){
    
    /*--------------------POLY1305 INIT-----------------------------*/

    __m128i key_offsets     = _mm_set_epi32(9, 6, 3, 0);
    __m128i r_vec = _mm_i32gather_epi32((const int *)key, key_offsets, 1);

    __m128i r_shift_amounts = _mm_set_epi32(6, 4, 2, 0);
    __m128i r_mask          = _mm_set_epi32(0x3F03FFF, 0x3FFC0FF, 0x3FFFF03, 0x3FFFFFF);
    
    r_vec = _mm_srlv_epi32(r_vec, r_shift_amounts);
    r_vec = _mm_and_si128(r_vec, r_mask);
    _mm_storeu_si128((__m128i *)r, r_vec);
    r[4] = (BYTE_PTR_TO_U32(key + 12) >> 8) & 0x00FFFFF;


    const unsigned char *s_key = key + HALF_KEY_SIZE; 
    
    __m128i s_offsets       = _mm_set_epi32(9, 6, 3, 0);
    __m128i s_vec = _mm_i32gather_epi32((const int *)s_key, s_offsets, 1);

    __m128i s_shift_amounts = _mm_set_epi32(6, 4, 2, 0);
    __m128i s_mask          = _mm_set1_epi32(KEEP_LOWEST_26_BITS); 

    s_vec = _mm_srlv_epi32(s_vec, s_shift_amounts);
    s_vec = _mm_and_si128(s_vec, s_mask);
    uint32_t s4 = (uint32_t)(s_key)[13] | ((uint32_t)(s_key)[14]  <<  8) | ((uint32_t)(s_key)[15]  <<  16);

    _mm_storeu_si128((__m128i *)s, s_vec);
    s[4] = s4 & 0x3FFFFFF;

    
    __m128i zero_vec = _mm_setzero_si128();
    _mm_store_si128((__m128i *)acc, zero_vec);
    acc[4] = 0;
    
    
    
    /*---------------------CREATE TAG------------------------------*/
    
    uint64_t full_blocks = (data_len) / BLOCK_SIZE;
    uint64_t paralle_calculations = full_blocks / (PARALLEL_BLOCKS*2);
    uint64_t remainder = data_len % BLOCK_SIZE;

    uint32_t r2[NUM_LIMBS];
    uint32_t r3[NUM_LIMBS];
    uint32_t r4[NUM_LIMBS];
    uint32_t r5[NUM_LIMBS];
    uint32_t r6[NUM_LIMBS];
    uint32_t r7[NUM_LIMBS];
    uint32_t r8[NUM_LIMBS];


    memcpy(r2, r,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r2, r); // r2 = r * r mod p
    uint64_t acc64_0[NUM_LIMBS], r64_0[NUM_LIMBS], mult_0[NUM_LIMBS];
    uint64_t carry_0;
    uint64_t g_0[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++) {
        acc64_0[i] = (uint64_t) r2[i];
        r64_0[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_0, r64_0, mult_0);

    CARRY_PROPAGATION(carry_0,mult_0, r2);

    COMPUTE_MOD_P(carry_0, r2,g_0);

    if (carry_0 > 0) {
        memcpy( r2, g_0, 5 * sizeof(uint32_t));
    }

    memcpy(r3, r2,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r3, r); // r3 = r^2 * r mod p
        uint64_t acc64_1[NUM_LIMBS], r64_1[NUM_LIMBS], mult_1[NUM_LIMBS];
        uint64_t carry_1;
        uint64_t g_1[NUM_LIMBS];

        for (int i = 0; i < NUM_LIMBS; i++) {
            acc64_1[i] = (uint64_t)r3[i];
            r64_1[i] = (uint64_t )r[i];
        }

        MUL_MOD_P(acc64_1, r64_1, mult_1);

        CARRY_PROPAGATION(carry_1,mult_1,r3);

        COMPUTE_MOD_P(carry_1,r3,g_1);

        if (carry_1 > 0) {
            memcpy(r3, g_1, 5 * sizeof(uint32_t));
        }

    memcpy(r4, r3,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r4, r); // r4 = r^3 * r mod p
    uint64_t acc64_2[NUM_LIMBS], r64_2[NUM_LIMBS], mult_2[NUM_LIMBS];
    uint64_t carry_2;
    uint64_t g_2[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++) {
        acc64_2[i] = (uint64_t)r4[i];
        r64_2[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_2, r64_2, mult_2);

    CARRY_PROPAGATION(carry_2,mult_2,r4);

    COMPUTE_MOD_P(carry_2,r4,g_2);

    if (carry_2 > 0) {
        memcpy(r4, g_2, 5 * sizeof(uint32_t));
    }
    
    memcpy(r5, r4,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r5, r); // r5 = r^5 mod p
    uint64_t acc64_5[NUM_LIMBS], r64_5[NUM_LIMBS], mult_5[NUM_LIMBS];
    uint64_t carry_5;
    uint64_t g_5[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++) {
        acc64_5[i] = (uint64_t)r5[i];
        r64_5[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_5, r64_5, mult_5);

    CARRY_PROPAGATION(carry_5,mult_5,r5);

    COMPUTE_MOD_P(carry_5,r5,g_5);

    if (carry_5 > 0) {
        memcpy(r5, g_5, 5 * sizeof(uint32_t));
    }

    memcpy(r6, r5,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r6, r); // r6 = r^6 mod p
    uint64_t acc64_6[NUM_LIMBS], r64_6[NUM_LIMBS], mult_6[NUM_LIMBS];
    uint64_t carry_6;
    uint64_t g_6[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++) {
        acc64_6[i] = (uint64_t)r6[i];
        r64_6[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_6, r64_6, mult_6);

    CARRY_PROPAGATION(carry_6,mult_6,r6);

    COMPUTE_MOD_P(carry_6,r6,g_6);

    if (carry_6 > 0) {
        memcpy(r6, g_6, 5 * sizeof(uint32_t));
    }

    memcpy(r7, r6,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r7, r); // r7 = r^7 mod p
    uint64_t acc64_7[NUM_LIMBS], r64_7[NUM_LIMBS], mult_7[NUM_LIMBS];
    uint64_t carry_7;
    uint64_t g_7[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++) {
        acc64_7[i] = (uint64_t)r7[i];
        r64_7[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_7, r64_7, mult_7);

    CARRY_PROPAGATION(carry_7,mult_7,r7);

    COMPUTE_MOD_P(carry_7,r7,g_7);

    if (carry_7 > 0) {
        memcpy(r7, g_7, 5 * sizeof(uint32_t));
    }

    memcpy(r8, r7,  NUM_LIMBS * sizeof(uint32_t));
    //mulmod_p(r8, r); // r8 = r^8 mod p
    uint64_t acc64_8[NUM_LIMBS], r64_8[NUM_LIMBS], mult_8[NUM_LIMBS];
    uint64_t carry_8;
    uint64_t g_8[NUM_LIMBS];

    for (int i = 0; i < NUM_LIMBS; i++) {
        acc64_8[i] = (uint64_t)r8[i];
        r64_8[i] = (uint64_t )r[i];
    }

    MUL_MOD_P(acc64_8, r64_8, mult_8);

    CARRY_PROPAGATION(carry_8,mult_8,r8);

    COMPUTE_MOD_P(carry_8,r8,g_8);

    if (carry_8 > 0) {
        memcpy(r8, g_8, 5 * sizeof(uint32_t));
    }

    /*----------------INITIALIZING VECTORS------------------------------------*/

    uint32_t acc_0[NUM_LIMBS];
    uint32_t acc_1[NUM_LIMBS];
    uint32_t acc_2[NUM_LIMBS];
    uint32_t acc_3[NUM_LIMBS];

    memset(acc_0, 0, sizeof(acc_0));
    memset(acc_1, 0, sizeof(acc_1));
    memset(acc_2, 0, sizeof(acc_2));
    memset(acc_3, 0, sizeof(acc_3));

    const uint8_t* curr_data = data;
    uint8_t block_0[17];

    __m256i r4_vect[NUM_LIMBS];
    __m256i r8_vect[NUM_LIMBS];
    __m256i acc_vect[NUM_LIMBS];
    __m256i g_vect[NUM_LIMBS];

    g_vect[0] = _mm256_set1_epi64x(0);
    g_vect[1] = _mm256_set1_epi64x(0);
    g_vect[2] = _mm256_set1_epi64x(0);
    g_vect[3] = _mm256_set1_epi64x(0);
    g_vect[4] = _mm256_set1_epi64x(0);

    acc_vect[0] = _mm256_set1_epi64x(0);
    acc_vect[1] = _mm256_set1_epi64x(0);
    acc_vect[2] = _mm256_set1_epi64x(0);
    acc_vect[3] = _mm256_set1_epi64x(0);
    acc_vect[4] = _mm256_set1_epi64x(0);


    for(int j=0; j<NUM_LIMBS; j++){
        r4_vect[j]      = _mm256_set_epi32(0, r4[j],      0, r4[j],      0, r4[j],      0, r4[j]);
        r8_vect[j]      = _mm256_set_epi32(0, r8[j],      0, r8[j],      0, r8[j],      0, r8[j]);     
    }


/*------------------- STARTING COMPUTATION ON BLOCKS----------------------------*/
    for(uint64_t i = 0; i < paralle_calculations; i++) {

        __m256i n_vect[NUM_LIMBS];
        __m256i nn_vect[NUM_LIMBS];
        __m256i a_vect[NUM_LIMBS];
        __m256i carry_vect;
        __m256i mult_vect[NUM_LIMBS];

        __m256i mask_26 = _mm256_set1_epi32(0x3FFFFFF);
        

        __m256i mask_even_lanes = _mm256_set_epi32(0, -1, 0, -1, 0, -1, 0, -1);


        __m256i low_v = _mm256_setr_epi64x(
            *(const uint64_t*)(curr_data + 0),
            *(const uint64_t*)(curr_data + 16),
            *(const uint64_t*)(curr_data + 32),
            *(const uint64_t*)(curr_data + 48)
        );


        __m256i high_v = _mm256_setr_epi64x(
            *(const uint64_t*)(curr_data + 8),
            *(const uint64_t*)(curr_data + 24),
            *(const uint64_t*)(curr_data + 40),
            *(const uint64_t*)(curr_data + 56)
        );


        __m256i last_v = _mm256_setr_epi32(0x01, 0, 0x01, 0, 0x01, 0, 0x01, 0);


        n_vect[0] = _mm256_and_si256(low_v, mask_even_lanes);
        n_vect[0] = _mm256_and_si256(n_vect[0], mask_26);
        

        n_vect[1] = _mm256_srli_epi64(low_v, 26);
        n_vect[1] = _mm256_and_si256(n_vect[1], mask_even_lanes);
        n_vect[1] = _mm256_and_si256(n_vect[1], mask_26);
        

        __m256i l2_part1 = _mm256_srli_epi64(low_v, 52);
        __m256i l2_part2 = _mm256_slli_epi64(high_v, 12);
        n_vect[2] = _mm256_or_si256(l2_part1, l2_part2);
        n_vect[2] = _mm256_and_si256(n_vect[2], mask_even_lanes);
        n_vect[2] = _mm256_and_si256(n_vect[2], mask_26);
        

        n_vect[3] = _mm256_srli_epi64(high_v, 14);
        n_vect[3] = _mm256_and_si256(n_vect[3], mask_even_lanes);
        n_vect[3] = _mm256_and_si256(n_vect[3], mask_26);
        

        __m256i l4_part1 = _mm256_srli_epi64(high_v, 40);
        __m256i l4_part2 = _mm256_slli_epi64(last_v, 24);
        n_vect[4] = _mm256_or_si256(l4_part1, l4_part2);
        n_vect[4] = _mm256_and_si256(n_vect[4], mask_even_lanes);
        n_vect[4] = _mm256_and_si256(n_vect[4], mask_26);

        
        __m256i nn_low_v = _mm256_setr_epi64x(
            *(const uint64_t*)(curr_data + 64),
            *(const uint64_t*)(curr_data + 80),
            *(const uint64_t*)(curr_data + 96),
            *(const uint64_t*)(curr_data + 112)
        );

        __m256i nn_high_v = _mm256_setr_epi64x(
            *(const uint64_t*)(curr_data + 72),
            *(const uint64_t*)(curr_data + 88),
            *(const uint64_t*)(curr_data + 104),
            *(const uint64_t*)(curr_data + 120)
        );


        nn_vect[0] = _mm256_and_si256(nn_low_v, mask_even_lanes);
        nn_vect[0] = _mm256_and_si256(nn_vect[0], mask_26);
        

        nn_vect[1] = _mm256_srli_epi64(nn_low_v, 26);
        nn_vect[1] = _mm256_and_si256(nn_vect[1], mask_even_lanes);
        nn_vect[1] = _mm256_and_si256(nn_vect[1], mask_26);
        

        __m256i nn_l2_part1 = _mm256_srli_epi64(nn_low_v, 52);
        __m256i nn_l2_part2 = _mm256_slli_epi64(nn_high_v, 12);
        nn_vect[2] = _mm256_or_si256(nn_l2_part1, nn_l2_part2);
        nn_vect[2] = _mm256_and_si256(nn_vect[2], mask_even_lanes);
        nn_vect[2] = _mm256_and_si256(nn_vect[2], mask_26);

        nn_vect[3] = _mm256_srli_epi64(nn_high_v, 14);
        nn_vect[3] = _mm256_and_si256(nn_vect[3], mask_even_lanes);
        nn_vect[3] = _mm256_and_si256(nn_vect[3], mask_26);
        
        __m256i nn_l4_part1 = _mm256_srli_epi64(nn_high_v, 40);
        __m256i nn_l4_part2 = _mm256_slli_epi64(last_v, 24);
        nn_vect[4] = _mm256_or_si256(nn_l4_part1, nn_l4_part2);
        nn_vect[4] = _mm256_and_si256(nn_vect[4], mask_even_lanes);
        nn_vect[4] = _mm256_and_si256(nn_vect[4], mask_26);


        DOUBLE_MULTIPLICATION_ADDITION_VECT(mult_vect, acc_vect, r8_vect, n_vect, r4_vect, nn_vect);

        CARRY_PROP_DELAYED_VECT(carry_vect, mult_vect, acc_vect);
        MOD_P_DELAYED_VECT(carry_vect, g_vect, acc_vect);

        curr_data += 16 * PARALLEL_BLOCKS * 2;
    }

    for(int i=0;i<NUM_LIMBS;i++){
        acc_0[i] = (uint64_t)_mm256_extract_epi64(acc_vect[i], 0);
        acc_1[i] = (uint64_t)_mm256_extract_epi64(acc_vect[i], 1);
        acc_2[i] = (uint64_t)_mm256_extract_epi64(acc_vect[i], 2);
        acc_3[i] = (uint64_t)_mm256_extract_epi64(acc_vect[i], 3);
    }

    uint32_t* align_powers[PARALLEL_BLOCKS] = {r4, r3, r2, r};
    uint32_t* acc_array[PARALLEL_BLOCKS] = {acc_0, acc_1, acc_2, acc_3};

    for(int i=0; i< PARALLEL_BLOCKS; i++){
        //mulmod_p(acc_array[i], align_powers[i]);
        uint64_t acc64_align[NUM_LIMBS], r64_align[NUM_LIMBS], mult_align[NUM_LIMBS];
        uint64_t carry_align;
        uint64_t g_align[NUM_LIMBS];

        for (int j = 0; j < NUM_LIMBS; j++) {
            acc64_align[j] = (uint64_t)acc_array[i][j];
            r64_align[j] = (uint64_t )align_powers[i][j];
        }

        MUL_MOD_P(acc64_align, r64_align, mult_align);

        CARRY_PROPAGATION(carry_align,mult_align,acc_array[i]);

        COMPUTE_MOD_P(carry_align,acc_array[i],g_align);

        if (carry_align > 0) {
            memcpy(acc_array[i], g_align, 5 * sizeof(uint32_t));
        }

        //add_large_nums_55(acc, acc_array[i]);
        carry_align = 0; 
        ADD_55(carry_align, acc, acc_array[i]);
    }

    uint64_t remaining_full = full_blocks % (PARALLEL_BLOCKS*2);
    for(int i =0; i<remaining_full; i++){
        memcpy(block_0, curr_data, 16); 

        block_0[16] = 0x01;

        uint32_t n_0[NUM_LIMBS];

        //to_large_num_rep(n_0, block_0, 17);
        uint64_t low  = *(const uint64_t*)&block_0[0];
        uint64_t high = *(const uint64_t*)&block_0[8];
        uint64_t last = block_0[16];
        n_0[0] = (uint32_t)(low) & 0x3FFFFFF;
        n_0[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;

        n_0[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        
        n_0[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;

        n_0[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;

        //add_large_nums_55(acc, n_0); // acc += block
        uint64_t carry_0 = 0; 
        ADD_55(carry_0, acc, n_0);
        //mulmod_p(acc, r);            // acc = acc * r mod p
        uint64_t acc64_0[NUM_LIMBS], r64_0[NUM_LIMBS], mult_0[NUM_LIMBS];
        uint64_t g_0[NUM_LIMBS];

        for (int j = 0; j < NUM_LIMBS; j++) {
            acc64_0[j] = (uint64_t)acc[j];
            r64_0[j] = (uint64_t )r[j];
        }

        MUL_MOD_P(acc64_0, r64_0, mult_0);

        CARRY_PROPAGATION(carry_0,mult_0,acc);

        COMPUTE_MOD_P(carry_0,acc,g_0);

        if (carry_0 > 0) {
            memcpy(acc, g_0, 5 * sizeof(uint32_t));
        }

        curr_data += 16;
    }

    if(remainder > 0) {
        memset(block_0, 0, 17);

        memcpy(block_0, curr_data, remainder);

        block_0[remainder] = 0x01; 

        block_0[16] = 0x00; 

        uint32_t n[NUM_LIMBS];

        uint64_t low  = *(const uint64_t*)&block_0[0];
        uint64_t high = *(const uint64_t*)&block_0[8];
        uint64_t last = block_0[16];
        
        n[0] = (uint32_t)(low) & 0x3FFFFFF;
        n[1] = (uint32_t)(low >> 26) & 0x3FFFFFF;
        n[2] = (uint32_t)((low >> 52) | (high << 12)) & 0x3FFFFFF;
        n[3] = (uint32_t)(high >> 14) & 0x3FFFFFF;
        n[4] = (uint32_t)((high >> 40) | (last << 24)) & 0x3FFFFFF;

        //add_large_nums_55(acc, n);
        uint64_t carry_0;
        ADD_55(carry_0, acc, n);

        //mulmod_p(acc, r);
        uint64_t acc64_0[NUM_LIMBS], r64_0[NUM_LIMBS], mult_0[NUM_LIMBS];
        
        uint64_t g_0[NUM_LIMBS];

        for (int i = 0; i < NUM_LIMBS; i++) {
            acc64_0[i] = (uint64_t)acc[i];
            r64_0[i] = (uint64_t )r[i];
        }

        MUL_MOD_P(acc64_0, r64_0, mult_0);

        CARRY_PROPAGATION(carry_0,mult_0,acc);

        COMPUTE_MOD_P(carry_0,acc,g_0);

        if (carry_0 > 0) {
            memcpy(acc, g_0, 5 * sizeof(uint32_t));
        }
    }
    uint32_t addition[4];
    //add_large_nums_54(addition, acc, s);
    uint64_t convert[4];

    convert[0] = (uint64_t)acc[0]        | ((uint64_t)acc[1] << 26);
    convert[1] = (uint64_t)(acc[1] >> 6)  | ((uint64_t)acc[2] << 20);
    convert[2] = (uint64_t)(acc[2] >> 12) | ((uint64_t)acc[3] << 14);
    convert[3] = (uint64_t)(acc[3] >> 18) | ((uint64_t)acc[4] << 8);

    uint64_t carry = 0;
    for(unsigned int i = 0; i < 4; i++){
        carry += (uint32_t)convert[i] + (uint64_t)s[i]; 
        addition[i] = (uint32_t)carry; 
        carry >>= 32; 
    }  
    
    unsigned char* tag = (unsigned char*)malloc(16 * sizeof(unsigned char));
    //to_16_le_bytes(addition, tag);
    for (int i = 0; i < 4; i++){
        tag[i*4] = (unsigned char)(addition[i] & 0xff); // extract lowest 8 bits (least significant byte)
        tag[i*4 + 1] = (unsigned char)((addition[i] >> 8) & 0xff);
        tag[i*4 + 2] = (unsigned char)((addition[i]>> 16) & 0xff);
        tag[i*4+ 3] = (unsigned char)((addition[i] >> 24) & 0xff);
    }
    return tag;
}


unsigned char* openssl_poly1305(uint32_t acc[5], uint32_t r[5], uint32_t s[4], uint8_t key[32], const unsigned char* data, uint64_t data_len){
    unsigned char* tag_out = (unsigned char*)malloc(16 * sizeof(unsigned char));         
    size_t tag_len = 16; // FIX: Hardcode to 16, do not use sizeof(tag_out)

    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    int success = 0;

    mac = EVP_MAC_fetch(NULL, "POLY1305", NULL);
    if (mac == NULL) {
        fprintf(stderr, "Failed to fetch POLY1305 algorithm\n");
        goto cleanup;
    }

    mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL) {
        fprintf(stderr, "Failed to create MAC context\n");
        goto cleanup;
    }

    // FIX: Hardcode to 32, do not use sizeof(key)
    if (EVP_MAC_init(mctx, key, 32, NULL) != 1) {
        fprintf(stderr, "Failed to initialize MAC operation\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    if (EVP_MAC_update(mctx, data, data_len) != 1) {
        fprintf(stderr, "Failed to update MAC data\n");
        goto cleanup;
    }

    // FIX: Hardcode the max out buffer limit to 16
    if (EVP_MAC_final(mctx, tag_out, &tag_len, 16) != 1) {
        fprintf(stderr, "Failed to finalize MAC tag\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    success = 1;

cleanup:
    if (mctx) EVP_MAC_CTX_free(mctx);
    if (mac)  EVP_MAC_free(mac);

    if (!success) {
        free(tag_out);
        return NULL;
    }

    return tag_out;
}