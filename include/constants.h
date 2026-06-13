#pragma once

//chacha
#define BLOCK_CTR_IDX 12

#define KEY_SIZE_B   32
#define KEY_SIZE_W   8
#define NONCE_SIZE_B 12
#define NONCE_SIZE_W 3
#define STATE_SIZE_B 64
#define STATE_SIZE_W 16
#define BLOCK_SIZE_B 64

#define STATE_0 0x61707865
#define STATE_1 0x3320646e
#define STATE_2 0x79622d32
#define STATE_3 0x6b206574

#define DOUBLE_ROUNDS 10

//poly1305
#define LIMBS_1305 5
#define BLOCK_SIZE_1305 16
#define KEY_SIZE_1305 32
#define HALF_KEY_SIZE_1305 16
#define TAG_SIZE_1305 16
#define PARALLEL_BLOCKS_1305 4
#define BLOCK_SIZE_1305 16

#define KEEP_LOWEST_26_BITS 0x3FFFFFF
#define CLEAR_TOP_4_BITS 0b00001111
#define CLEAR_LOW_2_BITS 0b11111100
#define mask_lowest_26bits 0x3ffffff
#define mask_lowest_32bits 0xffffffffULL

//poly2133
#define LIMBS_2133 8
#define NUM_GROUPS_2133 4
#define BLOCK_SIZE_2133 26
#define KEY_SIZE_2133 54
#define SIZE_HALF_KEY_2133 27

#define TAG_SIZE_2133 26

#define mask_lowest_28bits 0x0FFFFFFF
#define mask_lowest_17bits 0x0001FFFF


//poly1305-chacha20
#define AEAD_AUTH_FAIL 1
#define NONCE_SIZE_AEAD 12