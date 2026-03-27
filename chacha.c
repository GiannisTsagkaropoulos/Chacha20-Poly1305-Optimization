#define IS_BLOCK_CIPHER false
#define IS_AEAD true
#define TAG_LENGTH  16
#define NONCE_LENGTH  12
#define KEY_LENGTH  32
#define COUNTER  0
#define ROUNDS  20

short int* key[KEY_LENGTH];
short int* nonce[NONCE_LENGTH];
short int* tag[TAG_LENGTH];
static int* constants = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

static short int _round_mixup_box[9][4] = {{0, 4, 8, 12},
                        {1, 5, 9, 13},
                        {2, 6, 10, 14},
                        {3, 7, 11, 15},
                        {0, 5, 10, 15},
                        {1, 6, 11, 12},
                        {2, 7, 8, 13},
                        {3, 4, 9, 14}};


short int* bytearray_to_words(void);

void init(void){
    key[0] = bytearray_to_words();
    nonce[0] = bytearray_to_words();

}

