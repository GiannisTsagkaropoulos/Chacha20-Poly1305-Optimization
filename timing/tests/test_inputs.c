#include "test_inputs.h"

//p_length represents the length of plaintext in bytes
uint8_t* create_random_bytes(int p_length){
    uint8_t* random_bytes = malloc(p_length);
        
        // Seed with current time so it's different every run
        srand(time(NULL));
        if (random_bytes == NULL) {
            return NULL; 
        }
        for (int i = 0; i < p_length; i++) {
            // rand() returns an int, we cast/mask it to 8 bits
            random_bytes[i] = (uint8_t)(rand() % 256);

        }

        return random_bytes;
}

//key is 32 bytes
uint8_t* create_random_key(){
    uint8_t* key_bytes = malloc(32);
        
        // Seed with current time so it's different every run
        srand(time(NULL));
        if (key_bytes == NULL) {
            return NULL; 
        }
        for (int i = 0; i < 32; i++) {
            // rand() returns an int, we cast/mask it to 8 bits
            key_bytes[i] = (uint8_t)(rand() % 256);

        }

        return key_bytes;
}

//nonce is 12 bytes
uint8_t* create_random_nonce(){
    uint8_t* nonce_bytes = malloc(12);
        
        // Seed with current time so it's different every run
        srand(time(NULL));
        if (nonce_bytes == NULL) {
            return NULL; 
        }
        for (int i = 0; i < 12; i++) {
            // rand() returns an int, we cast/mask it to 8 bits
            nonce_bytes[i] = (uint8_t)(rand() % 256);

        }

        return nonce_bytes;
}

int chacha20_encryption_chosen_len(uint64_t p_length, uint8_t* plaintext_b, uint8_t* key_b, uint8_t* nonce_b){
    uint8_t* ciphertext_b = malloc(p_length);
    if (!ciphertext_b) return;

    uint32_t block_ctr = 1;
    int rounds = 20;

    int res = chacha20_encrypt(key_b, nonce_b, block_ctr, plaintext_b, p_length, rounds, ciphertext_b);
    
    if(res==0){
            free(ciphertext_b); // Don't forget to free!
        return 0;
    }else{
        free(ciphertext_b); // Don't forget to free!
        return 1;
    }

}

void fill_random_key(uint8_t key[32]) {
    // Note: Do NOT call srand() inside here. Call it once in main().
    for (int i = 0; i < 32; i++) {
        key[i] = (uint8_t)(rand() % 256);
    }
}

//in chacha the data is written as uint8_t while in poly as char, remenber to correct it
int poly1305_test(uint64_t data_length, uint8_t* key, uint8_t* data){
    uint32_t acc[5], r[5], s[4];
    unsigned char* tag = malloc(data_length);
    int flag = 0;

    poly1305_init(acc, r, s, key); // create acc, r and s from key
    tag = create_tag(acc, r, s, (const unsigned char*) data, data_length); // create the tag
    if (tag[0] == 0){
        flag = 1;
        free(tag);
    }
    return flag;
}

void seal_test(const uint8_t *key_b, /*32 bytes*/
    const uint8_t *nonce_b, /*12 bytes*/ 
    const uint8_t *plaintext_b, size_t plaintext_len, 
    const uint8_t *data, size_t data_len,
    uint8_t *ciphertext_b){

   int res = seal(key_b, nonce_b, plaintext_b, plaintext_len, data, data_len, ciphertext_b);
}