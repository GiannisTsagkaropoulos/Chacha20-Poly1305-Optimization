#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <functional>
#include "benchmark.h"
#include "utils.h"
#include "chacha20-poly1305.h"
#include "chacha20-poly2133.h"

struct aead_case_t {
    const aead_engine_t* engine;
    std::string          name;
};

void register_functions();
void add_engine(const aead_engine_t* engine, std::string name);

static std::vector<aead_case_t> cases;
int numFuncs = 0;

void add_engine(const aead_engine_t* engine, std::string name) {
    cases.push_back({engine, name});
    numFuncs++;
}

void register_functions() {
    add_engine(&AEAD_BASELINE,   "aead_decrypt_baseline");
    add_engine(&AEAD_SCALAR,     "aead_decrypt_scalar");
    add_engine(&AEAD_VECTORIZED, "aead_decrypt_vectorized");
}


int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <ptxt_len | --header>\n";
        return 1;
    }

    register_functions();
    // For benchmark runner to create the header.
    if (std::string(argv[1]) == "--header") {
        std::cout << "ptxt_len";

        for (const auto& c : cases){
            std::cout << "," << c.name;
        }
        std::cout << "\n";
        return 0;
    }

    uint64_t PTXT_LEN = std::strtoull(argv[1], nullptr, 10);
    if (PTXT_LEN == 0 || PTXT_LEN % 8 != 0) {
        std::cerr << "ptxt_len must be a non-zero multiple of 8\n";
        return 1;
    }

    if (numFuncs == 0){
        std::cout << std::endl;
        std::cout << "No functions registered - nothing for driver to do" << std::endl;
        std::cout << "Register functions by calling add_engine(e, name)" << std::endl;
        std::cout << "in register_functions()" << std::endl;

        return 0;
    }

    alignas(32) uint8_t key[KEY_SIZE_B];
    alignas(32) uint8_t nonce[NONCE_SIZE_B];
    // ciphertext = encrypted plaintext followed by the tag.
    size_t   ptxt_alloc = (PTXT_LEN + 31) & ~((size_t)31);
    size_t   ctxt_alloc = (PTXT_LEN + TAG_LENGTH + 31) & ~((size_t)31);
    uint8_t* ptxt       = (uint8_t*) aligned_alloc(32, ptxt_alloc);
    uint8_t* ctxt       = (uint8_t*) aligned_alloc(32, ctxt_alloc);
    uint8_t* ptxt_test  = (uint8_t*) aligned_alloc(32, ptxt_alloc);

    // No AAD for this benchmark (keeps the comparison focused on cipher + MAC).
    const uint8_t* aad     = nullptr;
    size_t         aad_len = 0;

    rands(key, KEY_SIZE_B);
    rands(nonce, NONCE_SIZE_B);
    rands(ptxt, PTXT_LEN);
    // Produce a valid (ciphertext || tag) once; every engine decrypts this.
    size_t cipher_len = encrypt_poly2133_with(&AEAD_BASELINE, ctxt, ptxt, PTXT_LEN, aad, aad_len, key, nonce);

    std::function<void(const aead_engine_t*)> runner = [&](const aead_engine_t* e) {
        decrypt_poly2133_with(e, ptxt_test, ctxt, cipher_len, aad, aad_len, key, nonce);
    };

    for (int i = 0; i < numFuncs; i++) {
        std::memset(ptxt_test, 0xFF, PTXT_LEN);

        size_t out_len = decrypt_poly2133_with(cases[i].engine, ptxt_test, ctxt, cipher_len, aad, aad_len, key, nonce);

        bool isWrong = (out_len != PTXT_LEN) ||
                       (std::memcmp(ptxt_test, ptxt, PTXT_LEN) != 0);
        if (isWrong)
            std::cerr << "CORRECTNESS FAIL: " << cases[i].name << "\n";
    }


    std::cout << PTXT_LEN;
    for (int i = 0; i < numFuncs; i++)
        std::cout << "," << perf_test(cases[i].engine, runner);
    std::cout <<  "\n";

    free(ptxt);
    free(ctxt);
    free(ptxt_test);


    return 0;
}
