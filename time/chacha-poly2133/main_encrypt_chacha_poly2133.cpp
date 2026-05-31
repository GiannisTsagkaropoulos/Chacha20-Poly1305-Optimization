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
static std::vector<aead_case_t> ops;
int numFuncs = 0;

void add_engine(const aead_engine_t* engine, std::string name) {
    cases.push_back({engine, name});
    numFuncs++;
}

void register_functions() {
    add_engine(&AEAD_BASELINE,   "aead_encrypt_baseline");
    add_engine(&AEAD_SCALAR,     "aead_encrypt_scalar");
    add_engine(&AEAD_VECTORIZED, "aead_encrypt_vectorized");
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
    // ciphertext holds the encrypted plaintext followed by the tag.
    size_t   ptxt_alloc = (PTXT_LEN + 31) & ~((size_t)31);
    size_t   ctxt_alloc = (PTXT_LEN + TAG_LENGTH + 31) & ~((size_t)31);
    uint8_t* ptxt       = (uint8_t*) aligned_alloc(32, ptxt_alloc);
    uint8_t* ctxt_base  = (uint8_t*) aligned_alloc(32, ctxt_alloc);
    uint8_t* ctxt_test  = (uint8_t*) aligned_alloc(32, ctxt_alloc);

    // No AAD for this benchmark (keeps the comparison focused on cipher + MAC).
    const uint8_t* aad     = nullptr;
    size_t         aad_len = 0;

    rands(key, KEY_SIZE_B);
    rands(nonce, NONCE_SIZE_B);
    rands(ptxt, PTXT_LEN);
    // Reference output from the baseline engine; every engine must match it.
    encrypt_poly2133_with(&AEAD_BASELINE, ctxt_base, ptxt, PTXT_LEN, aad, aad_len, key, nonce);

    std::function<void(const aead_engine_t*)> runner = [&](const aead_engine_t* e) {
        encrypt_poly2133_with(e, ctxt_test, ptxt, PTXT_LEN, aad, aad_len, key, nonce);
    };

    for (int i = 0; i < numFuncs; i++) {
        std::memset(ctxt_test, 0xFF, PTXT_LEN + TAG_LENGTH);

        encrypt_poly2133_with(cases[i].engine, ctxt_test, ptxt, PTXT_LEN, aad, aad_len, key, nonce);

        bool isWrong = (std::memcmp(ctxt_test, ctxt_base, PTXT_LEN + TAG_LENGTH) != 0);
        if (isWrong)
            std::cerr << "CORRECTNESS FAIL: " << cases[i].name << "\n";
    }


    std::cout << PTXT_LEN;
    for (int i = 0; i < numFuncs; i++)
        std::cout << "," << perf_test(cases[i].engine, runner);
    std::cout <<  "\n";

    free(ptxt);
    free(ctxt_base);
    free(ctxt_test);


    return 0;
}
