#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
#include <fstream>
#include "benchmark.h"
#include "utils.h"
#include "chacha_opts.h"

void register_functions();
void add_function(chacha20_encrypt_func f, std::string name);

static std::vector<chacha20_encrypt_func> userFuncs;
static std::vector<std::string>           funcNames;
int numFuncs = 0;

void add_function(chacha20_encrypt_func f, std::string name) {
    userFuncs.push_back(f);
    funcNames.push_back(name);
    numFuncs++;
}

void register_functions() {
    //scalar
    add_function(&chacha20_encrypt_baseline, "chacha20_encrypt_baseline");
    add_function(&chacha20_encrypt_strength_reduction, "chacha20_encrypt_strength_reduction");
    add_function(&chacha20_encrypt_inline, "chacha20_encrypt_inline");
    add_function(&chacha20_encrypt_unroll_ilp_ctxt, "chacha20_encrypt_unroll_ilp_ctxt");
    add_function(&chacha20_encrypt_multiple_pt_blocks_at_once, "chacha20_encrypt_multiple_pt_blocks_at_once");
    //vectorized
    add_function(&chacha20_encrypt_2, "chacha20_encrypt_2");
    add_function(&chacha20_encrypt_vectorized2, "chacha20_encrypt_vectorized2");
    add_function(&chacha20_encrypt_vectorized3, "chacha20_encrypt_vectorized3");
    add_function(&chacha20_encrypt_openssl, "chacha20_encrypt_openssl");
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

        for (const auto& funcName : funcNames){
            std::cout << "," << funcName;
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
        std::cout << "Register functions by calling register_func(f, name)" << std::endl;
        std::cout << "in register_funcs()" << std::endl;

        return 0;
    }

    alignas(32) uint8_t key[KEY_SIZE_B];
    alignas(32) uint8_t nonce[NONCE_SIZE_B];
    // Allocate buffers on heap, so large PTXT_LENs can be tested without stack overflow
    size_t alloc_size    = (PTXT_LEN + 31) & ~31;
    uint8_t* ptxt        = (uint8_t*) aligned_alloc(32, alloc_size);
    uint8_t* ctxt_base   = (uint8_t*) aligned_alloc(32, alloc_size);
    uint8_t* ctxt_test   = (uint8_t*) aligned_alloc(32, alloc_size);
    
    uint32_t ctr = 0;

    rands(key, KEY_SIZE_B);
    rands(nonce, NONCE_SIZE_B);
    rands(ptxt, PTXT_LEN);
    chacha20_encrypt_baseline(ctxt_base, ptxt, PTXT_LEN, key, nonce, ctr);

    std::function<void(chacha20_encrypt_func)> runner = [&](chacha20_encrypt_func f) {
        f(ctxt_test, ptxt, PTXT_LEN, key, nonce, ctr);
    };

    for (int i = 0; i < numFuncs; i++) {
        std::memset(ctxt_test, 0xFF, PTXT_LEN);

        chacha20_encrypt_func f = userFuncs[i];
        f(ctxt_test, ptxt, PTXT_LEN, key, nonce, ctr);

        bool isWrong = (std::memcmp(ctxt_test, ctxt_base, PTXT_LEN) != 0);
        if (isWrong)
            std::cerr << "CORRECTNESS FAIL: " << funcNames[i] << "\n";
    }

    std::cout << PTXT_LEN;
    for (int i = 0; i < numFuncs; i++)
        std::cout << "," << perf_test(userFuncs[i], runner);
    std::cout <<  "\n";

    free(ptxt);
    free(ctxt_base);
    free(ctxt_test);


    return 0;
}
