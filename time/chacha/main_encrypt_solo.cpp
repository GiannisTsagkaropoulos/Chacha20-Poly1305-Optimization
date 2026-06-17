#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
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
    add_function(&chacha20_encrypt_strength_reduction, "chacha20_encrypt_strength_reduction");
    add_function(&chacha20_encrypt_inline, "chacha20_encrypt_inline");
    add_function(&chacha20_encrypt_scalar_replacement, "chacha20_encrypt_scalar_replacement");
    add_function(&chacha20_encrypt_unroll_ilp_ctxt, "chacha20_encrypt_unroll_ilp_ctxt");
    add_function(&chacha20_encrypt_multiple_pt_blocks_at_once, "chacha20_encrypt_multiple_pt_blocks_at_once");
    add_function(&chacha20_encrypt_multiple_pt_blocks_at_once2, "chacha20_encrypt_multiple_pt_blocks_at_once2");
    add_function(&chacha20_encrypt_2, "chacha20_encrypt_2");
    add_function(&chacha20_encrypt_vectorized2, "chacha20_encrypt_vectorized2");
    add_function(&chacha20_encrypt_vectorized3, "chacha20_encrypt_vectorized3");
    add_function(&chacha20_encrypt_openssl, "chacha20_encrypt_openssl");
}

int main() {
    register_functions();

    if (numFuncs == 0){
        std::cout << std::endl;
        std::cout << "No functions registered - nothing for driver to do" << std::endl;
        std::cout << "Register functions by calling register_func(f, name)" << std::endl;
        std::cout << "in register_funcs()" << std::endl;

        return 0;
    }
    std::cout << "\nStarting ChaCha Encrypt Benchmark (" << numFuncs << " functions registered)\n" << std::endl;

    uint64_t PTXT_LEN = 1048576; // 2^{20}

    uint32_t ctr = 0;
    alignas(32) uint8_t key[KEY_SIZE_B];
    alignas(32) uint8_t nonce[NONCE_SIZE_B];
    
    size_t alloc_size    = (PTXT_LEN + 31) & ~31;
    uint8_t* ptxt        = (uint8_t*) aligned_alloc(32, alloc_size);
    uint8_t* ctxt_base   = (uint8_t*) aligned_alloc(32, alloc_size);
    uint8_t* ctxt_test   = (uint8_t*) aligned_alloc(32, alloc_size);
    
    rands(key, KEY_SIZE_B);
    rands(nonce, NONCE_SIZE_B);
    rands(ptxt, PTXT_LEN);

    std::function<void(chacha20_encrypt_func)> runner = [&](chacha20_encrypt_func f) {
        f(ctxt_test, ptxt, PTXT_LEN, key, nonce, ctr);
    };

    std::cout << "Correctness\n\n";
    chacha20_encrypt_baseline(ctxt_base, ptxt, PTXT_LEN, key, nonce, ctr);
    for (int i = 0; i < numFuncs; i++) {
        std::memset(ctxt_test, 0xFF, PTXT_LEN);

        chacha20_encrypt_func f = userFuncs[i];
        f(ctxt_test, ptxt, PTXT_LEN, key, nonce, ctr);

        bool isCorrect = (std::memcmp(ctxt_test, ctxt_base, PTXT_LEN) == 0);
        print_correctness(isCorrect, funcNames[i]);  
    }

    double base_cycles    = perf_test(chacha20_encrypt_baseline, runner);
    std::cout << "\nPerformance\n\n";
    std::cout << "base   : " << base_cycles    << " cycles\n";

    for (int i = 0; i < numFuncs; i++) {
        double cycles          = perf_test(userFuncs[i], runner);
        double speedup_base    = base_cycles    / cycles;

        print_benchmark(funcNames[i], cycles, speedup_base);
    }

    free(ptxt);
    free(ctxt_base);
    free(ctxt_test);

    return 0;
}