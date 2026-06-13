#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
#include "benchmark.h"
#include "utils.h"
#include "poly1305_init_opts.h"

void register_functions();
void add_function(poly1305_init_func f, std::string name);

static std::vector<poly1305_init_func> userFuncs;
static std::vector<std::string>        funcNames;
int numFuncs = 0;

void add_function(poly1305_init_func f, std::string name) {
    userFuncs.push_back(f);
    funcNames.push_back(name);
    numFuncs++;
}

void register_functions() {
    add_function(&poly1305_init_baseline, "poly1305_init_baseline");
    add_function(&poly1305_init_inline_64, "poly1305_init_inline_64");
    add_function(&poly1305_init_scalar_replacement, "poly1305_init_scalar_replacement");
    add_function(&poly1305_init_precompute_clamp_masks, "poly1305_init_precompute_clamp_masks");
    add_function(&poly1305_init_vectorized, "poly1305_init_vectorized");
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
    std::cout << "Starting Poly1305 Init Benchmark" << numFuncs << " functions registered)\n" << std::endl;

    alignas(32) uint32_t acc_base[LIMBS_1305];
    alignas(32) uint32_t r_base[LIMBS_1305];
    alignas(32) uint32_t s_base[LIMBS_1305-1];
    
    alignas(32) uint32_t acc_test[LIMBS_1305];
    alignas(32) uint32_t r_test[LIMBS_1305];
    alignas(32) uint32_t s_test[LIMBS_1305-1];
    
    alignas(32) unsigned char key[KEY_SIZE_1305];
    rands(key, KEY_SIZE_1305);
        
    std::cout << "Correctness\n\n";
    poly1305_init_baseline(acc_base, r_base, s_base, key);
    for (int i = 0; i < numFuncs; i++) {
        std::memset(acc_test, 0xFF, sizeof(acc_test));
        std::memset(r_test, 0xFF, sizeof(r_test));
        std::memset(s_test, 0xFF, sizeof(s_test));

        poly1305_init_func f = userFuncs[i];
        f(acc_test, r_test, s_test, key);

        bool acc_ok = (std::memcmp(acc_base, acc_test, LIMBS_1305 * sizeof(uint32_t)) == 0);
        bool r_ok   = (std::memcmp(r_base, r_test, LIMBS_1305 * sizeof(uint32_t)) == 0);
        bool s_ok   = (std::memcmp(s_base, s_test, 16) == 0);
        
        bool isCorrect = acc_ok && r_ok && s_ok;
        print_correctness(isCorrect, funcNames[i]);  
    }

    std::function<void(poly1305_init_func)> runner = [&](poly1305_init_func f) {
        f(acc_test, r_test, s_test, key);
    };

    double base_cycles    = perf_test(poly1305_init_baseline, runner);
    std::cout << "\nPerformance\n\n";
    std::cout << "base: " << base_cycles << " cycles\n";

    std::string bestFunc;
    double bestCycles = 1 << 30;
    double cycles;
    for (int i = 0; i < numFuncs; i++) {
        cycles = perf_test(userFuncs[i], runner);
        double speedup_base = base_cycles / cycles;
        print_benchmark(funcNames[i], cycles, speedup_base);

        if (cycles < bestCycles){
            bestFunc = funcNames[i];
        }
    }

    std::cout << "Best implementation: " <<  bestFunc << "\n";

    return 0;
}