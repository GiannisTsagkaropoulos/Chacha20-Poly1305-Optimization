#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
#include "benchmark.h"
#include "utils.h"
#include "chacha.h"

void register_functions();
void add_function(chacha_block_func f, std::string name);

static std::vector<chacha_block_func> userFuncs;
static std::vector<std::string>       funcNames;
int numFuncs = 0;

void add_function(chacha_block_func f, std::string name) {
    userFuncs.push_back(f);
    funcNames.push_back(name);
    numFuncs++;
}

void register_functions() {
    add_function(&chacha_block_2, "chacha_block_2");
    add_function(&chacha_block_best, "chacha_block_best");
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
    std::cout << "Starting ChaCha Block Benchmark (" << numFuncs << " functions registered)\n" << std::endl;

    alignas(32) uint32_t state[STATE_SIZE_W];
    alignas(32) uint8_t  ks_base[STATE_SIZE_B];
    alignas(32) uint8_t  ks_test[STATE_SIZE_B];
    int rounds = 20;
    rands(state, STATE_SIZE_W);

    std::function<void(chacha_block_func)> runner = [&](chacha_block_func f) {
        f(ks_test, state, rounds);
    };

    std::cout << "Correctness\n\n";
    chacha_block_base(ks_base, state, rounds);
    for (int i = 0; i < numFuncs; i++) {
        chacha_block_func f = userFuncs[i];
        f(ks_test, state, rounds);

        bool isCorrect = (std::memcmp(ks_test, ks_base, STATE_SIZE_B) == 0);
        print_correctness(isCorrect, funcNames[i]);  
    }

    double base_cycles    = perf_test(chacha_block_base, runner);
    double openssl_cycles = perf_test(chacha_block_base, runner);
    std::cout << "Performance\n\n";
    std::cout << "base   : " << base_cycles    << " cycles\n";
    std::cout << "openssl: " << openssl_cycles << " cycles\n\n";

    for (int i = 0; i < numFuncs; i++) {
        double cycles          = perf_test(userFuncs[i], runner);
        double speedup_base    = base_cycles    / cycles;
        double speedup_openssl = openssl_cycles / cycles;

        print_benchmark(funcNames[i], cycles, speedup_base, speedup_openssl);
    }

    return 0;
}