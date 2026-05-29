#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
#include "benchmark.h"
#include "utils.h"
#include "poly1305_opt.h"

#define CTXT_LEN 200000



void register_functions();
void add_function(poly1305_create_tag_func f, std::string name);


//void add_function(poly1305_create_tag f, std::string name);

static std::vector<poly1305_create_tag_func> userFuncs;
static std::vector<std::string>        funcNames;
int numFuncs = 0;

void add_function(poly1305_create_tag_func f, std::string name) {
    userFuncs.push_back(f);
    funcNames.push_back(name);
    numFuncs++;
}

void register_functions() {
    add_function(&inlined_create_tag, "inlined_create_tag");
    add_function(&not_inlined_parallel_Horner_create_tag, "not_inlined_parallel_Horner_create_tag");
    add_function(&inlined_parallel_Horner_create_tag, "inlined_parallel_Horner_create_tag");
    add_function(&carry_delay, "carry_delay");
    add_function(&inlined_carry_delay_parallel_Horner, "inlined_carry_delay_parallel_Horner");
    add_function(&memory_vect_inlined_carry_delay_parallel_Horner, "vect_inlined_carry_delay_parallel_Horner");
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
    std::cout << "Starting Poly1305 Create Tag Benchmark" << numFuncs << " functions registered)\n" << std::endl;

    alignas(32) uint32_t acc_base[NUM_LIMBS];
    alignas(32) uint32_t r [NUM_LIMBS];
    alignas(32) uint32_t s [NUM_LIMBS];

    size_t alloc_size    = (CTXT_LEN + 31) & ~31;
    uint8_t* data        = (uint8_t*) malloc(CTXT_LEN);

    
    alignas(32) uint32_t acc_test[NUM_LIMBS];
    

    rands(r, NUM_LIMBS);
    rands(s, NUM_LIMBS);
    rands(data, CTXT_LEN);

        
    std::cout << "Correctness\n\n";
    unsigned char* tag_base = create_tag(acc_base, r, s, data, CTXT_LEN);
    for (int i = 0; i < numFuncs; i++) {
        std::memset(acc_test, 0xFF, sizeof(acc_test));
        std::memset(r, 0xFF, sizeof(r));
        std::memset(s, 0xFF, sizeof(s));

        poly1305_create_tag_func f = userFuncs[i];
        unsigned char* tag_test = f(acc_test, r, s, data, CTXT_LEN);
        
        bool isCorrect = (std::memcmp(tag_test, tag_base, TAG_SIZE) != 0);

        print_correctness(isCorrect, funcNames[i]);  
    }


    std::function<void(poly1305_create_tag_func)> runner = [&](poly1305_create_tag_func f) {
        f(acc_test, r, s, data, CTXT_LEN);
    };

    double base_cycles    = perf_test(create_tag, runner);
    std::cout << "\nPerformance\n\n";
    std::cout << "base: " << base_cycles << " cycles\n";

    std::string bestFunc;
    double bestCycles = 1 << 30;
    double cycles;
    for (int i = 0; i < numFuncs; i++) {
        cycles = perf_test(userFuncs[i], runner);
        double speedup_base = base_cycles / cycles;
        print_benchmark(funcNames[i], cycles, speedup_base, 0);

        if (cycles < bestCycles){
            bestFunc = funcNames[i];
        }
    }

    std::cout << "Best implementation: " <<  bestFunc << "\n";

    free(data);
    return 0;
}
