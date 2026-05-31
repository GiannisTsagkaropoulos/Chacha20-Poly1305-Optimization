#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
#include <iomanip>
#include "benchmark.h"
#include "utils.h"
#include "../../include/poly2133_opt.h"

#define CTXT_LEN 50000

void print_tag_standard(const unsigned char* tag) {
    if (tag == nullptr) return;

    std::ios_base::fmtflags f(std::cout.flags());
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex 
                  << std::setw(2) 
                  << std::setfill('0') 
                  << static_cast<int>(tag[i]);
    }
    std::cout << "\n";
    std::cout.flags(f);
}

void register_functions();
void add_function(poly2133_create_tag_func f, std::string name);


//void add_function(poly1305_create_tag f, std::string name);

static std::vector<poly2133_create_tag_func> userFuncs;
static std::vector<std::string>        funcNames;
int numFuncs = 0;

void add_function(poly2133_create_tag_func f, std::string name) {
    userFuncs.push_back(f);
    funcNames.push_back(name);
    numFuncs++;
}

void register_functions() {
    add_function(&poly2133_create_tag_baseline, "poly2133_create_tag_baseline");
    add_function(&poly2133_create_tag_inlined, "poly2133_create_tag_inlined");
    add_function(&poly2133_create_tag_unrolled, "poly2133_create_tag_unrolled");
    add_function(&poly2133_create_tag_2level_basic, "poly2133_create_tag_2level_basic");
    add_function(&poly2133_create_tag_2level_inl_unr, "poly2133_create_tag_2level_inl_unr");
    add_function(&poly2133_create_tag_delcarry, "poly2133_create_tag_delcarry");
    add_function(&poly2133_create_tag_precomp, "poly2133_create_tag_precomp");
    add_function(&poly2133_create_tag_remif, "poly2133_create_tag_remif");
    add_function(&poly2133_create_tag_scalrep, "poly2133_create_tag_scalrep");
    add_function(&poly2133_create_tag_vec, "poly2133_create_tag_vec");
    add_function(&poly2133_create_tag_vec_8b, "poly2133_create_tag_vec_8b");
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
    std::cout << "Starting Poly2133 Create Tag Benchmark" << numFuncs << " functions registered)\n" << std::endl;

    alignas(32) uint32_t acc_base[NUM_LIMBS];
    alignas(32) uint32_t r_base [NUM_LIMBS];
    alignas(32) uint32_t s_base [NUM_LIMBS];
    alignas(32) uint32_t r_test [NUM_LIMBS];
    alignas(32) uint32_t s_test [NUM_LIMBS];
    alignas(32) uint8_t key[KEY_SIZE];

    size_t alloc_size    = (CTXT_LEN + 31) & ~31;
    uint8_t* data        = (uint8_t*) malloc(CTXT_LEN);

    
    alignas(32) uint32_t acc_test[NUM_LIMBS];
    

    rands(data, CTXT_LEN);
    rands(key, KEY_SIZE);

    poly2133_init(acc_base, r_base, s_base, key);
    poly2133_init(acc_test, r_test, s_test, key);

        

    std::cout << "Correctness\n\n";
    
    std::memset(acc_base, 0, sizeof(acc_base));
    unsigned char* ground_truth_ptr = poly2133_create_tag_baseline(acc_base, r_base, s_base, data, CTXT_LEN);
    
    unsigned char stable_tag_base[16];
    std::memcpy(stable_tag_base, ground_truth_ptr, 16);
    
    std::cout << "Expected Ground Truth Base Tag: ";
    print_tag_standard(stable_tag_base);
    std::cout << "------------------------------------\n";


    for (int i = 0; i < numFuncs; i++) {
        poly2133_create_tag_func f = userFuncs[i];
        
        std::memset(acc_test, 0, sizeof(acc_test));

        unsigned char* tag_test_ptr = f(acc_test, r_test, s_test, data, CTXT_LEN);
        
        unsigned char stable_tag_test[16];
        std::memcpy(stable_tag_test, tag_test_ptr, 16);

        std::cout << funcNames[i] << " Output: ";
        print_tag_standard(stable_tag_test);
        

        bool isWrong = (std::memcmp(stable_tag_test, stable_tag_base, 16) != 0);
        print_correctness(not isWrong, funcNames[i]);  
        std::cout << "\n"; 
    }


    std::function<void(poly2133_create_tag_func)> runner = [&](poly2133_create_tag_func f) {
        f(acc_test, r_test, s_test, data, CTXT_LEN);
    };

    double base_cycles    = perf_test(poly2133_create_tag_baseline, runner);
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