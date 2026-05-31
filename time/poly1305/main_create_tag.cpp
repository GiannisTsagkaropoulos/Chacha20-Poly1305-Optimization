#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
#include <iomanip>
#include "benchmark.h"
#include "utils.h"
#include "poly1305_tag_opt.h"

#define CTXT_LEN 5000

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
void add_function(poly1305_create_tag_func f, std::string name);

static std::vector<poly1305_create_tag_func> userFuncs;
static std::vector<std::string>        funcNames;
int numFuncs = 0;

void add_function(poly1305_create_tag_func f, std::string name) {
    userFuncs.push_back(f);
    funcNames.push_back(name);
    numFuncs++;
}

void register_functions() {
    add_function(&not_inlined_parallel_Horner_create_tag, "not_inlined_parallel_Horner_create_tag");
    add_function(&not_inlined_create_tag, "not_inlined_create_tag");
    add_function(&memory_vect_inlined_carry_delay_parallel_Horner, "memory_vect_inlined_carry_delay_parallel_Horner");
    add_function(&carry_delay, "carry_delay");
    add_function(&inlined_carry_delay_parallel_Horner, "inlined_carry_delay_parallel_Horner");
    add_function(&inlined_parallel_Horner_create_tag, "inlined_parallel_Horner_create_tag");
}

int main() {
    register_functions();

    if (numFuncs == 0){
        std::cout << "\nNo functions registered - nothing for driver to do" << std::endl;
        return 0;
    }
    std::cout << "Starting Poly1305 Create Tag Benchmark (" << numFuncs << " functions registered)\n" << std::endl;

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

    poly1305_init(acc_base, r_base, s_base, key);
    poly1305_init(acc_test, r_test, s_test, key);

    std::cout << "Correctness\n\n";
    
    std::memset(acc_base, 0, sizeof(acc_base));
    unsigned char* ground_truth_ptr = create_tag(acc_base, r_base, s_base, data, CTXT_LEN);
    
    unsigned char stable_tag_base[16];
    std::memcpy(stable_tag_base, ground_truth_ptr, 16);
    
    std::cout << "Expected Ground Truth Base Tag: ";
    print_tag_standard(stable_tag_base);
    std::cout << "------------------------------------\n";


    for (int i = 0; i < numFuncs; i++) {
        poly1305_create_tag_func f = userFuncs[i];
        
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

    std::function<void(poly1305_create_tag_func)> runner = [&](poly1305_create_tag_func f) {
        std::memset(acc_test, 0, sizeof(acc_test));
        f(acc_test, r_test, s_test, data, CTXT_LEN);
    };

    std::cout << "\nPerformance\n\n";

    double base_cycles = perf_test(create_tag, runner);
    std::cout << "base: " << base_cycles << " cycles\n";

    double ossl_cycles = perf_test(poly1305_create_tag_openssl, runner);
    std::cout << "OpenSSL: " << ossl_cycles << " cycles\n";
    

    std::string bestFunc;
    double bestCycles = 1 << 30;
    double cycles;
    
    for (int i = 0; i < numFuncs; i++) {
        cycles = perf_test(userFuncs[i], runner);
        double speedup_base = base_cycles / cycles;
        double speedup_ossl = ossl_cycles/cycles;
        print_benchmark(funcNames[i], cycles, speedup_base, speedup_ossl);

        if (cycles < bestCycles){
            bestCycles = cycles;
            bestFunc = funcNames[i];
        }
    }

    std::cout << "Best implementation: " << bestFunc << "\n";

    free(data);
    return 0;
}
