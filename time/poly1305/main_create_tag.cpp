#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
#include <iomanip>
#include <fstream>
#include "benchmark.h"
#include "utils.h"
#include "poly1305_tag_opt.h"
#include "poly1305_init_opts.h"

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
    add_function(&create_tag1305_baseline, "create_tag1305_baseline");
    add_function(&inlined_create_tag, "inlined_create_tag");
    add_function(&inlined_parallel_Horner_create_tag, "inlined_parallel_Horner_create_tag");
    add_function(&inlined_carry_delay_parallel_Horner, "inlined_carry_delay_parallel_Horner");
    add_function(&memory_vect_inlined_carry_delay_parallel_Horner, "memory_vect_inlined_carry_delay_parallel_Horner");
    add_function(&poly1305_create_tag_openssl, "poly1305_create_tag_openssl");
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

    uint64_t ptxt_len = std::strtoull(argv[1], nullptr, 10);
    if (ptxt_len == 0 || ptxt_len % 8 != 0) {
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


    alignas(32) uint32_t acc_base[LIMBS_1305];
    alignas(32) uint32_t r_base [LIMBS_1305];
    alignas(32) uint32_t s_base [LIMBS_1305];
    alignas(32) uint32_t r_test [LIMBS_1305];
    alignas(32) uint32_t s_test [LIMBS_1305];
    alignas(32) uint8_t key[KEY_SIZE_1305];

    size_t alloc_size    = (ptxt_len + 31) & ~31;
    uint8_t* data        = (uint8_t*) malloc(ptxt_len);

    
    alignas(32) uint32_t acc_test[LIMBS_1305];
    

    rands(data, ptxt_len);
    rands(key, KEY_SIZE_1305);

    poly1305_init_baseline(acc_base, r_base, s_base, key);
    poly1305_init_baseline(acc_test, r_test, s_test, key);


    
    std::memset(acc_base, 0, sizeof(acc_base));
    unsigned char* ground_truth_ptr = create_tag1305_baseline(acc_base, r_base, s_base, data, ptxt_len);
    unsigned char stable_tag_base[16];
    std::memcpy(stable_tag_base, ground_truth_ptr, 16);

    for (int i = 0; i < numFuncs; i++) {
        std::memset(acc_test, 0, sizeof(acc_test));
        
        poly1305_create_tag_func f = userFuncs[i];
        unsigned char* current_tag_ptr = f(acc_test, r_test, s_test, data, ptxt_len);

        unsigned char stable_tag_test[16];
        std::memcpy(stable_tag_test, current_tag_ptr, 16);
        

        bool isWrong = (std::memcmp(stable_tag_test, stable_tag_base, 16) != 0);
        if (isWrong)
            std::cerr << "CORRECTNESS FAIL: " << funcNames[i] << "\n";
    }

    std::function<void(poly1305_create_tag_func)> runner = [&](poly1305_create_tag_func f) {
        f(acc_test, r_test, s_test, data, ptxt_len);
    };

    std::cout << ptxt_len;
    for (int i = 0; i < numFuncs; i++)
        std::cout << "," << perf_test(userFuncs[i], runner);
    std::cout <<  "\n";

    free(data);
    return 0;
}
