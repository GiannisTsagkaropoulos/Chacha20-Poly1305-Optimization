#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib> 
#include <functional>
#include <iomanip>
#include "benchmark.h"
#include "utils.h"
#include "poly2133_opt.h"

void register_functions();
void add_function(poly2133_create_tag_func f, std::string name);

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
    add_function(&poly2133_create_tag_2level_inl_unr, "poly2133_create_tag_2level_inl_unr");
    add_function(&poly2133_create_tag_delcarry, "poly2133_create_tag_delcarry");
    add_function(&poly2133_create_tag_precomp, "poly2133_create_tag_precomp");
    add_function(&poly2133_create_tag_scalrep, "poly2133_create_tag_scalrep");
    add_function(&poly2133_create_tag_vec, "poly2133_create_tag_vec");
    add_function(&poly2133_create_tag_vec_8b, "poly2133_create_tag_vec_8b");
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
    size_t alloc_size = (ptxt_len + 31) & ~31;

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

    alignas(32) uint8_t  key[KEY_SIZE_2133];
    alignas(32) uint32_t r [LIMBS_2133];
    alignas(32) uint32_t s [LIMBS_2133];
    alignas(32) uint32_t acc_base[LIMBS_2133];
    alignas(32) uint32_t acc_test[LIMBS_2133];

    uint8_t* data = (uint8_t*) malloc(alloc_size);

    rands(data, alloc_size);
    rands(key, KEY_SIZE_2133);
    poly2133_init(acc_base, r, s, key);
    std::memset(acc_base, 0, sizeof(acc_base));

    unsigned char* ground_truth_ptr = poly2133_create_tag_baseline(acc_base, r, s, data, ptxt_len);
    
    for (int i = 0; i < numFuncs; i++) {
        std::memset(acc_test, 0, sizeof(acc_test));
        poly2133_create_tag_func f = userFuncs[i];
        
        unsigned char* tag_test_ptr = f(acc_test, r, s, data, ptxt_len);
        bool isWrong = (std::memcmp(tag_test_ptr, ground_truth_ptr, TAG_SIZE_2133) != 0);

        if (isWrong)
            std::cerr << "CORRECTNESS FAIL: " << funcNames[i] << "\n";
    }


    std::function<void(poly2133_create_tag_func)> runner = [&](poly2133_create_tag_func f) {
        f(acc_test, r, s, data, ptxt_len);
    };

    std::cout << ptxt_len;
    for (int i = 0; i < numFuncs; i++)
        std::cout << "," << perf_test(userFuncs[i], runner);
    std::cout <<  "\n";

    free(data);
    return 0;
}
