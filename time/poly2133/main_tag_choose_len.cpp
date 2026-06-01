#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
#include <fstream>
#include "benchmark.h"
#include "utils.h"
#include "poly2133_opt.h"


void register_functions();
void add_function(poly2133_create_tag_func f, std::string name, int ops_per_block);


static std::vector<poly2133_create_tag_func> userFuncs;
static std::vector<std::string>        funcNames;
static std::vector<int>                opsPerBlock;
int numFuncs = 0;

void add_function(poly2133_create_tag_func f, std::string name, int ops_per_block) {
    userFuncs.push_back(f);
    funcNames.push_back(name);
    opsPerBlock.push_back(ops_per_block);
    numFuncs++;
}

void register_functions() {
    add_function(&poly2133_create_tag_baseline, "poly2133_create_tag_baseline", 1057);
    add_function(&poly2133_create_tag_inlined, "poly2133_create_tag_inlined", 1057);
    add_function(&poly2133_create_tag_unrolled, "poly2133_create_tag_unrolled", 950);
    add_function(&poly2133_create_tag_2level_basic, "poly2133_create_tag_2level_basic", 1226);
    add_function(&poly2133_create_tag_2level_inl_unr, "poly2133_create_tag_2level_inl_unr", 1043);
    add_function(&poly2133_create_tag_delcarry, "poly2133_create_tag_delcarry", 496);
    add_function(&poly2133_create_tag_precomp, "poly2133_create_tag_precomp", 398);
    add_function(&poly2133_create_tag_remif, "poly2133_create_tag_remif", 247);
    add_function(&poly2133_create_tag_scalrep, "poly2133_create_tag_scalrep", 722);
    add_function(&poly2133_create_tag_vec, "poly2133_create_tag_vec", 270);
    add_function(&poly2133_create_tag_vec_8b, "poly2133_create_tag_vec_8b", 253);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <ctxt_len | --header>\n";
        return 1;
    }
    register_functions();

    // For benchmark runner to create the header.
    if (std::string(argv[1]) == "--header") {
        std::cout << "ctxt_len";

        for (const auto& funcName : funcNames){
            std::cout << "," << funcName;
        }
        std::cout << "\n";
        return 0;
    }

    uint64_t CTXT_LEN = std::strtoull(argv[1], nullptr, 10);
    if (CTXT_LEN == 0 || CTXT_LEN % 8 != 0) {
        std::cerr << "ctxt_len must be a non-zero multiple of 8\n";
        return 1;
    }

    if (numFuncs == 0){
        std::cout << std::endl;
        std::cout << "No functions registered - nothing for driver to do" << std::endl;
        std::cout << "Register functions by calling register_func(f, name, ops_per_block)" << std::endl;
        std::cout << "in register_funcs()" << std::endl;

        return 0;
    }


    alignas(32) uint32_t acc_base[LIMBS_2133];
    alignas(32) uint32_t r_base [LIMBS_2133];
    alignas(32) uint32_t s_base [LIMBS_2133];
    alignas(32) uint32_t r_test [LIMBS_2133];
    alignas(32) uint32_t s_test [LIMBS_2133];
    alignas(32) uint8_t key[KEY_SIZE_2133];

    uint8_t* data        = (uint8_t*) malloc(CTXT_LEN);
    
    alignas(32) uint32_t acc_test[LIMBS_2133];
    

    rands(data, CTXT_LEN);
    rands(key, KEY_SIZE_2133);

    poly2133_init(acc_base, r_base, s_base, key);
    poly2133_init(acc_test, r_test, s_test, key);

    std::memset(acc_base, 0, sizeof(acc_base));

    unsigned char* ground_truth_ptr = poly2133_create_tag_baseline(acc_base, r_base, s_base, data, CTXT_LEN);

    unsigned char stable_tag_base[TAG_SIZE_2133];
    std::memcpy(stable_tag_base, ground_truth_ptr, TAG_SIZE_2133);

    std::function<void(poly2133_create_tag_func)> runner = [&](poly2133_create_tag_func f) {
        std::memset(acc_test, 0, sizeof(acc_test));
        f(acc_test, r_test, s_test, data, CTXT_LEN);
    };

    for (int i = 0; i < numFuncs; i++) {
        std::memset(acc_test, 0, sizeof(acc_test));
        poly2133_create_tag_func f = userFuncs[i];
        unsigned char* current_tag_ptr = f(acc_test, r_test, s_test, data, CTXT_LEN);

        unsigned char stable_tag_test[TAG_SIZE_2133];
        std::memcpy(stable_tag_test, current_tag_ptr, TAG_SIZE_2133);
        
        bool isWrong = (std::memcmp(stable_tag_test, stable_tag_base, TAG_SIZE_2133) != 0);
        if (isWrong) 
            std::cerr << "CORRECTNESS FAIL: " << funcNames[i] << "\n";
    }


    //double base_cycles    = perf_test(create_tag, runner);

    std::cout << CTXT_LEN;
    for (int i = 0; i < numFuncs; i++)
        std::cout << "," << perf_test(userFuncs[i], runner);
    std::cout <<  "\n";
    
    // Write ops to CSV
    std::ofstream opsFile("plots/poly2133_ops.csv");
    opsFile << "function_name,ops_per_block\n";
    for (int i = 0; i < numFuncs; i++) {
        opsFile << funcNames[i] << "," << opsPerBlock[i] << "\n";
    }
    opsFile.close();

    free(data);
    return 0;
}