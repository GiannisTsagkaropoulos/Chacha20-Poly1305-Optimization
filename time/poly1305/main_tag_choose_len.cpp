#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <functional>
#include <fstream>
#include "benchmark.h"
#include "utils.h"
#include "poly1305_tag_opt.h"

void register_functions();
void add_function(poly1305_create_tag_func f, std::string name, int ops_per_block);

static std::vector<poly1305_create_tag_func> userFuncs;
static std::vector<std::string>        funcNames;
static std::vector<int>                opsPerBlock;
int numFuncs = 0;

void add_function(poly1305_create_tag_func f, std::string name, int ops_per_block) {
    userFuncs.push_back(f);
    funcNames.push_back(name);
    opsPerBlock.push_back(ops_per_block);
    numFuncs++;
}

void register_functions() {
    add_function(&create_tag, "create_tag", 146);
    add_function(&inlined_create_tag, "inlined_create_tag", 146);
    add_function(&not_inlined_parallel_Horner_create_tag, "not_inlined_parallel_Horner_create_tag", 146);
    add_function(&inlined_parallel_Horner_create_tag, "inlined_parallel_Horner_create_tag", 146);
    add_function(&carry_delay, "carry_delay", 146);
    add_function(&inlined_carry_delay_parallel_Horner, "inlined_carry_delay_parallel_Horner", 146);
    add_function(&memory_vect_inlined_carry_delay_parallel_Horner, "vect_inlined_carry_delay_parallel_Horner", 146);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <ctxt_len | --header>\n";
        return 1;
    }
    register_functions();

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
        std::cerr << "ptxt_len must be a non-zero multiple of 8\n";
        return 1;
    }

    if (numFuncs == 0){
        std::cout << std::endl;
        std::cout << "No functions registered - nothing for driver to do" << std::endl;
        std::cout << "Register functions by calling register_func(f, name, ops_per_block)" << std::endl;
        std::cout << "in register_funcs()" << std::endl;

        return 0;
    }

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
    

    std::memset(acc_base, 0, sizeof(acc_base));

    unsigned char* ground_truth_ptr = create_tag(acc_base, r_base, s_base, data, CTXT_LEN);
    

    unsigned char stable_tag_base[16];
    std::memcpy(stable_tag_base, ground_truth_ptr, 16);


    std::function<void(poly1305_create_tag_func)> runner = [&](poly1305_create_tag_func f) {
        std::memset(acc_test, 0, sizeof(acc_test));
        f(acc_test, r_test, s_test, data, CTXT_LEN);
    };


    for (int i = 0; i < numFuncs; i++) {

        std::memset(acc_test, 0, sizeof(acc_test));
        
        poly1305_create_tag_func f = userFuncs[i];
        unsigned char* current_tag_ptr = f(acc_test, r_test, s_test, data, CTXT_LEN);

        unsigned char stable_tag_test[16];
        std::memcpy(stable_tag_test, current_tag_ptr, 16);
        

        bool isWrong = (std::memcmp(stable_tag_test, stable_tag_base, 16) != 0);
        if (isWrong) {
            std::cerr << "CORRECTNESS FAIL: " << funcNames[i] << "\n";
        }
    }


    std::cout << CTXT_LEN;
    for (int i = 0; i < numFuncs; i++) {
        std::cout << "," << perf_test(userFuncs[i], runner);
    }
    std::cout << "\n";

    // Write ops to CSV
    std::ofstream opsFile("plots/poly1305_ops.csv");
    opsFile << "function_name,ops_per_block\n";
    for (int i = 0; i < numFuncs; i++) {
        opsFile << funcNames[i] << "," << opsPerBlock[i] << "\n";
    }
    opsFile.close();

    free(data);
    return 0;
}