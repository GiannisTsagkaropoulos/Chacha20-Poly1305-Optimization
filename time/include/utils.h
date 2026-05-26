#pragma once
#include <iostream>
#include <random>

#define ANSI_COLOR_RED   "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"

template<typename T>
void rands(T* m, size_t n)
{
    std::mt19937_64 gen{std::random_device{}()};
    
    for (size_t i = 0; i < n; ++i)
        m[i] = static_cast<T>(gen());
}


inline void print_correctness(bool isCorrect, std::string funcName) {   
 std::cout << "[" << (
            isCorrect ? ANSI_COLOR_GREEN "PASS" ANSI_COLOR_RESET : 
                        ANSI_COLOR_RED "FAIL" ANSI_COLOR_RESET
                ) << "] " << funcName << "\n";
}

inline void print_benchmark(std::string funcName, double cycles, double speedup_base) {
    std::string base_color = speedup_base > 1.0 ? ANSI_COLOR_GREEN : ANSI_COLOR_RED;

    std::cout << std::endl << funcName << ": " << cycles << " cycles (speedup: " 
    << base_color << speedup_base << ANSI_COLOR_RESET << "x)\n" << std::endl;
}

inline void print_benchmark(std::string funcName, double cycles, double speedup_base, double speedup_openssl) {
    std::string base_color = speedup_base > 1.0 ? ANSI_COLOR_GREEN : ANSI_COLOR_RED;
    std::string openssl_color = speedup_openssl > 1.0 ? ANSI_COLOR_GREEN : ANSI_COLOR_RED;

    std::cout << std::endl << funcName << ": " << cycles << " cycles\n"
       
        << base_color << speedup_base << ANSI_COLOR_RESET << "x speedup(base)\n"
        << openssl_color << speedup_openssl << ANSI_COLOR_RESET << "x speedup(openssl)\n" << std::endl;
}