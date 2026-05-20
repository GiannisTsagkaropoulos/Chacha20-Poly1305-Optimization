#pragma once
#include <random>

template<typename T>
void rands(T* m, size_t n)
{
    std::mt19937_64 gen{std::random_device{}()};
    
    for (size_t i = 0; i < n; ++i)
        m[i] = static_cast<T>(gen());
}
