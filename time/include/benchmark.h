#pragma once
#include <list>
#include <vector>
#include <string>
#include <random>
#include <iostream>
#include <functional>
#include "tsc_x86.h"

#define CYCLES_REQUIRED 1e8
#define REP 50
#define EPS (1e-3)
        
/*
* Returns the number of cycles required per iteration of the given function.
* It assumes that the measured function is correct.
*/
template<typename F>
double perf_test(F f, std::function<void(F)> runner) {
    double  cycles = 0.;
    long    num_runs = 100;
    double  multiplier = 1;
    myInt64 start, end;

    // Warm-up phase: we determine a number of executions that allows
    // the code to be executed for at least CYCLES_REQUIRED cycles.
    // This helps excluding timing overhead when measuring small runtimes.
    do {
        num_runs = num_runs * multiplier;
        start = start_tsc();
        for (long i = 0; i < num_runs; i++){
            runner(f);
        }
        end = stop_tsc(start);

        cycles = (double)end;
        multiplier = (CYCLES_REQUIRED) / (cycles);
        
    } while (multiplier > 2);

    // Actual performance measurements repeated REP times.
    // We simply store all results and compute medians during post-processing.
    double total_cycles = 0.0;
    for (int j = 0; j < REP; j++) {
        start = start_tsc();
        for (long i = 0; i < num_runs; i++){
            runner(f);
        } 
        end = stop_tsc(start);

        cycles = ((double)end) / num_runs;
        total_cycles += cycles;
    }
    return total_cycles / REP;
}   