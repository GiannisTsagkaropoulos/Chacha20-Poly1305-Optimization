# FAQ

# 1. How to time chacha_block function

1. Go into `time` directory
2. Run `make chacha_block`

# 2. How to register new function-optimization for chacha_block

1. Go into `time/chacha/chacha_block.cpp` and write an optimized implementation of chacha_block function
2. Declare this function in `time/chacha/chacha.h`
3. Go into `time/chacha/main_block.cpp` and register the function in  `register_functions()` using 
`add_function(&function_name, "function_name");`

# 3. How to time chacha_encrypt function for many plaintext lengths

1. Go into directory time. 
2. The benchmark runner for chacha is run_chacha_benchmarks.py. In that file, the variable  `SIZES` controls the range of plaintext lengths on which the implemented versions of chacha_encrypt will be tested. 
3. Run the run_chacha_benchmarks.py with `python3 run_chacha_benchmarks.py`. The runtime of every function along for the given plaintext length will be on `plots/chacha_encrypt.csv`


# 4. How to time chacha_encrypt function for single plaintext length

1. Go into `time/chacha/main_encrypt_solo.cpp` and change the `uint64_t PTXT_LEN = 1024;` to the desired length (should be multiple of 8)
2. Go into `time` directory
2. Run `make chacha_encrypt_solo` to get verbose performance information for the registered chacha_encrypt functions