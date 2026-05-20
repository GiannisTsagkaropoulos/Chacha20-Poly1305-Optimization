# FAQ

# 1. How to time chacha_block function

1. Go into `time` directory
2. Run make `chacha_block`

# 2. How to register new function-optimization for chacha_block

1. Go into `time/chacha/chacha_block.cpp` and write an optimized implementation of chacha_block function
2. Declare this function in `time/chacha/chacha.h`
3. Go into `time/chacha/main_block.cpp` and register the function in  `register_functions()` using 
`add_function(&function_name, "function_name");`