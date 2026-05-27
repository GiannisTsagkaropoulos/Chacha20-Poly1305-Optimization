# FAQ

# 1. How to time poly2133_init, chacha_block, chacha-encrypt functions?

1. Run `make bench-{chacha-block,poly2133-init,chacha-encrypt}`. More details can be found on `Makefile` located on root.


# 2. How to change range of plaintext lengths that chacha_encrypt is benchmarked for?

1. Go into `time/chacha/run_chacha_benchmarks.py`
2. Change the line `SIZES = [1 << i for i in range(8,11)]` and save file
3. Run `make clean`
4. Run `make bench-chacha-encrypt`


# 3. How to register new optimization for a specific function (e.g. chacha_encrypt)?

1. Go into the file for that specific function in the `optimizations/` folder (e.g. `optimizations/chacha-encrypt-optimizations.c`)
2. Create the new optimized function and documentation on what was optimized for that function
3. Add the newly created function's signature to the header file for that specific function (e.g. `optimizations/chacha_opts.h`)
4. Go into the `time/` directory, navigate to the function's more specific directory (e.g. `optimizations/chacha`)
5. Find the benchmark coordinator for that function (e.g. `optimizations/chacha/main_encrypt.cpp`)
6. Register the function you created following the way its done for other functions.