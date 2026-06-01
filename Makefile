# ==============================================================================
# Global Configuration & Toolchain
# ==============================================================================
CXX          = g++
CC           = gcc

INCLUDES     = -I. -Itime/include
LDLIBS       = -lcrypto
COMMON_FLAGS = -O3 -fno-tree-vectorize -march=native -Wall -Wextra
CFLAGS 		 = -Wall -Wextra -Wpointer-sign -Iinclude -Ioptimizations -mavx2 -msse4.1
BENCHMARK_FLAGS = $(COMMON_FLAGS) -std=c++17 $(INCLUDES)
C_FLAGS         = $(COMMON_FLAGS) $(INCLUDES)

BIN_DIR = bin
$(BIN_DIR):
	mkdir -p $(BIN_DIR)


CHACHA_SRCS = optimizations/chacha20/chacha-block-optimizations.c \
			optimizations/chacha20/chacha-encrypt-optimizations.c \
			optimizations/chacha20-poly1305/chacha20-poly1305.c \

POLY_SRCS = optimizations/poly1305/poly1305-init-optimizations.c \
			optimizations/poly1305/poly1305_tag_opt.c \
			optimizations/poly2133/poly2133-optimizations.c \
            optimizations/poly2133/poly2133-init-optimizations.c 

TEST_SRCS = tests/test_functions.c \
            tests/test_vectors.c \
            tests/test_helpers.c \
            tests/main.c

TEST_RUNNER =  $(BIN_DIR)/test_runner

.PHONY: all test
all: test

OPT_INCLUDES = \
    -Ioptimizations/chacha20 \
    -Ioptimizations/poly1305 \
    -Ioptimizations/poly2133 \
	-Ioptimizations/chacha20-poly1305 \

TEST_INCLUDES = $(INCLUDES) $(OPT_INCLUDES) -Itests/include

$(TEST_RUNNER): $(CHACHA_SRCS) $(TEST_SRCS) $(POLY_SRCS) | $(BIN_DIR)
	$(CC) $(CFLAGS) $(TEST_INCLUDES) -DUNIT_TEST -o $@ $^ $(LDLIBS)

test:  $(TEST_RUNNER)
	./$(TEST_RUNNER)
# ==============================================================================
# Benchmarks
# ==============================================================================


# ======== Poly2133_init ========
EXE_POLY2133_INIT       = $(BIN_DIR)/poly2133_init_benchmark_runner
$(EXE_POLY2133_INIT): optimizations/poly2133/poly2133-init-optimizations.c time/poly2133/main_init.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -Ioptimizations/poly2133 -o $@ $^

.PHONY: bench-poly2133-init
bench-poly2133-init: $(EXE_POLY2133_INIT)
	./$(EXE_POLY2133_INIT)

# ==============================


# ======== Poly2133_create_tag ========
EXE_POLY2133_CREATE_TAG     = $(BIN_DIR)/poly2133_create_tag_benchmark_runner
$(EXE_POLY2133_CREATE_TAG): optimizations/poly2133/poly2133-optimizations.c time/poly2133/main_create_tag.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -Ioptimizations/poly2133 -o $@ $^

.PHONY: bench-poly2133-create-tag
bench-poly2133-create-tag: $(EXE_POLY2133_CREATE_TAG)
	./$(EXE_POLY2133_CREATE_TAG)

# ==============================

# ======== Poly2133_create_tag_choose_len  ========
POLY2133_TAG_FLAGS = -march=native -Wall -Wextra -std=c++17

EXE_POLY2133_TAG_3 = $(BIN_DIR)/poly2133_create_tag_3

$(EXE_POLY2133_TAG_3): optimizations/poly2133/poly2133-optimizations.c time/poly2133/main_tag_choose_len.cpp | $(BIN_DIR)
	$(CXX) -O3 $(ENCRYPT_FLAGS) $(INCLUDES) -Ioptimizations/poly2133 -Ioptimizations/chacha20-poly2133-o -o $@ $^

.PHONY:  bench-poly2133-choose-len
bench-poly2133-create-tag-flag:  $(EXE_POLY2133_TAG_3)

bench-poly2133-choose-len: bench-poly2133-create-tag-flag
	cd time/poly2133 && python3 run_poly2133_benchmarks.py

create-poly2133-plots: 
	cd time/poly2133 && python3 plot_poly2133_benchmarks.py
# ==============================================================================  


# ======== Poly1305_init ========
EXE_POLY1305_INIT       = $(BIN_DIR)/poly1305_init_benchmark_runner
$(EXE_POLY1305_INIT): optimizations/poly1305/poly1305-init-optimizations.c time/poly1305/main_init.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -Ioptimizations/poly1305  -o $@ $^

.PHONY: bench-poly1305-init
bench-poly1305-init: $(EXE_POLY1305_INIT)
	./$(EXE_POLY1305_INIT)

# ==============================


# ======== Poly1305_create_tag ========
EXE_POLY1305_CREATE_TAG     = $(BIN_DIR)/poly1305_create_tag_benchmark_runner
$(EXE_POLY1305_CREATE_TAG): optimizations/poly1305/poly1305_tag_opt.c optimizations/poly1305/poly1305-init-optimizations.c time/poly1305/main_create_tag.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -Ioptimizations/poly1305 -o $@ $^ $(LDLIBS)

.PHONY: bench-poly1305-create-tag
bench-poly1305-create-tag: $(EXE_POLY1305_CREATE_TAG)
	./$(EXE_POLY1305_CREATE_TAG)

# ==============================

# ======== Poly1305_create_tag_choose_len  ========
POLY1305_TAG_FLAGS = -march=native -Wall -Wextra -std=c++17

EXE_POLY1305_TAG_3 = $(BIN_DIR)/poly1305_create_tag_3

$(EXE_POLY1305_TAG_3): optimizations/poly1305/poly1305_tag_opt.c optimizations/poly1305/poly1305-init-optimizations.c time/poly1305/main_tag_choose_len.cpp | $(BIN_DIR)
	$(CXX) -O3 $(ENCRYPT_FLAGS) $(INCLUDES) -Ioptimizations/poly1305 -o $@ $^ $(LDLIBS)

.PHONY: bench-poly1305-create-tag-flag bench-poly1305-choose-len
bench-poly1305-create-tag-flag:  $(EXE_POLY1305_TAG_3)

bench-poly1305-choose-len: bench-poly1305-create-tag-flag
	cd time/poly1305 && python3 run_poly1305_benchmarks.py

create-poly1305-plots: 
	cd time/poly1305 && python3 plot_poly1305_benchmarks.py
# ==============================================================================  



# ======== Poly1305_complete_choose_len  ========
POLY1305_COMPLETE_FLAGS = -march=native -Wall -Wextra -std=c++17

EXE_POLY1305_COMPLETE_3 = $(BIN_DIR)/poly1305_complete_3

$(EXE_POLY1305_COMPLETE_3): optimizations/poly1305/poly1305_complete.c optimizations/poly1305/poly1305-init-optimizations.c time/poly1305/OpenSSL-Complete-Benchmark/main_complete_choose_len.cpp | $(BIN_DIR)
	$(CXX) -O3 $(ENCRYPT_FLAGS) $(INCLUDES) -Ioptimizations/poly1305  -o $@ $^ $(LDLIBS)

.PHONY: bench-poly1305-complete-flag bench-poly1305-complete-choose-len
bench-poly1305-complete-flag:  $(EXE_POLY1305_COMPLETE_3)

bench-poly1305-complete-choose-len: bench-poly1305-complete-flag
	cd time/poly1305/OpenSSL-Complete-Benchmark && python3 run_poly1305_complete_benchmarks.py
# ==============================================================================


# ======== Chacha_block ========
EXE_CHACHA_BLOCK       = $(BIN_DIR)/chacha_block_benchmark_runner
$(EXE_CHACHA_BLOCK): optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_block.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -Ioptimizations/chacha20 -o $@ $^

.PHONY: bench-chacha-block
bench-chacha-block: $(EXE_CHACHA_BLOCK)
	./$(EXE_CHACHA_BLOCK)

# ==============================

# ======== Chacha_encrypt (one plaintext size and verbose) ========
EXE_CHACHA_ENCRYPT_SOLO = $(BIN_DIR)/chacha_encrypt_solo_benchmark_runner
<<<<<<< HEAD
$(EXE_CHACHA_ENCRYPT_SOLO): optimizations/chacha-encrypt-optimizations.c optimizations/chacha-block-optimizations.c time/chacha/op-computation.c time/chacha/main_encrypt_solo.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -o $@ $^ $(LDLIBS)
=======
$(EXE_CHACHA_ENCRYPT_SOLO): optimizations/chacha20/chacha-encrypt-optimizations.c optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_encrypt_solo.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -Ioptimizations/chacha20 -o $@ $^ $(LDLIBS)
>>>>>>> 176c25d (refactor: add folders to optimizations folder for better organization. Rename poly specific stuff so we have no conflicts when using both functionalities from poly1305 and poly2133. Rewrite poly1305 init function correctly (only works on little endian))

.PHONY: bench-chacha-encrypt-solo
bench-chacha-encrypt-solo: $(EXE_CHACHA_ENCRYPT_SOLO)
	./$(EXE_CHACHA_ENCRYPT_SOLO)

# ==============================

# ======== Chacha_encrypt  ========
ENCRYPT_FLAGS = -march=native -Wall -Wextra -std=c++17

EXE_ENCRYPT_0 = $(BIN_DIR)/bench_chacha_encrypt_0
EXE_ENCRYPT_1 = $(BIN_DIR)/bench_chacha_encrypt_1
EXE_ENCRYPT_2 = $(BIN_DIR)/bench_chacha_encrypt_2
EXE_ENCRYPT_3 = $(BIN_DIR)/bench_chacha_encrypt_3
EXE_ENCRYPT_3_NO_VEC = $(BIN_DIR)/bench_chacha_encrypt_3_no_vec


$(EXE_ENCRYPT_0): optimizations/chacha20/chacha-encrypt-optimizations.c optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O0 $(ENCRYPT_FLAGS) $(INCLUDES) -Ioptimizations/chacha20 -o $@ $^ $(LDLIBS)

$(EXE_ENCRYPT_1): optimizations/chacha20/chacha-encrypt-optimizations.c optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O1 $(ENCRYPT_FLAGS) $(INCLUDES) -Ioptimizations/chacha20 -o $@ $^ $(LDLIBS)

$(EXE_ENCRYPT_2): optimizations/chacha20/chacha-encrypt-optimizations.c optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O2 $(ENCRYPT_FLAGS) $(INCLUDES) -Ioptimizations/chacha20 -o $@ $^ $(LDLIBS)

$(EXE_ENCRYPT_3): optimizations/chacha20/chacha-encrypt-optimizations.c optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O3 $(ENCRYPT_FLAGS) $(INCLUDES) -Ioptimizations/chacha20 -o $@ $^ $(LDLIBS)

$(EXE_ENCRYPT_3_NO_VEC): optimizations/chacha20/chacha-encrypt-optimizations.c optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O3 -fno-tree-vectorize $(ENCRYPT_FLAGS) $(INCLUDES) -Ioptimizations/chacha20 -o $@ $^ $(LDLIBS)	

.PHONY: bench-chacha-encrypt-all bench-chacha-encrypt
bench-chacha-encrypt-all: $(EXE_ENCRYPT_0) $(EXE_ENCRYPT_1) $(EXE_ENCRYPT_2) $(EXE_ENCRYPT_3) $(EXE_ENCRYPT_3_NO_VEC)

bench-chacha-encrypt: bench-chacha-encrypt-all
	cd time/chacha && python3 run_chacha_benchmarks.py

create-chacha-plots: 
	cd time/chacha && python3 plot_chacha_benchmarks.py
# ==============================================================================    
 
# ======== Chacha20-Poly1305 Encrypt  ========
ENCRYPT_FLAGS = -march=native -Wall -Wextra -std=c++17

EXE_AEAD_ENCRYPT_0 = $(BIN_DIR)/bench_aead_encrypt2_0
EXE_AEAD_ENCRYPT_1 = $(BIN_DIR)/bench_aead_encrypt2_1
EXE_AEAD_ENCRYPT_2 = $(BIN_DIR)/bench_aead_encrypt2_2
EXE_AEAD_ENCRYPT_3 = $(BIN_DIR)/bench_aead_encrypt2_3
EXE_AEAD_ENCRYPT_3_NO_VEC = $(BIN_DIR)/bench_aead_encrypt2_3_no_vec

CHACHA_POLY1305_SRCS =  optimizations/chacha20-poly1305/chacha20-poly1305.c \
						optimizations/chacha20/chacha-encrypt-optimizations.c \
						optimizations/chacha20/chacha-block-optimizations.c \
						optimizations/poly1305/poly1305_tag_opt.c \
						optimizations/poly1305/poly1305-init-optimizations.c 

AEAD_INCLUDES = $(INCLUDES) -Ioptimizations/chacha20-poly1305 -Ioptimizations/chacha20 -Ioptimizations/poly1305

$(EXE_AEAD_ENCRYPT_0): $(CHACHA_POLY1305_SRCS) time/chacha-poly1305/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O0 $(ENCRYPT_FLAGS) $(AEAD_INCLUDES) -o $@ $^ $(LDLIBS)

$(EXE_AEAD_ENCRYPT_1): $(CHACHA_POLY1305_SRCS) time/chacha-poly1305/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O1 $(ENCRYPT_FLAGS) $(AEAD_INCLUDES) -o $@ $^ $(LDLIBS)

$(EXE_AEAD_ENCRYPT_2): $(CHACHA_POLY1305_SRCS) time/chacha-poly1305/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O2 $(ENCRYPT_FLAGS) $(AEAD_INCLUDES) -o $@ $^ $(LDLIBS)
	
$(EXE_AEAD_ENCRYPT_3): $(CHACHA_POLY1305_SRCS) time/chacha-poly1305/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O3 $(ENCRYPT_FLAGS) $(AEAD_INCLUDES) -o $@ $^ $(LDLIBS)	

$(EXE_AEAD_ENCRYPT_3_NO_VEC): $(CHACHA_POLY1305_SRCS) time/chacha-poly1305/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O3 -fno-tree-vectorize $(ENCRYPT_FLAGS) $(AEAD_INCLUDES) -o $@ $^ $(LDLIBS)	

EXE_AEAD_ENCRYPT_SOLO = $(BIN_DIR)/aead_encrypt_solo_benchmark_runner
$(EXE_AEAD_ENCRYPT_SOLO): $(CHACHA_POLY1305_SRCS) time/chacha-poly1305/main_encrypt_solo.cpp| $(BIN_DIR)
	$(CXX) -O3 $(ENCRYPT_FLAGS) $(AEAD_INCLUDES) -o $@ $^ $(LDLIBS)	

.PHONY: bench-aead-encrypt-all bench-aead-encrypt bench-aead-all bench-aead-encrypt-solo
bench-aead-encrypt-all: $(EXE_AEAD_ENCRYPT_0) $(EXE_AEAD_ENCRYPT_1) $(EXE_AEAD_ENCRYPT_2) $(EXE_AEAD_ENCRYPT_3) $(EXE_AEAD_ENCRYPT_3_NO_VEC)

bench-aead-all: bench-aead-encrypt-all

bench-aead-encrypt-solo: $(EXE_AEAD_ENCRYPT_SOLO)
	./$(EXE_AEAD_ENCRYPT_SOLO)

bench-aead-encrypt: bench-aead-encrypt-all
	cd time/chacha-poly1305 && python3 run_aead_encrypt_benchmarks.py

create-chacha-poly-plots:
	cd time/chacha-poly && python3 plot_chacha_poly_benchmarks.py
# ==============================================================================

# ======== ChaCha20-Poly2133 AEAD (encrypt + decrypt) ========
# whole chacha20-poly2133 benchmark across engine tiers, built at -O0..-O3 like chacha-poly
CHACHA_POLY2133_SRCS = optimizations/chacha20-poly2133/chacha_poly2133_combination.c \
                       optimizations/chacha20/chacha-encrypt-optimizations.c \
                       optimizations/chacha20/chacha-block-optimizations.c \
                       optimizations/poly2133/poly2133-optimizations.c \
                       optimizations/poly2133/poly2133-init-optimizations.c 

CHACHA_POLY1305_INCLUDES = $(INCLUDES) -Iinclude -Ioptimizations/chacha20-poly2133 -Ioptimizations/chacha20 -Ioptimizations/poly2133
CHACHA_POLY2133_FLAGS = -march=native -Wall -Wextra -std=c++17 $(CHACHA_POLY1305_INCLUDES)

EXE_CHACHA_POLY2133_ENCRYPT_0 = $(BIN_DIR)/bench_chacha_poly2133_encrypt_0
EXE_CHACHA_POLY2133_ENCRYPT_1 = $(BIN_DIR)/bench_chacha_poly2133_encrypt_1
EXE_CHACHA_POLY2133_ENCRYPT_2 = $(BIN_DIR)/bench_chacha_poly2133_encrypt_2
EXE_CHACHA_POLY2133_ENCRYPT_3 = $(BIN_DIR)/bench_chacha_poly2133_encrypt_3

EXE_CHACHA_POLY2133_DECRYPT_0 = $(BIN_DIR)/bench_chacha_poly2133_decrypt_0
EXE_CHACHA_POLY2133_DECRYPT_1 = $(BIN_DIR)/bench_chacha_poly2133_decrypt_1
EXE_CHACHA_POLY2133_DECRYPT_2 = $(BIN_DIR)/bench_chacha_poly2133_decrypt_2
EXE_CHACHA_POLY2133_DECRYPT_3 = $(BIN_DIR)/bench_chacha_poly2133_decrypt_3

ENCRYPT_POLY2133_MAIN = time/chacha-poly2133/main_encrypt_chacha_poly2133.cpp
DECRYPT_POLY2133_MAIN = time/chacha-poly2133/main_decrypt_chacha_poly2133.cpp

$(EXE_CHACHA_POLY2133_ENCRYPT_0): $(CHACHA_POLY2133_SRCS) $(ENCRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O0 $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)
$(EXE_CHACHA_POLY2133_ENCRYPT_1): $(CHACHA_POLY2133_SRCS) $(ENCRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O1 $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)
$(EXE_CHACHA_POLY2133_ENCRYPT_2): $(CHACHA_POLY2133_SRCS) $(ENCRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O2 $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)
$(EXE_CHACHA_POLY2133_ENCRYPT_3): $(CHACHA_POLY2133_SRCS) $(ENCRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O3 $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)

$(EXE_CHACHA_POLY2133_DECRYPT_0): $(CHACHA_POLY2133_SRCS) $(DECRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O0 $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)
$(EXE_CHACHA_POLY2133_DECRYPT_1): $(CHACHA_POLY2133_SRCS) $(DECRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O1 $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)
$(EXE_CHACHA_POLY2133_DECRYPT_2): $(CHACHA_POLY2133_SRCS) $(DECRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O2 $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)
$(EXE_CHACHA_POLY2133_DECRYPT_3): $(CHACHA_POLY2133_SRCS) $(DECRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O3 $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)

.PHONY: bench-chacha-poly2133-encrypt-all bench-chacha-poly2133-decrypt-all bench-chacha-poly2133 create-chacha-poly2133-plots
bench-chacha-poly2133-encrypt-all: $(EXE_CHACHA_POLY2133_ENCRYPT_0) $(EXE_CHACHA_POLY2133_ENCRYPT_1) $(EXE_CHACHA_POLY2133_ENCRYPT_2) $(EXE_CHACHA_POLY2133_ENCRYPT_3)
bench-chacha-poly2133-decrypt-all: $(EXE_CHACHA_POLY2133_DECRYPT_0) $(EXE_CHACHA_POLY2133_DECRYPT_1) $(EXE_CHACHA_POLY2133_DECRYPT_2) $(EXE_CHACHA_POLY2133_DECRYPT_3)

bench-chacha-poly2133: bench-chacha-poly2133-encrypt-all bench-chacha-poly2133-decrypt-all
	cd time/chacha-poly2133 && python3 run_chacha_poly2133_benchmarks.py

create-chacha-poly2133-plots:
	cd time/chacha-poly2133 && python3 plot_chacha_poly2133_benchmarks.py
# ==============================================================================

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)