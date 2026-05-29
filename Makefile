# ==============================================================================
# Global Configuration & Toolchain
# ==============================================================================
CXX          = g++
CC           = gcc

INCLUDES     = -I. -Itime/include -Ioptimizations/
LDLIBS       = -lcrypto
COMMON_FLAGS = -O3 -march=native -Wall -Wextra
CFLAGS 		 = -Wall -Wextra -Wpointer-sign -Iinclude -mavx2 -msse4.1
BENCHMARK_FLAGS = $(COMMON_FLAGS) -std=c++17 $(INCLUDES)
C_FLAGS         = $(COMMON_FLAGS) $(INCLUDES)

BIN_DIR = bin
$(BIN_DIR):
	mkdir -p $(BIN_DIR)
.PHONY: all test clean

CC     = gcc
CXX    = g++

INCLUDES     = -I. -Itime/include -Ioptimizations/ 
COMMON_FLAGS = -O3 -march=native -Wall -Wextra
CFLAGS 		 = -Wall -Wextra -Wpointer-sign -Iinclude -mavx2 -msse4.1
BENCHMARK_FLAGS = $(COMMON_FLAGS) -std=c++17 $(INCLUDES)
C_FLAGS         = $(COMMON_FLAGS) $(INCLUDES)

BIN_DIR = bin
$(BIN_DIR):
	mkdir -p $(BIN_DIR)


CHACHA_SRCS = chacha20.c \
              chacha20-poly1305.c

POLY_SRCS = optimizations/poly2133-optimizations.c \
            poly1305.c

TEST_SRCS = tests/test_functions.c \
            tests/test_vectors.c \
            tests/test_helpers.c \
            tests/main.c

TEST_RUNNER = test_runner

.PHONY: all test clean
all: test

test:  $(TEST_RUNNER)
	./$(TEST_RUNNER)

$(TEST_RUNNER): $(CHACHA_SRCS) $(TEST_SRCS) $(POLY_SRCS)
	$(CC) $(CFLAGS) -DUNIT_TEST -o $@ $^


# ==============================================================================
# Benchmarks
# ==============================================================================
ALL_BENCHMARKS =

# ======== Poly1305_init ========
EXE_POLY1305_INIT       = $(BIN_DIR)/poly1305_init_benchmark_runner
$(EXE_POLY1305_INIT): optimizations/poly1305-init-optimizations.c time/poly1305/main_init.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -o $@ $^

.PHONY: bench-poly1305-init
bench-poly1305-init: $(EXE_POLY1305_INIT)
	./$(EXE_POLY1305_INIT)

ALL_BENCHMARKS += $(EXE_POLY1305_INIT)
# ==============================

# ======== Poly2133_init ========
EXE_POLY2133_INIT       = $(BIN_DIR)/poly2133_init_benchmark_runner
$(EXE_POLY2133_INIT): optimizations/poly2133-init-optimizations.c time/poly2133/main_init.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -o $@ $^

.PHONY: bench-poly2133-init
bench-poly2133-init: $(EXE_POLY2133_INIT)
	./$(EXE_POLY2133_INIT)

ALL_BENCHMARKS += $(EXE_POLY2133_INIT)
# ==============================

# ======== Poly1305_create_tag ========
EXE_POLY1305_CREATE_TAG     = $(BIN_DIR)/poly1305_create_tag_benchmark_runner
$(EXE_POLY1305_CREATE_TAG): optimizations/poly1305_opt.c time/poly1305/main_create_tag.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -o $@ $^

.PHONY: bench-poly1305-create-tag
bench-poly1305-create-tag: $(EXE_POLY1305_CREATE_TAG)
	./$(EXE_POLY1305_CREATE_TAG)

ALL_BENCHMARKS += $(EXE_POLY1305_CREATE_TAG)
# ==============================

# ======== Chacha_block ========
EXE_CHACHA_BLOCK       = $(BIN_DIR)/chacha_block_benchmark_runner
$(EXE_CHACHA_BLOCK): optimizations/chacha-block-optimizations.c time/chacha/main_block.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -o $@ $^

.PHONY: bench-chacha-block
bench-chacha-block: $(EXE_CHACHA_BLOCK)
	./$(EXE_CHACHA_BLOCK)

ALL_BENCHMARKS += $(EXE_CHACHA_BLOCK)
# ==============================

# ======== Chacha_encrypt (one plaintext size and verbose) ========
EXE_CHACHA_ENCRYPT_SOLO = $(BIN_DIR)/chacha_encrypt_solo_benchmark_runner
$(EXE_CHACHA_ENCRYPT_SOLO): optimizations/chacha-encrypt-optimizations.c optimizations/chacha-block-optimizations.c time/chacha/main_encrypt_solo.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -o $@ $^ $(LDLIBS)

.PHONY: bench-chacha-encrypt-solo
bench-chacha-encrypt-solo: $(EXE_CHACHA_ENCRYPT_SOLO)
	./$(EXE_CHACHA_ENCRYPT_SOLO)

ALL_BENCHMARKS += $(EXE_CHACHA_ENCRYPT_SOLO)
# ==============================

# ======== Chacha_encrypt  ========
ENCRYPT_FLAGS = -march=native -Wall -Wextra -std=c++17

EXE_ENCRYPT_0 = $(BIN_DIR)/bench_chacha_encrypt_0
EXE_ENCRYPT_1 = $(BIN_DIR)/bench_chacha_encrypt_1
EXE_ENCRYPT_2 = $(BIN_DIR)/bench_chacha_encrypt_2
EXE_ENCRYPT_3 = $(BIN_DIR)/bench_chacha_encrypt_3


$(EXE_ENCRYPT_0): optimizations/chacha-encrypt-optimizations.c optimizations/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O0 $(ENCRYPT_FLAGS) $(INCLUDES) -o $@ $^ $(LDLIBS)

$(EXE_ENCRYPT_1): optimizations/chacha-encrypt-optimizations.c optimizations/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O1 $(ENCRYPT_FLAGS) $(INCLUDES) -o $@ $^ $(LDLIBS)

$(EXE_ENCRYPT_2): optimizations/chacha-encrypt-optimizations.c optimizations/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O2 $(ENCRYPT_FLAGS) $(INCLUDES) -o $@ $^ $(LDLIBS)

$(EXE_ENCRYPT_3): optimizations/chacha-encrypt-optimizations.c optimizations/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O3 $(ENCRYPT_FLAGS) $(INCLUDES) -o $@ $^ $(LDLIBS)

.PHONY: bench-chacha-encrypt-all bench-chacha-encrypt
bench-chacha-encrypt-all: $(EXE_ENCRYPT_0) $(EXE_ENCRYPT_1) $(EXE_ENCRYPT_2) $(EXE_ENCRYPT_3)

bench-chacha-encrypt: bench-chacha-encrypt-all
	cd time/chacha && python3 run_chacha_benchmarks.py

create-chacha-plots: 
	cd time/chacha && python3 plot_chacha_benchmarks.py
# ==============================================================================    


ALL_BENCHMARKS =

# ======== Poly1305_create_tag ========
EXE_POLY1305_CREATE_TAG     = $(BIN_DIR)/poly1305_create_tag_benchmark_runner
$(EXE_POLY1305_CREATE_TAG): optimizations/poly1305_opt.c time/poly1305/main_create_tag.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -o $@ $^

.PHONY: bench-poly1305-create-tag
bench-poly1305-create-tag: $(EXE_POLY1305_CREATE_TAG)
	./$(EXE_POLY1305_CREATE_TAG)

ALL_BENCHMARKS += $(EXE_POLY1305_CREATE_TAG)
# ==============================


clean:
	rm -f $(TEST_RUNNER)
	rm -rf $(BIN_DIR)