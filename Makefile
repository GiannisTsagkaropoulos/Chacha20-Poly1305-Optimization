# ==============================================================================
# Global Configuration & Toolchain
# ==============================================================================
CXX          = g++
CC           = gcc

INCLUDES     = -I. -Itime/include
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

# ======== Poly2133_init ========
EXE_POLY2133_INIT       = $(BIN_DIR)/poly2133_init_benchmark_runner
$(EXE_POLY2133_INIT): optimizations/poly2133-init-optimizations.c time/poly2133/main_init.cpp | $(BIN_DIR)
	$(CXX) $(BENCHMARK_FLAGS) -o $@ $^

.PHONY: bench-poly2133-init
bench-poly2133-init: $(EXE_POLY2133_INIT)
	./$(EXE_POLY2133_INIT)

ALL_BENCHMARKS += $(EXE_POLY2133_INIT)
# ==============================
# ==============================================================================	
clean:
	rm -f $(TEST_RUNNER) \
    rm -rf $(BIN_DIR) \