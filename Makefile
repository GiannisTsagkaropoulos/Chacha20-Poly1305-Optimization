# ==============================================================================
# Global Configuration & Toolchain
# ==============================================================================
CXX          = g++
CC           = gcc

INCLUDES     = -I. -Iinclude/ -Itime/include
LDLIBS       = -lcrypto
COMMON_FLAGS = -march=native -Wall -Wextra
BENCHMARK_FLAGS  = $(COMMON_FLAGS) -std=c++17 $(INCLUDES) -Ioptimizations/include

BIN_DIR = bin

OPT_INCLUDES = \
    -Ioptimizations/chacha20 \
    -Ioptimizations/poly1305 \
    -Ioptimizations/poly2133 \
	-Ioptimizations/chacha20-poly1305 \
	-Ioptimizations/include


TEST_INCLUDES = $(INCLUDES) $(OPT_INCLUDES) -Itests/include

TEST_RUNNER =  $(BIN_DIR)/test_runner
$(TEST_RUNNER): tests/*.c optimizations/**/*.c  | $(BIN_DIR)
	$(CC) $(COMMON_FLAGS) $(TEST_INCLUDES) -DUNIT_TEST -o $@ $^ $(LDLIBS)

.PHONY: test bin
test:  $(TEST_RUNNER)
	./$(TEST_RUNNER)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)


# ======== Chacha20 ========
CHACHA20_FLAGS =$(BENCHMARK_FLAGS) -Ioptimizations/chacha20

EXE_CHACHA_BLOCK        = $(BIN_DIR)/chacha_block_benchmark_runner
EXE_CHACHA_ENCRYPT_SOLO = $(BIN_DIR)/chacha_encrypt_solo_benchmark_runner
EXE_ENCRYPT_3           = $(BIN_DIR)/bench_chacha_encrypt_3
EXE_ENCRYPT_3_NO_VEC    = $(BIN_DIR)/bench_chacha_encrypt_3_no_vec


$(EXE_CHACHA_BLOCK): optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_block.cpp | $(BIN_DIR)
	$(CXX) $(CHACHA20_FLAGS) -o $@ $^

# ======== Chacha_encrypt (one plaintext size and verbose) ========
$(EXE_CHACHA_ENCRYPT_SOLO): optimizations/chacha20/chacha-encrypt-optimizations.c optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_encrypt_solo.cpp | $(BIN_DIR)
	$(CXX) $(CHACHA20_FLAGS) -o $@ $^ $(LDLIBS)

$(EXE_ENCRYPT_3): optimizations/chacha20/chacha-encrypt-optimizations.c optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O3 $(CHACHA20_FLAGS) -o $@ $^ $(LDLIBS)

$(EXE_ENCRYPT_3_NO_VEC): optimizations/chacha20/chacha-encrypt-optimizations.c optimizations/chacha20/chacha-block-optimizations.c time/chacha/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O3 -fno-tree-vectorize $(CHACHA20_FLAGS) -o $@ $^ $(LDLIBS)	


.PHONY: bench-chacha-block bench-chacha-encrypt-solo bench-chacha-encrypt create-chacha-plots
bench-chacha-block: $(EXE_CHACHA_BLOCK)
	./$(EXE_CHACHA_BLOCK)
	
bench-chacha-encrypt-solo: $(EXE_CHACHA_ENCRYPT_SOLO)
	./$(EXE_CHACHA_ENCRYPT_SOLO)

bench-chacha-encrypt: $(EXE_ENCRYPT_3) $(EXE_ENCRYPT_3_NO_VEC)
	cd time/chacha && python3 run_chacha_benchmarks.py

create-chacha-plots: 
	cd time/chacha && python3 plot_chacha_benchmarks.py
# ==============================================================================  


# ======== Poly1305 ========
POLY1305_FLAGS = $(BENCHMARK_FLAGS) -Ioptimizations/poly1305

EXE_POLY1305_INIT           = $(BIN_DIR)/poly1305_init_benchmark_runner
EXE_POLY1305_COMPLETE_3     = $(BIN_DIR)/poly1305_complete_3
EXE_CREATE_TAG1305_3        = $(BIN_DIR)/bench_poly1305_create_tag_3
EXE_CREATE_TAG1305_3_NO_VEC = $(BIN_DIR)/bench_poly1305_create_tag_3_no_vec


$(EXE_POLY1305_INIT): optimizations/poly1305/poly1305-init-optimizations.c time/poly1305/main_init.cpp | $(BIN_DIR)
	$(CXX) -O3 -fno-tree-vectorize $(POLY1305_FLAGS)  -o $@ $^

$(EXE_POLY1305_COMPLETE_3): optimizations/poly1305/poly1305_complete.c optimizations/poly1305/poly1305-init-optimizations.c time/poly1305/OpenSSL-Complete-Benchmark/main_complete_choose_len.cpp | $(BIN_DIR)
	$(CXX) -O3 $(POLY1305_FLAGS) -o $@ $^ $(LDLIBS)

$(EXE_CREATE_TAG1305_3): optimizations/poly1305/poly1305_tag_opt.c optimizations/poly1305/poly1305-init-optimizations.c time/poly1305/main_create_tag.cpp | $(BIN_DIR)
	$(CXX) -O3 $(POLY1305_FLAGS) -o $@ $^ $(LDLIBS)

$(EXE_CREATE_TAG1305_3_NO_VEC): optimizations/poly1305/poly1305_tag_opt.c optimizations/poly1305/poly1305-init-optimizations.c time/poly1305/main_create_tag.cpp | $(BIN_DIR)
	$(CXX) -O3 -fno-tree-vectorize $(POLY1305_FLAGS) -o $@ $^ $(LDLIBS)	


.PHONY: bench-poly1305-init bench-poly1305-complete-choose-len bench-poly1305-create-tag create-poly1305-plots
bench-poly1305-init: $(EXE_POLY1305_INIT)
	./$(EXE_POLY1305_INIT)

bench-poly1305-complete-choose-len: $(EXE_POLY1305_COMPLETE_3)
	cd time/poly1305/OpenSSL-Complete-Benchmark && python3 run_poly1305_complete_benchmarks.py

bench-poly1305-create-tag: $(EXE_CREATE_TAG1305_3) $(EXE_CREATE_TAG1305_3_NO_VEC)
	cd time/poly1305 && python3 run_poly1305_benchmarks.py

create-poly1305-plots: 
	cd time/poly1305 && python3 plot_poly1305_benchmarks.py
# ==============================================================================      

# ======== Poly2133 ========
POLY2133_FLAGS = $(BENCHMARK_FLAGS) -Ioptimizations/poly2133

EXE_POLY2133_INIT           = $(BIN_DIR)/poly2133_init_benchmark_runner
EXE_CREATE_TAG2133_3        = $(BIN_DIR)/bench_poly2133_create_tag_3
EXE_CREATE_TAG2133_3_NO_VEC = $(BIN_DIR)/bench_poly2133_create_tag_3_no_vec

$(EXE_POLY2133_INIT): optimizations/poly2133/poly2133-init-optimizations.c time/poly2133/main_init.cpp | $(BIN_DIR)
	$(CXX) -O3 -fno-tree-vectorize $(POLY2133_FLAGS) -o $@ $^

$(EXE_CREATE_TAG2133_3): optimizations/poly2133/poly2133-optimizations.c optimizations/poly2133/poly2133-init-optimizations.c time/poly2133/main_create_tag.cpp | $(BIN_DIR)
	$(CXX) -O3 $(POLY2133_FLAGS)  -o $@ $^ $(LDLIBS)

$(EXE_CREATE_TAG2133_3_NO_VEC): optimizations/poly2133/poly2133-optimizations.c optimizations/poly2133/poly2133-init-optimizations.c time/poly2133/main_create_tag.cpp | $(BIN_DIR)
	$(CXX) -O3 -fno-tree-vectorize $(POLY2133_FLAGS) -o $@ $^ $(LDLIBS)	


.PHONY: bench-poly2133-init bench-poly2133-create-tag
bench-poly2133-init: $(EXE_POLY2133_INIT)
	./$(EXE_POLY2133_INIT)

bench-poly2133-create-tag: $(EXE_CREATE_TAG2133_3) $(EXE_CREATE_TAG2133_3_NO_VEC)
	cd time/poly2133 && python3 run_poly2133_benchmarks.py

create-poly2133-plots: 
	cd time/poly2133 && python3 plot_poly2133_benchmarks.py
# ==============================================================================    
 
# ======== Chacha20-Poly1305 Encrypt  ========
CHACHA_POLY1305_SRCS =  optimizations/chacha20-poly1305/chacha20-poly1305.c \
						optimizations/chacha20/chacha-encrypt-optimizations.c \
						optimizations/chacha20/chacha-block-optimizations.c \
						optimizations/poly1305/poly1305_tag_opt.c \
						optimizations/poly1305/poly1305-init-optimizations.c 

AEAD_FLAGS = $(BENCHMARK_FLAGS) -Ioptimizations/chacha20-poly1305 -Ioptimizations/chacha20 -Ioptimizations/poly1305

EXE_AEAD_ENCRYPT_SOLO = $(BIN_DIR)/aead_encrypt_solo_benchmark_runner
EXE_AEAD_ENCRYPT_3 = $(BIN_DIR)/bench_aead_encrypt_3
EXE_AEAD_ENCRYPT_3_NO_VEC = $(BIN_DIR)/bench_aead_encrypt_3_no_vec


$(EXE_AEAD_ENCRYPT_SOLO): $(CHACHA_POLY1305_SRCS) time/chacha-poly1305/main_encrypt_solo.cpp | $(BIN_DIR)
	$(CXX) -O3 $(AEAD_FLAGS) -o $@ $^ $(LDLIBS)	

$(EXE_AEAD_ENCRYPT_3): $(CHACHA_POLY1305_SRCS) time/chacha-poly1305/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O3 $(AEAD_FLAGS) -o $@ $^ $(LDLIBS)	

$(EXE_AEAD_ENCRYPT_3_NO_VEC): $(CHACHA_POLY1305_SRCS) time/chacha-poly1305/main_encrypt.cpp | $(BIN_DIR)
	$(CXX) -O3 -fno-tree-vectorize $(AEAD_FLAGS) -o $@ $^ $(LDLIBS)	


.PHONY:  bench-aead-encrypt bench-aead-all bench-aead-encrypt-solo create-chacha-poly-plots
bench-aead-encrypt-solo: $(EXE_AEAD_ENCRYPT_SOLO)
	./$(EXE_AEAD_ENCRYPT_SOLO)

bench-aead-encrypt: $(EXE_AEAD_ENCRYPT_3) $(EXE_AEAD_ENCRYPT_3_NO_VEC)
	cd time/chacha-poly1305 && python3 run_aead_encrypt_benchmarks.py

create-chacha-poly-plots:
	cd time/chacha-poly && python3 plot_chacha_poly_benchmarks.py
# ==============================================================================

# ======== ChaCha20-Poly2133 AEAD (encrypt + decrypt) ========
CHACHA_POLY2133_SRCS = optimizations/chacha20-poly2133/chacha20-poly2133.c \
                       optimizations/chacha20/chacha-encrypt-optimizations.c \
                       optimizations/chacha20/chacha-block-optimizations.c \
                       optimizations/poly2133/poly2133-optimizations.c \
                       optimizations/poly2133/poly2133-init-optimizations.c 

CHACHA_POLY2133_FLAGS = $(BENCHMARK_FLAGS) -Ioptimizations/chacha20-poly2133 -Ioptimizations/chacha20 -Ioptimizations/poly2133

EXE_CHACHA_POLY2133_ENCRYPT_3        = $(BIN_DIR)/bench_chacha_poly2133_encrypt_3
EXE_CHACHA_POLY2133_ENCRYPT_3_NO_VEC = $(BIN_DIR)/bench_chacha_poly2133_encrypt_3_no_vec

ENCRYPT_POLY2133_MAIN = time/chacha-poly2133/main_encrypt_chacha_poly2133.cpp

$(EXE_CHACHA_POLY2133_ENCRYPT_3): $(CHACHA_POLY2133_SRCS) $(ENCRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O3 $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)
$(EXE_CHACHA_POLY2133_ENCRYPT_3_NO_VEC): $(CHACHA_POLY2133_SRCS) $(ENCRYPT_POLY2133_MAIN) | $(BIN_DIR)
	$(CXX) -O3 -fno-tree-vectorize $(CHACHA_POLY2133_FLAGS) -o $@ $^ $(LDLIBS)

.PHONY: bench-chacha-poly2133-encrypt create-chacha-poly2133-plots
bench-chacha-poly2133-encrypt: $(EXE_CHACHA_POLY2133_ENCRYPT_3) $(EXE_CHACHA_POLY2133_ENCRYPT_3_NO_VEC)
	cd time/chacha-poly2133 && python3 run_chacha_poly2133_benchmarks.py

create-chacha-poly2133-plots:
	cd time/chacha-poly2133 && python3 plot_chacha_poly2133_benchmarks.py
# ==============================================================================

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)