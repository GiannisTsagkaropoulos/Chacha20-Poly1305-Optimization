CXX      = g++
CXXFLAGS = -march=native -std=c++17
INC      = -I./include

.PHONY: all chacha_block chacha_encrypt bench_chacha_encrypt_solo clean

all: bench_chacha_block bench_chacha_encrypt bench_chacha_encrypt_solo

bench_chacha_block: chacha/chacha_block.cpp chacha/main_block.cpp
	$(CXX) $(CXXFLAGS) $(INC) -I./chacha -o $@ $^

bench_chacha_encrypt_0: chacha/chacha_block.cpp chacha/chacha_encrypt.cpp chacha/main_encrypt.cpp
	$(CXX) $(CXXFLAGS) -O0 $(INC) -I./chacha -o $@ $^

bench_chacha_encrypt_1: chacha/chacha_block.cpp chacha/chacha_encrypt.cpp chacha/main_encrypt.cpp
	$(CXX) $(CXXFLAGS) -O1 $(INC) -I./chacha -o $@ $^

bench_chacha_encrypt_2: chacha/chacha_block.cpp chacha/chacha_encrypt.cpp chacha/main_encrypt.cpp
	$(CXX) $(CXXFLAGS) -O2 $(INC) -I./chacha -o $@ $^

bench_chacha_encrypt_3: chacha/chacha_block.cpp chacha/chacha_encrypt.cpp chacha/main_encrypt.cpp
	$(CXX) $(CXXFLAGS) -O3 $(INC) -I./chacha -o $@ $^

bench_chacha_encrypt_solo: chacha/chacha_block.cpp chacha/chacha_encrypt.cpp chacha/main_encrypt_solo.cpp
	$(CXX) $(CXXFLAGS) -O0 $(INC) -I./chacha -o $@ $^	
	

chacha_block:   bench_chacha_block   ; ./bench_chacha_block
chacha_encrypt_O0: bench_chacha_encrypt_0 ; ./bench_chacha_encrypt_0
chacha_encrypt_O1: bench_chacha_encrypt_1 ; ./bench_chacha_encrypt_1
chacha_encrypt_O2: bench_chacha_encrypt_2 ; ./bench_chacha_encrypt_2
chacha_encrypt_O3: bench_chacha_encrypt_3 ; ./bench_chacha_encrypt_3
chacha_encrypt_solo: bench_chacha_encrypt_solo ; ./bench_chacha_encrypt_solo

clean:
	rm -f bench_chacha_block bench_chacha_encrypt_0 bench_chacha_encrypt_1 bench_chacha_encrypt_2 bench_chacha_encrypt_3 bench_chacha_encrypt_solo