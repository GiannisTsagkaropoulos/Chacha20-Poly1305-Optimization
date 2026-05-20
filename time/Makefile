CXX      = g++
CXXFLAGS = -O0 -march=native -std=c++17
INC      = -I./include

.PHONY: all chacha_block  clean

all: bench_chacha_block bench_chacha_encrypt

bench_chacha_block: chacha/chacha_block.cpp chacha/main_block.cpp
	$(CXX) $(CXXFLAGS) $(INC) -I./chacha -o $@ $^

bench_chacha_encrypt: chacha/chacha_block.cpp chacha/chacha_encrypt.cpp chacha/main_encrypt.cpp
	$(CXX) $(CXXFLAGS) $(INC) -I./chacha -o $@ $^


chacha_block:   bench_chacha_block   ; ./bench_chacha_block
chacha_encrypt: bench_chacha_encrypt ; ./bench_chacha_encrypt

clean:
	rm -f bench_chacha_block bench_chacha_encrypt