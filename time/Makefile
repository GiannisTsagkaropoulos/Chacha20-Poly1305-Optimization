CXX      = g++
CXXFLAGS = -O0 -march=native -std=c++17
INC      = -I./include

.PHONY: all chacha_block  clean

all: bench_chacha_block

bench_chacha_block: chacha/chacha_block.cpp chacha/main_block.cpp
	$(CXX) $(CXXFLAGS) $(INC) -I./chacha -o $@ $^

chacha_block:   bench_chacha_block   ; ./bench_chacha_block

clean:
	rm -f bench_chacha_block