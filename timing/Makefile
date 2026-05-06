CC = gcc
CXX = g++
CFLAGS = -O3 -DUNIT_TEST -I../include -Iinclude

# Use these as defaults if not provided via command line
# Ensure OUT has no spaces in the default path to avoid shell errors
BIN_NAME = FW
OUT ?= ./data_files/results.txt
FUNC_NAME ?= quarter_round

# Targets
ALL = runner FW

all: $(ALL)

# The Linker Step: Join all objects into the final binary
FW: function_timing.o test_functions.o test_vectors.o chacha20.o test_helpers.o test_inputs.o poly1305.o chacha20-poly1305.o
	$(CC) function_timing.o test_functions.o test_vectors.o chacha20.o test_helpers.o test_inputs.o poly1305.o chacha20-poly1305.o -o FW

# Compile the timing logic (C++)
function_timing.o: function_timing.c
	$(CC) $(CXXFLAGS) -c function_timing.c -o function_timing.o

# Make sure you have a rule for the data file
test_vectors.o: ../tests/test_vectors.c
	$(CC) $(CFLAGS) -c ../tests/test_vectors.c -o test_vectors.o

# Compile the test data and functions (C)
test_functions.o: ../tests/test_functions.c
	$(CC) $(CFLAGS) -c ../tests/test_functions.c -o test_functions.o

# Compile the core algorithm (C)
chacha20.o: ../chacha20.c
	$(CC) $(CFLAGS) -c ../chacha20.c -o chacha20.o

poly1305.o: ../poly1305.c
	$(CC) $(CFLAGS) -c ../poly1305.c -o poly1305.o

test_inputs.o: tests/test_inputs.c
	$(CC) $(CFLAGS) -c tests/test_inputs.c -o test_inputs.o

test_helpers.o: ../tests/test_helpers.c
	$(CC) $(CFLAGS) -c ../tests/test_helpers.c -o test_helpers.o

chacha20-poly1305.o: ../chacha20-poly1305.c
	$(CC) $(CFLAGS) -c ../chacha20-poly1305.c -o chacha20-poly1305.o

# 3. Fixed source extension to .cpp
runner: benchmark_runner.c
	$(CC) $(CFLAGS) benchmark_runner.c -o runner

clean:
	rm -f $(ALL) *.o

# A helper to run the experiment
# We use quotes around $(OUT) in case the path contains spaces
run: all
	./runner ./FW "$(OUT)" "$(FUNC_NAME)"
	$(MAKE) clean

#./FW 64 "$(OUT)" "$(FUNC_NAME)"
