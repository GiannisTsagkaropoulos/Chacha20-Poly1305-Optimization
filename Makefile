.PHONY: all test clean

CC     = gcc
CFLAGS = -Wall -Wextra -Wpointer-sign -Iinclude

CHACHA_SRCS = chacha20.c \
              chacha20-poly1305.c

POLY_SRCS = poly2133.c \
            poly1305.c

TEST_SRCS = tests/test_functions.c \
            tests/test_vectors.c \
            tests/test_helpers.c \
            tests/main.c

TEST_RUNNER = test_runner

all: test

test:  $(TEST_RUNNER)
	./$(TEST_RUNNER)

$(TEST_RUNNER): $(CHACHA_SRCS) $(TEST_SRCS) $(POLY_SRCS)
	$(CC) $(CFLAGS) -DUNIT_TEST -o $@ $^

clean:
	rm -f $(TEST_RUNNER)