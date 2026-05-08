.PHONY: all test clean

CC     = gcc
CFLAGS = -Wall -Wextra -Wpointer-sign -Iinclude

CHACHA_SRCS = chacha20.c \
              chacha20-poly1305.c \
              tests/test_functions.c \
              tests/test_vectors.c \
              tests/test_helpers.c \
              tests/main.c

POLY_SRCS = poly2133.c

CHACHA_TESTS = chacha20_tests
POLY_TESTS = poly1305_tests

all: test

test:  $(CHACHA_TESTS) $(POLY_TESTS)
	./$(CHACHA_TESTS)
	./$(POLY_TESTS)

$(CHACHA_TESTS): $(CHACHA_SRCS) $(POLY_SRCS)
	$(CC) $(CFLAGS) -DUNIT_TEST -o $@ $^

clean:
	rm -f $(POLY_TESTS) $(CHACHA_TESTS)