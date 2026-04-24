all: test

test: poly1305_tests
	./poly1305_tests

poly1305_tests: poly1305_tests.c poly1305.c
	gcc -Wall -Wextra -o poly1305_tests poly1305_tests.c

clean:
	rm -f poly1305_tests