#include <stdint.h>

#define ANSI_COLOR_RED   "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_RESET "\x1b[0m"

int u32_arrays_are_same(uint32_t *a, uint32_t *b, uint64_t size_in_b);
int u8_arrays_are_same(uint8_t *a, uint8_t *b, uint64_t size_in_b);
void print_test_result(const char *test_name, int passed, int *total_tests, int *fails);