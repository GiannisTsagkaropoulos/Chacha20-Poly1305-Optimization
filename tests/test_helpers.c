#include <string.h>
#include <stdio.h>
#include "test_helpers.h"

int u32_arrays_are_same(uint32_t *a, uint32_t *b, uint64_t size_in_b){
    return memcmp(a, b, size_in_b) == 0;
}

int u8_arrays_are_same(uint8_t *a, uint8_t *b, uint64_t size_in_b){
    return memcmp(a, b, size_in_b) == 0;
}

void print_test_result(const char *test_name, int passed, int *total_tests, int *fails){
    if (passed) {
        printf("%s[PASS]:%s %s\n", ANSI_COLOR_GREEN, ANSI_COLOR_RESET, test_name);
    } else {
        printf("%s[FAIL]:%s %s\n", ANSI_COLOR_RED,   ANSI_COLOR_RESET, test_name);
        (*fails)++;
    }
    (*total_tests)++;
}

