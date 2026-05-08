#include <stdio.h>
#include "test_helpers.h"
#include "test_functions.h"

int main(){
    int tests = 0;
    int fails = 0;

    test_state_initialization(&tests, &fails);
    test_quarter_rounds      (&tests, &fails);
    test_apply_chacha_block  (&tests, &fails);
    test_serialization       (&tests, &fails);
    test_chacha_encryption   (&tests, &fails);
    test_poly1305_key_gen    (&tests, &fails);
    test_aead_encryption     (&tests, &fails);
    test_aead_decryption     (&tests, &fails);
    test_poly1305_tag_gen    (&tests, &fails);
    test_poly2133_tag_gen    (&tests, &fails);

    if (fails) {
         printf("%s %d/%d TESTS PASSED %s\n", ANSI_COLOR_RED, tests-fails, tests, ANSI_COLOR_RESET);
    } else {
        printf("%s %d/%d TESTS PASSED %s\n", ANSI_COLOR_GREEN, tests, tests, ANSI_COLOR_RESET);
    }

    return fails ? -1: 0;
}