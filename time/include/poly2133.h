#pragma once
#include <string>
#include <stdint.h>
#include <emmintrin.h>
#include <immintrin.h>

#include "include/poly2133_opt.h"

typedef void(*poly2133_init_func)(uint32_t *acc, uint32_t* r, uint32_t* s, const unsigned char *key);