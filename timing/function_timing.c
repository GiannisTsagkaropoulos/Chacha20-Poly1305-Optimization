#if defined(_WIN32) || defined(WIN32)
    #include <windows.h>
#else
    #include <sys/time.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "function_timing.h"
#include "chacha20.h"
#include "chacha20_priv.h"
#include "test_functions.h"
#include "test_vectors.h"
#include "test_inputs.h"

#ifdef __x86_64__
#include "tsc_x86.h"
#endif

#ifdef __aarch64__
#include "vct_arm.h"
#endif

#define NUM_REPS 30
#define NUM_RUNS 1
#define FREQUENCY 25e8 
#define CYCLES_REQUIRED 1e8
#define CALIBRATE
#define ITER 1
volatile uint8_t sink;

// Helper for qsort
int compare_doubles(const void *a, const void *b) {
    double arg1 = *(const double *)a;
    double arg2 = *(const double *)b;
    if (arg1 < arg2) return -1;
    if (arg1 > arg2) return 1;
    return 0;
}

void qr_wrapper(void* arg) {
    test_args_t* a = (test_args_t*)arg;
    test_quarter_rounds(a->tests, a->fails);
}

void init_wrapper(void* arg) {
    test_args_t* a = (test_args_t*)arg;
    test_state_initialization(a->tests, a->fails);
}

void block_wrapper(void* arg) {
    test_args_t* a = (test_args_t*)arg;
    test_apply_chacha_block(a->tests, a->fails);
}

void serial_wrapper(void* arg) {
    test_args_t* a = (test_args_t*)arg;
    test_serialization(a->tests, a->fails);
}

void chacha_wrapper(void* arg) {
    chacha_args_t* a = (chacha_args_t*)arg;
    int flag = chacha20_encryption_chosen_len(a->p_length, a->plaintext, a->key, a->nonce);
    sink = (uint8_t)flag; 
}

void poly_wrapper(void* arg) {
    poly_args_t* a = (poly_args_t*)arg;
    
    // 1. Run the test
    int flag = poly1305_test(a->data_length, a->key, a->data);
    
    // 2. Force a write to a volatile variable. 
    // The compiler CANNOT optimize this away.
    sink = (uint8_t)flag; 
}

void seal_wrapper(void* arg) {
    seal_args_t* a = (seal_args_t*)arg;
    seal_test(a->key_b, a->nonce_b, a->plaintext_b, a->plaintext_len, a->data, a->data_len, a->ciphertext_b);
}

#ifdef __x86_64__
/**
 * Measures execution time using the Time Stamp Counter (TSC).
 * In C, we pass the workload as a function pointer.
 */
double rdtsc(void (*workload)(void*), void* data) {
    int i, num_runs;
    myInt64 cycles;
    myInt64 start;
    num_runs = NUM_RUNS;
    double results[NUM_REPS];

#ifdef CALIBRATE
    while(num_runs < (1 << 14)) {
        start = start_tsc();
        for (i = 0; i < num_runs; ++i) {
            workload(data);
        }
        cycles = stop_tsc(start);

        if(cycles >= CYCLES_REQUIRED) break;
        num_runs *= 2;
    }
#endif

    // Measurement phase
    for (int rep = 0; rep < NUM_REPS; rep++) {
        start = start_tsc();
        for (i = 0; i < num_runs; ++i) {
            workload(data);
        }
        cycles = stop_tsc(start) / num_runs;
        results[rep] = (double)cycles;
    }

    qsort(results, NUM_REPS, sizeof(double), compare_doubles);
    return results[NUM_REPS / 2];
}
#endif

double compute_function(char* name, int n) {
    int tests = 0;
    int fails = 0;
    double res = 0;
    test_args_t t_args = { &tests, &fails };

    if (strcmp(name, "quarter_round") == 0) {
        res = rdtsc(qr_wrapper, &t_args);
        res = res / 2.0;
        printf("F\n");
    } else if (strcmp(name, "initialize_chacha_state") == 0) {
        res = rdtsc(init_wrapper, &t_args);
        res = res / 1.0;
    } else if (strcmp(name, "chacha_block") == 0) {
        res = rdtsc(block_wrapper, &t_args);
        res = res / 2.0;
    } else if (strcmp(name, "chacha20_encrypt") == 0) {
        uint8_t* key_b = create_random_key();
        uint8_t* nonce_b = create_random_nonce();
        uint8_t* plaintext_b = create_random_bytes(n);

        chacha_args_t args;
        args.p_length = n;
        args.plaintext = plaintext_b;
        args.key = key_b;
        args.nonce = nonce_b;
        res = rdtsc(chacha_wrapper, &args);

        free(key_b);
        free(nonce_b);
        free(plaintext_b);
    }else if(strcmp(name, "poly_tag") == 0){
        uint8_t key[32]; 
        fill_random_key(key);
        uint8_t* data = create_random_bytes(n);

        poly_args_t args;
        args.data_length = (uint64_t)n;
        args.key = key;   // This passes the address of the 32-byte array
        args.data = data; 

        res = rdtsc(poly_wrapper, &args);
        free(data);

    } else if (strcmp(name, "serialization") == 0) {
        res = rdtsc(serial_wrapper, &t_args);
        res = res / 3.0;
    }else if (strcmp(name, "seal") == 0) {
        uint8_t* key_b = create_random_key();
        uint8_t* nonce_b = create_random_nonce();
        uint8_t* plaintext_b = create_random_bytes(n);
        uint8_t *data = create_random_bytes(64);
        uint8_t * ciphertext_b = malloc(n+16);

        seal_args_t args;
        args.key_b = key_b;
        args.nonce_b = nonce_b;
        args.plaintext_b = plaintext_b;
        args.plaintext_len = n;
        args.data = data;
        args.data_len = 64;
        args.ciphertext_b = ciphertext_b;
        res = rdtsc(seal_wrapper, &args);

        free(key_b);
        free(nonce_b);
        free(plaintext_b);
        free(ciphertext_b);
    }

    return res;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("Parameters are invalid\n"); 
        return -1;
    }
    int n = atoi(argv[1]);
    char* data_file = argv[2];
    char* name = argv[3];
    printf(" Initializing data for n = %d...\n", n);
    printf("Reporting median over %d internal repetitions...\n\n", NUM_REPS);
    srand(0);
    
#ifdef __x86_64__
    double r_sum = 0.0;
    for(int k=0; k<ITER; k++) { 
        double r_1 = compute_function(name, n);
        r_sum += r_1;
    }
    double r = r_sum / ITER;
    printf("--- x86 RDTSC Instruction ---\n");
    printf("Median: %lf cycles measured per run.\n=> %lf seconds (assuming CPU frequency is %lf MHz).\n", 
            r, r / FREQUENCY, FREQUENCY / 1e6);

    // Standard C File Append
    FILE *f = fopen(data_file, "a");
    if (f == NULL) {
        fprintf(stderr, "ERROR: could not open file!\n");
    } else {
        fprintf(f, "%d, %lf\n", n, r);
        fclose(f);
    }
#endif


#ifdef __aarch64__
    double v = rdvct(A, x, y, n);
    printf("--- ARM VCT Instruction ---\n");
    printf("Median: %lf ticks measured per run.\n=> %lf seconds (assuming VCT clock frequency is %lf MHz).\n\n", 
           v, v / get_vct_freq(), get_vct_freq() / 1e6);

#ifdef PMU
    // Note: This requires sudo on macOS
    double p = rdpmu(A, x, y, n);
    printf("--- ARM PMU Instruction ---\n");
    printf("Median: %lf cycles measured per run.\n=> %lf seconds (assuming CPU frequency is %lf MHz).\n", 
           p, p / FREQUENCY, FREQUENCY / 1e6);
    printf("Note: Change FREQUENCY in the source code if your CPU differs.\n\n");
#endif
#endif

    printf("FINISHED\n");
    return 0;
    //return r;
}