#ifndef TSC_X86_H
#define TSC_X86_H

/* 1. Basic Type Definitions */
#if !defined(WIN32) || defined(__GNUC__)
    #define myInt64 unsigned long long
    #define INT32 unsigned int
    #define VOLATILE __volatile__
    #define ASM __asm__
#else
    #define myInt64 unsigned __int64
    #define INT32 unsigned __int32
#endif

/* 2. The tsc_counter Union (Defined ONCE, outside all blocks) */
typedef union {
    myInt64 int64;
    struct { INT32 lo, hi; } int32;
} tsc_counter;

/* 3. Helper Macros */
#define COUNTER_VAL(a) ((a).int64)

/* 4. Instruction Macros */
#if !defined(WIN32) || defined(__GNUC__)
    /* GCC / Linux / Clang */
    #define RDTSC(cpu_c) \
        ASM VOLATILE ("rdtsc" : "=a" ((cpu_c).int32.lo), "=d"((cpu_c).int32.hi))
    
    #define CPUID() \
        ASM VOLATILE ("cpuid" : : "a" (0) : "bx", "cx", "dx" )
#else
    /* MSVC / Windows */
    #define RDTSC(cpu_c)   \
    {       __asm rdtsc    \
            __asm mov (cpu_c).int32.lo,eax  \
            __asm mov (cpu_c).int32.hi,edx  \
    }
    #define CPUID() \
    { \
        __asm mov eax, 0 \
        __asm cpuid \
    }
#endif

/* 5. Timing Functions */
static inline void init_tsc() {
    ; 
}

static inline myInt64 start_tsc(void) {
    tsc_counter start; // Compiler now sees the typedef at the top
    CPUID();
    RDTSC(start);
    return COUNTER_VAL(start);
}

static inline myInt64 stop_tsc(myInt64 start_val) {
    tsc_counter end;
    RDTSC(end);
    CPUID();
    return COUNTER_VAL(end) - start_val;
}

#endif /* TSC_X86_H */