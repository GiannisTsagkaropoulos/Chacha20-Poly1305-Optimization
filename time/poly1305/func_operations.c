#include "op_computations.h"
#define BLOCK_SIZE 16

uint64_t count_COMPUTE_MUL_P(){
/* mult[0] = 4 ADDS, 9 MULTS
   mult[1] = 4 ADDS, 8 MULTS
   mult[2] = 4 ADDS, 7 MULTS
   mult[3] = 4 ADDS, 6 MULTS
   mult[4] = 4 ADDS, 5 MULTS
*/
    uint64_t ops = 4 + 9 + 4 + 8 + 4 + 7 + 4 + 6 + 4 + 5;
    return ops;
}

uint64_t count_CARRY_PROPAGATION(){
/* For loop on 4:
     1 SRIGHT, 1 AND, 2 ADDS
     1 INCREASE
    ------> TOTAL = 4*(1+1+2) + 4

    1 SRIGHT, 1 AND
    1 ADD, 1 MULT, 1 SRIGHT, 1 AND, 1 ADD
*/
    uint64_t ops = 4*(1+1+2) + 4 + 7;
    return ops;
}

uint64_t count_COMPUTE_MOD_P(){
/*  1 ADD

    For loop on 4:
      1 AND, 1 SRIGHT, 2 ADDS
    ------> TOTAL = 4*(1+1+2) + 4 increases

    1 AND, 1 SRIGHT
*/
    uint64_t ops = 4*(1+1+2) + 4 + 1 + 1;
    return ops;
}

uint64_t count_DOUBLE_MULTIPLICATION_ADDITION(){
/* mult[0] = 18 MULTS, 9 ADDS
   mult[1] = 16 MULTS, 9 ADDS
   mult[2] = 14 MULTS, 9 ADDS
   mult[3] = 12 MULTS, 9 ADDS
   mult[4] = 10 MULTS, 9 ADDS

   4 ADDS
*/
    uint64_t ops = 18+9+16+9+14+9+12+9+10+9+4+4;

    return ops;
}

uint64_t count_CARRY_PROP_DELAYED(){
/* For loop on 4
        1 RSHIFT, 1 AND, 2 ADDS
        1 INCREASE
    
    1 RSHIFT, 1 AND, 1 ADD, 1 MUL, 1 RSHIFT, 1 AND, 1 ADD

*/
    uint64_t ops = 4*(5) + 1+1+1+1+1+1+1;
    return ops;
}

uint64_t count_MOD_P_DELAYED(){
/* 1 ADD
    FOr loop on 4:
        1 AND, 1 RSHIFT, 2 ADDS
        1 INCREASE

    1 ADD 1 RSHIFT
*/
    uint64_t ops = 4*(5) + 2;
    return ops;
}

uint64_t count_ADD_55(){
/* For loop on 5:
        2 ADDS
        1 AND
        1 RSHIFT
        1 INCREASE
    
    1 ADD, 1 MUL

*/
    uint64_t ops = 5*(2+1+1+1) + 1 + 1;
    return ops;
}

uint64_t count_to_large_num_rep(){
/*  For loop on len_bytes:
        1 DIV
        1 OR
        1 LSHIFT
        1 DIV
        1 MUL
    -----------> TOT = 17*5 + 17 increases

    1 AND

    For loop on 4:
        1 ADD
        2 RSHIFT 
        1 OR
        1 AND
        1 ADD
        1 ADD
        1 SUB
    -------------> TOTAL = 4*8 + 4 increases
    //len_bytes always 17
*/
    uint64_t ops = 32+5+17 + 17*5;
    return ops;
}

uint64_t count_add_large_nums_55(){
/*   For loop on 5:
        2 ADDS
        1 AND
        1 RSHIFT
    ------------> 5*4 + 5 INCREASES
    1 ADD
    1 MUL
*/
    uint64_t ops = 5*4 + 5 +2;
    return ops;
}

uint64_t count_mulmod_p(){
/* 5 INCR
   mult[0] = 4 ADDS, 9 MULTS
   mult[1] = 4 ADDS, 8 MULTS
   mult[2] = 4 ADDS, 7 MULTS
   mult[3] = 4 ADDS, 6 MULTS
   mult[4] = 4 ADDS, 5 MULTS
 
   For loop on 4:
     1 SRIGHT, 1 AND, 2 ADDS
    ------> TOTAL = 4*(1+1+2) + 4

    1 SRIGHT, 1 AND
    1 ADD, 1 MULT, 1 SRIGHT, 1 AND, 1 ADD

    1 ADD

    For loop on 4:
      1 AND, 1 SRIGHT, 2 ADDS
    ------> TOTAL = 4*(1+1+2) + 4 increases

    1 AND, 1 SRIGHT
*/

    uint64_t ops_mult  = 5 + 4 + 9 + 4 + 8 + 4 + 7 + 4 + 4 + 6 + 4 + 5; //55

    uint64_t ops_after = 4*(1+1+2) + 4 + 8 + 4*(1+1+2) + 4 + 1 + 1;

    uint64_t total_ops = ops_mult + ops_after;
    
    return total_ops;
}

uint64_t count_add_large_nums_54(){
/*  1 MUL
    For loop on 4:
      1 RSHIFT, 1 OR, 1 ADD, 1 LSHIFT
      1 ADD, 1 SUB
    ---------------> TOTAL = 4*(6) + 4

   For loop on 4:
     1 ADD, 1 AND, 1 ADD
     1 RSHIFT
   ------------> TOTAL = 4*(4) + 4
*/
    uint64_t ops = 4*(6) + 4 + 4*(4) + 4;
    return ops;
}

uint64_t count_to_16_le_bytes(){
/* For loop on 4:
    1 MUL, 1 AND
    1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    ------> + 4 increases
*/
    uint64_t ops = 4*(2+4+4+4) +4;
    return ops;
}