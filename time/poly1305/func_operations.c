
#define BLOCK_SIZE 16

int count_COMPUTE_MUL_P(){
/* mult[0] = 4 ADDS, 9 MULTS
   mult[1] = 4 ADDS, 8 MULTS
   mult[2] = 4 ADDS, 7 MULTS
   mult[3] = 4 ADDS, 6 MULTS
   mult[4] = 4 ADDS, 5 MULTS
*/
    int ops = 4 + 9 + 4 + 8 + 4 + 7 + 4 + 6 + 4 + 5;
    return ops;
}

int count_CARRY_PROPAGATION(){
/* For loop on 4:
     1 SRIGHT, 1 AND, 2 ADDS
     1 INCREASE
    ------> TOTAL = 4*(1+1+2) + 4

    1 SRIGHT, 1 AND
    1 ADD, 1 MULT, 1 SRIGHT, 1 AND, 1 ADD
*/
    int ops = 4*(1+1+2) + 4 + 7;
    return ops;
}

int count_COMPUTE_MOD_P(){
/*  1 ADD

    For loop on 4:
      1 AND, 1 SRIGHT, 2 ADDS
    ------> TOTAL = 4*(1+1+2) + 4 increases

    1 AND, 1 SRIGHT
*/
    int ops = 4*(1+1+2) + 4 + 1 + 1;
    return ops;
}

int count_DOUBLE_MULTIPLICATION_ADDITION(){
/* mult[0] = 18 MULTS, 9 ADDS
   mult[1] = 16 MULTS, 9 ADDS
   mult[2] = 14 MULTS, 9 ADDS
   mult[3] = 12 MULTS, 9 ADDS
   mult[4] = 10 MULTS, 9 ADDS

   4 ADDS
*/
    int ops = 18+9+16+9+14+9+12+9+10+9+4+4;

    return ops;
}

int count_CARRY_PROP_DELAYED(){
/* For loop on 4
        1 RSHIFT, 1 AND, 2 ADDS
        1 INCREASE
    
    1 RSHIFT, 1 AND, 1 ADD, 1 MUL, 1 RSHIFT, 1 AND, 1 ADD

*/
    int ops = 4*(5) + 1+1+1+1+1+1+1;
    return ops;
}

int count_MOD_P_DELAYED(){
/* 1 ADD
    FOr loop on 4:
        1 AND, 1 RSHIFT, 2 ADDS
        1 INCREASE

    1 ADD 1 RSHIFT
*/
    int ops = 4*(5) + 2;
    return ops;
}

int count_ADD_55(){
/* For loop on 5:
        2 ADDS
        1 AND
        1 RSHIFT
        1 INCREASE
    
    1 ADD, 1 MUL

*/
    int ops = 5*(2+1+1+1) + 1 + 1;
    return ops;
}

int count_to_large_num_rep(){
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
    int ops = 32+5+17 + 17*5;
    return ops;
}

int count_add_large_nums_55(){
/*   For loop on 5:
        2 ADDS
        1 AND
        1 RSHIFT
    ------------> 5*4 + 5 INCREASES
    1 ADD
    1 MUL
*/
    int ops = 5*4 + 5 +2;
    return ops;
}

int count_mulmod_p(){
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

    int ops_mult  = 5 + 4 + 9 + 4 + 8 + 4 + 7 + 4 + 4 + 6 + 4 + 5; //55

    int ops_after = 4*(1+1+2) + 4 + 8 + 4*(1+1+2) + 4 + 1 + 1;

    int total_ops = ops_mult + ops_after;
    
    return total_ops;
}

int count_add_large_nums_54(){
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
    int ops = 4*(6) + 4 + 4*(4) + 4;
    return ops;
}

int count_to_16_le_bytes(){
/* For loop on 4:
    1 MUL, 1 AND
    1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    1 MUL, 1 ADD, 1 RSHIFT, 1 AND
    ------> + 4 increases
*/
    int ops = 4*(2+4+4+4) +4;
    return ops;
}

int count_create_tag(int data_len){
 /*  1 ADD , 1 DIV
    For loop on :
      1 MUL 
      1 SUB
      to_large_num_rep()
      add_large_nums_55()
      mulmod_p()
      1 INCREASE
    
    add_large_nums_54()
    to_16_le_bytes()
*/
    int ops = (data_len/BLOCK_SIZE) * (2 + compute_to_large_num_rep(17) + compute_add_large_nums_55() + compute_mulmod_p() +1)
    + compute_add_large_nums_54() + compute_to_16_le_bytes();

    return ops;
}

int count_inlined_create_tag(int data_len){
/* 5 ADDS
   1 DIV, 1 DIV
*/
    int before_loop = 7;
/*
   For loop on data_len/16:
      1 ADD, 4 ANDS, 6 SHIFTS, 2 ORS

      For loop on 5 ---> 5*(1 ADD + 1 INCREASE)

      mult[0] = 4 ADDS, 5 MULTS
      mult[1] = 4 ADDS, 5 MULTS
      mult[2] = 4 ADDS, 5 MULTS
      mult[3] = 4 ADDS, 5 MULTS
      mult[4] = 4 ADDS, 5 MULTS

      For loop on 4
        1 RSHIFT, 1 AND, 2 ADDS
        1 INCREASE
     
      1 RSHIFT, 1 AND, 1 ADD, 1 MUL, 1 RSHIFT, 1 AND, 1 ADD
      -----> TOTAL = 7
*/
    int loop = (data_len/16)*(1+4+6+2 + 5*(2) + 4*(4+5) + 4*(1+1+2+1)) + 7;

/* for loop on 5:
    1 ADD, 1 AND, 1 RSHIFT
    1 INCREASE
    -----> 5*4

    For loop on 4:
      1 RSHIFT, 1 OR, 1 ADD, 1 LSHIFT
       1 SUB, 1 ADD
      1 INCREASE
    -----> 4*(7)

    For loop on 4:
        1 ADD, 1 AND, 1 ADD
        1 RSHIFT
        1 INCREASE
    ----> 4*(5)

    For loop on 4:
        4 MUL, 3 ADDS, 4 ANDS, 3 RSHIFTS
        1 INCREASE
    ---> 4*(15)

*/
    int ops = 5*4 + 4*7 + 4*(5) + 4*(15) + loop + before_loop;
    return ops;
}

int count_inlined_parallel_Horner_create_tag(int data_len){
/*  3 DIVS

    3 * (count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P()) 

    For loop on data_len/(16*4):
        4 * (  1 AND, 1 RSHIFT, 1 AND, 2 SHIFTS, 1 OR, 1 AND, 1 RSHIFT, 1 AND
               2 SHIFTS, 1 OR, 1 AND )
        
        4*(count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P())

        4*(count_ADD_55())

        1 INCREASE
                                     
*/
    int ops_loop = 3 + (data_len/(16*4)) * (4*(13) + 4*(count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P()) + 4*(count_ADD_55()) + 1 );

/* For loop on 4:
        4* count_mulmod_p()
        4* count_add_large_nums_55()
        1 INCREASE

    4 ORS, 7 SHIFTS

    For loop on 4:
        2 ADDS
        1 RSHIFT
        1 INCREASE

    For loop on 4:
        1 MUL, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 increases
*/
    int after_loop = 4*(4*count_mulmod_p()+ 4* count_add_large_nums_55() +1) + 4 + 7 + 4*(4) + 4*(15);

    return after_loop + ops_loop;
}


int count_inlined_carry_delay_parallel_Horner(int data_len){
/*  3 DIVS, 1 MUL

    7* (count_CARRY_PROPAGATION() + count_MUL_MOD_P() + count_COMPUTE_MOD_P())

    For loop on (data_len/(16*8)):
        8 * (  1 AND, 1 RSHIFT, 1 AND, 2 SHIFTS, 1 OR, 1 AND, 1 RSHIFT, 1 AND
               2 SHIFTS, 1 OR, 1 AND )

        4*(count_DOUBLE_MULTIPLICATION_ADDITION + count_CARRY_PROP_DELAYED + count_MOD_P_DELAYED)
*/
    int ops_loop = 3 + 1 + (data_len/(16*8))*(8*(13) + 4*(count_DOUBLE_MULTIPLICATION_ADDITION() + count_CARRY_PROP_DELAYED() + count_MOD_P_DELAYED()));

    /* For loop on 4:
        4* count_mulmod_p()
        4* count_add_large_nums_55()
        1 INCREASE

    4 ORS, 7 SHIFTS

    For loop on 4:
        2 ADDS
        1 RSHIFT
        1 INCREASE

    For loop on 4:
        1 MUL, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 MUL, 1 ADD, 1 RSHIFT, 1 AND
        1 increases
*/
    int after_loop = 4*(4*count_mulmod_p()+ 4* count_add_large_nums_55() +1) + 4 + 7 + 4*(4) + 4*(15);

    return after_loop + ops_loop;
}