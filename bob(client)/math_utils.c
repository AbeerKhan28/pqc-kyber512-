#include "math_utils.h"
#include <stdlib.h>

#define R 512          // 2^9
#define R_BITS 9
#define QINV 255      

// Branchless, constant-time modulo for Q=3329
int16_t mod_q(int32_t x) {
    // 1. Large offset to ensure x is positive (handles large negatives from N=256)
    int32_t val = x + 3329000; 
    
    // 2. Division-less Barrett reduction for Q=3329
    int32_t q = ((int64_t)val * 5039) >> 24; 
    int32_t res = val - (q * 3329);
    
    // 3. Constant-time bitwise fixup
    int32_t mask = (res - 3329) >> 31; 
    res -= 3329 & (~mask); 
    
    return (int16_t)res;
}

// Constant-time random generation without the modulo operator
int16_t small_random() {
    uint32_t r = rand();
    int val = r & 3; // Get values 0, 1, 2, or 3
    
    // Branchlessly convert 3 to 0 to maintain our -1, 0, 1 range
    val = val ^ (3 & -(val == 3)); 
    
    return val - 1; // Map 0->-1, 1->0, 2->1
}

// ... vector_add, vector_sub, vector_copy remain exactly the same
void vector_add(int16_t *a, int16_t *b, int16_t *res, int size) {
    for(int i=0;i<size;i++) res[i] = mod_q(a[i]+b[i]);
}

void vector_sub(int16_t *a, int16_t *b, int16_t *res, int size) {
    for(int i=0;i<size;i++) res[i] = mod_q(a[i]-b[i]);
}

void vector_copy(int16_t *src, int16_t *dst, int size){
    for(int i=0;i<size;i++) dst[i] = src[i];
}

int16_t montgomery_reduce(int32_t t) {
    int32_t m = (t * QINV) & (R - 1);   // mod R (bitmask)
    int32_t u = (t + (int32_t)m * Q) >> R_BITS;  // divide by R
    
   int32_t mask = (u - Q) >> 31;
    u -= Q & (~mask); 
    return (int16_t)u;

}