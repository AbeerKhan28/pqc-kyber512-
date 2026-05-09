#include "ntt.h"
#include "math_utils.h"

int16_t W[128];           // Zetas (Twiddle factors) for NTT
int16_t odd_powers[128];  // Precomputed Zetas for Base Multiplication

// ====================================================================
//  Safe Modulo 
// ====================================================================
int16_t safe_mod(int32_t x) {
    int32_t r = x % Q;
    // If r is negative, mask becomes 0xFFFFFFFF. If positive, 0x00000000.
    int32_t mask = r >> 31; 
    
    // If negative, this adds Q. If positive, it adds 0.
    r += (mask & Q); 
    
    return (int16_t)r;
}

// 7-bit bit reversal for standard Kyber Butterfly
uint8_t bitrev7(uint8_t x) {
    uint8_t r = 0;
    for (int i = 0; i < 7; i++) {
        r |= ((x >> i) & 1) << (6 - i);
    }
    return r;
}

// ====================================================================
// Standard Kyber Zeta Initialization
// ====================================================================
void init_ntt() {
    int32_t current = 1;
    int16_t powers[128];
    
    for(int i = 0; i < 128; i++) {
        powers[i] = current;
        current = safe_mod(current * 17); 
    }
    
    for(int i = 0; i < 128; i++) {
        W[i] = powers[bitrev7(i)];
    }

    current = 17; 
    for(int i = 0; i < 128; i++) {
        odd_powers[i] = current;
        current = safe_mod(current * 17);
        current = safe_mod(current * 17); 
    }
}

int16_t mul_mod(int16_t a, int16_t b) {
    return safe_mod((int32_t)a * b);
}

// ====================================================================
// Standard Kyber Cooley-Tukey Butterfly NTT
// ====================================================================
void ntt(int16_t *a) {
    int len, start, j, k;
    int16_t zeta, t;
    
    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < N; start = j + len) {
            zeta = W[k++]; 
            for (j = start; j < start + len; j++) {
                t = mul_mod(zeta, a[j + len]);
                a[j + len] = safe_mod(a[j] - t);
                a[j] = safe_mod(a[j] + t);
            }
        }
    }
}

// ====================================================================
// Standard Kyber Gentleman-Sande Butterfly INTT
// ====================================================================
void intt(int16_t *a) {
    int len, start, j, k;
    int16_t zeta, t;
    
    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < N; start = j + len) {
            zeta = W[k--]; 
            for (j = start; j < start + len; j++) {
                t = a[j];
                a[j] = safe_mod(t + a[j + len]);
                // FIX: Kyber requires subtracting top from bottom!
                a[j + len] = safe_mod(a[j + len] - t);
                a[j + len] = mul_mod(zeta, a[j + len]);
            }
        }
    }
    
    // Scale by 128^-1 mod 3329 (which is exactly 3303)
    for (j = 0; j < N; j++) {
        a[j] = mul_mod(a[j], 3303);
    }
}

// ====================================================================
// Standard Kyber Base Multiplication Drop-In Replacement
// ====================================================================
void poly_mul(int16_t *a, int16_t *b, int16_t *res) {
    int16_t a_ntt[N], b_ntt[N];
    
    for(int i = 0; i < N; i++) {
        a_ntt[i] = a[i];
        b_ntt[i] = b[i];
    }
    
    ntt(a_ntt);
    ntt(b_ntt);
    
    for(int i = 0; i < 128; i++) {
        int16_t zeta = odd_powers[bitrev7(i)];
        
        int16_t a0 = a_ntt[2*i];
        int16_t a1 = a_ntt[2*i + 1];
        int16_t b0 = b_ntt[2*i];
        int16_t b1 = b_ntt[2*i + 1];
        
        res[2*i]     = safe_mod(mul_mod(a0, b0) + mul_mod(mul_mod(a1, b1), zeta));
        res[2*i + 1] = safe_mod(mul_mod(a0, b1) + mul_mod(a1, b0));
    }
    
    intt(res);
}