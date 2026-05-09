#include "kyber.h"
#include "dma_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include "fips202.h"
#include "hardware/structs/rosc.h"

// ====================================================================
// CONSTANT-TIME COMPARISON (Side-Channel Defense)
// Compares two arrays without early-exit branching.
// Returns 0 if identical, non-zero if different.
// ====================================================================
static uint8_t constant_time_cmp(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= (a[i] ^ b[i]); // XOR differences, OR them together
    }
    return result; 
}
// ====================================================================
// 1. HARDWARE TRNG (Raspberry Pi Pico Ring Oscillator)
// ====================================================================
void randombytes(uint8_t *out, size_t outlen) {
    for (size_t i = 0; i < outlen; i++) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++) {
            uint32_t bit = rosc_hw->randombit; 
            byte = (byte << 1) | bit;
        }
        out[i] = byte;
    }
}

// ====================================================================
// 2. STANDARD KYBER MATH HELPERS (CBD & PRF)
// ====================================================================
void kyber_cbd(int16_t *r, const uint8_t *buf) {
    for(int i = 0; i < N; i++) {
        uint8_t byte = buf[i / 2];
        uint8_t bits = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
        uint8_t a0 = bits & 1;
        uint8_t a1 = (bits >> 1) & 1;
        uint8_t b0 = (bits >> 2) & 1;
        uint8_t b1 = (bits >> 3) & 1;
        r[i] = (int16_t)((a0 + a1) - (b0 + b1));
    }
}

void prf_noise(uint8_t *out, const uint8_t *seed, uint8_t nonce) {
    uint8_t ext_seed[33];
    for(int i=0; i<32; i++) ext_seed[i] = seed[i];
    ext_seed[32] = nonce; 
    shake256(out, 128, ext_seed, 33);
}

// 1. Compress a coefficient from Q (3329) down to 'd' bits
uint16_t compress_coeff(uint16_t x, int d) {
    // Standard ML-KEM Formula: round((x * 2^d) / Q) mod 2^d
    uint32_t temp = ((uint32_t)x << d) + (3329 / 2);
    return (temp / 3329) & ((1 << d) - 1);
}

// 2. Decompress a coefficient from 'd' bits back to Q (3329)
uint16_t decompress_coeff(uint16_t x, int d) {
    // Standard ML-KEM Formula: round((x * Q) / 2^d)
    uint32_t temp = ((uint32_t)x * 3329) + (1 << (d - 1));
    return temp >> d;
}
// ====================================================================
// 3. KEY GENERATION (Alice)
// ====================================================================
void keygen(kyber_keypair *kp) {
    int16_t e[K][N]; 

    // A. Seed Expansion (Hardware TRNG -> SHA3-512)
    uint8_t d[32];
    randombytes(d, 32); 
    uint8_t hashed_seeds[64];
    sha3_512(hashed_seeds, d, 32); 
    uint8_t *public_seed = hashed_seeds;      
    uint8_t *noise_seed = hashed_seeds + 32;  

    // B. Generate Secret (s) and Error (e) with CBD + Nonces
    uint8_t noise_buf[128]; 
    uint8_t nonce = 0; 
    for(int i=0; i<K; i++) {
        prf_noise(noise_buf, noise_seed, nonce++);
        kyber_cbd(kp->s[i], noise_buf);
        
        prf_noise(noise_buf, noise_seed, nonce++);
        kyber_cbd(e[i], noise_buf);
    }

    // C. Generate Matrix A (SHAKE-128 Rejection Sampling)
    uint8_t a_buf[4096]; 
    shake128(a_buf, sizeof(a_buf), public_seed, 32);
    int a_idx = 0;
    for(int i=0; i<K; i++) {
        for(int j=0; j<K; j++) {
            int x = 0;
            while(x < N) {
                uint16_t val = (a_buf[a_idx] | (a_buf[a_idx+1] << 8)) & 0x0FFF; 
                a_idx += 2;
                if (val < 3329) {
                    kp->A[i][j][x] = val;
                    x++;
                }
            }
        }
    }

    // D. Calculate Public Key: t = A * s + e
    for(int i=0; i<K; i++) {
        for(int x=0; x<N; x++) kp->t[i][x] = e[i][x];
        for(int j=0; j<K; j++) {
            int16_t temp_poly[N];
            poly_mul(kp->A[i][j], kp->s[j], temp_poly);
            for(int x=0; x<N; x++) kp->t[i][x] = mod_q(kp->t[i][x] + temp_poly[x]);
        }
    }
    // Generate the Implicit Rejection Seed (z)
    for(int i = 0; i < 32; i++) {
        uint8_t random_byte = 0;
        for(int b = 0; b < 8; b++) {
            random_byte = (random_byte << 1) | (rosc_hw->randombit & 1);
        }
        kp->z[i] = random_byte;
    }
}


// ====================================================================
// 4. ENCAPSULATION (Bob)
// ====================================================================
void encapsulate(kyber_keypair *pk, uint8_t *ct, uint8_t *shared_key) {
    int16_t u[K][N];
    int16_t v[N];
    int16_t r[K][N], e1[K][N], e2[N];

    // A. Generate True Random Message
    uint8_t m[32];
    randombytes(m, 32); 

    // B. Generate Noise with CBD + Nonces
    uint8_t noise_buf[128]; 
    uint8_t nonce = 0; 
    for(int i=0; i<K; i++) {
        prf_noise(noise_buf, m, nonce++);
        kyber_cbd(r[i], noise_buf);
        
        prf_noise(noise_buf, m, nonce++);
        kyber_cbd(e1[i], noise_buf);
    }
    prf_noise(noise_buf, m, nonce++);
    kyber_cbd(e2, noise_buf);

    // C. Matrix Math for u: u = A^T * r + e1
    for(int i=0; i<K; i++) {
        for(int x=0; x<N; x++) u[i][x] = e1[i][x];
        for(int j=0; j<K; j++) {
            int16_t temp_poly[N];
            poly_mul(pk->A[j][i], r[j], temp_poly); 
            for(int x=0; x<N; x++) u[i][x] = mod_q(u[i][x] + temp_poly[x]);
        }
    }

    // D. Math for v: v = t^T * r + e2 + m
    for(int x=0; x<N; x++) v[x] = e2[x];
    for(int i=0; i<K; i++) {
        int16_t temp_poly[N];
        poly_mul(pk->t[i], r[i], temp_poly);
        for(int x=0; x<N; x++) v[x] = mod_q(v[x] + temp_poly[x]);
    }
    for(int i=0; i<N; i++) { 
        int bit = (m[i / 8] >> (i % 8)) & 1;
        v[i] = mod_q(v[i] + (bit * 1665)); 
    }
    
    // E. Key Derivation
    sha3_256(shared_key, m, 32);


    // ====================================================================
    // NEW: COMPRESS AND PACK INTO CIPHERTEXT (ct)
    // ====================================================================
    int offset = 0;

    // 1. Compress Vector U (10 bits)
    for(int i = 0; i < K; i++) {
        for(int j = 0; j < N / 4; j++) {
            uint16_t t0 = compress_coeff(u[i][4*j + 0], 10);
            uint16_t t1 = compress_coeff(u[i][4*j + 1], 10);
            uint16_t t2 = compress_coeff(u[i][4*j + 2], 10);
            uint16_t t3 = compress_coeff(u[i][4*j + 3], 10);

            ct[offset++] = (t0 >> 0);
            ct[offset++] = (t0 >> 8) | (t1 << 2);
            ct[offset++] = (t1 >> 6) | (t2 << 4);
            ct[offset++] = (t2 >> 4) | (t3 << 6);
            ct[offset++] = (t3 >> 2);
        }
    }

    // 2. Compress Vector V (4 bits)
    for(int j = 0; j < N / 2; j++) {
        uint16_t t0 = compress_coeff(v[2*j + 0], 4);
        uint16_t t1 = compress_coeff(v[2*j + 1], 4);
        ct[offset++] = t0 | (t1 << 4);
    }

}

// ====================================================================
// 5. DECAPSULATION (Alice)
// ====================================================================
void decapsulate(kyber_keypair *kp, uint8_t *ct, uint8_t *shared_key) {
    int16_t u[K][N];
    int16_t v[N];
    for(int i=0; i<32; i++) shared_key[i] = 0;

   // NEW: UNPACK AND DECOMPRESS FROM CIPHERTEXT (ct)
    // ====================================================================
    int offset = 0;

    // 1. Unpack Vector U (10 bits back to 3329)
    for(int i = 0; i < K; i++) {
        for(int j = 0; j < N / 4; j++) {
            uint8_t b0 = ct[offset++];
            uint8_t b1 = ct[offset++];
            uint8_t b2 = ct[offset++];
            uint8_t b3 = ct[offset++];
            uint8_t b4 = ct[offset++];

            uint16_t t0 = (b0 >> 0) | ((uint16_t)(b1 & 0x03) << 8);
            uint16_t t1 = (b1 >> 2) | ((uint16_t)(b2 & 0x0F) << 6);
            uint16_t t2 = (b2 >> 4) | ((uint16_t)(b3 & 0x3F) << 4);
            uint16_t t3 = (b3 >> 6) | ((uint16_t)(b4 & 0xFF) << 2);

            u[i][4*j + 0] = decompress_coeff(t0, 10);
            u[i][4*j + 1] = decompress_coeff(t1, 10);
            u[i][4*j + 2] = decompress_coeff(t2, 10);
            u[i][4*j + 3] = decompress_coeff(t3, 10);
        }
    }

    // 2. Unpack Vector V (4 bits back to 3329)
    for(int j = 0; j < N / 2; j++) {
        uint8_t b0 = ct[offset++];
        uint16_t t0 = b0 & 0x0F;
        uint16_t t1 = b0 >> 4;

        v[2*j + 0] = decompress_coeff(t0, 4);
        v[2*j + 1] = decompress_coeff(t1, 4);
    }

    // A. Recover Message (m_prime)
    int16_t s_u[N] = {0};
    for(int i=0; i<K; i++) {
        int16_t temp_poly[N];
        poly_mul(kp->s[i], u[i], temp_poly);
        for(int x=0; x<N; x++) s_u[x] = mod_q(s_u[x] + temp_poly[x]);
    }

    uint8_t m_prime[32] = {0};
    for(int i=0; i<N; i++) {
        int16_t msg_bit = mod_q(v[i] - s_u[i]);
        int bit = (((msg_bit << 1) + 1664) / 3329) & 1; 
        m_prime[i / 8] |= (bit << (i % 8));
    }

    // B. FUJISAKI-OKAMOTO RE-ENCRYPTION TRANSFORM
    int16_t u_prime[K][N], v_prime[N], r[K][N], e1[K][N], e2[N];
    uint8_t noise_buf[128]; 
    uint8_t nonce = 0; 

    // Re-create Bob's exact CBD Noise
    for(int i=0; i<K; i++) {
        prf_noise(noise_buf, m_prime, nonce++);
        kyber_cbd(r[i], noise_buf);
        
        prf_noise(noise_buf, m_prime, nonce++);
        kyber_cbd(e1[i], noise_buf);
    }
    prf_noise(noise_buf, m_prime, nonce++);
    kyber_cbd(e2, noise_buf);

    // Re-calculate u' = A^T * r + e1
    for(int i=0; i<K; i++) {
        for(int x=0; x<N; x++) u_prime[i][x] = e1[i][x];
        for(int j=0; j<K; j++) {
            int16_t temp_poly[N];
            poly_mul(kp->A[j][i], r[j], temp_poly);
            for(int x=0; x<N; x++) u_prime[i][x] = mod_q(u_prime[i][x] + temp_poly[x]);
        }
    }

    // Re-calculate v' = t^T * r + e2 + m_prime
    for(int x=0; x<N; x++) v_prime[x] = e2[x];
    for(int i=0; i<K; i++) {
        int16_t temp_poly[N];
        poly_mul(kp->t[i], r[i], temp_poly);
        for(int x=0; x<N; x++) v_prime[x] = mod_q(v_prime[x] + temp_poly[x]);
    }
    for(int i=0; i<N; i++) { 
        int bit = (m_prime[i / 8] >> (i % 8)) & 1;
        v_prime[i] = mod_q(v_prime[i] + (bit * 1665)); 
    }

    // C. The Verification Check (FIXED FOR COMPRESSION)
    int check_failed = 0;
    uint8_t ct_prime[768];
    int offset_prime = 0;

    // 1. Compress Vector u_prime (10 bits)
    for(int i = 0; i < K; i++) {
        for(int j = 0; j < N / 4; j++) {
            uint16_t t0 = compress_coeff(u_prime[i][4*j + 0], 10);
            uint16_t t1 = compress_coeff(u_prime[i][4*j + 1], 10);
            uint16_t t2 = compress_coeff(u_prime[i][4*j + 2], 10);
            uint16_t t3 = compress_coeff(u_prime[i][4*j + 3], 10);

            ct_prime[offset_prime++] = (t0 >> 0);
            ct_prime[offset_prime++] = (t0 >> 8) | (t1 << 2);
            ct_prime[offset_prime++] = (t1 >> 6) | (t2 << 4);
            ct_prime[offset_prime++] = (t2 >> 4) | (t3 << 6);
            ct_prime[offset_prime++] = (t3 >> 2);
        }
    }

    // 2. Compress Vector v_prime (4 bits)
    for(int j = 0; j < N / 2; j++) {
        uint16_t t0 = compress_coeff(v_prime[2*j + 0], 4);
        uint16_t t1 = compress_coeff(v_prime[2*j + 1], 4);
        ct_prime[offset_prime++] = t0 | (t1 << 4);
    }

    // Compare the original received ct with our re-encrypted ct_prime
    // SECURE CONSTANT-TIME PATCH
    check_failed = constant_time_cmp(ct, ct_prime, 768);
//====================================================================
    // D. NEW: IMPLICIT REJECTION & DOMAIN SEPARATION
    // ====================================================================
    // 1. Hash the 768-byte Ciphertext directly!
    uint8_t hashed_ct[32];
    sha3_256(hashed_ct, ct, 768); 

    // 2. Generate the "Valid" Key from the recovered message
    uint8_t valid_key[32];
    sha3_256(valid_key, m_prime, 32);

    // 3. Generate the "Junk" Key using Alice's secret 'z'
    uint8_t junk_key[32];
    uint8_t junk_buffer[64];
    for(int i = 0; i < 32; i++) junk_buffer[i] = kp->z[i];
    for(int i = 0; i < 32; i++) junk_buffer[i + 32] = hashed_ct[i];
    sha3_256(junk_key, junk_buffer, 64);

    // 4. The Secure Constant-Time Move (CMOV)
    uint8_t mask = -(uint8_t)check_failed; 
    for(int i = 0; i < 32; i++) {
        shared_key[i] = (valid_key[i] & ~mask) | (junk_key[i] & mask);
    }
}