#ifndef KYBER_H
#define KYBER_H


#include <stdint.h>
#include "math_utils.h"
#include "ntt.h"

typedef struct {
    int16_t s[K][N]; // secret
    int16_t t[K][N]; // public
    int16_t A[K][K][N];
    uint8_t z[32];
} kyber_keypair;

void keygen(kyber_keypair *kp);
void encapsulate(kyber_keypair *kp, uint8_t *ct, uint8_t *shared_key);
void decapsulate(kyber_keypair *kp, uint8_t *ct, uint8_t *shared_key);


#endif



