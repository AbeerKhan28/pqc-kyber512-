#ifndef NTT_H
#define NTT_H

#include <stdint.h>
#include "math_utils.h"

void init_ntt(void);
void ntt(int16_t *a);
void intt(int16_t *a);
void poly_mul(int16_t *a, int16_t *b, int16_t *res);

#endif