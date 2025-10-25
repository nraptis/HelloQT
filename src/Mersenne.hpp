#ifndef MERSENNE_HPP
#define MERSENNE_HPP

#include "stdafx.h"

// Mersenne Twister MT19937 parameters
#define MERSENNE_N          624
#define MERSENNE_M          397
#define MERSENNE_MATRIX_A   0x9908B0DFu
#define MERSENNE_UPPER_MASK 0x80000000u
#define MERSENNE_LOWER_MASK 0x7FFFFFFFu

class Mersenne {
public:
    // Constructors
    Mersenne(uint32_t seed = 5489u);
    void Seed(uint32_t seed);

    // Core generation
    uint32_t Get();
    

private:
    void Twist(); // state transition

    uint32_t mt[MERSENNE_N];
    uint32_t index;
};

#endif
