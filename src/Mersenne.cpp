#include "Mersenne.hpp"

// Constructor (seeds with default if none given)
Mersenne::Mersenne(uint32_t seed) {
    Seed(seed);
}

// Standard single-value seed
void Mersenne::Seed(uint32_t seed) {
    mt[0] = seed;
    for (uint32_t i = 1; i < MERSENNE_N; ++i) {
        mt[i] = 0x6C078965u * (mt[i-1] ^ (mt[i-1] >> 30)) + i;    
    }
    index = MERSENNE_N;
}

// Twist transformation
void Mersenne::Twist() {
    for (uint32_t i = 0; i < MERSENNE_N; ++i) {
        uint32_t x = (mt[i] & MERSENNE_UPPER_MASK) | (mt[(i + 1) % MERSENNE_N] & MERSENNE_LOWER_MASK);
        uint32_t xA = x >> 1;
        if ((x & 1u) != 0) {
            xA ^= MERSENNE_MATRIX_A;
        }
        mt[i] = mt[(i + MERSENNE_M) % MERSENNE_N] ^ xA;
    }
    index = 0;
}

// Generate next raw 32-bit number
uint32_t Mersenne::Get() {
    if (index >= MERSENNE_N) {
        Twist();
    }
    uint32_t y = mt[index++];
    y ^= (y >> 11);
    y ^= (y << 7)  & 0x9D2C5680u;
    y ^= (y << 15) & 0xEFC60000u;
    y ^= (y >> 18);
    return y;
}
