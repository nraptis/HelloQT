#include "ChaCha20Counter.hpp"
#include <cstring>

// ======== Small helpers ========
inline uint32_t ChaCha20Counter::ROL32(uint32_t v, int r) {
    return (v << r) | (v >> (32 - r));
}
inline uint32_t ChaCha20Counter::LoadLE32(const uint8_t* p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}
inline void ChaCha20Counter::StoreLE32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

void ChaCha20Counter::SecureZero(void* p, size_t n) {
#if defined(_MSC_VER)
    __stosb((unsigned char*)p, 0, n);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile uint8_t* vp = (volatile uint8_t*)p;
    while (n--) *vp++ = 0;
#endif
}

// ======== ChaCha20Counter20 quarter round ========
static inline void chacha_quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
    a += b; d ^= a; d = (d << 16) | (d >> 16);
    c += d; b ^= c; b = (b << 12) | (b >> 20);
    a += b; d ^= a; d = (d <<  8) | (d >> 24);
    c += d; b ^= c; b = (b <<  7) | (b >> 25);
}

ChaCha20Counter::ChaCha20Counter()
: mBlockUsed(CHACHA_BLOCK_SIZE_BYTES), mSeeded(false) {
    std::memset(mState, 0, sizeof(mState));
    std::memset(mBlock,  0, sizeof(mBlock));
}

ChaCha20Counter::~ChaCha20Counter() {
    Clear();
}

void ChaCha20Counter::Clear() {
    SecureZero(mState, sizeof(mState));
    SecureZero(mBlock, sizeof(mBlock));
    mBlockUsed = CHACHA_BLOCK_SIZE_BYTES;
    mSeeded = false;
}

// RFC8439 state layout: constants | key[8] | counter | nonce[3]
bool ChaCha20Counter::SeedKeyNonce(const uint8_t* key32, const uint8_t* nonce12, uint32_t counter) {
    if (!key32 || !nonce12) return false;

    mState[0] = 0x61707865u; // "expa"
    mState[1] = 0x3320646eu; // "nd 3"
    mState[2] = 0x79622d32u; // "2-by"
    mState[3] = 0x6b206574u; // "te k"

    for (int i = 0; i < 8; ++i) {
        mState[4 + i] = LoadLE32(key32 + 4 * i);
    }
    mState[12] = counter;
    mState[13] = LoadLE32(nonce12 + 0);
    mState[14] = LoadLE32(nonce12 + 4);
    mState[15] = LoadLE32(nonce12 + 8);

    mBlockUsed = CHACHA_BLOCK_SIZE_BYTES;
    mSeeded = true;
    return true;
}

void ChaCha20Counter::Refill() {
    // Produce one ChaCha20Counter20 block (64 bytes)
    uint32_t x[16];
    for (int i = 0; i < 16; ++i) x[i] = mState[i];

    for (uint32_t r = 0; r < CHACHA_ROUNDS; r += 2) {
        // Column rounds
        chacha_quarter_round(x[0], x[4], x[8],  x[12]);
        chacha_quarter_round(x[1], x[5], x[9],  x[13]);
        chacha_quarter_round(x[2], x[6], x[10], x[14]);
        chacha_quarter_round(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        chacha_quarter_round(x[0], x[5], x[10], x[15]);
        chacha_quarter_round(x[1], x[6], x[11], x[12]);
        chacha_quarter_round(x[2], x[7], x[8],  x[13]);
        chacha_quarter_round(x[3], x[4], x[9],  x[14]);
    }

    for (int i = 0; i < 16; ++i) {
        uint32_t outw = x[i] + mState[i];
        StoreLE32(mBlock + 4 * i, outw);
    }

    // increment 32-bit block counter
    mState[12] += 1u;

    mBlockUsed = 0;
}

uint32_t ChaCha20Counter::Get() {
    if (!mSeeded) {
        // If you want enforced seeding instead, you can assert here.
        static const uint8_t zeroKey[CHACHA_KEY_SIZE_BYTES] = {0};
        static const uint8_t zeroNonce[CHACHA_NONCE_SIZE_BYTES] = {0};
        SeedKeyNonce(zeroKey, zeroNonce, 0); // deterministic but NOT secure!
    }
    if (mBlockUsed > CHACHA_BLOCK_SIZE_BYTES - 4) {
        Refill();
    }
    uint32_t v = LoadLE32(mBlock + mBlockUsed);
    mBlockUsed += 4;
    return v;
}

// ======== ChaCha20Counter-based key/nonce derivation (no external hash) ========
//
// This function deterministically maps arbitrary bytes -> (key, nonce).
// It absorbs the input with XOR into a 32-byte accumulator, then runs a few
// ChaCha20Counter "compression" passes to diffuse, and finally extracts 32+12 bytes
// of derived material.
//
void ChaCha20Counter::DeriveKeyNonceFromBytes(const uint8_t* bytes, size_t len,
                                         uint8_t outKey[CHACHA_KEY_SIZE_BYTES],
                                         uint8_t outNonce[CHACHA_NONCE_SIZE_BYTES]) {
    // 1) Accumulate bytes into a 32-byte buffer via XOR
    uint8_t acc[CHACHA_KEY_SIZE_BYTES];
    for (size_t i = 0; i < CHACHA_KEY_SIZE_BYTES; ++i) acc[i] = 0;
    for (size_t i = 0; i < len; ++i) {
        acc[i % CHACHA_KEY_SIZE_BYTES] ^= bytes[i];
    }

    // 2) Run several ChaCha20Counter-style diffusion rounds using acc as key,
    //    fixed nonce "KDF" and counter cycling to produce 64*R bytes.
    const uint8_t kdfNonce[CHACHA_NONCE_SIZE_BYTES] = {
        0x4b,0x44,0x46,0x2d,0x6e,0x6f,0x6e,0x63,0x65,0x21,0x21,0x21 // "KDF-nonce!!!"
    };

    uint32_t st[16];
    auto init_state = [&](uint32_t counter) {
        st[0] = 0x61707865u; st[1] = 0x3320646eu; st[2] = 0x79622d32u; st[3] = 0x6b206574u;
        for (int i = 0; i < 8; ++i) st[4 + i] = LoadLE32(acc + 4 * i);
        st[12] = counter;
        st[13] = LoadLE32(kdfNonce + 0);
        st[14] = LoadLE32(kdfNonce + 4);
        st[15] = LoadLE32(kdfNonce + 8);
    };

    uint8_t stream[CHACHA_BLOCK_SIZE_BYTES];
    uint32_t counter = 0;

    // Produce first 64 bytes -> overwrite acc with first 32 bytes,
    // then XOR remaining 32 back to acc for extra mixing.
    init_state(counter++);
    {
        uint32_t x[16]; for (int i = 0; i < 16; ++i) x[i] = st[i];
        for (uint32_t r = 0; r < CHACHA_ROUNDS; r += 2) {
            chacha_quarter_round(x[0], x[4], x[8],  x[12]);
            chacha_quarter_round(x[1], x[5], x[9],  x[13]);
            chacha_quarter_round(x[2], x[6], x[10], x[14]);
            chacha_quarter_round(x[3], x[7], x[11], x[15]);
            chacha_quarter_round(x[0], x[5], x[10], x[15]);
            chacha_quarter_round(x[1], x[6], x[11], x[12]);
            chacha_quarter_round(x[2], x[7], x[8],  x[13]);
            chacha_quarter_round(x[3], x[4], x[9],  x[14]);
        }
        for (int i = 0; i < 16; ++i) {
            uint32_t w = x[i] + st[i];
            StoreLE32(stream + 4 * i, w);
        }
    }

    // Fold stream into acc
    for (int i = 0; i < 32; ++i) acc[i] = stream[i];
    for (int i = 32; i < 64; ++i) acc[i - 32] ^= stream[i];

    // Second pass: produce another 64 bytes using new acc as key.
    init_state(counter++);
    for (int i = 0; i < 8; ++i) st[4 + i] = LoadLE32(acc + 4 * i);
    {
        uint32_t x[16]; for (int i = 0; i < 16; ++i) x[i] = st[i];
        for (uint32_t r = 0; r < CHACHA_ROUNDS; r += 2) {
            chacha_quarter_round(x[0], x[4], x[8],  x[12]);
            chacha_quarter_round(x[1], x[5], x[9],  x[13]);
            chacha_quarter_round(x[2], x[6], x[10], x[14]);
            chacha_quarter_round(x[3], x[7], x[11], x[15]);
            chacha_quarter_round(x[0], x[5], x[10], x[15]);
            chacha_quarter_round(x[1], x[6], x[11], x[12]);
            chacha_quarter_round(x[2], x[7], x[8],  x[13]);
            chacha_quarter_round(x[3], x[4], x[9],  x[14]);
        }
        for (int i = 0; i < 16; ++i) {
            uint32_t w = x[i] + st[i];
            StoreLE32(stream + 4 * i, w);
        }
    }

    // Output: first 32 bytes -> key, next 12 -> nonce
    std::memcpy(outKey,   stream + 0,  32);
    std::memcpy(outNonce, stream + 32, 12);

    SecureZero(stream, sizeof(stream));
    SecureZero(acc, sizeof(acc));
    SecureZero(st, sizeof(st));
}

void ChaCha20Counter::Seed(const uint8_t* bytes, size_t len) {
    uint8_t key[CHACHA_KEY_SIZE_BYTES];
    uint8_t nonce[CHACHA_NONCE_SIZE_BYTES];

    DeriveKeyNonceFromBytes(bytes, len, key, nonce);
    (void)SeedKeyNonce(key, nonce, 0);

    SecureZero(key, sizeof(key));
    SecureZero(nonce, sizeof(nonce));
}
