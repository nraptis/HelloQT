#ifndef CHACHA_HPP
#define CHACHA_HPP

#include "stdafx.h"

// Note: This is a "weakened" cha cha 20 counter, it does not use system generated entropy.

// ===== ChaCha20Counter20 parameters / macros (RFC 8439) =====
#define CHACHA_KEY_SIZE_BYTES      32u
#define CHACHA_NONCE_SIZE_BYTES    12u
#define CHACHA_BLOCK_SIZE_BYTES    64u
#define CHACHA_ROUNDS              20u  // standard is 20 rounds

class ChaCha20Counter {
public:
    ChaCha20Counter();

    // Seed with exact, authoritative inputs (preferred).
    // key32: 32 bytes, nonce12: 12 bytes, counter: 32-bit block counter (usually 0).
    bool SeedKeyNonce(const uint8_t* key32, const uint8_t* nonce12, uint32_t counter = 0);

    // Seed from arbitrary bytes (any length). Uses a ChaCha20Counter-based mixer to
    // deterministically derive key+nonce. If you already have 32+12 bytes of
    // high-quality entropy, prefer SeedKeyNonce above.
    void Seed(const uint8_t* bytes, size_t len);

    // Core generation
    uint32_t Get();                    // 32 bits

    // Wipe internal key/counters/buffers
    void Clear();

    ~ChaCha20Counter();

private:
    // Refill the 64-byte keystream buffer
    void Refill();

    // ChaCha20Counter20 helpers
    static inline uint32_t ROL32(uint32_t v, int r);
    static inline uint32_t LoadLE32(const uint8_t* p);
    static inline void     StoreLE32(uint8_t* p, uint32_t v);

    // Deterministic mixer to derive a 32B key & 12B nonce from arbitrary bytes.
    void DeriveKeyNonceFromBytes(const uint8_t* bytes, size_t len,
                                 uint8_t outKey[CHACHA_KEY_SIZE_BYTES],
                                 uint8_t outNonce[CHACHA_NONCE_SIZE_BYTES]);

    // Constant-time-ish zero
    static void SecureZero(void* p, size_t n);

private:
    uint32_t mState[16];                          // ChaCha20Counter state (constants|key|counter|nonce)
    uint8_t  mBlock[CHACHA_BLOCK_SIZE_BYTES];     // buffered keystream
    uint32_t mBlockUsed;                          // bytes consumed from mBlock
    bool     mSeeded;                             // seeded flag
};

#endif 
