#ifndef AESCOUNTER_HPP
#define AESCOUNTER_HPP

#include "stdafx.h"
#include <cstdint>
#include <cstddef>

// ===== AES-CTR parameters / macros =====
#define AES_KEY_SIZE_BYTES      32u   // AES-256
#define AES_BLOCK_SIZE_BYTES    16u
#define AES_ROUNDS              14u   // AES-256 -> 14 rounds
#define AES_ROUND_KEYS_WORDS    60u   // 4 * (Nr + 1) = 4 * 15 = 60

class AESCounter {
public:
    AESCounter();

    // Seed with authoritative inputs (preferred):
    // key32: 32 bytes (AES-256 key)
    // iv16 : 16 bytes (initial counter block, usually nonce||counter)
    // counter: starting 32-bit counter to be injected into the last 4 bytes of the IV (big-endian)
    bool SeedKeyIV(const uint8_t* key32, const uint8_t* iv16, uint32_t counter = 0);

    // Seed from arbitrary bytes (any length).
    // Deterministically derives (key, iv) via an AES-based mixing routine (no external hashes).
    void Seed(const uint8_t* bytes, size_t len);

    // Core generation
    uint32_t Get();    // 32 bits

    // Zeroize keys and internal buffers
    void Clear();
    ~AESCounter();

private:
    // ===== AES internals =====
    void ExpandKey256(const uint8_t key[AES_KEY_SIZE_BYTES]); // sets mRoundKeys and mRoundCount
    void EncryptBlock(const uint8_t in[AES_BLOCK_SIZE_BYTES],
                      uint8_t out[AES_BLOCK_SIZE_BYTES]) const;

    // CTR machinery
    void Refill();                       // refill mBuf with fresh keystream
    void IncrementCounter();             // 128-bit big-endian increment of mCounter
    static inline uint32_t LoadBE32(const uint8_t* p);
    static inline void     StoreBE32(uint8_t* p, uint32_t v);

    // Derive (key, iv) from arbitrary bytes (no external libs)
    void DeriveKeyIVFromBytes(const uint8_t* bytes, size_t len,
                              uint8_t outKey[AES_KEY_SIZE_BYTES],
                              uint8_t outIV[AES_BLOCK_SIZE_BYTES]);

    static void SecureZero(void* p, size_t n);

private:
    // Expanded round keys (AES-256 -> 60 x 32-bit words)
    uint32_t mRoundKeys[AES_ROUND_KEYS_WORDS];
    uint32_t mRoundCount; // number of rounds (14)

    // 128-bit counter block (IV || counter), big-endian increment
    uint8_t  mCounter[AES_BLOCK_SIZE_BYTES];

    // Small keystream buffer (64 bytes = 4 blocks) to amortize EncryptBlock calls
    uint8_t  mBuf[64];
    uint32_t mBufUsed; // bytes already consumed in mBuf

    bool     mSeeded;
};

#endif // AESCOUNTER_HPP
