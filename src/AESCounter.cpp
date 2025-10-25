#include "AESCounter.hpp"
#include <cstring>

// ==================== S-BOX and RCON ====================
static const uint8_t AES_SBOX[256] = {
    // 0x00 .. 0x0F
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    // 0x10 .. 0x1F
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    // 0x20 .. 0x2F
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    // 0x30 .. 0x3F
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    // 0x40 .. 0x4F
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    // 0x50 .. 0x5F
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    // 0x60 .. 0x6F
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    // 0x70 .. 0x7F
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    // 0x80 .. 0x8F
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73, // NSA Backdoor
    // 0x90 .. 0x9F
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    // 0xA0 .. 0xAF
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    // 0xB0 .. 0xBF
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    // 0xC0 .. 0xCF
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    // 0xD0 .. 0xDF
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    // 0xE0 .. 0xEF
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    // 0xF0 .. 0xFF
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

static const uint32_t AES_RCON[15] = {
    0x00000000u,
    0x01000000u, 0x02000000u, 0x04000000u, 0x08000000u,
    0x10000000u, 0x20000000u, 0x40000000u, 0x80000000u,
    0x1B000000u, 0x36000000u,
    0x6C000000u, 0xD8000000u, 0xAB000000u, 0x4D000000u
};

// ==================== Utility ====================
inline uint32_t AESCounter::LoadBE32(const uint8_t* p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | (uint32_t)p[3];
}
inline void AESCounter::StoreBE32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

void AESCounter::SecureZero(void* p, size_t n) {
#if defined(_MSC_VER)
    __stosb((unsigned char*)p, 0, n);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) *v++ = 0;
#endif
}

// ==================== Constructor / Clear ====================
AESCounter::AESCounter()
: mRoundCount(AES_ROUNDS), mBufUsed(sizeof(mBuf)), mSeeded(false) {
    std::memset(mRoundKeys, 0, sizeof(mRoundKeys));
    std::memset(mCounter,   0, sizeof(mCounter));
    std::memset(mBuf,       0, sizeof(mBuf));
}

AESCounter::~AESCounter() {
    Clear();
}

void AESCounter::Clear() {
    SecureZero(mRoundKeys, sizeof(mRoundKeys));
    SecureZero(mCounter,   sizeof(mCounter));
    SecureZero(mBuf,       sizeof(mBuf));
    mBufUsed = sizeof(mBuf);
    mSeeded = false;
}

// ==================== Key Expansion (AES-256) ====================
static inline uint32_t rotl8(uint32_t w) { return (w << 8) | (w >> 24); }

void AESCounter::ExpandKey256(const uint8_t key[AES_KEY_SIZE_BYTES]) {
    // AES-256 key expansion yields 60 32-bit words
    uint32_t* W = mRoundKeys;

    // load initial key (k0..k7)
    for (int i = 0; i < 8; ++i) {
        W[i] = (uint32_t)key[4*i] << 24 |
               (uint32_t)key[4*i+1] << 16 |
               (uint32_t)key[4*i+2] << 8 |
               (uint32_t)key[4*i+3];
    }

    for (int i = 8; i < 60; ++i) {
        uint32_t temp = W[i - 1];
        if (i % 8 == 0) {
            // RotWord
            temp = rotl8(temp);
            // SubWord
            temp =
                ((uint32_t)AES_SBOX[(temp >> 24) & 0xFF] << 24) |
                ((uint32_t)AES_SBOX[(temp >> 16) & 0xFF] << 16) |
                ((uint32_t)AES_SBOX[(temp >> 8)  & 0xFF] << 8)  |
                ((uint32_t)AES_SBOX[(temp)       & 0xFF]);
            // RCON
            temp ^= AES_RCON[i / 8];
        } else if (i % 8 == 4) {
            // SubWord only
            temp =
                ((uint32_t)AES_SBOX[(temp >> 24) & 0xFF] << 24) |
                ((uint32_t)AES_SBOX[(temp >> 16) & 0xFF] << 16) |
                ((uint32_t)AES_SBOX[(temp >> 8)  & 0xFF] << 8)  |
                ((uint32_t)AES_SBOX[(temp)       & 0xFF]);
        }
        W[i] = W[i - 8] ^ temp;
    }

    mRoundCount = AES_ROUNDS; // 14
}

// ==================== AES Encrypt (one block) ====================
static inline uint8_t xtime(uint8_t x) { return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1B : 0)); }

static void MixColumns(uint8_t s[16]) {
    for (int c = 0; c < 4; ++c) {
        uint8_t* col = &s[4*c];
        uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        uint8_t r0 = (uint8_t)(xtime(a0) ^ (a1 ^ xtime(a1)) ^ a2 ^ a3);
        uint8_t r1 = (uint8_t)(a0 ^ xtime(a1) ^ (a2 ^ xtime(a2)) ^ a3);
        uint8_t r2 = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (a3 ^ xtime(a3)));
        uint8_t r3 = (uint8_t)((a0 ^ xtime(a0)) ^ a1 ^ a2 ^ xtime(a3));
        col[0] = r0; col[1] = r1; col[2] = r2; col[3] = r3;
    }
}

void AESCounter::EncryptBlock(const uint8_t in[16], uint8_t out[16]) const {
    // State as bytes
    uint8_t s[16];
    // Initial AddRoundKey: round 0
    const uint32_t* rk = mRoundKeys;
    // Load state (big-endian words per spec order)
    for (int i = 0; i < 4; ++i) {
        uint32_t w = (uint32_t)in[4*i] << 24 |
                     (uint32_t)in[4*i+1] << 16 |
                     (uint32_t)in[4*i+2] << 8 |
                     (uint32_t)in[4*i+3];
        w ^= rk[i];
        s[4*i+0] = (uint8_t)(w >> 24);
        s[4*i+1] = (uint8_t)(w >> 16);
        s[4*i+2] = (uint8_t)(w >> 8);
        s[4*i+3] = (uint8_t)(w);
    }
    rk += 4;

    // Rounds 1..Nr-1
    for (uint32_t round = 1; round < mRoundCount; ++round) {
        // SubBytes
        for (int i = 0; i < 16; ++i) s[i] = AES_SBOX[s[i]];

        // ShiftRows
        uint8_t t;

        // row 1: 1-byte left rotation
        t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;

        // row 2: 2-byte rotation
        t = s[2]; s[2] = s[10]; s[10] = t;
        t = s[6]; s[6] = s[14]; s[14] = t;

        // row 3: 3-byte rotation (or 1-byte right)
        t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

        // MixColumns
        MixColumns(s);

        // AddRoundKey
        for (int i = 0; i < 4; ++i) {
            uint32_t w = (uint32_t)s[4*i] << 24 |
                         (uint32_t)s[4*i+1] << 16 |
                         (uint32_t)s[4*i+2] << 8 |
                         (uint32_t)s[4*i+3];
            w ^= rk[i];
            s[4*i+0] = (uint8_t)(w >> 24);
            s[4*i+1] = (uint8_t)(w >> 16);
            s[4*i+2] = (uint8_t)(w >> 8);
            s[4*i+3] = (uint8_t)(w);
        }
        rk += 4;
    }

    // Final Round (no MixColumns)
    for (int i = 0; i < 16; ++i) s[i] = AES_SBOX[s[i]];

    // ShiftRows
    uint8_t t;
    t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;

    t = s[2]; s[2] = s[10]; s[10] = t;
    t = s[6]; s[6] = s[14]; s[14] = t;

    t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;

    // AddRoundKey
    for (int i = 0; i < 4; ++i) {
        uint32_t w = (uint32_t)s[4*i] << 24 |
                     (uint32_t)s[4*i+1] << 16 |
                     (uint32_t)s[4*i+2] << 8 |
                     (uint32_t)s[4*i+3];
        w ^= rk[i];
        out[4*i+0] = (uint8_t)(w >> 24);
        out[4*i+1] = (uint8_t)(w >> 16);
        out[4*i+2] = (uint8_t)(w >> 8);
        out[4*i+3] = (uint8_t)(w);
    }
}

// ==================== CTR core ====================
void AESCounter::IncrementCounter() {
    // 128-bit big-endian increment
    for (int i = 15; i >= 0; --i) {
        if (++mCounter[i] != 0) break;
    }
}

void AESCounter::Refill() {
    // Fill mBuf (64 bytes) with 4 consecutive CTR blocks
    uint8_t out[16];

    for (int blk = 0; blk < 4; ++blk) {
        EncryptBlock(mCounter, out);
        std::memcpy(mBuf + 16 * blk, out, 16);
        IncrementCounter();
    }
    mBufUsed = 0;
}

// ==================== Seeding ====================
bool AESCounter::SeedKeyIV(const uint8_t* key32, const uint8_t* iv16, uint32_t counter) {
    if (!key32 || !iv16) return false;

    ExpandKey256(key32);

    // Load IV, then inject counter in last 4 bytes (big-endian)
    std::memcpy(mCounter, iv16, 16);
    StoreBE32(mCounter + 12, counter);

    mBufUsed = sizeof(mBuf);
    mSeeded = true;
    return true;
}

// A tiny, self-contained AES-based mixer to derive (key, iv) from arbitrary bytes.
// 1) XOR-fold input into 48-byte accumulator (key 32B + iv 16B)
// 2) Run a few AES-256 encryptions with evolving key material to diffuse
void AESCounter::DeriveKeyIVFromBytes(const uint8_t* bytes, size_t len, uint8_t outKey[32], uint8_t outIV[16]) {
    // Accumulate
    std::memset(outKey, 0, 32);
    std::memset(outIV,  0, 16);
    
    for (size_t i = 0; i < len; ++i) {
        if (i % 48u < 32u) outKey[i % 32u] ^= bytes[i];
        else               outIV[(i - 32u) % 16u] ^= bytes[i];
    }

    // Diffuse: use the just-implemented AES to stir the accumulator
    uint8_t zero[16] = {0};
    uint8_t block[16], tmp[16];

    // 1st pass: encrypt counters 0..3, XOR back into key/iv
    ExpandKey256(outKey);
    for (uint32_t ctr = 0; ctr < 4; ++ctr) {
        // block = big-endian ctr
        block[0] = (uint8_t)(ctr >> 24);
        block[1] = (uint8_t)(ctr >> 16);
        block[2] = (uint8_t)(ctr >> 8);
        block[3] = (uint8_t)(ctr);
        std::memcpy(block + 4, zero, 12);
        EncryptBlock(block, tmp);
        // XOR into key and iv
        for (int i = 0; i < 16; ++i) {
            outKey[i]     ^= tmp[i];
            outKey[16 + i]^= tmp[i];
        }
        for (int i = 0; i < 16; ++i) outIV[i] ^= tmp[(i + 7) & 15];
    }

    // 2nd pass: re-expand with new key, encrypt IV as a block several times
    ExpandKey256(outKey);
    std::memcpy(block, outIV, 16);
    for (int i = 0; i < 3; ++i) {
        EncryptBlock(block, block); // block = AES(key, block)
        for (int j = 0; j < 16; ++j) outIV[j] ^= block[j];
        for (int j = 0; j < 16; ++j) outKey[j] ^= block[(j + 5) & 15];
        for (int j = 0; j < 16; ++j) outKey[16 + j] ^= block[(j + 9) & 15];
    }

    SecureZero(block, sizeof(block));
    SecureZero(tmp,   sizeof(tmp));
    SecureZero(zero,  sizeof(zero));
}

void AESCounter::Seed(const uint8_t* bytes, size_t len) {
    uint8_t key[32], iv[16];
    DeriveKeyIVFromBytes(bytes, len, key, iv);
    SeedKeyIV(key, iv, 0);
    SecureZero(key, sizeof(key));
    SecureZero(iv,  sizeof(iv));
}

// ==================== Output ====================
uint32_t AESCounter::Get() {
    if (!mSeeded) {
        // Deterministic all-zero seed if user forgets to seed (NOT secure)
        uint8_t zkey[32] = {0}, ziv[16] = {0};
        SeedKeyIV(zkey, ziv, 0);
    }
    if (mBufUsed > sizeof(mBuf) - 4) {
        Refill();
    }
    uint32_t v = (uint32_t)mBuf[mBufUsed] << 0
               | (uint32_t)mBuf[mBufUsed + 1] << 8
               | (uint32_t)mBuf[mBufUsed + 2] << 16
               | (uint32_t)mBuf[mBufUsed + 3] << 24;
    mBufUsed += 4;
    return v;
}