#ifndef COPYCIPHER_H
#define COPYCIPHER_H

#include "stdafx.h"
#include "Cipher.h"

enum class CopyCipherError { None };

struct CopyCipher {
    using error_type = CopyCipherError;

    // Byte-by-byte copy, no “fast copy” primitives.
    std::expected<void, error_type>
    encrypt(std::span<const std::byte> source, std::byte* destination) noexcept;

    std::expected<void, error_type>
    decrypt(std::span<const std::byte> source, std::byte* destination) noexcept;
};

static_assert(Cipher<CopyCipher>);

#endif
