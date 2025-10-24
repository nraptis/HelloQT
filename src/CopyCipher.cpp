#include "CopyCipher.h"
#include "stdafx.h"

std::expected<void, CopyCipher::error_type>
CopyCipher::encrypt(std::span<const std::byte> source, std::byte* destination) noexcept {
    const std::size_t n = source.size();
    for (std::size_t i = 0; i < n; ++i) {
        destination[i] = source[i];
    }
    return {};
}

std::expected<void, CopyCipher::error_type>
CopyCipher::decrypt(std::span<const std::byte> source, std::byte* destination) noexcept {
    const std::size_t n = source.size();
    for (std::size_t i = 0; i < n; ++i) {
        destination[i] = source[i];
    }
    return {};
}
