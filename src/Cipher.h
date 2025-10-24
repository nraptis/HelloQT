#ifndef CIPHER_H
#define CIPHER_H

#include "stdafx.h"

template<class CipherType>
concept Cipher = requires(
    CipherType cipher,
    std::span<const std::byte> source,
    std::byte* destination
) {
    typename CipherType::error_type;

    { cipher.encrypt(source, destination) }
        -> std::same_as<std::expected<void, typename CipherType::error_type>>;

    { cipher.decrypt(source, destination) }
        -> std::same_as<std::expected<void, typename CipherType::error_type>>;
};

#endif
