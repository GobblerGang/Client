#pragma once

#include <vector>
#include <openssl/evp.h>
#include <stdexcept>

class X25519PrivateKey {
public:
    explicit X25519PrivateKey(const std::vector<uint8_t>& key_bytes);
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;
    [[nodiscard]] std::vector<uint8_t> get_public_key_bytes() const;
    EVP_PKEY* to_evp_pkey() const { return pkey; }
private:
    EVP_PKEY* pkey;
};

class X25519PublicKey {
public:
    explicit X25519PublicKey(const std::vector<uint8_t>& key_bytes);
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;
    EVP_PKEY* to_evp_pkey() const { return pkey; }

private:
    EVP_PKEY* pkey;
};
