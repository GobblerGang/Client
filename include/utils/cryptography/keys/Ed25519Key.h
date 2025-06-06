#pragma once

#include <vector>
#include <openssl/evp.h>

class Ed25519PrivateKey {
public:
    explicit Ed25519PrivateKey(const std::vector<uint8_t>& key_bytes);

    Ed25519PrivateKey(const std::vector<unsigned char> & vector, const std::vector<unsigned char> & base64_decode);

    [[nodiscard]] std::vector<uint8_t> to_bytes() const;
    [[nodiscard]] std::vector<uint8_t> get_public_key_bytes() const;
    EVP_PKEY* to_evp_pkey() const { return pkey; }
private:
    EVP_PKEY* pkey;
};

class Ed25519PublicKey {
public:
    explicit Ed25519PublicKey(const std::vector<uint8_t>& key_bytes);
    [[nodiscard]] std::vector<uint8_t> to_bytes() const;
    EVP_PKEY* to_evp_pkey() const { return pkey; }
private:
    EVP_PKEY* pkey;
};
