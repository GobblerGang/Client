#include "Ed25519Key.h"
#include <openssl/evp.h>
#include <openssl/err.h>

Ed25519PrivateKey::Ed25519PrivateKey(const std::vector<uint8_t>& key_bytes) {
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, key_bytes.data(), key_bytes.size());
    if (!pkey) throw std::runtime_error("Failed to load Ed25519 private key");
}

std::vector<uint8_t> Ed25519PrivateKey::to_bytes() const {
    std::vector<uint8_t> buf(32);
    size_t len = buf.size();
    if (!EVP_PKEY_get_raw_private_key(pkey, buf.data(), &len)) {
        throw std::runtime_error("Failed to get Ed25519 private key bytes");
    }
    return buf;
}

std::vector<uint8_t> Ed25519PrivateKey::get_public_key_bytes() const {
    uint8_t pubkey[32];
    size_t len = sizeof(pubkey);

    if (!EVP_PKEY_get_raw_public_key(pkey, pubkey, &len)) {
        throw std::runtime_error("Failed to derive Ed25519 public key");
    }

    return {pubkey, pubkey + len};
}


Ed25519PublicKey::Ed25519PublicKey(const std::vector<uint8_t>& key_bytes) {
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, key_bytes.data(), key_bytes.size());
    if (!pkey) throw std::runtime_error("Failed to load Ed25519 public key");
}

std::vector<uint8_t> Ed25519PublicKey::to_bytes() const {
    std::vector<uint8_t> buf(32);
    size_t len = buf.size();
    if (!EVP_PKEY_get_raw_public_key(pkey, buf.data(), &len)) {
        throw std::runtime_error("Failed to get Ed25519 public key bytes");
    }
    return buf;
}
