#include "X25519Key.h"
#include <openssl/evp.h>
#include <openssl/err.h>

X25519PrivateKey::X25519PrivateKey(const std::vector<uint8_t>& key_bytes) {
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, key_bytes.data(), key_bytes.size());
    if (!pkey) throw std::runtime_error("Failed to load X25519 private key");
}

std::vector<uint8_t> X25519PrivateKey::to_bytes() const {
    std::vector<uint8_t> buf(32);
    size_t len = buf.size();
    if (!EVP_PKEY_get_raw_private_key(pkey, buf.data(), &len)) {
        throw std::runtime_error("Failed to get X25519 private key bytes");
    }
    return buf;
}

std::vector<uint8_t> X25519PrivateKey::get_public_key_bytes() const {
    uint8_t pubkey[32];
    size_t len = sizeof(pubkey);

    if (!EVP_PKEY_get_raw_public_key(pkey, pubkey, &len)) {
        throw std::runtime_error("Failed to derive Ed25519 public key");
    }

    return {pubkey, pubkey + len};
}


X25519PublicKey::X25519PublicKey(const std::vector<uint8_t>& key_bytes) {
    pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, key_bytes.data(), key_bytes.size());
    if (!pkey) throw std::runtime_error("Failed to load X25519 public key");
}

std::vector<uint8_t> X25519PublicKey::to_bytes() const {
    std::vector<uint8_t> buf(32);
    size_t len = buf.size();
    if (!EVP_PKEY_get_raw_public_key(pkey, buf.data(), &len)) {
        throw std::runtime_error("Failed to get X25519 public key bytes");
    }
    return buf;
}
