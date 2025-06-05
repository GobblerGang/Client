#include "KeyGeneration.h"
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <vector>
#include <tuple>
#include "keys/Ed25519Key.h"
#include "keys/X25519Key.h"

std::vector<uint8_t> KeyGeneration::derive_master_key(const std::string& password, const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> key(32);
    if (argon2id_hash_raw(2, 65536, 2, password.data(), password.size(), salt.data(), salt.size(), key.data(), key.size()) != ARGON2_OK) {
        throw std::runtime_error("Argon2id key derivation failed");
    }
    return key;
}

IdentityKeyPairs KeyGeneration::generate_identity_keypair() {
    // === Generate Ed25519 Key ===
    EVP_PKEY_CTX* ed_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* ed_pkey = nullptr;
    EVP_PKEY_keygen_init(ed_ctx);
    EVP_PKEY_keygen(ed_ctx, &ed_pkey);
    EVP_PKEY_CTX_free(ed_ctx);

    // Extract raw keys
    std::vector<uint8_t> ed_priv_bytes(32);
    size_t priv_len = ed_priv_bytes.size();
    if (!EVP_PKEY_get_raw_private_key(ed_pkey, ed_priv_bytes.data(), &priv_len))
        throw std::runtime_error("Failed to get raw Ed25519 private key");

    std::vector<uint8_t> ed_pub_bytes(32);
    size_t pub_len = ed_pub_bytes.size();
    if (!EVP_PKEY_get_raw_public_key(ed_pkey, ed_pub_bytes.data(), &pub_len))
        throw std::runtime_error("Failed to get raw Ed25519 public key");

    auto* ed_priv = new Ed25519PrivateKey(ed_priv_bytes);
    auto* ed_pub = new Ed25519PublicKey(ed_pub_bytes);

    // === Generate X25519 Key ===
    EVP_PKEY_CTX* x_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* x_pkey = nullptr;
    EVP_PKEY_keygen_init(x_ctx);
    EVP_PKEY_keygen(x_ctx, &x_pkey);
    EVP_PKEY_CTX_free(x_ctx);

    // Extract raw X25519 keys
    std::vector<uint8_t> x_priv_bytes(32);
    priv_len = x_priv_bytes.size();
    if (!EVP_PKEY_get_raw_private_key(x_pkey, x_priv_bytes.data(), &priv_len))
        throw std::runtime_error("Failed to get raw X25519 private key");

    std::vector<uint8_t> x_pub_bytes(32);
    pub_len = x_pub_bytes.size();
    if (!EVP_PKEY_get_raw_public_key(x_pkey, x_pub_bytes.data(), &pub_len))
        throw std::runtime_error("Failed to get raw X25519 public key");

    auto* x_priv = new X25519PrivateKey(x_priv_bytes);
    auto* x_pub = new X25519PublicKey(x_pub_bytes);

    // Cleanup
    EVP_PKEY_free(ed_pkey);
    EVP_PKEY_free(x_pkey);

    IdentityKeyPairs key_pair;
    key_pair.ed25519_private = std::unique_ptr<Ed25519PrivateKey>(ed_priv);
    key_pair.ed25519_public = std::unique_ptr<Ed25519PublicKey>(ed_pub);
    key_pair.x25519_private = std::unique_ptr<X25519PrivateKey>(x_priv);
    key_pair.x25519_public = std::unique_ptr<X25519PublicKey>(x_pub);

    return key_pair;
}

std::vector<uint8_t> KeyGeneration::generate_symmetric_key() {
    std::vector<uint8_t> kek(32);
    if (RAND_bytes(kek.data(), kek.size()) != 1) {
        throw std::runtime_error("Failed to generate KEK");
    }
    return kek;
}

std::tuple<X25519PrivateKey *, X25519PublicKey *, std::vector<uint8_t>> KeyGeneration::generate_signed_prekey(
    EVP_PKEY *identity_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* priv = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &priv);
    EVP_PKEY_CTX_free(ctx);

    EVP_PKEY* pub = EVP_PKEY_dup(priv);
    std::vector<uint8_t> pub_bytes(32);
    size_t len = pub_bytes.size();
    EVP_PKEY_get_raw_public_key(pub, pub_bytes.data(), &len);

    EVP_PKEY_CTX* sign_ctx = EVP_PKEY_CTX_new(identity_key, nullptr);
    EVP_PKEY_sign_init(sign_ctx);

    size_t siglen = 0;
    EVP_PKEY_sign(sign_ctx, nullptr, &siglen, pub_bytes.data(), pub_bytes.size());

    std::vector<uint8_t> signature(siglen);
    EVP_PKEY_sign(sign_ctx, signature.data(), &siglen, pub_bytes.data(), pub_bytes.size());
    signature.resize(siglen);

    EVP_PKEY_CTX_free(sign_ctx);

    // Extract raw X25519 keys
    std::vector<uint8_t> x_priv_bytes(32);
    size_t priv_len = x_priv_bytes.size();
    if (!EVP_PKEY_get_raw_private_key(priv, x_priv_bytes.data(), &priv_len))
        throw std::runtime_error("Failed to get raw X25519 private key");

    std::vector<uint8_t> x_pub_bytes(32);
    size_t pub_len = x_pub_bytes.size();
    if (!EVP_PKEY_get_raw_public_key(pub, x_pub_bytes.data(), &pub_len))
        throw std::runtime_error("Failed to get raw X25519 public key");

    auto* x_priv = new X25519PrivateKey(x_priv_bytes);
    auto* x_pub = new X25519PublicKey(x_pub_bytes);
    std::tuple signedkey= std::make_tuple(x_priv, x_pub, signature);
    return signedkey;
}

std::vector<OPKPair> KeyGeneration::keypairs_from_opk_bytes(
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& decrypted_opks) {

    std::vector<OPKPair> opk_keypairs;
    for (const auto& [priv_bytes, pub_bytes] : decrypted_opks) {
        OPKPair pair{X25519PrivateKey(priv_bytes), X25519PublicKey(pub_bytes)};
        opk_keypairs.push_back(pair);
    }
    return opk_keypairs;
}
