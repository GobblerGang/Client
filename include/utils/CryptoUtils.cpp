#include "CryptoUtils.h"
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <sstream>
#include <nlohmann/json.hpp>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include "Ed25519Key.h"
#include "VaultManager.h"

using namespace std;

std::vector<uint8_t> CryptoUtils::derive_master_key(const std::string& password, const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> key(32);
    if (argon2id_hash_raw(2, 65536, 2, password.data(), password.size(), salt.data(), salt.size(), key.data(), key.size()) != ARGON2_OK) {
        throw std::runtime_error("Argon2id key derivation failed");
    }
    return key;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> CryptoUtils::encrypt_with_key(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::optional<std::vector<uint8_t>>& associated_data) {
    std::vector<uint8_t> nonce(12);
    RAND_bytes(nonce.data(), nonce.size());

    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    int outlen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    if (associated_data) {
        EVP_EncryptUpdate(ctx, nullptr, &outlen, associated_data->data(), associated_data->size());
    }

    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size());
    int total_len = outlen;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen);
    total_len += outlen;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + plaintext.size());
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(plaintext.size() + 16);
    return {nonce, ciphertext};
}

std::vector<uint8_t> CryptoUtils::decrypt_with_key(const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::optional<std::vector<uint8_t>>& associated_data) {
    if (ciphertext.size() < 16) throw std::runtime_error("Ciphertext too short");

    std::vector<uint8_t> plaintext(ciphertext.size() - 16);
    int outlen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    if (associated_data) {
        EVP_DecryptUpdate(ctx, nullptr, &outlen, associated_data->data(), associated_data->size());
    }

    EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext.data(), plaintext.size());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(ciphertext.data() + plaintext.size()));

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: Invalid tag");
    }

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

pair<Ed25519PrivateKey*, Ed25519PublicKey*> CryptoUtils::generate_identity_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* priv = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &priv);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY* pub = EVP_PKEY_dup(priv);
    return {priv, pub};
}

tuple<X25519PrivateKey*, X25519PublicKey*, std::vector<uint8_t>> CryptoUtils::generate_signed_prekey(EVP_PKEY* identity_key) {
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

    return {priv, pub, signature};
}

std::vector<uint8_t> CryptoUtils::perform_3xdh_sender(EVP_PKEY* id_priv, EVP_PKEY* eph_priv, EVP_PKEY* r_id_pub, EVP_PKEY* r_spk_pub, EVP_PKEY* r_otk_pub) {
    std::vector<uint8_t> shared;
    size_t len = 32;
    auto dh = [&](EVP_PKEY* priv, EVP_PKEY* pub) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, pub);
        std::vector<uint8_t> out(len);
        EVP_PKEY_derive(ctx, out.data(), &len);
        shared.insert(shared.end(), out.begin(), out.end());
        EVP_PKEY_CTX_free(ctx);
    };
    dh(eph_priv, r_id_pub);
    dh(id_priv, r_spk_pub);
    dh(eph_priv, r_spk_pub);
    if (r_otk_pub) dh(eph_priv, r_otk_pub);

    std::vector<uint8_t> key(32);
    EVP_PKEY_CTX* hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init(hkdf_ctx);
    EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared.data(), shared.size());
    EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, reinterpret_cast<const unsigned char *>("3XDH key agreement"), strlen("3XDH key agreement"));
    EVP_PKEY_derive(hkdf_ctx, key.data(), &len);
    EVP_PKEY_CTX_free(hkdf_ctx);
    return key;
}

std::vector<uint8_t> CryptoUtils::perform_3xdh_recipient(
    EVP_PKEY* id_priv,
    EVP_PKEY* spk_priv,
    EVP_PKEY* s_id_pub,
    EVP_PKEY* s_eph_pub,
    EVP_PKEY* otk_priv
) {
    std::vector<uint8_t> shared;
    size_t len = 32;
    auto dh = [&](EVP_PKEY* priv, EVP_PKEY* pub) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, pub);
        std::vector<uint8_t> out(len);
        EVP_PKEY_derive(ctx, out.data(), &len);
        shared.insert(shared.end(), out.begin(), out.end());
        EVP_PKEY_CTX_free(ctx);
    };

    dh(id_priv, s_eph_pub);
    dh(spk_priv, s_id_pub);
    dh(spk_priv, s_eph_pub);
    if (otk_priv) dh(otk_priv, s_eph_pub);

    std::vector<uint8_t> key(32);
    EVP_PKEY_CTX* hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init(hkdf_ctx);
    EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared.data(), shared.size());
    EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, reinterpret_cast<const unsigned char *>("3XDH key agreement"), strlen("3XDH key agreement"));
    EVP_PKEY_derive(hkdf_ctx, key.data(), &len);
    EVP_PKEY_CTX_free(hkdf_ctx);
    return key;
}

PAC CryptoUtils::create_pac(
    const std::string &file_id,
    const std::string &recipient_id,
    const std::string &issuer_id,
    const std::vector<uint8_t> &encrypted_file_key,
    const std::vector<uint8_t> &encrypted_file_key_nonce,
    const std::vector<uint8_t> &sender_ephemeral_pubkey,
    int64_t valid_until,
    EVP_PKEY* identity_key,  // Ed25519 private key
    const std::optional<std::string> &filename,
    const std::optional<std::string> &mime_type
) {
    // 1. Create the PAC JSON structure with ordered keys
    nlohmann::ordered_json pac_json = {
        {"file_id", file_id},
        {"recipient_id", recipient_id},
        {"issuer_id", issuer_id},
        {"encrypted_file_key", VaultManager::base64_encode(encrypted_file_key)},
        {"encrypted_file_key_nonce", VaultManager::base64_encode(encrypted_file_key_nonce)},
        {"sender_ephemeral_pubkey", VaultManager::base64_encode(sender_ephemeral_pubkey)},
        {"valid_until", valid_until},
        {"revoked", false},
        {"filename", filename.value()},
        {"mime_type", mime_type.value()}
    };

    std::string message = pac_json.dump();

    std::vector<uint8_t> signature(EVP_PKEY_size(identity_key));
    size_t siglen = signature.size();

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, identity_key) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize Ed25519 signing");
    }

    if (EVP_DigestSign(ctx, signature.data(), &siglen,
                     reinterpret_cast<const uint8_t*>(message.data()),
                     message.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to create Ed25519 signature");
    }
    EVP_MD_CTX_free(ctx);
    signature.resize(siglen);

    std::optional<std::string> valid_until_iso;
    if (valid_until != 0) {
        auto time = static_cast<std::time_t>(valid_until);
        std::tm tm = *std::gmtime(&time);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        valid_until_iso = oss.str();
    }
    return PAC{
        .recipient_id = recipient_id,
        .file_uuid = file_id,
        .valid_until = valid_until_iso,
        .encrypted_file_key = pac_json.at("encrypted_file_key").get<std::string>(),
        .signature = VaultManager::base64_encode(signature),
        .issuer_id = issuer_id,
        .sender_ephemeral_public = pac_json.at("sender_ephemeral_pubkey").get<std::string>(),
        .k_file_nonce = pac_json.at("encrypted_file_key_nonce").get<std::string>(),
        .filename = filename,
        .mime_type = mime_type
    };
}

bool CryptoUtils::verify_pac(const nlohmann::json &pac_json, EVP_PKEY *issuer_public_key) {
    try {
        nlohmann::json copy = pac_json;
        std::vector<uint8_t> signature = VaultManager::base64_decode(copy["signature"]);
        copy.erase("signature");

        std::string message = copy.dump();
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, issuer_public_key);
        EVP_DigestVerifyUpdate(ctx, message.data(), message.size());

        int ok = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
        EVP_MD_CTX_free(ctx);
        return ok == 1;
    } catch (...) {
        return false;
    }
}
#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include "Ed25519Key.h"
#include "X25519Key.h"
#include "User.hpp"
#include "vault.h"

// Forward declaration to avoid circular dependency
class CryptoUtils;

struct OPKPair {
    X25519PrivateKey private_key;
    X25519PublicKey public_key;
};

class VaultManager {
    // Declare CryptoUtils as a friend class
    friend class CryptoUtils;

public:
    // Get vault from user database entry
    static Vault get_user_vault(const User& user);
    
    // Create user database entry from vault
    static User create_user_from_vault(const std::string& username, const std::string& email, 
                                       const std::string& uuid, const Vault& vault);
    
    // Try to decrypt private keys from vault using master key
    static std::optional<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>>
    try_decrypt_private_keys(const Vault& vault, const std::vector<uint8_t>& master_key);
    
    // Verify that decrypted keys match their public counterparts
    static bool verify_decrypted_keys(
        const std::vector<uint8_t>& ed25519_identity_private_bytes,
        const std::vector<uint8_t>& x25519_identity_private_bytes,
        const std::vector<uint8_t>& spk_private_bytes,
        const Vault& vault);
    
    // Generate a new vault with all necessary keys
    static Vault generate_user_vault(
        const Ed25519PrivateKey& ed25519_identity_private,
        const Ed25519PublicKey& ed25519_identity_public,
        const X25519PrivateKey& x25519_identity_private,
        const X25519PublicKey& x25519_identity_public,
        const X25519PrivateKey& spk_private,
        const X25519PublicKey& spk_public,
        const std::vector<uint8_t>& spk_signature,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& master_key,
        const std::vector<OPKPair>& opks = {});
    
    // Decrypt all one-time prekeys
    static std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
    decrypt_all_opks(const Vault& vault, const std::vector<uint8_t>& master_key);
    
    // Convert decrypted bytes to key pairs
    static std::vector<OPKPair> keypairs_from_opk_bytes(
        const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& decrypted_opks);

    // Make these public so they can be accessed directly
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& input);

private:
    // Private methods if any
    static const std::vector<uint8_t> ed25519_identity_associated_data;
    static const std::vector<uint8_t> x25519_identity_associated_data;
    static const std::vector<uint8_t> spk_associated_data;
    static const std::vector<uint8_t> opk_associated_data;
};