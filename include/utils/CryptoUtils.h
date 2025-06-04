#pragma once

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "dataclasses/PAC.h"
#include "Ed25519Key.h"
#include "X25519Key.h"

class VaultManager;

class CryptoUtils {
    friend class VaultManager;
public:
    static std::vector<uint8_t> derive_master_key(const std::string& password, const std::vector<uint8_t>& salt);

    static std::vector<uint8_t> generate_nonce(std::size_t size = 12);

    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    encrypt_with_key(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::optional<std::vector<uint8_t>>& associated_data = std::nullopt);

    static std::vector<uint8_t>
    decrypt_with_key(const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::optional<std::vector<uint8_t>>& associated_data = std::nullopt);

    static std::pair<std::pair<Ed25519PrivateKey*, Ed25519PublicKey*>,std::pair<X25519PrivateKey*, X25519PublicKey*>>
    generate_identity_keypair();
    // returns Ed25519 + X25519 keypairs
    static std::vector<uint8_t> generate_kek();
    static std::tuple<X25519PrivateKey *, X25519PublicKey *, std::vector<uint8_t>>
    generate_signed_prekey(EVP_PKEY *identity_key); // X25519 + signature

    static std::vector<uint8_t> perform_3xdh_sender(
        EVP_PKEY* identity_private,
        EVP_PKEY* ephemeral_private,
        EVP_PKEY* recipient_identity_public,
        EVP_PKEY* recipient_signed_prekey_public,
        EVP_PKEY* recipient_one_time_prekey_public = nullptr
    );

    static std::vector<uint8_t> perform_3xdh_recipient(
        EVP_PKEY* identity_private,
        EVP_PKEY* signed_prekey_private,
        EVP_PKEY* sender_identity_public,
        EVP_PKEY* sender_ephemeral_public,
        EVP_PKEY* one_time_prekey_private = nullptr
    );

    static PAC create_pac(
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
    );

    static bool verify_pac(const nlohmann::json &pac_json, EVP_PKEY *issuer_public_key); // Ed25519
};
