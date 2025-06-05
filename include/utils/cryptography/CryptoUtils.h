#pragma once

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>
#include "../dataclasses/PAC.h"
#include "keys/Ed25519Key.h"
#include "keys/X25519Key.h"

class VaultManager;

class CryptoUtils {
    friend class VaultManager;
public:
    static std::vector<uint8_t> generate_nonce(std::size_t size = 12);

    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    encrypt_with_key(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::optional<std::vector<uint8_t>>& associated_data = std::nullopt);

    static std::vector<uint8_t>
    decrypt_with_key(const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::optional<std::vector<uint8_t>>& associated_data = std::nullopt);


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

    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& input);
};
