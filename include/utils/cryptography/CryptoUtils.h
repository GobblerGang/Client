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
    // inline is here only for searchability. this functions is inlined implicitly as it is defined fully in header
    static inline std::vector<uint8_t> CryptoUtils::generate_nonce(const std::size_t size) {
        std::vector<uint8_t> nonce(size);
        if (RAND_bytes(nonce.data(), static_cast<int>(size)) != 1) {
            throw std::runtime_error("Failed to generate secure nonce");
        }
        return nonce;
    }
    /**
     * Encrypts the given plaintext using the provided key and nonce.
     *
     * @param plaintext the plaintext to encrypt, must be a multiple of 16 bytes.
     * @param key the key to use for encryption, must be 32 bytes (256 bits).
     * @param associated_data optional associated data for additional authenticated data (AAD).
     * @param nonce passed by reference, will be modified to contain the nonce used for encryption.
     * @return Encrypted ciphertext as a vector of bytes.
     */
    static std::vector<uint8_t>
    encrypt_with_key(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, std::vector<uint8_t>& nonce, const std::optional<std::vector<uint8_t>>& associated_data = std::nullopt);

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
    /**
     *
     * @param spk_public - The public key of the signed prekey.
     * @param spk_signature - The signature of the signed prekey.
     * @param spk_data - The data that was signed with the signed prekey.
     * @return
     */
    static bool verify_spk(const std::vector<uint8_t>& spk_public, const std::vector<uint8_t>& spk_signature, const std::vector<uint8_t>& spk_data);
    static std::string base64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> base64_decode(const std::string& input);
};
