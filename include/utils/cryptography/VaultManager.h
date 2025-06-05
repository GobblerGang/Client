#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include "keys/Ed25519Key.h"
#include "keys/X25519Key.h"
#include "models/UserModel.h"
#include "keys/OPKPair.h"

// Forward declaration to avoid circular dependency
class CryptoUtils;

class VaultManager {
    // Declare CryptoUtils as a friend class
    friend class CryptoUtils;

public:
    static auto get_user_vault(const UserModel &user) -> std::map<std::string, std::string>;
    
    static std::optional<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>>
    try_decrypt_private_keys(const std::map<std::string, std::string>& vault,
                           const std::vector<uint8_t>& master_key);
    
    static bool verify_decrypted_keys(
        const std::vector<uint8_t>& ed25519_identity_private_bytes,
        const std::vector<uint8_t>& x25519_identity_private_bytes,
        const std::vector<uint8_t>& spk_private_bytes,
        const std::map<std::string, std::string>& vault);
    
    static std::map<std::string, std::string> generate_user_vault(
        const Ed25519PrivateKey& ed25519_identity_private,
        const Ed25519PublicKey& ed25519_identity_public,
        const X25519PrivateKey& x25519_identity_private,
        const X25519PublicKey& x25519_identity_public,
        const X25519PrivateKey& spk_private,
        const X25519PublicKey& spk_public,
        const std::vector<uint8_t>& spk_signature,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& master_key,
        const std::vector<OPKPair>& opks);
    
    static std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
    decrypt_all_opks(const std::string& opks_json, const std::vector<uint8_t>& master_key);

private:
    // Private methods if any
    static const std::vector<uint8_t> ed25519_identity_associated_data;
    static const std::vector<uint8_t> x25519_identity_associated_data;
    static const std::vector<uint8_t> spk_associated_data;
    static const std::vector<uint8_t> opk_associated_data;
};