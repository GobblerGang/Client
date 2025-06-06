#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include "keys/Ed25519Key.h"
#include "keys/IdentityKeyPairs.h"
#include "keys/X25519Key.h"
#include "models/UserModel.h"
#include "keys/OPKPair.h"
#include "keys/SignedPreKey.h"

// Forward declaration to avoid circular dependency
class CryptoUtils;

class VaultManager {
    // Declare CryptoUtils as a friend class
    friend class CryptoUtils;

public:
    static auto get_user_vault(const UserModel &user) -> std::map<std::string, std::string>;
    
    static std::optional<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>>
    try_decrypt_private_keys(const std::map<std::string, std::string>& vault,
                           const std::vector<uint8_t>& kek);
    
    static bool verify_decrypted_keys(
        const std::vector<uint8_t>& ed25519_identity_private_bytes,
        const std::vector<uint8_t>& x25519_identity_private_bytes,
        const std::vector<uint8_t>& spk_private_bytes,
        const std::map<std::string, std::string>& vault);
    
    static void generate_user_vault(
        const std::vector<uint8_t> &kek,
        const std::vector<OPKPair> &opks,
        UserModel &user,
        const IdentityKeyPairs &identity_key_pairs,
        const SignedPreKey &spk);
    
    static std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
    decrypt_all_opks(const std::string& opks_json, const std::vector<uint8_t>& master_key);
    static const std::vector<uint8_t>& get_ed25519_identity_associated_data();
    static const std::vector<uint8_t>& get_x25519_identity_associated_data();
    static const std::vector<uint8_t>& get_spk_associated_data();
    static const std::vector<uint8_t>& get_opk_associated_data();

private:
    // Private methods if any
    static const std::vector<uint8_t> ed25519_identity_associated_data;
    static const std::vector<uint8_t> x25519_identity_associated_data;
    static const std::vector<uint8_t> spk_associated_data;
    static const std::vector<uint8_t> opk_associated_data;
};