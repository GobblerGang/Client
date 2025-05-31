#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <cstdint>

// Forward declarations for key types
class Ed25519PrivateKey;
class Ed25519PublicKey;
class X25519PrivateKey;
class X25519PublicKey;

struct OPKPair {
    X25519PrivateKey private_key;
    X25519PublicKey public_key;
};

class VaultManager {
public:
    // Serialize user vault from fields (e.g. user struct)
    static std::map<std::string, std::string> get_user_vault(const /*User&*/ auto& user);

    // Try decrypt private keys; returns pair of private keys bytes or nullopt on failure
    static std::optional<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
    try_decrypt_private_keys(const std::map<std::string, std::string>& vault,
                             const std::vector<uint8_t>& master_key);

    // Verify decrypted private keys match public keys in vault
    static bool verify_decrypted_keys(const std::vector<uint8_t>& identity_private_bytes,
                                     const std::vector<uint8_t>& spk_private_bytes,
                                     const std::map<std::string, std::string>& vault);

    // Generate user vault map from given keys and data
    static std::map<std::string, std::string> generate_user_vault(
        const Ed25519PrivateKey& identity_private,
        const Ed25519PublicKey& identity_public,
        const X25519PrivateKey& spk_private,
        const X25519PublicKey& spk_public,
        const std::vector<uint8_t>& spk_signature,
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& master_key,
        const std::vector<OPKPair>& opks);

    // Decrypt all OPKs from JSON string and master key
    static std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
    decrypt_all_opks(const std::string& opks_json, const std::vector<uint8_t>& master_key);

    // Convert OPK private/public bytes pairs into key objects
    static std::vector<OPKPair> keypairs_from_opk_bytes(
        const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& decrypted_opks);

private:
    // Base64 encode / decode helpers
    static std::string b64_encode(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> b64_decode(const std::string& data);
};
