#define VAULT_H

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

class Vault {
public:
    // Constructor with all fields
    Vault(
        std::string salt,
        std::string ed25519_identity_key_public,
        std::string ed25519_identity_key_private_enc,
        std::string ed25519_identity_key_private_nonce,
        std::string x25519_identity_key_public,
        std::string x25519_identity_key_private_enc,
        std::string x25519_identity_key_private_nonce,
        std::string signed_prekey_public,
        std::string signed_prekey_signature,
        std::string signed_prekey_private_enc,
        std::string signed_prekey_private_nonce,
        std::vector<nlohmann::json> opks = {}
    );

    // Default constructor
    Vault() = default;

    // Static factory method to create a Vault from JSON
    static Vault from_json(const nlohmann::json& data);

    // Convert Vault to JSON
    nlohmann::json to_json() const;

    // Getters and setters
    const std::string& get_salt() const { return salt; }
    const std::string& get_ed25519_identity_key_public() const { return ed25519_identity_key_public; }
    const std::string& get_ed25519_identity_key_private_enc() const { return ed25519_identity_key_private_enc; }
    const std::string& get_ed25519_identity_key_private_nonce() const { return ed25519_identity_key_private_nonce; }
    const std::string& get_x25519_identity_key_public() const { return x25519_identity_key_public; }
    const std::string& get_x25519_identity_key_private_enc() const { return x25519_identity_key_private_enc; }
    const std::string& get_x25519_identity_key_private_nonce() const { return x25519_identity_key_private_nonce; }
    const std::string& get_signed_prekey_public() const { return signed_prekey_public; }
    const std::string& get_signed_prekey_signature() const { return signed_prekey_signature; }
    const std::string& get_signed_prekey_private_enc() const { return signed_prekey_private_enc; }
    const std::string& get_signed_prekey_private_nonce() const { return signed_prekey_private_nonce; }
    const std::vector<nlohmann::json>& get_opks() const { return opks; }

    // Legacy getters for backward compatibility
    const std::string& get_identity_key_public() const { return ed25519_identity_key_public; }
    const std::string& get_identity_key_private_enc() const { return ed25519_identity_key_private_enc; }
    const std::string& get_identity_key_private_nonce() const { return ed25519_identity_key_private_nonce; }

private:
    std::string salt;
    std::string ed25519_identity_key_public;
    std::string ed25519_identity_key_private_enc;
    std::string ed25519_identity_key_private_nonce;
    std::string x25519_identity_key_public;
    std::string x25519_identity_key_private_enc;
    std::string x25519_identity_key_private_nonce;
    std::string signed_prekey_public;
    std::string signed_prekey_signature;
    std::string signed_prekey_private_enc;
    std::string signed_prekey_private_nonce;
    std::vector<nlohmann::json> opks;
};