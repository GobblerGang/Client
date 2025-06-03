#include "utils/dataclasses/Vault.h"

Vault::Vault(
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
    std::vector<nlohmann::json> opks
) : 
    salt(std::move(salt)),
    ed25519_identity_key_public(std::move(ed25519_identity_key_public)),
    ed25519_identity_key_private_enc(std::move(ed25519_identity_key_private_enc)),
    ed25519_identity_key_private_nonce(std::move(ed25519_identity_key_private_nonce)),
    x25519_identity_key_public(std::move(x25519_identity_key_public)),
    x25519_identity_key_private_enc(std::move(x25519_identity_key_private_enc)),
    x25519_identity_key_private_nonce(std::move(x25519_identity_key_private_nonce)),
    signed_prekey_public(std::move(signed_prekey_public)),
    signed_prekey_signature(std::move(signed_prekey_signature)),
    signed_prekey_private_enc(std::move(signed_prekey_private_enc)),
    signed_prekey_private_nonce(std::move(signed_prekey_private_nonce)),
    opks(std::move(opks))
{}

Vault Vault::from_json(const nlohmann::json& data) {
    // Handle both new and legacy formats
    
    // Check if data contains new key format
    bool has_new_format = data.contains("ed25519_identity_key_public") && 
                          data.contains("x25519_identity_key_public");
    
    if (has_new_format) {
        return Vault(
            data["salt"].get<std::string>(),
            data["ed25519_identity_key_public"].get<std::string>(),
            data["ed25519_identity_key_private_enc"].get<std::string>(),
            data["ed25519_identity_key_private_nonce"].get<std::string>(),
            data["x25519_identity_key_public"].get<std::string>(),
            data["x25519_identity_key_private_enc"].get<std::string>(),
            data["x25519_identity_key_private_nonce"].get<std::string>(),
            data["signed_prekey_public"].get<std::string>(),
            data["signed_prekey_signature"].get<std::string>(),
            data["signed_prekey_private_enc"].get<std::string>(),
            data["signed_prekey_private_nonce"].get<std::string>(),
            data.value("opks", std::vector<nlohmann::json>{})  // Default empty array
        );
    } else {
        // Legacy format - use identity_key fields for ed25519 and leave x25519 empty
        return Vault(
            data["salt"].get<std::string>(),
            data["identity_key_public"].get<std::string>(),
            data["identity_key_private_enc"].get<std::string>(),
            data["identity_key_private_nonce"].get<std::string>(),
            "", // x25519_identity_key_public
            "", // x25519_identity_key_private_enc
            "", // x25519_identity_key_private_nonce
            data["signed_prekey_public"].get<std::string>(),
            data["signed_prekey_signature"].get<std::string>(),
            data["signed_prekey_private_enc"].get<std::string>(),
            data["signed_prekey_private_nonce"].get<std::string>(),
            data.value("opks", std::vector<nlohmann::json>{})  // Default empty array
        );
    }
}

nlohmann::json Vault::to_json() const {
    nlohmann::json result = {
        {"salt", salt},
        {"ed25519_identity_key_public", ed25519_identity_key_public},
        {"ed25519_identity_key_private_enc", ed25519_identity_key_private_enc},
        {"ed25519_identity_key_private_nonce", ed25519_identity_key_private_nonce},
        {"x25519_identity_key_public", x25519_identity_key_public},
        {"x25519_identity_key_private_enc", x25519_identity_key_private_enc},
        {"x25519_identity_key_private_nonce", x25519_identity_key_private_nonce},
        {"signed_prekey_public", signed_prekey_public},
        {"signed_prekey_signature", signed_prekey_signature},
        {"signed_prekey_private_enc", signed_prekey_private_enc},
        {"signed_prekey_private_nonce", signed_prekey_private_nonce},
        {"opks", opks}
    };
    
    // Add legacy fields for backward compatibility
    result["identity_key_public"] = ed25519_identity_key_public;
    result["identity_key_private_enc"] = ed25519_identity_key_private_enc;
    result["identity_key_private_nonce"] = ed25519_identity_key_private_nonce;
    
    return result;
}