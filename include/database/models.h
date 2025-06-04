#pragma once
#include <string>

struct KEKModel {
    int id;
    std::string enc_kek;
    std::string kek_nonce;
    std::string updated_at;
    int user_id;
};

struct UserModel {
    int id;
    std::string uuid;
    std::string username;
    std::string email;

    // Ed25519 identity key fields
    std::string ed25519_identity_key_public;
    std::string ed25519_identity_key_private_enc;
    std::string ed25519_identity_key_private_nonce;

    // X25519 identity key fields
    std::string x25519_identity_key_public;
    std::string x25519_identity_key_private_enc;
    std::string x25519_identity_key_private_nonce;

    // Salt for key derivation
    std::string salt;

    // Signed prekey fields
    std::string signed_prekey_public;
    std::string signed_prekey_signature;
    std::string signed_prekey_private_enc;
    std::string signed_prekey_private_nonce;

    // One-time prekeys as JSON
    std::string opks_json;
};