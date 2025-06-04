// src/models/keys.h
#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include <vector>
// This file defines the Keys structure used on the server to store user keys.
// This only contains the public keys and signatures.
struct PublicKeys {
    std::string ed25519_identity_key_public;
    std::string x25519_identity_key_public;
    std::string signed_prekey_public;
    std::string signed_prekey_signature;
    std::vector<std::pair<std::string, std::string>> opks;
};