//
// Created by Ruairi on 04/06/2025.
//

#include "RemoteUserManager.h"

RemoteUserManager::RemoteUserManager() {
    // TODO: implement constructor
}

nlohmann::json RemoteUserManager::save() {
    // TODO: implement save logic
    // This should serialize user_data and keys_data to a string format (e.g., JSON)
    // UUID will be returned by the server. This will be returned to set in the DB
    nlohmann::json j;
    j["user"] = {
        {"username", user_remote.username},
        {"email", user_remote.email},
        {"salt", user_remote.salt}
    };
    j["keys"] = {
        {"ed25519_identity_key_public", keys_remote.ed25519_identity_key_public},
        {"x25519_identity_key_public", keys_remote.x25519_identity_key_public},
        {"signed_prekey_public", keys_remote.signed_prekey_public},
        {"signed_prekey_signature", keys_remote.signed_prekey_signature},
        {"opks", keys_remote.opks}
    };
    //TODO: send json payload to server
    return j;
}

void RemoteUserManager::load(const std::string& identifier) {
    // TODO: implement load logic
}

