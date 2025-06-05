//
// Created by Ruairi on 04/06/2025.
//

#include "RemoteUserManager.h"

#include <iostream>

#include "Server.h"

RemoteUserManager::RemoteUserManager() {
    // TODO: implement constructor
}

RemoteUserManager::~RemoteUserManager() {

}

nlohmann::json RemoteUserManager::save() {
    // TODO: implement save logic
    // This should serialize user_data and keys_data to a string format (e.g., JSON)
    // UUID will be returned by the server. This will be returned to set in the DB
    if (!user_remote_ptr || !keys_remote_ptr || !kek_data_ptr) {
        throw std::runtime_error("RemoteUserManager: User, keys, or KEK data not set.");
    }
    // std::string user_uuid = Server::instance().get_new_user_uuid();

    // std::cout << "RemoteUserManager: Saving user with UUID: " << user_uuid << std::endl;
    // std::cout << "RemoteUserManager: User data: " << user_remote_ptr->username << ", " << user_remote_ptr->email << std::endl;
    // std::cout << "RemoteUserManager: Keys data: " << keys_remote_ptr->ed25519_identity_key_public << ", "
    //           << keys_remote_ptr->x25519_identity_key_public << std::endl;
    // std::cout << "RemoteUserManager: SPK data: " << keys_remote_ptr->signed_prekey_public << ", "
    //           << keys_remote_ptr->signed_prekey_signature << std::endl;
    // std::cout << "RemoteUserManager: KEK data: " << kek_data_ptr->enc_kek_cyphertext << ", "
    //           << kek_data_ptr->nonce << ", " << kek_data_ptr->updated_at << std::endl;

    nlohmann::json j;
    j["user"] = {
        {"uuid", user_remote_ptr->uuid},
        {"username", user_remote_ptr->username},
        {"email", user_remote_ptr->email},
        {"salt", user_remote_ptr->salt}
    };
    j["keys"] = {
        {"ed25519_identity_key_public", keys_remote_ptr->ed25519_identity_key_public},
        {"x25519_identity_key_public", keys_remote_ptr->x25519_identity_key_public},
        {"signed_prekey_public", keys_remote_ptr->signed_prekey_public},
        {"signed_prekey_signature", keys_remote_ptr->signed_prekey_signature},
        {"opks", keys_remote_ptr->opks}
    };
    j["kek"] = {
        {"enc_kek_cyphertext", kek_data_ptr->enc_kek_cyphertext},
        {"nonce", kek_data_ptr->nonce},
        {"updated_at", kek_data_ptr->updated_at}
    };
    Server& server = Server::instance();
    // TODO: this throws runtime error if the server request fails, ensure this is handled properly in calling function
    server.create_user(j);
    return j;
}

void RemoteUserManager::load(const std::string& identifier) {
    // TODO: implement load logic
}

