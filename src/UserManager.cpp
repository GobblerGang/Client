//
// Created by Ruairi on 04/06/2025.
//

#include "UserManager.h"

#include <iostream>

#include "nlohmann/json.hpp"
#include "utils/cryptography/keys/MasterKey.h"
#include "Server.h"
#include <utils/cryptography/CryptoUtils.h>
#include "KekService.h"
#include "database/db_instance.h"
#include "models/UserModelORM.h"
#include "utils/cryptography/KeyGeneration.h"
#include "utils/cryptography/VaultManager.h"
#include "utils/cryptography/keys/SignedPreKey.h"
#include <optional>
#include <string>
#include <utility>

#include "utils/dataclasses/Vault.h"

UserManager::UserManager() {
    user_data = UserModel();
}

UserManager::~UserManager() {
    MasterKey::instance().clear();
}

KEKModel UserManager::get_local_kek(int user_id) const {
    auto kek_models = db().get_all<KEKModel>(where(c(&KEKModel::user_id) == user_id));
    if (kek_models.empty()) {
        throw std::runtime_error("No KEK found for user_id: " + std::to_string(user_id));
    }
    return kek_models.front();
}
nlohmann::json UserManager::save() {
    setRemoteUser(std::make_shared<const UserModel>(user_data));
    setKeys(std::make_shared<const UserModel>(user_data));

    nlohmann::json server_response = RemoteUserManager::save();
    // handle_saving_remote_user_data();
    if  (server_response.empty()) {
        throw std::runtime_error("Failed to save user data remotely.");
    }

    // user_data.uuid = server_response["user"]["uuid"];

    nlohmann::json response_json;
    response_json["user"] = {
        {"uuid", user_data.uuid},
        {"username", user_data.username},
        {"email", user_data.email},
        {"salt", user_data.salt}
    };
    response_json["keys"] = {
        {"ed25519_identity_key_public", user_data.ed25519_identity_key_public},
        {"x25519_identity_key_public", user_data.x25519_identity_key_public},
        {"signed_prekey_public", user_data.signed_prekey_public},
        {"signed_prekey_signature", user_data.signed_prekey_signature},
        {"opks", user_data.opks}
    };
    response_json["kek"] = {
        {"enc_kek_cyphertext", getKEK().enc_kek_cyphertext},
        {"nonce", getKEK().nonce},
        {"updated_at", getKEK().updated_at}
    };
    UserModelORM user_orm;
    user_orm = user_data;
    // Save user_orm to database
    int user_id = db().insert(user_orm);
    if (user_id < 0) {
        throw std::runtime_error("Failed to save user data to database.");
    }
    KEKModel kek_model;
    kek_model.enc_kek_cyphertext = getKEK().enc_kek_cyphertext;
    kek_model.nonce = getKEK().nonce;
    kek_model.updated_at = getKEK().updated_at;
    kek_model.user_id = user_id; // Set the user ID after saving the user

    setKEK(std::make_shared<const KEKModel>(kek_model));
    int kek_id = db().insert(kek_model);
    if (kek_id < 0) {
        throw std::runtime_error("Failed to save kek data to database.");
    }
    return response_json;
}

void UserManager::load(const std::string& identifier) {
    // Implement get logic here
    // Use setUser(UserModel) from db or from server
    auto users = db().get_all<UserModelORM>(where(c(&UserModelORM::uuid) == identifier));
    if (users.empty()) {
        throw std::runtime_error("User not found with username: " + identifier);
    }
    const UserModelORM user = users.front();
    setUser(UserModel(user));
}

// In UserManager.cpp

bool UserManager::login(const std::string& username, const std::string& password) {
    auto users = db().get_all<UserModelORM>(where(c(&UserModelORM::username) == username));
    if (users.empty()) {
        auto server_user = Server::instance().get_user_by_name(username);
        if (server_user.uuid.empty()) {
            throw std::runtime_error("User not found locally or on server.");
        }
        throw std::runtime_error("User not found locally, but exists on server. Please import your key bundle.");
    }
    const auto user = users.front();

    if (password.empty()) {
        throw std::runtime_error("Password is required");
    }

    UserModel temp_user;
    temp_user = UserModel(user);

    std::string salt_b64 = user.salt;
    std::vector<uint8_t> salt = CryptoUtils::base64_decode(salt_b64);
    std::vector<uint8_t> master_key = MasterKey::instance().derive_key(password, salt);

    KEKModel remote_kek_info = Server::instance().get_kek_info(temp_user.uuid);
    std::string server_updated_at = remote_kek_info.updated_at;
    KEKModel local_kek_info = get_local_kek(temp_user.id);

    try {
        check_kek_freshness();
        auto [kek, aad] = KekService::decrypt_kek(local_kek_info, master_key, temp_user.uuid);
        // Only now assign to user_data
        user_data = temp_user;
        MasterKey::instance().set_key(master_key);
        return true;
    } catch (const std::exception&) {
        try {
            auto [kek, aad] = KekService::decrypt_kek(remote_kek_info, master_key, temp_user.uuid);
            if (local_kek_info.updated_at != server_updated_at) {
                local_kek_info.enc_kek_cyphertext = remote_kek_info.enc_kek_cyphertext;
                local_kek_info.nonce = remote_kek_info.nonce;
                local_kek_info.updated_at = server_updated_at;
                db().update(local_kek_info);
            }
            user_data = temp_user;
            MasterKey::instance().set_key(master_key);
            return true;
        } catch (...) {
            throw std::runtime_error("password changed or data has been tampered");
        }
    }
}

bool UserManager::signup(const std::string &username, const std::string &email, const std::string &password) {
    //Function overloading
    setUser(username, email);
    //generate and set master key from password
    std::vector<uint8_t> salt_bytes = CryptoUtils::generate_nonce(16);
    user_data.salt = CryptoUtils::base64_encode(salt_bytes);
    const std::vector<uint8_t> master_key = MasterKey::instance().derive_key(password, salt_bytes);
    MasterKey::instance().set_key(master_key);
    user_data.uuid = Server::instance().get_new_user_uuid();

    //generate and encrpyt KEK with master key
    std::vector<uint8_t> kek_bytes = KeyGeneration::generate_symmetric_key();
    KEKModel kek_data = KekService::encrypt_kek(
        kek_bytes,
        master_key,
        user_data.uuid,
        -1 // Placeholder for user ID, should be set after saving user data
    );
    setKEK(std::make_shared<const KEKModel>(kek_data));

    const IdentityKeyPairs identity_keys = KeyGeneration::generate_identity_keypair();
    const SignedPreKey signed_prekey = KeyGeneration::generate_signed_prekey(identity_keys.ed25519_private->to_evp_pkey());
    std::vector<OPKPair> opks;
    // VaultManager vault_manager = VaultManager();
    VaultManager::generate_user_vault(
        kek_bytes,
        opks,
        this->user_data,
        identity_keys,
        signed_prekey
    );
    nlohmann::json server_response = save();
    if (server_response.empty()) {
        throw std::runtime_error("Failed to save user data remotely.");
    }
    user_data.uuid = server_response["user"]["uuid"].get<std::string>();
    return true; // Return true if signup is successful
}

void UserManager::changePassword(const std::string& user_uuid, const std::string& old_password, const std::string &new_password) {
    // Implement change password logic here
    // 1. Check if the old password is correct
    load(user_uuid);
    if (user_data.username.empty()) {
        throw std::runtime_error("User not found with UUID: " + user_uuid);
    }
    check_kek_freshness();
    setKEK(std::make_shared<const KEKModel>(get_local_kek(user_data.id)));
    const std::vector<uint8_t> old_salt_bytes = CryptoUtils::base64_decode(user_data.salt);
    const std::vector<uint8_t> old_master_key = MasterKey::instance().derive_key(old_password,old_salt_bytes);

    const std::vector<uint8_t> kek = get_decrypted_kek(old_master_key);
    if (kek.empty()) {
        throw std::runtime_error("Failed to decrypt KEK with old password.");
    }
    // 2. Generate new Master key
    const std::vector<uint8_t> new_salt_bytes = CryptoUtils::generate_nonce(16);
    const std::vector<uint8_t> new_master_key = MasterKey::instance().derive_key(new_password, new_salt_bytes);

    // 3. Encrypt KEK with new Master key
    KEKModel new_kek_model = KekService::encrypt_kek(
        kek,
        new_master_key,
        user_data.uuid,
        user_data.id // Use the current user ID
    );
    new_kek_model.id = getKEK().id; // Preserve the existing KEK ID
    setKEK(std::make_shared<const KEKModel>(new_kek_model));
    // 4. Update user data
    user_data.salt = CryptoUtils::base64_encode(new_salt_bytes);

    // 5. Get Ed25519 IK private for signing request header
    auto ed25519_private_key_bytes = CryptoUtils::decrypt_with_key(
        CryptoUtils::base64_decode(user_data.ed25519_identity_key_private_enc),
        CryptoUtils::base64_decode(user_data.ed25519_identity_key_private_nonce),
        new_master_key,
        VaultManager::get_ed25519_identity_associated_data()
    );
    if (ed25519_private_key_bytes.empty()) {
        throw std::runtime_error("Failed to decrypt Ed25519 identity key with new password.");
    }
    Ed25519PrivateKey ed25519_private_key(ed25519_private_key_bytes);
    nlohmann::json server_response = Server::instance().update_kek_info(
        new_kek_model.enc_kek_cyphertext,
        new_kek_model.nonce,
        new_kek_model.updated_at,
        user_data.uuid,
        ed25519_private_key
    );
    // write the new KEK to the database
    if (server_response.empty()) {
        throw std::runtime_error("Failed to update KEK info on server.");
    }
    // Update the KEK in the database
    if (new_kek_model.id <= 0) {
        throw std::runtime_error("Invalid KEK ID.");
    }
    db().update(new_kek_model);
}

void UserManager::setUser(const UserModel& user) {
    this->user_data = user;
}
void UserManager::setUser(const std::string& username, const std::string& email) {
    this->user_data.username = username;
    this->user_data.email = email;
}

std::vector<uint8_t> UserManager::get_decrypted_kek(const std::vector<uint8_t> &master_key) const {
    // Get the current KEK model and user UUID
    KEKModel kek_model = get_local_kek(user_data.id);
    // const std::vector<uint8_t>& master_key = MasterKey::instance().get();

    // Decrypt the KEK using KekService
    const std::string& user_uuid = user_data.uuid;
    auto [decrypted_kek, _aad] = KekService::decrypt_kek(kek_model, master_key, user_uuid);

    return decrypted_kek;
};


void UserManager::check_kek_freshness() {
    // Fetch KEK info from server
    KEKModel server_kek_info = Server::instance().get_kek_info(user_data.uuid);

    std::string server_updated_at = server_kek_info.updated_at;
    KEKModel local_Kek_Model = get_local_kek(user_data.id);
    std::string local_updated_at = local_Kek_Model.updated_at;

    if (!server_updated_at.empty() && local_updated_at != server_updated_at) {
        throw std::runtime_error(
            "Your password was changed on another device. Please use the new password. Server updated at: " + server_updated_at);
    }
}

nlohmann::json UserManager::export_keys() {
    nlohmann::json keys_json;
    load(user_data.uuid);
    keys_json["ed25519_identity_key_public"]= user_data.ed25519_identity_key_public;
    keys_json["ed25519_identity_key_private_enc"] = user_data.ed25519_identity_key_private_enc;
    keys_json["ed25519_identity_key_private_nonce"] = user_data.ed25519_identity_key_private_nonce;
    keys_json["x25519_identity_key_public"] = user_data.x25519_identity_key_public;
    keys_json["x25519_identity_key_private_enc"] = user_data.x25519_identity_key_private_enc;
    keys_json["x25519_identity_key_private_nonce"] = user_data.x25519_identity_key_private_nonce;
    keys_json["signed_prekey_public"] = user_data.signed_prekey_public;
    keys_json["signed_prekey_signature"] = user_data.signed_prekey_signature;
    keys_json["signed_prekey_private_enc"] = user_data.signed_prekey_private_enc;
    keys_json["signed_prekey_private_nonce"] = user_data.signed_prekey_private_nonce;
    keys_json["opks"] = user_data.opks;
    return keys_json;
}

void UserManager::import_keys(const nlohmann::json& keys, const std::string &password, const std::string &username) {
    if (!db().get_all<UserModelORM>(where(c(&UserModelORM::username) == username)).empty()) {
        throw std::runtime_error("User already exists locally with username: " + username);
    }

    auto user = Server::instance().get_user_by_name(username);
    UserModel temp_user = user;

    std::vector<uint8_t> salt_bytes = CryptoUtils::base64_decode(user.salt);
    if (salt_bytes.empty()) {
        throw std::runtime_error("Invalid salt in user data.");
    }
    std::vector<uint8_t> master_key = MasterKey::instance().derive_key(password, salt_bytes);
    KEKModel kek_info = Server::instance().get_kek_info(temp_user.uuid);
    auto [kek, _aad] = KekService::decrypt_kek(kek_info, master_key, temp_user.uuid);
    if (kek.empty()) {
        throw std::runtime_error("Failed to decrypt KEK with provided password.");
    }

    temp_user.ed25519_identity_key_public = keys["ed25519_identity_key_public"];
    temp_user.ed25519_identity_key_private_enc = keys["ed25519_identity_key_private_enc"];
    temp_user.ed25519_identity_key_private_nonce = keys["ed25519_identity_key_private_nonce"];
    temp_user.x25519_identity_key_public = keys["x25519_identity_key_public"];
    temp_user.x25519_identity_key_private_enc = keys["x25519_identity_key_private_enc"];
    temp_user.x25519_identity_key_private_nonce = keys["x25519_identity_key_private_nonce"];
    temp_user.signed_prekey_public = keys["signed_prekey_public"];
    temp_user.signed_prekey_signature = keys["signed_prekey_signature"];
    temp_user.signed_prekey_private_enc = keys["signed_prekey_private_enc"];
    temp_user.signed_prekey_private_nonce = keys["signed_prekey_private_nonce"];
    // temp_user.opks = keys["opks"].dump();

    user_data = temp_user;

    UserModelORM user_orm;
    user_orm = user_data;
    kek_info.user_id = db().insert(user_orm);
    if (!kek_info.user_id) {
        throw std::runtime_error("Failed to save user data to database.");
    }
    if (!db().insert(kek_info)) {
        throw std::runtime_error("Failed to save KEK data to database.");
    }
}
