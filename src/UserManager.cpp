//
// Created by Ruairi on 04/06/2025.
//

#include "UserManager.h"
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

UserManager::UserManager() {
    user_data = UserModel();
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

    user_data.uuid = server_response["user"]["uuid"].get<std::string>();

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

void UserManager::login(const std::string& username, const std::string& password) {
    // Implement login logic here
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
    check_kek_freshness();
    setKEK(std::make_shared<const KEKModel>(get_local_kek(user_data.id)));
    const std::vector<uint8_t> salt_bytes = CryptoUtils::base64_decode(user_data.salt);
    std::vector<uint8_t> old_master_key = MasterKey::instance().derive_key(old_password,salt_bytes);

    std::vector<uint8_t> kek = get_decrypted_kek();


}
void UserManager::handle_saving_remote_user_data() {

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
