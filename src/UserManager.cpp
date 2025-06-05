//
// Created by Ruairi on 04/06/2025.
//

#include "UserManager.h"
#include "nlohmann/json.hpp"
#include "utils/cryptography/keys/MasterKey.h"
#include "Server.h"
#include <utils/cryptography/CryptoUtils.h>

#include "KekService.h"
#include "utils/cryptography/KeyGeneration.h"

UserManager::UserManager() {
    user_data = UserModel();
}

nlohmann::json UserManager::save() {
    setUser(std::make_shared<const UserModel>(user_data));
    setKeys(std::make_shared<const UserModel>(user_data));

    nlohmann::json server_response = RemoteUserManager::save();
    // handle_saving_remote_user_data();
    if  (server_response.empty()) {
        throw std::runtime_error("Failed to save user data remotely.");
    }

    user_data.uuid = server_response["user"]["uuid"].get<std::string>();
    // TODO save user & kek to db

    return {};
}

void UserManager::load(const std::string& identifier) {
    // Implement get logic here
}

void UserManager::login(const std::string& username, const std::string& password) {
    // Implement login logic here
}

void UserManager::signup(const std::string& username, const std::string& email, const std::string& password) {
    // Implement signup logic here
    // This should call the save method to save the user data, after validating the input
    user_data.username = username;
    user_data.email = email;
    //generate and set master key from password
    std::vector<uint8_t> salt_bytes = CryptoUtils::generate_nonce(16);
    user_data.salt = std::string(salt_bytes.begin(), salt_bytes.end());
    const std::vector<uint8_t> master_key = MasterKey::instance().derive_key(password, salt_bytes);
    MasterKey::instance().set_key(master_key);
    user_data.uuid = Server::instance().get_new_user_uuid();
    //TODO generate and encrpyt KEK with master key
    KEKModel kek_data = KekService::encrypt_kek(
        KeyGeneration::generate_symmetric_key(),
        master_key,
        user_data.uuid,
        -1 // Placeholder for user ID, should be set after saving user data
    );



    //TODO generate and encrypt user keys with master key
}

void UserManager::changePassword(const std::string& username, const std::string& password) {
    // Implement change password logic here
}
void UserManager::handle_saving_remote_user_data() {

}

std::vector<uint8_t> get_decrypted_kek() {
    // MasterKey& master_key = MasterKey::instance();
    // str:: string user_uuid = user_data.uuid;
    return std::vector<uint8_t>();
};