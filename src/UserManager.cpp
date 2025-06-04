//
// Created by Ruairi on 04/06/2025.
//

#include "UserManager.h"
#include "nlohmann/json.hpp"

UserManager::UserManager() {
    user_data = UserModel();
    return;
}

nlohmann::json UserManager::save() {
    const RemoteUser remote_user = user_data;
    const PublicKeys public_keys = user_data;
    setUser(remote_user);
    setKeys(public_keys);

    nlohmann::json server_response = RemoteUserManager::save();
    handle_saving_remote_user_data(server_response);


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

}

void UserManager::changePassword(const std::string& username, const std::string& password) {
    // Implement change password logic here
}
void UserManager::handle_saving_remote_user_data(const nlohmann::json& server_response) {
    // This function handles the saving of remote user data
    // It should extract the user UUID and update the local user_data accordingly
    if (server_response.contains("user") && server_response["user"].contains("uuid")) {
        user_data.uuid = server_response["user"]["uuid"];
    }
    else if (server_response.contains("error")) {
        // Handle error case
        throw std::runtime_error("Error saving remote user data: " + server_response["error"].get<std::string>());
    }
}