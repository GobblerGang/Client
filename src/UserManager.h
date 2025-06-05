//
// Created by Ruairi on 04/06/2025.
//

#ifndef USERMANAGER_H
#define USERMANAGER_H

#include <models/UserModel.h>
#include "RemoteUserManager.h"

// Derived class for managing user data locally
class UserManager: RemoteUserManager {
public:
    // #Default Constructor
    // Initializes a new UserManager instance
    UserManager();
    // #Function Declaration (call by const reference)
    // Authenticates a user with the provided credentials
    void login(const std::string& username, const std::string& password);
    // #Function Declaration (call by const reference)
    // Creates a new user account with the provided information
    bool signup(const std::string &username, const std::string &email, const std::string &password);
    // #Function Declaration (call by const reference)
    // Changes the user's password after verifying the old password
    void changePassword(const std::string& user_uuid, const std::string& old_password, const std::string &new_password);
    // #Function Declaration (returns bool)
    // Verifies if the KEK (Key Encryption Key) is valid
    bool checkKek();
    // #Function Declaration
    // Handles saving remote user data to local storage
    void handle_saving_remote_user_data();
    // #Function Declaration (call by const reference)
    // Sets the user data from a UserModel instance
    void setUser(const UserModel& user);
    // #Function Declaration (call by const reference)
    // Sets the user data with provided username and email
    void setUser(const std::string& username, const std::string& email);
    // #Function Declaration (call by const reference, returns by value)
    // Decrypts the KEK using the provided master key
    std::vector<uint8_t> get_decrypted_kek(const std::vector<uint8_t> &master_key) const;
    // #Function Declaration
    // Checks if the KEK needs to be refreshed
    void check_kek_freshness();
protected:
    // #Function Declaration (call by const reference)
    // Loads user data from the specified identifier
    void load(const std::string& identifier) override;
    // #Function Declaration (returns by value)
    // Saves the current user data to a JSON object
    nlohmann::json save() override;
private:
    UserModel user_data; // Internal storage for user data
    // #Function Declaration (returns by value)
    // Retrieves the local KEK for the specified user ID
    KEKModel get_local_kek(int user_id) const;
};



#endif //USERMANAGER_H
