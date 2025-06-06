//
// Created by Ruairi on 04/06/2025.
//

#ifndef USERMANAGER_H
#define USERMANAGER_H

#include <models/UserModel.h>
#include "RemoteUserManager.h"
#include "utils/cryptography/CryptoUtils.h"
#include "utils/cryptography/keys/Ed25519Key.h"

// Derived class for managing user data locally
class UserManager: RemoteUserManager {
public:
    // #Default Constructor
    // Initializes a new UserManager instance
    UserManager();
    ~UserManager() override;

    // #Function Declaration (call by const reference)
    // Authenticates a user with the provided credentials
    bool login(const std::string& username, const std::string& password);

    // #Function Declaration (call by const reference)
    // Creates a new user account with the provided information
    bool signup(const std::string &username, const std::string &email, const std::string &password);

    // #Function Declaration (call by const reference)
    // Changes the user's password after verifying the old password
    void changePassword(const std::string& user_uuid, const std::string& old_password, const std::string &new_password);

    void setUser(const UserModel& user);

    // #Function Declaration (call by const reference)
    // Sets the user data with provided username and email
    void setUser(const std::string& username, const std::string& email);

    const UserModel& getUser() const {
        return user_data;
    }
    // #Function Declaration (call by const reference, returns by value)
    // Decrypts the KEK using the provided master key
    std::vector<uint8_t> get_decrypted_kek(const std::vector<uint8_t> &master_key) const;

    Ed25519PrivateKey get_ed25519_identity_key_private();
    X25519PrivateKey get_x25519_identity_key_private();
    X25519PrivateKey get_x25519_signed_prekey_private();
    // #Function Declaration
    // Checks if the KEK needs to be refreshed
    void check_kek_freshness();

    nlohmann::json export_keys();
    void import_keys(const nlohmann::json& keys, const std::string &password, const std::string &username);
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
