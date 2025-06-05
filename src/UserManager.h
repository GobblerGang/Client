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
    // #Constructor
    UserManager();
    // #Function Declaration (call by const reference)
    void login(const std::string& username, const std::string& password);
    // #Function Declaration (call by const reference)
    bool signup(const std::string &username, const std::string &email, const std::string &password);
    // #Function Declaration (call by const reference)
    void changePassword(const std::string& user_uuid, const std::string& old_password, const std::string &new_password);
    // #Function Declaration (returns bool)
    bool checkKek();
    // #Function Declaration
    void handle_saving_remote_user_data();
    // #Function Declaration (call by const reference)
    void setUser(const UserModel& user);
    // #Function Declaration (call by const reference)
    void setUser(const std::string& username, const std::string& email);
    // #Function Declaration (call by const reference, returns by value)
    std::vector<uint8_t> get_decrypted_kek(const std::vector<uint8_t> &master_key) const;
    // #Function Declaration
    void check_kek_freshness();
protected:
    // #Function Declaration (call by const reference)
    void load(const std::string& identifier) override;
    // #Function Declaration (returns by value)
    nlohmann::json save() override;
private:
    UserModel user_data;
    // #Function Declaration (returns by value)
    KEKModel get_local_kek(int user_id) const;
};



#endif //USERMANAGER_H
