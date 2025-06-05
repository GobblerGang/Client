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
    UserManager();
    void login(const std::string& username, const std::string& password);

    bool signup(const std::string &username, const std::string &email, const std::string &password);
    void changePassword(const std::string& username, const std::string& password);
    bool checkKek();
    void handle_saving_remote_user_data();

    void setUser(const UserModel& user);
    void setUser(const std::string& username, const std::string& email);
    std::vector<uint8_t> get_decrypted_kek(const std::vector<uint8_t> &master_key) const;

    void check_kek_freshness();
protected:
    void load(const std::string& identifier) override;
    nlohmann::json save() override;
private:
    UserModel user_data;
    KEKModel get_local_kek(int user_id) const;
};



#endif //USERMANAGER_H
