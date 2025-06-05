//
// Created by Ruairi on 04/06/2025.
//

#ifndef REMOTEUSERMANAGER_H
#define REMOTEUSERMANAGER_H

#include <DataManager.h>
#include <models/RemoteUser.h>
#include <models/PublicKeys.h>

#include "models/KEKModel.h"

// Derived class for managing remote user data
class RemoteUserManager:DataManager {
public:
    RemoteUserManager();
    virtual ~RemoteUserManager() override = default;
protected:
    // Setters use reference args to avoid slicing
    // and set the pointers to the remote user, keys, and KEK data
    void setUser(std::shared_ptr<const RemoteUser> user) { user_remote_ptr = std::move(user); }
    void setKeys(std::shared_ptr<const PublicKeys> keys) { keys_remote_ptr = std::move(keys); }
    void setKEK(std::shared_ptr<const KEKModel> kek) { kek_data_ptr = std::move(kek); }
    const KEKModel& getKEK() const { return *kek_data_ptr; }
    virtual nlohmann::json save() override;
    virtual void load(const std::string& identifier) override;
private:
    std::shared_ptr<const RemoteUser> user_remote_ptr = nullptr;
    std::shared_ptr<const PublicKeys> keys_remote_ptr = nullptr;
    std::shared_ptr<const KEKModel> kek_data_ptr = nullptr;
};

#endif //REMOTEUSERMANAGER_H
