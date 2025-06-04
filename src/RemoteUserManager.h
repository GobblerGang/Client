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
    virtual ~RemoteUserManager() override= default;
protected:
    void setUser(const RemoteUser& user) { user_remote = user; }
    void setKeys(const PublicKeys& keys) { keys_remote = keys; }
    void setKEK(const KEKModel& kek) { kek_data = kek; }
    const KEKModel& getKEK() const { return kek_data; }
    virtual nlohmann::json save() override;
    virtual void load(const std::string& identifier) override;
private:
    RemoteUser user_remote;
    PublicKeys keys_remote;
    KEKModel kek_data;
};

#endif //REMOTEUSERMANAGER_H
