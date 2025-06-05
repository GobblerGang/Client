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
    // #Default Constructor
    // Initializes a new RemoteUserManager instance
    RemoteUserManager();

    // #Virtual Destructor
    // Ensures proper cleanup of RemoteUserManager resources
    virtual ~RemoteUserManager() override = default;

protected:
    // Setters use reference args to avoid slicing
    // and set the pointers to the remote user, keys, and KEK data
    // #Function Declaration (call by const reference)
    // Sets the remote user data pointer
    void setRemoteUser(std::shared_ptr<const RemoteUser> user) { user_remote_ptr = std::move(user); }

    // #Function Declaration (call by const reference)
    // Sets the public keys pointer
    void setKeys(std::shared_ptr<const PublicKeys> keys) { keys_remote_ptr = std::move(keys); }

    // #Function Declaration (call by const reference)
    // Sets the KEK data pointer
    void setKEK(std::shared_ptr<const KEKModel> kek) { kek_data_ptr = std::move(kek); }

    // #Function Declaration (returns const reference)
    // Returns a constant reference to the KEK data
    const KEKModel& getKEK() const { return *kek_data_ptr; }

    // #Function Declaration (returns by value)
    // Saves the current remote user data to a JSON object
    virtual nlohmann::json save() override;

    // #Function Declaration (call by const reference)
    // Loads remote user data from the specified identifier
    virtual void load(const std::string& identifier) override;

private:
    // #Smart Pointer (shared_ptr)
    // Demonstrates shared ownership of remote user data
    std::shared_ptr<const RemoteUser> user_remote_ptr = nullptr; // Pointer to remote user data
    std::shared_ptr<const PublicKeys> keys_remote_ptr = nullptr; // Pointer to public keys
    std::shared_ptr<const KEKModel> kek_data_ptr = nullptr; // Pointer to KEK data
};

#endif //REMOTEUSERMANAGER_H
