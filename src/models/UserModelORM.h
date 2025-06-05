//
// Created by Ruairi on 04/06/2025.
//

#ifndef USERMODELORM_H
#define USERMODELORM_H
#include <string>
#include "UserModel.h"
struct UserModel;

// Flat struct for ORM (Object-Relational Mapping)
struct UserModel;
// Flat struct for ORM
struct UserModelORM {
    // #Member Variables
    int id;
    std::string uuid;
    std::string username;
    std::string email;
    std::string ed25519_identity_key_public;
    std::string ed25519_identity_key_private_enc;
    std::string ed25519_identity_key_private_nonce;
    std::string x25519_identity_key_public;
    std::string x25519_identity_key_private_enc;
    std::string x25519_identity_key_private_nonce;
    std::string salt;
    std::string signed_prekey_public;
    std::string signed_prekey_signature;
    std::string signed_prekey_private_enc;
    std::string signed_prekey_private_nonce;
    std::string opks_json;

    UserModelORM& operator=(const UserModel& user);
    // #Assignment Operator Overload (call by const reference, returns by reference)
    // Copies data from UserModel to this UserModelORM instance
    // Uses this pointer to refer to the current object
};

#endif //USERMODELORM_H
