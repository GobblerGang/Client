//
// Created by Ruairi on 04/06/2025.
//

#ifndef USERMODELORM_H
#define USERMODELORM_H
#include <string>

#include "UserModel.h"
struct UserModel;
// Flat struct for ORM
struct UserModelORM {
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

    UserModelORM& operator=(const UserModel& user) {
        uuid = user.uuid;
        username = user.username;
        email = user.email;
        ed25519_identity_key_public = user.ed25519_identity_key_public;
        ed25519_identity_key_private_enc = user.ed25519_identity_key_private_enc;
        ed25519_identity_key_private_nonce = user.ed25519_identity_key_private_nonce;
        x25519_identity_key_public = user.x25519_identity_key_public;
        x25519_identity_key_private_enc = user.x25519_identity_key_private_enc;
        x25519_identity_key_private_nonce = user.x25519_identity_key_private_nonce;
        salt = user.salt;
        signed_prekey_public = user.signed_prekey_public;
        signed_prekey_signature = user.signed_prekey_signature;
        signed_prekey_private_enc = user.signed_prekey_private_enc;
        signed_prekey_private_nonce = user.signed_prekey_private_nonce;
        opks_json = user.opks_json;
        return *this;
    }
};

#endif //USERMODELORM_H
