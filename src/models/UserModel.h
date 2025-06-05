//
// Created by Ruairi on 04/06/2025.
//
#pragma once
#include <string>
#include <models/RemoteUser.h>
#include <models/PublicKeys.h>
#include "UserModelORM.h"
#ifndef USERMODEL_H
#define USERMODEL_H

// This struct is used for local user data storage.
// i.e. during runtime the logged-in user data is stored here.
struct UserModel: RemoteUser, PublicKeys {
    // Local Database ID
    int id;

    // Ed25519 identity key fields
    std::string ed25519_identity_key_private_enc;
    std::string ed25519_identity_key_private_nonce;

    // X25519 identity key fields
    std::string x25519_identity_key_private_enc;
    std::string x25519_identity_key_private_nonce;


    // Signed prekey fields
    std::string signed_prekey_private_enc;
    std::string signed_prekey_private_nonce;

    // One-time prekeys as JSON
    std::string opks_json;

    // #Assignment Operator Overload (call by const reference, returns by reference)
    UserModel& operator=(const UserModelORM& orm) {
        id = orm.id;
        uuid = orm.uuid;
        username = orm.username;
        email = orm.email;
        ed25519_identity_key_public = orm.ed25519_identity_key_public;
        ed25519_identity_key_private_enc = orm.ed25519_identity_key_private_enc;
        ed25519_identity_key_private_nonce = orm.ed25519_identity_key_private_nonce;
        x25519_identity_key_public = orm.x25519_identity_key_public;
        x25519_identity_key_private_enc = orm.x25519_identity_key_private_enc;
        x25519_identity_key_private_nonce = orm.x25519_identity_key_private_nonce;
        salt = orm.salt;
        signed_prekey_public = orm.signed_prekey_public;
        signed_prekey_signature = orm.signed_prekey_signature;
        signed_prekey_private_enc = orm.signed_prekey_private_enc;
        signed_prekey_private_nonce = orm.signed_prekey_private_nonce;
        opks_json = orm.opks_json;
        return *this;
    }
    // #Explicit Constructor (call by const reference)
    explicit UserModel(const UserModelORM& orm) {
        *this = orm; // Uses the assignment operator
    }
    // #Default Constructor
    UserModel() = default; // Default constructor
};
#endif //USERMODEL_H
