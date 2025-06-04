//
// Created by Ruairi on 04/06/2025.
//
#include <string>
#include <models/RemoteUser.h>
#include <models/PublicKeys.h>
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
};
#endif //USERMODEL_H
