//
// Created by Ruairi on 05/06/2025.
//
#include "UserModelORM.h"
#include "UserModel.h"

UserModelORM& UserModelORM::operator=(const UserModel &user) {
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

