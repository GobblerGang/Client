//
// Created by Ruairi on 05/06/2025.
//
#include "UserModelORM.h"
#include "UserModel.h"

UserModelORM& UserModelORM::operator=(const UserModel &user) {
    this->uuid = user.uuid;
    this->username = user.username;
    this->email = user.email;
    this->ed25519_identity_key_public = user.ed25519_identity_key_public;
    this->ed25519_identity_key_private_enc = user.ed25519_identity_key_private_enc;
    this->ed25519_identity_key_private_nonce = user.ed25519_identity_key_private_nonce;
    this->x25519_identity_key_public = user.x25519_identity_key_public;
    this->x25519_identity_key_private_enc = user.x25519_identity_key_private_enc;
    this->x25519_identity_key_private_nonce = user.x25519_identity_key_private_nonce;
    this->salt = user.salt;
    this->signed_prekey_public = user.signed_prekey_public;
    this->signed_prekey_signature = user.signed_prekey_signature;
    this->signed_prekey_private_enc = user.signed_prekey_private_enc;
    this->signed_prekey_private_nonce = user.signed_prekey_private_nonce;
    this->opks_json = user.opks_json;
    return *this;
}

