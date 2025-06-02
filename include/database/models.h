#pragma once
#include <string>

struct User {
    int id;
    std::string uuid;
    std::string username;
    std::string email;
    std::string identity_key_public;
    std::string signed_prekey_public;
    std::string signed_prekey_signature;
    std::string salt;
    std::string identity_key_private_enc;
    std::string identity_key_private_nonce;
    std::string signed_prekey_private_enc;
    std::string signed_prekey_private_nonce;
    std::string opks_json;
};

struct KEK {
    int id;
    std::string enc_kek;
    std::string kek_nonce;
    std::string updated_at;
    int user_id;
};
