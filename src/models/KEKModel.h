#pragma once
#include <string>

struct KEKModel {
    int id;
    std::string enc_kek_cyphertext; // Encrypted KEK,
    std::string nonce;              // Nonce,
    std::string updated_at;
    int user_id;
};