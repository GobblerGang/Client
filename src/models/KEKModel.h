#pragma once
#include <string>

struct KEKModel {
    std::string enc_kek_cyphertext; // Encrypted KEK, raw bytes
    std::string nonce;              // Nonce, raw bytes
    std::string updated_at;                  // ISO format timestamp
};