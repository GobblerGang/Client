#pragma once
#include <vector>
#include <string>

struct KEK {
    std::string enc_kek_cyphertext; // Encrypted KEK, raw bytes
    std::string nonce;              // Nonce, raw bytes
    std::string updated_at;                  // ISO format timestamp
};