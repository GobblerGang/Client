#pragma once
#include <vector>
#include <string>

struct KEK {
    std::vector<uint8_t> enc_kek_cyphertext; // Encrypted KEK, raw bytes
    std::vector<uint8_t> nonce;              // Nonce, raw bytes
    std::string updated_at;                  // ISO format timestamp
};