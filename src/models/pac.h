#pragma once
#include <string>
#include <vector>

struct PAC {
    std::string recipient_uuid;
    std::string file_uuid;
    std::string valid_until;
    std::vector<uint8_t> encrypted_file_key;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> sender_ephemeral_public;
    std::vector<uint8_t> k_file_nonce;
};