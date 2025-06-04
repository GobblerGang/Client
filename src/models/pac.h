#pragma once
#include <string>
#include <vector>

struct PAC {
    std::string recipient_uuid;
    std::string file_uuid;
    std::string valid_until;
    std::string encrypted_file_key;
    std::string signature;
    std::string sender_ephemeral_public;
    std::string k_file_nonce;
};