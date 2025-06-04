#pragma once
#include <string>
#include <vector>

struct File {
    std::string file_name;
    std::vector<uint8_t> enc_file_ciphertext;
    std::string mime_type;
    std::vector<uint8_t> file_nonce;
    std::vector<uint8_t> enc_file_k;
    std::vector<uint8_t> k_file_nonce;
};
