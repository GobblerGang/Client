#pragma once
#include <string>
#include <vector>

struct File {
    std::string file_name;
    std::string enc_file_ciphertext;
    std::string mime_type;
    std::string file_nonce;
    std::string enc_file_k;
    std::string k_file_nonce;
};
