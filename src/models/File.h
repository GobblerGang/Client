#ifndef FILEDATA_H
#define FILEDATA_H

#include <string>


struct File {
    std::string file_name;
    std::string enc_file_ciphertext;  // base64 encoded
    std::string mime_type;
    std::string file_nonce;           // base64 encoded
    std::string enc_file_k;           // base64 encoded
    std::string k_file_nonce;         // base64 encoded
};

#endif // FILEDATA_H 