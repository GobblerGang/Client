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
    std::string file_uuid;

    static File from_json(const nlohmann::json& data) {
        File file;
        file.file_name = data.contains("filename") ? data["filename"].get<std::string>() : "";
        file.enc_file_ciphertext = data.contains("enc_file_ciphertext") ? data["enc_file_ciphertext"].get<std::string>() : "";
        file.mime_type = data.contains("mime_type") ? data["mime_type"].get<std::string>() : "";
        file.file_nonce = data.contains("file_nonce") ? data["file_nonce"].get<std::string>() : "";
        file.enc_file_k = data.contains("enc_file_k") ? data["enc_file_k"].get<std::string>() : "";
        file.k_file_nonce = data.contains("k_file_nonce") ? data["k_file_nonce"].get<std::string>() : "";
        file.file_uuid = data.contains("file_uuid") ? data["file_uuid"].get<std::string>() : "";
        return file;
    }
};

#endif // FILEDATA_H 