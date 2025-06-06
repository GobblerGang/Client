#include "FileManager.h"

#include <iostream>

#include "utils/cryptography/CryptoUtils.h"
#include "utils/cryptography/KeyGeneration.h"
#include "UserManager.h"
#include <stdexcept>
#include "Server.h"
#include "utils/cryptography/VaultManager.h"
#include "utils/cryptography/keys/MasterKey.h"


// Add a member variable for UserManager reference in FileManager's implementation file

// Store a reference to UserManager

// Constructor to accept UserManager reference
FileManager::FileManager(UserManager* user_manager)
    : data_(), userManager_(user_manager)
{}

void FileManager::encrypt(const std::vector<uint8_t>& plain_text, const std::string& mime_type, const std::string &filename) {
    // Generate a random k_file
    std::vector<uint8_t> k_file = KeyGeneration::generate_symmetric_key();
    auto file_nonce = CryptoUtils::generate_nonce(12);
    // Encrypt the file with k_file
    auto enc_file = CryptoUtils::encrypt_with_key(plain_text, k_file, file_nonce, std::nullopt );
    const std::vector<uint8_t>& master_key = MasterKey::instance().get();
    std::vector<uint8_t> kek = userManager_->get_decrypted_kek(master_key);

    // Encrypt k_file with KEK
    auto k_file_nonce = CryptoUtils::generate_nonce(12);
    auto enc_k_file = CryptoUtils::encrypt_with_key(k_file, kek, k_file_nonce, std::nullopt);

    // Store all the encrypted data
    data_.file_nonce = CryptoUtils::base64_encode(file_nonce);
    data_.enc_file_ciphertext = CryptoUtils::base64_encode(enc_file);
    data_.mime_type = mime_type;
    data_.file_name = filename;
    data_.enc_file_k = CryptoUtils::base64_encode(enc_k_file);
    data_.k_file_nonce = CryptoUtils::base64_encode(k_file_nonce);
}

nlohmann::json FileManager::prepareForUpload() const {
    nlohmann::json j;
    j["file_name"] = data_.file_name;
    j["enc_file_ciphertext"] = data_.enc_file_ciphertext;
    j["mime_type"] = data_.mime_type;
    j["file_nonce"] = data_.file_nonce;
    j["enc_file_k"] = data_.enc_file_k;
    j["k_file_nonce"] = data_.k_file_nonce;
    return j;
}

nlohmann::json FileManager::save() {
    return prepareForUpload();
}

void FileManager::load(const std::string& identifier = "") {
    // this will get all owned and shared files for the user
    auto current_user = userManager_->getUser();
    const UserModel user = userManager_->getUser();
    auto [files_json, error] = Server::instance().get_owned_files(
        user.uuid,
        userManager_->get_ed25519_identity_key_private()
    );
    if (!error.empty()) {
        throw std::runtime_error("Failed to load files: " + error);
    }
    std::cout << "Files JSON: " << files_json.dump(4) << std::endl;
    setFilesFromJson(files_json["files"], true);
    auto pacs_json = Server::instance().get_user_pacs(
        user.uuid,
        userManager_->get_ed25519_identity_key_private()
        );
    std::cout << "PACs JSON: " << pacs_json.dump(4) << std::endl;

    nlohmann::json issued_pacs = pacs_json["issued_pacs"];
    nlohmann::json received_pacs = pacs_json["received_pacs"];
    setFilesFromJson(received_pacs, false);
}

void FileManager::setFilesFromJson(const nlohmann::json &files_json, bool isOwner = false) {
    if (!files_json.is_array()) {
        throw std::runtime_error("Invalid files JSON format: expected an array");
    }
    for (const auto& file_json : files_json) {
        std::cout << "File JSON: " << file_json.dump(4) << std::endl;
        File file;

        if (file_json.contains("filename")) {
            file.file_name = file_json["filename"].get<std::string>();
        } else if (file_json.contains("file_name")) {
            file.file_name = file_json["file_name"].get<std::string>();
        }
        file.file_uuid = file_json["file_uuid"].get<std::string>();
        file.mime_type = file_json["mime_type"].get<std::string>();
        file.isOwner = isOwner;
        files_.push_back(file);
    }
}

void FileManager::refreshFiles() {
    try {
        load();
    } catch (const std::exception& e) {
        std::cerr << "Error refreshing files: " << e.what() << std::endl;
    }
}

void FileManager::uploadFile(const std::vector<uint8_t>& fileBytes,
                           const std::string& mimeType,
                           const std::string& fileName) {
    try {
        // 1. Create File struct and set file name
        std::cout << "File name: " << fileBytes.size() << std::endl;
        // 2. Encrypt the file
        encrypt(fileBytes, mimeType, fileName);

        // 3. Upload to server using Server singleton
        const UserModel current_user = userManager_->getUser();

        Ed25519PrivateKey ed25519_private_key= userManager_->get_ed25519_identity_key_private();


        auto [response, error] = Server::instance().upload_file(
            data_,
            current_user.uuid,
            ed25519_private_key
        );

        if (!error.empty()) {
            throw std::runtime_error(error);
        }

    } catch (const std::exception& e) {
        throw std::runtime_error("Upload failed: " + std::string(e.what()));
    }
}
