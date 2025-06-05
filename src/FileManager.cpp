#include "FileManager.h"

#include <iostream>

#include "utils/cryptography/CryptoUtils.h"
#include "utils/cryptography/KeyGeneration.h"
#include "UserManager.h"
#include <stdexcept>
#include "Server.h"
#include "utils/cryptography/keys/MasterKey.h"

// Add a member variable for UserManager reference in FileManager's implementation file

// Store a reference to UserManager

// Constructor to accept UserManager reference
FileManager::FileManager(UserManager& user_manager)
    : userManager_(user_manager)
{}

void FileManager::encrypt(const std::vector<uint8_t>& plain_text, const std::string& mime_type) {
    // Generate a random k_file
    std::vector<uint8_t> k_file = KeyGeneration::generate_symmetric_key();
    auto file_nonce = CryptoUtils::generate_nonce(12);
    // Encrypt the file with k_file
    auto enc_file = CryptoUtils::encrypt_with_key(plain_text, k_file, file_nonce, std::nullopt );
    const std::vector<uint8_t>& master_key = MasterKey::instance().get();
    std::vector<uint8_t> kek = userManager_.get_decrypted_kek(master_key);

    // Encrypt k_file with KEK
    auto k_file_nonce = CryptoUtils::generate_nonce(12);
    auto enc_k_file = CryptoUtils::encrypt_with_key(k_file, kek, k_file_nonce, std::nullopt);

    // Store all the encrypted data
    data_.file_nonce = CryptoUtils::base64_encode(file_nonce);
    data_.enc_file_ciphertext = CryptoUtils::base64_encode(enc_file);
    data_.mime_type = mime_type;
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

void FileManager::load(const std::string& identifier) {
    // TODO: Implement loading from storage
    // This will be implemented when we have the storage system ready
    // For now, this is a placeholder
}

// std::vector<uint8_t> FileManager::decryptWithKey(
//     const std::vector<uint8_t>& nonce,
//     const std::vector<uint8_t>& ciphertext,
//     const std::vector<uint8_t>& key,
//     const std::optional<std::vector<uint8_t>>& associated_data
// ) const {
//     return CryptoUtils::decrypt_with_key(nonce, ciphertext, key, associated_data);
// }

void FileManager::uploadFile(const std::vector<uint8_t>& fileBytes,
                           const std::string& mimeType,
                           const std::string& fileName) {
    try {
        // 1. Create File struct and set file name
        std::cout << "File name: " << fileBytes.size() << std::endl;
        // 2. Encrypt the file
        encrypt(fileBytes, mimeType);

        // 3. Upload to server using Server singleton
        // auto [response, error] = Server::instance().upload_file(
        //     data_,
        //     data_.get_user_data().uuid,
        //     data_.get_identity_key()
        // );

        // if (!error.empty()) {
        //     throw std::runtime_error(error);
        // }

    } catch (const std::exception& e) {
        throw std::runtime_error("Upload failed: " + std::string(e.what()));
    }
}
