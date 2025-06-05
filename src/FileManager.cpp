#include "FileManager.h"
#include "utils/cryptography/CryptoUtils.h"
#include "utils/cryptography/KeyGeneration.h"
#include "UserManager.h"
#include <stdexcept>

FileManager::FileManager(const File& data) : data_(data) {}

void FileManager::encrypt(const std::vector<uint8_t>& plain_text, const std::string& mime_type) {
    // Generate a random k_file
    std::vector<uint8_t> k_file = KeyGeneration::generate_symmetric_key();
    
    // Encrypt the file with k_file
    auto [file_nonce, enc_file] = CryptoUtils::encrypt_with_key(plain_text, k_file);
    

    std::vector<uint8_t> kek = UserManager::get_decrypted_kek();
    
    // Encrypt k_file with KEK
    auto [k_file_nonce, enc_k_file] = CryptoUtils::encrypt_with_key(k_file, kek);

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

std::vector<uint8_t> FileManager::decryptWithKey(
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::optional<std::vector<uint8_t>>& associated_data
) const {
    return CryptoUtils::decrypt_with_key(nonce, ciphertext, key, associated_data);
}
