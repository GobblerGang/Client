#include "File.h"
#include "utils/VaultManager.h"
#include "utils/MasterKey.h"
#include <stdexcept>

#
File::File(const FileData& data) : data_(data) {}

void File::encrypt(const std::vector<uint8_t>& file_content, const std::string& mime_type) {
    // Generate a random k_file
    std::vector<uint8_t> k_file = CryptoUtils::generate_kek();
    
    // Encrypt the file with k_file
    auto [file_nonce, enc_file] = encryptWithKey(file_content, k_file);
    
    // Get the KEK from the database and decrypt it with master key
    std::vector<uint8_t> kek = getDecryptedKEK();
    
    // Encrypt k_file with KEK
    auto [k_file_nonce, enc_k_file] = encryptWithKey(k_file, kek);
    
    // Store all the encrypted data
    data_.file_nonce = VaultManager::base64_encode(file_nonce);
    data_.enc_file_ciphertext = VaultManager::base64_encode(enc_file);
    data_.mime_type = mime_type;
    data_.enc_file_k = VaultManager::base64_encode(enc_k_file);
    data_.k_file_nonce = VaultManager::base64_encode(k_file_nonce);
}

std::vector<uint8_t> File::decrypt() const {
    // Get the KEK from the database and decrypt it with master key
    std::vector<uint8_t> kek = getDecryptedKEK();
    
    // Decrypt k_file using KEK
    std::vector<uint8_t> k_file = decryptWithKey(
        VaultManager::base64_decode(data_.k_file_nonce),
        VaultManager::base64_decode(data_.enc_file_k),
        kek
    );
    
    // Decrypt the file using k_file
    return decryptWithKey(
        VaultManager::base64_decode(data_.file_nonce),
        VaultManager::base64_decode(data_.enc_file_ciphertext),
        k_file
    );
}

nlohmann::json File::prepareForUpload() const {
    nlohmann::json j;
    j["file_name"] = data_.file_name;
    j["enc_file_ciphertext"] = data_.enc_file_ciphertext;
    j["mime_type"] = data_.mime_type;
    j["file_nonce"] = data_.file_nonce;
    j["enc_file_k"] = data_.enc_file_k;
    j["k_file_nonce"] = data_.k_file_nonce;
    return j;
}

nlohmann::json File::save() {
    return prepareForUpload();
}

void File::load(const std::string& identifier) {
    // TODO: Implement loading from storage
    // This will be implemented when we have the storage system ready
    // For now, this is a placeholder
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> File::encryptWithKey(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    const std::optional<std::vector<uint8_t>>& associated_data
) const {
    return CryptoUtils::encrypt_with_key(plaintext, key, associated_data);
}

std::vector<uint8_t> File::decryptWithKey(
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& key,
    const std::optional<std::vector<uint8_t>>& associated_data
) const {
    return CryptoUtils::decrypt_with_key(nonce, ciphertext, key, associated_data);
}

std::vector<uint8_t> File::getDecryptedKEK() const {
    // Get the KEK from RemoteUserManager
    RemoteUserManager userManager;
    const KEKModel& kek = userManager.getKEK();
    
    // Get the master key
    std::vector<uint8_t> masterKey = MasterKey::instance().get();
    
    // TODO: Get the associated data format once it's available
    // For now, we'll use an empty associated data
    std::optional<std::vector<uint8_t>> associated_data = std::nullopt;
    
    // Decrypt the KEK
    return decryptWithKey(
        VaultManager::base64_decode(kek.nonce),
        VaultManager::base64_decode(kek.enc_kek_cyphertext),
        masterKey,
        associated_data
    );
} 