#include "FileManager.h"

#include <iostream>

#include "utils/cryptography/CryptoUtils.h"
#include "utils/cryptography/KeyGeneration.h"
#include "UserManager.h"
#include <stdexcept>
#include "Server.h"
#include "utils/cryptography/ThreexDH.h"
#include "utils/cryptography/VaultManager.h"
#include "utils/cryptography/keys/MasterKey.h"
#include "models/File.h"
#include "utils/cryptography/KeyGeneration.h"

// Add a member variable for UserManager reference in FileManager's implementation file

// Store a reference to UserManager

// Constructor to accept UserManager reference
FileManager::FileManager(UserManager* user_manager)
    : userManager_(user_manager)
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
        encrypt(fileBytes, mimeType, fileName);

        // 3. Upload to server using Server singleton
        const UserModel current_user = userManager_->getUser();
        auto vault = VaultManager::get_user_vault(current_user);
        auto master_key = MasterKey::instance().get();
        auto kek = userManager_->get_decrypted_kek(master_key);
        auto opt_keys = VaultManager::try_decrypt_private_keys(vault, kek);
        if (!opt_keys.has_value()) {
            throw std::runtime_error("Failed to decrypt private keys from vault.");
        }
        // const auto& [ed25519_private_key_bytes, x25519_private_key_bytes, signed_prekey_bytes] = *opt_keys;
        auto ed25519_private_key_bytes = CryptoUtils::decrypt_with_key(
        CryptoUtils::base64_decode(current_user.ed25519_identity_key_private_nonce),
        CryptoUtils::base64_decode(current_user.ed25519_identity_key_private_enc),
        kek,
        VaultManager::get_ed25519_identity_associated_data()
    );
        if (ed25519_private_key_bytes.empty()) {
            throw std::runtime_error("Failed to decrypt Ed25519 identity key with new password.");
        }
        Ed25519PrivateKey ed25519_private_key(ed25519_private_key_bytes);


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

void FileManager::shareFile(std::string file_uuid, const File &file_content, const std::string &mime_type,
                   const std::string &file_name, const std::string recipient_username)
{
    try {
        // 1. Query server for recipient's existence and public keys
        UserModel recipient_user = Server::instance().get_user_by_name(recipient_username);
        if (recipient_user.uuid.empty()) {
            throw std::runtime_error("Recipient user does not exist.");
        }

        std::vector<uint8_t> recipient_ed25519_pub = CryptoUtils::base64_decode(recipient_user.ed25519_identity_key_public);
        std::vector<uint8_t> recipient_x25519_pub = CryptoUtils::base64_decode(recipient_user.x25519_identity_key_public);
        std::vector<uint8_t> recipient_spk_pub = CryptoUtils::base64_decode(recipient_user.signed_prekey_public);

        // 2. Get our own identity keys (assume we have them decrypted already)
        const UserModel current_user = userManager_->getUser();
        auto vault = VaultManager::get_user_vault(current_user);
        auto master_key = MasterKey::instance().get();
        auto kek = userManager_->get_decrypted_kek(master_key);
        auto opt_keys = VaultManager::try_decrypt_private_keys(vault, kek);
        if (!opt_keys.has_value()) {
            throw std::runtime_error("Failed to decrypt private keys from vault.");
        }
        auto ed25519_private_key_bytes = CryptoUtils::decrypt_with_key(
            CryptoUtils::base64_decode(current_user.ed25519_identity_key_private_nonce),
            CryptoUtils::base64_decode(current_user.ed25519_identity_key_private_enc),
            kek,
            VaultManager::get_ed25519_identity_associated_data()
        );
        if (ed25519_private_key_bytes.empty()) {
            throw std::runtime_error("Failed to decrypt Ed25519 identity key.");
        }
        Ed25519PrivateKey ed25519_private_key(ed25519_private_key_bytes);

        // 3. Perform 3XDH to derive shared secret
        // You will need to adapt this to your actual 3XDH API and key types
        auto [X25519PrivateKey, X25519PublicKey] = KeyGeneration::generate_ephemeral_x25519_keypair();
        std::vector<uint8_t> shared_secret = ThreeXDH::perform_3xdh_sender(
            ed25519_private_key.to_evp_pkey(),
            X25519PrivateKey.to_evp_pkey(),
            X25519PublicKey.to_evp_pkey(),
            X25519PublicKey.to_evp_pkey()
        );

        // 4. Create PAC (Protected Access Credential) using shared secret
        // This is a placeholder for your PAC creation logic
        PAC pac = CryptoUtils::create_pac(
            file_uuid,
            recipient_user.uuid,
            current_user.uuid,
            CryptoUtils::base64_decode(file_content.enc_file_k),
            CryptoUtils::base64_decode(file_content.k_file_nonce),
            X25519PublicKey.to_bytes(),
            0, // valid_until, set to 0 for no expiration
            ed25519_private_key.to_evp_pkey(),
            std::make_optional(file_name),
            std::make_optional(mime_type)
        );

        // 5. Send PAC to server
        auto [response, error] = Server::instance().send_pac(
            pac,
            current_user.uuid,
            recipient_username
        );
        if (!error.empty()) {
            throw std::runtime_error(error);
        }
        std::cout << "File shared successfully with " << recipient_username << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Share failed: " << e.what() << std::endl;
        throw;
    }
}
