#include "FileManager.h"

#include <iostream>

#include "utils/cryptography/CryptoUtils.h"
#include "utils/cryptography/KeyGeneration.h"
#include "UserManager.h"
#include <stdexcept>
#include "Server.h"
#include "utils/cryptography/VaultManager.h"
#include "utils/cryptography/keys/MasterKey.h"
#include "utils/cryptography/3xDH.h"


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
    setFilesFromJson(files_json["files"], files_);
    auto pacs_json = Server::instance().get_user_pacs(
        user.uuid,
        userManager_->get_ed25519_identity_key_private()
        );
    std::cout << "PACs JSON: " << pacs_json.dump(4) << std::endl;

    nlohmann::json issued_pacs = pacs_json["issued_pacs"];
    const nlohmann::json received_pacs = pacs_json["received_pacs"];
    setFilesFromJson(received_pacs, received_pacs_);
    setFilesFromJson(issued_pacs, issued_pacs_);
}



void FileManager::refreshFiles() {
    try {
        load();
    } catch (const std::exception& e) {
        std::cerr << "Error refreshing files: " << e.what() << std::endl;
    }
}

std::vector<uint8_t> FileManager::downloadFile(const PAC &pac, const UserModel &user_model) {
    // get issuer keys
    auto [keys_json, error] = Server::instance().get_user_keys(
        user_model.uuid,
        pac.issuer_id,
        userManager_->get_ed25519_identity_key_private()
        );

    if (!error.empty()) {
        throw std::runtime_error("Failed to get user keys: " + error);
    }
    // verify spk
    auto issuer_ed25519_ik_pub_bytes = CryptoUtils::base64_decode(keys_json["ed25519_identity_key_public"]);
    std::cout<< "Issuer Ed25519 IK Public Bytes: " << CryptoUtils::base64_encode(issuer_ed25519_ik_pub_bytes) << std::endl;
    // auto issuer_spk_pub_bytes = CryptoUtils::base64_decode(keys_json["signed_prekey_public"]);
    // auto issuer_spk_signature_bytes = CryptoUtils::base64_decode(keys_json["signed_prekey_signature"]);
    // if (!CryptoUtils::verify_spk(issuer_spk_pub_bytes, issuer_spk_signature_bytes, issuer_ed25519_ik_pub_bytes)) {
    //     throw std::runtime_error("Failed to verify signed prekey, possible tampering.");
    // }

    Ed25519PublicKey issuer_ed25519_identity_key_public_ = Ed25519PublicKey(issuer_ed25519_ik_pub_bytes);
    // if (!CryptoUtils::verify_pac(pac.to_json(), issuer_ed25519_identity_key_public_.to_evp_pkey())) {
    //     throw std::runtime_error("Failed to verify PAC, possible tampering.");
    // }
    auto issuer_x25519_identity_key_public_ = X25519PublicKey(CryptoUtils::base64_decode(keys_json["x25519_identity_key_public"]));
    // decrypt recipients ik and spk priv
    X25519PrivateKey x25519_recipient_ik_priv = userManager_->get_x25519_identity_key_private();
    X25519PrivateKey x25519_recipient_spk_priv = userManager_->get_x25519_signed_prekey_private();

    X25519PublicKey sender_ephemeral_public = X25519PublicKey(CryptoUtils::base64_decode(pac.sender_ephemeral_public));
    auto shared_key = ThreeXDH::perform_3xdh_recipient(x25519_recipient_ik_priv.to_evp_pkey(),
                                      x25519_recipient_spk_priv.to_evp_pkey(),
                                      issuer_ed25519_identity_key_public_.to_evp_pkey(),
                                      sender_ephemeral_public.to_evp_pkey()
                                      );
    auto k_file = CryptoUtils::decrypt_with_key(CryptoUtils::base64_decode(pac.k_file_nonce),
                                  CryptoUtils::base64_decode(pac.encrypted_file_key),
                                  shared_key);
    auto [json, error_msg]=Server::instance().download_file(
        pac.file_uuid,
        userManager_->get_ed25519_identity_key_private(),
        user_model.uuid
    );
    if (!error_msg.empty()) {
        throw std::runtime_error("Failed to download file: " + error_msg);
    }
    if (json.empty()) {
        throw std::runtime_error("Received empty response for file download");
    }
    auto file_name = json["filename"].get<std::string>();
    auto file_nonce = CryptoUtils::base64_decode(json["file_nonce"]);
    auto enc_file_ciphertext = CryptoUtils::base64_decode(json["encrypted_blob"]);
    auto file = CryptoUtils::decrypt_with_key(file_nonce, enc_file_ciphertext, k_file);
    return file;
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
