#include "../VaultManager.h"
#include "CryptoUtils.h"
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <optional>
#include <map>
#include <vector>
#include <string>
#include "keys/Ed25519Key.h"


using json = nlohmann::json;

// Define the associated data constants for encryption/decryption
const std::vector<uint8_t> VaultManager::ed25519_identity_associated_data = {'e','d','2','5','5','1','9','_','i','d','e','n','t','i','t','y','_','k','e','y'};
const std::vector<uint8_t> VaultManager::x25519_identity_associated_data = {'x','2','5','5','1','9','_','i','d','e','n','t','i','t','y','_','k','e','y'};
const std::vector<uint8_t> VaultManager::spk_associated_data = {'s','i','g','n','e','d','_','p','r','e','k','e','y'};
const std::vector<uint8_t> VaultManager::opk_associated_data = {'o','p','k'};

std::string VaultManager::base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<uint8_t> VaultManager::base64_decode(const std::string& input) {
    BIO* bio, * b64;
    int maxLen = static_cast<int>(input.length());
    std::vector<uint8_t> buffer(maxLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), maxLen);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    int decodedLen = BIO_read(bio, buffer.data(), maxLen);
    if (decodedLen <= 0) {
        BIO_free_all(bio);
        throw std::runtime_error("Base64 decode failed.");
    }

    buffer.resize(decodedLen);
    BIO_free_all(bio);
    return buffer;
}

std::map<std::string, std::string> VaultManager::get_user_vault(const UserModel& user) {
    return {
            {"salt", user.salt},
            
            // Ed25519 identity key fields
            {"ed25519_identity_key_public", user.ed25519_identity_key_public},
            {"ed25519_identity_key_private_enc", user.ed25519_identity_key_private_enc},
            {"ed25519_identity_key_private_nonce", user.ed25519_identity_key_private_nonce},
            
            // X25519 identity key fields
            {"x25519_identity_key_public", user.x25519_identity_key_public},
            {"x25519_identity_key_private_enc", user.x25519_identity_key_private_enc},
            {"x25519_identity_key_private_nonce", user.x25519_identity_key_private_nonce},
            
            // Signed prekey fields
            {"signed_prekey_public", user.signed_prekey_public},
            {"signed_prekey_signature", user.signed_prekey_signature},
            {"signed_prekey_private_enc", user.signed_prekey_private_enc},
            {"signed_prekey_private_nonce", user.signed_prekey_private_nonce},
            
            // One-time prekeys
            {"opks", user.opks_json.empty() ? "[]" : user.opks_json},
    };
}

std::optional<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>, std::vector<uint8_t>>>
VaultManager::try_decrypt_private_keys(const std::map<std::string, std::string>& vault,
                                      const std::vector<uint8_t>& master_key) {
    // Decrypt Ed25519 identity key
    auto ed25519_ik_enc = base64_decode(vault.at("ed25519_identity_key_private_enc"));
    auto ed25519_ik_nonce = base64_decode(vault.at("ed25519_identity_key_private_nonce"));
    auto ed25519_identity_private_bytes = CryptoUtils::decrypt_with_key(
        ed25519_ik_nonce, ed25519_ik_enc, master_key, ed25519_identity_associated_data);
    
    // Decrypt X25519 identity key
    auto x25519_ik_enc = base64_decode(vault.at("x25519_identity_key_private_enc"));
    auto x25519_ik_nonce = base64_decode(vault.at("x25519_identity_key_private_nonce"));
    auto x25519_identity_private_bytes = CryptoUtils::decrypt_with_key(
        x25519_ik_nonce, x25519_ik_enc, master_key, x25519_identity_associated_data);
    
    // Decrypt signed prekey
    auto spk_enc = base64_decode(vault.at("signed_prekey_private_enc"));
    auto spk_nonce = base64_decode(vault.at("signed_prekey_private_nonce"));
    auto spk_private_bytes = CryptoUtils::decrypt_with_key(
        spk_nonce, spk_enc, master_key, spk_associated_data);

    return std::make_tuple(ed25519_identity_private_bytes, x25519_identity_private_bytes, spk_private_bytes);
}

bool VaultManager::verify_decrypted_keys(
    const std::vector<uint8_t>& ed25519_identity_private_bytes,
    const std::vector<uint8_t>& x25519_identity_private_bytes,
    const std::vector<uint8_t>& spk_private_bytes,
    const std::map<std::string, std::string>& vault) {

    // Construct key objects from bytes
    Ed25519PrivateKey ed25519_identity_private(ed25519_identity_private_bytes);
    X25519PrivateKey x25519_identity_private(x25519_identity_private_bytes);
    X25519PrivateKey spk_private(spk_private_bytes);

    // Get public keys from vault and decode from base64
    std::vector<uint8_t> ed25519_identity_public_bytes = base64_decode(vault.at("ed25519_identity_key_public"));
    std::vector<uint8_t> x25519_identity_public_bytes = base64_decode(vault.at("x25519_identity_key_public"));
    std::vector<uint8_t> spk_public_bytes = base64_decode(vault.at("signed_prekey_public"));

    Ed25519PublicKey ed25519_identity_public(ed25519_identity_public_bytes);
    X25519PublicKey x25519_identity_public(x25519_identity_public_bytes);
    X25519PublicKey spk_public(spk_public_bytes);

    // Derive public key from private and compare to vault public key
    std::vector<uint8_t> derived_ed25519_identity_pub = ed25519_identity_private.get_public_key_bytes();
    std::vector<uint8_t> derived_x25519_identity_pub = x25519_identity_private.get_public_key_bytes();
    std::vector<uint8_t> derived_spk_pub = spk_private.get_public_key_bytes();

    return derived_ed25519_identity_pub == ed25519_identity_public.to_bytes() &&
           derived_x25519_identity_pub == x25519_identity_public.to_bytes() &&
           derived_spk_pub == spk_public.to_bytes();
}

std::map<std::string, std::string> VaultManager::generate_user_vault(
    const Ed25519PrivateKey& ed25519_identity_private,
    const Ed25519PublicKey& ed25519_identity_public,
    const X25519PrivateKey& x25519_identity_private,
    const X25519PublicKey& x25519_identity_public,
    const X25519PrivateKey& spk_private,
    const X25519PublicKey& spk_public,
    const std::vector<uint8_t>& spk_signature,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& master_key,
    const std::vector<OPKPair>& opks) {

    // Encrypt Ed25519 identity key
    auto [ed25519_ik_nonce, ed25519_ik_enc] = CryptoUtils::encrypt_with_key(
        ed25519_identity_private.to_bytes(), master_key, ed25519_identity_associated_data);
    
    // Encrypt X25519 identity key
    auto [x25519_ik_nonce, x25519_ik_enc] = CryptoUtils::encrypt_with_key(
        x25519_identity_private.to_bytes(), master_key, x25519_identity_associated_data);
    
    // Encrypt signed prekey
    auto [spk_nonce, spk_enc] = CryptoUtils::encrypt_with_key(
        spk_private.to_bytes(), master_key, spk_associated_data);

    // Encrypt one-time prekeys
    json opks_json_list = json::array();
    for (const auto& opk : opks) {
        std::string opk_pub_base64 = base64_encode(opk.public_key.to_bytes());
        auto [opk_nonce, opk_enc] = CryptoUtils::encrypt_with_key(
            opk.private_key.to_bytes(), master_key, opk_associated_data);

        opks_json_list.push_back({
            {"public", opk_pub_base64},
            {"private_enc", base64_encode(opk_enc)},
            {"private_nonce", base64_encode(opk_nonce)}
        });
    }

    return {
        {"salt", base64_encode(salt)},
        
        // Ed25519 identity key fields
        {"ed25519_identity_key_public", base64_encode(ed25519_identity_public.to_bytes())},
        {"ed25519_identity_key_private_enc", base64_encode(ed25519_ik_enc)},
        {"ed25519_identity_key_private_nonce", base64_encode(ed25519_ik_nonce)},
        
        // X25519 identity key fields
        {"x25519_identity_key_public", base64_encode(x25519_identity_public.to_bytes())},
        {"x25519_identity_key_private_enc", base64_encode(x25519_ik_enc)},
        {"x25519_identity_key_private_nonce", base64_encode(x25519_ik_nonce)},
        
        // Signed prekey fields
        {"signed_prekey_public", base64_encode(spk_public.to_bytes())},
        {"signed_prekey_signature", base64_encode(spk_signature)},
        {"signed_prekey_private_enc", base64_encode(spk_enc)},
        {"signed_prekey_private_nonce", base64_encode(spk_nonce)},
        
        // One-time prekeys
        {"opks", opks_json_list.dump()},
    };
}

std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
VaultManager::decrypt_all_opks(const std::string& opks_json, const std::vector<uint8_t>& master_key) {
    json opks_json_list = json::parse(opks_json);
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> decrypted_opks;

    for (const auto& opk : opks_json_list) {
        auto private_nonce = base64_decode(opk.at("private_nonce").get<std::string>());
        auto private_enc = base64_decode(opk.at("private_enc").get<std::string>());
        auto public_bytes = base64_decode(opk.at("public").get<std::string>());

        auto priv_bytes = CryptoUtils::decrypt_with_key(
            private_nonce, private_enc, master_key, opk_associated_data);
        decrypted_opks.emplace_back(priv_bytes, public_bytes);
    }

    return decrypted_opks;
}

std::vector<OPKPair> VaultManager::keypairs_from_opk_bytes(
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& decrypted_opks) {

    std::vector<OPKPair> opk_keypairs;
    for (const auto& [priv_bytes, pub_bytes] : decrypted_opks) {
        OPKPair pair{X25519PrivateKey(priv_bytes), X25519PublicKey(pub_bytes)};
        opk_keypairs.push_back(pair);
    }
    return opk_keypairs;
}