#include "VaultManager.h"
#include "CryptoUtils.h"
#include <openssl/bio.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <optional>
#include <map>
#include <vector>
#include <string>
#include "keys/Ed25519Key.h"
#include "keys/IdentityKeyPairs.h"
#include "keys/SignedPreKey.h"


using json = nlohmann::json;

// Define the associated data constants for encryption/decryption
const std::vector<uint8_t> VaultManager::ed25519_identity_associated_data = {'e','d','2','5','5','1','9','_','i','d','e','n','t','i','t','y','_','k','e','y'};
const std::vector<uint8_t> VaultManager::x25519_identity_associated_data = {'x','2','5','5','1','9','_','i','d','e','n','t','i','t','y','_','k','e','y'};
const std::vector<uint8_t> VaultManager::spk_associated_data = {'s','i','g','n','e','d','_','p','r','e','k','e','y'};
const std::vector<uint8_t> VaultManager::opk_associated_data = {'o','p','k'};

const std::vector<uint8_t>& VaultManager::get_ed25519_identity_associated_data() {
    return ed25519_identity_associated_data;
}
const std::vector<uint8_t>& VaultManager::get_x25519_identity_associated_data() {
    return x25519_identity_associated_data;
}
const std::vector<uint8_t>& VaultManager::get_spk_associated_data() {
    return spk_associated_data;
}
const std::vector<uint8_t>& VaultManager::get_opk_associated_data() {
    return opk_associated_data;
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
    auto ed25519_ik_enc = CryptoUtils::base64_decode(vault.at("ed25519_identity_key_private_enc"));
    auto ed25519_ik_nonce = CryptoUtils::base64_decode(vault.at("ed25519_identity_key_private_nonce"));
    auto ed25519_identity_private_bytes = CryptoUtils::decrypt_with_key(
        ed25519_ik_nonce, ed25519_ik_enc, master_key, ed25519_identity_associated_data);
    
    // Decrypt X25519 identity key
    auto x25519_ik_enc = CryptoUtils::base64_decode(vault.at("x25519_identity_key_private_enc"));
    auto x25519_ik_nonce = CryptoUtils::base64_decode(vault.at("x25519_identity_key_private_nonce"));
    auto x25519_identity_private_bytes = CryptoUtils::decrypt_with_key(
        x25519_ik_nonce, x25519_ik_enc, master_key, x25519_identity_associated_data);
    
    // Decrypt signed prekey
    auto spk_enc = CryptoUtils::base64_decode(vault.at("signed_prekey_private_enc"));
    auto spk_nonce = CryptoUtils::base64_decode(vault.at("signed_prekey_private_nonce"));
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
    std::vector<uint8_t> ed25519_identity_public_bytes = CryptoUtils::base64_decode(vault.at("ed25519_identity_key_public"));
    std::vector<uint8_t> x25519_identity_public_bytes = CryptoUtils::base64_decode(vault.at("x25519_identity_key_public"));
    std::vector<uint8_t> spk_public_bytes = CryptoUtils::base64_decode(vault.at("signed_prekey_public"));

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

void VaultManager::generate_user_vault(
    const std::vector<uint8_t> &kek,
    const std::vector<OPKPair> &opks,
    UserModel &user,
    const IdentityKeyPairs &identity_key_pairs,
    const SignedPreKey &spk) {

    // Encrypt Ed25519 identity key
    std::vector<uint8_t> ed25519_ik_nonce;
    const auto ed25519_ik_enc = CryptoUtils::encrypt_with_key(
        identity_key_pairs.ed25519_private->to_bytes(), kek, ed25519_ik_nonce, ed25519_identity_associated_data);
    
    // Encrypt X25519 identity key
    std::vector<uint8_t> x25519_ik_nonce;
    const auto x25519_ik_enc = CryptoUtils::encrypt_with_key(
        identity_key_pairs.x25519_private->to_bytes(), kek, x25519_ik_nonce, x25519_identity_associated_data);
    
    // Encrypt signed prekey
    std::vector<uint8_t> spk_nonce;
    const auto spk_enc = CryptoUtils::encrypt_with_key(
        spk.private_key->to_bytes(), kek, spk_nonce, spk_associated_data);

    // Encrypt one-time prekeys
    json opks_json_list = json::array();
    for (const auto&[private_key, public_key] : opks) {
        std::string opk_pub_base64 = CryptoUtils::base64_encode(public_key.to_bytes());
        std::vector<uint8_t> opk_nonce;
        auto opk_enc = CryptoUtils::encrypt_with_key(
            private_key.to_bytes(), kek, opk_nonce, opk_associated_data);

        opks_json_list.push_back({
            {"public", opk_pub_base64},
            {"private_enc", CryptoUtils::base64_encode(opk_enc)},
            {"private_nonce", CryptoUtils::base64_encode(opk_nonce)}
        });
    }

    user.ed25519_identity_key_private_enc = CryptoUtils::base64_encode(ed25519_ik_enc);
    user.ed25519_identity_key_private_nonce = CryptoUtils::base64_encode(ed25519_ik_nonce);
    user.ed25519_identity_key_public = CryptoUtils::base64_encode(identity_key_pairs.ed25519_public->to_bytes());
    user.x25519_identity_key_private_enc = CryptoUtils::base64_encode(x25519_ik_enc);
    user.x25519_identity_key_private_nonce = CryptoUtils::base64_encode(x25519_ik_nonce);
    user.x25519_identity_key_public = CryptoUtils::base64_encode(identity_key_pairs.x25519_public->to_bytes());
    user.signed_prekey_private_enc = CryptoUtils::base64_encode(spk_enc);
    user.signed_prekey_private_nonce = CryptoUtils::base64_encode(spk_nonce);
    user.signed_prekey_public = CryptoUtils::base64_encode(spk.public_key->to_bytes());
    user.signed_prekey_signature = CryptoUtils::base64_encode(spk.signature);
    user.opks_json = opks_json_list.dump(-1, ' ', false, json::error_handler_t::replace);
}

std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
VaultManager::decrypt_all_opks(const std::string& opks_json, const std::vector<uint8_t>& master_key) {
    json opks_json_list = json::parse(opks_json);
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> decrypted_opks;

    for (const auto& opk : opks_json_list) {
        auto private_nonce = CryptoUtils::base64_decode(opk.at("private_nonce").get<std::string>());
        auto private_enc = CryptoUtils::base64_decode(opk.at("private_enc").get<std::string>());
        auto public_bytes = CryptoUtils::base64_decode(opk.at("public").get<std::string>());

        auto priv_bytes = CryptoUtils::decrypt_with_key(
            private_nonce, private_enc, master_key, opk_associated_data);
        decrypted_opks.emplace_back(priv_bytes, public_bytes);
    }

    return decrypted_opks;
}
