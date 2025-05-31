#include "VaultManager.h"
#include "CryptoUtils.h"
#include "Base64Utils.h" // Your b64 helpers
#include "Ed25519Key.h" // Your Ed25519 key wrapper classes
#include "X25519Key.h" // Your X25519 key wrapper classes
#include <nlohmann/json.hpp> // For JSON parsing (https://github.com/nlohmann/json)
#include <stdexcept>

using json = nlohmann::json;

// Example implementations:

std::string VaultManager::b64_encode(const std::vector<uint8_t>& data) {
    return Base64Utils::encode(data);
}

std::vector<uint8_t> VaultManager::b64_decode(const std::string& data) {
    return Base64Utils::decode(data);
}

std::map<std::string, std::string> VaultManager::get_user_vault(const auto& user) {
    return {
        {"salt", user.salt},
        {"identity_key_public", user.identity_key_public},
        {"signed_prekey_public", user.signed_prekey_public},
        {"signed_prekey_signature", user.signed_prekey_signature},
        {"identity_key_private_enc", user.identity_key_private_enc},
        {"identity_key_private_nonce", user.identity_key_private_nonce},
        {"signed_prekey_private_enc", user.signed_prekey_private_enc},
        {"signed_prekey_private_nonce", user.signed_prekey_private_nonce},
        {"opks", user.opks_json.empty() ? "[]" : user.opks_json}
    };
}

std::optional<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
VaultManager::try_decrypt_private_keys(const std::map<std::string, std::string>& vault,
                                       const std::vector<uint8_t>& master_key) {
    auto ik_enc = b64_decode(vault.at("identity_key_private_enc"));
    auto ik_nonce = b64_decode(vault.at("identity_key_private_nonce"));
    auto spk_enc = b64_decode(vault.at("signed_prekey_private_enc"));
    auto spk_nonce = b64_decode(vault.at("signed_prekey_private_nonce"));

    auto identity_private_bytes = CryptoUtils::decrypt_with_key(ik_nonce, ik_enc, master_key, {'i','d','e','n','t','i','t','y','_','k','e','y'});
    auto spk_private_bytes = CryptoUtils::decrypt_with_key(spk_nonce, spk_enc, master_key, {'s','i','g','n','e','d','_','p','r','e','k','e','y'});

    return std::make_pair(identity_private_bytes, spk_private_bytes);
}

bool VaultManager::verify_decrypted_keys(const std::vector<uint8_t>& identity_private_bytes,
                                         const std::vector<uint8_t>& spk_private_bytes,
                                         const std::map<std::string, std::string>& vault) {
    Ed25519PrivateKey identity_private = Ed25519PrivateKey::from_private_bytes(identity_private_bytes);
    X25519PrivateKey spk_private = X25519PrivateKey::from_private_bytes(spk_private_bytes);

    auto identity_public = identity_private.public_key();
    auto spk_public = spk_private.public_key();

    auto identity_public_b64 = b64_encode(identity_public.public_bytes());
    auto spk_public_b64 = b64_encode(spk_public.public_bytes());

    return identity_public_b64 == vault.at("identity_key_public") &&
           spk_public_b64 == vault.at("signed_prekey_public");
}

std::map<std::string, std::string> VaultManager::generate_user_vault(
    const Ed25519PrivateKey& identity_private,
    const Ed25519PublicKey& identity_public,
    const X25519PrivateKey& spk_private,
    const X25519PublicKey& spk_public,
    const std::vector<uint8_t>& spk_signature,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& master_key,
    const std::vector<OPKPair>& opks) {

    auto [ik_nonce, ik_enc] = CryptoUtils::encrypt_with_key(identity_private.private_bytes(), master_key, {'i','d','e','n','t','i','t','y','_','k','e','y'});
    auto [spk_nonce, spk_enc] = CryptoUtils::encrypt_with_key(spk_private.private_bytes(), master_key, {'s','i','g','n','e','d','_','p','r','e','k','e','y'});

    json opks_json_list = json::array();
    for (const auto& opk : opks) {
        std::string opk_pub_b64 = b64_encode(opk.public_key.public_bytes());
        auto [opk_nonce, opk_enc] = CryptoUtils::encrypt_with_key(opk.private_key.private_bytes(), master_key, {'o','p','k'});

        opks_json_list.push_back({
            {"public", opk_pub_b64},
            {"private_enc", b64_encode(opk_enc)},
            {"private_nonce", b64_encode(opk_nonce)}
        });
    }

    return {
        {"salt", b64_encode(salt)},
        {"identity_key_public", b64_encode(identity_public.public_bytes())},
        {"signed_prekey_public", b64_encode(spk_public.public_bytes())},
        {"signed_prekey_signature", b64_encode(spk_signature)},
        {"identity_key_private_enc", b64_encode(ik_enc)},
        {"identity_key_private_nonce", b64_encode(ik_nonce)},
        {"signed_prekey_private_enc", b64_encode(spk_enc)},
        {"signed_prekey_private_nonce", b64_encode(spk_nonce)},
        {"opks", opks_json_list.dump()}
    };
}

std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>
VaultManager::decrypt_all_opks(const std::string& opks_json, const std::vector<uint8_t>& master_key) {
    json opks_json_list = json::parse(opks_json);
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> decrypted_opks;

    for (const auto& opk : opks_json_list) {
        auto private_nonce = b64_decode(opk.at("private_nonce").get<std::string>());
        auto private_enc = b64_decode(opk.at("private_enc").get<std::string>());
        auto public_bytes = b64_decode(opk.at("public").get<std::string>());

        auto priv_bytes = CryptoUtils::decrypt_with_key(private_nonce, private_enc, master_key, {'o','p','k'});
        decrypted_opks.emplace_back(priv_bytes, public_bytes);
    }

    return decrypted_opks;
}

std::vector<OPKPair> VaultManager::keypairs_from_opk_bytes(
    const std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& decrypted_opks) {

    std::vector<OPKPair> opk_keypairs;
    for (const auto& [priv_bytes, pub_bytes] : decrypted_opks) {
        OPKPair pair;
        pair.private_key = X25519PrivateKey::from_private_bytes(priv_bytes);
        pair.public_key = X25519PublicKey::from_public_bytes(pub_bytes);
        opk_keypairs.push_back(pair);
    }
    return opk_keypairs;
}
