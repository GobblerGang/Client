#include "Auth.h"

#include <iostream>

#include "database/db_instance.h"
#include <random>
#include <optional>
#include <qtextstream.h>
#include <string>
#include <vector>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "utils/CryptoUtils.h"
#include "utils/VaultManager.h"
#include "utils/Ed25519Key.h"
#include "utils/X25519Key.h"

// Helper: Generate random salt
static std::vector<uint8_t> generateSalt(size_t len = 16) {
    std::vector<uint8_t> salt(len);
    std::random_device rd;
    std::generate(salt.begin(), salt.end(), [&rd]() { return rd() % 256; });
    return salt;
}

// Helper: Generate a dummy session token (for demo)
static std::string generateSessionToken() {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
    std::string token;
    std::random_device rd;
    for (int i = 0; i < 32; ++i)
        token += alphanum[rd() % (sizeof(alphanum) - 1)];
    return token;
}

// --- SIGNUP ---
Auth::SignUpResult Auth::signup(const std::string& username, const std::string& email, const std::string& password) {
    if (usernameExists(username)) {
        return { false, "Username already exists" };
    }
    if (emailExists(email)) {
        return { false, "Email already registered" };
    }
    if (password.empty()) {
        return { false, "Password is required" };
    }

    std::vector<uint8_t> salt = generateSalt();
    std::vector<uint8_t> masterKey = CryptoUtils::derive_master_key(password, salt);
    std::vector<uint8_t> kek = CryptoUtils::generate_kek();

    // Generate identity keypairs
    auto identityKeypairs = CryptoUtils::generate_identity_keypair();
    Ed25519PrivateKey* ed25519_priv = identityKeypairs.first.first;
    Ed25519PublicKey* ed25519_pub = identityKeypairs.first.second;
    X25519PrivateKey* x25519_priv = identityKeypairs.second.first;
    X25519PublicKey* x25519_pub = identityKeypairs.second.second;

    // Generate signed prekey
    auto spk_tuple = CryptoUtils::generate_signed_prekey(ed25519_priv->to_evp_pkey());
    X25519PrivateKey* spk_priv = std::get<0>(spk_tuple);
    X25519PublicKey* spk_pub = std::get<1>(spk_tuple);
    std::vector<uint8_t> spk_sig = std::get<2>(spk_tuple);
    std::cout << "priv" << spk_priv << std::endl;
    std::cout << "pub" << spk_pub << std::endl;
    std::cout << "signature" << spk_sig.size() << std::endl;

    // Generate OPKs (one-time prekeys)
    std::vector<OPKPair> opks; // You should implement CryptoUtils::generate_opks() if needed

    // Generate vault (returns a map of field name -> base64 string)
    auto vault_map = VaultManager::generate_user_vault(
        *ed25519_priv, *ed25519_pub,
        *x25519_priv, *x25519_pub,
        *spk_priv, *spk_pub, spk_sig,
        salt, masterKey, opks
    );

    auto uuidOpt = requestUUIDFromServer();
    if (!uuidOpt.has_value()) {
        return { false, "Error communicating with the server" };
    }

    // Encrypt KEK with masterKey and uuid as associated data
    std::string encryptedKEK;
    try {
        auto [nonce, kek_enc] = CryptoUtils::encrypt_with_key(kek, masterKey, std::vector<uint8_t>(uuidOpt->begin(), uuidOpt->end()));
        nlohmann::json kek_json = {
            {"nonce", VaultManager::base64_encode(nonce)},
            {"ciphertext", VaultManager::base64_encode(kek_enc)}
        };
        encryptedKEK = kek_json.dump();
    } catch (...) {
        return { false, "Failed to encrypt KEK" };
    }

    // Prepare User struct
    User user;
    user.uuid = uuidOpt.value();
    user.username = username;
    user.email = email;
    user.salt = vault_map["salt"];
    user.ed25519_identity_key_public = vault_map["ed25519_identity_key_public"];
    user.ed25519_identity_key_private_enc = vault_map["ed25519_identity_key_private_enc"];
    user.ed25519_identity_key_private_nonce = vault_map["ed25519_identity_key_private_nonce"];
    user.x25519_identity_key_public = vault_map["x25519_identity_key_public"];
    user.x25519_identity_key_private_enc = vault_map["x25519_identity_key_private_enc"];
    user.x25519_identity_key_private_nonce = vault_map["x25519_identity_key_private_nonce"];
    user.signed_prekey_public = vault_map["signed_prekey_public"];
    user.signed_prekey_signature = vault_map["signed_prekey_signature"];
    user.signed_prekey_private_enc = vault_map["signed_prekey_private_enc"];
    user.signed_prekey_private_nonce = vault_map["signed_prekey_private_nonce"];
    user.opks_json = vault_map["opks"];

    // Store encrypted KEK in a separate table or as needed; here, just for demo, we store in opks_json if needed
    // In a real system, you would have a KEK table or similar
    // For demo, you may want to store it in a separate struct or table

    // Insert user into DB
    try {
        db().insert(user);
    } catch (...) {
        // Clean up heap allocations
        delete ed25519_priv;
        delete ed25519_pub;
        delete x25519_priv;
        delete x25519_pub;
        delete spk_priv;
        delete spk_pub;
        return { false, "Failed to create user" };
    }

    // Clean up heap allocations
    delete ed25519_priv;
    delete ed25519_pub;
    delete x25519_priv;
    delete x25519_pub;
    delete spk_priv;
    delete spk_pub;

    return { true, "Registration successful! Please login." };
}

// // --- LOGIN ---
// Auth::LoginResult Auth::login(const std::string& usernameOrEmail, const std::string& password) {
//     // Find user by username or email
//     auto users = db().get_all<User>(
//         where(c(&User::username) == usernameOrEmail || c(&User::email) == usernameOrEmail)
//     );
//     if (users.empty()) {
//         return { false, "User not found", "" };
//     }
//     const User& user = users.front();
//
//     // Decode salt from base64
//     std::vector<uint8_t> salt;
//     try {
//         salt = VaultManager::base64_decode(user.salt);
//     } catch (...) {
//         return { false, "Corrupted salt", "" };
//     }
//     std::vector<uint8_t> masterKey = CryptoUtils::derive_master_key(password, salt);
//
//     // In a real system, fetch KEK for this user from KEK table and decrypt it here.
//     // For demo, we assume KEK is not needed for login, only masterKey is checked by decrypting a private key.
//
//     // Try to decrypt Ed25519 private key to verify password
//     try {
//         auto priv_enc = VaultManager::base64_decode(user.ed25519_identity_key_private_enc);
//         auto priv_nonce = VaultManager::base64_decode(user.ed25519_identity_key_private_nonce);
//         auto priv_bytes = CryptoUtils::decrypt_with_key(
//             priv_nonce, priv_enc, masterKey, VaultManager::ed25519_identity_associated_data
//         );
//         // If decryption succeeds, password is correct
//     } catch (...) {
//         return { false, "Invalid password", "" };
//     }
//
//     // Generate session token (for demo)
//     std::string sessionToken = generateSessionToken();
//     // Optionally: store sessionToken in DB/session manager
//
//     return { true, "Login successful", sessionToken };
// }

// --- HELPERS ---
bool Auth::usernameExists(const std::string& username) {
    auto users = db().get_all<User>(where(c(&User::username) == username));
    return !users.empty();
}

bool Auth::emailExists(const std::string& email) {
    auto users = db().get_all<User>(where(c(&User::email) == email));
    return !users.empty();
}



std::optional<std::string> Auth::requestUUIDFromServer() {
    CURL* curl = curl_easy_init();
    if (!curl) return std::nullopt;

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL, "https://gobblergang.gobbler.info/api/generate-uuid");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        auto* str = static_cast<std::string*>(userdata);
        str->append(ptr, size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) return std::nullopt;

    try {
        // If the response is JSON: { "uuid": "..." }
        auto json = nlohmann::json::parse(response);
        if (json.contains("uuid")) {
            return json["uuid"].get<std::string>();
        }
        // If the response is just the UUID as plain text
        return response;
    } catch (...) {
        // If not JSON, just return the raw response trimmed
        response.erase(response.find_last_not_of(" \n\r\t") + 1);
        if (!response.empty()) return response;
        return std::nullopt;
    }
}
