#include "Auth.h"

#include <iostream>
#include <chrono>
#include <unordered_map>
#include <mutex>

#include "database/db_instance.h"
#include <random>
#include <optional>
#include <qtextstream.h>
#include <string>
#include <vector>
#include <curl/curl.h>
#include <nlohmann/json.hpp>
#include "../include/utils/cryptography/CryptoUtils.h"
#include "../include/utils/cryptography/VaultManager.h"
#include "../include/utils/cryptography/KeyGeneration.h"
#include "../include/utils/cryptography/keys/Ed25519Key.h"
#include "../include/utils/cryptography/keys/X25519Key.h"
#include "utils/Config.h"

// Rate limiting for failed login attempts
namespace {
    struct LoginAttempt {
        int attempts;
        std::chrono::system_clock::time_point last_attempt;
    };
    std::unordered_map<std::string, LoginAttempt> login_attempts;
    std::mutex login_mutex;
    const int MAX_ATTEMPTS = 5;
    const int LOCKOUT_DURATION_SECONDS = 300; // 5 minutes

    const std::string DEFAULT_SERVER_URL = "https://gobblergang.gobbler.info";
    
    std::string get_server_url() {
        std::string url = Config::get_instance().server_url();
        return url.empty() ? DEFAULT_SERVER_URL : url;
    }
    
    const std::string server_url = get_server_url();

    // Master key management
    class MasterKeyManager {
    private:
        std::vector<uint8_t> master_key;
        mutable std::mutex key_mutex;  // Made mutable to allow locking in const member functions

    public:
        static MasterKeyManager& get_instance() {
            static MasterKeyManager instance;
            return instance;
        }

        void set_key(const std::vector<uint8_t>& key) {
            std::lock_guard<std::mutex> lock(key_mutex);
            master_key = key;
        }

        void clear() {
            std::lock_guard<std::mutex> lock(key_mutex);
            master_key.clear();
        }

        std::vector<uint8_t> get_key() const {
            std::lock_guard<std::mutex> lock(key_mutex);
            return master_key;
        }
    };
}

// Helper function to format AAD for KEK decryption
std::vector<uint8_t> format_aad(const std::string& user_uuid, const std::string& timestamp) {
    nlohmann::json aad_json = {
        {"user_uuid", user_uuid},
        {"timestamp", timestamp}
    };
    std::string aad_str = aad_json.dump();
    return std::vector<uint8_t>(aad_str.begin(), aad_str.end());
}

// Helper function to try decrypting KEK
std::pair<std::vector<uint8_t>, std::string> try_decrypt_kek(
    const nlohmann::json& kek_info,
    const std::string& user_uuid,
    const std::vector<uint8_t>& master_key
) {
    try {
        std::vector<uint8_t> enc_kek = CryptoUtils::base64_decode(kek_info["enc_kek_cyphertext"].get<std::string>());
        std::vector<uint8_t> kek_nonce = CryptoUtils::base64_decode(kek_info["nonce"].get<std::string>());
        std::string updated_at = kek_info["updated_at"].get<std::string>();
        std::vector<uint8_t> aad = format_aad(user_uuid, updated_at);

        auto kek = CryptoUtils::decrypt_with_key(kek_nonce, enc_kek, master_key, aad);
        return {kek, ""};
    } catch (...) {
        return {{}, "Failed to decrypt KEK with provided password."};
    }
}

// Helper to get current ISO8601 time
std::string current_iso8601_time() {
    std::time_t now = std::time(nullptr);
    std::tm tm = *std::gmtime(&now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

bool send_registration(
    const std::string& uuid,
    const std::string& username,
    const std::string& email,
    const std::vector<uint8_t>& salt,
    const std::string& identity_key_public,
    const std::string& signed_prekey_public,
    const std::string& signed_prekey_signature,
    const nlohmann::json& opks,
    const std::string& enc_kek_ciphertext,
    const std::string& kek_nonce
) {
    nlohmann::json payload = {
        {"user", {
            {"uuid", uuid},
            {"username", username},
            {"email", email},
            {"salt", CryptoUtils::base64_encode(salt)}
        }},
        {"keys", {
            {"identity_key_public", identity_key_public},
            {"signed_prekey_public", signed_prekey_public},
            {"signed_prekey_signature", signed_prekey_signature},
            {"opks", opks}
        }},
        {"kek", {
            {"enc_kek_cyphertext", enc_kek_ciphertext},
            {"nonce", kek_nonce},
            {"updated_at", current_iso8601_time()}
        }}
    };

    std::string json_str = payload.dump();
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string url = server_url + "/api/register";
    curl_easy_setopt(curl, CURLOPT_URL, server_url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    CURLcode res = curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return res == CURLE_OK;
}
static std::vector<uint8_t> generateSalt(size_t len = 16) {
    std::vector<uint8_t> salt(len);
    std::random_device rd;
    std::generate(salt.begin(), salt.end(), [&rd]() { return rd() % 256; });
    return salt;
}

// --- SIGNUP ---
Auth::SignUpResult Auth::signup(const std::string& username, const std::string& email, const std::string& password) {
    // if (usernameExists(username)) {
    //     return { false, "Username already exists" };
    // }
    // if (emailExists(email)) {
    //     return { false, "Email already registered" };
    // }
    // if (password.empty()) {
    //     return { false, "Password is required" };
    // }
    //
    // std::vector<uint8_t> salt = generateSalt();
    // std::vector<uint8_t> masterKey = KeyGeneration::derive_master_key(password, salt);
    // std::vector<uint8_t> kek = KeyGeneration::generate_symmetric_key();
    //
    // // Generate identity keypairs
    // auto identityKeypairs = KeyGeneration::generate_identity_keypair();
    // Ed25519PrivateKey* ed25519_priv = identityKeypairs.first.first;
    // Ed25519PublicKey* ed25519_pub = identityKeypairs.first.second;
    // X25519PrivateKey* x25519_priv = identityKeypairs.second.first;
    // X25519PublicKey* x25519_pub = identityKeypairs.second.second;
    //
    // // Generate signed prekey
    // auto spk_tuple = KeyGeneration::generate_signed_prekey(ed25519_priv->to_evp_pkey());
    // X25519PrivateKey* spk_priv = std::get<0>(spk_tuple);
    // X25519PublicKey* spk_pub = std::get<1>(spk_tuple);
    // std::vector<uint8_t> spk_sig = std::get<2>(spk_tuple);
    //
    // // Generate OPKs (one-time prekeys)
    // std::vector<OPKPair> opks; // You should implement CryptoUtils::generate_opks() if needed
    //
    // // Generate vault (returns a map of field name -> base64 string)
    // auto vault_map = VaultManager::generate_user_vault(
    //     *ed25519_priv, *ed25519_pub,
    //     *x25519_priv, *x25519_pub,
    //     *spk_priv, *spk_pub, spk_sig,
    //     salt, masterKey, opks
    // );
    //
    // auto uuidOpt = requestUUIDFromServer();
    // if (!uuidOpt.has_value()) {
    //     // Clean up heap allocations
    //     delete ed25519_priv;
    //     delete ed25519_pub;
    //     delete x25519_priv;
    //     delete x25519_pub;
    //     delete spk_priv;
    //     delete spk_pub;
    //     return { false, "Error communicating with the server" };
    // }
    // std::string uuid = uuidOpt.value();
    //
    // // Encrypt KEK with masterKey and uuid as associated data
    // std::string kek_nonce_b64, kek_ciphertext_b64;
    // try {
    //     std::vector<uint8_t> nonce;
    //     auto kek_enc = CryptoUtils::encrypt_with_key(kek, masterKey, nonce, std::vector<uint8_t>(uuid.begin(), uuid.end()));
    //     kek_nonce_b64 = CryptoUtils::base64_encode(nonce);
    //     kek_ciphertext_b64 = CryptoUtils::base64_encode(kek_enc);
    // } catch (...) {
    //     // Clean up heap allocations
    //     delete ed25519_priv;
    //     delete ed25519_pub;
    //     delete x25519_priv;
    //     delete x25519_pub;
    //     delete spk_priv;
    //     delete spk_pub;
    //     return { false, "Failed to encrypt KEK" };
    // }
    //
    // // Prepare User struct
    // UserModelORM user;
    // user.uuid = uuid;
    // user.username = username;
    // user.email = email;
    // user.salt = vault_map["salt"];
    // user.ed25519_identity_key_public = vault_map["ed25519_identity_key_public"];
    // user.ed25519_identity_key_private_enc = vault_map["ed25519_identity_key_private_enc"];
    // user.ed25519_identity_key_private_nonce = vault_map["ed25519_identity_key_private_nonce"];
    // user.x25519_identity_key_public = vault_map["x25519_identity_key_public"];
    // user.x25519_identity_key_private_enc = vault_map["x25519_identity_key_private_enc"];
    // user.x25519_identity_key_private_nonce = vault_map["x25519_identity_key_private_nonce"];
    // user.signed_prekey_public = vault_map["signed_prekey_public"];
    // user.signed_prekey_signature = vault_map["signed_prekey_signature"];
    // user.signed_prekey_private_enc = vault_map["signed_prekey_private_enc"];
    // user.signed_prekey_private_nonce = vault_map["signed_prekey_private_nonce"];
    // user.opks_json = vault_map["opks"];
    //
    // // Prepare UserKEK struct (assumes you have a UserKEK struct/table)
    // KEKModel userKek;
    // userKek.enc_kek_cyphertext = kek_ciphertext_b64;
    // userKek.nonce = kek_nonce_b64;
    //
    // // Insert user and KEK into DB
    // try {
    //     db().insert(user);
    //     db().insert(userKek);
    // } catch (...) {
    //     // Clean up heap allocations
    //     delete ed25519_priv;
    //     delete ed25519_pub;
    //     delete x25519_priv;
    //     delete x25519_pub;
    //     delete spk_priv;
    //     delete spk_pub;
    //     return { false, "Failed to create user or save KEK" };
    // }
    //
    // // Clean up heap allocations
    // delete ed25519_priv;
    // delete ed25519_pub;
    // delete x25519_priv;
    // delete x25519_pub;
    // delete spk_priv;
    // delete spk_pub;
    //
    return { true, "Registration successful! Please login." };
}

// --- LOGIN ---
Auth::LoginResult Auth::login(const std::string& username, const std::string& password) {
    // Check rate limiting
    {
        std::lock_guard<std::mutex> lock(login_mutex);
        auto now = std::chrono::system_clock::now();
        auto& attempt = login_attempts[username];
        
        if (attempt.attempts >= MAX_ATTEMPTS) {
            auto time_since_last = std::chrono::duration_cast<std::chrono::seconds>(
                now - attempt.last_attempt).count();
            if (time_since_last < LOCKOUT_DURATION_SECONDS) {
                return { false, "Too many failed attempts. Please try again later.", "" };
            }
            attempt.attempts = 0;
        }
        attempt.last_attempt = now;
    }

    // Check if user exists in local database
    auto users = db().get_all<UserModelORM>(where(c(&UserModelORM::username) == username));
    if (users.empty()) {
        // Check if user exists on server
        CURL* curl = curl_easy_init();
        if (!curl) {
            return { false, "Unable to connect to server", "" };
        }

        std::string response;
        std::string encoded_username = curl_easy_escape(curl, username.c_str(), username.length());
        std::string url = server_url + "/api/users/" + encoded_username;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
            auto* str = static_cast<std::string*>(userdata);
            str->append(ptr, size * nmemb);
            return size * nmemb;
        });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res == CURLE_OK) {
            try {
                auto json = nlohmann::json::parse(response);
                if (!json.contains("error")) {
                    return { false, "Please import your key bundle to continue", "" };
                }
            } catch (...) {
                // JSON parsing failed, continue with generic message
            }
        }
        return { false, "Invalid username or password", "" };
    }

    if (password.empty()) {
        return { false, "Password is required", "" };
    }

    const auto& user = users[0];
    std::vector<uint8_t> salt = CryptoUtils::base64_decode(user.salt);
    std::vector<uint8_t> master_key = KeyGeneration::derive_master_key(password, salt);
    MasterKeyManager::get_instance().set_key(master_key);

    // Get KEK info from server
    auto kek_info_opt = getKekInfo(user.uuid);
    if (!kek_info_opt) {
        MasterKeyManager::get_instance().clear();
        return { false, "Unable to connect to server", "" };
    }

    try {
        auto kek_info = nlohmann::json::parse(kek_info_opt.value());
        std::string server_updated_at = kek_info["updated_at"].get<std::string>();

        // Check KEK freshness
        if (!verifyKekFreshness(user.uuid, server_updated_at)) {
            MasterKeyManager::get_instance().clear();
            return { false, "Please use your new password", "" };
        }

        // Try to decrypt KEK
        auto [kek, kek_error] = try_decrypt_kek(kek_info, user.uuid, master_key);
        if (!kek_error.empty()) {
            // Increment failed attempts
            std::lock_guard<std::mutex> lock(login_mutex);
            login_attempts[username].attempts++;
            MasterKeyManager::get_instance().clear();
            return { false, "Invalid username or password", "" };
        }

        // Update local KEK if server's updated_at is newer
        auto local_kek = db().get_all<KEKModel>(where(c(&KEKModel::user_id) == user.id));
        if (!local_kek.empty() && local_kek[0].updated_at != server_updated_at) {
            local_kek[0].enc_kek_cyphertext = kek_info["enc_kek_cyphertext"].get<std::string>();
            local_kek[0].nonce = kek_info["nonce"].get<std::string>();
            local_kek[0].updated_at = server_updated_at;
            db().update(local_kek[0]);
        }

        // Reset failed attempts on successful login
        std::lock_guard<std::mutex> lock(login_mutex);
        login_attempts.erase(username);

        return { true, "Login successful!", user.uuid };
    } catch (...) {
        MasterKeyManager::get_instance().clear();
        return { false, "Unable to process server response", "" };
    }
}

std::optional<std::string> Auth::getKekInfo(const std::string& user_uuid) {
    CURL* curl = curl_easy_init();
    if (!curl) return std::nullopt;

    std::string response;
    std::string url = server_url + "/api/users/" + user_uuid + "/kek";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
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
        auto json = nlohmann::json::parse(response);
        if (json.contains("error")) {
            return std::nullopt;
        }
        return response;
    } catch (...) {
        return std::nullopt;
    }
}

bool Auth::verifyKekFreshness(const std::string& user_uuid, const std::string& server_updated_at) {
    auto users = db().get_all<UserModelORM>(where(c(&UserModelORM::uuid) == user_uuid));
    if (users.empty()) return false;

    auto local_kek = db().get_all<KEKModel>(where(c(&KEKModel::user_id) == users[0].id));
    if (local_kek.empty()) return false;

    return local_kek[0].updated_at == server_updated_at;
}

// --- HELPERS ---
bool Auth::usernameExists(const std::string& username) {
    auto users = db().get_all<UserModelORM>(where(c(&UserModelORM::username) == username));
    return !users.empty();
}

bool Auth::emailExists(const std::string& email) {
    auto users = db().get_all<UserModelORM>(where(c(&UserModelORM::email) == email));
    return !users.empty();
}

std::optional<std::string> Auth::requestUUIDFromServer() {
    CURL* curl = curl_easy_init();
    if (!curl) return std::nullopt;

    std::string response;
    std::string url = server_url + "/api/generate-uuid";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
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
