//
// Created by Ruairi on 04/06/2025.
//
#include <iostream>
#include <Server.h>
#include <curl/curl.h>
#include <string>
#include <vector>
#include <sstream>
#include <nlohmann/json.hpp>
#include "models/KEKModel.h"
#include "models/File.h"
#include "utils/Config.h"
#include "utils/cryptography/CryptoUtils.h"
#include "utils/cryptography/keys/Ed25519Key.h"

Server& Server::instance() {
    static Server instance;
    return instance;
}
Server::Server() {
    //Set up global resources and data structures required by cURL library for the entire process.
    //Must be called once before any cURL operations.
    curl_global_init(CURL_GLOBAL_DEFAULT);
    server_url_ = Config::get_instance().server_url();
}
Server::~Server() {
    curl_global_cleanup();
}

void Server::init_curl() {
    if (!curl_handle) {
        // Initialize the CURL handle if it hasn't been done yet
        // Handle is used to set options and perform requests
        curl_handle = curl_easy_init();
        if (!curl_handle) {
            throw std::runtime_error("Failed to initialize CURL handle");
        }
    }
}

void Server::cleanup_curl() {
    if (curl_handle) {
        curl_easy_cleanup(curl_handle);
        curl_handle = nullptr;
    }
}

// Helper function to handle HTTP requests
HttpResponse Server::perform_request(const std::string &url, const std::vector<std::string>& headers, const std::string* payload, bool is_post, bool is_put) {
    init_curl();
    HttpResponse response_obj;
    std::string response;
    curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
    if (is_post) {
        curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
        if (payload) {
            curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, payload->c_str());
        }
    } else if (is_put) {
        curl_easy_setopt(curl_handle, CURLOPT_CUSTOMREQUEST, "PUT");
        if (payload) {
            curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, payload->c_str());
        }
    } else {
        curl_easy_setopt(curl_handle, CURLOPT_HTTPGET, 1L);
    }
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, +[](const char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        auto* str = static_cast<std::string*>(userdata);
        str->append(ptr, size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

    struct curl_slist* curl_headers = nullptr;
    if (is_post || is_put) {
        curl_headers = curl_slist_append(curl_headers, "Content-Type: application/json");
    }
    for (const auto& header : headers) {
        curl_headers = curl_slist_append(curl_headers, header.c_str());
    }
    curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, curl_headers);

    const CURLcode res = curl_easy_perform(curl_handle);
    long http_code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
    }

    cleanup_curl();

    response_obj.status_code = static_cast<int>(http_code);
    response_obj.body = response;
    response_obj.success = (res == CURLE_OK && http_code>= 200 && http_code < 300);
    response_obj.curl_code = res;
    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    return response_obj;
}

HttpResponse Server::get_request(const std::string &url, const std::vector<std::string>& headers) {
    return perform_request(url, headers, nullptr, false, false);
}

HttpResponse Server::post_request(const std::string &url, const nlohmann::json &payload, const std::vector<std::string>& headers) {
    std::string payload_str = payload.dump();
    return perform_request(url, headers, &payload_str, true, false);
}

HttpResponse Server::put_request(const std::string &url, const nlohmann::json &payload, const std::vector<std::string>& headers) {
    std::string payload_str = payload.dump();
    return perform_request(url, headers, &payload_str, false, true);
}

nlohmann::json Server::parse_and_check_response(const HttpResponse& resp, const std::string& context) {
    if (!resp.success) {
        nlohmann::json json_body = nlohmann::json::parse(resp.body, nullptr, false);
        if (json_body.contains("error")) {
            throw std::runtime_error("Error in " + context + ": " + json_body["error"].get<std::string>());
        }
        throw std::runtime_error("Failed in " + context + ": " + resp.body);
    }
    if (resp.body.empty()) {
        throw std::runtime_error("Received empty response in " + context);
    }
    try {
        return nlohmann::json::parse(resp.body);
    } catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("Failed to parse JSON in " + context + ": " + std::string(e.what()));
    }
}

bool Server::get_index() {
    HttpResponse resp = get_request(server_url_ + "/");
    return resp.success;
}

std::string Server::get_server_nonce(const std::string &user_uuid) {
    HttpResponse resp = get_request(server_url_ + "/api/nonce?user_uuid=" + user_uuid);
    if (!resp.success) {
        throw std::runtime_error("Failed to get nonce: " + resp.body);
    }
    if (resp.body.empty()) {
        throw std::runtime_error("Received empty response for get nonce");
    }
    try {
        nlohmann::json json_response = nlohmann::json::parse(resp.body);
        if (json_response.contains("nonce") && json_response.contains("timestamp") &&
            json_response["nonce"].is_string() && json_response["timestamp"].is_string()) {
            std::string nonce = json_response["nonce"];
            return nonce;
            } else {
                throw std::runtime_error("Nonce or timestamp not found in response");
            }
    } catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("Failed to parse JSON response: " + std::string(e.what()));
    }
}

KEKModel Server::get_kek_info(const std::string& user_uuid) {
    HttpResponse resp = get_request(server_url_ + "/api/kek/" + user_uuid);
    if (!resp.success) {
        throw std::runtime_error("Failed to get kek: " + resp.body);
    }
    if (resp.body.empty()) {
        throw std::runtime_error("Received empty response for get kek");
    }
    try {
        nlohmann::json json_response = nlohmann::json::parse(resp.body);
        if (json_response.contains("uuid") && json_response.contains("user_uuid") &&
            json_response.contains("enc_kek_cyphertext") && json_response.contains("nonce") && json_response.contains("updated_at")) {
            KEKModel kek_model;
            kek_model.enc_kek_cyphertext = json_response["enc_kek_cyphertext"].get<std::string>();
            kek_model.nonce = json_response["nonce"].get<std::string>();
            kek_model.updated_at = json_response["updated_at"].get<std::string>();
            return kek_model;
            } else {
                throw std::runtime_error("One or many KEK attributes not found in response");
            }
    } catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("Failed to parse JSON response: " + std::string(e.what()));
    }
}

nlohmann::json Server::update_kek_info(const std::string &encrypted_kek,
                                       const std::string &kek_nonce, const std::string &updated_at,
                                       const std::string &user_uuid,
                                       const Ed25519PrivateKey &ik_priv) {
    nlohmann::json payload = {
        {"enc_kek_cyphertext", encrypted_kek},
        {"nonce", kek_nonce},
        {"updated_at", updated_at},
    };
    std::vector<std::string> headers = set_headers(ik_priv, user_uuid, payload);

    HttpResponse resp = put_request(server_url_ + "/api/kek?user_uuid=" + user_uuid, payload, headers);
    return parse_and_check_response(resp, "update_kek_info");
}

// src/Server.cpp

UserModel Server::get_user_by_name(const std::string& username) {
    // Make GET request to server endpoint
    HttpResponse resp = get_request(server_url_ + "/api/users/" + username);
    if (!resp.success) {
        throw std::runtime_error("Failed to get user by username: " + resp.body);
    }
    if (resp.body.empty()) {
        throw std::runtime_error("Received empty response for get user by username");
    }

    // Parse response
    nlohmann::json response_json = nlohmann::json::parse(resp.body); // Use resp.body instead of resp
    if (response_json.contains("error")) {
        std::cout << response_json.dump() << std::endl;
        return UserModel();
    }

    // Convert JSON to UserModel
    UserModel user;
    user.uuid = response_json["uuid"];
    user.username = response_json["username"];
    user.email = response_json["email"];
    user.salt = response_json["salt"];
    user.ed25519_identity_key_public = response_json["ed25519_identity_key_public"];
    user.x25519_identity_key_public = response_json["x25519_identity_key_public"];
    user.signed_prekey_public = response_json["signed_prekey_public"];
    user.signed_prekey_signature = response_json["signed_prekey_signature"];
    user.opks_json = response_json["opks"].dump();
    std::cout << "Fetched user: " << user.username << " with UUID: " << user.uuid << std::endl;
    return user;
}

std::pair<nlohmann::json, std::string> Server::upload_file(File file, const std::string &owner_uuid, const Ed25519PrivateKey &private_key)
{
    nlohmann::json payload = {
        {"file_name", file.file_name},
        {"enc_file_ciphertext", file.enc_file_ciphertext},
        {"mime_type", file.mime_type},
        {"file_nonce", file.file_nonce},
        {"enc_file_k", file.enc_file_k},
        {"k_file_nonce", file.k_file_nonce}
    };

    std::vector<std::string> headers = set_headers(private_key, owner_uuid, payload);
    const std::string url = server_url() + "/api/files/upload";

    HttpResponse res = post_request(url, payload.dump(), headers);

    if (!res.success) {
        return {{}, "Request failed: " + std::string(curl_easy_strerror(res.curl_code))};
    }

    try {
        auto json_response = nlohmann::json::parse(res.body);
        if (json_response.contains("error")) {
            return {{}, json_response["error"].get<std::string>()};
        }
        return {json_response, ""};
    } catch (const std::exception& e) {
        return {{}, std::string("JSON parsing error: ") + e.what()};
    }
}

// libcurl callback to store response data
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t total_size = size * nmemb;
    std::string* response = static_cast<std::string*>(userp);
    response->append(static_cast<char*>(contents), total_size);
    return total_size;
}

HttpResponse post_request(const std::string& url, const std::string& payload, const std::vector<std::string>& headers_vec) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        return {0, "", false, CURLE_FAILED_INIT};
    }

    std::string response_str;
    struct curl_slist* curl_headers = nullptr;
    curl_headers = curl_slist_append(curl_headers, "Content-Type: application/json");
    for (const auto& header : headers_vec) {
        curl_headers = curl_slist_append(curl_headers, header.c_str());
    }

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, curl_headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_str);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    CURLcode res = curl_easy_perform(curl);
    long status_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);

    curl_slist_free_all(curl_headers);
    curl_easy_cleanup(curl);

    return {
        status_code,
        response_str,
        res == CURLE_OK,
        res
    };
}


//TODO
// std::pair<nlohmann::json, std::string> Server::get_user_by_name(const std::string &username) {
// }
//
// std::pair<nlohmann::json, std::string> Server::upload_file(const std::string &file_ciphertext,
//     const std::string &file_name, const std::string &owner_uuid, const std::string &mime_type,
//     const std::string &file_nonce, const std::string &enc_file_k, const std::string &k_file_nonce,
//     const Ed25519PrivateKey &private_key) {
// }
//
// std::pair<nlohmann::json, std::string> Server::get_user_keys(const std::string &sender_user_uuid,
//     const std::string &recipient_uuid, const Ed25519PrivateKey &private_key) {
// }
//
// std::pair<nlohmann::json, std::string> Server::send_pac(const PAC &pac, const std::string &sender_uuid,
//     const Ed25519PrivateKey &private_key) {
// }
//
// std::pair<nlohmann::json, std::string> Server::download_file(const std::string &file_uuid,
//     const Ed25519PrivateKey &private_key, const std::string &user_uuid) {
// }
//
// std::pair<nlohmann::json, std::string> Server::get_owned_files(const std::string &user_id,
//     const Ed25519PrivateKey &private_key) {
// }
//
// nlohmann::json Server::get_user_pacs(const std::string &user_id, const Ed25519PrivateKey &private_key) {
// }
//
// std::pair<nlohmann::json, std::string> Server::get_file_info(const std::string &file_uuid, const std::string &user_uuid,
//     const Ed25519PrivateKey &private_key) {
//
// }


std::string Server::get_new_user_uuid() {
    HttpResponse resp = get_request(server_url_ + "/api/generate-uuid");
    nlohmann::json json_response = parse_and_check_response(resp, "get_new_user_uuid");
    if (json_response.contains("uuid")) {
        return json_response["uuid"].get<std::string>();
    }
    throw std::runtime_error("UUID not found in response");
}

void Server::create_user(const nlohmann::json &user_data) {
    // std::cout << "Json to send: " << user_data.dump(4) << std::endl;
    std::string payload = user_data.dump();
    const HttpResponse resp = post_request(server_url_ + "/api/register", nlohmann::json::parse(payload));
    if (!resp.success) {
        const nlohmann::json json_body = nlohmann::json::parse(resp.body, nullptr, false);
        if (json_body.contains("error")) {
            const std::string error_message = json_body["error"].get<std::string>();
            // std::cout << "Error creating user: " << json_body["error"] << std::endl;
            throw std::runtime_error("Error creating user: " + error_message);
        }
        throw std::runtime_error("Failed to create user: " + resp.body);
    }
    if (resp.body.empty()) {
        throw std::runtime_error("Received empty response when creating user");
    }
}

std::string Server::sign_payload(
    const std::vector<uint8_t>& payload,
    const std::string& nonce,
    const Ed25519PrivateKey& private_key
) {
    // 1. Combine payload and nonce into a single message
    std::vector<uint8_t> message(payload);
    message.insert(message.end(), nonce.begin(), nonce.end());

    // 2. Create a signing context
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key.to_evp_pkey(), nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create signing context");
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_sign_init failed");
    }

    // 3. Get the length of the signature
    size_t siglen = 0;
    if (EVP_PKEY_sign(ctx, nullptr, &siglen, message.data(), message.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_sign (size estimation) failed");
    }

    // 4. Generate the signature
    std::vector<uint8_t> signature(siglen);
    if (EVP_PKEY_sign(ctx, signature.data(), &siglen, message.data(), message.size()) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("EVP_PKEY_sign failed");
    }
    signature.resize(siglen);
    EVP_PKEY_CTX_free(ctx);

    // 5. Encode signature as base64 string
    return CryptoUtils::base64_encode(signature);
}

std::vector<std::string> Server::set_headers(
    const Ed25519PrivateKey &private_key,
    const std::string &user_uuid,
    const nlohmann::json &payload
) {
    std::string payload_str = payload.dump();
    std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());

    std::string nonce = get_server_nonce(user_uuid);
    if (nonce.empty()) {
        throw std::runtime_error("Failed to retrieve nonce from server.");
    }

    std::string signature = sign_payload(payload_bytes, nonce, private_key);

    std::vector<std::string> headers = {
        "X-User-UUID: " + user_uuid,
        "X-Nonce: " + nonce,
        "X-Signature: " + signature
    };
    return headers;
}

