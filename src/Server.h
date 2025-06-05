#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include "RequestHeaders.h"
#include "models/KEKModel.h"
#include "models/UserModel.h"
// Forward declaration
class Ed25519PrivateKey;
class PAC;
/**
 * @brief Struct to hold HTTP response data.
 */
struct HttpResponse {
    long status_code;
    std::string body;
    bool success;
    CURLcode curl_code;
};

/**
 * @brief Singleton class to manage server interactions.
 * This class provides methods to interact with the server for user management, file uploads, and other operations.
 */
class Server {
public:
    // #Singleton Instance Accessor
    // Returns the single instance of the Server class
    static Server& instance();

    // #Deleted Copy Constructor
    // Prevents copying of the singleton instance
    Server(const Server&) = delete;

    // #Deleted Copy Assignment Operator
    // Prevents assignment of the singleton instance
    Server& operator=(const Server&) = delete;

    // #Deleted Move Constructor
    // Prevents moving of the singleton instance
    Server(Server&&) = delete;

    // #Deleted Move Assignment Operator
    // Prevents move assignment of the singleton instance
    Server& operator=(Server&&) = delete;

    // #Function Overloading
    // Multiple functions with the same name but different parameters
    // Demonstrates compile-time polymorphism
    void create_user(const nlohmann::json& user_data);
    std::string get_new_user_uuid();
    KEKModel get_kek_info(const std::string& user_uuid);
    nlohmann::json update_kek_info(const std::string &encrypted_kek,
                                   const std::string &kek_nonce,
                                   const std::string &updated_at,
                                   const std::string &user_uuid,
                                   const Ed25519PrivateKey &ik_priv);

    // #Function Declaration (call by const reference, returns by value)
    // Retrieves user information by username
    UserModel get_user_by_name(const std::string& username);

    // #Function Declaration (call by const reference, returns by value)
    // Uploads a file to the server
    std::pair<nlohmann::json, std::string> upload_file(const std::string& file_ciphertext,
                                                       const std::string& file_name,
                                                       const std::string& owner_uuid,
                                                       const std::string& mime_type,
                                                       const std::string& file_nonce,
                                                       const std::string& enc_file_k,
                                                       const std::string& k_file_nonce,
                                                       const Ed25519PrivateKey& private_key);

    std::pair<nlohmann::json, std::string> get_user_keys(const std::string& sender_user_uuid,
                                                         const std::string& recipient_uuid,
                                                         const Ed25519PrivateKey& private_key);

    std::pair<nlohmann::json, std::string> send_pac(const PAC& pac,
                                                    const std::string& sender_uuid,
                                                    const Ed25519PrivateKey& private_key);

    std::pair<nlohmann::json, std::string> download_file(const std::string& file_uuid,
                                                         const Ed25519PrivateKey& private_key,
                                                         const std::string& user_uuid);

    std::pair<nlohmann::json, std::string> get_owned_files(const std::string& user_id,
                                                           const Ed25519PrivateKey& private_key);

    nlohmann::json get_user_pacs(const std::string& user_id,
                                 const Ed25519PrivateKey& private_key);

    std::pair<nlohmann::json, std::string> get_file_info(const std::string& file_uuid,
                                                         const std::string& user_uuid,
                                                         const Ed25519PrivateKey& private_key);

    bool get_index();
    // Get the server URL
    std::string server_url() const { return server_url_; }
private:
    // Private constructor to enforce singleton pattern
    Server();
    ~Server();

    std::string server_url_; // Default server URL
    CURL* curl_handle = nullptr; // CURL handle for requests

    // Helper function to initialize CURL
    void init_curl();

    // Helper function to clean up CURL
    void cleanup_curl();

    // #Function Declaration (call by const reference, returns by value)
    // Performs a POST request to the server
    HttpResponse post_request(const std::string& url, const nlohmann::json& payload, const std::vector<std::string>& headers = {});

    // #Function Declaration (call by const reference, returns by value, default argument)
    // Performs a GET request to the server
    HttpResponse get_request(const std::string& url, const std::vector<std::string>& headers = {});

    // #Function Declaration (call by const reference, returns by value, default argument)
    // Performs a PUT request to the server
    HttpResponse put_request(const std::string& url, const nlohmann::json& payload, const std::vector<std::string>& headers = {});

    // #Function Declaration (call by const reference, returns by value)
    // Parses and validates the server response
    nlohmann::json parse_and_check_response(const HttpResponse &resp, const std::string &context);

    // #Function Declaration (call by const reference, returns by value)
    // Retrieves a nonce from the server for the specified user
    std::string get_server_nonce(const std::string &user_uuid);

    // #Function Declaration (call by const reference, returns by value)
    // Signs the payload with the provided private key
    std::string sign_payload(const std::vector<uint8_t>& payload, const std::string& nonce, const Ed25519PrivateKey& private_key);

    // #Function Declaration (call by const reference, returns by value)
    // Sets up headers for the request
    std::vector<std::string> set_headers(const Ed25519PrivateKey &private_key, const std::string &user_uuid,
                                         const nlohmann::json &payload);

    // #Function Declaration (call by const reference, returns by value, default argument)
    // Performs the actual HTTP request
    HttpResponse perform_request(const std::string& url, const std::vector<std::string>& headers, const std::string* payload, bool is_post, bool is_put = false);

};

