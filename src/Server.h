#pragma once
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include <curl/curl.h>
#include "RequestHeaders.h"
#include "models/KEKModel.h"
// Forward declaration
class Ed25519PrivateKey;
class PAC;
/** * @brief Struct to hold HTTP response data.
 */
struct HttpResponse {
    long status_code;
    std::string body;
    bool success;
    CURLcode curl_code;
};

/** * @brief Singleton class to manage server interactions.
 * This class provides methods to interact with the server for user management, file uploads, and other operations.
 */
class Server {
public:
    // Singleton instance access
    static Server& instance();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    Server(Server&&) = delete;
    Server& operator=(Server&&) = delete;
    /**
     * @brief Creates a new user on the server. POSTs to url/api/users
     * @param user_data A JSON object containing user data (username, email, password).
     * @throws std::runtime_error if the server request fails or returns an error.
     */
    void create_user(const nlohmann::json& user_data);
    /**
     * @brief Generates a new UUID for the user. GETs url/api/generate-uuid
     * @return A string containing the new UUID.
     * @throws std::runtime_error if the server request fails or returns an error.
     */
    std::string get_new_user_uuid();

    KEKModel get_kek_info(const std::string& user_uuid);

    nlohmann::json update_kek_info(const std::string &encrypted_kek,
                                   const std::string &kek_nonce,
                                   const std::string &updated_at,
                                   const std::string &user_uuid,
                                   const Ed25519PrivateKey &ik_priv);

    std::pair<nlohmann::json, std::string> get_user_by_name(const std::string& username);

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

    /**
     * @brief Performs a POST request to the specified URL with the given payload.
     * @param url The URL to send the POST request to.
     * @param payload The JSON payload to send in the request body.
     * @param headers Optional headers to include in the request.
     * @return An HttpResponse object containing the response data.
     */
    HttpResponse post_request(const std::string& url, const nlohmann::json& payload, const std::vector<std::string>& headers = {});

    /**
     * @brief Performs a GET request to the specified URL.
     * @param url The URL to send the GET request to.
     * @param headers Optional headers to include in the request.
     * @return An HttpResponse object containing the response data.
     */
    HttpResponse get_request(const std::string& url, const std::vector<std::string>& headers = {});

    /**
     * @brief Performs a PUT request to the specified URL with the given payload.
     * @param url The URL to send the PUT request to.
     * @param payload The JSON payload to send in the request body.
     * @param headers Optional headers to include in the request.
     * @return An HttpResponse object containing the response data.
     */
    HttpResponse put_request(const std::string& url, const nlohmann::json& payload, const std::vector<std::string>& headers = {});

    nlohmann::json parse_and_check_response(const HttpResponse &resp, const std::string &context);

    // // Helper function to parse server response
    // std::optional<nlohmann::json> parse_server_response(const nlohmann::json response_body, int status_code);

    // Functions for setting/signing headers

    std::string get_server_nonce(const std::string &user_uuid);

    std::string sign_payload(const std::vector<uint8_t>& payload, const std::string& nonce, const Ed25519PrivateKey& private_key);

    std::vector<std::string> set_headers(const Ed25519PrivateKey &private_key, const std::string &user_uuid,
                                         const nlohmann::json &payload);

    /**
     * @brief Performs a request to the specified URL with the given payload.
     * @param url The URL to send the request to.
     * @param headers Optional headers to include in the request.
     * @param payload The JSON payload to send in the request body.
     * @param is_post Boolean indicating if the request is a POST request.
     * @param is_put Boolean indicating if the request is a PUT request.
     * @return An HttpResponse object containing the response data.
     */
    HttpResponse perform_request(const std::string& url, const std::vector<std::string>& headers, const std::string* payload, bool is_post, bool is_put = false);

};

