//
// Created by Ruairi on 04/06/2025.
//
#include <Server.h>

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

bool Server::get_index() {
    init_curl();
    std::string response;
    curl_easy_setopt(curl_handle, CURLOPT_URL, (server_url_ + "/").c_str());
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, +[](const char* ptr, const size_t size, size_t nmemb, void* userdata) -> size_t {
        auto* str = static_cast<std::string*>(userdata);
        str->append(ptr, size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl_handle);
    long http_code = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
    }
    cleanup_curl();
    return (res == CURLE_OK) && (http_code == 200);
}


// nlohmann::json Server::create_user(const nlohmann::json& user_data) const {
//     CURL* curl = curl_easy_init();
//     if (!curl) throw std::runtime_error("Failed to initialize CURL");
//
//     std::string response;
//     struct curl_slist* headers = nullptr;
//     headers = curl_slist_append(headers, "Content-Type: application/json");
//
//     curl_easy_setopt(curl, CURLOPT_URL, (server_url_ + "/api/register").c_str());
//     curl_easy_setopt(curl, CURLOPT_POSTFIELDS, user_data.dump().c_str());
//     curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
//     curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, +[](char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
//         auto* str = static_cast<std::string*>(userdata);
//         str->append(ptr, size * nmemb);
//         return size * nmemb;
//     });
//     curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
//
//     CURLcode res = curl_easy_perform(curl);
//     curl_slist_free_all(headers);
//     curl_easy_cleanup(curl);
//
//     if (res != CURLE_OK) throw std::runtime_error("CURL error: " + std::string(curl_easy_strerror(res)));
//
//     return nlohmann::json::parse(response);
// }
