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

HttpResponse Server::get_request(const std::string &url, const std::vector<std::string>& headers) {
    init_curl();
    HttpResponse response_obj;
    std::string response;
    curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, +[](const char* ptr, size_t size, size_t nmemb, void* userdata) -> size_t {
        auto* str = static_cast<std::string*>(userdata);
        str->append(ptr, size * nmemb);
        return size * nmemb;
    });
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &response);

    struct curl_slist* curl_headers = nullptr;
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
    response_obj.success = (res == CURLE_OK && http_code == 200);
    response_obj.curl_code = res;
    if (curl_headers) {
        curl_slist_free_all(curl_headers);
    }
    return response_obj;
}


bool Server::get_index() {
    HttpResponse resp = get_request(server_url_ + "/");
    return resp.success;
}

std::string Server::get_server_nonce(const std::string &user_uuid) {
    init_curl();
    return "";
}

std::string Server::get_new_user_uuid() {
    HttpResponse resp = get_request(server_url_ + "/api/generate-uuid");
    if (!resp.success) {
        throw std::runtime_error("Failed to get new user UUID: " + resp.body);
    }
    if (resp.body.empty()) {
        throw std::runtime_error("Received empty response for new user UUID");
    }
    try {
        nlohmann::json json_response = nlohmann::json::parse(resp.body);
        if (json_response.contains("uuid")) {
            return json_response["uuid"].get<std::string>();
        } else {
            throw std::runtime_error("UUID not found in response");
        }
    } catch (const nlohmann::json::exception& e) {
        throw std::runtime_error("Failed to parse UUID response: " + std::string(e.what()));
    }
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
