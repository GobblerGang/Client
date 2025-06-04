#include <utils/Config.h>
#include <stdexcept>
#include <fstream>
#include "nlohmann/json.hpp"

Config& Config::get_instance() {
    static Config instance;
    return instance;
}

const std::string& Config::server_url() const {
    return server_url_;
}

Config::Config() {
    std::ifstream file("config.json");
    if (!file) throw std::runtime_error("Missing config.json");

    nlohmann::json j;
    file >> j;

    if (!j.contains("server_url") || !j["server_url"].is_string())
        throw std::runtime_error("Invalid config.json: missing or invalid 'server_url'");

    server_url_ = j["server_url"].get<std::string>();
}