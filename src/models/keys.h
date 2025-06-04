// src/models/keys.h
#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include <vector>

struct Keys {
    std::string identity_key_public;
    std::string signed_prekey_public;
    std::string signed_prekey_signature;
    std::vector<std::pair<std::string, std::string>> opks;
};