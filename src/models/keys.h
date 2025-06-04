// src/models/keys.h
#pragma once
#include <string>
#include <nlohmann/json.hpp>
#include <vector>

struct Keys {
    std::vector<uint8_t> identity_key_public;
    std::vector<uint8_t> signed_prekey_public;
    std::vector<uint8_t> signed_prekey_signature;
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> opks;
};