#pragma once

#include <string>
#include <vector>
#include <utility>
#include "../include/utils/cryptography/CryptoUtils.h"
#include "models/KEKModel.h"

class KekService {
public:
    static KEKModel encrypt_kek(const std::vector<uint8_t>& kek, const std::vector<uint8_t>& master_key, const std::string& user_uuid, int user_id);

    //TODO remove pair, return only kek, get aad by ref
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> decrypt_kek(const KEKModel& kek_model, const std::vector<uint8_t>& master_key, const std::string& user_uuid);

private:
    static std::string get_current_iso8601_utc();
    static std::vector<uint8_t> format_aad(const std::string& user_uuid, const std::string& timestamp);
};