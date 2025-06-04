#pragma once

#include <string>
#include <vector>
#include <utility>  // for std::pair
#include "utils/CryptoUtils.h"
#include "models/KEKModel.h"

class KekService {
public:
    static KEKModel encrypt_kek(const std::vector<uint8_t>& kek, const std::vector<uint8_t>& master_key, const std::string& user_uuid, int user_id);

    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> try_decrypt_kek(const KEKModel& kek_model, const std::vector<uint8_t>& master_key, const std::string& user_uuid);

    static std::vector<uint8_t> get_decrypted_kek(const KEKModel& kek_model,
                                                  const std::vector<uint8_t>& master_key,
                                                  const std::string& user_uuid);

private:
    static std::string get_current_iso8601_utc();
    static std::vector<uint8_t> format_aad(const std::string& user_uuid, const std::string& timestamp);
};