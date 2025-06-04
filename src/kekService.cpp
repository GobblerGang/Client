#include "KekService.h"
#include "utils/CryptoUtils.h"
#include "utils/VaultManager.h"
#include "models/KEKModel.h"
#include <chrono>
#include <iomanip>
#include <sstream>

KEKModel KekService::encrypt_kek(const std::vector<uint8_t>& kek,
                                   const std::vector<uint8_t>& master_key,
                                   const std::string& user_uuid,
                                   int user_id) {
    std::string timestamp = get_current_iso8601_utc();
    std::vector<uint8_t> aad = format_aad(user_uuid, timestamp);
    auto [nonce, ciphertext] = CryptoUtils::encrypt_with_key(kek, master_key, aad);

    KEKModel kek_model;
    kek_model.enc_kek_cyphertext = VaultManager::base64_encode(ciphertext);
    kek_model.nonce = VaultManager::base64_encode(nonce);
    kek_model.updated_at = timestamp;
    kek_model.user_id = user_id;

    return kek_model;
}

std::vector<uint8_t> KekService::format_aad(const std::string& user_uuid, const std::string& timestamp) {
    std::string aad_str = user_uuid + ":" + timestamp;
    return std::vector<uint8_t>(aad_str.begin(), aad_str.end());
}

std::string KekService::get_current_iso8601_utc() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm utc_tm = *gmtime(&now_time);

    std::ostringstream oss;
    oss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

