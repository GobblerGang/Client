#include "KekService.h"
#include "utils/cryptography/CryptoUtils.h"
#include "utils/cryptography/VaultManager.h"
#include "models/KEKModel.h"
#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

KEKModel KekService::encrypt_kek(const std::vector<uint8_t>& kek,
                                   const std::vector<uint8_t>& master_key,
                                   const std::string& user_uuid,
                                   const int user_id) {
    const std::string timestamp = get_current_iso8601_utc();
    std::vector<uint8_t> aad = format_aad(user_uuid, timestamp);
    // Passing nonce by
    std::vector<uint8_t> kek_nonce;
    const auto ciphertext = CryptoUtils::encrypt_with_key(kek, master_key, kek_nonce, aad);

    KEKModel kek_model;
    kek_model.enc_kek_cyphertext = CryptoUtils::base64_encode(ciphertext);
    kek_model.nonce = CryptoUtils::base64_encode(kek_nonce);
    kek_model.updated_at = timestamp;
    kek_model.user_id = user_id;

    return kek_model;
}
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> KekService::decrypt_kek(
    const KEKModel& kek_model,
    const std::vector<uint8_t>& master_key,
    const std::string& user_uuid) {

    std::vector<uint8_t> ciphertext = CryptoUtils::base64_decode(kek_model.enc_kek_cyphertext);
    std::vector<uint8_t> nonce = CryptoUtils::base64_decode(kek_model.nonce);
    std::vector<uint8_t> aad = format_aad(user_uuid, kek_model.updated_at);

    std::vector<uint8_t> decrypted_kek = CryptoUtils::decrypt_with_key(nonce, ciphertext, master_key, aad);

    return std::make_pair(decrypted_kek, aad);
}


std::vector<uint8_t> KekService::format_aad(const std::string& user_uuid, const std::string& timestamp) {
    nlohmann::ordered_json aad_json = {{"user_uuid", user_uuid}, {"timestamp", timestamp}};
    std::string aad_str = aad_json.dump(); // Default dump() is compact, no spaces
    return {aad_str.begin(), aad_str.end()};
}

std::string KekService::get_current_iso8601_utc() {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    auto now_us = std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()) % 1000000;

    std::tm utc_tm = *gmtime(&now_time_t);

    std::ostringstream oss;
    oss << std::put_time(&utc_tm, "%Y-%m-%dT%H:%M:%S");
    oss << '.' << std::setw(6) << std::setfill('0') << now_us.count();
    oss << "+00:00";
    return oss.str();
}

