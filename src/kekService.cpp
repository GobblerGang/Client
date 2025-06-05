#include "KekService.h"
#include "utils/cryptography/CryptoUtils.h"
#include "utils/cryptography/VaultManager.h"
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
    kek_model.enc_kek_cyphertext = CryptoUtils::base64_encode(ciphertext);
    kek_model.nonce = CryptoUtils::base64_encode(nonce);
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

