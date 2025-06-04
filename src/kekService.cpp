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

#ifdef KEK_SERVICE_TEST_MAIN
#include <iostream>

int main() {
    std::vector<uint8_t> kek = {1,2,3,4,5,6,7,8,9,0};
    std::vector<uint8_t> master_key = {10,11,12,13,14,15,16,17,18,19};
    std::string user_uuid = "test-uuid";
    int user_id = 42;

    KEKModel model = KekService::encrypt_kek(kek, master_key, user_uuid, user_id);

    std::cout << "enc_kek_cyphertext: " << model.enc_kek_cyphertext << std::endl;
    std::cout << "nonce: " << model.nonce << std::endl;
    std::cout << "updated_at: " << model.updated_at << std::endl;
    std::cout << "user_id: " << model.user_id << std::endl;

    // Simple checks
    if (model.enc_kek_cyphertext.empty() || model.nonce.empty()) {
        std::cerr << "Test failed: ciphertext or nonce is empty." << std::endl;
        return 1;
    }
    std::cout << "KEKService::encrypt_kek test passed." << std::endl;
    return 0;
}
#endif
