#include "MasterKey.h"
#include "utils/cryptography//CryptoUtils.h"
#include <random>

MasterKey& MasterKey::instance() {
    static MasterKey instance;
    return instance;
}

void MasterKey::set_key(const std::vector<uint8_t>& key) {
    std::lock_guard<std::mutex> lock(_mutex);
    _key = key;
}

std::vector<uint8_t> MasterKey::get() {
    std::lock_guard<std::mutex> lock(_mutex);
    if (!_key.has_value()) {
        throw std::runtime_error("Master key not set");
    }
    return *_key;
}

void MasterKey::clear() {
    std::lock_guard<std::mutex> lock(_mutex);
    if (_key.has_value()) {
        // Overwrite key with random bytes before clearing
        std::random_device rd;
        std::vector<uint8_t>& key_ref = *_key;
        for (auto& byte : key_ref) {
            byte = static_cast<uint8_t>(rd());
        }
        _key.reset();
    }
}

std::vector<uint8_t> MasterKey::derive_key(const std::string& password, const std::vector<uint8_t>& salt) {
    return CryptoUtils::derive_master_key(password, salt);
}

MasterKey::~MasterKey() {
    clear();
}
