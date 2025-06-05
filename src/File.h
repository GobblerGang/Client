#ifndef FILE_H
#define FILE_H

#include "DataManager.h"
#include "models/FileData.h"
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <optional>
#include "../include/utils/cryptography/CryptoUtils.h"
#include "models/KEKModel.h"
#include "RemoteUserManager.h"


class File : public DataManager {
public:
    File() = default;
    explicit File(const FileData& data);
    ~File() override = default;

    // Getters
    const FileData& getData() const { return data_; }
    
    // Setters
    void setData(const FileData& data) { data_ = data; }

    // File operations
    void encrypt(const std::vector<uint8_t>& file_content, const std::string& mime_type);
    std::vector<uint8_t> decrypt() const;
    
    // Server operations
    nlohmann::json prepareForUpload() const;

protected:
    // Implement virtual functions from DataManager
    nlohmann::json save() override;
    void load(const std::string& identifier) override;

private:
    FileData data_;
    
    // Helper functions for encryption
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encryptWithKey(
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& key,
        const std::optional<std::vector<uint8_t>>& associated_data = std::nullopt
    ) const;
    
    std::vector<uint8_t> decryptWithKey(
        const std::vector<uint8_t>& nonce,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& key,
        const std::optional<std::vector<uint8_t>>& associated_data = std::nullopt
    ) const;

    // KEK operations
    std::vector<uint8_t> getDecryptedKEK() const;
};

#endif // FILE_H
