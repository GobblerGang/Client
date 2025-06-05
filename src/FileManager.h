#ifndef FILE_H
#define FILE_H

#include "DataManager.h"
#include "models/File.h"
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include <optional>
#include "utils/cryptography/CryptoUtils.h"


class FileManager : public DataManager {
public:
    FileManager() = default;
    explicit FileManager(const File& data);
    ~FileManager() override = default;

    // Getters
    const File& getData() const { return data_; }
    
    // Setters
    void setData(const File& data) { data_ = data; }

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
    File data_;

};

#endif // FILE_H
