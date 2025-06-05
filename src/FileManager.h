#ifndef FILE_H
#define FILE_H

#include "DataManager.h"
#include "models/File.h"
#include <nlohmann/json.hpp>
#include <vector>
#include <string>
#include "utils/cryptography/CryptoUtils.h"


class FileManager : public DataManager {
public:
    // #Default Constructor
    FileManager() = default;
    // #Constructor (call by const reference)
    explicit FileManager(const File& data);
    // #Destructor
    ~FileManager() override = default;

    // Getters
    // #Function Declaration (returns const reference)
    const File& getData() const { return data_; }
    
    // Setters
    // #Function Declaration (call by const reference)
    void setData(const File& data) { data_ = data; }

    // File operations
    // #Function Declaration (call by const reference)
    void encrypt(const std::vector<uint8_t>& file_content, const std::string& mime_type);
    // #Function Declaration (returns by value)
    std::vector<uint8_t> decrypt() const;
    
    // Server operations
    // #Function Declaration (returns by value)
    nlohmann::json prepareForUpload() const;

protected:
    // Implement virtual functions from DataManager
    // #Function Declaration (returns by value)
    nlohmann::json save() override;
    // #Function Declaration (call by const reference)
    void load(const std::string& identifier) override;

private:
    File data_;
};

#endif // FILE_H
