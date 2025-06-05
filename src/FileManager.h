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
    // Initializes a new FileManager instance with default values
    FileManager() = default;
    // #Constructor (call by const reference)
    // Creates a new FileManager instance with the specified File data
    explicit FileManager(const File& data);
    // #Destructor
    // Ensures proper cleanup of FileManager resources
    ~FileManager() override = default;

    // Getters
    // #Function Declaration (returns const reference)
    // Returns a constant reference to the internal File data
    const File& getData() const { return data_; }
    
    // Setters
    // #Function Declaration (call by const reference)
    // Sets the internal File data to the provided value
    void setData(const File& data) { data_ = data; }

    // File operations
    // #Function Declaration (call by const reference)
    // Encrypts the provided file content with the specified MIME type
    void encrypt(const std::vector<uint8_t>& file_content, const std::string& mime_type);
    // #Function Declaration (returns by value)
    // Decrypts and returns the file content
    std::vector<uint8_t> decrypt() const;
    
    // Server operations
    // #Function Declaration (returns by value)
    // Prepares the file data for upload to the server
    nlohmann::json prepareForUpload() const;

protected:
    // Implement virtual functions from DataManager
    // #Function Declaration (returns by value)
    // Saves the current state of the file manager to a JSON object
    nlohmann::json save() override;
    // #Function Declaration (call by const reference)
    // Loads file data from the specified identifier
    void load(const std::string& identifier) override;

private:
    File data_; // Internal storage for file data
};

#endif // FILE_H
