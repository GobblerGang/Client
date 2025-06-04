#ifndef FILE_H
#define FILE_H

#include "../DataManager.h"
#include "FileData.h"
#include <nlohmann/json.hpp>

class File : public DataManager {
public:
    File() = default;
    explicit File(const FileData& data);
    ~File() override = default;

    // Getters
    const FileData& getData() const { return data_; }
    
    // Setters
    void setData(const FileData& data) { data_ = data; }

protected:
    // Implement virtual functions from DataManager
    nlohmann::json save() override;
    void load(const std::string& identifier) override;

private:
    FileData data_;
};

#endif // FILE_H
