#pragma once

#include <vector>
#include <string>
#include <mutex>
#include <optional>

class MasterKey {
public:
    static MasterKey& instance();

    void set_key(const std::vector<uint8_t>& key);
    std::vector<uint8_t> get();
    void clear();

    std::vector<uint8_t> derive_key(const std::string& password, const std::vector<uint8_t>& salt);

private:
    MasterKey() = default;
    ~MasterKey();

    MasterKey(const MasterKey&) = delete;
    MasterKey& operator=(const MasterKey&) = delete;

    std::optional<std::vector<uint8_t>> _key;
    std::mutex _mutex;
};
