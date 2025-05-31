#pragma once

#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

class PAC {
public:
    std::string recipient_id;
    std::string file_uuid;
    std::optional<std::string> valid_until;  // ISO 8601 string format
    std::vector<uint8_t> encrypted_file_key;
    std::vector<uint8_t> signature;
    std::string issuer_id;
    std::vector<uint8_t> sender_ephemeral_public;
    std::vector<uint8_t> k_file_nonce;
    std::optional<std::string> filename;
    std::optional<std::string> mime_type;

    PAC() = default;

    PAC(const std::string& recipient_id,
        const std::string& file_uuid,
        const std::optional<std::string>& valid_until,
        const std::vector<uint8_t>& encrypted_file_key,
        const std::vector<uint8_t>& signature,
        const std::string& issuer_id,
        const std::vector<uint8_t>& sender_ephemeral_public,
        const std::vector<uint8_t>& k_file_nonce,
        const std::optional<std::string>& filename = std::nullopt,
        const std::optional<std::string>& mime_type = std::nullopt);

    static PAC from_json(const nlohmann::json& data);
    nlohmann::json to_json() const;
};

