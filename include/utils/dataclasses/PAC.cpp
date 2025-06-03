#include "PAC.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

PAC::PAC(const std::string& recipient_id,
         const std::string& file_uuid,
         const std::string& valid_until,
         const std::string& encrypted_file_key,
         const std::string& signature,
         const std::string& issuer_id,
         const std::string& sender_ephemeral_public,
         const std::string& k_file_nonce,
         const std::string& filename,
         const std::string& mime_type)
    : recipient_id(recipient_id),
      file_uuid(file_uuid),
      valid_until(valid_until),
      encrypted_file_key(encrypted_file_key),
      signature(signature),
      issuer_id(issuer_id),
      sender_ephemeral_public(sender_ephemeral_public),
      k_file_nonce(k_file_nonce),
      filename(filename),
      mime_type(mime_type) {}

PAC PAC::from_json(const json& data) {
    const json& pac_data = data.contains("pac") ? data["pac"] : json::object();

    auto get_optional_str = [](const json& j, const std::string& key) -> std::optional<std::string> {
        return j.contains(key) && !j[key].is_null() ? std::make_optional(j[key].get<std::string>()) : std::nullopt;
    };

    return PAC(
        data.at("recipient_id").get<std::string>(),
        data.contains("file_uuid") ? data["file_uuid"].get<std::string>() : data["file_id"].get<std::string>(),
        pac_data.at("valid_until").get<std::string>(),
        pac_data.at("encrypted_file_key").get<std::string>(),
        pac_data.at("signature").get<std::string>(),
        data.at("issuer_id").get<std::string>(),
        pac_data.at("sender_encrypted_file_key").get<std::string>(),
        pac_data.contains("nonce") ? pac_data["nonce"].get<std::string>()
                                   : pac_data.at("encrypted_file_key_nonce").get<std::string>(),
        pac_data.at("filename").get<std::string>(),
        pac_data.at("mime_type").get<std::string>()
    );
}

json PAC::to_json() const {
    json pac_json;
    pac_json["recipient_id"] = recipient_id;
    pac_json["file_uuid"] = file_uuid;
    pac_json["valid_until"] = valid_until;
    pac_json["encrypted_file_key"] = encrypted_file_key;
    pac_json["signature"] = signature;
    pac_json["issuer_id"] = issuer_id;
    pac_json["sender_ephemeral_public"] = sender_ephemeral_public;
    pac_json["k_file_nonce"] = k_file_nonce;
    pac_json["filename"] = filename;
    pac_json["mime_type"] = mime_type;

    return pac_json;
}
