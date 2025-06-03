#include "PAC.h"

using json = nlohmann::json;

PAC::PAC(const std::string& recipient_id,
         const std::string& file_uuid,
         const std::optional<std::string>& valid_until,
         const std::vector<uint8_t>& encrypted_file_key,
         const std::vector<uint8_t>& signature,
         const std::string& issuer_id,
         const std::vector<uint8_t>& sender_ephemeral_public,
         const std::vector<uint8_t>& k_file_nonce,
         const std::optional<std::string>& filename,
         const std::optional<std::string>& mime_type)
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

    auto base64_to_bytes = [](const std::string& encoded) -> std::vector<uint8_t> {
        return nlohmann::json::from_bson(nlohmann::json::to_bson(encoded));
        // You should replace this with real base64 decoding
    };

    return PAC(
        data.at("recipient_id").get<std::string>(),
        data.contains("file_uuid") ? data["file_uuid"].get<std::string>() : data["file_id"].get<std::string>(),
        pac_data.value("valid_until", std::optional<std::string>{}),
        base64_to_bytes(pac_data["encrypted_file_key"]),
        base64_to_bytes(pac_data["signature"]),
        pac_data["issuer_id"].get<std::string>(),
        base64_to_bytes(pac_data["sender_ephemeral_public"]),
        base64_to_bytes(pac_data.contains("nonce") ? pac_data["nonce"].get<std::string>()
                                                   : pac_data["encrypted_file_key_nonce"].get<std::string>()),
        pac_data.value("filename", std::optional<std::string>{}),
        pac_data.value("mime_type", std::optional<std::string>{})
    );
}

json PAC::to_json() const {
    auto bytes_to_base64 = [](const std::vector<uint8_t>& bin) -> std::string {
        return nlohmann::json::from_bson(bin).dump(); // You should replace this with real base64 encoding
    };

    json pac_json;
    pac_json["recipient_id"] = recipient_id;
    pac_json["file_uuid"] = file_uuid;
    if (valid_until) pac_json["valid_until"] = *valid_until;
    pac_json["encrypted_file_key"] = bytes_to_base64(encrypted_file_key);
    pac_json["signature"] = bytes_to_base64(signature);
    pac_json["issuer_id"] = issuer_id;
    pac_json["sender_ephemeral_public"] = bytes_to_base64(sender_ephemeral_public);
    pac_json["k_file_nonce"] = bytes_to_base64(k_file_nonce);
    if (filename) pac_json["filename"] = *filename;
    if (mime_type) pac_json["mime_type"] = *mime_type;

    return pac_json;
}

