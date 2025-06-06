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
         const std::string& mime_type,
         const std::string& issuer_username,
         const std::string& recipient_username)
    : recipient_id(recipient_id),
      file_uuid(file_uuid),
      valid_until(valid_until),
      encrypted_file_key(encrypted_file_key),
      signature(signature),
      issuer_id(issuer_id),
      sender_ephemeral_public(sender_ephemeral_public),
      k_file_nonce(k_file_nonce),
      filename(filename),
      mime_type(mime_type),
      issuer_username(issuer_username),
      recipient_username(recipient_username) {}

PAC PAC::from_json(const json& data) {
    auto get_str = [](const nlohmann::json& j, const std::string& key, const std::string& def = "") {
    return j.contains(key) && !j[key].is_null() ? j[key].get<std::string>() : def;
};

    return PAC(
        get_str(data, "recipient_uuid"),
        get_str(data, "file_uuid"),
        get_str(data, "valid_until"),
        get_str(data, "encrypted_file_key"),
        get_str(data, "signature"),
        get_str(data, "issuer_uuid"),
        get_str(data, "sender_ephemeral_public_key"),
        get_str(data, "k_file_nonce"),
        get_str(data, "file_name"),
        get_str(data, "mime_type"),
        get_str(data, "issuer_username"),
        get_str(data, "recipient_username")
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
