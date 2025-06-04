#pragma once
#include "Congig.cpp"
#include <string>
#include <vector>
#include <optional>
#include <nlohmann/json.hpp>

// Forward declaration
class Ed25519PrivateKey;
class PAC;

// Helper function
std::optional<nlohmann::json> parse_server_response(const std::string& response_body, int status_code);

// Server request functions
std::string get_server_nonce(const std::string& user_uuid);
std::string sign_payload(const std::vector<uint8_t>& payload, const std::string& nonce, const Ed25519PrivateKey& private_key);
nlohmann::json set_headers(const Ed25519PrivateKey& private_key, const std::string& user_uuid, const nlohmann::json& payload);

nlohmann::json create_user(const nlohmann::json& user_data);
std::pair<std::string, std::string> get_new_user_uuid();

std::pair<nlohmann::json, std::string> get_kek_info(const std::string& user_uuid);
std::pair<nlohmann::json, std::string> update_kek_info(const std::string& encrypted_kek,
                                                        const std::string& kek_nonce,
                                                        const std::string& updated_at,
                                                        const std::string& user_uuid,
                                                        const Ed25519PrivateKey& ik_priv);

std::pair<nlohmann::json, std::string> get_user_by_name(const std::string& username);

std::pair<nlohmann::json, std::string> upload_file(const std::vector<uint8_t>& file_ciphertext,
                                                   const std::string& file_name,
                                                   const std::string& owner_uuid,
                                                   const std::string& mime_type,
                                                   const std::vector<uint8_t>& file_nonce,
                                                   const std::vector<uint8_t>& enc_file_k,
                                                   const std::vector<uint8_t>& k_file_nonce,
                                                   const Ed25519PrivateKey& private_key);

std::pair<nlohmann::json, std::string> get_user_keys(const std::string& sender_user_uuid,
                                                     const std::string& recipient_uuid,
                                                     const Ed25519PrivateKey& private_key);

std::pair<nlohmann::json, std::string> send_pac(const PAC& pac,
                                                const std::string& sender_uuid,
                                                const Ed25519PrivateKey& private_key);

std::pair<nlohmann::json, std::string> download_file(const std::string& file_uuid,
                                                     const Ed25519PrivateKey& private_key,
                                                     const std::string& user_uuid);

std::pair<nlohmann::json, std::string> get_owned_files(const std::string& user_id,
                                                       const Ed25519PrivateKey& private_key);

nlohmann::json get_user_pacs(const std::string& user_id,
                             const Ed25519PrivateKey& private_key);

std::pair<nlohmann::json, std::string> get_file_info(const std::string& file_uuid,
                                                     const std::string& user_uuid,
                                                     const Ed25519PrivateKey& private_key);
