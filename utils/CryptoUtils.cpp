// CryptoUtils.cpp

#include "CryptoUtils.h"
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <stdexcept>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <openssl/core_names.h>
#include <openssl/params.h>

using namespace std;

std::vector<uint8_t> CryptoUtils::derive_master_key(const std::string& password, const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> key(32);
    if (argon2id_hash_raw(2, 65536, 2, password.data(), password.size(), salt.data(), salt.size(), key.data(), key.size()) != ARGON2_OK) {
        throw std::runtime_error("Argon2id key derivation failed");
    }
    return key;
}

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> CryptoUtils::encrypt_with_key(const std::vector<uint8_t>& plaintext, const std::vector<uint8_t>& key, const std::optional<std::vector<uint8_t>>& associated_data) {
    std::vector<uint8_t> nonce(12);
    RAND_bytes(nonce.data(), nonce.size());

    std::vector<uint8_t> ciphertext(plaintext.size() + 16);
    int outlen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    if (associated_data) {
        EVP_EncryptUpdate(ctx, nullptr, &outlen, associated_data->data(), associated_data->size());
    }

    EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size());
    int total_len = outlen;

    EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen);
    total_len += outlen;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + plaintext.size());
    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(plaintext.size() + 16);
    return {nonce, ciphertext};
}

std::vector<uint8_t> CryptoUtils::decrypt_with_key(const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& key, const std::optional<std::vector<uint8_t>>& associated_data) {
    if (ciphertext.size() < 16) throw std::runtime_error("Ciphertext too short");

    std::vector<uint8_t> plaintext(ciphertext.size() - 16);
    int outlen;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());

    if (associated_data) {
        EVP_DecryptUpdate(ctx, nullptr, &outlen, associated_data->data(), associated_data->size());
    }

    EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext.data(), plaintext.size());

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(ciphertext.data() + plaintext.size()));

    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: Invalid tag");
    }

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

pair<EVP_PKEY*, EVP_PKEY*> CryptoUtils::generate_identity_keypair() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* priv = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &priv);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY* pub = EVP_PKEY_dup(priv);
    return {priv, pub};
}

tuple<EVP_PKEY*, EVP_PKEY*, std::vector<uint8_t>> CryptoUtils::generate_signed_prekey(EVP_PKEY* identity_key) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* priv = nullptr;
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_keygen(ctx, &priv);
    EVP_PKEY_CTX_free(ctx);

    EVP_PKEY* pub = EVP_PKEY_dup(priv);
    std::vector<uint8_t> pub_bytes(32);
    size_t len = pub_bytes.size();
    EVP_PKEY_get_raw_public_key(pub, pub_bytes.data(), &len);

    EVP_PKEY_CTX* sign_ctx = EVP_PKEY_CTX_new(identity_key, nullptr);
    EVP_PKEY_sign_init(sign_ctx);

    size_t siglen = 0;
    EVP_PKEY_sign(sign_ctx, nullptr, &siglen, pub_bytes.data(), pub_bytes.size());

    std::vector<uint8_t> signature(siglen);
    EVP_PKEY_sign(sign_ctx, signature.data(), &siglen, pub_bytes.data(), pub_bytes.size());
    signature.resize(siglen);

    EVP_PKEY_CTX_free(sign_ctx);

    return {priv, pub, signature};
}

std::vector<uint8_t> CryptoUtils::perform_3xdh_sender(EVP_PKEY* id_priv, EVP_PKEY* eph_priv, EVP_PKEY* r_id_pub, EVP_PKEY* r_spk_pub, EVP_PKEY* r_otk_pub) {
    std::vector<uint8_t> shared;
    size_t len = 32;
    auto dh = [&](EVP_PKEY* priv, EVP_PKEY* pub) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
        EVP_PKEY_derive_init(ctx);
        EVP_PKEY_derive_set_peer(ctx, pub);
        std::vector<uint8_t> out(len);
        EVP_PKEY_derive(ctx, out.data(), &len);
        shared.insert(shared.end(), out.begin(), out.end());
        EVP_PKEY_CTX_free(ctx);
    };
    dh(eph_priv, r_id_pub);
    dh(id_priv, r_spk_pub);
    dh(eph_priv, r_spk_pub);
    if (r_otk_pub) dh(eph_priv, r_otk_pub);

    std::vector<uint8_t> key(32);
    EVP_PKEY_CTX* hkdf_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    EVP_PKEY_derive_init(hkdf_ctx);
    EVP_PKEY_CTX_set_hkdf_md(hkdf_ctx, EVP_sha256());
    EVP_PKEY_CTX_set1_hkdf_key(hkdf_ctx, shared.data(), shared.size());
    EVP_PKEY_CTX_add1_hkdf_info(hkdf_ctx, reinterpret_cast<const unsigned char *>("3XDH key agreement"), strlen("3XDH key agreement"));
    EVP_PKEY_derive(hkdf_ctx, key.data(), &len);
    EVP_PKEY_CTX_free(hkdf_ctx);
    return key;
}

std::vector<uint8_t> CryptoUtils::perform_3xdh_recipient(EVP_PKEY* id_priv, EVP_PKEY* spk_priv, EVP_PKEY* s_id_pub, EVP_PKEY* s_eph_pub, EVP_PKEY* otk_priv) {
    return perform_3xdh_sender(id_priv, spk_priv, s_eph_pub, s_id_pub, otk_priv);
}

PAC CryptoUtils::create_pac(const std::string &file_id, const std::string &recipient_id, const std::string &issuer_id, const std::vector<uint8_t> &
                            encrypted_file_key, const std::vector<uint8_t> &encrypted_file_key_nonce, const std::vector<uint8_t> &
                            sender_ephemeral_pubkey, int64_t valid_until, EVP_MD_CTX *identity_key, const std::string &filename, const std::string
                            &mime_type) {
    nlohmann::json pac_json = {
        {"file_id", file_id},
        {"recipient_id", recipient_id},
        {"issuer_id", issuer_id},
        {"encrypted_file_key", nlohmann::json::binary(encrypted_file_key)},
        {"encrypted_file_key_nonce", nlohmann::json::binary(encrypted_file_key_nonce)},
        {"sender_ephemeral_pubkey", nlohmann::json::binary(sender_ephemeral_pubkey)},
        {"valid_until", valid_until},
        {"revoked", false},
        {"filename", filename},
        {"mime_type", mime_type}
    };
    std::string message = pac_json.dump();

    std::vector<uint8_t> signature(64);
    size_t siglen = signature.size();
    EVP_DigestSign(identity_key, signature.data(), &siglen, (const uint8_t*)message.data(), message.size());
    signature.resize(siglen);

    pac_json["signature"] = nlohmann::json::binary(signature);

    return PAC::from_json(pac_json);
}

bool CryptoUtils::verify_pac(const nlohmann::json &pac_json, EVP_MD_CTX *issuer_public_key) {
    try {
        nlohmann::json copy = pac_json;
        std::vector<uint8_t> signature = copy["signature"].get_binary();
        copy.erase("signature");
        std::string message = copy.dump();

        int ok = EVP_DigestVerify(issuer_public_key, signature.data(), signature.size(), (const uint8_t*)message.data(), message.size());
        return ok == 1;
    } catch (...) {
        return false;
    }
}
