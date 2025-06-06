#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <sstream>
#include <nlohmann/json.hpp>
#include <openssl/x509.h>
#include <iomanip>
#include "CryptoUtils.h"

#include <iostream>

std::vector<uint8_t> CryptoUtils::encrypt_with_key(
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& key,
    std::vector<uint8_t>& nonce,
    const std::optional<std::vector<uint8_t>>& associated_data
    ) {
    nonce = generate_nonce(12);

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
    return ciphertext;
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

PAC CryptoUtils::create_pac(
    const std::string &file_id,
    const std::string &recipient_id,
    const std::string &issuer_id,
    const std::vector<uint8_t> &encrypted_file_key,
    const std::vector<uint8_t> &encrypted_file_key_nonce,
    const std::vector<uint8_t> &sender_ephemeral_pubkey,
    int64_t valid_until,
    EVP_PKEY* identity_key,  // Ed25519 private key
    const std::optional<std::string> &filename,
    const std::optional<std::string> &mime_type
) {
    // Build ordered JSON for PAC payload
    nlohmann::ordered_json pac_json = {
        {"file_id", file_id},
        {"recipient_id", recipient_id},
        {"issuer_id", issuer_id},
        {"encrypted_file_key", base64_encode(encrypted_file_key)},
        {"encrypted_file_key_nonce", base64_encode(encrypted_file_key_nonce)},
        {"sender_ephemeral_pubkey", base64_encode(sender_ephemeral_pubkey)},
        {"valid_until", valid_until},
        {"revoked", false},
        {"filename", filename.value_or("")},
        {"mime_type", mime_type.value_or("")}
    };

    // Serialize JSON to string to sign
    std::string message = pac_json.dump();

    // Sign message with Ed25519 using OpenSSL EVP interface
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, identity_key) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize Ed25519 signing");
    }

    size_t siglen = 0;
    // First call to get signature length
    if (EVP_DigestSign(ctx, nullptr, &siglen,
                       reinterpret_cast<const uint8_t*>(message.data()), message.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to get signature length");
    }

    std::vector<uint8_t> signature(siglen);

    // Second call to get actual signature
    if (EVP_DigestSign(ctx, signature.data(), &siglen,
                       reinterpret_cast<const uint8_t*>(message.data()), message.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to create Ed25519 signature");
    }
    EVP_MD_CTX_free(ctx);

    // Resize in case signature size differs
    signature.resize(siglen);

    // Convert valid_until to ISO8601 string or empty string if 0
    std::string valid_until_iso;
    if (valid_until != 0) {
        std::time_t time = static_cast<std::time_t>(valid_until);
        std::tm tm = *std::gmtime(&time);
        std::ostringstream oss;
        oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
        valid_until_iso = oss.str();
    }

    return PAC{
        recipient_id,
        file_id,
        valid_until_iso,
        pac_json.at("encrypted_file_key").get<std::string>(),
        base64_encode(signature),
        issuer_id,
        pac_json.at("sender_ephemeral_pubkey").get<std::string>(),
        pac_json.at("encrypted_file_key_nonce").get<std::string>(),
        filename.value_or(""),
        mime_type.value_or(""),
        "",
        ""
    };

}

bool CryptoUtils::verify_pac(const nlohmann::json &pac_json, EVP_PKEY *issuer_public_key) {
    try {
        nlohmann::json copy = pac_json;
        std::vector<uint8_t> signature = base64_decode(copy["signature"]);
        copy.erase("signature");

        std::string message = copy.dump();
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, issuer_public_key);
        EVP_DigestVerifyUpdate(ctx, message.data(), message.size());

        int ok = EVP_DigestVerifyFinal(ctx, signature.data(), signature.size());
        EVP_MD_CTX_free(ctx);
        return ok == 1;
    } catch (...) {
        return false;
    }
}

std::string CryptoUtils::base64_encode(const std::vector<uint8_t>& data) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    BIO_write(bio, data.data(), static_cast<int>(data.size()));
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<uint8_t> CryptoUtils::base64_decode(const std::string& input) {
    BIO* bio, * b64;
    int maxLen = static_cast<int>(input.length());
    std::vector<uint8_t> buffer(maxLen);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), maxLen);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);  // No newlines
    int decodedLen = BIO_read(bio, buffer.data(), maxLen);
    if (decodedLen <= 0) {
        BIO_free_all(bio);
        throw std::runtime_error("Base64 decode failed.");
    }

    buffer.resize(decodedLen);
    BIO_free_all(bio);
    return buffer;
}

bool CryptoUtils::verify_spk(const std::vector<uint8_t> &spk_public, const std::vector<uint8_t> &spk_signature, const std::vector<uint8_t> &spk_data) {
    if (spk_public.size() != 32 || spk_signature.size() != 64) {
        return false;
    }
    EVP_PKEY* pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, spk_public.data(), spk_public.size());
    if (!pubkey) {
        return false;
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pubkey);
        return false;
    }
    bool result = false;
    if (EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pubkey) == 1) {
        int ok = EVP_DigestVerify(ctx, spk_signature.data(), spk_signature.size(), spk_data.data(), spk_data.size());
        result = (ok == 1);
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);
    return result;
}
inline std::vector<uint8_t> CryptoUtils::generate_nonce(const std::size_t size) {
    std::vector<uint8_t> nonce(size);
    if (RAND_bytes(nonce.data(), static_cast<int>(size)) != 1) {
        throw std::runtime_error("Failed to generate secure nonce");
    }
    return nonce;
}
