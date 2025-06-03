#include "CryptoUtils.h"
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <stdexcept>
#include <sstream>
#include <tuple>
#include <nlohmann/json.hpp>
#include <openssl/x509.h>
#include <openssl/obj_mac.h>
#include "Ed25519Key.h"
#include "VaultManager.h"

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

std::pair<
    std::pair<Ed25519PrivateKey*, Ed25519PublicKey*>,
    std::pair<X25519PrivateKey*, X25519PublicKey*>
> CryptoUtils::generate_identity_keypair() {
    // === Generate Ed25519 Key ===
    EVP_PKEY_CTX* ed_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    EVP_PKEY* ed_pkey = nullptr;
    EVP_PKEY_keygen_init(ed_ctx);
    EVP_PKEY_keygen(ed_ctx, &ed_pkey);
    EVP_PKEY_CTX_free(ed_ctx);

    // Extract raw keys
    std::vector<uint8_t> ed_priv_bytes(32);
    size_t priv_len = ed_priv_bytes.size();
    if (!EVP_PKEY_get_raw_private_key(ed_pkey, ed_priv_bytes.data(), &priv_len))
        throw std::runtime_error("Failed to get raw Ed25519 private key");

    std::vector<uint8_t> ed_pub_bytes(32);
    size_t pub_len = ed_pub_bytes.size();
    if (!EVP_PKEY_get_raw_public_key(ed_pkey, ed_pub_bytes.data(), &pub_len))
        throw std::runtime_error("Failed to get raw Ed25519 public key");

    auto* ed_priv = new Ed25519PrivateKey(ed_priv_bytes);
    auto* ed_pub = new Ed25519PublicKey(ed_pub_bytes);

    // === Generate X25519 Key ===
    EVP_PKEY_CTX* x_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    EVP_PKEY* x_pkey = nullptr;
    EVP_PKEY_keygen_init(x_ctx);
    EVP_PKEY_keygen(x_ctx, &x_pkey);
    EVP_PKEY_CTX_free(x_ctx);

    // Extract raw X25519 keys
    std::vector<uint8_t> x_priv_bytes(32);
    priv_len = x_priv_bytes.size();
    if (!EVP_PKEY_get_raw_private_key(x_pkey, x_priv_bytes.data(), &priv_len))
        throw std::runtime_error("Failed to get raw X25519 private key");

    std::vector<uint8_t> x_pub_bytes(32);
    pub_len = x_pub_bytes.size();
    if (!EVP_PKEY_get_raw_public_key(x_pkey, x_pub_bytes.data(), &pub_len))
        throw std::runtime_error("Failed to get raw X25519 public key");

    auto* x_priv = new X25519PrivateKey(x_priv_bytes);
    auto* x_pub = new X25519PublicKey(x_pub_bytes);

    // Cleanup
    EVP_PKEY_free(ed_pkey);
    EVP_PKEY_free(x_pkey);

    return {
        {ed_priv, ed_pub},
        {x_priv, x_pub}
    };
}


std::tuple<X25519PrivateKey *, X25519PublicKey *, std::vector<uint8_t>> CryptoUtils::generate_signed_prekey(
    EVP_PKEY *identity_key) {
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


    // Extract raw X25519 keys
    std::vector<uint8_t> x_priv_bytes(32);
    size_t priv_len = x_priv_bytes.size();
    if (!EVP_PKEY_get_raw_private_key(priv, x_priv_bytes.data(), &priv_len))
        throw std::runtime_error("Failed to get raw X25519 private key");

    std::vector<uint8_t> x_pub_bytes(32);
    size_t pub_len = x_pub_bytes.size();
    if (!EVP_PKEY_get_raw_public_key(pub, x_pub_bytes.data(), &pub_len))
        throw std::runtime_error("Failed to get raw X25519 public key");

    auto* x_priv = new X25519PrivateKey(x_priv_bytes);
    auto* x_pub = new X25519PublicKey(x_pub_bytes);
    std::tuple signedkey= std::make_tuple(x_priv, x_pub, signature);
    return signedkey;
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

std::vector<uint8_t> CryptoUtils::perform_3xdh_recipient(
    EVP_PKEY* id_priv,
    EVP_PKEY* spk_priv,
    EVP_PKEY* s_id_pub,
    EVP_PKEY* s_eph_pub,
    EVP_PKEY* otk_priv
) {
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

    dh(id_priv, s_eph_pub);
    dh(spk_priv, s_id_pub);
    dh(spk_priv, s_eph_pub);
    if (otk_priv) dh(otk_priv, s_eph_pub);

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

#include <openssl/evp.h>
#include <iomanip>
#include <sstream>
#include <ctime>
#include <stdexcept>

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
        {"encrypted_file_key", VaultManager::base64_encode(encrypted_file_key)},
        {"encrypted_file_key_nonce", VaultManager::base64_encode(encrypted_file_key_nonce)},
        {"sender_ephemeral_pubkey", VaultManager::base64_encode(sender_ephemeral_pubkey)},
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
        VaultManager::base64_encode(signature),
        issuer_id,
        pac_json.at("sender_ephemeral_pubkey").get<std::string>(),
        pac_json.at("encrypted_file_key_nonce").get<std::string>(),
        filename.value_or(""),
        mime_type.value_or("")
    };

}

bool CryptoUtils::verify_pac(const nlohmann::json &pac_json, EVP_PKEY *issuer_public_key) {
    try {
        nlohmann::json copy = pac_json;
        std::vector<uint8_t> signature = VaultManager::base64_decode(copy["signature"]);
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