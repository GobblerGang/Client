#include "3xDH.h"
#include <openssl/evp.h>
#include <vector>
#include <cstring>

std::vector<uint8_t> perform_3xdh_sender(
    EVP_PKEY* id_priv, EVP_PKEY* eph_priv, EVP_PKEY* r_id_pub, EVP_PKEY* r_spk_pub, EVP_PKEY* r_otk_pub
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

std::vector<uint8_t> perform_3xdh_recipient(
    EVP_PKEY* id_priv, EVP_PKEY* spk_priv, EVP_PKEY* s_id_pub, EVP_PKEY* s_eph_pub, EVP_PKEY* otk_priv
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


