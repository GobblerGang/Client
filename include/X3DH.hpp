#pragma once

#include <QByteArray>
#include <QString>
#include <memory>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>
#include <stdexcept>

class X3DH {
public:
    static constexpr size_t KEY_SIZE = 32;  // 256 bits
    static constexpr size_t NONCE_SIZE = 24;  // 192 bits for XChaCha20-Poly1305

    struct KeyPair {
        QByteArray privateKey;
        QByteArray publicKey;
    };

    struct PreKeyBundle {
        QByteArray identityKey;      // Long-term identity key
        QByteArray signedPreKey;     // Signed pre-key
        QByteArray preKeySignature;  // Signature of the signed pre-key
        QByteArray oneTimePreKey;    // One-time pre-key (optional)
    };

    // Generate a new EC key pair
    static KeyPair generateKeyPair() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create key context");
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize key generation");
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to generate key pair");
        }

        // Get public key
        size_t pub_len = 0;
        if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &pub_len) <= 0) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to get public key length");
        }

        QByteArray publicKey(pub_len, 0);
        if (EVP_PKEY_get_raw_public_key(pkey, reinterpret_cast<unsigned char*>(publicKey.data()), &pub_len) <= 0) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to get public key");
        }

        // Get private key
        size_t priv_len = 0;
        if (EVP_PKEY_get_raw_private_key(pkey, nullptr, &priv_len) <= 0) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to get private key length");
        }

        QByteArray privateKey(priv_len, 0);
        if (EVP_PKEY_get_raw_private_key(pkey, reinterpret_cast<unsigned char*>(privateKey.data()), &priv_len) <= 0) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to get private key");
        }

        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        return {privateKey, publicKey};
    }

    // Helper function to perform ECDH key exchange
    static QByteArray performECDH(const QByteArray& privateKey, const QByteArray& publicKey) {
        EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
            reinterpret_cast<const unsigned char*>(privateKey.data()), privateKey.size());
        if (!pkey) {
            throw std::runtime_error("Failed to create private key");
        }

        EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
            reinterpret_cast<const unsigned char*>(publicKey.data()), publicKey.size());
        if (!peer_pkey) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create peer public key");
        }

        EVP_PKEY_CTX* derive_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!derive_ctx) {
            EVP_PKEY_free(peer_pkey);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create derive context");
        }

        if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
            EVP_PKEY_CTX_free(derive_ctx);
            EVP_PKEY_free(peer_pkey);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to initialize derive");
        }

        if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pkey) <= 0) {
            EVP_PKEY_CTX_free(derive_ctx);
            EVP_PKEY_free(peer_pkey);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to set peer");
        }

        size_t shared_len = 0;
        if (EVP_PKEY_derive(derive_ctx, nullptr, &shared_len) <= 0) {
            EVP_PKEY_CTX_free(derive_ctx);
            EVP_PKEY_free(peer_pkey);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to get shared secret length");
        }

        QByteArray sharedSecret(shared_len, 0);
        if (EVP_PKEY_derive(derive_ctx, reinterpret_cast<unsigned char*>(sharedSecret.data()), &shared_len) <= 0) {
            EVP_PKEY_CTX_free(derive_ctx);
            EVP_PKEY_free(peer_pkey);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to derive shared secret");
        }

        EVP_PKEY_CTX_free(derive_ctx);
        EVP_PKEY_free(peer_pkey);
        EVP_PKEY_free(pkey);

        return sharedSecret;
    }

    // Helper function to generate a random nonce
    static QByteArray generateNonce() {
        QByteArray nonce(NONCE_SIZE, 0);
        if (RAND_bytes(reinterpret_cast<unsigned char*>(nonce.data()), NONCE_SIZE) != 1) {
            throw std::runtime_error("Failed to generate nonce");
        }
        return nonce;
    }

    // Generate a new pre-key bundle
    static PreKeyBundle generatePreKeyBundle() {
        PreKeyBundle bundle;
        
        // Generate identity key pair
        auto identityKeys = generateKeyPair();
        bundle.identityKey = identityKeys.publicKey;

        // Generate signed pre-key pair
        auto signedPreKeys = generateKeyPair();
        bundle.signedPreKey = signedPreKeys.publicKey;

        // Sign the signed pre-key with the identity key
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            throw std::runtime_error("Failed to create signature context");
        }

        if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, nullptr) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw std::runtime_error("Failed to initialize signing");
        }

        if (EVP_DigestSignUpdate(md_ctx, bundle.signedPreKey.data(), bundle.signedPreKey.size()) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw std::runtime_error("Failed to update signature");
        }

        size_t sig_len = 0;
        if (EVP_DigestSignFinal(md_ctx, nullptr, &sig_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw std::runtime_error("Failed to get signature length");
        }

        bundle.preKeySignature.resize(sig_len);
        if (EVP_DigestSignFinal(md_ctx, reinterpret_cast<unsigned char*>(bundle.preKeySignature.data()), &sig_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            throw std::runtime_error("Failed to finalize signature");
        }

        EVP_MD_CTX_free(md_ctx);

        // Generate one-time pre-key (optional)
        auto oneTimeKeys = generateKeyPair();
        bundle.oneTimePreKey = oneTimeKeys.publicKey;

        return bundle;
    }

    // Perform the 3XDH key exchange
    static QByteArray performX3DH(const QByteArray& identityPrivateKey,
                                const QByteArray& ephemeralPrivateKey,
                                const PreKeyBundle& bundle) {
        // 1. DH1 = DH(IK_A, SPK_B)
        QByteArray dh1 = performECDH(identityPrivateKey, bundle.signedPreKey);

        // 2. DH2 = DH(EK_A, IK_B)
        QByteArray dh2 = performECDH(ephemeralPrivateKey, bundle.identityKey);

        // 3. DH3 = DH(EK_A, SPK_B)
        QByteArray dh3 = performECDH(ephemeralPrivateKey, bundle.signedPreKey);

        // 4. DH4 = DH(EK_A, OPK_B) if available
        QByteArray dh4;
        if (!bundle.oneTimePreKey.isEmpty()) {
            dh4 = performECDH(ephemeralPrivateKey, bundle.oneTimePreKey);
        }

        // 5. Combine all shared secrets
        QByteArray combined;
        combined.append(dh1);
        combined.append(dh2);
        combined.append(dh3);
        if (!dh4.isEmpty()) {
            combined.append(dh4);
        }

        // 6. Generate final key using HKDF
        QByteArray finalKey(KEY_SIZE, 0);
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create HKDF context");
        }

        if (EVP_PKEY_derive_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize HKDF");
        }

        if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set HKDF digest");
        }

        // Convert QByteArray data to unsigned char*
        const unsigned char* combinedData = reinterpret_cast<const unsigned char*>(combined.constData());
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, combinedData, combined.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set HKDF salt");
        }

        if (EVP_PKEY_CTX_set1_hkdf_key(ctx, combinedData, combined.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set HKDF key");
        }

        size_t outlen = KEY_SIZE;
        if (EVP_PKEY_derive(ctx, reinterpret_cast<unsigned char*>(finalKey.data()), &outlen) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to derive final key");
        }

        EVP_PKEY_CTX_free(ctx);
        return finalKey;
    }
}; 