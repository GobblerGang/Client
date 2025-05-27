#pragma once

#include <QString>
#include <QByteArray>
#include <QDateTime>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <memory>
#include <stdexcept>

// PAC structure definition
struct PAC {
    QString username;
    QString operation;
    QDateTime timestamp;
    QByteArray signature;
};

class PACManager {
private:
    static constexpr size_t RSA_KEY_SIZE = 2048;
    static constexpr size_t SIGNATURE_SIZE = 256;  // For RSA-2048

    // Helper function to convert PAC to byte array for signing
    static QByteArray pacToBytes(const PAC& pac) {
        QByteArray data;
        data.append(pac.username.toUtf8());
        data.append(pac.operation.toUtf8());
        data.append(pac.timestamp.toString(Qt::ISODate).toUtf8());
        return data;
    }

public:
    // Generate a new RSA key pair
    static std::pair<QByteArray, QByteArray> generateKeyPair() {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (!ctx) {
            throw std::runtime_error("Failed to create key context");
        }

        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize key generation");
        }

        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, RSA_KEY_SIZE) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to set RSA key size");
        }

        EVP_PKEY* pkey = nullptr;
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to generate key pair");
        }

        // Save private key
        BIO* bio = BIO_new(BIO_s_mem());
        if (!bio) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to create BIO");
        }

        if (PEM_write_bio_PrivateKey(bio, pkey, nullptr, nullptr, 0, nullptr, nullptr) != 1) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to write private key");
        }

        char* privateKeyData = nullptr;
        long privateKeyLength = BIO_get_mem_data(bio, &privateKeyData);
        QByteArray privateKey(privateKeyData, privateKeyLength);
        BIO_free(bio);

        // Save public key
        bio = BIO_new(BIO_s_mem());
        if (!bio) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to create BIO");
        }

        if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
            BIO_free(bio);
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            throw std::runtime_error("Failed to write public key");
        }

        char* publicKeyData = nullptr;
        long publicKeyLength = BIO_get_mem_data(bio, &publicKeyData);
        QByteArray publicKey(publicKeyData, publicKeyLength);

        // Clean up
        BIO_free(bio);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);

        return {privateKey, publicKey};
    }

    // Sign a PAC
    static QByteArray signPAC(const PAC& pac, const QByteArray& privateKey) {
        // Load private key
        BIO* bio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }

        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) {
            throw std::runtime_error("Failed to read private key");
        }

        // Create signature context
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create signature context");
        }

        // Initialize signing
        if (EVP_DigestSignInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to initialize signing");
        }

        // Convert PAC to bytes
        QByteArray data = pacToBytes(pac);

        // Sign the data
        if (EVP_DigestSignUpdate(md_ctx, data.data(), data.size()) != 1) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to update signature");
        }

        // Get signature size
        size_t sig_len = SIGNATURE_SIZE;
        QByteArray signature(sig_len, 0);

        // Finalize signature
        if (EVP_DigestSignFinal(md_ctx, reinterpret_cast<unsigned char*>(signature.data()), &sig_len) != 1) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to finalize signature");
        }

        // Clean up
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);

        return signature.left(sig_len);
    }

    // Verify a PAC
    static bool verifyPAC(const PAC& pac, const QByteArray& publicKey) {
        // Load public key
        BIO* bio = BIO_new_mem_buf(publicKey.data(), publicKey.size());
        if (!bio) {
            throw std::runtime_error("Failed to create BIO");
        }

        EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!pkey) {
            throw std::runtime_error("Failed to read public key");
        }

        // Create verification context
        EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
        if (!md_ctx) {
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to create verification context");
        }

        // Initialize verification
        if (EVP_DigestVerifyInit(md_ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to initialize verification");
        }

        // Convert PAC to bytes
        QByteArray data = pacToBytes(pac);

        // Update verification
        if (EVP_DigestVerifyUpdate(md_ctx, data.data(), data.size()) != 1) {
            EVP_MD_CTX_free(md_ctx);
            EVP_PKEY_free(pkey);
            throw std::runtime_error("Failed to update verification");
        }

        // Verify signature
        int result = EVP_DigestVerifyFinal(md_ctx, 
            reinterpret_cast<const unsigned char*>(pac.signature.data()),
            pac.signature.size());

        // Clean up
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(pkey);

        return result == 1;
    }

    // Create a new PAC
    static PAC createPAC(const QString& username, const QString& operation, const QByteArray& privateKey) {
        PAC pac;
        pac.username = username;
        pac.operation = operation;
        pac.timestamp = QDateTime::currentDateTime();
        pac.signature = signPAC(pac, privateKey);
        return pac;
    }
}; 