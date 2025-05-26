#pragma once
#include <QString>
#include <QByteArray>
#include <QFile>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <memory>
#include <stdexcept>

class FileEncryption {
private:
    static constexpr size_t KEY_SIZE = 32;  // 256 bits for AES-256
    static constexpr size_t IV_SIZE = 12;   // 96 bits for GCM mode
    static constexpr size_t TAG_SIZE = 16;  // 128 bits for GCM authentication tag

    // Helper function to generate random bytes
    static QByteArray generateRandomBytes(size_t length) {
        QByteArray bytes(length, 0);
        if (RAND_bytes(reinterpret_cast<unsigned char*>(bytes.data()), length) != 1) {
            throw std::runtime_error("Failed to generate random bytes");
        }
        return bytes;
    }

public:
    // Encrypts a file using AES-GCM
    static QByteArray encryptFile(const QString& filePath, const QByteArray& key) {
        if (key.size() != KEY_SIZE) {
            throw std::invalid_argument("Invalid key size");
        }

        // Read the file
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            throw std::runtime_error("Failed to open file for reading");
        }
        QByteArray plaintext = file.readAll();
        file.close();

        // Generate IV
        QByteArray iv = generateRandomBytes(IV_SIZE);

        // Create and initialize the encryption context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        // Initialize encryption
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, 
            reinterpret_cast<const unsigned char*>(key.data()),
            reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize encryption");
        }

        // Prepare output buffer
        QByteArray ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH, 0);
        int len = 0;

        // Encrypt the data
        if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(ciphertext.data()), &len,
            reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt data");
        }

        // Finalize encryption
        int finalLen = 0;
        if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(ciphertext.data() + len), &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize encryption");
        }

        // Get the authentication tag
        QByteArray tag(TAG_SIZE, 0);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to get authentication tag");
        }

        // Clean up
        EVP_CIPHER_CTX_free(ctx);

        // Combine IV + ciphertext + tag
        QByteArray result;
        result.append(iv);
        result.append(ciphertext.left(len + finalLen));
        result.append(tag);

        return result;
    }

    // Decrypts a file using AES-GCM
    static QByteArray decryptFile(const QByteArray& encryptedData, const QByteArray& key) {
        if (key.size() != KEY_SIZE) {
            throw std::invalid_argument("Invalid key size");
        }

        if (encryptedData.size() < IV_SIZE + TAG_SIZE) {
            throw std::invalid_argument("Invalid encrypted data size");
        }

        // Extract IV, ciphertext, and tag
        QByteArray iv = encryptedData.left(IV_SIZE);
        QByteArray tag = encryptedData.right(TAG_SIZE);
        QByteArray ciphertext = encryptedData.mid(IV_SIZE, encryptedData.size() - IV_SIZE - TAG_SIZE);

        // Create and initialize the decryption context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        // Initialize decryption
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
            reinterpret_cast<const unsigned char*>(key.data()),
            reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize decryption");
        }

        // Prepare output buffer
        QByteArray plaintext(ciphertext.size(), 0);
        int len = 0;

        // Decrypt the data
        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(plaintext.data()), &len,
            reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to decrypt data");
        }

        // Set the expected tag value
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to set authentication tag");
        }

        // Finalize decryption
        int finalLen = 0;
        if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plaintext.data() + len), &finalLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize decryption (authentication failed)");
        }

        // Clean up
        EVP_CIPHER_CTX_free(ctx);

        return plaintext.left(len + finalLen);
    }

    // Generates a new random encryption key
    static QByteArray generateKey() {
        return generateRandomBytes(KEY_SIZE);
    }
}; 