#pragma once

#include <QString>
#include <QStringList>
#include <QByteArray>
#include "PACManager.hpp"
#include "X3DH.hpp"

class User {
protected:
    // Core identity
    int id;                            // Matches SQLAlchemy id
    QString uuid;                     // UUID for user identification
    QString username;                 // Unique username
    QString email;                    // Email address

    // Owned/shared files
    QStringList ownedFiles;
    QStringList sharedFiles;

    // Cryptographic keys (public)
    QByteArray identity_key_public;   // Base64 encoded Ed25519 public key
    QByteArray signed_prekey_public;  // Base64 encoded X25519 public key
    QByteArray signed_prekey_signature; // Base64 encoded signature

    // Vault values
    QByteArray salt;                        // Base64 encoded salt (44 chars)
    QByteArray identity_key_private_enc;   // Base64 encrypted private key
    QByteArray identity_key_private_nonce; // Nonce for identity key encryption
    QByteArray signed_prekey_private_enc;  // Base64 encrypted SPK
    QByteArray signed_prekey_private_nonce;// Nonce for SPK encryption

    // One-Time PreKeys (OPKs)
    QString opks_json;                     // JSON string of base64-encoded OPKs

    // Derived X3DH key pairs (not serialized directly in DB)
    QByteArray encryptionKey;
    QByteArray privateKey;  // SPK private key raw
    QByteArray publicKey;   // SPK public key raw

    QByteArray identityPrivateKey;
    QByteArray identityPublicKey;
    QByteArray ephemeralPrivateKey;
    QByteArray ephemeralPublicKey;

    X3DH::PreKeyBundle preKeyBundle;

    friend class VaultManager;


public:
    explicit User(const QString& name);
    virtual ~User() = default;

    // File operations
    virtual void addFile(const QString& file);
    void removeFile(const QString& file, bool& success);
    const QStringList& getOwnedFiles() const;
    const QStringList& getSharedFiles() const;

    // Accessors
    const QByteArray& getEncryptionKey() const;
    const QByteArray& getPublicKey() const { return publicKey; }

    // PAC operations
    PAC createOperationPAC(const QString& operation) const;
    bool verifyOperationPAC(const PAC& pac) const;

    // X3DH operations
    void generateX3DHKeys();
    const X3DH::PreKeyBundle& getPreKeyBundle() const;
    QByteArray performKeyExchange(const X3DH::PreKeyBundle& peerBundle);

    // DB sync helpers (optional if you want to serialize/deserialize from DB)
    void setUUID(const QString& id) { uuid = id; }
    const QString& getUUID() const { return uuid; }

    void setEmail(const QString& e) { email = e; }
    const QString& getEmail() const { return email; }

    void setOPKsJson(const QString& json) { opks_json = json; }
    const QString& getOPKsJson() const { return opks_json; }

    // and so on for other fields...
};

