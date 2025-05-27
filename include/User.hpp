#pragma once

#include <QString>
#include <QStringList>
#include <QByteArray>
#include "FileEncryption.hpp"
#include "PACManager.hpp"

class User {
protected:
    QString username;
    QStringList ownedFiles;
    QStringList sharedFiles;
    QByteArray encryptionKey;
    QByteArray privateKey;
    QByteArray publicKey;

public:
    explicit User(const QString& name);
    virtual ~User() = default;

    virtual void addFile(const QString& file);
    void removeFile(const QString& file, bool& success);
    const QStringList& getOwnedFiles() const;
    const QStringList& getSharedFiles() const;
    const QByteArray& getEncryptionKey() const;
    const QByteArray& getPublicKey() const { return publicKey; }

    // PAC operations
    PAC createOperationPAC(const QString& operation) const;
    bool verifyOperationPAC(const PAC& pac) const;
};

class AdminUser : public User {
public:
    explicit AdminUser(const QString& name);
    void addFile(const QString& file) override;
}; 