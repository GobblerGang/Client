#include <QString>
#include <QStringList>
#include <QWidget>
#include <QFileDialog>
#include <QMessageBox>
#include <QListWidget>
#include <QFileInfo>
#include <QDir>
#include <memory>
#include <unordered_map>
#include "include/FileEncryption.hpp"
#include "include/User.hpp"
#include "include/FileManager.hpp"
#include "include/PACManager.hpp"

// Abstract class
class FileOperation {
public:
    virtual void execute() = 0;
    virtual ~FileOperation() = default;
};

// User class implementation
User::User(const QString& name) : username(name) {
    // Generate encryption key
    encryptionKey = FileEncryption::generateKey();
    
    // Generate RSA key pair for PAC
    auto [priv, pub] = PACManager::generateKeyPair();
    privateKey = priv;
    publicKey = pub;
}

void User::addFile(const QString& file) {
    ownedFiles.append(file);
}

void User::removeFile(const QString& file, bool& success) {
    if (ownedFiles.contains(file)) {
        ownedFiles.removeAll(file);
        success = true;
    } else {
        success = false;
    }
}

const QStringList& User::getOwnedFiles() const {
    return ownedFiles;
}

const QStringList& User::getSharedFiles() const {
    return sharedFiles;
}

const QByteArray& User::getEncryptionKey() const {
    return encryptionKey;
}

PAC User::createOperationPAC(const QString& operation) const {
    return PACManager::createPAC(username, operation, privateKey);
}

bool User::verifyOperationPAC(const PAC& pac) const {
    return PACManager::verifyPAC(pac, publicKey);
}

// AdminUser implementation
AdminUser::AdminUser(const QString& name) : User(name) {}

void AdminUser::addFile(const QString& file) {
    User::addFile(file);
}

// FileManager implementation
FileManager::FileManager(QListWidget* list) : QObject(list), fileList(list) {
    encryptedFilesDir = QDir::currentPath() + "/encrypted_files";
    QDir().mkpath(encryptedFilesDir);
}

void FileManager::setUser(std::unique_ptr<User> user) {
    currentUser = std::move(user);
}

User* FileManager::getCurrentUser() const {
    return currentUser.get();
}

void FileManager::refreshFileList() {
    if (!currentUser) return;

    fileList->clear();
    fileList->addItem("Owned Files:");
    for (const QString& file : currentUser->getOwnedFiles()) {
        fileList->addItem("  " + file);
    }
    fileList->addItem("Shared With You:");
    for (const QString& file : currentUser->getSharedFiles()) {
        fileList->addItem("  " + file);
    }
}

QString FileManager::getEncryptedFilesDir() const {
    return encryptedFilesDir;
}

// UploadOperation implementation
class UploadOperation : public FileOperation {
private:
    QWidget* parent;
    User* user;
    QListWidget* fileList;
    QString encryptedFilesDir;

public:
    UploadOperation(QWidget* p, User* u, QListWidget* fl)
        : parent(p), user(u), fileList(fl) {
        FileManager* manager = qobject_cast<FileManager*>(fl->parent());
        if (manager) {
            encryptedFilesDir = manager->getEncryptedFilesDir();
        } else {
            encryptedFilesDir = QDir::currentPath() + "/encrypted_files";
            QDir().mkpath(encryptedFilesDir);
        }
    }

    void execute() override {
        QString fileName = QFileDialog::getOpenFileName(parent, "Select File to Upload");
        if (!fileName.isEmpty()) {
            try {
                // Create PAC for upload operation
                auto pac = user->createOperationPAC("UPLOAD");
                if (!user->verifyOperationPAC(pac)) {
                    QMessageBox::critical(parent, "Security Error", "Operation verification failed");
                    return;
                }

                QByteArray encryptedData = FileEncryption::encryptFile(fileName, user->getEncryptionKey());
                
                QFileInfo info(fileName);
                QString encryptedPath = encryptedFilesDir + "/" + info.fileName() + ".enc";
                QFile encryptedFile(encryptedPath);
                
                if (encryptedFile.open(QIODevice::WriteOnly)) {
                    encryptedFile.write(encryptedData);
                    encryptedFile.close();
                    
                    user->addFile(info.fileName());
                    QMessageBox::information(parent, "Uploaded", "File encrypted and uploaded: " + info.fileName());
                } else {
                    QMessageBox::warning(parent, "Error", "Failed to save encrypted file");
                }
            } catch (const std::exception& e) {
                QMessageBox::critical(parent, "Error", QString("Operation failed: %1").arg(e.what()));
            }
        }
    }

    static bool decryptAndSaveFile(const QString& encryptedPath, const QString& outputPath, const QByteArray& key) {
        try {
            QFile encryptedFile(encryptedPath);
            if (!encryptedFile.open(QIODevice::ReadOnly)) {
                return false;
            }

            QByteArray encryptedData = encryptedFile.readAll();
            encryptedFile.close();

            QByteArray decryptedData = FileEncryption::decryptFile(encryptedData, key);

            QFile outputFile(outputPath);
            if (!outputFile.open(QIODevice::WriteOnly)) {
                return false;
            }

            outputFile.write(decryptedData);
            outputFile.close();
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }
};

