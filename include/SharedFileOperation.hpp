#pragma once
#include "FileOperationBase.hpp"
#include "Shareable.hpp"
#include <QFile>
#include <QDebug>

// Class that demonstrates multiple inheritance
class SharedFileOperation : public FileOperationBase, public Shareable {
private:
    std::unique_ptr<QFile> fileHandle;
    size_t fileSize;

public:
    explicit SharedFileOperation(const QString& path) 
        : FileOperationBase(path), fileSize(0) {
        fileHandle = std::make_unique<QFile>(path);
    }

    // Implementation of FileOperationBase methods
    bool execute() override {
        if (!validate()) return false;
        
        preProcess();
        bool success = fileHandle->open(QIODevice::ReadOnly);
        if (success) {
            fileSize = fileHandle->size();
            fileHandle->close();
            postProcess();
        }
        return success;
    }

    bool validate() const override {
        return QFile::exists(filePath);
    }

    void preProcess() override {
        addToHistory("Shared File", "Starting shared file operation");
    }

    void postProcess() override {
        addToHistory("Shared File", "Completed shared file operation of " + QString::number(fileSize) + " bytes");
    }

    // Implementation of Shareable methods
    bool shareWith(const QString& username) override {
        if (username.isEmpty()) return false;
        
        // Check if already shared with this user
        if (isSharedWith(username)) return true;
        
        sharedWithUsers.push_back(username);
        addToHistory("Share", "Shared with user: " + username);
        return true;
    }

    bool revokeAccess(const QString& username) override {
        auto it = std::find(sharedWithUsers.begin(), sharedWithUsers.end(), username);
        if (it != sharedWithUsers.end()) {
            sharedWithUsers.erase(it);
            addToHistory("Revoke", "Revoked access for user: " + username);
            return true;
        }
        return false;
    }

    std::vector<QString> getSharedWith() const override {
        return sharedWithUsers;
    }

    bool isSharedWith(const QString& username) const override {
        return std::find(sharedWithUsers.begin(), sharedWithUsers.end(), username) != sharedWithUsers.end();
    }

    // Override callback function
    OperationCallback getCallback() override {
        return [this](const QString& path) {
            this->filePath = path;
            this->execute();
        };
    }
}; 