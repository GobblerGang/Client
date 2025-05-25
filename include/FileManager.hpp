#pragma once
#include <QListWidget>
#include <memory>
#include <unordered_map>
#include "EnhancedUser.hpp"
#include "FileOperations.hpp"

template<typename T>
class FileManagerTemplate {
private:
    std::shared_ptr<T> currentUser;
    QListWidget* fileList;
    std::unordered_map<QString, std::shared_ptr<T>> userDatabase;

public:
    explicit FileManagerTemplate(QListWidget* list) : fileList(list) {}

    void setUser(std::shared_ptr<T> user) {
        currentUser = std::move(user);
    }

    std::shared_ptr<T> getCurrentUser() const {
        return currentUser;
    }

    void refreshFileList() {
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

    bool addUser(const QString& username, const QString& password) {
        if (userDatabase.find(username) != userDatabase.end()) {
            return false;
        }
        userDatabase[username] = std::make_shared<T>(username);
        return true;
    }

    std::shared_ptr<T> authenticateUser(const QString& username, const QString& password) {
        auto it = userDatabase.find(username);
        if (it != userDatabase.end()) {
            return it->second;
        }
        return nullptr;
    }
};

// Concrete implementation using EnhancedUser
using FileManager = FileManagerTemplate<EnhancedUser>; 