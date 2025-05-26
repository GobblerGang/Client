#pragma once

#include <QObject>
#include <QListWidget>
#include <QString>
#include <memory>
#include "User.hpp"

class FileManager : public QObject {
    Q_OBJECT
private:
    std::unique_ptr<User> currentUser;
    QListWidget* fileList;
    QString encryptedFilesDir;

public:
    explicit FileManager(QListWidget* list);
    void setUser(std::unique_ptr<User> user);
    User* getCurrentUser() const;
    void refreshFileList();
    QString getEncryptedFilesDir() const;
}; 