#include <QString>
#include <QStringList>
#include <QWidget>
#include <QFileDialog>
#include <QMessageBox>
#include <QListWidget>
#include <QFileInfo>
#include <memory>
#include <unordered_map>
using namespace std;

// Abstract class
class FileOperation {
public:
    virtual void execute() = 0;
    virtual ~FileOperation() = default;
};

class User {
protected:
    QString username;
    QStringList ownedFiles;
    QStringList sharedFiles;

public:
    User(const QString& name) : username(name) {}
    virtual ~User() = default;

    virtual void addFile(const QString& file) { ownedFiles.append(file); }

    void removeFile(const QString& file, bool& success) {
        if (ownedFiles.contains(file)) {
            ownedFiles.removeAll(file);
            success = true;
        } else {
            success = false;
        }
    }

    const QStringList& getOwnedFiles() const { return ownedFiles; }
    const QStringList& getSharedFiles() const { return sharedFiles; }
};

class AdminUser : public User {
public:
    AdminUser(const QString& name) : User(name) {}
    void addFile(const QString& file) override {
        User::addFile(file);
    }
};

class FileManager {
private:
    unique_ptr<User> currentUser;
    QListWidget* fileList;

public:
    FileManager(QListWidget* list) : fileList(list) {}

    void setUser(unique_ptr<User> user) {
        currentUser = move(user);
    }

    User* getCurrentUser() const {
        return currentUser.get();
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
};

class UploadOperation : public FileOperation {
private:
    QWidget* parent;
    User* user;
    QListWidget* fileList;

public:
    UploadOperation(QWidget* p, User* u, QListWidget* fl)
            : parent(p), user(u), fileList(fl) {}

    void execute() override {
        QString fileName = QFileDialog::getOpenFileName(parent, "Select File to Upload");
        if (!fileName.isEmpty()) {
            QFileInfo info(fileName);
            user->addFile(info.fileName());
            QMessageBox::information(parent, "Uploaded", "File uploaded: " + info.fileName());
        }
    }
};

