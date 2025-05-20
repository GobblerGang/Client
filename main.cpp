#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QLabel>
#include <QListWidget>
#include <QTabWidget>
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <vector>
#include <memory>
using namespace std;

// Abstract base class for file operations
class FileOperation {
public:
    virtual void execute() = 0;
    virtual ~FileOperation() = default;
};
//test
//please

// Base class for user management
class User {
protected:
    QString username;
    QStringList ownedFiles;
    QStringList sharedFiles;

public:
    User(const QString& name) : username(name) {}
    virtual ~User() = default;

    // Make addFile virtual so it can be overridden
    virtual void addFile(const QString& file) { ownedFiles.append(file); }
    void addFile(const QString& file, const QString& owner) {
        sharedFiles.append(file + " (shared by " + owner + ")");
    }

    // Call by reference
    void removeFile(const QString& file, bool& success) {
        if (ownedFiles.contains(file)) {
            ownedFiles.removeAll(file);
            success = true;
        } else {
            success = false;
        }
    }

    QString getUsername() const { return username; }
    const QStringList& getOwnedFiles() const { return ownedFiles; }
    const QStringList& getSharedFiles() const { return sharedFiles; }
};

// Derived class for admin users
class AdminUser : public User {
public:
    AdminUser(const QString& name) : User(name) {}

    // Override virtual function
    void addFile(const QString& file) override {
        User::addFile(file);
        // Admin-specific file handling
    }
};

// File manager class using RAII
class FileManager {
private:
    unique_ptr<User> currentUser;
    QListWidget* fileList;

public:
    FileManager(QListWidget* list) : fileList(list) {}

    // Copy constructor
    FileManager(const FileManager& other) : fileList(other.fileList) {
        if (other.currentUser) {
            currentUser = std::make_unique<User>(other.currentUser->getUsername());
        }
    }

    void setUser(unique_ptr<User> user) {
        currentUser = move(user);
    }

    // Add getCurrentUser method
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

    // Pointer arithmetic example
    void processFiles() {
        QStringList* files = new QStringList(currentUser->getOwnedFiles());
        QStringList* current = files;
        while (current != files + 1) {
            // Process files
            current++;
        }
        delete files;
    }
};

// Concrete file operation classes
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

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    QWidget window;
    window.setWindowTitle("Secure File Sharing");

    QTabWidget *tabs = new QTabWidget();

    // --- Login/Signup tab ---
    QWidget *authTab = new QWidget();
    QVBoxLayout *authLayout = new QVBoxLayout();

    QLineEdit *usernameEdit = new QLineEdit();
    usernameEdit->setPlaceholderText("Username");
    QLineEdit *passwordEdit = new QLineEdit();
    passwordEdit->setPlaceholderText("Password");
    passwordEdit->setEchoMode(QLineEdit::Password);

    QPushButton *loginButton = new QPushButton("Login");
    QPushButton *signupButton = new QPushButton("Sign Up");

    authLayout->addWidget(new QLabel("Login / Signup"));
    authLayout->addWidget(usernameEdit);
    authLayout->addWidget(passwordEdit);
    authLayout->addWidget(loginButton);
    authLayout->addWidget(signupButton);
    authTab->setLayout(authLayout);

    // --- File Manager tab ---
    QWidget *fileTab = new QWidget();
    QVBoxLayout *fileLayout = new QVBoxLayout();

    QListWidget *fileList = new QListWidget();
    QPushButton *uploadButton = new QPushButton("Upload");
    QPushButton *downloadButton = new QPushButton("Download");
    QPushButton *shareButton = new QPushButton("Share");
    QPushButton *revokeButton = new QPushButton("Revoke Access");
    QPushButton *deleteButton = new QPushButton("Delete");

    QHBoxLayout *buttonsLayout = new QHBoxLayout();
    buttonsLayout->addWidget(uploadButton);
    buttonsLayout->addWidget(downloadButton);
    buttonsLayout->addWidget(shareButton);
    buttonsLayout->addWidget(revokeButton);
    buttonsLayout->addWidget(deleteButton);

    fileLayout->addWidget(new QLabel("Your Files:"));
    fileLayout->addWidget(fileList);
    fileLayout->addLayout(buttonsLayout);
    fileTab->setLayout(fileLayout);

    tabs->addTab(authTab, "Login");
    tabs->addTab(fileTab, "Files");

    QVBoxLayout *mainLayout = new QVBoxLayout();
    mainLayout->addWidget(tabs);
    window.setLayout(mainLayout);
    window.resize(650, 400);

    // Create file manager
    FileManager fileManager(fileList);

    // Connect signals
    QObject::connect(loginButton, &QPushButton::clicked, [&]() {
        QString username = usernameEdit->text();
        if (username.isEmpty()) {
            QMessageBox::warning(&window, "Login Failed", "Please enter a username.");
            return;
        }

        // Create new user
        fileManager.setUser(make_unique<User>(username));
        QMessageBox::information(&window, "Logged in", "Welcome, " + username + "!");
        tabs->setCurrentIndex(1);
        fileManager.refreshFileList();
    });

    QObject::connect(uploadButton, &QPushButton::clicked, [&]() {
        UploadOperation uploadOp(&window, fileManager.getCurrentUser(), fileList);
        uploadOp.execute();
        fileManager.refreshFileList();
    });

    window.show();
    return app.exec();
}