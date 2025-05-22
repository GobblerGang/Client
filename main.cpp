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
#include <QSpacerItem>
#include <unordered_map>
#include <memory>

using namespace std;

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

    QString getUsername() const { return username; }
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

int main(int argc, char *argv[]) {
    cout<<"test";
    QApplication app(argc, argv);

    QWidget window;
    window.setWindowTitle("Secure File Sharing");

    QTabWidget *tabs = new QTabWidget();
    tabs->setTabPosition(QTabWidget::North);

    QWidget *authTab = new QWidget();
    QVBoxLayout *authLayout = new QVBoxLayout();
    authLayout->setAlignment(Qt::AlignCenter);

    QLineEdit *usernameEdit = new QLineEdit();
    usernameEdit->setPlaceholderText("Username");
    QLineEdit *passwordEdit = new QLineEdit();
    passwordEdit->setPlaceholderText("Password");
    passwordEdit->setEchoMode(QLineEdit::Password);

    QPushButton *loginButton = new QPushButton("Login");
    QPushButton *signupButton = new QPushButton("Sign Up");

    QLabel *statusLabel = new QLabel;

    authLayout->addWidget(new QLabel("Login / Signup"));
    authLayout->addWidget(usernameEdit);
    authLayout->addWidget(passwordEdit);
    authLayout->addWidget(loginButton);
    authLayout->addWidget(signupButton);
    authLayout->addWidget(statusLabel);
    authTab->setLayout(authLayout);

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

    QVBoxLayout *mainLayout = new QVBoxLayout();
    mainLayout->addWidget(tabs);
    window.setLayout(mainLayout);
    window.resize(700, 400);

    FileManager *fileManagerPtr = new FileManager(fileList);
    unordered_map<QString, QString> userDatabase;

    tabs->addTab(authTab, "Login");

    QObject::connect(loginButton, &QPushButton::clicked, [&]() {
        QString username = usernameEdit->text().trimmed();
        QString password = passwordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            statusLabel->setText("Please enter both username and password.");
            return;
        }

        auto it = userDatabase.find(username);
        if (it != userDatabase.end() && it->second == password) {
            fileManagerPtr->setUser(make_unique<User>(username));
            fileManagerPtr->refreshFileList();
            statusLabel->setText("Login successful!");
            if (tabs->count() < 2)
                tabs->addTab(fileTab, "Files");
            tabs->setCurrentWidget(fileTab);
        } else {
            statusLabel->setText("Incorrect username or password.");
        }
    });

    QObject::connect(signupButton, &QPushButton::clicked, [&]() {
        QString username = usernameEdit->text().trimmed();
        QString password = passwordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            statusLabel->setText("Please enter both username and password.");
            return;
        }

        if (userDatabase.find(username) != userDatabase.end()) {
            statusLabel->setText("User already exists.");
        } else {
            userDatabase[username] = password;
            fileManagerPtr->setUser(make_unique<User>(username));
            fileManagerPtr->refreshFileList();
            statusLabel->setText("Signup successful! You are now logged in.");
            if (tabs->count() < 2)
                tabs->addTab(fileTab, "Files");
            tabs->setCurrentWidget(fileTab);
        }
    });

    QObject::connect(uploadButton, &QPushButton::clicked, [&]() {
        UploadOperation op(&window, fileManagerPtr->getCurrentUser(), fileList);
        op.execute();
        fileManagerPtr->refreshFileList();
    });

    QObject::connect(deleteButton, &QPushButton::clicked, [&]() {
        auto* user = fileManagerPtr->getCurrentUser();
        QListWidgetItem* selectedItem = fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(&window, "Delete", "Please select a file.");
            return;
        }

        QString itemText = selectedItem->text().trimmed();
        if (itemText.startsWith("Owned Files:") || itemText.startsWith("Shared With You:")) {
            return;
        }

        bool success = false;
        user->removeFile(itemText, success);
        if (success) {
            QMessageBox::information(&window, "Deleted", "File removed.");
        } else {
            QMessageBox::warning(&window, "Failed", "You can only delete owned files.");
        }
        fileManagerPtr->refreshFileList();
    });

    window.show();
    return app.exec();
}
