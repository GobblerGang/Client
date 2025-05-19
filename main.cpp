#include <QApplication>
#include <QWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QLabel>
#include <QListWidget>
#include <QTabWidget>
#include <QFileDialog>
#include <QInputDialog>
#include <QMessageBox>

QString currentUser;
QStringList ownedFiles;
QStringList sharedFiles;

void refreshFileList(QListWidget *list) {
    list->clear();
    list->addItem("📁 Owned Files:");
    for (const QString &file : ownedFiles) {
        list->addItem("  " + file);
    }
    list->addItem("👥 Shared With You:");
    for (const QString &file : sharedFiles) {
        list->addItem("  " + file);
    }
}

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

    // Add tabs to the main window
    tabs->addTab(authTab, "Login");
    tabs->addTab(fileTab, "Files");

    QVBoxLayout *mainLayout = new QVBoxLayout();
    mainLayout->addWidget(tabs);
    window.setLayout(mainLayout);
    window.resize(650, 400);
    window.show();

    // --- Functional connections ---

    QObject::connect(loginButton, &QPushButton::clicked, [&]() {
        currentUser = usernameEdit->text();
        if (currentUser.isEmpty()) {
            QMessageBox::warning(&window, "Login Failed", "Please enter a username.");
            return;
        }
        QMessageBox::information(&window, "Logged in", "Welcome, " + currentUser + "!");
        tabs->setCurrentIndex(1);
        refreshFileList(fileList);
    });

    QObject::connect(signupButton, &QPushButton::clicked, [&]() {
        QString user = usernameEdit->text();
        if (user.isEmpty()) {
            QMessageBox::warning(&window, "Signup Failed", "Please enter a username.");
            return;
        }
        QMessageBox::information(&window, "Signup Complete", "Account created for " + user);
    });

    QObject::connect(uploadButton, &QPushButton::clicked, [&]() {
        QString fileName = QFileDialog::getOpenFileName(&window, "Select File to Upload");
        if (!fileName.isEmpty()) {
            QFileInfo info(fileName);
            ownedFiles.append(info.fileName());
            QMessageBox::information(&window, "Uploaded", "File uploaded: " + info.fileName());
            refreshFileList(fileList);
        }
    });

    QObject::connect(downloadButton, &QPushButton::clicked, [&]() {
        QListWidgetItem *item = fileList->currentItem();
        if (!item || item->text().startsWith("📁") || item->text().startsWith("👥")) {
            QMessageBox::warning(&window, "Download", "Please select a file to download.");
            return;
        }
        QMessageBox::information(&window, "Downloaded", "File downloaded: " + item->text().trimmed());
    });

    QObject::connect(deleteButton, &QPushButton::clicked, [&]() {
        QListWidgetItem *item = fileList->currentItem();
        QString name = item ? item->text().trimmed() : "";
        if (ownedFiles.contains(name)) {
            ownedFiles.removeAll(name);
            QMessageBox::information(&window, "Deleted", "File deleted: " + name);
            refreshFileList(fileList);
        } else {
            QMessageBox::warning(&window, "Delete", "You can only delete your own files.");
        }
    });

    QObject::connect(shareButton, &QPushButton::clicked, [&]() {
        QListWidgetItem *item = fileList->currentItem();
        QString name = item ? item->text().trimmed() : "";
        if (ownedFiles.contains(name)) {
            QString targetUser = QInputDialog::getText(&window, "Share File", "Share with user:");
            if (!targetUser.isEmpty()) {
                sharedFiles.append(name + " (shared by " + currentUser + ")");
                QMessageBox::information(&window, "Shareds", "File shared with " + targetUser);
                refreshFileList(fileList);
            }
        } else {
            QMessageBox::warning(&window, "Share", "Select one of your own files to share.");
        }
    });

    QObject::connect(revokeButton, &QPushButton::clicked, [&]() {
        QListWidgetItem *item = fileList->currentItem();
        QString name = item ? item->text().trimmed() : "";
        if (sharedFiles.contains(name)) {
            sharedFiles.removeAll(name);
            QMessageBox::information(&window, "Access Revoked", "Access revoked for file: " + name);
            refreshFileList(fileList);
        } else {
            QMessageBox::warning(&window, "Revoke", "Select a shared file to revoke.");
        }
    });

    return app.exec();
}