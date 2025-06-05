#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>

#include "FileManager.h"
#include "Server.h"
#include "UI.cpp"
#include "UserManager.h"
#include "database/db_instance.h"
#include "src/Auth.h"
#include "src/models/UserModel.h"
#include <QMimeDatabase>
#include <QFileInfo>
#include <QFile>
int main(int argc, char *argv[]){
    // #Reference to Singleton
    Server& server = Server::instance();

    // #Raw Pointer to UserManager
    UserManager* userManager = new UserManager();
    FileManager* fileManager = new FileManager(*userManager);
    QApplication app(argc, argv);
    const MainWindowUI ui;
    QString currentUser;

    // #Raw Pointer to QListWidgetItem
    QListWidgetItem* selectedItem = ui.fileList->currentItem();

    bool ok = server.get_index();
    if (!ok) {
        QMessageBox::critical(nullptr, "Server Error", "Failed to connect to the server. Please check your network connection or server status.");
        return 1;
    }

    // Persistent instance
    // Function to switch to login/signup tab
    auto switchToAuthTabs = [&]() {
        currentUser.clear();

        ui.loginUsernameEdit->clear();
        ui.loginPasswordEdit->clear();
        ui.loginStatusLabel->clear();

        ui.signupUsernameEdit->clear();
        ui.signupPasswordEdit->clear();
        ui.signupEmailEdit->clear();
        ui.signupStatusLabel->clear();

        while (ui.tabs->count() > 0) {
            ui.tabs->removeTab(0);
        }

        ui.tabs->addTab(ui.loginTab, "Login");
        ui.tabs->addTab(ui.signupTab, "Sign Up");

        ui.window->setWindowTitle("GG File Sharing");
    };

    // Function to switch to files tab
    auto switchToFilesTab = [&]() {
        while (ui.tabs->count() > 0) {
            ui.tabs->removeTab(0);
        }

        ui.tabs->addTab(ui.fileTab, "Files");

        ui.fileList->clear();
        ui.fileList->addItem("Owned Files:");
        ui.fileList->addItem("Shared With You:");

        ui.window->setWindowTitle("GG File Sharing - " + currentUser);
    };

    // Logout
    QObject::connect(ui.logoutButton, &QPushButton::clicked, [&]() {
        QMessageBox::StandardButton reply = QMessageBox::question(
            ui.window,
            "Logout Confirmation",
            "Are you sure you want to logout?",
            QMessageBox::Yes | QMessageBox::No
        );
        if (reply == QMessageBox::Yes) {
            switchToAuthTabs();
        }
    });

    // Login
    // main.cpp

    QObject::connect(ui.loginButton, &QPushButton::clicked, [&]() {
        QString username = ui.loginUsernameEdit->text().trimmed();
        QString password = ui.loginPasswordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            ui.loginStatusLabel->setText("Please enter both username and password.");
            return;
        }

        try {
            bool result = userManager ->login(username.toStdString(), password.toStdString());
            if (result) {
                currentUser = username;
                ui.loginStatusLabel->setText("Login successful!");
                switchToFilesTab();
            } else {
                ui.loginStatusLabel->setText("Login failed. Please try again.");
            }
        } catch (const std::exception& e) {
            ui.loginStatusLabel->setText(QString::fromStdString(e.what()));
        }
    });

    // Signup
    QObject::connect(ui.signupButton, &QPushButton::clicked, [&]() {
        QString username = ui.signupUsernameEdit->text().trimmed();
        QString password = ui.signupPasswordEdit->text().trimmed();
        QString email = ui.signupEmailEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty() || email.isEmpty()) {
            ui.signupStatusLabel->setText("All fields are required.");
            return;
        }

        try {
            auto existing = db().get_all<UserModelORM>(
                where(c(&UserModelORM::username) == username.toStdString())
            );

            if (!existing.empty()) {
                ui.signupStatusLabel->setText("Username already exists. Please choose another.");
                return;
            }
            bool result = userManager->signup(username.toStdString(), email.toStdString(), password.toStdString());
            if (!result) {
                ui.signupStatusLabel->setText(QString::fromStdString("Signup failed. Please try again."));
                return;
            }

            ui.signupStatusLabel->setText("Signup successful! You can now log in.");
            ui.signupUsernameEdit->clear();
            ui.signupPasswordEdit->clear();
            ui.signupEmailEdit->clear();
        } catch (const std::exception& e) {
            ui.signupStatusLabel->setText("Signup error: " + QString(e.what()));
        }
    });

    // Upload
    QObject::connect(ui.uploadButton, &QPushButton::clicked, [&]() {
        QString filePath = QFileDialog::getOpenFileName(ui.window, "Select File to Upload");
        if (filePath.isEmpty()) {
            return; // User cancelled selection
        }

        try {
            // Read the file
            QFile file(filePath);
            if (!file.open(QIODevice::ReadOnly)) {
                QMessageBox::critical(ui.window, "Error", "Could not open file for reading.");
                return;
            }

            // Get file info
            QFileInfo fileInfo(file);
            QString fileName = fileInfo.fileName();
            QString mimeType = QMimeDatabase().mimeTypeForFile(fileInfo).name();
            QByteArray fileData = file.readAll();
            file.close();

            // Convert QByteArray to vector<uint8_t>
            std::vector<uint8_t> fileBytes(fileData.begin(), fileData.end());

            // Call uploadFile with the file data
            fileManager->uploadFile(fileBytes, mimeType.toStdString(), fileName.toStdString());

            QMessageBox::information(ui.window, "Success", "File uploaded successfully!");

        } catch (const std::exception& e) {
            QMessageBox::critical(ui.window, "Error",
                QString("Failed to upload file: %1").arg(e.what()));
        }
    });

    // Share
    QObject::connect(ui.shareButton, &QPushButton::clicked, [&]() {
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Share", "Please select a file to share.");
            return;
        }

        QString itemText = selectedItem->text();
        if (itemText == "Owned Files:" || itemText == "Shared With You:") return;

        bool ok;
        QString username = QInputDialog::getText(ui.window, "Share File",
                                                 "Enter username to share with:", QLineEdit::Normal,
                                                 "", &ok);
        // Share logic
    });

    // Revoke
    QObject::connect(ui.revokeButton, &QPushButton::clicked, [&]() {
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Revoke", "Please select a file.");
            return;
        }

        QString itemText = selectedItem->text();
        if (itemText == "Owned Files:" || itemText == "Shared With You:") return;

        bool ok;
        QString username = QInputDialog::getText(ui.window, "Revoke Access",
                                                 "Enter username to revoke access from:", QLineEdit::Normal,
                                                 "", &ok);
        // Revoke logic
    });

    // Delete
    QObject::connect(ui.deleteButton, &QPushButton::clicked, [&]() {
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Delete", "Please select a file.");
            return;
        }

        QString itemText = selectedItem->text();
        if (itemText == "Owned Files:" || itemText == "Shared With You:") return;

        // Delete logic
    });

    // Initialize with Login + Signup tabs
    switchToAuthTabs();
    ui.window->show();
    return app.exec();
}
