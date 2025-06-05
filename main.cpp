#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>

#include "Server.h"
#include "UI.cpp"
#include "UserManager.h"
#include "database/db_instance.h"
#include "src/Auth.h"
#include "src/models/UserModel.h"

#ifdef _WIN32
#include <windows.h>
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    int argc = 0;
    char **argv = nullptr;
#else
int main(int argc, char *argv[]) {
#endif
    QApplication app(argc, argv);

    Server& server = Server::instance(); // Initialize server instance
    bool ok = server.get_index();
    if (!ok) {
        QMessageBox::critical(nullptr, "Server Error", "Failed to connect to the server. Please check your network connection or server status.");
        return 1;
    }

    const MainWindowUI ui;
    QString currentUser;

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
    QObject::connect(ui.loginButton, &QPushButton::clicked, [&]() {
        QString username = ui.loginUsernameEdit->text().trimmed();
        QString password = ui.loginPasswordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            ui.loginStatusLabel->setText("Please enter both username and password.");
            return;
        }

        try {
            auto users = db().get_all<UserModelORM>(
                where(c(&UserModelORM::username) == username.toStdString())
            );

            if (users.empty()) {
                ui.loginStatusLabel->setText("User not found. Please check your username.");
                return;
            }

            const UserModelORM& user = users.front();

            // Replace this with secure password check
            if (user.salt == password.toStdString()) {
                currentUser = username;
                ui.loginStatusLabel->setText("Login successful!");
                switchToFilesTab();
            } else {
                ui.loginStatusLabel->setText("Incorrect password. Please try again.");
            }
        } catch (const std::exception& e) {
            ui.loginStatusLabel->setText("Login error: " + QString(e.what()));
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
            // Auth::SignUpResult result = Auth::signup(username.toStdString(), email.toStdString(), password.toStdString());
            UserManager* userManager = new UserManager();
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
        QString fileName = QFileDialog::getOpenFileName(ui.window, "Select File to Upload");
        // File upload logic
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
