#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>
#include <unordered_map>
#include "UI.cpp"
#include "User.hpp"
#include "database/db_instance.h"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    MainWindowUI ui;
    std::unordered_map<QString, QString> userDatabase;
    QString currentUser; // Track the currently logged in user

    // Function to switch to login tab
    auto switchToLoginTab = [&]() {
        // Clear current user
        currentUser.clear();
        
        // Clear the input fields
        ui.usernameEdit->clear();
        ui.passwordEdit->clear();
        ui.statusLabel->clear();
        
        // Remove all tabs
        while (ui.tabs->count() > 0) {
            ui.tabs->removeTab(0);
        }
        
        // Add login tab
        ui.tabs->addTab(ui.authTab, "Login");
        
        // Reset window title
        ui.window->setWindowTitle("GG File Sharing");
    };

    // Function to switch to files tab and hide login tab
    auto switchToFilesTab = [&]() {
        // Remove the login tab
        ui.tabs->removeTab(0);
        
        // Add the files tab if it's not already there
        ui.tabs->addTab(ui.fileTab, "Files");
        
        // Clear and populate file list
        ui.fileList->clear();
        ui.fileList->addItem("Owned Files:");
        ui.fileList->addItem("Shared With You:");
        
        // Set window title to include username
        ui.window->setWindowTitle("GG File Sharing - " + currentUser);
    };
    
    // Connect logout button
    QObject::connect(ui.logoutButton, &QPushButton::clicked, [&]() {
        // Ask for confirmation
        QMessageBox::StandardButton reply = QMessageBox::question(
            ui.window, 
            "Logout Confirmation", 
            "Are you sure you want to logout?",
            QMessageBox::Yes | QMessageBox::No
        );
        
        if (reply == QMessageBox::Yes) {
            switchToLoginTab();
        }
    });

    QObject::connect(ui.loginButton, &QPushButton::clicked, [&]() {
        QString username = ui.usernameEdit->text().trimmed();
        QString password = ui.passwordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            ui.statusLabel->setText("Please enter both username and password.");
            return;
        }

        auto it = userDatabase.find(username);
        if (it != userDatabase.end() && it->second == password) {
            currentUser = username; // Set current user
            ui.statusLabel->setText("Login successful!");
            switchToFilesTab();
        } else {
            ui.statusLabel->setText("Incorrect username or password.");
        }
    });

    QObject::connect(ui.signupButton, &QPushButton::clicked, [&]() {
        QString username = ui.usernameEdit->text().trimmed();
        QString password = ui.passwordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            ui.statusLabel->setText("Please enter both username and password.");
            return;
        }

        if (userDatabase.find(username) != userDatabase.end()) {
            ui.statusLabel->setText("User already exists. Please login instead.");
        } else {
            userDatabase[username] = password;
            ui.statusLabel->setText("Signup successful! You can now login with your credentials.");
            
            // Clear the input fields after successful signup
            ui.usernameEdit->clear();
            ui.passwordEdit->clear();
        }
    });

    QObject::connect(ui.uploadButton, &QPushButton::clicked, [&]() {
        QString fileName = QFileDialog::getOpenFileName(ui.window, "Select File to Upload");
        // if (!fileName.isEmpty()) {
        //     fileManager.processFile(fileName, [&](const QString& path) {
        //         ui.fileList->addItem(path);
        //         QMessageBox::information(ui.window, "Uploaded", "File uploaded: " + path);
        //     });
        // }
    });

    QObject::connect(ui.shareButton, &QPushButton::clicked, [&]() {
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Share", "Please select a file to share.");
            return;
        }

        QString itemText = selectedItem->text();
        if (itemText == "Owned Files:" || itemText == "Shared With You:") {
            return;
        }

        bool ok;
        QString username = QInputDialog::getText(ui.window, "Share File",
                                               "Enter username to share with:", QLineEdit::Normal,
                                               "", &ok);
        // if (ok && !username.isEmpty()) {
        //     auto operation = fileManager.createOperation(itemText);
        //     if (operation->shareWith(username)) {
        //         QMessageBox::information(ui.window, "Shared", "File shared with " + username);
        //     } else {
        //         QMessageBox::warning(ui.window, "Share Failed", "Could not share file with " + username);
        //     }
        // }
    });

    QObject::connect(ui.revokeButton, &QPushButton::clicked, [&]() {
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Revoke", "Please select a file.");
            return;
        }

        QString itemText = selectedItem->text();
        if (itemText == "Owned Files:" || itemText == "Shared With You:") {
            return;
        }

        bool ok;
        QString username = QInputDialog::getText(ui.window, "Revoke Access",
                                               "Enter username to revoke access from:", QLineEdit::Normal,
                                               "", &ok);
        // if (ok && !username.isEmpty()) {
        //     auto operation = fileManager.createOperation(itemText);
        //     if (operation->revokeAccess(username)) {
        //         QMessageBox::information(ui.window, "Revoked", "Access revoked from " + username);
        //     } else {
        //         QMessageBox::warning(ui.window, "Revoke Failed", "Could not revoke access from " + username);
        //     }
        // }
    });

    QObject::connect(ui.deleteButton, &QPushButton::clicked, [&]() {
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Delete", "Please select a file.");
            return;
        }

        QString itemText = selectedItem->text();
        if (itemText == "Owned Files:" || itemText == "Shared With You:") {
            return;
        }
        //
        // fileManager.processFileWithPolicy<DefaultPolicy>(itemText);
        // delete ui.fileList->takeItem(ui.fileList->row(selectedItem));
        // QMessageBox::information(ui.window, "Deleted", "File removed.");
    });

    // Initially only show the login tab and remove the files tab
    while (ui.tabs->count() > 0) {
        ui.tabs->removeTab(0);
    }
    ui.tabs->addTab(ui.authTab, "Login");

    ui.window->show();
    return app.exec();
}