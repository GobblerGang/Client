#include <QApplication>
#include <QMainWindow>
#include <QMessageBox>
#include <QFileDialog>
#include <unordered_map>
#include "include/FileOperationBase.hpp"
#include "include/TemplateFileManager.hpp"
#include "UI.cpp"

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    MainWindowUI ui;
    TemplateFileManager<UploadOperation> fileManager(ui.fileList);
    std::unordered_map<QString, QString> userDatabase;

    // Function pointer example
    auto loginHandler = [&](const QString& username) {
        fileManager.processUpload(username + "_files.txt");
    };

    QObject::connect(ui.loginButton, &QPushButton::clicked, [&]() {
        QString username = ui.usernameEdit->text().trimmed();
        QString password = ui.passwordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            ui.statusLabel->setText("Please enter both username and password.");
            return;
        }

        auto it = userDatabase.find(username);
        if (it != userDatabase.end() && it->second == password) {
            // Create a shared pointer for the user
            auto user = std::make_shared<UploadOperation>(username + "_files.txt");
            fileManager.processFile(username + "_files.txt", [&](const QString& path) {
                ui.statusLabel->setText("Login successful!");
                if (ui.tabs->count() < 2)
                    ui.tabs->addTab(ui.fileTab, "Files");
                ui.tabs->setCurrentWidget(ui.fileTab);
            });
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
            ui.statusLabel->setText("User already exists.");
        } else {
            userDatabase[username] = password;
            // Create a unique pointer for the new user
            auto user = std::make_unique<UploadOperation>(username + "_files.txt");
            fileManager.processFile(username + "_files.txt", [&](const QString& path) {
                ui.statusLabel->setText("Signup successful! You are now logged in.");
                if (ui.tabs->count() < 2)
                    ui.tabs->addTab(ui.fileTab, "Files");
                ui.tabs->setCurrentWidget(ui.fileTab);
            });
        }
    });

    QObject::connect(ui.uploadButton, &QPushButton::clicked, [&]() {
        QString fileName = QFileDialog::getOpenFileName(ui.window, "Select File to Upload");
        if (!fileName.isEmpty()) {
            // Use template method with callback
            fileManager.processFile(fileName, [&](const QString& path) {
                QMessageBox::information(ui.window, "Uploaded", "File uploaded: " + path);
            });
        }
    });

    QObject::connect(ui.deleteButton, &QPushButton::clicked, [&]() {
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Delete", "Please select a file.");
            return;
        }

        QString itemText = selectedItem->text().trimmed();
        if (itemText.startsWith("Owned Files:") || itemText.startsWith("Shared With You:")) {
            return;
        }

        // Use template method with policy
        fileManager.processFileWithPolicy<DefaultPolicy>(itemText);
        QMessageBox::information(ui.window, "Deleted", "File removed.");
    });

    ui.window->show();
    return app.exec();
}
