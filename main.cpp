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

    // Function to switch to files tab
    auto switchToFilesTab = [&]() {
        // Add the files tab if it doesn't exist
        if (ui.tabs->count() < 2) {
            ui.tabs->addTab(ui.fileTab, "Files");
        }
        ui.tabs->setCurrentIndex(1);  // Switch to files tab (index 1)
        ui.fileList->clear();
        ui.fileList->addItem("Owned Files:");
        ui.fileList->addItem("Shared With You:");
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
            ui.statusLabel->setText("User already exists.");
        } else {
            userDatabase[username] = password;
            ui.statusLabel->setText("Signup successful! You are now logged in.");
            switchToFilesTab();
        }
    });

    QObject::connect(ui.uploadButton, &QPushButton::clicked, [&]() {
        QString fileName = QFileDialog::getOpenFileName(ui.window, "Select File to Upload");
        if (!fileName.isEmpty()) {
            fileManager.processFile(fileName, [&](const QString& path) {
                ui.fileList->addItem(path);
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

        QString itemText = selectedItem->text();
        if (itemText == "Owned Files:" || itemText == "Shared With You:") {
            return;
        }

        fileManager.processFileWithPolicy<DefaultPolicy>(itemText);
        delete ui.fileList->takeItem(ui.fileList->row(selectedItem));
        QMessageBox::information(ui.window, "Deleted", "File removed.");
    });

    // Initially show only the login tab
    ui.tabs->removeTab(1);

    ui.window->show();
    return app.exec();
}
