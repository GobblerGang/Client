#include <fstream>
#include <QApplication>
#include <QMessageBox>
#include <QFileDialog>
#include <QInputDialog>

#include "Server.h"
#include "ui.h"
#include "UserManager.h"
#include "database/db_instance.h"
#include "src/Auth.h"
#include "src/models/UserModel.h"
#include <QMimeDatabase>
#include <QFileInfo>
#include <QFile>
#include "FileManager.h"

class ApplicationController {
public:
    ApplicationController(MainWindowUI& ui, UserManager* userManager, FileManager* fileManager)
        : ui(ui), userManager(userManager), fileManager(fileManager) {
        setupConnections();
    }

    void run() {
        switchToAuthTabs();
        ui.window->show();
    }

private:
    MainWindowUI& ui;
    UserManager* userManager;
    FileManager* fileManager;
    QString currentUser;

    // using HandlerType = void (ApplicationController::*)(bool);

    void connectButton(QPushButton* button, void (ApplicationController::*handler)(bool)  ) {
        QObject::connect(button, &QPushButton::clicked,
            [this, handler](bool checked) {
                (this->*handler)(checked);
            });
    }

    void setupConnections() {
        connectLogout();
        connectLogin();
        connectSignup();
        connectFileOperations();
    }

    void connectLogout() {
        connectButton(ui.logoutButton, &ApplicationController::handleLogout);
    }

    void handleImportKeys(bool arg) {
        QString username = ui.loginUsernameEdit->text().trimmed();
        QString password = ui.loginPasswordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            ui.loginStatusLabel->setText("Please enter both username and password before importing keys.");
            return;
        }

        QString fileName = QFileDialog::getOpenFileName(ui.window, "Import Keys", "", "JSON Files (*.json)");
        if (fileName.isEmpty()) return;

        try {
            std::ifstream in(fileName.toStdString());
            if (!in) throw std::runtime_error("Failed to open file.");

            nlohmann::json keys;
            in >> keys;
            in.close();

            userManager->import_keys(keys, password.toStdString(), username.toStdString());
            ui.loginStatusLabel->setText("Keys imported successfully. You can now log in.");
        } catch (const std::exception& e) {
            ui.loginStatusLabel->setText(QString("Import failed: ") + e.what());
        }
    };


    void connectLogin() {
        connectButton(ui.loginButton, &ApplicationController::handleLogin);
        connectButton(ui.importKeysButton, &ApplicationController::handleImportKeys);
    }

    void connectSignup() {
        connectButton(ui.signupButton, &ApplicationController::handleSignup);
    }

    void connectFileOperations() {
        connectButton(ui.uploadButton, &ApplicationController::handleUpload);
        connectButton(ui.downloadButton, &ApplicationController::handleDownload);
        connectButton(ui.shareButton, &ApplicationController::handleShare);
        connectButton(ui.revokeButton, &ApplicationController::handleRevoke);
        connectButton(ui.deleteButton, &ApplicationController::handleDelete);
        connectButton(ui.exportKeysButton, &ApplicationController::handleExportKeys);
    }


    void handleDownload(bool) {
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Download", "Please select a file to download.");
            return;
        }

        QString itemText = selectedItem->text();
        if (itemText == "Owned Files:" || itemText == "Shared With You:") return;

        QString fileUuid = selectedItem->data(Qt::UserRole).toString();
        if (fileUuid.isEmpty()) {
            QMessageBox::warning(ui.window, "Download", "Invalid file selection.");
            return;
        }

        // Find the PAC for this file_uuid in received_pacs
        const auto& received_pacs = fileManager->getReceivedPacs();
        auto it = std::find_if(received_pacs.begin(), received_pacs.end(),
            [&](const PAC& pac) { return pac.file_uuid == fileUuid.toStdString(); });

        if (it == received_pacs.end()) {
            QMessageBox::warning(ui.window, "Download", "No access PAC found for this file.");
            return;
        }

        try {
            // Download the file
            std::vector<uint8_t> fileData = fileManager->downloadFile(*it, userManager->getUser());

            // Ask user where to save
            QString savePath = QFileDialog::getSaveFileName(ui.window, "Save File", QString::fromStdString(it->filename));
            if (savePath.isEmpty()) return;

            QFile outFile(savePath);
            if (!outFile.open(QIODevice::WriteOnly)) {
                QMessageBox::critical(ui.window, "Error", "Could not open file for writing.");
                return;
            }
            outFile.write(reinterpret_cast<const char*>(fileData.data()), fileData.size());
            outFile.close();

            QMessageBox::information(ui.window, "Download", "File downloaded successfully.");
        } catch (const std::exception& e) {
            QMessageBox::critical(ui.window, "Download Error", e.what());
        }
    }

    void handleLogout(bool) {
        QMessageBox::StandardButton reply = QMessageBox::question(
            ui.window,
            "Logout Confirmation",
            "Are you sure you want to logout?",
            QMessageBox::Yes | QMessageBox::No
        );
        if (reply == QMessageBox::Yes) {
            switchToAuthTabs();
        }
    }

    void handleLogin(bool) {
        QString username = ui.loginUsernameEdit->text().trimmed();
        QString password = ui.loginPasswordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            ui.loginStatusLabel->setText("Please enter both username and password.");
            return;
        }

        try {
            if (userManager->login(username.toStdString(), password.toStdString())) {
                currentUser = username;
                ui.loginStatusLabel->setText("Login successful!");
                switchToFilesTab();
            } else {
                ui.loginStatusLabel->setText("Login failed. Please try again.");
            }
        } catch (const std::exception& e) {
            ui.loginStatusLabel->setText(QString::fromStdString(e.what()));
        }
    }

    void handleSignup(bool) {
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

            if (!userManager->signup(username.toStdString(), email.toStdString(), password.toStdString())) {
                ui.signupStatusLabel->setText("Signup failed. Please try again.");
                return;
            }

            ui.signupStatusLabel->setText("Signup successful! You can now log in.");
            ui.signupUsernameEdit->clear();
            ui.signupPasswordEdit->clear();
            ui.signupEmailEdit->clear();
        } catch (const std::exception& e) {
            ui.signupStatusLabel->setText("Signup error: " + QString(e.what()));
        }
    }
    void handleExportKeys(bool) {
        try {
            const nlohmann::json keys = userManager->export_keys();
            const QString fileName = QFileDialog::getSaveFileName(ui.window, "Export Keys", "", "JSON Files (*.json)");
            if (fileName.isEmpty()) return;

            std::ofstream out(fileName.toStdString());
            out << keys.dump(4);
            out.close();

            QMessageBox::information(ui.window, "Export Successful", "Keys exported successfully.");
        } catch (const std::exception& e) {
            QMessageBox::critical(ui.window, "Export Failed", e.what());
        }
    }

    void handleUpload(bool) {
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
    }

    void handleShare(bool) {
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
    }

    void handleRevoke(bool) {
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
    }

    void handleDelete(bool) {
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Delete", "Please select a file.");
            return;
        }

        QString itemText = selectedItem->text();
        if (itemText == "Owned Files:" || itemText == "Shared With You:") return;

        // Delete logic
    }

    void loadFiles() const {
        try {
            fileManager->refreshFiles();
            const auto& files = fileManager->getFiles();
            const auto& received_pacs = fileManager->getReceivedPacs();
            const auto& issued_pacs = fileManager->getIssuedPacs();
            ui.fileList->clear();
            ui.fileList->addItem("Owned Files:");
            for (const auto& file : files) {
                std::vector<std::string> sharedWith;
                for (const auto& pac : issued_pacs) {
                    if (pac.file_uuid == file.file_uuid) {
                        sharedWith.push_back(pac.recipient_username); // or pac.recipient_uuid
                    }
                }
                // Display file info and sharedWith list
                QString info = QString("%1\nMIME: %2\nShared with: %3")
                    .arg(QString::fromStdString(file.file_name))
                    .arg(QString::fromStdString(file.mime_type))
                    .arg(QString::fromStdString(
                        sharedWith.empty() ? "None" :
                        std::accumulate(std::next(sharedWith.begin()), sharedWith.end(), sharedWith[0],
                            [](std::string a, std::string b) { return a + ", " + b; })
                    ));
                    QListWidgetItem* item = new QListWidgetItem(info);
                    item->setData(Qt::UserRole, QString::fromStdString(file.file_uuid));
                    ui.fileList->addItem(item);
            }
            ui.fileList->addItem("Shared With You:");
            for (const auto& pac : received_pacs) {

                    QString info = QString("%1\n %2\nOwner: %3")
                        .arg(QString::fromStdString(pac.filename))
                        .arg(QString::fromStdString(pac.mime_type))
                        .arg(QString::fromStdString(pac.issuer_username));
                    QListWidgetItem* item = new QListWidgetItem(info);
                    item->setData(Qt::UserRole, QString::fromStdString(pac.file_uuid));
                    ui.fileList->addItem(item);

            }
        }
        catch (const std::exception& e) {
            QMessageBox::critical(ui.window, "Error", QString("Failed to load files: %1").arg(e.what()));
        }
    }

    void switchToAuthTabs() {
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
    }

    void switchToFilesTab() {
        while (ui.tabs->count() > 0) {
            ui.tabs->removeTab(0);
        }

        ui.tabs->addTab(ui.fileTab, "Files");

        ui.fileList->clear();
        ui.fileList->addItem("Owned Files:");
        ui.fileList->addItem("Shared With You:");

        ui.window->setWindowTitle("GG File Sharing - " + currentUser);
        loadFiles();
    }
};


int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    Server& server = Server::instance();
    if (!server.get_index()) {
        QMessageBox::critical(nullptr, "Server Error",
            "Failed to connect to the server. Please check your network connection or server status.");
        return 1;
    }



    UserManager* userManager = new UserManager();
    FileManager* fileManager = new FileManager(userManager);
    MainWindowUI ui;
    ApplicationController controller(ui, userManager, fileManager);

    controller.run();
    return app.exec();
}