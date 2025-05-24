#include <QApplication>
#include <QMessageBox>
#include <unordered_map>
#include "model.cpp"
#include "ui.cpp"
//test
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);

    MainWindowUI ui;
    FileManager fileManager(ui.fileList);
    unordered_map<QString, QString> userDatabase;

    QObject::connect(ui.loginButton, &QPushButton::clicked, [&]() {
        QString username = ui.usernameEdit->text().trimmed();
        QString password = ui.passwordEdit->text().trimmed();

        if (username.isEmpty() || password.isEmpty()) {
            ui.statusLabel->setText("Please enter both username and password.");
            return;
        }

        auto it = userDatabase.find(username);
        if (it != userDatabase.end() && it->second == password) {
            fileManager.setUser(make_unique<User>(username));
            fileManager.refreshFileList();
            ui.statusLabel->setText("Login successful!");
            if (ui.tabs->count() < 2)
                ui.tabs->addTab(ui.fileTab, "Files");
            ui.tabs->setCurrentWidget(ui.fileTab);
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
            fileManager.setUser(make_unique<User>(username));
            fileManager.refreshFileList();
            ui.statusLabel->setText("Signup successful! You are now logged in.");
            if (ui.tabs->count() < 2)
                ui.tabs->addTab(ui.fileTab, "Files");
            ui.tabs->setCurrentWidget(ui.fileTab);
        }
    });

    QObject::connect(ui.uploadButton, &QPushButton::clicked, [&]() {
        UploadOperation op(ui.window, fileManager.getCurrentUser(), ui.fileList);
        op.execute();
        fileManager.refreshFileList();
    });

    QObject::connect(ui.deleteButton, &QPushButton::clicked, [&]() {
        User* user = fileManager.getCurrentUser();
        QListWidgetItem* selectedItem = ui.fileList->currentItem();
        if (!selectedItem) {
            QMessageBox::warning(ui.window, "Delete", "Please select a file.");
            return;
        }

        QString itemText = selectedItem->text().trimmed();
        if (itemText.startsWith("Owned Files:") || itemText.startsWith("Shared With You:")) {
            return;
        }

        bool success = false;
        user->removeFile(itemText, success);
        if (success) {
            QMessageBox::information(ui.window, "Deleted", "File removed.");
        } else {
            QMessageBox::warning(ui.window, "Failed", "You can only delete owned files.");
        }
        fileManager.refreshFileList();
    });

    ui.window->show();
    return app.exec();
}
