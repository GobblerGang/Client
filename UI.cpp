#include <QVBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QTabWidget>
#include <QWidget>

class MainWindowUI {
public:
    QWidget* window;
    QTabWidget* tabs;
    QWidget* authTab;
    QWidget* fileTab;

    QLineEdit* usernameEdit;
    QLineEdit* passwordEdit;
    QLabel* statusLabel;
    QPushButton* loginButton;
    QPushButton* signupButton;

    QListWidget* fileList;
    QPushButton* uploadButton;
    QPushButton* downloadButton;
    QPushButton* shareButton;
    QPushButton* revokeButton;
    QPushButton* deleteButton;

    MainWindowUI() {
        window = new QWidget();
        window->setWindowTitle("GG File Sharing");
        window->resize(700, 400);

        tabs = new QTabWidget();
        tabs->setTabPosition(QTabWidget::North);

        // Auth Tab
        authTab = new QWidget();
        QVBoxLayout* authLayout = new QVBoxLayout();
        authLayout->setAlignment(Qt::AlignCenter);

        usernameEdit = new QLineEdit();
        usernameEdit->setPlaceholderText("Username");

        passwordEdit = new QLineEdit();
        passwordEdit->setPlaceholderText("Password");
        passwordEdit->setEchoMode(QLineEdit::Password);

        loginButton = new QPushButton("Login");
        signupButton = new QPushButton("Sign Up");

        statusLabel = new QLabel;

        authLayout->addWidget(new QLabel("Login / Signup"));
        authLayout->addWidget(usernameEdit);
        authLayout->addWidget(passwordEdit);
        authLayout->addWidget(loginButton);
        authLayout->addWidget(signupButton);
        authLayout->addWidget(statusLabel);
        authTab->setLayout(authLayout);

        // File Tab
        fileTab = new QWidget();
        QVBoxLayout* fileLayout = new QVBoxLayout();

        fileList = new QListWidget();
        uploadButton = new QPushButton("Upload");
        downloadButton = new QPushButton("Download");
        shareButton = new QPushButton("Share");
        revokeButton = new QPushButton("Revoke Access");
        deleteButton = new QPushButton("Delete");

        QHBoxLayout* buttonsLayout = new QHBoxLayout();
        buttonsLayout->addWidget(uploadButton);
        buttonsLayout->addWidget(downloadButton);
        buttonsLayout->addWidget(shareButton);
        buttonsLayout->addWidget(revokeButton);
        buttonsLayout->addWidget(deleteButton);

        fileLayout->addWidget(new QLabel("Your Files:"));
        fileLayout->addWidget(fileList);
        fileLayout->addLayout(buttonsLayout);
        fileTab->setLayout(fileLayout);

        QVBoxLayout* mainLayout = new QVBoxLayout();
        mainLayout->addWidget(tabs);
        window->setLayout(mainLayout);

        tabs->addTab(authTab, "Login");
    }
};
