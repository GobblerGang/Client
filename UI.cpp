#include "ui.h"

MainWindowUI::MainWindowUI() {
    window = new QWidget();
    window->setWindowTitle("GG File Sharing");
    window->resize(700, 450);
    window->setStyleSheet("background-color: #000000; color: #ffffff;");

    tabs = new QTabWidget();
    tabs->setTabPosition(QTabWidget::North);
    tabs->setStyleSheet(
        "QTabBar::tab { height: 30px; width: 120px; font-weight: bold; }"
        "QTabBar::tab:selected { background: #4A90E2; color: white; border-radius: 5px; }"
        "QTabBar::tab:!selected { background: #d0d0d0; border-radius: 5px; }"
    );

    setupLoginTab();
    setupSignupTab();
    setupFileTab();

    QVBoxLayout* mainLayout = new QVBoxLayout();
    mainLayout->addWidget(tabs);
    window->setLayout(mainLayout);

    tabs->addTab(loginTab, "Login");
    tabs->addTab(signupTab, "Sign Up");
    tabs->addTab(fileTab, "Files");
}

void MainWindowUI::setupLoginTab() {
    loginTab = new QWidget();
    QVBoxLayout* loginLayout = new QVBoxLayout(loginTab);
    loginLayout->setContentsMargins(40, 30, 40, 30);
    loginLayout->setSpacing(15);
    loginLayout->setAlignment(Qt::AlignTop | Qt::AlignHCenter);

    QLabel* loginTitle = new QLabel("Login");
    QFont titleFont;
    titleFont.setPointSize(18);
    titleFont.setBold(true);
    loginTitle->setFont(titleFont);
    loginTitle->setAlignment(Qt::AlignCenter);
    loginLayout->addWidget(loginTitle);

    QFormLayout* loginForm = new QFormLayout();
    loginForm->setLabelAlignment(Qt::AlignRight);
    loginForm->setFormAlignment(Qt::AlignCenter);
    loginForm->setHorizontalSpacing(15);
    loginForm->setVerticalSpacing(10);

    loginUsernameEdit = new QLineEdit();
    loginUsernameEdit->setPlaceholderText("Enter your username");
    loginUsernameEdit->setFixedWidth(250);

    loginPasswordEdit = new QLineEdit();
    loginPasswordEdit->setPlaceholderText("Enter your password");
    loginPasswordEdit->setEchoMode(QLineEdit::Password);
    loginPasswordEdit->setFixedWidth(250);

    loginForm->addRow("Username:", loginUsernameEdit);
    loginForm->addRow("Password:", loginPasswordEdit);
    loginLayout->addLayout(loginForm);

    loginButton = new QPushButton("Login");
    loginButton->setFixedSize(110, 35);
    loginButton->setStyleSheet(
        "QPushButton { background-color: #4A90E2; color: white; border-radius: 6px; font-weight: bold; }"
        "QPushButton:hover { background-color: #357ABD; }"
        "QPushButton:pressed { background-color: #2C5C9A; }"
    );
    loginLayout->addWidget(loginButton, 0, Qt::AlignCenter);

    importKeysButton = new QPushButton("Import Keys");
    importKeysButton->setFixedSize(110, 35);
    importKeysButton->setStyleSheet(
        "QPushButton { background-color: #7B8D93; color: white; border-radius: 6px; font-weight: bold; }"
        "QPushButton:hover { background-color: #5C6C71; }"
        "QPushButton:pressed { background-color: #445056; }"
    );
    loginLayout->addWidget(importKeysButton, 0, Qt::AlignCenter);


    loginStatusLabel = new QLabel;
    loginStatusLabel->setAlignment(Qt::AlignCenter);
    loginStatusLabel->setStyleSheet("color: red; font-weight: bold;");
    loginLayout->addWidget(loginStatusLabel);
}

void MainWindowUI::setupSignupTab() {
    signupTab = new QWidget();
    QVBoxLayout* signupLayout = new QVBoxLayout(signupTab);
    signupLayout->setContentsMargins(40, 30, 40, 30);
    signupLayout->setSpacing(15);
    signupLayout->setAlignment(Qt::AlignTop | Qt::AlignHCenter);

    QLabel* signupTitle = new QLabel("Sign Up");
    QFont titleFont;
    titleFont.setPointSize(18);
    titleFont.setBold(true);
    signupTitle->setFont(titleFont);
    signupTitle->setAlignment(Qt::AlignCenter);
    signupLayout->addWidget(signupTitle);

    QFormLayout* signupForm = new QFormLayout();
    signupForm->setLabelAlignment(Qt::AlignRight);
    signupForm->setFormAlignment(Qt::AlignCenter);
    signupForm->setHorizontalSpacing(15);
    signupForm->setVerticalSpacing(10);

    signupUsernameEdit = new QLineEdit();
    signupUsernameEdit->setPlaceholderText("Choose a username");
    signupUsernameEdit->setFixedWidth(250);

    signupEmailEdit = new QLineEdit();
    signupEmailEdit->setPlaceholderText("Enter your email address");
    signupEmailEdit->setFixedWidth(250);

    signupPasswordEdit = new QLineEdit();
    signupPasswordEdit->setPlaceholderText("Create a password");
    signupPasswordEdit->setEchoMode(QLineEdit::Password);
    signupPasswordEdit->setFixedWidth(250);

    signupForm->addRow("Username:", signupUsernameEdit);
    signupForm->addRow("Email:", signupEmailEdit);
    signupForm->addRow("Password:", signupPasswordEdit);
    signupLayout->addLayout(signupForm);

    signupButton = new QPushButton("Sign Up");
    signupButton->setFixedSize(110, 35);
    signupButton->setStyleSheet(
        "QPushButton { background-color: #7B8D93; color: white; border-radius: 6px; font-weight: bold; }"
        "QPushButton:hover { background-color: #5C6C71; }"
        "QPushButton:pressed { background-color: #445056; }"
    );
    signupLayout->addWidget(signupButton, 0, Qt::AlignCenter);

    signupStatusLabel = new QLabel;
    signupStatusLabel->setAlignment(Qt::AlignCenter);
    signupStatusLabel->setStyleSheet("color: red; font-weight: bold;");
    signupLayout->addWidget(signupStatusLabel);
}

void MainWindowUI::setupFileTab() {
    fileTab = new QWidget();
    QVBoxLayout* fileLayout = new QVBoxLayout(fileTab);
    fileLayout->setContentsMargins(30, 20, 30, 20);
    fileLayout->setSpacing(15);

    QLabel* filesLabel = new QLabel("Your Files:");
    QFont filesFont;
    filesFont.setPointSize(14);
    filesFont.setBold(true);
    filesLabel->setFont(filesFont);
    fileLayout->addWidget(filesLabel);

    fileList = new QListWidget();
    fileList->setStyleSheet(
        "QListWidget { background-color: white; border: 1px solid #ccc; border-radius: 6px; color: black; }"
        "QListWidget::item:selected { background-color: #4A90E2; color: black; }"
    );
    fileLayout->addWidget(fileList);

    QHBoxLayout* buttonsLayout = new QHBoxLayout();
    buttonsLayout->setSpacing(15);

    //new keyword (heap allocation)
    uploadButton = new QPushButton("Upload");
    downloadButton = new QPushButton("Download");
    shareButton = new QPushButton("Share");
    revokeButton = new QPushButton("Revoke Access");
    deleteButton = new QPushButton("Delete");
    exportKeysButton = new QPushButton("Export Keys");

    QPushButton* fileButtons[] = {uploadButton, downloadButton, shareButton, revokeButton, deleteButton, exportKeysButton};
    // Pointer Arithmetic
    for (QPushButton** btn = fileButtons; btn < fileButtons + 6; ++btn) {
        (*btn)->setFixedHeight(35);
        (*btn)->setStyleSheet(
            "QPushButton { background-color: #4A90E2; color: white; border-radius: 6px; font-weight: bold; }"
            "QPushButton:hover { background-color: #357ABD; }"
            "QPushButton:pressed { background-color: #2C5C9A; }"
        );
        buttonsLayout->addWidget(*btn);
    }

    fileLayout->addLayout(buttonsLayout);

    QHBoxLayout* logoutLayout = new QHBoxLayout();
    logoutLayout->setContentsMargins(0, 10, 0, 0);
    logoutLayout->addStretch();

    logoutButton = new QPushButton("Logout");
    logoutButton->setFixedSize(110, 35);
    logoutButton->setStyleSheet(
        "QPushButton { background-color: #E74C3C; color: white; border-radius: 6px; font-weight: bold; }"
        "QPushButton:hover { background-color: #C0392B; }"
        "QPushButton:pressed { background-color: #A93226; }"
    );
    logoutLayout->addWidget(logoutButton);
    fileLayout->addLayout(logoutLayout);
}