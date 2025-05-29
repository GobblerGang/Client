#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QTabWidget>
#include <QWidget>
#include <QFont>
#include <QSpacerItem>

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
    QPushButton* logoutButton; // New logout button

    MainWindowUI() {
        window = new QWidget();
        window->setWindowTitle("GG File Sharing");
        window->resize(700, 450);
        window->setStyleSheet("background-color: #f9f9f9;");

        tabs = new QTabWidget();
        tabs->setTabPosition(QTabWidget::North);
        tabs->setStyleSheet(
                "QTabBar::tab { height: 30px; width: 120px; font-weight: bold; }"
                "QTabBar::tab:selected { background: #4A90E2; color: white; border-radius: 5px; }"
                "QTabBar::tab:!selected { background: #d0d0d0; border-radius: 5px; }"
        );

        // Auth Tab
        authTab = new QWidget();
        QVBoxLayout* authMainLayout = new QVBoxLayout(authTab);
        authMainLayout->setContentsMargins(40, 30, 40, 30);
        authMainLayout->setSpacing(15);
        authMainLayout->setAlignment(Qt::AlignTop | Qt::AlignHCenter);

        QLabel* titleLabel = new QLabel("Login / Signup");
        QFont titleFont;
        titleFont.setPointSize(18);
        titleFont.setBold(true);
        titleLabel->setFont(titleFont);
        titleLabel->setAlignment(Qt::AlignCenter);
        authMainLayout->addWidget(titleLabel);

        QFormLayout* formLayout = new QFormLayout();
        formLayout->setLabelAlignment(Qt::AlignRight);
        formLayout->setFormAlignment(Qt::AlignCenter);
        formLayout->setHorizontalSpacing(15);
        formLayout->setVerticalSpacing(10);

        usernameEdit = new QLineEdit();
        usernameEdit->setPlaceholderText("Enter your username");
        usernameEdit->setFixedWidth(250);

        passwordEdit = new QLineEdit();
        passwordEdit->setPlaceholderText("Enter your password");
        passwordEdit->setEchoMode(QLineEdit::Password);
        passwordEdit->setFixedWidth(250);

        formLayout->addRow("Username:", usernameEdit);
        formLayout->addRow("Password:", passwordEdit);

        authMainLayout->addLayout(formLayout);

        // Buttons horizontally spaced
        QHBoxLayout* authButtonsLayout = new QHBoxLayout();
        authButtonsLayout->setSpacing(30);
        authButtonsLayout->setAlignment(Qt::AlignCenter);

        loginButton = new QPushButton("Login");
        signupButton = new QPushButton("Sign Up");

        loginButton->setFixedSize(110, 35);
        signupButton->setFixedSize(110, 35);

        loginButton->setStyleSheet(
                "QPushButton { background-color: #4A90E2; color: white; border-radius: 6px; font-weight: bold; }"
                "QPushButton:hover { background-color: #357ABD; }"
                "QPushButton:pressed { background-color: #2C5C9A; }"
        );

        signupButton->setStyleSheet(
                "QPushButton { background-color: #7B8D93; color: white; border-radius: 6px; font-weight: bold; }"
                "QPushButton:hover { background-color: #5C6C71; }"
                "QPushButton:pressed { background-color: #445056; }"
        );

        authButtonsLayout->addWidget(loginButton);
        authButtonsLayout->addWidget(signupButton);

        authMainLayout->addLayout(authButtonsLayout);

        statusLabel = new QLabel;
        statusLabel->setAlignment(Qt::AlignCenter);
        statusLabel->setStyleSheet("color: red; font-weight: bold;");
        authMainLayout->addWidget(statusLabel);

        // File Tab
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
                "QListWidget { background-color: white; border: 1px solid #ccc; border-radius: 6px; }"
                "QListWidget::item:selected { background-color: #4A90E2; color: white; }"
        );
        fileLayout->addWidget(fileList);

        // Add a horizontal layout for the file operation buttons
        QHBoxLayout* buttonsLayout = new QHBoxLayout();
        buttonsLayout->setSpacing(15);

        uploadButton = new QPushButton("Upload");
        downloadButton = new QPushButton("Download");
        shareButton = new QPushButton("Share");
        revokeButton = new QPushButton("Revoke Access");
        deleteButton = new QPushButton("Delete");

        QList<QPushButton*> fileButtons = {uploadButton, downloadButton, shareButton, revokeButton, deleteButton};
        for (QPushButton* btn : fileButtons) {
            btn->setFixedHeight(35);
            btn->setStyleSheet(
                    "QPushButton { background-color: #4A90E2; color: white; border-radius: 6px; font-weight: bold; }"
                    "QPushButton:hover { background-color: #357ABD; }"
                    "QPushButton:pressed { background-color: #2C5C9A; }"
            );
            buttonsLayout->addWidget(btn);
        }

        fileLayout->addLayout(buttonsLayout);
        
        // Add logout button in a separate horizontal layout
        QHBoxLayout* logoutLayout = new QHBoxLayout();
        logoutLayout->setContentsMargins(0, 10, 0, 0);
        
        // Add a spacer to push the logout button to the right
        logoutLayout->addStretch();
        
        // Create logout button
        logoutButton = new QPushButton("Logout");
        logoutButton->setFixedSize(110, 35);
        logoutButton->setStyleSheet(
            "QPushButton { background-color: #E74C3C; color: white; border-radius: 6px; font-weight: bold; }"
            "QPushButton:hover { background-color: #C0392B; }"
            "QPushButton:pressed { background-color: #A93226; }"
        );
        
        logoutLayout->addWidget(logoutButton);
        fileLayout->addLayout(logoutLayout);

        QVBoxLayout* mainLayout = new QVBoxLayout();
        mainLayout->addWidget(tabs);
        window->setLayout(mainLayout);

        tabs->addTab(authTab, "Login");
        tabs->addTab(fileTab, "Files");
    }
};