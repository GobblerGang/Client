#ifndef UI_H
#define UI_H

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

    QWidget* loginTab;
    QWidget* signupTab;
    QWidget* fileTab;

    // Login widgets
    QLineEdit* loginUsernameEdit;
    QLineEdit* loginPasswordEdit;
    QLabel* loginStatusLabel;
    QPushButton* loginButton;
    QPushButton* importKeysButton;

    // Signup widgets
    QLineEdit* signupUsernameEdit;
    QLineEdit* signupEmailEdit;
    QLineEdit* signupPasswordEdit;
    QLabel* signupStatusLabel;
    QPushButton* signupButton;

    // File tab widgets
    QListWidget* fileList;
    QPushButton* uploadButton;
    QPushButton* downloadButton;
    QPushButton* shareButton;
    QPushButton* revokeButton;
    QPushButton* deleteButton;
    QPushButton* logoutButton;
    QPushButton* exportKeysButton;

    MainWindowUI();

private:
    void setupLoginTab();
    void setupSignupTab();
    void setupFileTab();
};

#endif // UI_H