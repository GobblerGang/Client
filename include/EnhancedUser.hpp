#pragma once
#include <QString>
#include <QStringList>
#include <memory>
#include <vector>

class EnhancedUser {
private:
    QString username;
    QStringList ownedFiles;
    QStringList sharedFiles;
    std::vector<std::shared_ptr<EnhancedUser>> sharedWith; //smart pointer

public:
    // Constructor
    explicit EnhancedUser(const QString& name) : username(name) {}  // name is passed by value
    
    // Copy constructor
    EnhancedUser(const EnhancedUser& other) 
        : username(other.username)
        , ownedFiles(other.ownedFiles)
        , sharedFiles(other.sharedFiles) {
        // Deep copy of shared users
        for (const auto& user : other.sharedWith) {
            sharedWith.push_back(std::make_shared<EnhancedUser>(*user));
        }
    }
    
    // Assignment operator
    EnhancedUser& operator=(const EnhancedUser& other) {
        if (this != &other) {  // Using this pointer for self-assignment check
            username = other.username;
            ownedFiles = other.ownedFiles;
            sharedFiles = other.sharedFiles;
            sharedWith.clear();
            for (const auto& user : other.sharedWith) {
                sharedWith.push_back(std::make_shared<EnhancedUser>(*user));
            }
        }
        return *this;  // Using this pointer to return reference to current object
    }
    
    // Move constructor
    EnhancedUser(EnhancedUser&& other) noexcept
        : username(std::move(other.username))
        , ownedFiles(std::move(other.ownedFiles))
        , sharedFiles(std::move(other.sharedFiles))
        , sharedWith(std::move(other.sharedWith)) {}
    
    // Move assignment operator
    EnhancedUser& operator=(EnhancedUser&& other) noexcept {
        if (this != &other) {
            username = std::move(other.username);
            ownedFiles = std::move(other.ownedFiles);
            sharedFiles = std::move(other.sharedFiles);
            sharedWith = std::move(other.sharedWith);
        }
        return *this;
    }
    
    // Destructor
    virtual ~EnhancedUser() = default;
    
    // Member functions using this pointer
    void addFile(const QString& file) {
        this->ownedFiles.append(file);
    }
    
    void shareFile(const QString& file, std::shared_ptr<EnhancedUser> user) {
        if (this->ownedFiles.contains(file)) {
            user->sharedFiles.append(file);
            this->sharedWith.push_back(user);
        }
    }
    
    // Getters
    const QString& getUsername() const { return this->username; }
    const QStringList& getOwnedFiles() const { return this->ownedFiles; }
    const QStringList& getSharedFiles() const { return this->sharedFiles; }
}; 