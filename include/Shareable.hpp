#pragma once
#include <QString>
#include <vector>
#include <memory>

// Interface for shareable objects
class Shareable {
public:
    virtual ~Shareable() = default;
    
    // Pure virtual functions for sharing functionality
    virtual bool shareWith(const QString& username) = 0;
    virtual bool revokeAccess(const QString& username) = 0;
    virtual std::vector<QString> getSharedWith() const = 0;
    virtual bool isSharedWith(const QString& username) const = 0;
    
protected:
    std::vector<QString> sharedWithUsers;
}; 