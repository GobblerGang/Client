#pragma once
#include <QString>
#include <QFile>
#include <QFileInfo>
#include <memory>
#include <functional>

// Template class for file operations
template<typename T>
class FileOperationTemplate {
public:
    virtual T execute() = 0;
    virtual ~FileOperationTemplate() = default;
};

// Function overloading examples
class FileOperations {
public:
    // Overloaded functions for different file operations
    static bool processFile(const QString& path) {
        return QFile::exists(path);
    }
    
    static bool processFile(const QString& path, std::function<void(const QString&)> callback) {
        if (QFile::exists(path)) {
            callback(path);
            return true;
        }
        return false;
    }
    
    // Inline function with default arguments
    inline static QString getFileExtension(const QString& path, bool includeDot = true) {
        QFileInfo info(path);
        QString ext = info.suffix();
        return includeDot ? "." + ext : ext;
    }
};

// Function pointer type definition
using FileOperationCallback = std::function<void(const QString&)>;

// Function that returns a function pointer
FileOperationCallback getFileOperationHandler(const QString& operationType); 