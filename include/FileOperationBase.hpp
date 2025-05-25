#pragma once
#include <QString>
#include <QFile>
#include <QFileInfo>
#include <memory>
#include <vector>
#include <functional>

// Forward declarations
class QFile;
class QListWidget;

// Callback type for file operations
using OperationCallback = std::function<void(const QString&)>;

// Abstract base class with pure virtual functions
class FileOperationBase {
protected:
    QString filePath;
    std::vector<QString> operationHistory;
    OperationCallback callback;

public:
    // Constructors
    FileOperationBase() = default;
    explicit FileOperationBase(const QString& path) : filePath(path) {}
    
    // Virtual destructor
    virtual ~FileOperationBase() = default;
    
    // Pure virtual functions
    virtual bool execute() = 0;
    virtual bool validate() const = 0;
    
    // Virtual functions that can be overridden
    virtual void preProcess() {}
    virtual void postProcess() {}
    
    // Operator overloading
    bool operator==(const FileOperationBase& other) const {
        return this->filePath == other.filePath;
    }
    
    bool operator!=(const FileOperationBase& other) const {
        return !(*this == other);
    }
    
    // Function overloading
    void addToHistory(const QString& operation) {
        operationHistory.push_back(operation);
    }
    
    void addToHistory(const QString& operation, const QString& details) {
        operationHistory.push_back(operation + ": " + details);
    }
    
    // Inline function with default arguments
    inline QString getFilePath(bool includeFullPath = false) const {
        return includeFullPath ? QFileInfo(filePath).absoluteFilePath() : filePath;
    }
    
    // Function that returns a function pointer
    virtual OperationCallback getCallback() { return callback; }

    // Getters
    QString getFilePath() const { return filePath; }
    void setCallback(OperationCallback cb) { callback = std::move(cb); }
};

// Derived class for upload operations
class UploadOperation : public FileOperationBase {
private:
    std::unique_ptr<QFile> fileHandle;
    size_t fileSize;

public:
    // Constructor with initialization list
    explicit UploadOperation(const QString& path) 
        : FileOperationBase(path), fileSize(0) {
        fileHandle = std::make_unique<QFile>(path);
    }
    
    // Copy constructor
    UploadOperation(const UploadOperation& other)
        : FileOperationBase(other.filePath), fileSize(other.fileSize) {
        if (other.fileHandle) {
            fileHandle = std::make_unique<QFile>(other.filePath);
        }
    }
    
    // Move constructor
    UploadOperation(UploadOperation&& other) noexcept
        : FileOperationBase(std::move(other.filePath))
        , fileHandle(std::move(other.fileHandle))
        , fileSize(other.fileSize) {
        other.fileSize = 0;
    }
    
    // Assignment operator
    UploadOperation& operator=(const UploadOperation& other) {
        if (this != &other) {
            filePath = other.filePath;
            fileSize = other.fileSize;
            if (other.fileHandle) {
                fileHandle = std::make_unique<QFile>(other.filePath);
            }
        }
        return *this;
    }
    
    // Move assignment operator
    UploadOperation& operator=(UploadOperation&& other) noexcept {
        if (this != &other) {
            filePath = std::move(other.filePath);
            fileHandle = std::move(other.fileHandle);
            fileSize = other.fileSize;
            other.fileSize = 0;
        }
        return *this;
    }
    
    // Override virtual functions
    bool execute() override {
        if (!validate()) return false;
        
        preProcess();
        bool success = fileHandle->open(QIODevice::ReadOnly);
        if (success) {
            fileSize = fileHandle->size();
            fileHandle->close();
            postProcess();
        }
        return success;
    }
    
    bool validate() const override {
        return QFile::exists(filePath);
    }
    
    void preProcess() override {
        addToHistory("Upload", "Starting upload process");
    }
    
    void postProcess() override {
        addToHistory("Upload", "Completed upload of " + QString::number(fileSize) + " bytes");
    }
    
    // Override callback function
    OperationCallback getCallback() override {
        return [this](const QString& path) {
            this->filePath = path;
            this->execute();
        };
    }
    
    // Pointer arithmetic example
    void processFileChunks() {
        if (!fileHandle || !fileHandle->isOpen()) return;
        
        const int chunkSize = 1024;
        char* buffer = new char[chunkSize];
        char* currentPos = buffer;
        
        while (!fileHandle->atEnd()) {
            qint64 bytesRead = fileHandle->read(currentPos, chunkSize);
            if (bytesRead <= 0) break;
            
            // Process chunk
            processChunk(currentPos, bytesRead);
            
            // Move pointer to next chunk
            currentPos += bytesRead;
        }
        
        delete[] buffer;
    }
    
private:
    void processChunk(char* data, qint64 size) {
        // Process file chunk
        for (qint64 i = 0; i < size; ++i) {
            // Example: Convert to uppercase
            if (data[i] >= 'a' && data[i] <= 'z') {
                data[i] = data[i] - 'a' + 'A';
            }
        }
    }
}; 