#pragma once
#include <QListWidget>
#include <memory>
#include <unordered_map>
#include <type_traits>
#include <functional>
#include "FileOperationBase.hpp"

// Policy class for file operations
struct DefaultPolicy {
    static bool validate(const QString& path) {
        return QFile::exists(path);
    }
    
    static void preProcess(const QString& path) {
        // Default pre-processing
    }
    
    static void postProcess(const QString& path) {
        // Default post-processing
    }
};

// Template for file operation traits
template<typename T>
struct FileOperationTraits {
    static constexpr bool isFileOperation = false;
    using ResultType = void;
};

// Specialization for file operations
template<>
struct FileOperationTraits<QString> {
    static constexpr bool isFileOperation = true;
    using ResultType = bool;
};

// Template class for file manager
template<typename T, typename U = std::enable_if_t<std::is_base_of_v<FileOperationBase, T>>>
class TemplateFileManager {
private:
    std::shared_ptr<T> currentOperation;
    QListWidget* fileList;
    std::unordered_map<QString, std::shared_ptr<T>> operationHistory;

public:
    // Constructor
    explicit TemplateFileManager(QListWidget* list) : fileList(list) {}

    // Template method for processing files
    template<typename Callback>
    bool processFile(const QString& path, Callback&& callback) {
        if (QFile::exists(path)) {
            currentOperation = std::make_shared<T>(path);
            bool result = currentOperation->execute();
            if (result) {
                callback(path);
                operationHistory[path] = currentOperation;
            }
            return result;
        }
        return false;
    }

    // Template method for batch processing
    template<typename Container, typename Callback>
    void processFiles(const Container& paths, Callback&& callback) {
        for (const auto& path : paths) {
            processFile(path, callback);
        }
    }

    // Function template for file operations
    template<typename OperationType>
    bool performOperation(const QString& path) {
        auto operation = std::make_shared<OperationType>(path);
        return operation->execute();
    }

    // Template method for file operations with policy
    template<typename Policy>
    bool processFileWithPolicy(const QString& path) {
        if (Policy::validate(path)) {
            Policy::preProcess(path);
            bool result = currentOperation->execute();
            Policy::postProcess(path);
            return result;
        }
        return false;
    }

    // Template method for creating file operations
    template<typename... Args>
    std::shared_ptr<T> createOperation(Args&&... args) {
        return std::make_shared<T>(std::forward<Args>(args)...);
    }

    // Template method for file operations with result type
    template<typename ResultType>
    ResultType getOperationResult(const QString& path) {
        if (auto it = operationHistory.find(path); it != operationHistory.end()) {
            if constexpr (std::is_same_v<ResultType, bool>) {
                return it->second->execute();
            } else if constexpr (std::is_same_v<ResultType, QString>) {
                return it->second->getFilePath();
            }
        }
        return ResultType();
    }
};

// Specialized template for UploadOperation
template<>
class TemplateFileManager<UploadOperation> {
private:
    std::shared_ptr<UploadOperation> currentOperation;
    QListWidget* fileList;

public:
    explicit TemplateFileManager(QListWidget* list) : fileList(list) {}

    bool processUpload(const QString& path) {
        currentOperation = std::make_shared<UploadOperation>(path);
        if (currentOperation->execute()) {
            fileList->addItem("Uploaded: " + path);
            return true;
        }
        return false;
    }

    // Add the missing methods to match the base template
    template<typename Callback>
    bool processFile(const QString& path, Callback&& callback) {
        return processUpload(path);
    }

    template<typename Policy>
    bool processFileWithPolicy(const QString& path) {
        if (Policy::validate(path)) {
            Policy::preProcess(path);
            bool result = processUpload(path);
            Policy::postProcess(path);
            return result;
        }
        return false;
    }
}; 