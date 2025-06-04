#pragma once
#include <QString>
#include <QFileInfo>
#include <type_traits>
#include <memory>

namespace FileHandlers {

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

// Generic file operation handler
template<typename T, typename = std::enable_if_t<FileOperationTraits<T>::isFileOperation>>
class GenericFileHandler {
public:
    using ResultType = typename FileOperationTraits<T>::ResultType;

    // Template method for processing files
    template<typename Callback>
    static ResultType processFile(const T& path, Callback&& callback) {
        if (QFile::exists(path)) {
            return callback(path);
        }
        return ResultType();
    }

    // Template method for batch processing
    template<typename Container, typename Callback>
    static void processFiles(const Container& paths, Callback&& callback) {
        for (const auto& path : paths) {
            processFile(path, callback);
        }
    }
};

// Template for file operation policies
template<typename Policy>
class FileOperationPolicy {
public:
    template<typename T>
    static bool validate(const T& path) {
        return Policy::validate(path);
    }

    template<typename T>
    static void preProcess(const T& path) {
        Policy::preProcess(path);
    }

    template<typename T>
    static void postProcess(const T& path) {
        Policy::postProcess(path);
    }
};

// Example policy implementations
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

struct SecurePolicy {
    static bool validate(const QString& path) {
        QFileInfo info(path);
        return info.exists() && info.isReadable();
    }

    static void preProcess(const QString& path) {
        // Security checks
    }

    static void postProcess(const QString& path) {
        // Cleanup security
    }
};

// Template for file operation factory
template<typename T, typename Policy = DefaultPolicy>
class FileOperationFactory {
public:
    template<typename... Args>
    static std::unique_ptr<T> create(Args&&... args) {
        return std::make_unique<T>(std::forward<Args>(args)...);
    }

    template<typename U, typename... Args>
    static std::unique_ptr<U> createDerived(Args&&... args) {
        return std::make_unique<U>(std::forward<Args>(args)...);
    }
};

} // namespace FileHandlers