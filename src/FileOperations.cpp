// #include "../include/FileOperationBase.hpp"
// #include "../include/TemplateFileManager.hpp"
// #include <QDebug>
// #include <QFileDialog>
// #include <QMessageBox>
// #include <QFile>

// #Function Pointer Type Definition
using FileOperationCallback = std::function<void(const QString&)>;
using FileOperationValidator = std::function<bool(const QString&)>;

// #Function Pointer Type
using FileOperationFunc = bool (*)(const QString&);

// #Call by Reference (const reference)
void fileOperationCallback(const QString& path) {
    qDebug() << "Operation completed for file:" << path;
}

// #Function that Returns a Function Pointer
FileOperationFunc getFileOperation(const QString& type) {
    if (type == "upload") {
        return [](const QString& path) -> bool {
            QFile file(path);
            return file.exists();
        };
    }
    return nullptr;
}

// #Function that Takes a Function Pointer as Parameter
bool executeFileOperation(const QString& path, FileOperationFunc operation) {
    if (operation) {
        return operation(path);
    }
    return false;
}

// #Function Overloading - First version
bool processFile(const QString& path) {
    return QFile::exists(path);
}

// #Function Overloading - Second version
bool processFile(const QString& path, const QString& type) {
    if (type == "upload") {
        return QFile::exists(path);
    }
    return false;
}

// #Inline Function
inline bool validateFile(const QString& path) {
    return QFile::exists(path);
}

// #Smart Pointer Usage
std::unique_ptr<QFile> createFileHandle(const QString& path) {
    return std::make_unique<QFile>(path);
}

// #Function that demonstrates exception handling
bool safeFileOperation(const QString& path) {
    try {
        QFile file(path);
        if (!file.exists()) {
            throw std::runtime_error("File does not exist");
        }
        return true;
    } catch (const std::exception& e) {
        qDebug() << "Error:" << e.what();
        return false;
    }
}

// #Function that returns a function pointer
FileOperationCallback getFileOperationHandler(const QString& operationType) {
    if (operationType == "upload") {
        return [](const QString& path) {
            qDebug() << "Handling upload for:" << path;
            UploadOperation op(path);
            op.execute();
        };
    } else if (operationType == "download") {
        return [](const QString& path) {
            qDebug() << "Handling download for:" << path;
            // Download operation implementation
        };
    }
    return [](const QString& path) {
        qDebug() << "Unknown operation for:" << path;
    };
}

// #Function that takes a function pointer as argument
void processFileWithCallback(const QString& path, FileOperationCallback callback) {
    if (QFile::exists(path)) {
        callback(path);
    }
}

// #Function that demonstrates pointer arithmetic with arrays
void processFileArray(char* data, size_t size) {
    char* end = data + size;
    while (data < end) {
        // Process each byte
        *data = toupper(*data);
        ++data;
    }
}

// #Function that demonstrates array-pointer relationship
void processFileChunks(const QString& path) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) return;

    const int chunkSize = 1024;
    char* buffer = new char[chunkSize];

    while (!file.atEnd()) {
        qint64 bytesRead = file.read(buffer, chunkSize);
        if (bytesRead <= 0) break;

        // Demonstrate array-pointer relationship
        char* current = buffer;
        char* end = buffer + bytesRead;

        while (current < end) {
            *current = toupper(*current);
            ++current;
        }
    }

    delete[] buffer;
    file.close();
}

// // Function that demonstrates dynamic memory allocation
// std::unique_ptr<UploadOperation> createUploadOperation(const QString& path) {
//     return std::make_unique<UploadOperation>(path);
// }
//
// // Function that demonstrates shared pointers
// std::shared_ptr<UploadOperation> createSharedUploadOperation(const QString& path) {
//     return std::make_shared<UploadOperation>(path);
// }

// #Function that demonstrates function overloading with different names
void processFileWithLogging(const QString& path) {
    QFileInfo info(path);
    qDebug() << "Processing file:" << info.fileName();
}

void processFileWithOperation(const QString& path, const QString& operation) {
    QFileInfo info(path);
    qDebug() << "Processing file:" << info.fileName() << "with operation:" << operation;
}

// #Inline function with default arguments
inline QString getFileExtension(const QString& path, bool includeDot = true) {
    QFileInfo info(path);
    QString ext = info.suffix();
    return includeDot ? "." + ext : ext;
}

// #Function that demonstrates call by value vs call by reference
void processFilePath(QString path) {  // Call by value
    path = path.toUpper();
}

void processFilePathRef(QString& path) {  // Call by reference
    path = path.toUpper();
}