#pragma once

#include <string>
#include <optional>
#include <tuple>
class Auth {
public:
    struct SignUpResult {
        bool success;
        std::string message;
    };

    // #Function Declaration (returns struct)
    static SignUpResult signup(const std::string& username, const std::string& email, const std::string& password);

private:
    // #Function Declaration (returns bool, call by const reference)
    static bool usernameExists(const std::string& username);
    // #Function Declaration (returns bool, call by const reference)
    static bool emailExists(const std::string& email);
    // #Function Declaration (returns optional by value)
    static std::optional<std::string> requestUUIDFromServer();
    // #Function Declaration (returns optional by value, call by const reference)
    static std::optional<std::string> createUser(
        const std::string& username,
        const std::string& email,
        const std::string& vault,
        const std::string& userUUID,
        const std::string& encryptedKEK
    );
};
