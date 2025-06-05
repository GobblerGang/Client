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

    struct LoginResult {
        bool success;
        std::string message;
        std::string user_uuid;  // Only set if login is successful
    };

    static SignUpResult signup(const std::string& username, const std::string& email, const std::string& password);
    static LoginResult login(const std::string& username, const std::string& password);

private:
    static bool usernameExists(const std::string& username);
    static bool emailExists(const std::string& email);
    static std::optional<std::string> requestUUIDFromServer();
    static std::optional<std::string> getKekInfo(const std::string& user_uuid);
    static bool verifyKekFreshness(const std::string& user_uuid, const std::string& local_updated_at);

    static std::optional<std::string> createUser(
        const std::string& username,
        const std::string& email,
        const std::string& vault,
        const std::string& userUUID,
        const std::string& encryptedKEK
    );
};
