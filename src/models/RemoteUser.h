#pragma once
#include <string>
// This file defines the User structure used on the server to store user information.

struct RemoteUser {
    std::string uuid;
    std::string username;
    std::string email;
    std::string salt;
};
