#pragma once
#include <string>

struct User {
    std::string uuid;
    std::string username;
    std::string email;
    std::string salt;
};
