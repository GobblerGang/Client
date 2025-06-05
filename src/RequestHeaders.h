//
// Created by eddie phelan on 05/06/2025.
//
#ifndef REQUESTHEADERS_H
#include <string>
#define REQUESTHEADERS_H

struct RequestHeaders {
    std::string user_uuid;
    std::string nonce;
    std::string signature;
};
#endif //REQUESTHEADERS_H
