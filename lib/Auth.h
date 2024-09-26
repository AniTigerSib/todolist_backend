//
// Created by michael on 9/27/24.
//

#ifndef AUTH_H
#define AUTH_H

#include <drogon/drogon.h>
#include "jwt/jwt.hpp"

namespace Auth
{
    static const std::string alg = "HS256";
    static const std::string type = "JWT";
    static const std::string issuer = "todolist.com";

    std::string generateRandomToken(size_t lenght);
    jwt::jwt_object generateAccessToken(const std::string& key, const std::string& userLogin, const int& userId);
    std::pair<bool, std::string> validateAccessToken(const std::string &accessToken, const std::string& key);
}

#endif //AUTH_H
