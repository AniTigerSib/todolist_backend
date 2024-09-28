//
// Created by michael on 9/27/24.
//

#ifndef AUTH_H
#define AUTH_H

#include <drogon/drogon.h>
#include "jwt/jwt.hpp"

namespace Auth
{
    struct accTokRetType
    {
        bool isValid = true;
        std::string reason = std::string();
        jwt::jwt_object token = jwt::jwt_object();

#ifdef DEBUG
        std::string toString();
#endif
    };

    static const std::string alg = "HS256";
    static const std::string type = "JWT";
    static const std::string issuer = "todolist.com";
    static const auto expiration_time = std::chrono::seconds(1200);
    static const std::string stateStrArr[11] = {
        "",
        "Invalid algorithm",
        "Token has expired",
        "Invalid issuer",
        "Invalid subject",
        "Invalid iat field",
        "Invalid jti field",
        "Invalid audience",
        "Nbf time not reached",
        "Invalid signature",
        "Invalid type used"};

    std::string generateRandomToken(size_t lenght);
    jwt::jwt_object generateAccessToken(const std::string& key, const std::string& userLogin, const int& userId);
    std::pair<bool, std::string> validateAccessToken(const std::string& token, const std::string& key);
    accTokRetType verifyAccessToken(const std::string &accToken, const std::string& key);
}

#endif //AUTH_H
