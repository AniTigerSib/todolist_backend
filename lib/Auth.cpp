//
// Created by michael on 9/27/24.
//

#include "Auth.h"

#include <bits/random.h>

std::string Auth::generateRandomToken(const size_t lenght)
{
    static const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, chars.size() - 1);
    std::string token;

    for (size_t i = 0; i < lenght; i++)
    {
        token += chars[dis(gen)];
    }
    return token;
}

jwt::jwt_object Auth::generateAccessToken(const std::string& key, const std::string& userLogin, const int& userId)
{
    using namespace jwt::params;
    std::map<std::string, std::string> hd;
    hd["alg"] = alg;
    hd["type"] = type;

    std::map<std::string, std::string> pl;
    pl["iss"] = issuer;
    pl["sub"] = userLogin;
    pl["exp"] = std::to_string((std::chrono::system_clock::now() + std::chrono::seconds(1200)).time_since_epoch().count());
    pl["iat"] = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    pl["uid"] = std::to_string(userId);

    jwt::jwt_object token{algorithm(alg), headers(hd), payload(pl), secret(key)};
    return token;
}