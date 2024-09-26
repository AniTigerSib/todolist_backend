//
// Created by michael on 9/27/24.
//

#ifndef AUTH_H
#define AUTH_H

#include <drogon/drogon.h>
#include "jwt/jwt.hpp"

namespace Auth
{
    std::string generateRandomToken(const size_t lenght);
    std::string generateAccessToken();
    bool validateAccessToken(const std::string &accessToken);
}

#endif //AUTH_H
