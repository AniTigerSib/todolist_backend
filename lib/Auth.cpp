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
