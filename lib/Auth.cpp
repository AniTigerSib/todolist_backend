//
// Created by michael on 9/27/24.
//

#include "Auth.h"

#include <random>

#ifdef DEBUG
std::string Auth::accTokRetType::toString()
{
    std::stringstream ss;
    ss << "accTokRetType: { ";
    ss << (isValid ? "true " : "false ") << reason << token.signature(); // May throw errors
}
#endif


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

    jwt::jwt_object token{algorithm(alg),
                          headers({
                              {"alg", Auth::alg},
                              {"type", Auth::type}}),
                          payload({
                              {"iss", Auth::issuer},
                              {"sub", userLogin}}),
                          secret(key)};
    token.add_claim("exp", std::chrono::system_clock::now() + Auth::expiration_time)
         .add_claim("iat", std::chrono::system_clock::now())
         .add_claim("uid", userId);
    return token;
}

std::pair<bool, std::string> Auth::validateAccessToken(const std::string& token, const std::string& key)
{
    using namespace jwt::params;
    std::error_code ec;
    std::pair<bool, std::string> result;

    try
    {
        auto dec_token = jwt::decode(token, algorithms({Auth::alg}), secret(key), verify(false));
        result.first = true;
        result.second.clear();
    } catch (const jwt::DecodeError& e)
    {
        LOG_WARN << "JWT decode error: " << e.what();

        result.first = false;
        result.second.append(e.what());
    }

    return std::move(result);
}

Auth::accTokRetType Auth::verifyAccessToken(const std::string &accToken, const std::string& key)
{
    using namespace jwt::params;

    Auth::accTokRetType result;
    std::error_code ec;

    auto token = jwt::decode(accToken, algorithms({Auth::alg}), ec, secret(key),
                                     jwt::params::issuer(Auth::issuer));

    if (ec)
    {
        LOG_INFO << "User JWT not valid: " << ec.message();

        result.isValid = false;
        result.reason.append(stateStrArr[ec.value()]);
    }

    result.token = std::move(token);
    return std::move(result);
}