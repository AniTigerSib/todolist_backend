//
// Created by michael on 9/27/24.
//

#include "auth.h"

#include <random>

#ifdef DEBUG
std::string lib::Auth::atVerifyRType::toString() const
{
    std::stringstream ss;
    ss << "atVerifyRType: { ";
    ss << (is_valid ? "true " : "false ") << reason << token.signature(); // May throw errors
    ss << "}";
    return ss.str();
}
#endif


std::string lib::Auth::generateRandomToken(const size_t lenght)
{
    static const std::string chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, static_cast<int>(chars.size()) - 1);
    std::string token;

    for (size_t i = 0; i < lenght; i++)
    {
        token += chars[dis(gen)];
    }
    return token;
}

std::string lib::Auth::generateAccessToken(const std::string& key, const std::string& userLogin)
{
    using namespace jwt::params;
    std::string result;

    jwt::jwt_object token{algorithm(alg),
                          headers({
                              {"alg", Auth::alg},
                              {"type", Auth::type}}),
                          payload({
                              {"iss", Auth::issuer},
                              {"sub", userLogin}}),
                          secret(key)};
    token.add_claim("exp", std::chrono::system_clock::now() + Auth::expiration_time)
         .add_claim("iat", std::chrono::system_clock::now());

    try
    {
        result = std::move(token.signature());
    } catch (jwt::MemoryAllocationException& e)
    {
        throw ATMemAllocException(e.what());
    } catch (jwt::SigningError& e)
    {
        throw ATGenerateException(e.what());
    }

    return std::move(result);
}

void lib::Auth::validateAccessToken(const std::string& token, const std::string& key)
{
    using namespace jwt::params;

    try
    {
        jwt::decode(token, algorithms({Auth::alg}), secret(key), verify(false));
    } catch (jwt::MemoryAllocationException& e)
    {
        throw ATMemAllocException(e.what());
    } catch (const jwt::DecodeError& e)
    {
        throw ATValidationException(e.what());
    }
}


std::pair<jwt::jwt_object, std::string> lib::Auth::verifyAccessToken(const std::string &accToken, const std::string& key)
{
    using namespace jwt::params;
    std::pair<jwt::jwt_object, std::string> result;

    try
    {
        jwt::jwt_object jwt;
        std::error_code ec;
        jwt = std::move(jwt::decode(accToken, algorithms({Auth::alg}), ec, secret(key),
                                      jwt::params::issuer(Auth::issuer)));

        auto login = jwt.payload().get_claim_value<std::string>("sub");

        if (ec)
        {
            throw ATVerificationException(Auth::ver_state_str_arr[ec.value()]);
        }
        if (login.empty())
        {
            throw ATVerificationException(Auth::ver_state_str_arr[Auth::sub_inval_str_index]);
        }

        result.first = std::move(jwt);
        result.second = std::move(login);
    } catch (jwt::MemoryAllocationException& e)
    {
        throw ATMemAllocException(e.what());
    }

    return std::move(result);
}