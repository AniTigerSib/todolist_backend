#ifndef AUTH_H
#define AUTH_H

#include <drogon/drogon.h>
#include "jwt/jwt.hpp"

namespace lib::Auth
{
    struct atVerifyRType
    {
        bool is_valid = true;
        std::string reason = std::string();
        jwt::jwt_object token = jwt::jwt_object();

#ifdef DEBUG
            [[nodiscard]] std::string toString() const;
#endif
    };

    static const std::string alg = "HS256";
    static const std::string type = "JWT";
    static const std::string issuer = "todolist.com";
    static const auto expiration_time = std::chrono::seconds(1200);
    static constexpr int sub_inval_str_index = 4;
    static const std::string ver_state_str_arr[11] = {
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

    std::string generateAccessToken(const std::string& key, const std::string& userLogin);
    void validateAccessToken(const std::string& token, const std::string& key);
    std::pair<jwt::jwt_object, std::string> verifyAccessToken(const std::string &accToken, const std::string& key);
}

class AccessTokenException : std::exception
{
public:
    AccessTokenException() : reason_("Access token exception") {}
    explicit AccessTokenException(const char *reason) : reason_(reason) {}
    explicit AccessTokenException(std::string reason) : reason_(reason.c_str()) {}
    explicit AccessTokenException(std::string& reason) : reason_(reason.c_str()) {}
    [[nodiscard]] const char* what() const noexcept override { return this->reason_; }
private:
    const char *reason_;
};

class ATGenerateException final : AccessTokenException
{
public:
    ATGenerateException() : AccessTokenException("Access token generating failed") {}
    explicit ATGenerateException(const char *reason) : AccessTokenException(std::string("Access token generating failed: ") + reason) {}
};

class ATMemAllocException final : AccessTokenException
{
public:
    ATMemAllocException() : AccessTokenException("Memory allocation failed") {}
    explicit ATMemAllocException(const char *reason) : AccessTokenException(std::string("Memory allocation failed: ") + reason) {}
};

class ATValidationException final : AccessTokenException
{
public:
    ATValidationException() : AccessTokenException("Invalid access token signature") {}
    explicit ATValidationException(const char *reason) : AccessTokenException(std::string("Invalid access token signature: ") + reason) {}
};

class ATVerificationException final : AccessTokenException
{
public:
    ATVerificationException() : AccessTokenException("Access token invalid") {}
    explicit ATVerificationException(const char *reason) : AccessTokenException(std::string("Access token invalid: ") + reason) {}
    explicit ATVerificationException(const std::string& reason) : AccessTokenException(reason) {}
};

#endif //AUTH_H