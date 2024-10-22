#include "user.h"
#include <cstddef>
#include <regex>
#include <string>
#include <utility>
#include "../server.h"
#include "lib/auth.h"

std::regex const User::loginRegex_ = std::regex("^[\\w]{3,20}$");
std::regex const User::emailRegex_ = std::regex(R"(^[\w\-\.]+@([\w-]+\.)+[\w-]{2,}$)");
std::regex const User::passwordRegex_ = std::regex("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&()_+])[A-Za-z\\d!@#$%^&()_+]{8,}$");

// +++++++++++++++++ Initialization +++++++++++++++++ //

User::User(const User& other)
{
    id_ = other.id_;
    login_ = other.login_;
    email_ = other.email_;
    salt_ = other.salt_;
    password_ = other.password_;
}

User::User(const drogon::orm::Row& row)
{
    id_ = row["id"].as<int>();
    login_ = std::move(row["login"].as<std::string>());
    email_ = std::move(row["email"].as<std::string>());
    salt_ = std::move(row["salt"].as<std::string>());
    password_ = std::move(row["password"].as<std::string>());
}

User::User(const char* login, const char* email, const char* password)
{
    if (login == nullptr || email == nullptr || password == nullptr)
        throw ServerException("Invalid user data");
    validateUserData(login, email, password);

    login_ = std::string(login);
    email_ = std::string(email);
    this->setPassword(password);
    id_ = 0;
}

User::User(const std::string& login, const std::string& email, const std::string& password)
{
    validateUserData(login.c_str(), email.c_str(), password.c_str());

    login_ = login;
    email_ = email;
    this->setPassword(password.c_str());
    id_ = 0;
}

User::User(std::string login, std::string email, const std::string &password)
{
    validateUserData(login.c_str(), email.c_str(), password.c_str());

    login_ = std::move(login);
    email_ = std::move(email);
    this->setPassword(password.c_str());
    id_ = 0;
}

User::User(const char* login, const char* email, const char* password, const char *salt, const unsigned int id)
{
    login_ = std::string(login);
    email_ = std::string(email);
    password_ = std::string(password);
    salt_ = std::string(salt);
    id_ = id;
}

void User::validateUserData(const char* login, const char* email, const char* password)
{
    std::cmatch m;

    if (login != nullptr && (strlen(login) > loginSizeMax_ || !std::regex_match(login, m, loginRegex_)))
        throw UserException("Invalid login format");
    if (email != nullptr && (strlen(email) > emailSizeMax_ || !std::regex_match(email, m, emailRegex_)))
        throw UserException("Invalid email format");
    if (password != nullptr && !std::regex_match(password, m, passwordRegex_))
        throw UserException("Invalid password format");
}

User::UDataEvalErrc User::validateUserDataErrc(const char* login, const char*email, const char* password)
{
    try
    {
        validateUserData(login, email, password);
    } catch (const UserException& e)
    {
        std::cout << e.what() << std::endl;
        if (std::strcmp(e.what(), "Invalid login format") != 0) return UDataEvalErrc::INVALID_LOGIN;
        if (std::strcmp(e.what(), "Invalid email format") != 0) return UDataEvalErrc::INVALID_EMAIL;
        if (std::strcmp(e.what(), "Invalid password format") != 0) return UDataEvalErrc::INVALID_PASSWORD;
    }
    return UDataEvalErrc::OK;
}

const char *User::getErrcStr(UDataEvalErrc errc)
{
    switch (errc)
    {
    case UDataEvalErrc::OK:
        return "OK";
    case UDataEvalErrc::INVALID_LOGIN:
    case UDataEvalErrc::INVALID_EMAIL:
        return "Invalid login format";
    case UDataEvalErrc::INVALID_PASSWORD:
        return "Invalid password format";
    default:
        return "Unknown error";
    }
}

void User::setPassword(const char* password)
{
    if (salt_.empty())
    {
        salt_ = drogon::utils::secureRandomString(64);
    }
    password_ = std::move(hashPasswordWithSalt(password, salt_));
    // password_ = std::move(drogon::utils::getSha256(password + salt_));
}

const char *User::getQueryGetString(bool byEmail)
{
    if (byEmail) return "select * from users where email=$1";
    return "select * from users where login=$1";
}

// ----------------- Initialization ----------------- //

std::string User::getToken(std::string &key)
{
    return std::move(lib::Auth::generateAccessToken(key, std::to_string(id_)));
}

User User::createUserFromJson(Json::Value& json)
{
    const auto login = json["login"].asString();
    const auto email = json["email"].asString();
    const auto password = json["password"].asString();

    return {login.c_str(), email.c_str(), password.c_str()};
}

User User::createFullUserFromJson(Json::Value& json)
{
    const auto login = json["login"].asString();
    const auto email = json["email"].asString();
    const auto password = json["password"].asString();
    const auto salt = json["salt"].asString();
    const auto id = json["id"].asUInt();

    return {login.c_str(), email.c_str(), password.c_str(), salt.c_str(), id};
}

Json::Value User::toJson() const
{
    Json::Value json;
    json["id"] = id_;
    json["login"] = login_;
    json["email"] = email_;
#ifdef DEBUG
    json["password"] = password_;
#endif

    return std::move(json);
}

bool User::hasEqualPassword(const std::string& password) const
{
    std::string hash = hashPasswordWithSalt(password, salt_);
    return hash == password_;
}