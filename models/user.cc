#include "user.h"
#include <cstddef>
#include <regex>
#include <string>
#include "../server.h"

std::regex const User::loginRegex_ = std::regex("^[\\w]{3,20}$");
std::regex const User::emailRegex_ = std::regex(R"(^[\w\-\.]+@([\w-]+\.)+[\w-]{2,}$)");
std::regex const User::passwordRegex_ = std::regex("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&()_+])[A-Za-z\\d!@#$%^&()_+]{8,}$");

// +++++++++++++++++ Initialization +++++++++++++++++ //

User::User(const drogon::orm::Row& row)
{
    id_ = row["id"].as<int>();
    login_ = std::move(row["login"].as<std::string>());
    email_ = std::move(row["email"].as<std::string>());
    password_ = std::move(row["password"].as<std::string>());
}

void User::validateUserData(const char *login, const char *email, const char *password)
{
    std::cmatch m;

    if (login != nullptr && (strlen(login) > loginSizeMax_ || !std::regex_match(login, m, loginRegex_)))
        throw UserException("Invalid login format");
    if (email != nullptr && (strlen(email) > emailSizeMax_ || !std::regex_match(email, m, emailRegex_)))
        throw UserException("Invalid email format");
    if (password != nullptr && !std::regex_match(password, m, passwordRegex_))
        throw UserException("Invalid password format");
}

User::User(const char* login, const char* email, const char* password)
{
    if (login == nullptr || email == nullptr || password == nullptr)
        throw ServerException("Invalid user data");
    validateUserData(login, email, password);

    login_ = std::string(login);
    email_ = std::string(email);
    password_ = std::move(hashPassword(std::string(password)));
    id_ = -1;
}

User::User(const std::string& login, const std::string& email, const std::string& password)
{
    validateUserData(login.c_str(), email.c_str(), password.c_str());

    login_ = login;
    email_ = email;
    password_ = std::move(hashPassword(std::string(password)));
    id_ = -1;
}

User::User(std::string login, std::string email, std::string password)
{
    validateUserData(login.c_str(), email.c_str(), password.c_str());

    login_ = std::move(login);
    email_ = std::move(email);
    password_ = std::move(hashPassword(std::string(std::move(password))));
    id_ = -1;
}

// ----------------- Initialization ----------------- //


// +++++++++++++++++ Main methods +++++++++++++++++ //

std::future<drogon::orm::Result> User::getUserByLoginAsyncFutureSqlExec(const drogon::orm::DbClientPtr& clientPtr, std::string& login)
{
    validateUserData(login.c_str(), nullptr, nullptr);

    return clientPtr->execSqlAsyncFuture("select id, login, email, password from users where login=$1", login);
}

User User::getUserByLogin(const drogon::orm::DbClientPtr& clientPtr, std::string& login)
{
    const auto result = getUserByLoginAsyncFutureSqlExec(clientPtr, login).get();

    if (result.empty())
        throw UserException("User not found");

    const auto res = result[0];
    return std::move(User(res));
}

// ----------------- Main methods ----------------- //