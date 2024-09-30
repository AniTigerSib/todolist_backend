#include "User.h"
#include <regex>
#include <string>

std::regex const User::loginRegex_ = std::regex("^[\\w]{3,20}$");
std::regex const User::emailRegex_ = std::regex(R"(^[\w\-\.]+@([\w-]+\.)+[\w-]{2,}$)");
std::regex const User::passwordRegex_ = std::regex("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[!@#$%^&()_+])[A-Za-z\\d!@#$%^&()_+]{8,}$");

User::User(drogon::orm::Row& row)
{
    id_ = row["id"].as<int>();
    login_ = std::move(row["login"].as<std::string>());
    email_ = std::move(row["email"].as<std::string>());
    password_ = std::move(row["password"].as<std::string>());
}

User::User(const char* login, const char* email, const char* password) : User(std::move(std::string(login)),
                                                                              std::move(std::string(email)),
                                                                              std::move(std::string(password))) {}

User::User(std::string& login, std::string& email, std::string& password) : User(std::move(login),
                                                                                 std::move(email),
                                                                                 std::move(password)) {}

User::User(std::string login, std::string email, std::string password)
{
    std::cmatch m;

    if (!std::regex_match(login.c_str(), m, loginRegex_))
        throw UserException("Invalid login format");
    if (!std::regex_match(email.c_str(), m, emailRegex_))
        throw UserException("Invalid email format");
    if (!std::regex_match(password.c_str(), m, passwordRegex_))
        throw UserException("Invalid password format");

    login_ = std::move(login);
    email_ = std::move(email);
    password_ = std::move(password);
    id_ = -1;
}

std::future<drogon::orm::Result> User::getGetByLoginAsyncFutureSqlExec(drogon::orm::DbClientPtr& clientPtr, std::string& login)
{
    std::cmatch m;

    if (!std::regex_match(login.c_str(), m, loginRegex_))
        throw UserException("Invalid login format");

    return clientPtr->execSqlAsyncFuture("select id, login, email, password from users where login=$1", login);
}

User User::getByLogin(drogon::orm::DbClientPtr& clientPtr, std::string& login)
{
    auto result = getGetByLoginAsyncFutureSqlExec(clientPtr, login).get();

    if (result.size() == 0)
        throw UserException("User not found");

    auto res = result[0];
    return std::move(User(res));
}