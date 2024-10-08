//
// Created by michael on 9/28/24.
//

#ifndef USER_H
#define USER_H
#include <drogon/drogon.h>
#include <exception>
#include <regex>
#include <string>

class User;
class UserException;

class User {
public:
    // Constructors
    explicit User(const drogon::orm::Row& row);
    User(const char* login, const char* email, const char* password);
    User(const std::string& login, const std::string& email, const std::string& password);
    User(std::string login, std::string email, std::string password);

    // Getters and setters
    [[nodiscard]] const std::string& getLogin() const { return login_; }
    [[nodiscard]] const std::string& getEmail() const { return email_; }
    [[nodiscard]] const std::string& getPassword() const { return password_; }
    [[nodiscard]] int getId() const { return id_; }

    // Static methods
    static void validateUserData(const char *login, const char *email, const char *password);
    static std::future<drogon::orm::Result> getGetByLoginAsyncFutureSqlExec(const drogon::orm::DbClientPtr& clientPtr, std::string& login);
    static User getByLogin(const drogon::orm::DbClientPtr& clientPtr, std::string& login);

    // std::future<const drogon::orm::Result>  getInsertAsyncFutureSqlExec();
    // std::future<const drogon::orm::Result>  getUpdateAsyncFutureSqlExec();

private:
    int id_;
    std::string login_, email_, password_;
    static constexpr int loginSizeMax_ = 20;
    static constexpr int emailSizeMax_ = 30;
    static std::regex const loginRegex_;
    static std::regex const emailRegex_;
    static std::regex const passwordRegex_;
};

class UserException final : public std::exception
{
public:
    explicit UserException(std::string what = "Failed to create user") : msg(std::move(what)) {}
    std::string what() { return std::move(msg); };

private:
    std::string msg;
};

#endif //USER_H
