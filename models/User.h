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
    User(drogon::orm::Row& row);
    User(const char* login, const char* email, const char* password);
    User(std::string& login, std::string& email, std::string& password);
    User(std::string login, std::string email, std::string password);

    const std::string& getLogin() const { return login_; }
    const std::string& getEmail() const { return email_; }
    const std::string& getPassword() const { return password_; }
    int getId() const { return id_; }

    static std::future<drogon::orm::Result> getGetByLoginAsyncFutureSqlExec(drogon::orm::DbClientPtr& clientPtr, std::string& login);
    static User getByLogin(drogon::orm::DbClientPtr& clientPtr, std::string& login);

    // std::future<const drogon::orm::Result>  getInsertAsyncFutureSqlExec();
    // std::future<const drogon::orm::Result>  getUpdateAsyncFutureSqlExec();

private:
    int id_;
    std::string login_, email_, password_;
    static int const loginSizeMax_ = 20;
    static int const emailSizeMax_ = 30;
    static std::regex const loginRegex_;
    static std::regex const emailRegex_;
    static std::regex const passwordRegex_;
};

class UserException : public std::exception
{
public:
    UserException(std::string what = "Failed to create user") : msg(std::move(what)) {}
    const std::string what() { return std::move(msg); };

private:
    std::string msg;
};

#endif //USER_H
