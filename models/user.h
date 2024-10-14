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

// TODO: Уточнить, выгоднее ли сначала проверять валидность данных, а уже потом создавать объект

class User {
public:
    // Constructors
    explicit User(const drogon::orm::Row& row);
    User(const char* login, const char* email, const char* password);
    User(const std::string& login, const std::string& email, const std::string& password);
    User(std::string login, std::string email, const std::string &password);

    // Getters and setters
    [[nodiscard]] const std::string& getLogin() const { return login_; }
    [[nodiscard]] const std::string& getEmail() const { return email_; }
    [[nodiscard]] const std::string& getPassword() const { return password_; }
    [[nodiscard]] const std::string& getSalt() const { return salt_; }
    [[nodiscard]] unsigned int getId() const { return id_; }
    void setId(const int id) { id_ = id; }
    void setLogin(const std::string& login) { login_ = login; }
    void setEmail(const std::string& email) { email_ = email; }
    void setPassword(const std::string& password) { password_ = password; }
    void setSalt(const std::string& salt) { salt_ = salt; }
    [[nodiscard]] Json::Value toJson() const;

    // Password work
    [[nodiscard]] bool comparePassword(const std::string& password) const;
    static std::string hashPassword(const std::string& password)
    {
        return std::move(drogon::utils::getSha256(password));
    }
    static std::string hashPasswordWithSalt(const std::string& password, const std::string& salt)
    {
        return std::move(drogon::utils::getSha256(password + salt));
    }


    // Static methods
    static User createUserFromJson(Json::Value& json);
    static User createFullUserFromJson(Json::Value& json);
    static void validateUserData(const char* login, const char*email, const char* password);

private:
    // Inner usage constructor. Does not check validity of data.
    User(const char* login, const char* email, const char* password, const char *salt, unsigned int id);
    unsigned int id_;
    std::string login_, email_, password_, salt_;
    void setPassword(const char* password);

    // Constants
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
    [[nodiscard]] const char* what() const noexcept override { return msg.c_str(); }

private:
    std::string msg;
};

#endif //USER_H
