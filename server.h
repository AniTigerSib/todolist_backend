#ifndef SERVER_H
#define SERVER_H

#include <exception>
#include <string>

class ServerException final : public std::exception
{
public:
    explicit ServerException(std::string what = "Failed to create user") : msg(std::move(what)) {}
    [[nodiscard]] const char* what() const noexcept override { return msg.c_str(); };

private:
    std::string msg;
};

#endif // SERVER_H