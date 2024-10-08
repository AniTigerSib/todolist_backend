#ifndef SERVER_H
#define SERVER_H

#include <exception>
#include <string>

class ServerException final : public std::exception
{
public:
    explicit ServerException(std::string what = "Failed to create user") : msg(std::move(what)) {}
    std::string what() { return std::move(msg); };

private:
    std::string msg;
};

#endif // SERVER_H