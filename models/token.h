//
// Created by michael on 10/15/24.
//

#ifndef TOKEN_H
#define TOKEN_H
#include <chrono>
#include <string>


class token {
public:

private:
    int id_, userId_;
    std::string token_;
    std::chrono::time_point<std::chrono::system_clock> time_;
};


#endif //TOKEN_H
