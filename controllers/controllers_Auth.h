#pragma once

#include <drogon/HttpController.h>

using namespace drogon;

namespace controllers
{
class Auth final : public drogon::HttpController<Auth>
{
public:
    METHOD_LIST_BEGIN

    ADD_METHOD_TO(Auth::registerHandler, "/register", Post); // path is /register
    ADD_METHOD_TO(Auth::loginHandler, "/login", Post); // path is /login

    METHOD_LIST_END

    void registerHandler(const HttpRequestPtr &req,
                         std::function<void (const HttpResponsePtr &)> &&callback) const;
    void loginHandler(const HttpRequestPtr &req,
                      std::function<void (const HttpResponsePtr &)> &&callback) const;
private:
    drogon::orm::DbClientPtr clientPtr = drogon::app().getDbClient("pg_base");
};
}
