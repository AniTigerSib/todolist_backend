#include "controllers_Auth.h"

#include <server.h>
#include <user.h>

#include "lib/auth.h"

using namespace controllers;



// Add definition of your processing function here
void Auth::registerHandler(const HttpRequestPtr &req,
                  std::function<void (const HttpResponsePtr &)> &&callback) const
{
    LOG_DEBUG << "Got request: " << req->method() << " : " << req->path() << " : " << req->query() << " : " << req->body();
    const auto reqJsonPtr = req->getJsonObject();

    if (reqJsonPtr == nullptr)
    {
        const std::string error = req->getJsonError();
        LOG_INFO << "Failed to parse request body: " << error << " : " << req->body();
        Json::Value ret;
        ret["status"] = "error";
        ret["message"] = "Invalid request body";
        const auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    Json::Value reqJson = *reqJsonPtr;
    
    try
    {
        const auto user = User::createUserFromJson(reqJson);
        LOG_DEBUG << "Created user: " << user.getLogin();

        const auto transPtr = clientPtr->newTransaction();
        transPtr->execSqlAsync("select * from users where login=$1 or email=$2",
                               [=](const orm::Result &r)
                               {
                                   if (r.empty())
                                   {
                                       LOG_INFO << "Adding user to database: " << user.getLogin();
                                       *transPtr << "insert into users (login, email, password, salt) values ($1, $2, $3, $4)"
                                                 << user.getLogin()
                                                 << user.getEmail()
                                                 << user.getPassword()
                                                 << user.getSalt()
                                                 >> [=](const orm::Result &rInsert)
                                                 {
                                                     LOG_INFO << "User successfully added to database";
                                                     User uLocal = user;
                                                     std::string key("key");
                                                     Json::Value ret;
                                                     ret["status"] = "ok";
                                                     ret["user"] = Json::Value(std::move(user.toJson()));
                                                     ret["access"] = uLocal.getToken(key);
                                                     // ret["refresh"] = drogon::utils::secureRandomString(200);
                                                     const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                                     resp->setStatusCode(k201Created);
                                                     callback(resp);
                                                 }
                                                 >> [=](const orm::DrogonDbException &e)
                                                 {
                                                     LOG_ERROR << "Failed to add user to database: " << e.base().what();
                                                     Json::Value ret;
                                                     ret["status"] = "error";
                                                     ret["message"] = "Internal error";
                                                     const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                                     resp->setStatusCode(k500InternalServerError);
                                                     callback(resp);
                                                 };
                                   } else
                                   {
                                       LOG_INFO << "User already exists in database";
                                       Json::Value ret;
                                       ret["status"] = "error";
                                       ret["message"] = "User already exists";
                                       const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                       resp->setStatusCode(k400BadRequest);
                                       callback(resp);
                                   }
                               },
                               [=](const orm::DrogonDbException &e)
                               {
                                   LOG_ERROR << "Failed to refer to database: " << e.base().what();
                                   Json::Value ret;
                                   ret["status"] = "error";
                                   ret["message"] = "Internal error";
                                   const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                   resp->setStatusCode(k500InternalServerError);
                                   callback(resp);
                               },
                               user.getLogin().c_str(),
                               user.getEmail().c_str());
    } catch (const std::exception &e)
    {
        HttpStatusCode code;
        LOG_INFO << "Failed to create user: " << e.what();
        Json::Value ret;
        ret["status"] = "error";
        if (dynamic_cast<const UserException *>(&e))
        {
            ret["message"] = e.what();
            code = k400BadRequest;
        } else if (dynamic_cast<const ServerException *>(&e))
        {
            LOG_WARN << "JSON parse error.";
            ret["message"] = "User creating failed";
            code = k500InternalServerError;
        } else
        {
            LOG_WARN << "JSON parse error. Not identified exception.";
            ret["message"] = "User creating failed";
            code = k400BadRequest;
        }
        const auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(code);
        callback(resp);
    }
}

void Auth::loginHandler(const HttpRequestPtr &req,
                      std::function<void (const HttpResponsePtr &)> &&callback) const
{
    LOG_DEBUG << "Got request: " << req->method() << " : " << req->path() << " : " << req->query() << " : " << req->body();
    const auto reqJsonPtr = req->getJsonObject();

    if (reqJsonPtr == nullptr)
    {
        const std::string error = req->getJsonError();
        LOG_INFO << "Failed to parse request body: " << error << " : " << req->body();
        Json::Value ret;
        ret["status"] = "error";
        ret["message"] = "Invalid request body";
        const auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    const Json::Value& reqJson = *reqJsonPtr;
    std::pair<std::string, std::string> loginData;
    bool isEmail = false;
    try
    {
        loginData.first = reqJson["username"].asString();
        loginData.second = reqJson["password"].asString();
    } catch (const std::exception &e)
    {
        LOG_INFO << "Failed to parse request body: " << e.what();
        Json::Value ret;
        ret["status"] = "error";
        ret["message"] = "Invalid request body";
        const auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    User::UDataEvalErrc evalRes = User::validateUserDataErrc(loginData.first.c_str(), nullptr, loginData.second.c_str());
    LOG_DEBUG << "Eval result: " << User::getErrcStr(evalRes);
    if (evalRes == User::UDataEvalErrc::INVALID_LOGIN)
    {
        evalRes = User::validateUserDataErrc(nullptr, loginData.first.c_str(), loginData.second.c_str());
        isEmail = true;
    }
    if (evalRes != User::UDataEvalErrc::OK)
    {
        LOG_INFO << "Failed to validate user data";
        Json::Value ret;
        ret["status"] = "error";
        ret["message"] = User::getErrcStr(evalRes);
        const auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        callback(resp);
        return;
    }

    LOG_DEBUG << "User data validated";
    clientPtr->execSqlAsync(User::getQueryGetString(isEmail),
                            [loginData = std::make_unique<std::pair<std::string, std::string>>(loginData), callback](const orm::Result &r)
                            {
                                if (r.empty())
                                {
                                    LOG_INFO << "User " << loginData->first << " not found";
                                    Json::Value ret;
                                    ret["status"] = "error";
                                    ret["message"] = "User not found";
                                    const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                    resp->setStatusCode(k404NotFound);
                                    callback(resp);
                                    return;
                                }
                                try
                                {
                                    auto user = User(r[0]);
                                    if (user.hasEqualPassword(loginData->second))
                                    {
                                        LOG_INFO << "User " << loginData->first << " logged in";
                                        std::string key("key");
                                        Json::Value ret;
                                        ret["status"] = "ok";
                                        ret["message"] = "User logged in";
                                        ret["access"] = user.getToken(key);
                                        // ret["refresh"] = drogon::utils::secureRandomString(200);
                                        const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                        resp->setStatusCode(k200OK);
                                        callback(resp);
                                    } else
                                    {
                                        LOG_INFO << "User " << loginData->first << " sent wrong password";
                                        Json::Value ret;
                                        ret["status"] = "error";
                                        ret["message"] = "Wrong password";
                                        const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                        resp->setStatusCode(k400BadRequest);
                                        callback(resp);
                                    }
                                } catch (const std::exception &e)
                                {
                                    LOG_WARN << "Failed to create user: " << e.what();
                                    Json::Value ret;
                                    ret["status"] = "error";
                                    ret["message"] = "Internal error";
                                    const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                    resp->setStatusCode(k500InternalServerError);
                                    callback(resp);
                                }
                            },
                            [callback](const orm::DrogonDbException &e)
                            {
                                LOG_ERROR << "Failed to refer to database: " << e.base().what();
                                Json::Value ret;
                                ret["status"] = "error";
                                ret["message"] = "Internal error";
                                const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                resp->setStatusCode(k500InternalServerError);
                                callback(resp);
                            },
                            loginData.first);
}