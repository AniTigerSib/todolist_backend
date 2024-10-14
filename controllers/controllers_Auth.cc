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
    Json::Value reqJson;
    Json::Reader reader;
    reader.parse(req->body().data(), reqJson);
    
    try
    {
        auto user = User::createUserFromJson(reqJson);
        LOG_DEBUG << "Created user: " << user.toJson().toStyledString();

        auto transPtr = clientPtr->newTransaction();
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
                                                     Json::Value ret;
                                                     ret["status"] = "ok";
                                                     ret["user"] = Json::Value(std::move(user.toJson()));
                                                     const auto resp = HttpResponse::newHttpJsonResponse(ret);
                                                     resp->setStatusCode(k201Created);
                                                     callback(resp);
                                                 }
                                                 >> [=](const orm::DrogonDbException &e)
                                                 {
                                                     LOG_INFO << "Failed to add user to database: " << e.base().what();
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
                                   LOG_INFO << "Failed to refer to database: " << e.base().what();
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
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(code);
        callback(resp);
    }
}
