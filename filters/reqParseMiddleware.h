#pragma once

#include <drogon/HttpFilter.h>
using namespace drogon;


class reqParseMiddleware : public HttpMiddleware<reqParseMiddleware>
{
  public:
    reqParseMiddleware() = default;
    void invoke(const HttpRequestPtr &req,
                MiddlewareNextCallback &&nextCb,
                MiddlewareCallback &&mcb) override;
};

