#include "reqParseMiddleware.h"

using namespace drogon;

void reqParseMiddleware::invoke(const HttpRequestPtr &req,
                MiddlewareNextCallback &&nextCb,
                MiddlewareCallback &&mcb)
{
    Json::Value reqJson;
    Json::Reader reader;

    bool parsingSuccessful = reader.parse(req->body().data(), reqJson);

    if (!parsingSuccessful)
    {
        LOG_ERROR << "Failed to parse request JSON: " << reader.getFormattedErrorMessages()
                  << " : " << req->body();
        Json::Value ret;
        ret["status"] = "error";
        ret["message"] = "Failed to parse request JSON";
        auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        mcb(resp);
        return;
    }
    nextCb([mcb = std::move(mcb)](const HttpResponsePtr &resp)
    {
        mcb(resp);
    });
}
