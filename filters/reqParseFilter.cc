#include "reqParseFilter.h"

using namespace drogon;

void reqParseFilter::doFilter(const HttpRequestPtr &req,
                              FilterCallback &&fcb,
                              FilterChainCallback &&fccb)
{
    Json::Value reqJson;
    Json::Reader reader;

    if (bool parsingSuccessful = reader.parse(req->body().data(), reqJson); !parsingSuccessful)
    {
        LOG_ERROR << "Failed to parse request body: " << reader.getFormattedErrorMessages()
                  << " : " << req->body();
        Json::Value ret;
        ret["status"] = "error";
        ret["message"] = "Invalid request body";
        const auto resp = HttpResponse::newHttpJsonResponse(ret);
        resp->setStatusCode(k400BadRequest);
        fcb(resp);
        return;
    }
    fccb();
}
