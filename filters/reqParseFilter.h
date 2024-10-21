#pragma once

#include <drogon/HttpFilter.h>
using namespace drogon;


class reqParseFilter final : public drogon::HttpFilter<reqParseFilter>
{
  public:
      void doFilter(const HttpRequestPtr &req,
                    FilterCallback &&fcb,
                    FilterChainCallback &&fccb) override ;
};

