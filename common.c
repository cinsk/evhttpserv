#include <stdlib.h>
#include "common.h"

struct statuscode_pair {
  int code;
  char *desc;
} statuscodes[] = {
  { 100, "Continue" },
  { 101, "Switching Protocols" },
  { 200, "OK" },
  { 201, "Created" },
  { 202, "Accepted" },
  { 203, "Non-Authoritative Information" },
  { 204, "No Content" },
  { 205, "Reset Content" },
  { 206, "Partial Content" },
  { 300, "Multiple Choices" },
  { 301, "Moved Permanently" },
  { 302, "Moved Temporarily" },
  { 303, "See Other" },
  { 304, "Not Modified" },
  { 305, "Use Proxy" },
  { 400, "Bad Request" },
  { 401, "Unauthorized" },
  { 402, "Payment Required" },
  { 403, "Forbidden" },
  { 404, "Not Found" },
  { 405, "Method Not Allowed" },
  { 406, "Not Acceptable" },
  { 407, "Proxy Authentication Required" },
  { 408, "Request Time-out" },
  { 409, "Conflict" },
  { 410, "Gone" },
  { 411, "Length Required" },
  { 412, "Precondition Failed" },
  { 413, "Request Entity Too Large" },
  { 414, "Request-URI Too Large" },
  { 415, "Unsupported Media Type" },
  { 500, "Internal Server Error" },
  { 501, "Not Implemented" },
  { 502, "Bad Gateway" },
  { 503, "Service Unavailable" },
  { 504, "Gateway Time-out" },
  { 505, "HTTP Version not supported" },
};


static int
statuscode_cmp(const void *l, const void *r)
{
  struct statuscode_pair *lhs = (struct statuscode_pair *)l;
  struct statuscode_pair *rhs = (struct statuscode_pair *)r;
  return lhs->code - rhs->code;
}


const char *
statuscode2str(int statuscode)
{
  static size_t npairs = sizeof(statuscodes) / sizeof(statuscodes[0]);
  struct statuscode_pair *r;

  r = bsearch(&statuscode, statuscodes,
              npairs, sizeof(statuscodes[0]), statuscode_cmp);
  if (r)
    return r->desc;
  return "UNKNOWN";
}
