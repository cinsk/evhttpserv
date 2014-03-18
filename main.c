#include "evhttp.h"
#include "xerror.h"

int debug_mode = 1;

int
my_callback(struct ev_loop *loop, struct ev_httpconn *w, int revents)
{
  xdebug(0, "my_callback (revents: %08x)", revents);

  if (revents & EV_TIMEOUT)
    return 0;

  else if (revents & EV_READ) {
    /* For debugging, just copy the request into the response */
    xdebug(0, "Request(%s): %s", w->method_string, w->uri);
    xobs_sprintf(&w->rsp_pool, "HTTP/1.1 200 OK\r\n\r\n");
  }

  return 1;
}


int
main(int argc, char *argv[])
{
  struct ev_loop *loop = EV_DEFAULT;
  ev_http http;

  xerror_init(0, 0);

  xdebug(0, "sizeof ev_httpconn: %zd", sizeof(struct ev_httpconn));

  ev_http_init(&http, my_callback, "0.0.0.0", 8080);

  ev_http_start(loop, &http);

  ev_run(loop, 0);

  ev_http_stop(loop, &http);
  return 0;
}
