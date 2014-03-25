#include <signal.h>
#include <errno.h>

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
    char *v = xobs_alloc(&w->rsp_pool, 30);

    w->rsp_code = 200;
    xdebug(0, "Request(%s): %s", w->method_string, w->uri);
    xobs_sprintf(&w->rsp_pool, "<html><body>hello</body></html>");

    sprintf(v, "%u", xobs_object_size(&w->rsp_pool));
    hdrstore_set(&w->rsp_hdrs, "Content-Length", v);
    hdrstore_set(&w->rsp_hdrs, "Connection", "Keep-Alive");
  }

  return 0;
}


int
main(int argc, char *argv[])
{
  struct ev_loop *loop = EV_DEFAULT;
  ev_http http;

  xerror_init(0, 0);

  xdebug(0, "sizeof ev_httpconn: %zd", sizeof(struct ev_httpconn));

  {
    struct sigaction sig;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;
    sig.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sig, NULL) != 0)
      xdebug(errno, "sigaction failed");
  }


  ev_http_init(&http, my_callback, "0.0.0.0", 8080);

  ev_http_start(loop, &http);

  ev_run(loop, 0);

  ev_http_stop(loop, &http);
  return 0;
}
