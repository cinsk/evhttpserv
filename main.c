#include <signal.h>
#include <errno.h>

#include <getopt.h>

#include "evhttp.h"
#include "xobstack.h"
#include "xerror.h"

int debug_mode = 1;

struct xobs pool;


int req_callback(struct ev_loop *loop, struct ev_httpconn *w,
                 int eob, int revents);
//static void sigint_cb(struct ev_loop *loop, ev_signal *w, int revents);


int
main(int argc, char *argv[])
{
  struct ev_loop *loop = EV_DEFAULT;
  ev_http http;

  xerror_init(0, 0);

  xdebug(0, "sizeof ev_httpconn: %zd", sizeof(struct ev_httpconn));

  if (argc != 2) {
    fprintf(stderr, "usage: %s port\n", argv[0]);
    return 1;
  }

  xobs_init(&pool);

  {
    struct sigaction sig;
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;
    sig.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sig, NULL) != 0)
      xdebug(errno, "sigaction failed");
    signal(SIGPIPE, SIG_IGN);
  }

  ev_http_init(&http, req_callback, "0.0.0.0", atoi(argv[1]), 8888);

  ev_http_start(loop, &http);

  ev_run(loop, 0);

  ev_http_stop(loop, &http);
  return 0;
}


int
req_callback(struct ev_loop *loop, struct ev_httpconn *w, int eob, int revents)
{
  xdebug(0, "req_callback (revents: %08x)", revents);

  if (revents & EV_TIMEOUT)
    return 0;

  else if (revents & EV_READ) {
    w->rsp_code = 200;
    xdebug(0, "Request(%s, %s): %s", w->method_string, w->version, w->uri);

#if 1
    {
      char *hdrs;
      hdrstore_fill(&w->req_hdrs, &pool, NULL, 0);
      xobs_1grow(&pool, '\0');
      hdrs = xobs_finish(&pool);
      fputs(hdrs, stderr);
      xobs_free(&pool, hdrs);
    }
#endif

    buffer_printf(&w->obuf, "<html><body>hello</body></html>\n");
    // sprintf(v, "%u", xobs_object_size(&w->rsp_pool));
    // hdrstore_set(&w->rsp_hdrs, "Content-Length", v);
    hdrstore_set(&w->rsp_hdrs, "Connection", "Keep-Alive");

    xobs_sprintf(&w->hdr_pool, "%zd", buffer_size(&w->obuf, NULL));
    hdrstore_set(&w->rsp_hdrs, "Content-Length", xobs_finish(&w->hdr_pool));
  }

  return 0;
}
