/*
 * libev-based HTTP server implementation
 * Copyright (C) 2014  Seong-Kook Shin <cinsky@gmail.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <signal.h>
#include <errno.h>

#include <getopt.h>

#include "evhttp.h"
#include "xobstack.h"
#include "xerror.h"
#include "buffer.h"

int debug_mode = 1;

struct xobs pool;


int req_callback(struct ev_loop *loop, struct ev_httpconn *w,
                 int eob, int revents);

static void sigint_cb(struct ev_loop *loop, ev_signal *w, int revents);

ev_http http;
ev_signal sigint_watcher;

int
main(int argc, char *argv[])
{
  struct ev_loop *loop = EV_DEFAULT;

  xerror_init(0, 0);

  xdebug(0, "sizeof ev_httpconn: %zd", sizeof(struct ev_httpconn));

  if (argc != 3) {
    fprintf(stderr, "usage: %s port nthread\n", argv[0]);
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

  // ev_set_io_collect_interval(loop, 0.000001);

  ev_http_init(&http, atoi(argv[2]), req_callback, "0.0.0.0", atoi(argv[1]), -1);
  ev_signal_init(&sigint_watcher, sigint_cb, SIGINT);

  ev_http_start(loop, &http);
  ev_signal_start(loop, &sigint_watcher);
  ev_unref(loop);

  ev_run(loop, 0);

  ev_http_stop(loop, &http);

  xdebug(0, "evhttp terminated normally");

  ev_loop_destroy(loop);
  xobs_free(&pool, 0);
  return 0;
}


int
req_callback(struct ev_loop *loop, struct ev_httpconn *w, int eob, int revents)
{
  xdebug(0, "req_callback (revents: %08x)", revents);

  if (revents & EV_TIMEOUT)
    return 0;

  else if (revents & EV_READ) {

    if (w->method == HM_GET) {
      w->rsp_code = HTTP_OK;
      xdebug(0, "Request(%s, %s): %s", w->method_string, w->version, w->uri);
      buffer_printf(&w->obuf, "<html><body>hello</body></html>\n");
      // sprintf(v, "%u", xobs_object_size(&w->rsp_pool));
      // hdrstore_set(&w->rsp_hdrs, "Content-Length", v, 0);
      hdrstore_set(&w->rsp_hdrs, "Connection", "Keep-Alive", 0);

      xobs_sprintf(&w->hdr_pool, "%zd", buffer_size(&w->obuf, NULL));
      hdrstore_set(&w->rsp_hdrs, "Content-Length",
                   xobs_finish(&w->hdr_pool), 0);
    }
    else if (w->method == HM_POST) {
      if (w->form)
        form_dump(stderr, w->form);

      xobs_sprintf(&w->hdr_pool, "%zd", buffer_size(&w->obuf, NULL));
      hdrstore_set(&w->rsp_hdrs, "Content-Length",
                   xobs_finish(&w->hdr_pool), 0);
      w->rsp_code = HTTP_OK;
    }
    else {
      w->rsp_code = HTTP_NOT_IMPLEMENTED;
    }

  }

  return 0;
}


static void
sigint_cb(struct ev_loop *loop, ev_signal *w, int revents)
{
  //ev_http_stop(loop, &http);
  xdebug(0, "SIGINT received");
  ev_http_break(loop, &http);
}
