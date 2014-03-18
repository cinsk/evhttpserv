#ifndef EVHTTP_H__
#define EVHTTP_H__

#include <netinet/in.h>
#include <ev.h>

#include "xobstack.h"
#include "hdrstore.h"

enum HTTP_METHOD {
  HM_NONE,
  HM_GET,
  HM_HEAD,
  HM_POST,
  HM_PUT,
  HM_DEBUG_CAT,
  HM_OPTIONS,
  HM_DELETE,
  HM_TRACE,
  HM_UNKNOWN = 100,
};
typedef enum HTTP_METHOD HTTP_METHOD;



struct ev_httpconn;
/*
 * when REVENTS contains EV_TIMER, it means that timeout occurred.
 * if the user returns zero, it means that user wants to let HTTP module
 * release the connection.  If not (nonzero), HTTP module will ignore the
 * timeout event just for this time.
 */
typedef int (*http_callback)(struct ev_loop *loop, struct ev_httpconn *w,
                             int revents);

/*
  struct ev_httpconn {
    ev_io read;      // watcher for reading
    ev_io write;     // watcher for writing
    ...
  };

  struct ev_httpconn {
    ev_io io;        // watcher for reading/writing at the same time
    ...
  };

  // this will be my choice.
  struct ev_httpconn {
    ev_io io;        // watcher for reading/writing
                     // start/stop for reading, then start/stop for writing
    ...
  };
 */

struct ev_httpconn {
  ev_io io;
  ev_timer timer;

  ev_tstamp r_timeout;
  ev_tstamp w_timeout;

  ev_tstamp acc_time;

  struct hdrstore headers;
  struct xobs str_pool;

  struct xobs rsp_pool;         /* response buffer (dynamically generated) */

#if 0
  struct {
    char *body;                 /* if BODY is (char *)-1, then call sendfile(2)
                                 * with BODYFD and OFFSET */
    int bodyfd;

    char *headers;           /* response-line plus response headers */
    size_t size;             /* if HEADERS is non-null,
                              * SIZE represents the size of the
                              * contents starting from HEADERS.
                              * Otherwise, it represents the size
                              * of the contents starting from
                              * BODY. */
    off_t offset;               /* if HEADERS is non-null, OFFSET
                                 * points the offset of remaining data
                                 * in HEADERS.  Otherwise, OFFSET
                                 * points the offset of remaining data
                                 * in rsp_body. */
  } resp;
#else
  int rsp_fd;                   /* response fd (static) */
  off_t rsp_off;                /* offset that starts the sending block */
#endif

  char *cli_address;
  int cli_port;

  http_callback cb;


  HTTP_METHOD method;
  /* Theses three represents the Request-Line, and the pointed memory is
   * in INBUF. (no need to release) */
  char *method_string;
  char *uri;
  char *version;

  char *begin, *end, *cur;

  size_t inbuf_size;
  char inbuf[0];
};
typedef struct ev_httpconn ev_httpconn;

struct ev_http {
  ev_io io;
  char address[INET_ADDRSTRLEN];
  int port;

  http_callback cb;
};
typedef struct ev_http ev_http;

int ev_http_init(ev_http *http, http_callback cb, char *address, int port);
void ev_http_start(struct ev_loop *loop, ev_http *http);
void ev_http_stop(struct ev_loop *loop, ev_http *http);



#endif /* EVHTTP_H__ */
