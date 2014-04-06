#ifndef EVHTTP_H__
#define EVHTTP_H__

#include <netinet/in.h>
#include <ev.h>

#include "xobstack.h"
#include "hdrstore.h"
#include "buffer.h"

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
 * When REVENTS contains EV_TIMER, it means that timeout occurred.
 * if the user returns zero, it means that user wants to let HTTP module
 * release the connection.  If not (nonzero), HTTP module will ignore the
 * timeout event just for this time.
 *
 * When REVENTS contains EV_READ, it means that a complete HTTP
 * request is ready to serve.  The user need to fill w->rsp_code with
 * the status code, w->rsp_hdrs with response headers, and w->obuf
 * with the response body.  If the user cannot provide the complete
 * response body, then the user need to fill it as much as he/she can,
 * then return from the callback with nonzero value.  If the callback
 * returns with zero, it means that the response body is completed.
 *
 * How to receive the response body:
 *
 *   If EOB is nonzero, then the whole request body is stored in
 *   w->ibuf.  If EOB is zero, then the partial request body is stored
 *   in w->ibuf.  In either case, the callback must read(consume) the
 *   contents in w->ibuf.  The callback need to just read the
 *   contents, since the buffer contents in w->ibuf will be
 *   automatically released.  If w->body_chnk is zero, it means that
 *   the response body is being transfered in identity encoding (as
 *   is, no transformation).
 *
 *   You may read w->body_chnk to determine whether the chunked
 *   transfer encoding is in effect.  Although I don't think that the
 *   callback need it.  Currently, as the callback's point of view,
 *   w->body_size and w->body_rest may be useless, since they will be
 *   updated after the callback is called.
 */
typedef int (*http_callback)(struct ev_loop *loop, struct ev_httpconn *w,
                             int eob,
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

#define HTTP_TE_MAX             4

#define HTTP_TE_NONE            0
#define HTTP_TE_IDENTITY        1
#define HTTP_TE_CHUNKED         2
#define HTTP_TE_GZIP            3
#define HTTP_TE_COMPRESS        4
#define HTTP_TE_DEFLATE         5
#define HTTP_TE_UNKNOWN         100

struct ev_http;

typedef enum {
  HC_INIT,
  HC_RECV_REQ,
  HC_RECV_BODY,
  HC_SEND_RSP,
  HC_SEND_BODY,
} HC_STATE;

struct ev_httpconn {
  ev_io io;
  ev_timer timer;

  ev_tstamp r_timeout;
  ev_tstamp w_timeout;

  ev_tstamp acc_time;

  struct ev_http *http;

  HC_STATE state;

  struct xobs hdr_pool; /* 1. keys and values from req_hdrs and rsp_hdrs.
                         * 2. if STATE is HC_SEND_RSP, this will contains
                         *    a growing object, which contains all headers
                         *    from rsp_hdrs. */

  char *hdr_pool_reset;         /* xobs_free()ing this one makes the
                                 * hdr_pool clean. */

  struct hdrstore req_hdrs;

  HTTP_METHOD method;
  char *method_string;
  char *uri;
  char *version;

  char req_te[HTTP_TE_MAX];

  /* When STATE is HC_RECV_BODY,
   * these three members (body_*) record the state of the receiving of
   * request body.  If BODY_CHNK is nonzero, it means that the TE of
   * current request body is 'chunked'.  BODY_SIZE is the size of the
   * current chunk, BODY_REST is the remaining bytes to complete the
   * current chunk.  If BODY_CHNK is zero (i.e. TE is 'identity'),
   * both BODY_SIZE and BODY_REST contain values of the whole body.
   *
   * When STATE is HC_SEND_RSP,
   * BODY_SIZE will contains the size of the RSP_LINE_HDRS, and
   * BODY_REST will contains the remaining bytes of RSP_LINE_HDRS
   * that is not sent yet.  The not-sent-part can be obtained
   * as RSP_LINE_HDRS[BODY_SIZE - BODY_REST] ... RSP_LINE_HDRS[BODY_SIZE] */
  ssize_t body_size;
  ssize_t body_rest;
  int     body_chnk;

  struct buffer ibuf;

  struct hdrstore rsp_hdrs;
  int rsp_code;
  int rsp_disconnect; /* if nonzero, the connection will be disconnected */

  char *rsp_line_hdrs;          /* points the buffer that contains
                                 * response line and response headers
                                 * allocated from HDR_POOL. */

  struct buffer obuf;           /* contains response body */
  int eob;                      /* nonzero means that end of response body. */
};
typedef struct ev_httpconn ev_httpconn;

struct ev_httpconnOLD {
  ev_io io;
  ev_timer timer;

  ev_tstamp r_timeout;
  ev_tstamp w_timeout;

  ev_tstamp acc_time;

  struct xobs str_pool;         /* most objects in STR_POOL will be invalidated
                                 * at every http request. */
  struct hdrstore headers;      /* headers of the http request.  Note
                                 * that this is the first object
                                 * allocated in STR_POOL per request.
                                 * Thus, releasing this object will
                                 * invalidate all objects allocated
                                 * from STR_POOL for the request. */
  int rsp_code;
  struct hdrstore rsp_hdrs;     /* headers of the http response. */

  struct xobs rsp_pool;         /* response buffer (dynamically
                                 * generated): first, user's response
                                 * body is filled here as a growing
                                 * object, then we will xobs_finish(),
                                 * then allocate storege for response
                                 * headers */

  /* Currently, the callback CB will update RSP_HDRS and RSP_POOL for
   * the response in addition to its return value.  There is no way
   * for CB to pass a file descriptor to serve the response with the
   * regular file.  If we are to deal all regular file ourselves, it
   * would be fine with the current design.  If not, we need to
   * provides some way to CB to pass the file descriptor.
   */
#if 1
  struct {
    unsigned states;

    char *buf;
    char *bufend;
    char *sent;

    char *hdrs;
    char *hdrsend;
    char *body;
    char *bodyend;

    int fd;
#if 0
    char *body;                 /* if BODY is (char *)-1, then call sendfile(2)
                                 * with BODYFD and OFFSET */
    // int fd;

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
#endif  /* 0 */
  } rsp;
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

  ssize_t body_size;           /* size of the current body or chunk */
  ssize_t body_rest; /* size of remaining bytes of the body or chunk */
  int chunked;       /* if nonzero, body_size and body_rest are for
                        the current chunk */
};
typedef struct ev_httpconn ev_httpconnOLD;

struct ev_http {
  ev_io io;
  char address[INET_ADDRSTRLEN];
  int port;

  int obufsize;
  int ibufsize;

  http_callback cb;
};
typedef struct ev_http ev_http;

int ev_http_init(ev_http *http, http_callback cb, char *address, int port);
void ev_http_start(struct ev_loop *loop, ev_http *http);
void ev_http_stop(struct ev_loop *loop, ev_http *http);



#endif /* EVHTTP_H__ */
