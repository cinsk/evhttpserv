#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "evhttp.h"
#include "evhttpconn.h"

#include "xerror.h"


#ifdef __GNUC__
#ifndef offsetof
#define offsetof(type, member)  __builtin_offsetof(type, member)
#endif
#endif


#define CRLF    "\r\n"
#define CRLFLEN (sizeof(CRLF) - 1)

#define CRLF2    "\r\n\r\n"
#define CRLF2LEN (sizeof(CRLF2) - 1)


#define IS_RECVING(hc)  ((hc)->io.events & EV_READ)
#define IS_SENDING(hc)  ((hc)->io.events & EV_WRITE)


#define RSP_SENDING_HDRS        0x01
#define RSP_SENDING_BODY        0x02
#define RSP_SENDING_MASK        (RSP_SENDING_HDRS | RSP_SENDING_BODY)
#define RSP_USE_COPYFILE        0x04
#define RSP_USERCB_FIN          0x08

#define RSP_SENDING(s, x)       do {            \
    s = ((s & (~RSP_SENDING_MASK)) | x);        \
  } while (0)

static __inline__ void set_response(ev_httpconn *hc,
                                    int rsp_code, int disconnect);
static int load_req_line_headers(ev_httpconn *hc, char *req);
static __inline__ void set_content_length(ev_httpconn *hc);
static __inline__ void do_callback(struct ev_loop *loop,
                                   ev_httpconn *hc, int eob);

static void ev_httpconn_toggle_readwrite(struct ev_loop *loop, ev_httpconn *hc);

static void ev_httpconn_write_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_httpconn_read_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_httpconn_timer_cb(struct ev_loop *loop,
                                 ev_timer *w, int revents);

static const char *method2str(HTTP_METHOD method);
static HTTP_METHOD str2method(const char *method);
static __inline__ int str2te(const char *s);

static __inline__ void set_response(ev_httpconn *hc,
                                    int rsp_code, int disconnect);
static __inline__ int get_te(ev_httpconn *hc, int index);


#if 0
static int
httpconnOLD_set_endpoint(ev_httpconnOLD *hc)
{
  struct sockaddr_storage addr;
  socklen_t len = sizeof(addr);

  if (getpeername(hc->io.fd, (struct sockaddr *)&addr, &len) != 0) {
    xerror(0, errno, "getpeername(%d, ...) failed", hc->io.fd);
    return -1;
  }

  hc->cli_address = xobs_alloc(&hc->str_pool, INET6_ADDRSTRLEN);
  if (!hc->cli_address) {
    xerror(0, errno, "http_set_endpoint: out of memory");
    return -1;
  }
  if (addr.ss_family == AF_INET) {
    struct sockaddr_in *s = (struct sockaddr_in *)&addr;
    hc->cli_port = ntohs(s->sin_port);
    inet_ntop(AF_INET, &s->sin_addr, hc->cli_address, INET6_ADDRSTRLEN);
  }
  else {                      /* AF_INET6 */
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
    hc->cli_port = ntohs(s->sin6_port);
    inet_ntop(AF_INET6, &s->sin6_addr, hc->cli_address, INET6_ADDRSTRLEN);
  }
  return 0;
}
#endif  /* 0 */


/*
 * Get the INDEX-th Transfer Encoding.
 *
 * If INDEX is negative, it is considered from the end of the actual TE.
 * For example, get_te(hc, -1) will return the last Transfer-Encoding.
 */
static __inline__ int
get_te(ev_httpconn *hc, int index)
{
  int i;

  for (i = HTTP_TE_MAX - 1; i >= 0; i--) {
    if (hc->req_te[i] != HTTP_TE_NONE)
      break;
  }

  assert(i == 0 && hc->req_te[0] != HTTP_TE_NONE);

  if (index < 0)
    index += i + 1;

  assert(index >= 0);

  return hc->req_te[index];
}


int
ev_httpconn_init(ev_httpconn *hc, struct ev_http *http, int fd)
{
  ev_io_init(&hc->io, ev_httpconn_read_cb, fd, EV_READ);

  hc->r_timeout = 10;
  hc->w_timeout = 10;

  ev_timer_init(&hc->timer, ev_httpconn_timer_cb,
                hc->r_timeout, hc->r_timeout);

  hc->acc_time = 0;
  hc->http = http;

  hc->state = HC_INIT;

  if (!xobs_init(&hc->hdr_pool))
    return 0;
  hc->hdr_pool_reset = xobs_alloc(&hc->hdr_pool, 1);

  hdrstore_init(&hc->req_hdrs, &hc->hdr_pool);

  hc->method = HM_NONE;
  hc->method_string = hc->uri = hc->version = 0;

  memset(hc->req_te, HTTP_TE_NONE, HTTP_TE_MAX);

  hc->body_size = -1;
  hc->body_rest = -1;
  hc->body_chnk = 0;

  buffer_init(&hc->ibuf, http->ibufsize);

  hdrstore_init(&hc->rsp_hdrs, &hc->hdr_pool);
  hc->rsp_code = 0;
  hc->rsp_disconnect = 0;

  hc->rsp_line_hdrs = 0;
  buffer_init(&hc->obuf, http->obufsize);
  hc->eob = 0;

  return 1;
}


void
ev_httpconn_start(struct ev_loop *loop, ev_httpconn *hc)
{
  hc->state = HC_RECV_REQ;
  ev_io_start(loop, &hc->io);
  ev_timer_start(loop, &hc->timer);
}

void
ev_httpconn_stop(struct ev_loop *loop, ev_httpconn *hc)
{
  xdebug(0, "ev_httpconn_stop for fd(%d)", hc->io.fd);
  ev_io_stop(loop, &hc->io);
  ev_timer_stop(loop, &hc->timer);

  if (close(hc->io.fd) == -1)
    xdebug(errno, "close(%d) failed", hc->io.fd);

  /* TODO: release everything */
  xobs_free(&hc->hdr_pool, 0);

  buffer_clear(&hc->ibuf);
  buffer_clear(&hc->obuf);

  /* Since all ev_httpconn struct is allocate via malloc(3) from
   * ev_http module, it should be released here, I think. */

  /* TODO: do I call some callback from user-side? */

  free(hc);
}


static __inline__ void
ev_httpconn_reset(struct ev_httpconn *hc, int clear_ibuf)
{
  /* TODO: do I need to call ev_clear_pending()? */

  xobs_free(&hc->hdr_pool, hc->hdr_pool_reset);
  hc->hdr_pool_reset = xobs_alloc(&hc->hdr_pool, 1);
  hdrstore_free(&hc->req_hdrs, 1);
  hdrstore_free(&hc->rsp_hdrs, 1);
  hc->method = HM_NONE;
  hc->method_string = hc->uri = hc->version = 0;

  memset(hc->req_te, HTTP_TE_NONE, HTTP_TE_MAX);

  hc->body_size = -1;
  hc->body_rest = -1;
  hc->body_chnk = 0;

  if (clear_ibuf)
    buffer_clear(&hc->ibuf);

  hc->rsp_code = 0;
  hc->rsp_disconnect = 0;

  hc->rsp_line_hdrs = 0;
  buffer_clear(&hc->obuf);
  hc->eob = 0;

  /* TODO: do I need to check that hc->io is in EV_READ state? */
}


static void
ev_httpconn_toggle_readwrite(struct ev_loop *loop, ev_httpconn *hc)
{
  ev_io_stop(loop, &hc->io);

  if (hc->io.cb == ev_httpconn_read_cb) {
    if (hc->state == HC_SEND_RSP) {
      // Transition from HC_RECV_RSP|HC_RECV_BODY.

      /* TODO: make sure that required members in HC are actually right. */
      if (0 /* some members in HC is not set correctly */) {
        /* TODO: what now? */
        set_response(hc, HTTP_INTERNAL_SERVER_ERROR, 1);
        /* TODO: maybe we can write the reason using xdebug()? */
      }
      else {
        assert(xobs_object_size(&hc->hdr_pool) == 0);
        hdrstore_fill(&hc->rsp_hdrs, &hc->hdr_pool, hc->version, hc->rsp_code);

        hc->body_size = hc->body_rest = xobs_object_size(&hc->hdr_pool);
        hc->rsp_line_hdrs = xobs_finish(&hc->hdr_pool);
      }
    }

    ev_set_cb(&hc->io, ev_httpconn_write_cb);
    ev_io_set(&hc->io, hc->io.fd, EV_WRITE);
  }
  else {
    if (hc->state == HC_RECV_REQ) {
      /* TODO: reset httpconn to the initial state!!! */
      ev_httpconn_reset(hc, 0);
      if (buffer_size(&hc->ibuf, NULL) > 0)
        ev_feed_event(loop, &hc->io, EV_READ | EV_CUSTOM);
    }
    else
      abort();

    ev_set_cb(&hc->io, ev_httpconn_read_cb);
    ev_io_set(&hc->io, hc->io.fd, EV_READ);
    /* TODO: not implemented yet */
  }
  ev_io_start(loop, &hc->io);
}

static struct {
  const char *name;
  HTTP_METHOD method;
} http_methods[] = {
#define P(x)    { #x, HM_ ## x }
  P(GET),
  P(HEAD),
  P(POST),
  P(PUT),
  P(DEBUG_CAT),
  P(OPTIONS),
  P(DELETE),
  P(TRACE),
  P(NONE),
  { 0, HM_UNKNOWN },
};


static const char *
method2str(HTTP_METHOD method)
{
  int i = 0;
  while (http_methods[i].name != 0) {
    if (http_methods[i].method == method)
      return http_methods[i].name;
  }
  return "UNKNOWN";
}

static HTTP_METHOD
str2method(const char *method)
{
  int i = 0;

  if (!method)
    return HM_NONE;

  while (http_methods[i].name != 0) {
    if (strcmp(http_methods[i].name, method) == 0)
      return http_methods[i].method;
  }
  return HM_UNKNOWN;
}


static __inline__ void
set_response(ev_httpconn *hc, int rsp_code, int disconnect)
{
  hc->rsp_code = rsp_code;
  hc->rsp_disconnect = disconnect;

  /* TODO: Fill hc->obuf with the pre-generated body depending on
   *       rsp_code */
  hc->eob = 1;
}


static void
ev_httpconn_write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  ev_httpconn *hc = (ev_httpconn *)(((char *)w) - offsetof(ev_httpconn, io));
  ssize_t written;

  if (!(revents & EV_WRITE)) {
    xdebug(0, "ev_httpconn_write_cb: receives revents, %x", revents);
    return;
  }
  assert(hc->state == HC_SEND_RSP || hc->state == HC_SEND_BODY);

  hc->acc_time = ev_now(loop);

  if (hc->state == HC_SEND_RSP) {
    /* hc->body_size is the size of the hc->rsp_line_hdrs,
     * and we need to send data in hc->rsp_line_hdrs with range between
     * (hc->body_size - hc->body_rest) and hc->body_size. */

    written = write(hc->io.fd,
                    hc->rsp_line_hdrs + hc->body_size - hc->body_rest,
                    hc->body_rest);

    if (written == -1) {
      if (errno == EINTR || errno == EAGAIN)
        return;
      if (errno != ECONNRESET)
        xdebug(errno, "ev_httpconn_write_cb: write(2) failed");
      ev_httpconn_stop(loop, hc);
    }
    else {
      hc->body_rest -= written;
      if (hc->body_rest <= 0) {
        hc->state = HC_SEND_BODY;

        hc->body_size = hc->body_rest = buffer_size(&hc->obuf, NULL);
        hc->body_chnk = (hc->eob == 0);
        goto send_body;
      }
      return;
    }
  }
  else {
  send_body:
    /* TODO: call buffer_flush() here. */

    if (hc->body_chnk) {
      // TODO: add the chunk size in backpad area of the first bufnode
      //       in OBUF.

      abort();                  /* TODO: implement */
    }
    else {
      written = buffer_flush(&hc->obuf, NULL, NULL, hc->io.fd);
      if (written == -1) {
        xdebug(errno, "buffer_flush() failed");
        ev_httpconn_stop(loop, hc);
        return;
      }
      hc->body_rest -= written;
      if (hc->body_rest <= 0) {
        if (hc->eob) {
          if (hc->rsp_disconnect) {
            ev_httpconn_stop(loop, hc);
            return;
          }
          else {
            hc->state = HC_RECV_REQ;
            ev_httpconn_toggle_readwrite(loop, hc);
            return;
          }
        }
        else { /* We've send everything we have, but it may be not finished. */
          do_callback(loop, hc, 1);
          /* TODO */
          return;
        }
      }
    }
  }
}

/*
 * Set several parameters for receving request body.
 *
 * On success, it returns nonzero.  Otherwise it returns zero.  In
 * case of error, you should transfer the control to
 * sending-response-header.
 */
static int
set_reqbody_params(ev_httpconn *hc)
{
  const char *val;
  ssize_t sz;

  if (get_te(hc, -1) != HTTP_TE_CHUNKED) {
    val = hdrstore_get(&hc->req_hdrs, "Content-Length");
    if (!val) {
      set_response(hc, HTTP_LENGTH_REQUIRED, 1);
      goto err;
    }
    sz = atoi(val);
    if (sz < 0) {    /* TODO: rsp_code is right here? */
      set_response(hc, HTTP_LENGTH_REQUIRED, 1);
      goto err;
    }
    hc->body_size = hc->body_rest = sz;
    hc->body_chnk = 0;
  }
  else {
    hc->body_size = hc->body_rest = -1;
    hc->body_chnk = 1;
  }
  return 1;

 err:
  hc->state = HC_SEND_RSP;
  return 0;
}


struct sipair {
  const char *s;
  int i;
};

struct sipair tepairs[] = {
  { "identity", HTTP_TE_IDENTITY },
  { "chunked", HTTP_TE_CHUNKED },
  { "gzip", HTTP_TE_GZIP },
  { "compress", HTTP_TE_COMPRESS },
  { "deflate", HTTP_TE_DEFLATE },
};

static __inline__ int
str2te(const char *s)
{
  int i;
  for (i = 0; i < sizeof(tepairs) / sizeof(tepairs[0]); i++) {
    if (strcasecmp(s, tepairs[i].s) == 0)
      return tepairs[i].i;
  }
  return HTTP_TE_UNKNOWN;
}


/* Load request line and headers in req
 *
 * If loading failed (mostly due to malformed request), this function
 * sets hc->rsp_code and possibly hc->rsp_disconnect, then returns 0.
 * Otherwise (on success), it returns nonzero.  */
static int
load_req_line_headers(ev_httpconn *hc, char *req)
{
  char *line, *saveptr1, *saveptr2;
  char *name, *value;
  int teval;
  char *te = hc->req_te;

  if (!req)
    return 0;

  line = strtok_r(req, "\r\n", &saveptr1);

  hc->method_string = strtok_r(line, " \t", &saveptr2);
  hc->method = str2method(hc->method_string);
  if (hc->method == HM_NONE)
    goto reqline_err;

  hc->uri = strtok_r(NULL, " \t", &saveptr2);
  if (!hc->uri) goto reqline_err;
  hc->version = strtok_r(NULL, " \t", &saveptr2);
  if (!hc->version) goto reqline_err;

  while ((line = strtok_r(NULL, "\r\n", &saveptr1)) != 0) {
    name = line + strspn(line, " \t");
    value = strchr(name, ':');
    if (!value) {
      xdebug(0, "request header has no value: |%s|", line);
      continue;
    }
    *value = '\0';
    value++;
    value += strspn(value, " \t");

    if (strcmp(name, "Transfer-Encoding") == 0) {
      teval = str2te(value);
      if (teval == HTTP_TE_UNKNOWN) {
        set_response(hc, HTTP_NOT_IMPLEMENTED, 1);
        return 0;
      }

      if (te < hc->req_te + HTTP_TE_MAX)
        *te++ = teval;
      else {
        /* Too many Transfer-Encoding headers */
        set_response(hc, HTTP_BAD_REQUEST, 1); /* TODO: is this code right? */
        return 0;
      }
    }
    else
      hdrstore_set(&hc->req_hdrs, name, value);
  }

  {
    const char *val;

    val = hdrstore_get(&hc->req_hdrs, "Connection");
    if (val && strcmp(val, "close") == 0)
        hc->rsp_disconnect = 1;
    else if (strcmp(hc->version, "HTTP/1.0") == 0)
        hc->rsp_disconnect = 1;
  }

  return 1;

 reqline_err:
  set_response(hc, HTTP_BAD_REQUEST, 1);
  return 0;
}


static __inline__ void
set_content_length(ev_httpconn *hc)
{
  assert(hc->eob == 1);
  assert(xobs_object_size(&hc->hdr_pool) == 0);
  xobs_sprintf(&hc->hdr_pool, "%zu", buffer_size(&hc->obuf, NULL));
  hdrstore_set(&hc->rsp_hdrs, "Content-Length", xobs_finish(&hc->hdr_pool));
}


static __inline__ void
do_callback(struct ev_loop *loop, ev_httpconn *hc, int eob)
{
  /* TODO: handle static contents */
  /* TODO: handle pattern matching to find-out the exact CB. */

  /* TODO: how to pass EOB to the callback? */
  if (hc->http->cb(loop, hc, eob, EV_READ | EV_CUSTOM) == 0) {
    hc->eob = 1;

    // if (!hc->body_chnk && calc_len) set_content_length(hc);
  }
}


static void
ev_httpconn_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  ev_httpconn *hc = (ev_httpconn *)(((char *)w) - offsetof(ev_httpconn, io));
  bufpos found;
  ssize_t readch;
  int eof;

  if (!(revents & EV_READ)) {
    xdebug(0, "ev_httpconn_read_cb: receives revents %x", revents);
    return;
  }

  assert(hc->state == HC_RECV_REQ || hc->state == HC_RECV_BODY);

  hc->acc_time = ev_now(loop);

  if (hc->state == HC_RECV_REQ) {
    readch = buffer_fill_fd(&hc->ibuf, w->fd, hc->http->ibufsize, &eof);
    if (readch == -1) {
      xdebug(errno, "read failed (errno=%d)", errno);
      ev_httpconn_stop(loop, hc);
      return;
    }
    else if (eof) {
#ifndef NDEBUG
      if (buffer_size(&hc->ibuf, NULL) > 0)
        xdebug(0, "premature EOF");
#endif
      ev_httpconn_stop(loop, hc);
      return;
    }

    /* TODO: implement 5th arg of buffer_find()? */
    if (!buffer_find(&hc->ibuf, CRLF2, CRLF2LEN, &found, NULL))
      return;

    buffer_copy(&hc->hdr_pool, &hc->ibuf, &found);

    {
      /* Do we need to keep the ptr to the below xobs chunk?  It will
       * be release when the request is processed anyway. */
      // size_t hdrs_sz = xobs_object_size(&hc->hdr_pool);
      char *req;
      xobs_1grow(&hc->hdr_pool, '\0');
      req = xobs_finish(&hc->hdr_pool);
      load_req_line_headers(hc, req);
    }

    buffer_advance(&hc->ibuf, found.node, found.ptr, CRLF2LEN);

    if (hc->method != HM_POST || hc->method != HM_PUT) {
      do_callback(loop, hc, 1);

      hc->state = HC_SEND_RSP;
      ev_httpconn_toggle_readwrite(loop, hc);
      return;
    }

    hc->state = HC_RECV_BODY;

    if (!set_reqbody_params(hc)) {
      hc->state = HC_SEND_RSP;
      ev_httpconn_toggle_readwrite(loop, hc);
      return;
    }

    goto recv_body;
  }
  else if (hc->state == HC_RECV_BODY) {
    if (buffer_fill_fd(&hc->ibuf, w->fd, hc->http->ibufsize, &eof) == -1) {
      xdebug(errno, "read failed (errno=%d)", errno);
      ev_httpconn_stop(loop, hc);
      return;
    }
    else if (eof) {
      xdebug(0, "premature EOF");
      ev_httpconn_stop(loop, hc);
      return;
    }

  recv_body: /* TODO: am I sure that this label is after buffer_fill_fd()? */

    if (hc->body_chnk) {            /* chunked encoding */
      abort();                      /* TODO: implement */
    }
    else {
      if (hc->body_rest > 0) {
        bufpos pos;
        size_t remains = buffer_seek(&hc->ibuf, hc->body_rest, SEEK_SET, &pos);
        if (remains == 0) {
          // we got the whole body.
          do_callback(loop, hc, 1);
        }
        else {
          // we have the partial body.
          do_callback(loop, hc, 0);
        }
        buffer_advance(&hc->ibuf, pos.node, pos.ptr, 0);
        hc->body_rest -= remains;
      }
    }
  }
#if 0
    /*
      first:
         condition: (body_size == -1 && chunk_size == -1)

         body_size(-1), body_rest(-1), chunk_size(-1), chunk_rest(-1)

         if (te[-1] == chunked) {
           chunk_size = get_chunk_size(inbuf);
           if (not_complete)
             feed EV_READ, return

           // body_size(-1), body_rest(-1), chunk_size(NN), chunk_rest(MM)
         }
         else {
           body_size = Content-Length;
           body_rest = count_inbuf();

           // body_size(AA), body_rest(BB), chunk_size(-1), chunk_rest(-1)
         }

      subsequent calls:
        condition: (body_size != -1 || chunk_size != -1)

        if (body_size) {

        }
     */
    val = hdrstore_get(&hc->req_hdrs, "Content-Length");
    if (val)
      hc->body_size = atoi(val);

    if (hc->req_body_size == -1) {
      /* TODO: check if Transfer-Encoding has at least HTTP_TE_CHUNKED */
      if (get_te(hc, -1) != HTTP_TE_CHUNKED) {
        /* 411 Length Required */
        set_response(hc, HTTP_LENGTH_REQUIRED, 1);
        hc->state = HC_SEND_RSP;
        // toggle_readwrite
        return;
      }
      else {
        /* TODO: need to receive chunked request body using hc->req_next_chunk */
#if 0
        if (hc->req_chunk_remains) { /* we are reading middle of a chunk */
        }
        else {
          bufpos pos;
          hc->req_chunk_size = next_chunk_size(hc->inbuf, &pos);
          hc->req_body_rest = hc->req_chunk_size;

          if (hc->req_chunk_size == 0) { /* we are done */
            if (hc->req_body_rest > 0) {
              // TODO: feed ibuf[...hc->req_body_rest]
            }
            hc->state = HC_SEND_RSP;
            // TODO: toggle_readwrite
          }
          else {
            remains = buffer_byte_count(&hc->ibuf, pos);
            if (remains < hc->req_body_rest) {
              /* we haven't received a complete chunk */
              // TODO: feed ibuf[pos...end-of-buffer] to user CB.
              hc->req_body_rest -= remains;
            }
            else {
              // TODO: feed ibuf[pos...pos + hc->req_body_rest]
              hc->req_body_rest = 0;
              // TODO: feed EV_READ
            }
          }
#endif  /* 0 */
        }
      }
    }
    else {
      remains = buffer_byte_count(&hc->ibuf, NULL);

      if (remains >= hc->req_body_size) {
        /* we've received a complete request body */
        // feed ibuf[...remains] to user CB
        hc->state = HC_SEND_RSP;
        // TODO: toggle_readwrite
      }
      else {

      }
    }
  }
#endif  /* 0 */
}


static void
ev_httpconn_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
  ev_httpconn *hc = (ev_httpconn *)(((char *)w) - offsetof(ev_httpconn, timer));
  ev_tstamp after = hc->acc_time - ev_now(loop) +
    ((hc->io.events & EV_READ) ? hc->r_timeout : hc->w_timeout);

  if (after < 0.) {             /* timeout occurred */
    /* TODO: now what? */
    xdebug(0, "%c_timeout for fd %d",
           ((hc->io.events & EV_READ) ? 'r' : 'w'), hc->io.fd);

    if (!hc->http->cb(loop, hc, 0, EV_TIMER)) {
      /* The user agreed to release the connection */
      xdebug(0, "close the connection (reason = timeout)");
      ev_httpconn_stop(loop, hc);
      return;
    }
  }
  ev_timer_set(&hc->timer, after, 0);
  ev_timer_start(loop, w);

}
