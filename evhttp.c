#define _GNU_SOURCE

#include <assert.h>
#include <string.h>

#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "evhttp.h"

#include "xerror.h"

#ifdef __GNUC__
#ifndef offsetof
#define offsetof(type, member)  __builtin_offsetof(type, member)
#endif
#endif

#ifndef RCVBUF_SIZE
#define RCVBUF_SIZE     8196
#endif

#ifndef SNDBUF_SIZE
#define SNDBUF_SIZE     8196
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

static void get_buf_size(int fd, int *rdbuf_size, int *wrbuf_size);
static int tcp_listen(const char *address, int port, int flags);
static void ev_http_io_cb(struct ev_loop *loop, ev_io *w, int revents);

static void ev_httpconn_write_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_httpconn_read_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_httpconn_timer_cb(struct ev_loop *loop, ev_timer *w, int revents);

static const char *method2str(HTTP_METHOD method);
static HTTP_METHOD str2method(const char *method);

int
ev_http_init(ev_http *http, http_callback cb, char *address, int port)
{
  int fd;

  strncpy(http->address, address, INET_ADDRSTRLEN - 1);
  http->address[INET_ADDRSTRLEN - 1] = '\0';
  http->port = port;
  http->cb = cb;

  fd = tcp_listen(address, port, O_NONBLOCK);
  if (fd == -1) {
    xdebug(errno, "tcp_listen(%s, %d) failed", address, port);
    return -1;
  }

  ev_io_init(&http->io, ev_http_io_cb, fd, EV_READ);
  return 0;
}


void
ev_http_start(struct ev_loop *loop, ev_http *http)
{
  ev_io_start(loop, &http->io);
}

void
ev_http_stop(struct ev_loop *loop, ev_http *http)
{
}

static int
httpconn_set_endpoint(ev_httpconn *hc)
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


int
ev_httpconn_init(ev_httpconn *hc, http_callback cb, int fd,
                 size_t inbufsize, size_t outbufsize)
{
  xdebug(0, "ev_httpconn_init(%p, %p, %d, %zd, %zd)",
         hc, cb, fd, inbufsize, outbufsize);

  ev_io_init(&hc->io, ev_httpconn_read_cb, fd, EV_READ);

  hc->r_timeout = 5;
  hc->w_timeout = 5;

  hc->cb = cb;

  ev_timer_init(&hc->timer, ev_httpconn_timer_cb,
                hc->r_timeout, hc->r_timeout);

  xobs_init(&hc->str_pool);
  hdrstore_init(&hc->headers, &hc->str_pool);
  hdrstore_init(&hc->rsp_hdrs, &hc->str_pool);

  xobs_begin(&hc->rsp_pool, outbufsize);

  hc->rsp.states = 0;
  hc->rsp.buf = hc->rsp.bufend = hc->rsp.sent = 0;
  hc->rsp.hdrs = hc->rsp.hdrsend = hc->rsp.body = hc->rsp.bodyend = 0;

  hc->rsp.fd = -1;

  hc->method = HM_NONE;
  hc->uri = 0;
  hc->version = 0;

  if (httpconn_set_endpoint(hc) == -1) {
    return -1;
  }

  hc->inbuf_size = inbufsize;
  hc->begin = hc->end = hc->cur = hc->inbuf;
  return 0;
}


void
ev_httpconn_start(struct ev_loop *loop, ev_httpconn *hc)
{
  ev_io_start(loop, &hc->io);
  ev_timer_start(loop, &hc->timer);

  /* TODO: now what? */
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
  xobs_free(&hc->str_pool, 0);
  xobs_free(&hc->rsp_pool, 0);

  /* Since all ev_httpconn struct is allocate via malloc(3) from
   * ev_http module, it should be released here, I think. */

  /* TODO: do I call some callback from user-side? */

  free(hc);
}


static void
get_buf_size(int fd, int *rdbuf_size, int *wrbuf_size)
{
  int ibsz, obsz, notsock = 0, ret = 0;
  socklen_t bsz_len;
  struct stat sbuf;

  bsz_len = sizeof(ibsz);
  ret = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &ibsz, &bsz_len);

  if (ret == 0) {
    bsz_len = sizeof(obsz);
    ret = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &obsz, &bsz_len);

    if (ret == 0) {
      *rdbuf_size = ibsz;
      *wrbuf_size = obsz;
      return;
    }
    else if (errno == ENOTSOCK)
      notsock = 1;
  }
  else if (errno == ENOTSOCK)
    notsock = 1;

  if (notsock && fstat(fd, &sbuf) == -1) {
    *rdbuf_size = sbuf.st_blksize;
    *wrbuf_size = sbuf.st_blksize;
  }
  else {
    *rdbuf_size = RCVBUF_SIZE;
    *wrbuf_size = SNDBUF_SIZE;
  }
}


static void
ev_http_io_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  int fd;
  struct sockaddr_storage cliaddr;
  socklen_t size = sizeof(cliaddr);
  ev_http *http = (ev_http *)(((char *)w) - offsetof(ev_http, io));
  ev_httpconn *hc;
  int ibsz, obsz;

  fd = accept(w->fd, (struct sockaddr *)&cliaddr, &size);
  if (fd == -1) {
    if (errno == EWOULDBLOCK || errno == EINTR)
      return;
    xerror(0, errno, "can't accept more connection");
    /* TODO: now what? */
    ev_http_stop(loop, http);
  }

#if 1
  {
    /* TODO: is FD non-blocking?? */
    int sflag;

    if ((sflag = fcntl(fd, F_GETFL)) == -1)
      xerror(0, errno, "fcntl failed");
    if (sflag & O_NONBLOCK)
      xdebug(0, "fd(%d) is %sBLOCKING", fd, (sflag & O_NONBLOCK) ? "NON-" : "");
  }
#endif

  /* TODO: shouldn't rcvbuf_size be static variable? */
  get_buf_size(fd, &ibsz, &obsz);
  xdebug(0, "socket buffer size: recv(%d) send(%d)", ibsz, obsz);


  hc = malloc(sizeof(*hc) + ibsz);
  if (!hc) {
    xerror(0, errno, "can't accept more connection");
    close(fd);
    return;
  }

  ev_httpconn_init(hc, http->cb, fd, ibsz, obsz);
  ev_httpconn_start(loop, hc);
}


static __inline__ void
shift_inbuf(ev_httpconn *hc)
{
  /*
    INBUF: _____pppppRRRRR......
                ^    ^    ^     ^
             begin  cur   end   INBUF + INFBUF_SIZE

    INBUF: pppppRRRRR...........
           ^    ^    ^          ^
         begin  cur  end        INBUF + INFBUF_SIZE
   */

  if (hc->begin == hc->inbuf)
    return;

  size_t offset = hc->begin - hc->inbuf;
  memmove(hc->inbuf, hc->begin, hc->end - hc->begin);
  hc->begin -= offset;
  hc->cur -= offset;
  hc->end -= offset;
}


static void
ev_httpconn_toggle_response_mode(struct ev_loop *loop, ev_httpconn *hc)
{
  void *p;

  ev_io_stop(loop, &hc->io);

  if (hc->io.events & EV_READ) { /* EV_READ(recv) -> EV_WRITE(send) */
    ev_set_cb(&hc->io, ev_httpconn_write_cb);
    ev_io_set(&hc->io, hc->io.fd, EV_WRITE);
  }
  else {                        /* EV_WRITE(send) -> EV_READ(recv) */
    /* We assume that every data in hc->rsp_pool is already sent.
     * Thus, initialize reponse-related members to the init state */

    assert(hc->rsp.buf == 0);

    ev_set_cb(&hc->io, ev_httpconn_read_cb);
    ev_io_set(&hc->io, hc->io.fd, EV_READ);

    if (hc->begin < hc->end) {
      char *found = memmem(hc->begin, hc->end - hc->begin, CRLF2, CRLF2LEN);
      if (found)
        ev_feed_event(loop, &hc->io, EV_READ | EV_CUSTOM);
    }
  }

  ev_io_start(loop, &hc->io);
}


int
debug_cat_cb(struct ev_loop *loop, struct ev_httpconn *w, int revents)
{
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


#if 0
static void
prepare_rsp(ev_httpconn *hc, int complete_body)
{
  /* TODO: what happend if there is no growing object in hc->rsp_pool? */

  hc->rsp.states = 0;

  if (xobs_object_size(&hc->rsp_pool) == 0) {
    /* The user didn't provide a body.  (i.e. HEAD request?) */
    hc->rsp.body = 0;
  }
  else {
    hc->rsp.body = xobs_finish(&hc->rsp_pool);
    hc->rsp.states |= RSP_READY_BODY_STR;
  }

  hc->rsp.fd = -1;    /* not used for now. maybe later for sendfile(2) */

  /* TODO: fill rsp->headers */

  if (hdrstore_fill(&hc->rsp_hdrs, &hc->rsp_pool) > 0) {
    hc->rsp.headers = xobs_finish(&hc->rsp_pool);
    hc->rsp.states |= RSP_HEADERS;
  }
  else {
    /* Warning: no headers?? */
    xdebug(0, "there is no header for this reponse");
    hc->rsp.headers = 0;
  }

  hc->rsp.offset = 0;

  if (complete_body)
    hc->rsp.states |= RSP_READY_BODY_COMPLETE;
}
#endif  /* 0 */


/*
 * This function will set hc->rsp.(buf|bufend|sent) members
 * for actual data transfer.  It will call the callback in httpconn
 * to let the user fill the buffer.
 *
 * If this function is called for the first time, you'll need to set
 * FIRST to nonzero.
 *
 * If there's something to send, it will return non-zero.  Otherwise
 * it returns zero.
 */
static int
httpconn_fill_rsp(struct ev_loop *loop, ev_httpconn *hc, int first)
{
  size_t sz;

  if (first) {
    hc->rsp.states = 0;

    hc->rsp.hdrs = hc->rsp.hdrsend = hc->rsp.body = hc->rsp.bodyend = 0;
  }

  assert(xobs_object_size(&hc->rsp_pool) == 0);
  assert(hc->rsp.buf == 0);

  if (hc->rsp.states & RSP_USERCB_FIN)
    return 0;

  if (!hc->cb(loop, hc, EV_READ))
    hc->rsp.states |= RSP_USERCB_FIN;

  /* Now, user provided reponse body is in hc->rsp_pool as a growing object. */
  /* and user provided headers are in hc->rsp_hdrs. */

  sz = xobs_object_size(&hc->rsp_pool);
  if (sz > 0) {
    hc->rsp.body = xobs_finish(&hc->rsp_pool);
    hc->rsp.bodyend = hc->rsp.body + sz;
  }
  else
    hc->rsp.body = hc->rsp.bodyend = 0;

  if (first) {
    hdrstore_fill(&hc->rsp_hdrs, &hc->rsp_pool, hc->rsp_code);
    sz = xobs_object_size(&hc->rsp_pool);
    hc->rsp.hdrs = xobs_finish(&hc->rsp_pool);
    hc->rsp.hdrsend = hc->rsp.hdrs + sz;
    RSP_SENDING(hc->rsp.states, RSP_SENDING_HDRS);
  }
  else {
    if (hc->rsp.body < hc->rsp.bodyend)
      RSP_SENDING(hc->rsp.states, RSP_SENDING_BODY);
    else
      ;
  }

  switch (hc->rsp.states & RSP_SENDING_MASK) {
  case RSP_SENDING_HDRS:
    hc->rsp.buf = hc->rsp.hdrs;
    hc->rsp.bufend = hc->rsp.hdrsend;
    hc->rsp.sent = hc->rsp.buf;
    return 1;

  case RSP_SENDING_BODY:
    hc->rsp.buf = hc->rsp.body;
    hc->rsp.bufend = hc->rsp.bodyend;
    hc->rsp.sent = hc->rsp.buf;
    return 1;

  default:
    xdebug(0, "httpconn_fill_rsp: nothing to send");
    /* TODO: set hc->rsp_code to 500, and set contents for the error
     *       handling */
    return 0;
  }
}


static void
ev_httpconn_parse_request(struct ev_loop *loop,
                          ev_httpconn *hc, char *begin, char *end)
{
  char *savep;
  char *headers = memmem(begin, end - begin, CRLF, CRLFLEN);
  // char *bp = memmem(begin, end - begin, CRLF2, CRLF2LEN);

  if (headers)
    headers += CRLF2LEN;

  /* HEADERS points the start of the HTTP headers */
  /* BP points the end of the request */
  xdebug(0, "ev_httpconn_parse_request");
  fprintf(stderr, "--BEGIN: REQ--\n");
  fwrite(begin, 1, end - begin, stderr);
  fprintf(stderr, "\n--END: REQ--\n");

#if 0
  if (!bp) {
    /* TODO: what to do? */
    /* set invalid request, */
  }
  *bp = '\0';
  bp += 2;
#endif  /* 0 */

  hc->method_string = strtok_r(begin, " ", &savep);
  hc->uri           = strtok_r(NULL, " ", &savep);
  hc->version       = strtok_r(NULL, " " CRLF, &savep);

  if (!hc->method_string || !hc->uri || !hc->version) {
    /* TODO: something is wrong in the request line */
  }
  hc->method = str2method(hc->method_string);
  if (!hdrstore_load(&hc->headers, headers, end - headers)) {
    /* TODO: failed to parse headers  */
  }

#if 0
  {
    /* TODO: call user's callback to prepare the response */
    /* TODO: change the watcher to receive EV_WRITE?? */
    hc->method = HM_DEBUG_CAT;
    hc->uri = 0;
    hc->version = 0;

    hc->cb(loop, hc, EV_READ /* EV_READ?? */);
  }
#endif  /* 0 */

  if (httpconn_fill_rsp(loop, hc, 1))
    ev_httpconn_toggle_response_mode(loop, hc);
  else {
    /* not possible. nothing to send?  no status-line?? */
    abort();
  }

#if 0
  /* After the callback below, the response headers are filled by
   * hc->cb(), and reponse body is in the form of growing object in
   * hc->rsp_pool.  NOTE THAT hc->cb may not complete the whole
   * response body! */
  if (hc->cb(loop, hc, EV_READ)) {
    if (xobs_object_size(&hc->rsp_pool) == 0) {
      /* the construction of response body is not finished,
       * but nothing to send right now. */

      // TODO: return;
    }
    else {
      /* not completed, but we have something to send */
    }
    prepare_rsp(hc, 0);
  }
  else {
    /* The use completed building response body in rsp_pool. */
    prepare_rsp(hc, 1);
  }
#endif  /* 0 */

  /* TODO: prepare hc->rsp for the writing callback to work. */

  //ev_httpconn_toggle_response_mode(loop, hc);
}


void
handle_request(struct ev_loop *loop, ev_httpconn *hc, char *found)
{
  /* TODO:
   * 0. Now, INBUF looks like
   *    ('r': previously read data, 'R': currently read data):
   *    INBUF: ____rrrrrRRRR....
   *               ^    ^   ^
   *           begin   cur  end
   *
   * 1. test for CRLFCRLF from (hc->begin) ... (hc->end)
   * 2. if found, process request from (hc->begin ... FOUND),
   *    then set hc->begin to FOUND, set hc->cur = hc->end.
   *    INBUF: __________RRR....
   *                     ^  ^
   *                 begin  (cur, end)
   * 3. if not, advance hc->cur to the hc->end.
   *    INBUF: ____rrrrrRRRR....
   *               ^        ^
   *           begin     (cur, end)
   */

  if (!found)
    found = memmem(hc->begin, hc->end - hc->begin, "\r\n\r\n", 4);

  if (found) {
    *found = '\0';
    ev_httpconn_parse_request(loop, hc, hc->begin, found);
    /* TODO: process the request */
    hc->begin = found + 4;
    hc->cur = hc->end;
  }
  else {
    hc->cur = hc->end;
    return;
  }
  found = memmem(hc->begin, hc->end - hc->begin, "\r\n\r\n", 4);
  if (found) {
    /* TODO: This may be not the place to feed the event.
     *       The remaining should be handled after completion
     *       of the response transfer. */
    ev_feed_event(loop, &hc->io, EV_READ | EV_CUSTOM);
  }

  /* TODO: Is this a right place to shift inbuf? (perhaps before
     read(2) call in the caller? */
  if (hc->end == hc->inbuf + hc->inbuf_size) {
    /* There's no available slot in hc->data. */
    if (hc->begin == hc->inbuf) {
      xdebug(0, "read buffer is full without complete request");
      ev_httpconn_stop(loop, hc);
    }
    else
      shift_inbuf(hc);
  }
}


static void
ev_httpconn_write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  size_t remain;
  ssize_t written;
  ev_httpconn *hc = (ev_httpconn *)(((char *)w) - offsetof(ev_httpconn, io));

  if (revents & EV_WRITE) {
    hc->acc_time = ev_now(loop);
    xdebug(0, "ev_httpconn_write_cb for EV_WRITE, (revents: %08x)", revents);

    if (hc->rsp.sent < hc->rsp.bufend) {
      remain = hc->rsp.bufend - hc->rsp.sent;
      written = write(w->fd, hc->rsp.sent, remain);

      if (written == -1) {
        if (errno == EAGAIN || errno == EINTR)
          return;
        if (errno != EPIPE)
          xdebug(errno, "ev_httpconn_write_cb: write(2) failed");
        ev_httpconn_stop(loop, hc);
      }
      else {
        hc->rsp.sent += written;
        if (hc->rsp.sent >= hc->rsp.bufend) {

          /* RSP_SENDING_HDRS or RSP_SENDNG_BODY?? */
          if (hc->rsp.states & RSP_SENDING_HDRS) {
            RSP_SENDING(hc->rsp.states, RSP_SENDING_BODY);

            hc->rsp.buf = hc->rsp.body;
            hc->rsp.bufend = hc->rsp.bodyend;
            hc->rsp.sent = hc->rsp.buf;

            ev_feed_event(loop, &hc->io, EV_WRITE | EV_CUSTOM);
            return;
          }

          xobs_free(&hc->rsp_pool, hc->rsp.buf);
          hc->rsp.buf = hc->rsp.bufend = hc->rsp.sent = 0;

          if (httpconn_fill_rsp(loop, hc, 0)) {
            ev_feed_event(loop, &hc->io, EV_WRITE | EV_CUSTOM);
            return;
          }
          else {
            ev_httpconn_toggle_response_mode(loop, hc);
            return;
          }
        }
        else
          return;
      }
    }
    else {                      /* hc->rsp.sent >= hc->rsp.bufend */
      /* Actually, hc->rsp.sent == hc->rsp.bufend == hc->rsp.buf == 0 */
      /* And, the control should not come here?? */
      if (httpconn_fill_rsp(loop, hc, 0)) {
        ev_feed_event(loop, &hc->io, EV_WRITE | EV_CUSTOM);
        return;
      }
      else {
        ev_httpconn_toggle_response_mode(loop, hc);
        return;
      }
    }
  }
}


static void
ev_httpconn_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  ev_httpconn *hc = (ev_httpconn *)(((char *)w) - offsetof(ev_httpconn, io));
  size_t remain;
  ssize_t readch;

  /* TODO: maybe ACC_TIME should be set just before leaving this function? */

  if (revents & EV_READ) {
    hc->acc_time = ev_now(loop);
    xdebug(0, "ev_httpconn_read_cb for EV_READ, (revents: %08x)", revents);

    assert(hc->cur == hc->end);

    if (revents & EV_CUSTOM) {
      /* TODO: I need a way to mark a simulated event without using
       *       EV_CUSTOM */
      xdebug(0, "\thandle_request from simulated read event");
      handle_request(loop, hc, NULL);
      return;
    }

    remain = hc->inbuf + hc->inbuf_size - hc->cur;
    /* TODO: WHAT IF REMAIN IS ZERO???? */
    readch = read(hc->io.fd, hc->cur, remain);

    if (readch == -1) {
      if (errno == EAGAIN || errno == EINTR) {
        /* TODO: we need to handle the remaining data if any */
        return;
      }
      if (errno != ECONNRESET)
        xdebug(errno, "read failed (errno=%d)", errno);
      ev_httpconn_stop(loop, hc);
    }
    else if (readch == 0) {             /* EOF */
      /* TODO: check if we can process data (hc->begin) ... (hc->end) */

      if (hc->begin < hc->cur) {
        /* We have incomplete data, ignoring it */
        xdebug(0, "premature end of request");
      }
      ev_httpconn_stop(loop, hc);
    }
    else {
      hc->end += readch;

      xdebug(0, "\thandle_request from genuine read event");
      handle_request(loop, hc, NULL);
    }
  }
}

static void
ev_httpconn_timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
  ev_httpconn *hc = (ev_httpconn *)(((char *)w) - offsetof(ev_httpconn, timer));

  ev_tstamp after = hc->acc_time - ev_now(loop) +
    ((hc->io.events & EV_READ) ? hc->r_timeout : hc->w_timeout);

#if 0
  xdebug(0, "ev_httpconn_timer_cb (fd: %d, revents: %08x): acc_time(%f), now(%f), after(%f)", hc->io.fd, revents, hc->acc_time, ev_now(loop), after);
#endif

  if (after < 0.) {             /* timeout occurred */
    /* TODO: now what? */
    xdebug(0, "%c_timeout for fd %d",
           ((hc->io.events & EV_READ) ? 'r' : 'w'), hc->io.fd);

    if (!hc->cb(loop, hc, EV_TIMER)) {
      /* The user agreed to release the connection */
      xdebug(0, "close the connection (reason = timeout)");
      ev_httpconn_stop(loop, hc);
      return;
    }
  }
  ev_timer_set(&hc->timer, after, 0);
  ev_timer_start(loop, w);
}


static int
tcp6_listen(const char *address, int port, int flags)
{
  struct sockaddr_in6 addr6;
  static struct in6_addr any6 = IN6ADDR_ANY_INIT;
  int fd;
  int sopt;
  int saved_errno;

  fd = socket(PF_INET6, SOCK_STREAM, 0);

  if (fd < 0)
    return -1;
  sopt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sopt, sizeof(sopt)) != 0)
    xerror(0, errno, "setsockopt(SO_REUSEADDR) failed");

  if (address == 0) {
    memcpy(&addr6.sin6_addr, &any6, sizeof(any6));
  }
  else if (inet_pton(AF_INET6, address, &addr6.sin6_addr) != 1) {
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  addr6.sin6_family = AF_INET6;
  addr6.sin6_port = htons(port);

  if (bind(fd, (struct sockaddr *)&addr6, sizeof(addr6)) != 0) {
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }

  if (flags)
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | flags);

  if (listen(fd, 5) != 0) {
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }

  return fd;
}


static int
tcp4_listen(const char *address, int port, int flags)
{
  struct sockaddr_in addr;

  int fd;
  int sopt;
  int saved_errno;

  fd = socket(PF_INET, SOCK_STREAM, 0);
  if (fd < 0)
    return -1;
  sopt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &sopt, sizeof(sopt)) != 0)
    xerror(0, errno, "setsockopt(SO_REUSEADDR) failed");

  if (address == 0)
    addr.sin_addr.s_addr = INADDR_ANY;
  else if (inet_pton(AF_INET, address, &addr.sin_addr) != 1) {
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);

  if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }

  if (flags)
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | flags);

  if (listen(fd, 5) != 0) {
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
  }
  return fd;
}

int
tcp_listen(const char *address, int port, int flags)
{
  if (strchr(address, ':')) {
    return tcp6_listen(address, port, flags);
  }
  else
    return tcp4_listen(address, port, flags);
}
