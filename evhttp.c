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
#include "evhttpconn.h"

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

static void ev_http_io_cb(struct ev_loop *loop, ev_io *w, int revents);

static void get_buf_size(int fd, int *rdbuf_size, int *wrbuf_size);
static int tcp_listen(const char *address, int port, int flags);
static int tcp6_listen(const char *address, int port, int flags);
static int tcp4_listen(const char *address, int port, int flags);


int
ev_http_init(ev_http *http, http_callback cb, char *address, int port)
{
  int fd;

  strncpy(http->address, address, INET_ADDRSTRLEN - 1);
  http->address[INET_ADDRSTRLEN - 1] = '\0';
  http->port = port;
  http->cb = cb;

  fd = tcp_listen(address, port, O_NONBLOCK);
  {
    /* TODO: is FD non-blocking?? */
    int sflag;

    if ((sflag = fcntl(fd, F_GETFL)) == -1)
      xerror(0, errno, "fcntl failed");
    xdebug(0, "fd(%d) is %sBLOCKING", fd, (sflag & O_NONBLOCK) ? "NON-" : "");
  }

  if (fd == -1) {
    xdebug(errno, "tcp_listen(%s, %d) failed", address, port);
    return -1;
  }

  get_buf_size(fd, &http->ibufsize, &http->obufsize);

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
  /* TODO */
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
      xerror(1, errno, "fcntl failed");

    if (fcntl(fd, F_SETFL, sflag | O_NONBLOCK) == -1)
      xerror(1, errno, "fcntl failed");
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

  ev_httpconn_init(hc, http, fd, ibsz, obsz);
  ev_httpconn_start(loop, hc);
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
