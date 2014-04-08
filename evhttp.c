#define _GNU_SOURCE

#include <assert.h>
#include <string.h>
#include <limits.h>

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
static void ev_http_ctrl_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_http_idle_cb(struct ev_loop *loop, ev_idle *w, int revents);

static void get_buf_size(int fd, int *rdbuf_size, int *wrbuf_size);
static int tcp_open(const char *address, int port, int type, int flags);
static int tcp4_open(const char *address, int port, int type, int flags);
static int tcp6_open(const char *address, int port, int type, int flags);


int
ev_http_init(ev_http *http, http_callback cb, char *address,
             int port, int ctrl_port)
{
  int fd, cfd;

  http->quit = 0;
  http->nclients = 0;
  http->cb = cb;

  strncpy(http->address, address, INET_ADDRSTRLEN - 1);
  http->address[INET_ADDRSTRLEN - 1] = '\0';
  http->port = port;
  http->ctrlport = ctrl_port;

  fd = tcp_open(address, port, SOCK_STREAM, O_NONBLOCK);
  if (fd == -1) {
    xdebug(errno, "tcp_open(%s, %d, STREAM, NONBLOCK) failed", address, port);
    return 0;
  }

  if (listen(fd, 5) != 0) {
    xerror(0, errno, "listen() failed");
    close(fd);
    return 0;
  }

  {
    /* TODO: is FD non-blocking?? */
    int sflag;

    if ((sflag = fcntl(fd, F_GETFL)) == -1)
      xerror(0, errno, "fcntl failed");
    xdebug(0, "fd(%d) is %sBLOCKING", fd, (sflag & O_NONBLOCK) ? "NON-" : "");
  }

  cfd = tcp_open("127.0.0.1", ctrl_port, SOCK_DGRAM, O_NONBLOCK);
  if (cfd == -1) {
    xdebug(errno, "can't open control port %d", ctrl_port);
  }

  get_buf_size(fd, &http->ibufsize, &http->obufsize);

  ev_io_init(&http->io, ev_http_io_cb, fd, EV_READ);

  if (cfd == -1)
    http->ctrlport = -1;
  if (http->ctrlport != -1)
    ev_io_init(&http->ctrl, ev_http_ctrl_cb, cfd, EV_READ);

  ev_idle_init(&http->idle, ev_http_idle_cb);

  return 1;
}


void
ev_http_start(struct ev_loop *loop, ev_http *http)
{
  if (http->ctrlport != -1)
    ev_io_start(loop, &http->ctrl);
  ev_io_start(loop, &http->io);
  ev_idle_start(loop, &http->idle);
}


void
ev_http_stop(struct ev_loop *loop, ev_http *http)
{
  /* TODO */

  if (!http->quit) {
    ev_io_stop(loop, &http->io);
    if (close(http->io.fd) == -1)
      xdebug(errno, "close(httpfd) failed");
  }

  if (http->ctrlport != -1) {
    ev_io_stop(loop, &http->ctrl);
    if (close(http->ctrl.fd) == -1)
      xerror(0, errno, "close(ctrlfd) failed");
  }

  ev_idle_stop(loop, &http->idle);
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
ev_http_idle_cb(struct ev_loop *loop, ev_idle *w, int revents)
{
  ev_http *http = (ev_http *)(((char *)w) - offsetof(ev_http, idle));

  if (http->quit && http->nclients == 0)
    ev_break(loop, EVBREAK_ALL);
}


static void
ev_http_ctrl_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  ev_http *http = (ev_http *)(((char *)w) - offsetof(ev_http, ctrl));
  int readch;
  struct sockaddr_storage addr;
  socklen_t addrlen = sizeof(addr);

  char ibuf[LINE_MAX];
  char obuf[LINE_MAX];
  size_t olen;
  ssize_t sent;

  readch = recvfrom(w->fd, ibuf, sizeof(ibuf) - 1,
                    MSG_DONTWAIT, (struct sockaddr *)&addr, &addrlen);

  if (readch == -1) {
    if (errno == EINTR || errno == EAGAIN)
      return;
    xerror(0, errno, "recvfrom(2) failed on control fd (errno=%d)", errno);
    /* TODO: What now? */
  }
  else if (readch == 0) {
    xdebug(errno, "WARNING!: control fd is closed? (errno=%d)", errno);
    /* TODO: reopen */
    return;
  }
  ibuf[LINE_MAX - 1] = '\0';

  switch (ibuf[0]) {
  case 'n':
    sprintf(obuf, "OK %zd\n", http->nclients);
    break;
  case 'q':
    xerror(0, 0, "QUIT request received");
    ev_io_stop(loop, &http->io);
    if (close(http->io.fd) == -1)
      xdebug(errno, "close(httpfd) failed");
    http->quit = 1;

    strcpy(obuf, "OK\n");
    break;
  default:
    strcpy(obuf, "ERR\n");
    break;
  }
  olen = strlen(obuf);
  sent = sendto(w->fd, obuf, olen, MSG_DONTWAIT,
                (struct sockaddr *)&addr, addrlen);
  if (sent < 0)
    xdebug(errno, "sendto(2) failed");
  else
    xdebug(0, "sendto(fd, buffer, len:%zd) == %zd", olen, sent);
}

static void
ev_http_io_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  int fd;
  struct sockaddr_storage cliaddr;
  socklen_t size = sizeof(cliaddr);
  ev_http *http = (ev_http *)(((char *)w) - offsetof(ev_http, io));
  ev_httpconn *hc;

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

#if 0
  /* TODO: shouldn't rcvbuf_size be static variable? */
  get_buf_size(fd, &ibsz, &obsz);
  xdebug(0, "socket buffer size: recv(%d) send(%d)", ibsz, obsz);
#endif

  hc = malloc(sizeof(*hc));
  if (!hc) {
    xerror(0, errno, "can't accept more connection");
    close(fd);
    return;
  }

  ev_httpconn_init(hc, http, fd);
  ev_httpconn_start(loop, hc);
}


static int
tcp6_open(const char *address, int port, int type, int flags)
{
  struct sockaddr_in6 addr6;
  static struct in6_addr any6 = IN6ADDR_ANY_INIT;
  int fd;
  int sopt;
  int saved_errno;

  fd = socket(PF_INET6, type, 0);

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

  if (flags) {
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | flags) == -1)
      xerror(0, errno, "fcntl() failed");
  }

  return fd;
}


static int
tcp4_open(const char *address, int port, int type, int flags)
{
  struct sockaddr_in addr;

  int fd;
  int sopt;
  int saved_errno;

  fd = socket(PF_INET, type, 0);
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

  if (flags) {
    if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | flags) == -1)
      xerror(0, errno, "fcntl() failed");
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
tcp_open(const char *address, int port, int type, int flags)
{
  if (strchr(address, ':')) {
    return tcp6_open(address, port, type, flags);
  }
  else
    return tcp4_open(address, port, type, flags);
}
