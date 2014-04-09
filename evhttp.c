#define _GNU_SOURCE

#include <assert.h>
#include <string.h>
#include <limits.h>

#include <errno.h>

#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
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


static void ev_http_producer_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_worker_io_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_worker_idle_cb(struct ev_loop *loop, ev_idle *w, int revents);

static void *worker_proc(void *arg);
static __inline__ int set_nonblock(int fd);


struct wwatcher {
  int fd;                       /* listening socket */
  int quit;
  size_t nclients;
  ev_http *http;

  ev_io io;
  ev_idle idle;
};


static __inline__ void
worker_stop(struct ev_loop *loop, struct wwatcher *ww, int now)
{
  close(ww->io.fd);
  ev_io_stop(loop, &ww->io);
  ww->quit = 1;

  if (now)
    ev_break(loop, EVBREAK_ALL);
  else
    ev_idle_start(loop, &ww->idle);
}

static void *
worker_proc(void *arg)
{
  struct wwatcher *ww = (struct wwatcher *)arg;
  struct ev_loop *loop = ev_loop_new(EVFLAG_AUTO);

  if (!loop) {
    xerror(0, 0, "creating event loop failed");
    return NULL;
  }

  ev_io_init(&ww->io, ev_worker_io_cb, ww->fd, EV_READ);
  ev_idle_init(&ww->idle, ev_worker_idle_cb);

  ev_io_start(loop, &ww->io);
  // ev_idle_start(loop, &ww->idle);

  ev_run(loop, 0);

  ev_io_stop(loop, &ww->io);

  close(ww->io.fd);

  free(ww);
  return NULL;
}


static void
ev_http_producer_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  ev_http *http = (ev_http *)(((char *)w) - offsetof(ev_http, io));
  int fd;
  int i;
  struct sockaddr_storage cliaddr;
  socklen_t size = sizeof(cliaddr);
  ssize_t written;
  static size_t next = (size_t)-1;

  if (!(revents & EV_READ)) {
    xdebug(0, "ev_http_producer_cb: receives unrecognized revents(%x)", revents);
    return;
  }

  while (1) {
    fd = accept(w->fd, (struct sockaddr *)&cliaddr, &size);
    if (fd == -1) {
      int e = errno;
      if (errno == EWOULDBLOCK || errno == EINTR)
        return;
      xerror(0, errno, "can't accept more connection");
      /* TODO: now what? */
      ev_http_stop(loop, http);   /* TODO: follow ev_http_stop() and see if it is right. */
      return;
    }

    // set_nonblock(fd);

    for (i = 0; i < http->nworkers; i++) {
      next = (next + 1) % http->nworkers;
      written = write(http->workers[next].fd, &fd, sizeof(fd));

      if (written == sizeof(fd)) {
        xdebug(0, "push fd(%d) to thread#%zd", fd, next);
        break;
      }
      if (errno != EINTR && errno != EAGAIN) {
        xdebug(errno, "can't produce the job to thread#%zd", next);
        abort();                  /* TODO: implement the error handling */
      }
    }

    if (written == -1) {
      /* no thread can accept FD. */
      xdebug(errno, "possible overload. ignoring the connection");
      close(fd);
    }
  }
}


static void
ev_worker_io_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  struct wwatcher *ww = (struct wwatcher *)(((char *)w) - offsetof(struct wwatcher, io));
  ssize_t readch;
  int fds[100];
  ev_httpconn *hc;
  int i, nfds;

  if (!(revents & EV_READ))
    return;

  while (1) {
    readch = read(w->fd, &fds, sizeof(fds));
    if (readch == -1) {
      if (errno == EAGAIN || errno == EINTR)
        return;
      xdebug(errno, "read(2) failed in the worker");

      worker_stop(loop, ww, 1);
      break;
    }
    else if (readch == 0) {
      worker_stop(loop, ww, 0);
      break;
    }
    else if (readch % sizeof(fds[0]) != 0)
      xdebug(0, "worker read data was not INT boundary");

    nfds = readch / sizeof(fds[0]);
    xdebug(0, "worker read data fds = %d", nfds);

    for (i = 0; i < nfds; i++) {
      set_nonblock(fds[i]);
      hc = malloc(sizeof(*hc));
      if (!hc) {
        xerror(0, errno, "can't create connection struct");
        close(fds[i]);
        continue;                 /* TODO: continue or break? */
      }
      ev_httpconn_init(hc, ww->http, fds[i], &ww->nclients);
      ev_httpconn_start(loop, hc);
    }
  }
}


static void
ev_worker_idle_cb(struct ev_loop *loop, ev_idle *w, int revents)
{
  struct wwatcher *ww = (struct wwatcher *)(((char *)w) - offsetof(struct wwatcher, idle));

  __sync_synchronize();

  if (ww->quit && ww->nclients == 0) {
    ev_idle_stop(loop, &ww->idle);
    ev_break(loop, EVBREAK_ALL);
  }
}



static __inline__ int
set_nonblock(int fd)
{
  int flags;
  flags = fcntl(fd, F_GETFL);
  if (flags != -1) {
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
      xdebug(errno, "fcntl(2) failed, OP = F_SETFL");
    else
      return 0;
  }
  return -1;
}


int
ev_http_init(ev_http *http, size_t nworkers, http_callback cb, char *address,
             int port, int ctrl_port)
{
  int fd, cfd;
  int i;

  http->quit = 0;
  http->nclients = 0;
  http->cb = cb;

  if (nworkers == 0) {
    http->workers = 0;
    http->nworkers = 0;
  }
  else {
    http->workers = malloc(sizeof(*http->workers) * nworkers);
    if (!http->workers)
      return 0;
    http->nworkers = nworkers;
    for (i = 0; i < nworkers; i++) {
      http->workers[i].fd = -1;
    }
  }

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

  if (nworkers == 0) {
    ev_io_init(&http->io, ev_http_io_cb, fd, EV_READ);

    if (cfd == -1)
      http->ctrlport = -1;
    if (http->ctrlport != -1)
      ev_io_init(&http->ctrl, ev_http_ctrl_cb, cfd, EV_READ);

    ev_idle_init(&http->idle, ev_http_idle_cb);
  }
  else {
    // TODO: ev_http_producer_cb,
    http->ctrlport = -1;        /* TODO: until implementation */
    ev_io_init(&http->io, ev_http_producer_cb, fd, EV_READ);
  }

  return 1;
}


void
ev_http_start(struct ev_loop *loop, ev_http *http)
{
  int i;
  int fds[2];
  int ret;
  struct wwatcher *w;

  if (http->nworkers == 0) {
    if (http->ctrlport != -1)
      ev_io_start(loop, &http->ctrl);

    ev_set_priority(&http->io, EV_MAXPRI);
    ev_io_start(loop, &http->io);
    //ev_idle_start(loop, &http->idle);
  }
  else {
    for (i = 0; i < http->nworkers; i++) {
      if (socketpair(AF_LOCAL, SOCK_STREAM, 0, fds) == -1) {
        xerror(0, errno, "ev_http_start: socketpair(2) failed");
        continue;
      }
      set_nonblock(fds[0]);
      set_nonblock(fds[1]);

      http->workers[i].fd = fds[1];

      w = malloc(sizeof(*w));
      if (!w) {
        xerror(0, errno, "ev_http_start: can't create a watcher for the worker");
        close(fds[0]);
        close(fds[1]);
        continue;
      }
      w->fd = fds[0];
      w->nclients = 0;
      w->http = http;
      w->quit = 0;

      ret = pthread_create(&http->workers[i].tid, NULL /* attr */,
                           worker_proc,
                           (void *)w);
      if (ret)
        xerror(0, ret, "ev_http_start: thread creation failed");
    }

    ev_io_start(loop, &http->io);
    /* TODO: start controller. */
  }
}


void
ev_http_stop(struct ev_loop *loop, ev_http *http)
{
  /* TODO */
  void *retval;
  int i;

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

  if (http->nworkers != 0) {
    /* TODO: implement */

    for (i = 0; i < http->nworkers; i++) {
      if (http->workers[i].fd != -1) {
        close(http->workers[i].fd);
        http->workers[i].fd = -1;
      }
    }

    for (i = 0; i < http->nworkers; i++) {
      pthread_join(http->workers[i].tid, &retval);
    }
  }
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

  if (http->quit && http->nclients == 0) {
    ev_idle_stop(loop, w);
    ev_break(loop, EVBREAK_ALL);
  }
}


void
ev_http_break(struct ev_loop *loop, ev_http *http)
{
  int i;

  if (close(http->io.fd) == -1)
    xdebug(errno, "close(httpfd) failed");
  ev_io_stop(loop, &http->io);

  http->quit = 1;

  if (http->nworkers == 0)
    ev_idle_start(loop, &http->idle);

  for (i = 0; i < http->nworkers; i++) {
    if (close(http->workers[i].fd) == -1)
      xdebug(errno, "closing worker fd failed");
    http->workers[i].fd = -1;
  }
  __sync_synchronize();
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
    /* TODO: use ev_http_break() */
    xerror(0, 0, "QUIT request received");
    if (close(http->io.fd) == -1)
      xdebug(errno, "close(httpfd) failed");
    ev_io_stop(loop, &http->io);
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

  if (!(revents & EV_READ)) {
    xdebug(0, "ev_http_io_cb: receives unrecognized revents(%x)", revents);
    return;
  }

  fd = accept(w->fd, (struct sockaddr *)&cliaddr, &size);
  if (fd == -1) {
    if (errno == EWOULDBLOCK || errno == EINTR)
      return;
    xerror(0, errno, "can't accept more connection");
    /* TODO: now what? */
    ev_http_stop(loop, http);
  }

  xdebug(0, "accept() => %d", fd);
  /* TODO: is FD non-blocking?? */
  set_nonblock(fd);

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

  ev_httpconn_init(hc, http, fd, &http->nclients);
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

  sopt = 1;
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &sopt, sizeof(sopt)) != 0)
    xerror(0, errno, "setsockopt(TCP_NODELAY) failed");

  {
    struct linger l;
    l.l_onoff = 1;
    l.l_linger = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)) != 0)
      xerror(0, errno, "setsockopt(SO_LINGER) failed");
  }

#if defined(REUSEPORT) && defined(SO_REUSEPORT)
  sopt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &sopt, sizeof(sopt)) != 0)
    xerror(0, errno, "setsockopt(SO_REUSEPORT) failed");
#endif

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

#if defined(REUSEPORT) && defined(SO_REUSEPORT)
  sopt = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &sopt, sizeof(sopt)) != 0)
    xerror(0, errno, "setsockopt(SO_REUSEPORT) failed");
#endif

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

  if (listen(fd, 131072) != 0) {
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
