#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <getopt.h>

#include <ev.h>

#include "xobstack.h"
#include "xerror.h"
#include "couchlite.h"

#define BUF_MAX 65536
#define RCVBUF_SIZE_DEFAULT     4096

int tcp_listen(const char *address, int port, int flags);
struct buffer *buffer_new(int sockfd);
void buffer_delete(struct buffer *p);

static void accept_cb(struct ev_loop *loop, ev_io *w, int revents);
static void read_cb(struct ev_loop *loop, ev_io *w, int revents);
static void debug_cb(EV_P_ ev_io *w, int revents);

ev_io accept_watcher;
ev_io debug_watcher;
struct ev_loop *main_loop;

int
main(int argc, char *argv[])
{
  int fd;
  fd = tcp_listen("0.0.0.0", 8080, O_NONBLOCK);
  if (fd < 0)
    xerror(1, errno, "tcp_listen failed");

  main_loop = EV_DEFAULT;
  ev_io_init(&accept_watcher, accept_cb, fd, EV_READ);
  ev_io_start(main_loop, &accept_watcher);

  ev_io_init(&debug_watcher, debug_cb, STDIN_FILENO, EV_READ);
  ev_io_start(main_loop, &debug_watcher);

  ev_run(main_loop, 0);
  ev_io_stop(main_loop, &accept_watcher);
  ev_io_stop(main_loop, &debug_watcher);

  return 0;
}


int
tcp_listen(const char *address, int port, int flags)
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


static void
accept_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  struct sockaddr_in cliaddr;
  socklen_t clilen = sizeof(cliaddr);
  int fd;

  ev_buf *watcher = malloc(sizeof(*watcher));

  if (!watcher)
    xerror(0, errno, "accept_cb: malloc failed");

  if (revents & EV_ERROR) {
    xerror(0, 0, "accept_cb: invalid event");
    free(watcher);
    return;
  }

  fd = accept(w->fd, (struct sockaddr *)&cliaddr, &clilen);
  if (fd < 0) {
    xerror(0, errno, "accept failed");
    free(watcher);
    return;
  }

  ev_buf_init(watcher, read_cb, watcher->io.fd, EV_READ | EV_WRITE, 0, 0);

  //dump_sflag(stderr, fd, "accepted: ");
  //ev_io_init(watcher, read_cb, fd, EV_READ);

  ev_buf_start(loop, watcher);
}


/*
 * divide_by_delims(p, "\n\n", 0);
 *  +-> divide_by_delims(p->next, "\n\n", 1);
 *
 * Found delim[0] in P, and proceed*  to p->next for delim[1]
 */
static bufnode *
divide_by_delims(bufnode *head, char *begin, const char *delims, int index)
{
  bufnode *p = head;

  size_t buflen = p->end - begin;

  if (!head)
    return 0;

  if (begin >= head->end)
    return divide_by_delims(head->next, head->next->begin, delims, index);

  if (delims[index] == '\0') {
    head->begin = begin;
    return head;
  }

  dp = memchr(begin, delim[index], buflen);
  if (dp) {
    if (dp == p->end - 1)
      return divide_by_delims(head->next, head->next->begin, delims, index + 1);
    else
      return divide_by_delims(head, begin + 1, delims, index + 1);
  }
  else
    return divide_by_delims(head->next, head->next->begin, delims, index);
}

static void
read_cb(struct ev_loop *loop, ev_buf *w, int revents)
{
  struct buffer *bp = w->data;
  int readch;

  divide_by_delims(w->rb_head, w->rb_head->begin, "\n\n", 0);

  ev_buf_read_done(0);

  if (!bp) {
    xerror(0, 0, "no internal buffer for fd(%d)", w->fd);
    ev_io_stop(loop, w);
    free(w->data);
    free(w);                    /* TODO: is this safe to call? */
    return;
  }

#if 0
  readch = read(w->fd, bp->rbuf, bp->rbuf_size);

  if (readch == 0) {            /* EOF */
    ev_io_stop(loop, w);

    if (bp->len > 0) {
      /* If the connection was closed when we have some data in BP,
       * we try to consume the remains. */
      bp->base[bp->len] = '\0';
      consume_line(w, bp->base);
    }

    buffer_delete(w->data);
    free(w);
    return;
  }
  else if (readch == -1) {
    if (errno != EAGAIN)
      xerror(0, errno, "readcb: read failed");
    return;
  }
  else {
    bp->len += readch;
  }

  {
    char *q;
    char *p = bp->base;
    ssize_t remains = bp->len;

    while (p < bp->base + bp->len && remains > 0) {
      q = memchr(p, '\n', remains);
      if (q) {
        *q = '\0';

        consume_line(w, p);
        remains -= q - p + 1;
        p = q + 1;
      }
      else {
        memmove(bp->base, p, remains);
        bp->len = remains;
        return;
      }
    }
    if (!(p < bp->base + bp->len && remains > 0)) {
      bp->len = 0;
    }

  }
#endif  /* 0 */
}


static void
debug_cb(EV_P_ ev_io *w, int revents)
{
  int sflag;

  puts("stdin ready");

  if ((sflag = fcntl(w->fd, F_GETFL)) == -1)
    xerror(0, errno, "fcntl failed");

  printf("FD status flags: ");
  if (sflag & O_NONBLOCK)
    printf(" NONBLOCK");
  if (sflag & O_APPEND)
    printf(" APPEND");
  if (sflag & O_ASYNC)
    printf(" ASYNC");
  putchar('\n');


  ev_io_stop(EV_A_ w);

  ev_break(EV_A_ EVBREAK_ALL);
}


int
buffer_readreq(struct buffer *bp, int fd)
{
  char *buf;
  ssize_t readch;
  struct rcvchunk rc;

  buf = xobs_alloc(&bp->incoming, bp->rcv_size);
  if (!buf)
    return -1;
#if 0
  if (!xobs_blank(&bp->pool, sizeof(struct rcvchunk))) {
    xobs_free(&bp->incoming, buf);
    return -1;
  }
#endif  /* 0 */

  readch = read(fd, buf, bp->rcv_size);
  if (readch == -1) {
    if (errno == EAGAIN)
      return 0;                 /* TBD */

    xerror(0, errno, "read(2) failed from fd(%d)", fd);
    xobs_free(&bp->incoming, buf);
    return -1;
  }
  else if (readch == 0) {
  }
  else {
    rc.data = buf;
    rc.size = readch;
    if (!xobs_grow(&bp->pool, &rc, sizeof(rc))) {
      xobs_free(&bp->incoming, buf);
      return -1;
    }
    /* TODO: find \r\n\r\n for the end of request, and do the rest */
    if (buffer_is_complete_req()) {
      // handle request

    }

  }

}


struct buffer *
buffer_new(int sockfd)
{
  struct buffer *p;
  int rcvsize;
  socklen_t rcvsize_len = sizeof(rcvsize);

  p = malloc(sizeof(*p));
  if (!p)
    return NULL;

  if (xobs_init(&p->pool) == 0) {
    free(p);
    return NULL;
  }
  if (xobs_init(&p->incoming) == 0) {
    xobs_free(&p->pool);
    free(p);
    return NULL;
  }

  if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvsize, &rcvsize_len) == -1) {
    rcvsize = RCVBUF_SIZE_DEFAULT;
    xerror(0, errno, "RCVBUF size: %d", rcvsize);
  }
  else
    xerror(0, 0, "rcvbuf size: %d", rcvsize);

  //p->rbuf_size = rcvsize;
  p->rcv_size = rcvsize;

  p->req = 0;
  p->headers = 0;

  return p;
}


void
buffer_delete(struct buffer *p)
{
  if (xobs_object_size(&p->pool) != 0)
    xobs_finish(&p->pool);
  if (xobs_object_size(&p->incoming) != 0)
    xobs_finish(&p->incoming);

  xobs_free(&p->pool, NULL);
  xobs_free(&p->incoming, NULL);

  free(p);
}

#include <kclangc.h>

//using namespace std;
//using namespace kyotocabinet;

// main routine
int
s_main(int argc, char *argv[]) {
  KCCUR *cursor;

  KCDB *db = kcdbnew();

  if (!kcdbopen(db, argv[1], KCOREADER | KCOWRITER)) {
    xerror(1, 0, "kcdbopen() failed: %s", kcdbemsg(db));
  }


#if 0
  // create the database object
  HashDB db;

  // open the database
  if (!db.open("casket.kch", HashDB::OWRITER | HashDB::OCREATE)) {
    cerr << "open error: " << db.error().name() << endl;
  }

  // store records
  if (!db.set("foo", "hop") ||
      !db.set("bar", "step") ||
      !db.set("baz", "jump")) {
    cerr << "set error: " << db.error().name() << endl;
  }

  // retrieve a record
  string value;
  if (db.get("foo", &value)) {
    cout << value << endl;
  } else {
    cerr << "get error: " << db.error().name() << endl;
  }

  // traverse records
  DB::Cursor* cur = db.cursor();
  cur->jump();
  string ckey, cvalue;
  while (cur->get(&ckey, &cvalue, true)) {
    cout << ckey << ":" << cvalue << endl;
  }
  delete cur;

  // close the database
  if (!db.close()) {
    cerr << "close error: " << db.error().name() << endl;
  }
#endif  /* 0 */

  cursor = kcdbcursor(db);
  if (!kccurjump(cursor))
    xerror(1, 0, "kcdbcursor() failed: %s", kcdbemsg(db));

  {
    const char *key, *value;
    size_t key_sz, val_sz;

    while ((key = kccurget(cursor, &key_sz, &value, &val_sz, 1)) != NULL) {
      printf("[%s] = |%s|\n", key, value);
    }
  }
  kccurdel(cursor);



  if (!kcdbclose(db)) {
    xerror(1, 0, "kcdbclose() failed: %s", kcdbemsg(db));
  }

  return 0;
}
