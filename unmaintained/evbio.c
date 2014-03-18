

struct iobuf {
  struct iobuf *next;

  char *begin;
  char *end;
  size_t size;

  char data[0];
};
typedef struct iobuf iobuf;

struct ev_bio;
typedef struct ev_bio ev_bio;


typedef void (*ev_bio_callback)(struct ev_loop *loop, ev_bio *bio,
                                int revent, int eof);
typedef int (*ev_bio_ready)(struct ev_loop *loop, ev_bio *bio,
                            int revent, int eof);

struct ev_bio {
  ev_io io;
  ev_timer timer;

  iobuf *head, *tail;

  size_t bufsize;               /* default buffer size */

  ev_bio_callback callback;
  ev_bio_ready ready;

  struct ev_bio *pair;

  void *data;
};

iobuf *iobuf_new(size_t size);
void iobuf_delete(iobuf *p);

static void ev_buf_read_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_buf_write_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_buf_timer_cb(struct ev_loop *loop, ev_timer *w, int revents);
static int get_buffer_size(int fd, int events);

iobuf *
iobuf_new(size_t size)
{
  iobuf *p;
  p = malloc(sizeof(*p) + size);
  if (!p)
    return NULL;

  p->next = 0;

  p->size = size;
  p->begin = p->data + 0;
  p->end = p->begin;

  return p;
}


void
iobuf_delete(iobuf *p)
{
  free(p);
}


static int
get_buffer_size(int fd, int events)
{
  int bsz, ret;
  socklen_t bsz_len = sizeof(bsz);
  struct stat sbuf;

  if (events | EV_WRITE) {
    ret = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bsz, &bsz_len);
    if (ret == 0)
      return bsz;

    if (errno == ENOTSOCK) {
      if (fstat(fd, &sbuf) == -1)
        return SNDBUF_SIZE;
      return sbuf.st_blksize;
    }
    return SNDBUF_SIZE;
  }
  else if (events | EV_READ) {
    ret = getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bsz, &bsz_len);
    if (ret == 0)
      return bsz;

    if (errno == ENOTSOCK) {
      if (fstat(fd, &sbuf) == -1)
        return RCVBUF_SIZE;
      return sbuf.st_blksize;
    }
    return RCVBUF_SIZE;
  }
  else
    abort();
}


void
ev_bio_init(ev_bio *bio, ev_bio_callback, int fd, int events,
            ev_tstamp timeout)
{
  assert(events & (EV_READ | EV_WRITE)); /* not supported */

  if (events | EV_READ)
    ev_io_init(&bio->io, ev_bio_read_cb, fd, events);
  if (events | EV_WRITE)
    ev_io_init(&bio->io, ev_bio_write_cb, fd, events);

  ev_timer_init(&bio->timer, ev_bio_timer_cb, timeout, 0.);

  bio->head = bio->tail = 0;
  ev->bufsize = get_buffer_size(fd, events);
  xdebug(0, "ev_bio_init: buffer size = %zu", ev->bufsize);

}


int
ev_bio_stop(struct ev_loop *loop, ev_bio *w)
{
  ev_io_stop(loop, &w->io);
  ev_timer_stop(loop, &w->timer);

  return 0;
}


int
ev_bio_start(struct ev_loop *loop, ev_bio *w)
{
  ev_io_start(loop, &w->io);

  ev_timer_start(loop, &w->timer);

  return 0;                     /* TBD */
}


static void
ev_bio_read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  iobuf *bp = w->tail;
  ssize_t rch;
  ssize_t cap;

  if (revents & EV_ERROR) {
    xdebug(0, "ev_bio_read_cb: receiving error event");
    return;
  }

  if (!bp) {
    bp = iobuf_new(w->bufsize);
    w->head = w->tail = bp;
  }
  else if (bp->end >= bp->data + bp->size) {
    bp = iobuf_new(w->bufsize);
    w->tail->next = bp;
    w->tail = bp;
  }

  cap = bp->data + bp->size - bp->end;
  rch = read(w->io.fd, bp->end, cap);

  if (rch == -1) {
    if (errno == EAGAIN) {
      /* TODO: */
      return;
    }
    xdebug(errno, "ev_bio_read_cb: read failed");
    /* TODO: release all resources */
  }
  else {
    bp->end += rch;

    /* If there is some data waiting even if we filled current BP,
     * it will be read at next event loop. */

    /* TODO: we've read all for now */
  }
}


static void
ev_bio_write_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  iobuf *bp = w->head;
  ssize_t wch;

  if (revents & EV_ERROR) {
    xdebug(0, "ev_bio_write_cb: receiving error event");
    return;
  }

  if (!bp) {
    xdebug(0, "ev_bio_write_cb: nothing to write");
    return;
  }

  //if (bp->begin < bp->end)
  wch = write(w->io.fd, bp->begin, bp->end - bp->begin);
  if (wch == -1) {
    if (errno == EAGAIN)
      return;
    xdebug(errno, "ev_bio_write_cb: write failed");
    /* TODO: release all resources */
  }
  else {
    bp->begin += wch;
    if (bp->begin >= bp->end) {
      w->head = bp->next;
      free(bp);
    }

    if (w->head || bp->begin > bp->end) {
      xdebug(0, "ev_bio_write_cb: feed new write EV for handling more data");
      ev_feed_event(loop, &w->io, revents);
    }
    else {                      /* nothing to write for now */
      xdebug(0, "ev_bio_write_cb: stop write EV.");
      ev_io_stop(loop, &w->io);
    }
  }
}


static void
ev_bio_timer_cb(struct ev_loop *loop, ev_tmer *w, int revents)
{
}
