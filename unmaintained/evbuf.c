#include <stdlib.h>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "evbuf.h"
#include "xerror.h"

#ifndef RCVBUF_SIZE
#define RCVBUF_SIZE     4096
#endif

static void ev_buf_io_cb(struct ev_loop *loop, ev_io *w, int revents);
static void ev_buf_rtimer_cb(struct ev_loop *loop, ev_timer *w, int revents);
static void ev_buf_wtimer_cb(struct ev_loop *loop, ev_timer *w, int revents);

static int read_ready(struct ev_loop *loop, ev_buf *w, int eof);

static int
read_ready(struct ev_loop *loop, ev_buf *w, int eof)
{
  return 1;
}


static int
get_read_buffer_size(int fd)
{
  int bsz, ret;
  socklen_t bsz_len = sizeof(bsz);
  struct stat sbuf;

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


int
ev_buf_init(ev_buf *ev,
            void (*callback)(struct ev_loop *loop, ev_buf *w, int revents),
            int fd, int events,
            ev_tstamp read_timeout, ev_tstamp write_timeout)
{
  ev_io_init(&ev->io, ev_buf_io_cb, fd, EV_READ | EV_WRITE);
  ev_timer_init(&ev->rtimer, ev_buf_rtimer_cb, read_timeout, 0.);
  ev_timer_init(&ev->wtimer, ev_buf_wtimer_cb, write_timeout, 0.);

  ev->rb_head = ev->rb_tail = 0;
  ev->wb_head = ev->wb_tail = 0;

  ev->rb_size = get_read_buffer_size(fd);
  ev->on_writing = 0;

  ev->callback = callback;
  ev->read_ready = read_ready;

  ev->data = 0;

  return 0;
}


int
ev_buf_stop(struct ev_loop *loop, ev_buf *w)
{
  ev_io_stop(loop, &w->io);
  /* TODO: we may need to take different path depending on w->on_writing */

  if (w->on_writing)
    ev_timer_stop(loop, &w->wtimer);
  else
    ev_timer_stop(loop, &w->rtimer);

  return 0;
}


int
ev_buf_start(struct ev_loop *loop, ev_buf *w)
{
  ev_io_start(loop, &w->io);

  if (w->on_writing)
    ev_timer_start(loop, &w->wtimer);
  else
    ev_timer_start(loop, &w->rtimer);

  return 0;                     /* TBD */
}


bufnode *
bufnode_new(size_t size)
{
  bufnode *p;
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
bufnode_delete(bufnode *p)
{
  free(p);
}


#define bufnode_append_r(w, buf)        do {  \
    if ((w)->rb_tail)                           \
      (w)->rb_tail->next = (buf);               \
    else                                        \
      (w)->rb_head = (buf);                     \
    (w)->rb_tail = (buf);                       \
  } while (0)

#define bufnode_append_w(w, buf)        do {  \
    if ((w)->wb_tail)                           \
      (w)->wb_tail->next = (buf);               \
    else                                        \
      (w)->wb_head = (buf);                     \
    (w)->wb_tail = (buf);                       \
  } while (0)


#if 0
// bufnode_advance(struct bufnode *p, char *until_here);
#define bufnode_advance(bc, offset)    do {    \
    (bc)->begin += (offset);                    \
  } while (0)
#endif  /* 0 */

static void ev_buf_io_cb(struct ev_loop *loop, ev_io *w, int revents);

#if 0
void internal_callback(...) {
  if (write_event) {
    ev_buf_feed(...);
  }
  else if (timer_event) {
    /* TODO: read timeout? write timeout? or same? */
    /*       determine by evaulating 'w->on_read'. */
  }
  else {
    // scan W->rbuf whether we've read enough for the processing.
    // if we have enough, then process it,
    // then, call ev_buf_advance() to release the data that processed.
  }
}
#endif  /* 0 */

static void
ev_buf_io_cb(struct ev_loop *loop, ev_io *w, int revents)
{
  bufnode *buf;
  int ret;
  ev_buf *watcher = (ev_buf *)(((char *)w) - offsetof(ev_buf, io));

  /* TODO: disable timer */
  if (revents | EV_READ) {
    xdebug(0, "read event");

    buf = bufnode_new(watcher->rb_size);
    if (!buf) {
      xdebug(errno, "cannot allocate new bufnode");
      /* TODO: what now? */
      abort();
    }
    ret = read(watcher->io.fd, buf->data, watcher->rb_size);
    if (ret > 0) {                      /* read RET byte(s) */
      bufnode_append_r(watcher, buf);
      if (watcher->read_ready(loop, watcher, 0))
        watcher->callback(loop, watcher, EV_READ);
    }
    else {
      if (ret == 0) {             /* EOF */
        /* TODO: review this code, unless it may cause infinite loop
         *       if the predicate gives false... */
        if (watcher->read_ready(loop, watcher, 1))
          watcher->callback(loop, watcher, EV_READ);
      }
      else if (ret == -1) {
        if (errno != EAGAIN) {
          xdebug(errno, "read(2) failed");
          /* TODO: what now? */
        }
        return;
      }
      bufnode_delete(buf);
    }
  }

  /* TODO: enable the timer again */
}

static void
ev_buf_rtimer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
}


static void
ev_buf_wtimer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
}


#if 0
/* TODO: implment this function, behaves like memmem(3) */
void *
bufnode_memmem(bufnode *src, const void *pattern, size_t len)
{
  size_t buflen = src->end - src->begin;

  /* TODO: Perhaps I may need to re-write not to use recursion?
   *       */
  if (src == 0)
    return 0;

  AA*$*

  *$*$*

  if (buflen < len) {
    if (memcmp(src->begin, pattern, buflen) != 0)
      return bufnode_memmem(src->next, pattern, len);
    else {

  }
  else {

  }

}
#endif  /* 0 */
