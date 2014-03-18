#ifndef EVBUF_H__
#define EVBUF_H__

#include <ev.h>
#include <stddef.h>

typedef struct bufnode {
  struct bufnode *next;

  char *begin;
  char *end;

  /* Do we need SIZE member of the capacity of DATA?,
   *
   * If we are exposing this structure for users to fill it for
   * writing, then the size of this structure may be not fixed, but
   * depends on the size of the data for writing.
   */
  size_t size;                  /* size of DATA */

  // union {
  char data[0];
  //   char *ptr;
  // };
} bufnode;

#define bufnode_is_empty(bc)   ((bc)->begin >= (bc)->end)

struct ev_buf;
typedef struct ev_buf ev_buf;

struct ev_buf
{
  ev_io io;
  ev_timer rtimer;
  ev_timer wtimer;

  //struct xobs wpool;
  //struct xobs rc_pool;
  //struct xobs wc_pool;

  bufnode *rb_head;
  bufnode *rb_tail;
  bufnode *wb_head;
  bufnode *wb_tail;

  size_t rb_size;
  int on_writing;                  /* current mode: read or write */

  void (*callback)(struct ev_loop *loop, ev_buf *w, int revents);
  //(*read_cb)(struct ev_loop *loop, ev_buf *w, int revents);
  //(*write_cb)(struct ev_loop *loop, ev_buf *w, int revents);

  int (*read_ready)(struct ev_loop *loop, ev_buf *w, int eof);

  void *data;
};

int ev_buf_init(ev_buf *ev,
                void (*callback)(struct ev_loop *loop, ev_buf *w,
                                 int revents),
                int fd, int events,
                ev_tstamp read_timeout, ev_tstamp write_timeout);
int ev_buf_stop(struct ev_loop *loop, ev_buf *w);
int ev_buf_start(struct ev_loop *loop, ev_buf *w);

/* FEED new data for writing */
int ev_buf_feed(ev_buf *ev, const void *data, size_t len);

// When we read enough, we set the end of the meaningful unit of data
// as eaten-up, then the user need to provide data to write (TBD:
// how?)
void ev_buf_read_done(bufnode *processed);
//void ev_strstr

#endif /* EVBUF_H__ */
