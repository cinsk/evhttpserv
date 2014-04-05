#define _GNU_SOURCE
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>             /* for memmem(3) */
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>

#include "buffer.h"
#include "hexdump.h"
#include "xobstack.h"

/* BACKPAD will be used for storing chunk size when TE is 'chunked' */
#define BACKPAD_SIZE    16
#define REARPAD_SIZE    16


static struct bufnode *bufnode_new(size_t size);
static void buffer_insert_buf(struct buffer *b, struct bufnode *node);
static struct bufnode *buffer_remove_buf(struct buffer *b);


void
buffer_init(struct buffer *b, size_t sizehint)
{
  b->head = b->tail = 0;
  b->nbuf = 0;

  b->sizehint = sizehint;
}


void
buffer_clear(struct buffer *b)
{
  struct bufnode *p;

  while (b->head) {
    p = buffer_remove_buf(b);
    free(p);
  }
}


static __inline__ void
buffer_insert_buf(struct buffer *b, struct bufnode *node)
{
  if (!b->tail)
    b->head = b->tail = node;
  else {
    b->tail->next = node;
    b->tail = node;
  }
  b->nbuf++;
}


static __inline__ struct bufnode *
buffer_remove_buf(struct buffer *b)
{
  struct bufnode *p;

  if (!b->head)
    return 0;

  p = b->head;
  if (b->head == b->tail)
    b->head = b->tail = 0;
  else
    b->head = p->next;
  b->nbuf--;
  return p;
}


static struct bufnode *
bufnode_new(size_t size)
{
  struct bufnode *p;
  p = malloc(sizeof(*p) + size + BACKPAD_SIZE + REARPAD_SIZE);
  if (!p) {
    errno = ENOMEM;           /* redundant, according to UNIX 98 */
    return 0;
  }

  p->size = size + BACKPAD_SIZE;
  p->begin = p->end = p->last = p->data + BACKPAD_SIZE;
  p->next = 0;
  return p;
}


struct bufnode *
buffer_grow_capacity(struct buffer *b, size_t size)
{
  struct bufnode *nptr = b->tail;
  size_t realsize;
  size_t remains;

  realsize = b->sizehint > size ? b->sizehint : size;

  if (!nptr) {
    nptr = bufnode_new(realsize);
    if (!nptr)
      return 0;
    buffer_insert_buf(b, nptr);
  }
  else {
    remains = BUFNODE_AVAIL(nptr);

    if (remains < size) {
      nptr = bufnode_new(realsize);
      if (!nptr)
        return 0;
      buffer_insert_buf(b, nptr);
    }
  }
  assert(BUFNODE_AVAIL(nptr) >= size);
  return nptr;
}


ssize_t
buffer_fill_fd(struct buffer *b, int fd, size_t size)
{
  /* Design consideration
   *
   * Which is better, to fill the last bufnode in B from FD, or
   * to create new bufnode and fill it from FD?
   *
   * Currently, I'll choose the last one. */
  struct bufnode *nptr;
  ssize_t readch;
  size_t remains;
  size_t total = 0;

  while (1) {
    if ((nptr = buffer_grow_capacity(b, 1)) == 0)
      return -1;

    /* Because of BACKPAD_SIZE, merely using NPTR->SIZE for REMAINS
     * is not good. */
    remains = BUFNODE_AVAIL(nptr);
    if (remains > size)
      remains = size;

    /* TODO: EPIPE handling?? */

    readch = read(fd, nptr->end, remains);
    if (readch == -1) {
      if (errno == EINTR || errno == EAGAIN)
        return total;
      else
        return -1;
    }
    else if (readch == 0) {            /* EOF */
      errno = 0;                       /* Is this necessary? */
      return total;
    }

    nptr->end += readch;
    total += readch;

    if (total >= size)
      break;
  }
  return total;
}


int
buffer_printf(struct buffer *b, const char *format, ...)
{
  struct bufnode *nptr;
  va_list ap;
  int len;

  va_start(ap, format);
  len = vsnprintf(NULL, 0, format, ap);
  va_end(ap);

  nptr = buffer_grow_capacity(b, len + 1);
  if (!nptr)
    return -1;

  va_start(ap, format);
  vsnprintf(nptr->end, len + 1, format, ap);
  va_end(ap);

  nptr->end += len;

  return len;
}

/*
 * TODO:
 *
 * bufpos buffer_find(struct buffer *buf, const void *seed, size_t size,
 *                    bufpos from);
 *
 * int buffer_find(struct buffer *buf,
 *                 const void *seed, size_t size,
 *                 bufpos *found,
 *                 const bufpos *from);
 */
int
buffer_find(struct buffer *buf, const void *seed, size_t size,
            bufpos *found, const bufpos *from_)
{
  struct bufnode *p, *q;
  char *c;
  bufpos from = { 0, 0 };

  if (!buf->head)
    return 0;

  if (from_)
    from = *from_;

  if (!from.node) {
    from.node = buf->head;
    from.ptr = from.node->begin;
  }

  p = from.node;
  q = p->next;
  if (q)
    memcpy(p->end, q->begin, size);
  c = memmem(from.ptr, p->end - from.ptr + size, seed, size);
  if (c) {
    if (found) {
      found->node = p;
      found->ptr = c;
    }
    return 1;
  }

  for (p = p->next; p != NULL; p = p->next) {
    q = p->next;

    if (q)
      memcpy(p->end, q->begin, size);

    c = memmem(p->begin, p->end - p->begin + size, seed, size);
    if (c) {
      if (found) {
        found->node = p;
        found->ptr = c;
      }
      return 1;
    }
  }

  return 0;
}


#if 0

bufpos
buffer_find(struct buffer *buf, const void *seed, size_t size,
            const bufpos *from)
{
  struct bufnode *p, *q;
  char *c;
  bufpos pos = { 0, 0 };

  assert(size < REARPAD_SIZE);

  if (!buf->head)
    return pos;

  if (from)
    pos = *from;

  if (!pos.node) {
    pos.node = buf->head;
    pos.ptr = pos.node->begin;
  }

  p = pos.node;
  q = p->next;
  if (q)
    memcpy(p->end, q->begin, size);
  c = memmem(pos.ptr, p->end - pos.ptr + size, seed, size);
  if (c) {
    pos.node = p;
    pos.ptr = c;
    return pos;
  }

  for (p = p->next; p != NULL; p = p->next) {
    q = p->next;

    if (q)
      memcpy(p->end, q->begin, size);

    c = memmem(p->begin, p->end - p->begin + size, seed, size);
    if (c) {
      pos.node = p;
      pos.ptr = c;
      return pos;
    }
  }

  pos.node = 0;
  pos.ptr = 0;
  return pos;
}


char *
buffer_find(struct buffer *buf, const void *seed, size_t size,
            struct bufnode **dst)
{
  struct bufnode *p;
  char *c;

  assert(size < REARPAD_SIZE);

  for (p = buf->head; p != NULL; p = p->next) {
    struct bufnode *q = p->next;

    if (q)
      memcpy(p->end, q->begin, size);

    c = memmem(p->begin, p->end - p->begin + size, seed, size);
    if (c) {
      *dst = p;
      return c;
    }
  }
  return 0;
}
#endif  /* 0 */


void
buffer_advance(struct buffer *b, struct bufnode *n, char *next, int offset)
{
  struct bufnode *p;

  if (!n)
    n = b->head;

  while (b->head && b->head != n) {
    p = buffer_remove_buf(b);
    free(p);
  }

  if (next) {
    assert(n->data <= next && next <= n->data + n->size);

    n->begin = next + offset;
    n->last = next + offset;
  }
  else {
    n->begin = n->end;
    n->last = n->end;
  }

  if (n->begin >= n->end) {     /* N is empty. */
    offset -= n->end - next;
    buffer_remove_buf(b);       /* delete N from the buffer, B */
    free(n);

    n = b->head;
    if (n) {
      n->begin += offset;
      n->last = n->begin;

      assert(n->begin < n->end);
    }
    else {
      assert(offset == 0);
    }
  }
}


// copy the contents from the beginning of the buffer to POS into the OBS
// as a growing object.
size_t
buffer_copy(struct xobs *obs, struct buffer *b, const bufpos *pos)
{
  struct bufnode *p;
  bufpos pos_;
  size_t total = 0;
  size_t sz;

  // assert(xobstack_object_size(obs) == 0);

  if (!pos) {
    pos_.node = b->tail;
    pos_.ptr = pos_.node->end;
    pos = &pos_;
  }

  for (p = b->head; p != NULL; p = p->next) {
    if (p != pos->node) {        /* copy the whole content of bufnode to OBS */
      sz = p->end - p->begin;
      xobs_grow(obs, p->begin, sz);
      total += sz;
    }
    else {
      sz = pos->ptr - p->end;
      xobs_grow(obs, p->begin, sz);
      total += sz;
      break;
    }
  }
  return total;
}

ssize_t
buffer_flush(struct buffer *b, struct bufnode *n, char *next, int fd)
{
  size_t remains;
  ssize_t written;
  ssize_t total = 0;

  struct bufnode *p = b->head;

  if (!n)
    n = b->tail;

  while ((p = b->head) != n && p != NULL) {
    remains = p->end - p->begin;
    if (remains > 0) {
      written = write(fd, p->begin, remains);
      if (written == -1) {
        if (errno == EAGAIN || errno == EINTR)
          return total;
        return -1;
      }
      else {
        total += written;
      }
    }
    buffer_remove_buf(b);
    free(p);
  }

  if (!p)
    return total;

  if (next && b->head == n)
    remains = next - n->begin;
  else
    remains = n->end - n->begin;

  written = write(fd, n->begin, remains);
  if (written == -1) {
    if (errno == EAGAIN || errno == EINTR)
      return 0;
    return -1;
  }
  else {
    // n->begin += written;
    buffer_advance(b, b->head, n->begin + written, 0);
    total += written;
  }
  return total;
}


// void
// buffer_advance(struct buffer *b, struct bufnode *n, char *next, int offset)
int
buffer_seek(struct buffer *b, off_t offset, int whence, bufpos *pos)
{
  // whence := (SEEK_SET|SEEK_CUR|SEEK_END)
  size_t sz;
  bufpos p;

  /* TODO: review the code.  I smell fishy. */
  assert(pos != 0);

  if (!b->head)
    return -1;

  switch (whence) {
  case SEEK_CUR:
    p = *pos;
    break;
  case SEEK_SET:
    p.node = b->head;
    p.ptr = p.node->begin;
    break;
  case SEEK_END:
    p.node = b->tail;
    p.ptr = p.node->end;
    break;
  default:
    abort();
  }

  while (p.node) {
    sz = p.node->end - p.ptr;

    if (offset > sz) {
      if (p.node->next) {
        p.node = p.node->next;
        p.ptr = p.node->begin;
        offset -= sz;
      }
      else {
        p.ptr = p.node->end;
        *pos = p;
        return offset;
      }
    }
    else {
      p.ptr += offset;
      if (p.ptr == p.node->end && p.node->next) {
        p.node = p.node->next;
        p.ptr = p.node->begin;
        *pos = p;
      }
      else
        *pos = p;
      return 0;
    }
  }
  return offset;
}


size_t
buffer_size(struct buffer *b, const bufpos *pos)
{
  size_t total = 0;
  bufpos p;
  struct bufnode *bp;

  if (!b->head)
    return 0;

  if (pos)
    p = *pos;
  else {
    p.node = b->head;
    p.ptr = p.node->begin;
  }

  total = p.node->end - p.ptr;

  for (bp = p.node->next; bp != NULL; bp = bp->next) {
    total += bp->end - bp->begin;
  }

  return total;
}


void
buffer_dump(FILE *fp, struct buffer *b)
{
  struct bufnode *p;

  fprintf(fp, "head: %p\n", b->head);
  fprintf(fp, "tail: %p\n", b->tail);
  fprintf(fp, "nbuf: %zd\n", b->nbuf);
  fprintf(fp, "size: %zd\n", b->sizehint);
  fprintf(fp, "back: %d\n", BACKPAD_SIZE);
  fprintf(fp, "rear: %d\n", REARPAD_SIZE);

  for (p = b->head; p != NULL; p = p->next) {
    fprintf(fp, "bufnode[%p]:\n", p);
    fprintf(fp, "   next: %p\n", p->next);
    fprintf(fp, "  begin: %p\n", p->begin);
    fprintf(fp, "   last: %p\n", p->last);
    fprintf(fp, "    end: %p\n", p->end);
    fprintf(fp, "   size: %zd\n", p->size);
    hexdump(fp, 1, -1, p->data, p->data + p->size + BACKPAD_SIZE);
  }
}


#if 0
void
buf_advance(struct buf *buf, char *spot)
{
  assert(spot >= buf->begin);
  assert(spot <= buf->end);     /* TODO: (spot < buf->end)? */

  if (spot == buf->begin)
    return;

  if (spot == buf->end) {       /* buf empty */
    buf->begin = buf->last = buf->end = buf->data;
  }
  else if (spot >= buf->data + (buf->size >> 2)) {
    size_t remains = buf->end - spot;
    memmove(buf->data, spot, remains);
    buf->data = buf->begin = buf->last;
    buf->end = buf->data + remains;
  }
  else {
    buf->begin = spot;
    if (buf->last < spot)
      buf->last = buf->begin;
  }
}


/*
 * Flush the buf contents from BUF->BEGIN to HERE.
 */
int
buf_flush_fd(struct buf *buf, int fd, char *here)
{
  size_t remains;
  ssize_t written;

  if (!here)
    here = buf->end;
  remains = here - buf->begin;

  written = write(fd, buf->begin, remains);
  if (written == -1) {
    if (errno == EAGAIN || errno == EINTR)
      return 0;
    else
      return -1;
  }
  else {
    buf_advance(buf, buf->begin + written);
    return written;
  }
}


/*
 *
 * Fill BUF by reading from FD.
 *
 * returns:
 *
 *   buf full (-1, errno = ENOMEM)
 *   read error (-1, errno = ERROR)
 *   EINTR (0, errno = EINTR)
 *   EOF  (0, errno = 0)
 *   read N byte(s) (read-bytes, errno = ??)
 */
int
buf_fill_fd(struct buf *buf, int fd)
{
  size_t remains = buf->data + buf->size - buf->end;
  ssize_t readch;

  /* TODO: EPIPE handling?? */

  buf->last = buf->end;

  if (remains == 0) {           /* BUF is full */
    errno = ENOMEM;
    return -1;                  /* return what?? */
  }

  readch = read(fd, buf->end, remains);
  if (readch == -1) {
    if (errno == EINTR || errno == EAGAIN)
      return 0;                 /* return what? */
    else
      return -1;                /* return what? error */
  }
  else if (readch == 0) {            /* EOF */
    errno = 0;
    return 0;                        /* return what? */
  }

  buf->end += readch;
  return readch;
}


static int
fdprintf(int fd, const char *format, ...)
{
  va_list ap;
  int len;
  char *buf;

  va_start(ap, format);
  len = vsnprintf(0, 0, format, ap);
  va_end(ap);

  buf = malloc(len + 1);
  va_start(ap, format);
  len = vsnprintf(buf, len + 1, format, ap);
  va_end(ap);

  write(fd, buf, len);
  free(buf);
  return len;
}


read_cb()
{
  rbuf rb;

  rb.fill();

  offset = rb.parse_request();
  if (offset == -1) {           /* not fully received for complete request */
    return;
  }

  if (can_handle_request()) { /* GET, HEAD, OPTIONS or DELETE */
    rb.advance(offset);
    call_request_handler();
  }
  else {                      /* POST or PUT */
    call_post_or_put_handler();
  }
}
#endif


#ifdef TEST_BUFFER
#include <unistd.h>
#include <fcntl.h>


int
set_nonblock(int fd)
{
  int flags;

  flags = fcntl(fd, F_GETFL);
  if (flags == -1) {
    fprintf(stderr, "fcntl failed: %s\n", strerror(errno));
    return -1;
  }
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    fprintf(stderr, "fcntl failed: %s\n", strerror(errno));
    return -1;
  }
  return 0;
}


int
main(int argc, char *argv[])
{
  struct buffer b;

  // socket
#if 0
  fd = open(argv[1], O_RDONLY | O_NONBLOCK);
  if (fd == -1) {
    fprintf(stderr, "open failed: %s\n", strerror(errno));
    return 1;
  }
#endif  /* 0 */

  setvbuf(stdout, NULL, _IONBF, 0);

  set_nonblock(0);

  /* Don't know why, but if I set STDOUT_FILENO to non-blocking in OSX,
   * the shell that execute this program logout prematurely. */
  //set_nonblock(1);

  buffer_init(&b, 64);
  buffer_fill_fd(&b, 0, -1);

  buffer_dump(stderr, &b);

  printf("========================\n");

  {
    bufpos found;

    {
      bufpos pos;

      buffer_seek(&b, 0, SEEK_SET, &pos);
      printf("pos.node = %p, pos.ptr = %p\n", pos.node, pos.ptr);
      buffer_seek(&b, 160, SEEK_CUR, &pos);
      printf("pos.node = %p, pos.ptr = %p\n", pos.node, pos.ptr);
      buffer_seek(&b, 10, SEEK_END, &pos);
      printf("pos.node = %p, pos.ptr = %p\n", pos.node, pos.ptr);
    }

    if (buffer_find(&b, "HD_OFFSET", 9, &found, NULL)) {
      printf("buffer_find(): found(node[%p], ptr[%p])\n",
             found.node, found.ptr);

      buffer_advance(&b, found.node, found.ptr, 9);
    }
  }

  {
    bufpos pos;
    buffer_seek(&b, 0, SEEK_END, &pos);
    printf("pos.node = %p, pos.ptr = %p\n", pos.node, pos.ptr);
    buffer_seek(&b, 1, SEEK_CUR, &pos);
    printf("pos.node = %p, pos.ptr = %p\n", pos.node, pos.ptr);
    buffer_seek(&b, 10, SEEK_SET, &pos);
    printf("pos.node = %p, pos.ptr = %p\n", pos.node, pos.ptr);
  }

  buffer_flush(&b, NULL, NULL, STDOUT_FILENO);

  // buffer_clear(&b);
  printf("========================\n");

  buffer_dump(stderr, &b);
  return 0;
}
#endif  /* TEST_BUFFER */
