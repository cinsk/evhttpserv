/*
 * libev-based HTTP server implementation
 * Copyright (C) 2014  Seong-Kook Shin <cinsky@gmail.com>
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#define _GNU_SOURCE
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>             /* for memmem(3) */
#include <stdlib.h>
#include <errno.h>

#include <unistd.h>

#include "xerror.h"
#include "buffer.h"
#include "hexdump.h"
#include "xobstack.h"

/* BACKPAD will be used for storing chunk size when TE is 'chunked' */
#define BACKPAD_SIZE    16

/* Read RFC2046 for the maximum length of the multipart boundary (around 70) */
#define REARPAD_SIZE    80


static struct bufnode *bufnode_new(size_t size);
static void buffer_insert_buf(struct buffer *b, struct bufnode *node);
static struct bufnode *buffer_remove_buf(struct buffer *b);


void
buffer_init(struct buffer *b, size_t sizehint)
{
  b->head = b->tail = 0;
  b->nbuf = 0;
  b->nbytes = 0;

  b->sizehint = sizehint;
}


void
buffer_clear(struct buffer *b)
{
  struct bufnode *p;

  xdebug(0, "buffer_clear");
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


/*
 * Remove the first bufnode from the buffer, B.
 */
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
  b->nbytes -= (p->end - p->begin);

  return p;
}


/*
 * Create new BUFNODE struct.
 *
 * The returned BUFNODE can hold at most SIZE characters.
 *
 * Internally, each BUFNODE has a room for other operations.  Each
 * BUFNODE has two rooms, called 'backpad' and 'rearpad'.  Thus, the
 * actual size of DATA member will be SIZE + BACKPAD_SIZE +
 * REARPAD_SIZE.
 */
static struct bufnode *
bufnode_new(size_t size)
{
  struct bufnode *p;

  xdebug(0, "bufnode_new(%zu): %zu", size,
         sizeof(*p) + size + BACKPAD_SIZE + REARPAD_SIZE);

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


int
buffer_load(struct buffer *b, const void *data, size_t size)
{
  /* Design consideration
   *
   * Which is better, to fill the last bufnode in B from FD, or
   * to create new bufnode and fill it from FD?
   *
   * Currently, I'll choose the last one. */
  struct bufnode *nptr;
  size_t remains;
  const void *cur = data;
  const void *end = data + size;
  bufpos snapshot;

  /* TODO: what happen if B is empty? */
  buffer_seek(b, 0, SEEK_END, &snapshot);

  while (cur < end) {
    if ((nptr = buffer_grow_capacity(b, 1)) == 0) {
      buffer_truncate(b, &snapshot);
      return -1;
    }

    /* Because of BACKPAD_SIZE, merely using NPTR->SIZE for REMAINS
     * is not good. */
    remains = BUFNODE_AVAIL(nptr);
    if (cur + remains > end)
      remains = end - cur;

    memcpy(nptr->end, cur, remains);
    cur += remains;

    nptr->end += remains;
    b->nbytes += remains;
  }

  return 0;
}


ssize_t
buffer_fill_fd(struct buffer *b, int fd, size_t size, int *eof)
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
      *eof = 0;
      if (errno == EINTR || errno == EAGAIN)
        return total;
      else
        return -1;
    }
    else if (readch == 0) {            /* EOF */
      if (eof)
        *eof = 1;
      return total;
    }

    nptr->end += readch;
    total += readch;
    b->nbytes += readch;

    if (total >= size)
      break;
  }
  *eof = 0;
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
  b->nbytes += len;

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
    if (from.node)
      from.ptr = from.node->begin;
    else
      from.ptr = 0;
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


bufpos
buffer_span(struct buffer *buf, bufpos *from, const char *accept)
{

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


#if 0
int
buffer_advance(struct buffer *b, struct bufnode *n, char *next, int offset)
{
  struct bufnode *p;
  size_t bsz = b->nbytes;

  if (!n)
    n = b->head;

  while (b->head && b->head != n) {
    p = buffer_remove_buf(b);
    free(p);
  }

  if (next) {
    assert(n->data <= next && next <= n->data + n->size);

    b->nbytes -= (next - n->begin) + offset;

    n->begin = next + offset;
    n->last = next + offset;
  }
  else {
    b->nbytes -= n->end - n->begin;

    n->begin = n->end;
    n->last = n->end;
  }

  /* TODO: something related to offset below looks buggy!! */

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

  /* TODO: return the number of byte(s) it passed */
}
#else
int
buffer_advance(struct buffer *b, struct bufnode *n, char *next, int offset)
{
  struct bufnode *p;
  size_t bsz = b->nbytes;

  if (!n)
    n = b->head;
  if (!next)
    next = n->end;

  while (b->head && b->head != n) {
    p = buffer_remove_buf(b);
    free(p);
  }

  assert(n->data <= next && next <= n->data + n->size);
  b->nbytes -= (next - n->begin);
  n->begin = next;
  n->last = next;

  while (n && offset > 0) {
    size_t remains = n->end - n->begin;
    if (remains > offset) {
      n->begin += offset;
      b->nbytes -= offset;
      break;
    }
    else {
      buffer_remove_buf(b);
      free(n);
      offset -= remains;
      n = b->head;
    }
  }
  return bsz - b->nbytes;
}
#endif


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
      sz = pos->ptr - p->begin;
      xobs_grow(obs, p->begin, sz);
      total += sz;
      break;
    }
  }
  return total;
}


size_t
buffer_copy_range(struct xobs *obs, struct buffer *b,
                  const bufpos *from, const bufpos *to)
{
  bufpos begin, end;
  size_t total = 0;
  size_t sz;

  // assert(xobstack_object_size(obs) == 0);

  if (from)
    begin = *from;
  else {
    begin.node = b->head;
    if (begin.node)
      begin.ptr = begin.node->begin;
    else
      return 0;
  }

  if (to)
    end = *to;
  else {
    end.node = b->tail;
    if (end.node)
      end.ptr = end.node->end;
    else
      return 0;
  }

  while (bufpos_isempty(&begin)) {
    if (begin.node != end.node) {
      /* copy the whole contents of BEGIN to OBS */
      sz = begin.node->end - begin.ptr;
      xobs_grow(obs, begin.ptr, sz);
      total += sz;
    }
    else {
      sz = end.ptr - begin.ptr;
      xobs_grow(obs, begin.ptr, sz);
      total += sz;
      break;
    }

    begin.node = begin.node->next;
    begin.ptr = begin.node->begin;
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
        if (errno == EAGAIN || errno == EINTR) {
          return total;
        }
        return -1;
      }
      else {
        total += written;
      }
    }
    if (written < remains) {    /* on non-blocking FD */
      buffer_advance(b, p, p->begin + written, 0);
      return total;
    }
    else
      buffer_remove_buf(b);
    free(p);
  }

  if (!p) {
    /* If following assertion failed, it means that N points invalid
     * bufnode. */
    assert(n == 0);
    return total;
  }

  assert(n == p);

  if (next)
    remains = next - p->begin;
  else
    remains = p->end - p->begin;

  written = write(fd, p->begin, remains);
  if (written == -1) {
    if (errno == EAGAIN || errno == EINTR)
      return total;
    return -1;
  }
  else {
    // n->begin += written;
    buffer_advance(b, b->head, p->begin + written, 0);
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


int
buffer_truncate(struct buffer *b, bufpos *from)
{
  bufpos pos;
  struct bufnode *p, *q;
  size_t ncount = 0;

  if (from)
    pos = *from;
  else {
    pos.node = b->head;
    if (!pos.node)
      return 0;
    pos.ptr = b->head->begin;
  }

  ncount = pos.node->end - pos.ptr;
  pos.node->end = pos.ptr;

  p = pos.node->next;
  while (p) {
    q = p->next;
    ncount += p->end - p->begin;
    free(p);
    p = q;
  }

  pos.node->next = 0;
  b->nbytes -= ncount;
  return ncount;
}


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
  int eof;

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
  buffer_fill_fd(&b, 0, -1, &eof);

  buffer_dump(stderr, &b);

  printf("size: %zd\n", buffer_size(&b, 0));
  printf("========================\n");

  {
    bufpos found1, found2;
    struct xobs po;
    size_t copied;
    void *p;

    xobs_init(&po);
    if (buffer_find(&b, "buffer_init", 11, &found1, NULL)) {
      if (buffer_find(&b, "buffer_remove_buf", 17, &found2, &found1)) {
        fprintf(stderr, "COPIED-START ===========\n");
        copied = buffer_copy_range(&po, &b, &found1, &found2);
        xerror(0, 0, "copied: %zd byte(s)", copied);
        p = xobs_finish(&po);
        hexdump(stderr, 1, 0, p, p + copied);
        fprintf(stderr, "COPIED-END ===========\n");
      }
    }
    xobs_free(&po, 0);
  }

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

  printf("========================\n");
  buffer_flush(&b, NULL, NULL, STDOUT_FILENO);

  // buffer_clear(&b);
  printf("========================\n");

  //buffer_dump(stderr, &b);
  return 0;
}
#endif  /* TEST_BUFFER */
