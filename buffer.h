#ifndef BUFFER_H__
#define BUFFER_H__

#include <string.h>

struct xobs;                    /* forward declaration */

struct bufnode {
  char *begin, *end;
  char *last;
  size_t size;
  struct bufnode *next;
  char data[0];
};

typedef struct {
  struct bufnode *node;
  char *ptr;
} bufpos;

struct buffer {
  struct bufnode *head;
  struct bufnode *tail;

  size_t nbuf;
  size_t nbytes;
  size_t sizehint;
};

#define BUFNODE_AVAIL(n)        ((n)->data + (n)->size - (n)->end)

#define BUFPOS_BEGIN(buf, src)  ({ bufpos p;    \
      if (src)                                  \
        p = *(src);                             \
      else {                                    \
        p.node = (buf)->head;                   \
        p.ptr = (p.node) ? p.node->begin : 0;   \
      }                                         \
      p; })

#define BUFPOS_END(buf, src)    ({ bufpos p;    \
      if (src)                                  \
        p = *(src);                             \
      else {                                    \
        p.node = (buf)->tail;                   \
        p.ptr = (p.node) ? p.node->end : 0;     \
      }                                         \
      p; })




void buffer_init(struct buffer *b, size_t sizehint);
void buffer_clear(struct buffer *b);


/*
 * Append data from FD with SIZE byte(s) in the buffer, B.
 *
 * It returns the number of actual read byte(s).  On EOF, it returns
 * zero with 'errno' cleared.  It is possible that this function read
 * less than SIZE byte(s).
 *
 * When FD is marked non-blocking and there is nothing to read
 * currently, it returns zero with 'errno' set to EAGAIN.  If it is
 * signaled, it returns zero with 'errno' set to EINTR.  Otherwise (on
 * error) it returns -1.
 */
ssize_t buffer_fill_fd(struct buffer *b, int fd, size_t size, int *eof);


/*
 * Find SEED with SIZE byte(s) from the buffer contents.
 *
 * FROM should points the starting position for the searching.
 * FROM as NULL means the beginning of the buffer.
 *
 * This function returns nonzero if SEED was found.  Otherwise it
 * returns zero.
 *
 * If FOUND is non-null, it will be set to the location of the first SEED
 * in the buffer on success.
 */
int buffer_find(struct buffer *buf, const void *seed, size_t size,
                bufpos *found, const bufpos *from);
//char *buffer_find(struct buffer *buf, const void *seed, size_t size, struct bufnode **dst);


/*
 * Advance the buffer position so that the beginning of the buffer
 * is set to NEXT of N.  All previous bufnode before N will be released.
 *
 * If offset is nonzero, the buffer position will advance in addition
 * of OFFSET bytes.  In other words, the beginning of the contents is
 * set to NEXT + OFFSET.  This is especially useful when you want to
 * advance the buffer from the returned pointer of buffer_find() with
 * the size of the seed.   For example:
 *
 * char *p = buffer_find(buffer, seed, seed_size, &nextnode);
 * ...
 * buffer_advance(buffer, nextnode, p, seed_size);
 */
int buffer_advance(struct buffer *b, struct bufnode *n,
                   char *next, int offset);


/*
 * Get the position of the buffer like lseek(2).
 *
 * The target location is stored in POS.
 *
 * On error, buffer_seek() returns -1.  On success, it returns the
 * remaining bytes that it would advance if the buffer has more
 * contents.  For example, if the total number of bytes in the buffer
 * is 40, and you called buffer_seek(b, 50, SEEK_SET), then it will
 * return 10.
 */
int buffer_seek(struct buffer *b, off_t offset, int whence, bufpos *pos);


/*
 * Flush (write) the buffer contents into the file FD.
 *
 * It will write the contents from the beginning of the buffer to the
 * point NEXT in the bufnode N.  If N is NULL, the last BUFNODE in
 * the B is used as a default.  If NEXT is NULL, it is assumes that
 * the end of the N.  To write the whole contents of B into FD, you
 * may pass NULL for both of N and NEXT.
 *
 * It may call write(2) multiple times if there are more than one
 * bufnode in B.
 *
 * It returns the total number of byte(s) it wrote on success.  If FD
 * is marked as non-blocking, this function may return without writing
 * fully.  In this case, this function returns the number of byte(s)
 * it wrote so far, and 'errno' will be set to EAGAIN.  (Likewise, if
 * it signaled, it returns the number of byte(s) it wrote, then
 * 'errno' will be set to EINTR.)
 *
 * On error (except neither EAGAIN nor EINTR), this function returns
 * -1, and 'errno' is set appropriately by write(2).  Note that if
 * there occurs an error after succesfully wrote some contents, there
 * is no way to get the number of byte(s) it wrote so far.
 */
ssize_t buffer_flush(struct buffer *b, struct bufnode *n, char *next, int fd);

/*
 * Convenient function to fill the buffer with printf(3) like formatted
 * string.
 *
 * Note that this function does not append '\0'.
 *
 * It returns the number of bytes that it append on success.
 * Otherwise, it returns -1.
 */
int buffer_printf(struct buffer *b, const char *format, ...)
  __attribute__((format (printf, 2, 3)));


/* Copy the contents of the buffer between the beginning of the buffer
 * to POS into OBS as a growing object.  If POS is NULL, it is
 * considered as the end of the buffer.
 *
 * It returns the number of byte(s) copied. */
size_t buffer_copy(struct xobs *obs, struct buffer *b, const bufpos *pos);

int buffer_load(struct buffer *b, const void *data, size_t size);

/*
 * Copy buffer contents in range between FROM and TO to the OBS.
 *
 * If FROM is NULL, the beginning of the buffer is used.  If TO is
 * NULL, the end of the buffer is used.
 *
 * This function returns the number of byte(s) it copied.  Note that
 * the copied contents are stored in OBS as a growing object.
 */
size_t buffer_copy_range(struct xobs *obs, struct buffer *b,
                         const bufpos *from, const bufpos *to);

#define buffer_isempty(b)       ((b)->head == 0 || \
                                 ((b)->head == (b)->tail && \
                                  (b)->tail->begin >= (b)->tail->end))

#define bufpos_isempty(p)       ((p)->node == 0)

/* Return the number of availabe byte(s) that a buffer can hold without
 * allocating additional bufnode. */
#define buffer_roomsize(b)      ((b)->tail ? BUFNODE_AVAIL((b)->tail) : 0)

/*
 * Add more bufnode to the buffer B if the current bufnodes can't hold
 * additional SIZE byte(s).
 */
struct bufnode *buffer_grow_capacity(struct buffer *b, size_t size);


/*
 * truncate B from POS to the end of the buffer.
 *
 * Returns the number of byte(s) that discarded.
 *
 * If POS is null, it is considered as the beginning of the buffer.
 */
int buffer_truncate(struct buffer *b, bufpos *pos);

#define buffer_1add_fast(b, ch)        (*(b)->tail->end++ = ch)

static __inline__ int
buffer_1add(struct buffer *b, char ch)
{
  struct bufnode *nptr = buffer_grow_capacity(b, 1);
  if (!nptr)
    return 0;
  *nptr->end++ = ch;
  return 1;
}


static __inline__ ssize_t
buffer_fill(struct buffer *b, const void *data, size_t size)
{
  struct bufnode *nptr = buffer_grow_capacity(b, size);

  if (!nptr)
    return -1;

  nptr->last = nptr->end;
  memcpy(nptr->end, data, size);
  nptr->end += size;

  return size;
}


/*
 * Iterate all bufnode of BUF, starting from POS.  If POS is NULL, it
 * is considered as the first node of BUF.  ITER should be a l-value
 * of bufnode type.  On each iteration, ITER.node will points the
 * BUFNODE and ITER.ptr will be set to the beginning of the BUFNODE,
 * except on the first iteration; ITER.ptr will be set to either
 * POS->ptr or the beginning of the BUF.
 *
 * See buffer_size() for the example usage of BUFNODE_ITER().
 */
#define BUFNODE_ITER(buf, pos, iter, tmp)                               \
  for (((pos) ? ((tmp = *(pos)), 0) :                                   \
        (tmp.node = buf->head,                                          \
         tmp.ptr = ((tmp.node) ? tmp.node->begin : 0), 0)),             \
         iter = tmp;                                                    \
       tmp.node != NULL;                                                \
       ((tmp.node = tmp.node->next),                                    \
        (tmp.ptr = (tmp.node) ? tmp.node->begin : 0)), iter = tmp)


/*
 * Return the number of byte(s) that the buffer B holds.
 *
 * If POS is non-null, the counting starts from POS.
 */
static __inline__ size_t
buffer_size(struct buffer *b, const bufpos *pos)
{
  size_t total = 0;
  bufpos p, tmp;

  BUFNODE_ITER(b, pos, p, tmp) {
    total += p.node->end - p.ptr;
  }

  return total;
}

/*
 * Return the total number of bytes in the buffer, B.
 *
 * This runs at O(1), and is faster than using buffer_size(),
 */
#define BUFFER_SIZE(b)  ((b)->nbytes)

static __inline__ size_t
buffer_node_count(struct buffer *b, bufpos *from)
{
  bufpos pos, tmp;
  size_t ncount = 0;

#if 1
  BUFNODE_ITER(b, from, pos, tmp) {
    (void)pos.node;
    ncount++;
  }
#else
  if (from)
    pos = *from;
  else {
    pos.node = b->head;
    if (!pos.node)
      return 0;
    pos.ptr = b->head->begin;
  }

  for (ncount = 0; pos.node != NULL; pos.node = pos.node->next, ncount++)
    ;
#endif

  return ncount;
}

#include <stdio.h>
void buffer_dump(FILE *fp, struct buffer *b);

#if 0
/* TODO */

// return the number of byte(s) in B from POS to end of the buffer.
// If POS is NULL, the beginning of the buffer is used.
size_t buffer_size(struct buffer *b, const bufpos *pos);

ssize_t buffer_flush(struct buffer *b, int fd);
buffer_getc();

char *buffer_gets(); // next buffer operation may invalidate the returned ptr

#endif  /* 0 */

#endif /* BUFFER_H__ */
