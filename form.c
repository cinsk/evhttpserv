#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>

#include "form.h"
#include "xobstack.h"
#include "xerror.h"
#include "buffer.h"

#define CRLF    "\r\n"
#define CRLFLEN (sizeof(CRLF) - 1)

#define CRLF2    "\r\n\r\n"
#define CRLF2LEN (sizeof(CRLF2) - 1)

#define TMPFILE_MAX     PATH_MAX

#define MULTIPART_FORMDATA      "multipart/form-data"

#define MPS_RECV_HDRS   1
#define MPS_RECV_BODY   2

struct mpparser {
  const char *boundary;
  size_t boundary_size;
  size_t len;                   /* Content-Length */

  int state;

  struct form_entry *current;
  struct form_entry *entries;
};


static int mp_open(struct form *f, struct hdrstore *req);
static int mp_close(struct form *f);
static int mp_parse(struct form *f, struct buffer *b, int eos);
static int ue_open(struct form *f, struct hdrstore *req);
static int ue_close(struct form *f);
static int ue_parse(struct form *f, struct buffer *b, int eos);

struct fparser nil_parser = { 0, 0, 0 };
struct fparser fmp_parser = { mp_open, mp_close, mp_parse };
struct fparser fue_parser = { ue_open, ue_close, ue_parse };

#define form_parser_close(f)            ((f)->parser.close(f))
#define form_parser_parse(f, b, e)      ((f)->parser.parse((f), (b), (e)))


static __inline__ struct forment *form_get(struct form *f,
                                           const char *key);
static int form_set_string(struct form *f, const char *key, const char *value);

int
form_init(struct form *f)
{
  if (!xobs_init(&f->pool))
    return 0;

  f->root = NULL;
  f->parser = nil_parser;
  f->padata = NULL;

  return 1;
}


int
form_set_parser(struct form *f, struct hdrstore *req)
{
  const char *ctype = hdrstore_get(req, "CONTENT-TYPE", 0);

  if (!ctype)
    return 0;

  if (strcmp(ctype, "application/x-www-form-urlencoded") == 0)
    f->parser = fue_parser;
  else if (strcmp(ctype, "multipart/form-data") == 0) {
    /* TODO: what about multipart/mixed or others? */
    f->parser = fmp_parser;
  }
  else {
    xdebug(0, "cannot determine content-type(%s) for parsing form", ctype);
    return 0;
  }

  return f->parser.open(f, req);
}


int
form_parse(struct form *f, struct buffer *b, int eos)
{
  int ret;

  ret = form_parser_parse(f, b, eos);
  if (ret == 0)
    return 0;
  else if (ret == 1) {
    return form_parser_close(f);
  }
  else {
    /* TODO: how to handle the error? */
    return -1;
  }
}


void
form_free(struct form *f)
{
  /* TODO: release f.root */
  xobs_free(&f->pool, NULL);
}


static int
mp_open(struct form *f, struct hdrstore *req)
{
  return -1;
}

static int
mp_close(struct form *f)
{
  return -1;
}

static int
mp_parse(struct form *f, struct buffer *b, int eos)
{
  return -1;
}

static int
ue_open(struct form *f, struct hdrstore *req)
{
  return -1;
}

static int
ue_close(struct form *f)
{
  return -1;
}


static char *
url_decode(char *s)
{
  unsigned char *r, *w;
  unsigned escvalue;

  r = w = (unsigned char *)s;

  while (*r) {
    switch (*r) {
    case '%':
      if (isxdigit(*(r + 1))) {
        if (isxdigit(*(r + 2))) {
          if (*(r + 1) >= '0' && *(r + 1) <= '9')
            escvalue = *(r + 1) - '0';
          else
            escvalue = toupper(*(r + 1)) - 'A';

          escvalue <<= 4;

          if (*(r + 2) >= '0' && *(r + 2) <= '9')
            escvalue += *(r + 2) - '0';
          else
            escvalue = toupper(*(r + 2)) - 'A';

          *w++ = escvalue;
          r += 3;
        }
        else {
          *w++ = *(r + 1);
          r += 2;
        }
      }
      else
        r++;
      break;
    case '+':
      *w++ = ' ';
      r++;
      break;
    default:
      *w++ = *r++;
      break;
    }
  }
  *w = '\0';

  return s;
}


static int
ue_parse(struct form *f, struct buffer *b, int eos)
{
  char *src;
  char *name, *value, *saveptr;

  assert(eos == 1); /* we handle iff the complete input is available  */
  assert(xobs_object_size(&f->pool) == 0);

  buffer_copy(&f->pool, b, NULL);
  src = xobs_finish(&f->pool);
  buffer_truncate(b, NULL);

  name = strtok_r(src, "&", &saveptr);
  do {
    value = strchr(name, '=');
    if (value) {
      *value = '\0';
      value++;
      /* Now, NAME and VALUE points the beginning of the each content. */
      name = url_decode(name);
      value = url_decode(value);
      form_set_string(f, name, value);
    }
    else {
      /* name part is missing */
      value = url_decode(name);
      xdebug(0, "urlencoded value(%s) without name part detected", value);
    }
  } while ((name = strtok_r(NULL, "&", &saveptr)) != 0);

  return 1;
}


static __inline__ struct forment *
form_get(struct form *f, const char *key)
{
  struct forment *ent;

  HASH_FIND_STR(f->root, key, ent);
  return ent;
}


/* Note that form_set_string() do not copy the contents of KEY
 * and VALUE.  You may need to allocate some spaces if that's what you
 * need. */
static int
form_set_string(struct form *f,
                const char *key, const char *value)
{
  struct forment *ent = form_get(f, key);
  size_t klen = strlen(key);

  if (ent) {
    hdrstore_free(&ent->hdrs, 1); /* TODO: hdrstore_clear() */

    if (ent->type == FORM_STRING) {
      ent->v.str = value;
      if (!ent->v.str)
        return 0;
    }
    else
      abort();
    return 1;
  }

  ent = xobs_alloc(&f->pool, sizeof(*ent));
  if (!ent)
    return 0;

  hdrstore_init(&ent->hdrs, &f->pool);

  ent->type = FORM_STRING;
  ent->k = key;
  ent->v.str = value;

  HASH_ADD_KEYPTR(hh, f->root, ent->k, klen, ent);
  return 1;
}


void
form_dump(FILE *fp, struct form *f)
{
  struct forment *p, *tmp;

  HASH_ITER(hh, f->root, p, tmp) {
    fprintf(fp, "[%s] = type(%d) ", p->k, p->type);
    switch (p->type) {
    case FORM_STRING:
      fprintf(fp, "val: |%s|\n", p->v.str);
      break;
    case FORM_FILE:
      fprintf(fp, "val: |%s| (%d)\n", p->v.file.path, p->v.file.fd);
      break;
    default:
      fprintf(fp, "val: *NIL*\n");
      break;
    }
  }
}


#if 0
struct form_entry {
  char *k;
  int type;

  /* TODO: Content-type */
  union {
    char *str;
    /* TODO: do we need size for STR? */

    struct {
      char *path;
      int fd;
    } file;
  } v;

  struct hdrstore hdrs;
  UT_hash_handle hh;
};


const char *tmpfile_template __attribute__((weak)) = "/tmp/evhttp-XXXXXX";

static __inline__ int tmpfile(char tmpfile[TMPFILE_MAX]);

static __inline__ struct form_entry *form_entry_new(struct xobs *pool);
static int mpart_buffer2file(struct mpart *mp,
                             struct xobs *pool,
                             struct buffer *buf, bufpos *until);


/* TODO:
 *
 * multipart_init(&parser, boundary);
 *
 *
 * form_parse_buffer(parser, buffer, from, eob) returns:
 *
 * -1: on error
 *  0: still on parsing, need more data in buffer.
 *  1: done, successful.
 */

int
form_mpart_init(struct xobs *pool, struct mpart *mp, struct hdrstore *hdrs)
{
  const char *boundary;
  struct header *ctype;
  const char *lenstr;

  ctype = hdrstore_get_header(hdrs, "CONTENT-TYPE", 0);
  if (!ctype)
    return 0;
  boundary = hdrstore_get(hdrs, "BOUNDARY", ctype);
  if (!boundary)
    return 0;
  lenstr = hdrstore_get(hdrs, "CONTENT-LENGTH", 0);
  if (!lenstr)
    return 0;

  mp->boundary = boundary;
  mp->boundary_size = strlen(boundary);
  mp->len = atoi(lenstr);
  mp->state = MPS_RECV_HDRS;

  mp->current = 0;
  mp->entries = 0;

  return 1;
}


static __inline__ int
tmpfile(char tmpfile[TMPFILE_MAX])
{
  int fd;

#ifdef _GNU_SOURCE
  fd = mkostemp(tmpfile, O_APPEND);
#else
  fd = mkstemp(tmpfile);
  {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
      xdebug(errno, "fcntl(fd, F_GETFL) failed on tmpfile");
    else
      if (fcntl(fd, F_SETFL, flags | O_APPEND) == -1)
        xdebug(errno, "fcntl(fd, F_SETFL) failed for setting O_APPEND");
    /* TODO: what's next step if fcntl() failed? */
  }
#endif
  return fd;
}


int
form_mpart_parse(struct xobs *pool, struct mpart *mp,
                 struct buffer *buffer, /* bufpos *from, */ int eob)
{

  return 0;
}


#if 0
/* TODO: need to decide the return code of this function
 *
 * -1: on error
 *  0: need more input to finish
 *  1: done. */
int
form_mpart_parse(struct xobs *pool, struct mpart *mp,
                 struct buffer *buffer, /* bufpos *from, */ int eob)
{
  bufpos begin, found;
  size_t hdrsize;
  char *hdrs;
  struct header *hp;
  char tmpfile[TMPFILE_MAX];

  switch (mp->state) {
  case MPS_RECV_HDRS:
    begin = BUFPOS_BEGIN(buf, from);
    if (!begin.ptr)
      return 0;

    /* TODO: check for boundary, not CRLF2 */
    if (buffer_find(buffer, CRLF2, CRLF2LEN, &found, 0)) {
      /* TODO: check for Content-Length to finish */
      mp->current = form_entry_new(pool);

      buffer_seek(buffer, mp->boundary_size, SEEK_SET, &begin);

      buffer_copy_range(pool, buffer, &begin, &found);
      hdrsize = xobs_object_size(pool);
      hdrs = xobs_finish(pool);
      hdrstore_load(&mp->current->hdrs, hdrs, hdrsize, 0);

      {
        struct header *hp;
        hp = hdrstore_get_header(&mp->current->hdrs, "CONTENT-DISPOSITION", 0);

        if (hp) {
          char *key = hdrstore_get(&mp->current->hdrs, "NAME", hp);
          if (key) {
            mp->current->k = key;
          }
          else {
            /* TODO: huh? */
          }
        }
        else {
          /* TODO: huh? */
        }
      }

      hp = hdrstore_get_header(&mp->current->hdrs, "CONTENT-TYPE");
      if (hp) {
        int fd;

        /* TODO: For now, if there is a content-type header for the
         *       part, we just use FORM_FILE to save the contents.
         *       Later, we may need to parse content-type and use
         *       FORM_FILE if the contents is a media type. */
        mp->current->type = FORM_FILE;

        /* TODO: open the tmp file */

        strncpy(tmpfile, tmpfile_template, TMPFILE_MAX - 1);
        tmpfile[TMPFILE_MAX - 1] = '\0';

#ifdef _GNU_SOURCE
        fd = mkostemp(tmpfile, O_APPEND);
#else
        fd = mkstemp(tmpfile);
        {
          int flags = fcntl(fd, F_GETFL);
          if (flags == -1)
            xdebug(errno, "fcntl(fd, F_GETFL) failed on tmpfile");
          else
            if (fcntl(fd, F_SETFL, flags | O_APPEND) == -1)
              xdebug(errno, "fcntl(fd, F_SETFL) failed for setting O_APPEND");
          /* TODO: what's next step if fcntl() failed? */
        }
#endif
        if (fd == -1) {
          xerror(0, errno, "cannot create a temporary file");
          return -1;             /* TODO: return what? */
        }
        mp->current->v.file.fd = fd;
        mp->current->v.file.path = xobs_copy0(pool, tmpfile, strlen(tmpfile));
      }
      else {
        mp->current->type = FORM_STRING;
      }

      buffer_advance(buffer, found.node, found.ptr, CRLF2LEN);

      mp->state = MPS_RECV_BODY;
      /* TODO: reset BEGIN!!! */

      goto recv_body;
    }
    else {
      /* If we haven't received complete headers, leave the function. */
      if (eob)
        return -1;              /* TODO: what error code? */
      return 0;
    }

  case MPS_RECV_BODY:
  recv_body:
    assert(mp->current != 0);
    /* TODO: FORM_STRING handling? */
    if (mp->current->type == FORM_STRING) {
      if (buffer_find(buffer, mp->boundary, mp->boundary_size,
                      &found, 0)) {
        buffer_copy(pool, buffer, &found);
        mp->current->v.str = xobs_finish(pool);
        /* TODO: goto recv_hdrs state */
        return 0;
      }
      else {
        /* We haven't received the boundary. */
        return 0;
      }
    }
    else {
      if (buffer_find(buffer, mp->boundary, mp->boundary_size,
                      &found, 0)) {
        /* TODO: consume all from the beginning to FOUND */
        if (!mpart_buffer2file(mp, pool, buffer, found))
          return -1;
      }
      else {
        /* consume all from the beginning to (end - sizeof(boundary)) */
        size_t sz = buffer_size(buffer);
        if (sz > mp->boundary_size) {
          buffer_seek(buffer, sz - mp->boundary_size, SEEK_SET, &pos);
          mpart_buffer2file(mp, pool, buffer, pos);
        }
      }
    }

  default:
    break;
  }
}
#endif

int
form_value_type(struct form_entry *value)
{
  return value->type;
}


const char *
form_value_string(struct form_entry *ent)
{
  assert(ent->type == FORM_STRING);
  return ent->v.str;
}


const char *
form_value_file(struct form_entry *ent)
{
  assert(ent->type == FORM_FILE);
  return ent->v.file.path;
}


static __inline__ struct form_entry *
form_entry_new(struct xobs *pool)
{
  struct form_entry *p;
  p = xobs_alloc(pool, sizeof(*p));
  hdrstore_init(&p->hdrs, pool);

  p->k = 0;
  p->type = FORM_NIL;
  return p;
}


/* Note form_set_string_copy() only copies VALUE part, not KEY. */
int
form_set_string_copy(struct xobs *pool, struct form_entry **root,
                     const char *key, const char *value)
{
  char *v = xobs_copy0(pool, value, strlen(value));

  if (!v)
    return 0;
  return form_set_String_copy(pool, root, key, v);
}


int
form_set_file(struct xobs *pool, struct form_entry **root,
              const char *key, const char *filename, int fd)
{
  struct form_entry *ent = form_get(*root, key);
  size_t klen;

  if (ent) {
    hdrstore_free(&ent->hdrs, 1); /* TODO: hdrstore_clear() */

    if (ent->type == FORM_FILE) {
      ent->v.file.path = xobs_copy0(pool, filename, strlen(filename));
      if (!ent->v.file.path)
        return 0;
    }
    else
      abort();
    return 1;
  }

  ent = xobs_alloc(pool, sizeof(*ent));
  if (!ent)
    return 0;

  hdrstore_init(&ent->hdrs, pool);

  ent->type = FORM_FILE;
  klen = strlen(key);
  ent->k = xobs_copy0(pool, key, klen);
  if (!ent->k)
    return 0;

  ent->v.file.path = xobs_copy0(pool, filename, strlen(filename));
  if (!ent->v.file.path) {
    xobs_free(pool, ent->k);    /* not thread safe */
    return 0;
  }
  ent->v.file.fd = fd;

  HASH_ADD_KEYPTR(hh, *root, ent->k, klen, ent);
  return 1;
}


static int
mpart_buffer2string(struct mpart *mp,
                    struct xobs *pool,
                    struct buffer *buf, bufpos *until)
{
  /* TODO: consider url encoding? */

}


/*
 * Save the buffer contents [begin...UNTIL] to the file pointed in MP->current
 *
 * returns 1 on success, return zero on failure.
 */
static int
mpart_buffer2file(struct mpart *mp,
                  struct xobs *pool,
                  struct buffer *buf, bufpos *until)
{
  struct iovec *v, *p;
  bufpos end;
  size_t nnode = buffer_node_count(buf, 0);
  int saved_errno;

  v = p = xobs_alloc(pool, sizeof(*v) * nnode);
  if (!v) {
    saved_errno = errno;
    goto err;
  }

  end = BUFPOS_END(buf, until);

  BUFNODE_ITER(source, 0, pos, tmp) {
    if (pos.node != end.node) {
      p->iov_base = pos.ptr;
      p->iov_len = pos.node->end - pos.ptr;
    }
    else {
      p->iov_base = pos.ptr;
      p->iov_len = end.ptr - pos.ptr->begin;
    }
    p++;
  }

  written = writev(fd, v, p - v);
  if (written == -1) {
    saved_errno = errno;
    xerror(0, saved_errno, "writev(2) failed");
    goto err;
  }

  buffer_advance(buf, end.node, end.ptr, 0);
  xobs_free(pool, v);
  return 1;

 err:
  xobs_free(pool, v);
  errno = saved_errno;
  return 0;
}


/* TODO: we need to save the buffer contents between the
 * beginning-of-the-buffer to the POS (or end-of-the-buffer if POS is
 * NULL). */

/* Save the contents of SOURCE [between POS ... end-of-buffer]
 * into a file, clear the contents of SOURCE, and set the form
 * value as a file. */
int
form_import_buffer(struct xobs *pool, struct form_entry **root,
                   const char *key,
                   struct buffer *source, bufpos *from)
{
  char tmpfile[TMPFILE_MAX];
  int fd;
  bufpos pos, tmp;
  size_t nnodes;
  ssize_t written;
  struct iovec *v, *p;

  assert(xobs_object_size(pool) == 0);

  strncpy(tmpfile, tmpfile_template, TMPFILE_MAX - 1);
  tmpfile[TMPFILE_MAX - 1] = '\0';

#ifdef _GNU_SOURCE
  fd = mkostemp(tmpfile, O_APPEND);
#else
  fd = mkstemp(tmpfile);
  {
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
      xdebug(errno, "fcntl(fd, F_GETFL) failed on tmpfile");
    else
      if (fcntl(fd, F_SETFL, flags | O_APPEND) == -1)
        xdebug(errno, "fcntl(fd, F_SETFL) failed for setting O_APPEND");
    /* TODO: what's next step if fcntl() failed? */
  }
#endif

  if (fd == -1) {
    xdebug(errno, "cannot create uniq temp file");
    return 0;
  }

  nnodes = buffer_node_count(source, from);
  v = p = xobs_alloc(pool, sizeof(*v) * nnodes);
  if (!v)
    goto err;

  BUFNODE_ITER(source, from, pos, tmp) {
    p->iov_base = pos.ptr;
    p->iov_len = pos.node->end - pos.ptr;

    p++;
  }

  written = writev(fd, v, p - v);
  if (written == -1) {
    xdebug(errno, "writev(2) failed on tmpfile");
    goto err;
  }

  if (form_set_file(pool, root, key, tmpfile, fd)) {
    buffer_truncate(source, from);
    return 1;
  }

  /* fall through to error handler */

 err:
  unlink(tmpfile);
  close(fd);
  return 0;
}


void
form_free(struct xobs *pool, struct form_entry *root, int reset_only)
{
  struct form_entry *p, *tmp;

  HASH_ITER(hh, root, p, tmp) {
    if (p->type == FORM_FILE) {
      if (p->v.file.fd != -1) {
        close(p->v.file.fd);
        p->v.file.fd = -1;
      }
    }
  }

  HASH_CLEAR(hh, root);

  if (!reset_only)
    xobs_free(pool, root);
}


const char *
form_parse_boundary(struct xobs *pool, const char *content_type)
{
  const char *ctype = content_type;
  char *p;
  int skip;

  assert(xobs_object_size(pool) == 0);

  /*
    Content-Type   = "Content-Type" ":" media-type
    media-type     = type "/" subtype *( ";" parameter )
    type           = token
    subtype        = token

    e.g.) Content-Type: text/html; charset=ISO-8859-4
          Content-type: multipart/form-data, boundary=AaB03x

          TODO: rfc2616 uses 'Content-Type' whereas rfc1867 uses
                'Content-type'.
   */
  if (!ctype)
    return 0;

  // Since, we don't need to parse the exact Content-Type header, we just
  // check if the value starts with 'multipart/form-data', then
  // retrive the boundary string.

  skip = strspn(ctype, " ");
  if (strncmp(ctype + skip, MULTIPART_FORMDATA,
              sizeof(MULTIPART_FORMDATA) - 1) != 0)
    return 0;

  ctype += skip + sizeof(MULTIPART_FORMDATA) - 1;

  ctype += strspn(ctype, ";, \t");
  p = strstr(ctype, "boundary=");
  if (!p)
    return 0;

  ctype = p + sizeof("boundary=") - 1;
  skip = strcspn(ctype, "\n\r, ");

  xobs_grow(pool, ctype, skip);
  xobs_1grow(pool, '\r');
  xobs_1grow(pool, '\n');

  return xobs_finish(pool);
}

#endif  /* 0 */

#ifdef TEST_FORM
int debug_mode = 1;

int
main(int argc, char *argv[])
{
  bufpos pos;
  struct xobs pool;
  struct form_entry *form = 0;
  struct buffer b;
  struct hdrstore store;
  int eof;
  int readch;
  char *boundary;

  xobs_init(&pool);
  hdrstore_init(&store, &pool);
  setvbuf(stdout, NULL, _IONBF, 0);
  //set_nonblock(0);
  /* Don't know why, but if I set STDOUT_FILENO to non-blocking in OSX,
   * the shell that execute this program logout prematurely. */
  //set_nonblock(1);

  buffer_init(&b, 64);
#if 0
  buffer_printf(&b, "blah blah blah blah blah...");
  buffer_seek(&b, 0, SEEK_END, &pos);
#endif  /* 0 */

  //boundary = form_parse_boundary(&pool, argv[1]);
  //xdebug(0, "boundary: %s", boundary);

  while (1) {
    bufpos found;
    size_t reqsz;
    char *req;

    readch = buffer_fill_fd(&b, 0, -1, &eof);
    if (buffer_find(&b, CRLF2, CRLF2LEN, &found, NULL)) {
      buffer_copy(&pool, &b, &found);
      reqsz = xobs_object_size(&pool);
      req = xobs_finish(&pool);
      hdrstore_load(&store, req, reqsz, 0);
      buffer_advance(&b, found.node, found.ptr, CRLF2LEN);
      hdrstore_dump(&store, stderr);
      break;
    }
  }


  while (1) {
    readch = buffer_fill_fd(&b, 0, -1, &eof);
    if (readch == -1) {
      xerror(0, errno, "buffer_fill_fd() failed");
      break;
    }
    buffer_dump(stderr, &b);
    {
      bufpos endpos;
      buffer_seek(&b, 0, SEEK_END, &endpos);
      buffer_advance(&b, endpos.node, endpos.ptr, 0);
    }

    if (eof)
      break;
  }

#if 0
  form_set_string(&pool, &form, "name", "Seong-Kook Shin");
  form_set_string(&pool, &form, "email", "cinsky@hmail.com");

  form_dump(stderr, form);

  form_import_buffer(&pool, &form, "file", &b, &pos);
  form_dump(stderr, form);

  buffer_dump(stderr, &b);

#endif  /* 0 */
  hdrstore_free(&store, 1);
  buffer_clear(&b);
  // form_free(&pool, form, 1);
  xobs_free(&pool, NULL);
  return 0;
}
#endif  /* TEST_FORM */
