#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>

#include "form.h"
#include "xerror.h"
#include "uthash.h"
#include "buffer.h"

#define TMPFILE_MAX     PATH_MAX


struct form_entry {
  char *k;
  int type;

  union {
    char *str;

    struct {
      char *path;
      int fd;
    } file;
  } v;

  UT_hash_handle hh;
};


const char *tmpfile_template __attribute__((weak)) = "/tmp/evhttp-XXXXXX";


int
form_value_type(struct form_entry *value)
{
  return value->type;
}


struct form_entry *
form_get(struct form_entry *root, const char *key)
{
  struct form_entry *ent;

  HASH_FIND_STR(root, key, ent);
  return ent;
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


int
form_set_string(struct xobs *pool, struct form_entry **root,
                const char *key, const char *value)
{
  struct form_entry *ent = form_get(*root, key);
  size_t klen;

  if (ent) {
    if (ent->type == FORM_STRING) {
      ent->v.str = xobs_copy0(pool, value, strlen(value));
      if (!ent->v.str)
        return 0;
    }
    else
      abort();
    return 1;
  }

  ent = xobs_alloc(pool, sizeof(*ent));
  if (!ent)
    return 0;

  ent->type = FORM_STRING;
  klen = strlen(key);
  ent->k = xobs_copy0(pool, key, klen);
  if (!ent->k)
    return 0;
  ent->v.str = xobs_copy0(pool, value, strlen(value));
  if (!ent->v.str) {
    xobs_free(pool, ent->k);    /* not thread safe */
    return 0;
  }

  HASH_ADD_KEYPTR(hh, *root, ent->k, klen, ent);
  return 1;
}


int
form_set_file(struct xobs *pool, struct form_entry **root,
              const char *key, const char *filename, int fd)
{
  struct form_entry *ent = form_get(*root, key);
  size_t klen;

  if (ent) {
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


void
form_dump(FILE *fp, struct form_entry *form)
{
  struct form_entry *p, *tmp;

  HASH_ITER(hh, form, p, tmp) {
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


#ifdef TEST_FORM
int debug_mode = 1;

int
main(int argc, char *argv[])
{
  bufpos pos;
  struct xobs pool;
  struct form_entry *form = 0;
  struct buffer b;

  xobs_init(&pool);

  setvbuf(stdout, NULL, _IONBF, 0);
  //set_nonblock(0);
  /* Don't know why, but if I set STDOUT_FILENO to non-blocking in OSX,
   * the shell that execute this program logout prematurely. */
  //set_nonblock(1);

  buffer_init(&b, 64);
  buffer_printf(&b, "blah blah blah blah blah...");
  buffer_seek(&b, 0, SEEK_END, &pos);
  buffer_fill_fd(&b, 0, -1, 0);

  form_set_string(&pool, &form, "name", "Seong-Kook Shin");
  form_set_string(&pool, &form, "email", "cinsky@hmail.com");

  form_dump(stderr, form);

  form_import_buffer(&pool, &form, "file", &b, &pos);
  form_dump(stderr, form);

  buffer_dump(stderr, &b);

  buffer_clear(&b);
  form_free(&pool, form, 1);
  xobs_free(&pool, NULL);
  return 0;
}
#endif  /* TEST_FORM */
