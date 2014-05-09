#ifndef FORM_H__
#define FORM_H__

#include "buffer.h"
#include "xobstack.h"
#include "uthash.h"
#include "hdrstore.h"

#define FP_URLENCODED   1
#define FP_MULTIPART    2

#define FORM_NIL        0
#define FORM_STRING     1
#define FORM_FILE       2

struct mpparser;

struct forment {
  const char *k;
  int type;

  /* TODO: Content-type */
  union {
    const char *str;
    /* TODO: do we need size for STR? */

    struct {
      const char *path;
      int fd;
    } file;
  } v;

  struct hdrstore hdrs;
  UT_hash_handle hh;
};

struct form;

struct fparser {
  /* returns zero on success,  -1 on error */
  int (*open)(struct form *f, struct hdrstore *req);
  /* returns zero on success,  -1 on error */
  int (*close)(struct form *f);
  /* returns 1 if the parsing is done, returns 0
   * if it need more input, returns -1 on error. */
  int (*parse)(struct form *f, struct buffer *b, int eos);
};

struct form {
  struct forment *root;

  struct fparser parser;
  void *padata;
  struct xobs pool;
};

int form_init(struct form *f);

/* return 0 on success, -1 on failure */
int form_set_parser(struct form *f, struct hdrstore *req);

int form_parse(struct form *f, struct buffer *b, int eos);
void form_free(struct form *f);
void form_dump(FILE *fp, struct form *f);

#if 0
struct form_entry;

struct form_entry *form_get(struct form_entry *root, const char *key);
int form_value_type(struct form_entry *value);
const char *form_value_string(struct form_entry *ent);
const char *form_value_file(struct form_entry *ent);

int form_set_string(struct xobs *pool, struct form_entry **root,
                    const char *key, const char *value);
int form_set_file(struct xobs *pool, struct form_entry **root,
                  const char *key, const char *filename, int fd);
int form_import_buffer(struct xobs *pool, struct form_entry **root,
                       const char *key,
                       struct buffer *source, bufpos *from);
#endif  /* 0 */

#endif /* FORM_H__ */
