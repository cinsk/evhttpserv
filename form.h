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
#ifndef FORM_H__
#define FORM_H__

#include "buffer.h"
#include "xobstack.h"
#include "uthash.h"
#include "hdrstore.h"

/* This indirect using of extern "C" { ... } makes Emacs happy */
#ifndef BEGIN_C_DECLS
# ifdef __cplusplus
#  define BEGIN_C_DECLS extern "C" {
#  define END_C_DECLS   }
# else
#  define BEGIN_C_DECLS
#  define END_C_DECLS
# endif
#endif /* BEGIN_C_DECLS */

BEGIN_C_DECLS

#define FP_URLENCODED   1
#define FP_MULTIPART    2

#define FORMENT_NIL        0
#define FORMENT_STRING     1
#define FORMENT_FILE       2

#define FORMENT_TYPE(fe)        ((fe)->type)
#define FORMENT_KEY(fe)         ((fe)->k)
#define FORMENT_AS_STRING(fe)   ((fe)->v.str)
#define FORMENT_AS_FILE(fe)     ((fe)->v.file)

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

END_C_DECLS

#endif /* FORM_H__ */
