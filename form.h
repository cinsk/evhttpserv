#ifndef FORM_H__
#define FORM_H__

#include "buffer.h"
#include "xobstack.h"

#define FORM_NIL        0
#define FORM_STRING     1
#define FORM_FILE       2

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

#endif /* FORM_H__ */
