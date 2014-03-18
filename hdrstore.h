#ifndef HDRSTORE_H__
#define HDRSTORE_H__

#include "uthash.h"
#include "xobstack.h"

struct header {
  const char *name;             /* field-name */
  const char *value;            /* field-value */
  UT_hash_handle hh;
};

struct hdrstore {
  struct xobs *pool;

  struct header *root;
  size_t nheaders;
};

void hdrstore_init(struct hdrstore *store, struct xobs *pool);
void hdrstore_free(struct hdrstore *store);
int hdrstore_set(struct hdrstore *store,
                 const char *key, const char *value);
struct header *hdrstore_get(struct hdrstore *store, const char *key);
int hdrstore_fill(struct hdrstore *store, struct xobs *opool);
char *hdrstore_load(struct hdrstore *store, char *buf, size_t size);


#endif /* HDRSTORE_H__ */
