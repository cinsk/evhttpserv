#include <assert.h>
#include <stdio.h>

#include "hdrstore.h"

void
hdrstore_init(struct hdrstore *store, struct xobs *pool)
{
  store->pool = pool;

  fprintf(stderr, "objectsize: %d\n", xobs_object_size(store->pool));
  assert(xobs_object_size(store->pool) == 0);

  store->root = 0;
  store->nheaders = 0;
}


void
hdrstore_free(struct hdrstore *store)
{
  xobs_free(store->pool, store->root);
}


int
hdrstore_set(struct hdrstore *store,
             const char *key, const char *value)
{
  struct header *ent;

  HASH_FIND_STR(store->root, key, ent);
  if (ent) {
    ent->value = xobs_copy0(store->pool, value, strlen(value));
    return 1;
  }

  ent = xobs_alloc(store->pool, sizeof(*ent));
  if (!ent)
    return 0;
  ent->name = key;
  ent->value = value;

  HASH_ADD_KEYPTR(hh, store->root, ent->name, strlen(ent->name), ent);
  return 1;
}


struct header *
hdrstore_get(struct hdrstore *store, const char *key)
{
  struct header *h;
  HASH_FIND_STR(store->root, key, h);
  return h;
}


int
hdrstore_fill(struct hdrstore *store, struct xobs *opool)
{
  struct header *hp, *tmp;
  int count = 0;

  HASH_ITER(hh, store->root, hp, tmp) {
    if (!hp->value)
      continue;
    xobs_grow(opool, hp->name, strlen(hp->name));
    xobs_grow(opool, ": ", 2);
    xobs_grow(opool, hp->value, strlen(hp->value));
    xobs_grow(opool, "\r\n", 2);
    count++;
  }
  return count;
}


int
hdrstore_dump(struct hdrstore *store, FILE *fp)
{
  struct xobs pool;
  char *p;
  int count;

  xobs_init(&pool);
  count = hdrstore_fill(store, &pool);
  p = xobs_finish(&pool);
  fprintf(fp, "%s", p);
  xobs_free(&pool, NULL);
  return count;
}


char *
hdrstore_load(struct hdrstore *store, char *buf, size_t size)
{
  char *line, *saveptr;
  char *name, *value;

  if (!buf)
    return 0;

  buf[size - 1] = '\0';

  line = strtok_r(buf, "\r\n", &saveptr);

  do {
    name = line + strspn(line, " \t");

    value = strchr(name, ':');
    if (!value) {                   /* TODO: parse error? */
      continue;
    }
    *value = '\0';
    value++;
    value += strspn(value, " \t");

    hdrstore_set(store, name, value);
  } while ((line = strtok_r(NULL, "\r\n", &saveptr)) != 0);

  return buf + size;
}


#ifdef TEST_HDRS
int
main(void)
{
  struct xobs pool;
  struct hdrstore hstore;
  char source[] = "Date: Mon, 17 Mar 2014 14:55:45 GMT\r\n\
Server: Apache\r\n\
Last-Modified: Thu, 13 Feb 2014 02:53:35 GMT\r\n\
ETag \"cf0002-2f79-4f240cba109c0\"\r\n\
Accept-Ranges: bytes\r\n\
Content-Length: 12153\r\n\
Content-Type: text/html\r\n\r\nBODY";

  xobs_init(&pool);
  hdrstore_init(&hstore, &pool);

  hdrstore_load(&hstore, source, sizeof(source));
  //hdrstore_set(&hstore, "Host", "www.cinsk.org");
  //hdrstore_set(&hstore, "Accept", "*/*");
  //hdrstore_set(&hstore, "Transfer-Encoding", "chunked");

  hdrstore_dump(&hstore, stderr);
  hdrstore_free(&hstore);
  xobs_free(&pool, NULL);

  fprintf(stderr, "--\n");

  fwrite(source, 1, sizeof(source), stderr);

  getchar();
  return 0;
}
#endif  /* TEST_HDRS */
