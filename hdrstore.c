#include <assert.h>
#include <stdio.h>

#include "buffer.h"
#include "hdrstore.h"

struct statuscode_pair {
  int code;
  char *desc;
} statuscodes[] = {
  { 100, "Continue" },
  { 101, "Switching Protocols" },
  { 200, "OK" },
  { 201, "Created" },
  { 202, "Accepted" },
  { 203, "Non-Authoritative Information" },
  { 204, "No Content" },
  { 205, "Reset Content" },
  { 206, "Partial Content" },
  { 300, "Multiple Choices" },
  { 301, "Moved Permanently" },
  { 302, "Moved Temporarily" },
  { 303, "See Other" },
  { 304, "Not Modified" },
  { 305, "Use Proxy" },
  { 400, "Bad Request" },
  { 401, "Unauthorized" },
  { 402, "Payment Required" },
  { 403, "Forbidden" },
  { 404, "Not Found" },
  { 405, "Method Not Allowed" },
  { 406, "Not Acceptable" },
  { 407, "Proxy Authentication Required" },
  { 408, "Request Time-out" },
  { 409, "Conflict" },
  { 410, "Gone" },
  { 411, "Length Required" },
  { 412, "Precondition Failed" },
  { 413, "Request Entity Too Large" },
  { 414, "Request-URI Too Large" },
  { 415, "Unsupported Media Type" },
  { 500, "Internal Server Error" },
  { 501, "Not Implemented" },
  { 502, "Bad Gateway" },
  { 503, "Service Unavailable" },
  { 504, "Gateway Time-out" },
  { 505, "HTTP Version not supported" },
};


static int
statuscode_cmp(const void *l, const void *r)
{
  struct statuscode_pair *lhs = (struct statuscode_pair *)l;
  struct statuscode_pair *rhs = (struct statuscode_pair *)r;
  return lhs->code - rhs->code;
}


const char *
statuscode2str(int statuscode)
{
  static size_t npairs = sizeof(statuscodes) / sizeof(statuscodes[0]);
  struct statuscode_pair *r;

  r = bsearch(&statuscode, statuscodes,
              npairs, sizeof(statuscodes[0]), statuscode_cmp);
  if (r)
    return r->desc;
  return "UNKNOWN";
}

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
hdrstore_free(struct hdrstore *store, int reset_only)
{
  store->root = 0;
  store->nheaders = 0;

  if (!reset_only)
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


const char *
hdrstore_get(struct hdrstore *store, const char *key)
{
  struct header *h;
  HASH_FIND_STR(store->root, key, h);
  if (h)
    return h->value;
  else
    return NULL;
}


int
hdrstore_fill(struct hdrstore *store, struct xobs *opool,
              const char *version, int status_code)
{
  struct header *hp, *tmp;
  int count = 0;

  if (status_code > 0)
    xobs_sprintf(opool, "%s %u %s\r\n", version, status_code,
                 statuscode2str(status_code));

  HASH_ITER(hh, store->root, hp, tmp) {
    if (!hp->value)
      continue;
    xobs_grow(opool, hp->name, strlen(hp->name));
    xobs_grow(opool, ": ", 2);
    xobs_grow(opool, hp->value, strlen(hp->value));
    xobs_grow(opool, "\r\n", 2);
    count++;
  }
  xobs_grow(opool, "\r\n", 2);
  return count;
}


int
hdrstore_dump(struct hdrstore *store, FILE *fp)
{
  struct xobs pool;
  char *p;
  int count;

  count = hdrstore_fill(store, &pool, "HTTP/fake", 200);
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


#if 0
int
hdrstore_load(struct hdrstore *store, struct buffer *buf, bufpos *end)
{
  if (buf->head == end.node) {
    /* we're lucky! we've request line and request headers in the same bufnode. */

  }
  else {

  }
}
#endif  /* 0 */

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
  hdrstore_free(&hstore, 0);
  xobs_free(&pool, NULL);

  fprintf(stderr, "--\n");

  fwrite(source, 1, sizeof(source), stderr);

  getchar();
  return 0;
}
#endif  /* TEST_HDRS */
