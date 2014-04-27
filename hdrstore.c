#include <assert.h>
#include <ctype.h>
#include <stdio.h>

#include "buffer.h"
#include "hdrstore.h"
#include "xerror.h"

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


static __inline__ char *strtoupper(char *s);
static void clear_params(struct header **root);

struct hhpair {
  const char *name;
  int (*handler)(struct hdrstore *store, const char *key, char *value,
                 void *data);
};

static __inline__ int hh_token_params(struct hdrstore *store, const char *key,
                                      char *value, void *data);
static int hh_content_disposition(struct hdrstore *store, const char *key,
                                  char *value, void *data);
static int hh_content_type(struct hdrstore *store, const char *key,
                           char *value, void *data);

struct hhpair hdr_handlers[] = {
  { "CONTENT-DISPOSITION", hh_content_disposition },
  { "CONTENT-TYPE", hh_content_type },
};


static int
hh_cmp(const void *l, const void *r)
{
  struct hhpair *lhs = (struct hhpair *)l;
  struct hhpair *rhs = (struct hhpair *)r;
  return strcmp(lhs->name, rhs->name);
}


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

  assert(xobs_object_size(store->pool) == 0);

  store->root = 0;
  store->nheaders = 0;
}


void
hdrstore_free(struct hdrstore *store, int reset_only)
{
  struct header *hp, *tmp;

  HASH_ITER(hh, store->root, hp, tmp) {
    if (hp->params) {
      clear_params(&hp->params);
    }
    // hp->params = 0;
    HASH_DEL(store->root, hp);
  }
  // HASH_CLEAR(hh, store->root);

  store->root = 0;
  store->nheaders = 0;

  if (!reset_only)
    xobs_free(store->pool, store->root);
}


static __inline__ char *
strtoupper(char *s)
{
  char *p = s;

  if (!p)
    return 0;

  while (*p) {
    *p = toupper(*p);
    p++;
  }
  return s;
}


static void
clear_params(struct header **root)
{
  struct header *hp, *tmp;

  // xdebug(0, "clear_params: root(%p, %s)", *root, (*root)->name);
  HASH_ITER(hh, *root, hp, tmp) {
    // xdebug(0, "clear_params: hp(%p, %s)", hp, hp->name);
    if (hp->params)
      clear_params(&hp->params);
    HASH_DEL(*root, hp);
    // HASH_DEL((*root)->params, hp);
  }
}


void
hdrstore_del(struct hdrstore *store, const char *key)
{
  struct header *ent;

  HASH_FIND_STR(store->root, key, ent);
  if (ent) {
    if (ent->params)
      clear_params(&ent->params);
    HASH_DEL(store->root, ent);
  }
}


struct header *
hdrstore_set(struct hdrstore *store,
             const char *key, const char *value,
             struct header *dst)
{
  struct header *ent;
  char *name;

  /* TODO: value should transform to all-lowercases or all-uppercases */

  name = strtoupper(xobs_copy0(store->pool, key, strlen(key)));

  if (dst)
    HASH_FIND_STR(dst->params, key, ent);
  else
    HASH_FIND_STR(store->root, key, ent);

  if (ent) {
    xobs_free(store->pool, name);

    ent->value = strtoupper(xobs_copy0(store->pool, value, strlen(value)));

    if (ent->params) {
      clear_params(&ent->params);
      //HASH_DEL(ent->params, ent->params);
      ent->params = 0;
    }
    ent->data = 0;
    return ent;
  }

  ent = xobs_alloc(store->pool, sizeof(*ent));
  if (!ent)
    return 0;
  ent->name = name;
  ent->value = xobs_copy0(store->pool, value, strlen(value));
  ent->params = 0;
  ent->data = 0;

  if (dst)
    HASH_ADD_KEYPTR(hh, dst->params, ent->name, strlen(ent->name), ent);
  else
    HASH_ADD_KEYPTR(hh, store->root, ent->name, strlen(ent->name), ent);
  return ent;
}


struct header *
hdrstore_get_header(struct hdrstore *store, const char *key,
                    struct header *source)
{
  struct header *h;

#ifndef NDEBUG
  {
    unsigned char *s = (unsigned char *)key;
    while (*s) {
      if (isalpha(*s) && !isupper(*s))
        abort();
      s++;
    }
  }
#endif

  /* TODO: value should transform to all-lowercases or all-uppercases */
  if (source)
    HASH_FIND_STR(source->params, key, h);
  else
    HASH_FIND_STR(store->root, key, h);

  return h;
}


int
hdrstore_fill(struct hdrstore *store, struct xobs *opool,
              const char *version, int status_code,
              int (*param_handler)(struct xobs *pool, struct header *p))
{
  struct header *hp, *tmp;
  int count = 0;
  int noerr = 1;

  assert(xobs_object_size(opool) == 0);

  if (status_code > 0)
    xobs_sprintf(opool, "%s %u %s\r\n", version, status_code,
                 statuscode2str(status_code));

  HASH_ITER(hh, store->root, hp, tmp) {
    if (hp->params && param_handler) {
      noerr = param_handler(opool, hp);
      if (noerr)
        continue;
      else
        break;
    }

    if (!hp->value)
      continue;

    xobs_grow(opool, hp->name, strlen(hp->name));
    xobs_grow(opool, ": ", 2);
    xobs_grow(opool, hp->value, strlen(hp->value));
    xobs_grow(opool, "\r\n", 2);
    count++;
  }
  if (noerr) {
    xobs_grow(opool, "\r\n", 2);
    return count;
  }
  else {
    xobs_free(opool, xobs_finish(opool));
    return 0;
  }
}


static void
hdrstore_dump_(struct header *root, int lev, FILE *fp)
{
  struct header *hp, *tmp;

  HASH_ITER(hh, root, hp, tmp) {
    if (hp->value)
      fprintf(fp, "%*s[%s]: |%s|\n", lev * 4, "", hp->name, hp->value);
    else
      fprintf(fp, "%*s[%s]: *NIL*\n", lev * 4, "", hp->name);

    if (hp->data)
      fprintf(fp, "%*sDATA: %p\n", (lev + 1) * 4, "", hp->data);

    if (hp->params)
      hdrstore_dump_(hp->params, lev + 1, fp);
  }
}


int
hdrstore_dump(struct hdrstore *store, FILE *fp)
{
  struct xobs pool;
  char *p;
  int count;

  if (!fp)
    fp = stderr;

  xobs_init(&pool);
  count = hdrstore_fill(store, &pool, "HTTP/fake", 200, 0);
  p = xobs_finish(&pool);
  fprintf(fp, "%s\n--\n", p);
  xobs_free(&pool, NULL);

  hdrstore_dump_(store->root, 0, fp);
  return count;
}


static int
hh_content_type(struct hdrstore *store, const char *key,
                char *value, void *data)
{
  // Content-Type: text/html; charset=ISO-8859-4
  // Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr2nav90pCAt7fppL
  return hh_token_params(store, key, value, data);
}


static int
hh_content_disposition(struct hdrstore *store, const char *key,
                       char *value, void *data)
{
  // Content-Disposition: form-data; name="upload"; filename="1 pixel.png"
  return hh_token_params(store, key, value, data);
}

static __inline__ int
hh_token_params(struct hdrstore *store, const char *key,
                char *value, void *data)
{
  // Content-Disposition: form-data; name="upload"; filename="1 pixel.png"
  // Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr2nav90pCAt7fppL
  char *disp;
  char *name, *val;
  int pos;
  int quoted = 0;

  struct header *param;

  disp = (value += strspn(value, " "));
  pos = strcspn(value, "; ");

  if (pos == 0)
    goto err;

  value += pos;
  if (*value == '\0') {         /* no additional parameters */
    param = hdrstore_set(store, key, disp, 0);
    return 1;
  }
  else {
    *value++ = '\0';
    param = hdrstore_set(store, key, disp, 0);
  }

  while (1) {
    name = value + strspn(value, " ;");
    if (name == 0 || *name == '\0')
      break;
    pos = strcspn(name, "=\"");
    if (pos == 0)
      goto err;
    value = name + pos;
    *value++ = '\0';

    quoted = (*value == '"') ? 1 : 0;
    if (quoted)
      value++;                    /* skip the first \" */

    val = value;

    {
      char *dst = val;
      int escaping = 0;

      if (quoted) {             /* value is a quoted-string */
        while (*value) {
          switch (*value) {
          case '\\':
            escaping = 1;
            break;
          case '"':
            if (escaping) {
              *dst++ = '"';
              escaping = 0;
            }
            else
              goto value_done;
            break;
          default:
            *dst++ = *value;
            break;
          }
          value++;
        }
      }
      else {                    /* value is not a quoted-string */
        dst += strcspn(dst, " ;");
        value = dst;
      }

    value_done:
      *dst = '\0';

      /* Now, NAME holds the name, and VAL holds the value. */
      hdrstore_set(store, name, val, param);

      if (*value == '\0')
        break;
      value++;
    }
  }
  return 1;
 err:
  xdebug(0, "Content-Disposition parse error: %s", value);
  hdrstore_del(store, key);
  return 0;
}


char *
hdrstore_load(struct hdrstore *store, char *buf, size_t size, void *data)
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

    strtoupper(name);

    {
      static size_t npairs = sizeof(hdr_handlers) / sizeof(hdr_handlers[0]);
      struct hhpair src;
      struct hhpair *found;
      src.name = name;

      found = bsearch(&src, hdr_handlers, npairs, sizeof(hdr_handlers[0]),
                      hh_cmp);

      if (found) {
#ifndef NDEBUG
        char *save = strdup(value);
        if (found->handler(store, name, value, data) == 0) {
          xdebug(0, "parsing %s failed: %s", name, save);
        }
        free(save);
#else
        found->handler(store, name, value, data);
#endif
      }
      else
        hdrstore_set(store, name, value, 0);
    }
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
int debug_mode = 1;

int
main(void)
{
  struct xobs pool;
  struct hdrstore hstore;
  char source[] = "Date: Mon, 17 Mar 2014 14:55:45 GMT\r\n\
Server: Apache\r\n\
Last-Modified: Thu, 13 Feb 2014 02:53:35 GMT\r\n\
ETag \"cf0002-2f79-4f240cba109c0\"\r\n\
Content-Disposition: form-data; name=\"up\"l\\\"oad\"; filename=\"1 pixel.png\"\r\n\
Accept-Ranges: bytes\r\n\
Content-Length: 12153\r\n\
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryr2nav90pCAt7fppL\r\n\r\nBODY";

  xobs_init(&pool);
  hdrstore_init(&hstore, &pool);

  hdrstore_load(&hstore, source, sizeof(source), 0);
#if 0
  hdrstore_set(&hstore, "Host", "www.cinsk.org", 0);
  hdrstore_set(&hstore, "Accept", "*/*", 0);
  hdrstore_set(&hstore, "Transfer-Encoding", "chunked", 0);
#endif
  {
    struct header *p = hdrstore_set(&hstore, "Blah", "Bloh", 0);
    p->data = "asdf";
    hdrstore_set(&hstore, "sub1", "val1", p);

    if (1) {
      struct header *q = hdrstore_set(&hstore, "sub2", "val2", p);
      q->data = "qwer";

      if (1) {
        hdrstore_set(&hstore, "subsub1", "valval1", q);
        // hdrstore_set(&hstore, "sub2", "newval2", p);
      }
    }
    hdrstore_set(&hstore, "sub3", "val3", p);
  }

  hdrstore_dump(&hstore, stderr);
  hdrstore_free(&hstore, 1);
  xobs_free(&pool, NULL);

  fprintf(stderr, "--\n");

  fwrite(source, 1, sizeof(source), stderr);

  //getchar();
  return 0;
}
#endif  /* TEST_HDRS */
