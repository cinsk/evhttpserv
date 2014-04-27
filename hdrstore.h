#ifndef HDRSTORE_H__
#define HDRSTORE_H__

#include <stdio.h>
#include "uthash.h"
#include "xobstack.h"


typedef enum {
  HTTP_INIT = 0,                /* initialized for responding */
  HTTP_CONTINUE = 100,
  HTTP_SWITCH,
  HTTP_OK = 200,
  HTTP_CREATED,
  HTTP_ACCEPTED,
  HTTP_NAUTH_INFO,
  HTTP_NO_CONTENT,
  HTTP_RESET_CONTENT,
  HTTP_PARTIAL_CONTENT,
  HTTP_MULTIPLE_CHOICE = 300,
  HTTP_MOVED_PERMANENTLY,
  HTTP_MOVED_TEMPORARILY,
  HTTP_SET_OTHER,
  HTTP_NOT_MODIFIED,
  HTTP_USE_PROXY,
  HTTP_BAD_REQUEST = 400,
  HTTP_UNAUTHORIZED,
  HTTP_PAYMENT_REQUIRED,
  HTTP_FORBIDDEN,
  HTTP_NOT_FOUND,
  HTTP_METHOD_NOT_ALLOWED,
  HTTP_NOT_ACCEPTABLE,
  HTTP_PROXY_AUTH_REQUIRED,
  HTTP_REQUEST_TIMEOUT,
  HTTP_CONFLICT,
  HTTP_GONE,
  HTTP_LENGTH_REQUIRED,
  HTTP_PRECONDITION_FAILED,
  HTTP_REQ_ENTITY_TOO_LARGE,
  HTTP_REQ_URI_TOO_LARGE,
  HTTP_UNSUPPORTED_MEDIA_TYPE,
  HTTP_INTERNAL_SERVER_ERROR = 500,
  HTTP_NOT_IMPLEMENTED,
  HTTP_BAD_GATEWAY,
  HTTP_SERVICE_UNAVAILABLE,
  HTTP_GATEWAY_TIMEOUT,
  HTTP_VERSION_NOT_SUPPORTED,
} httpresponse_t;

struct header {
  const char *name;             /* field-name */
  const char *value;            /* field-value */

  struct header *params;
  void *data;                   /* TODO: Is this necessary? */

  UT_hash_handle hh;
};

struct hdrstore {
  struct xobs *pool;

  struct header *root;
  size_t nheaders;
};

void hdrstore_init(struct hdrstore *store, struct xobs *pool);

/*
 *
 * TODO: currently, it is possible to use STORE after calling
 *       hdrstore_free(store, ...).  Once hdrstore_free() is called,
 *       STORE is in clean state, like just after hdr_store_init() is
 *       called.  I need to think to provide additional interface,
 *       such as hdrstore_clear() for this.
 */
void hdrstore_free(struct hdrstore *store, int reset_only);


/*
 * Set the value (in VALUE) of the header name, KEY.
 *
 * If the KEY already exists, it will be overwritten.  Note that
 * in the process of overwriting, all parameters will be
 * erased and user data is set to NULL.
 *
 * To set the parameter of the header, you need to pass the pointer
 * to the header in DST.  Otherwise DST should stay NULL.
 *
 * It returns the pointer to the header struct on success, otherwise
 * it returns NULL.
 */
struct header *hdrstore_set(struct hdrstore *store,
                            const char *key, const char *value,
                            struct header *dst);

/*
 * Get the header struct by given name, KEY.
 *
 * If you want to retrive header struct for parameters, set SOURCE
 * to the pointer to the header.  Otherwise SOURCE should be NULL.
 *
 * See the example in the documentation of hdrstore_get().
 */
struct header *hdrstore_get_header(struct hdrstore *store, const char *key,
                                   struct header *source);

/*
 * Get the value of the header, NAME.
 *
 * If you want to retrive the parameter of the header, pass the
 * pointer to the header in SOURCE.  Otherwise, SOURCE should be NULL.
 *
 * If the given header NAME not found, it returns NULL.
 *
 * For example, to retrive charset parameter of 'Content-Type' header:
 *
 * const char *charset = 0;
 * struct header *p = hdrstore_get_header(store, "CONTENT-TYPE", 0);
 * if (p)
 *   charset = hdrstore_get(store, "CHARSET", p);
 */
static __inline__ const char *
hdrstore_get(struct hdrstore *store, const char *name,
             struct header *source)
{
  struct header *p = hdrstore_get_header(store, name, source);
  if (p)
    return p->value;
  return 0;
}


void hdrstore_del(struct hdrstore *store, const char *key);

/*
 * Fill OPOOL with HTTP response line and response headers.
 *
 * If STATUS_CODE is not positive, response line will not be
 * generated.  Generated contents are stored in OPOOL as a growing
 * object, so that you can get the pointer and size using xobs_base()
 * and xobs_object_size().
 *
 * This function returns the number of headers that it generated.
 *
 * In the current implementation, this function cares neither
 * parameters of the header nor user data.
 */
int hdrstore_fill(struct hdrstore *store, struct xobs *opool,
                  const char *version, int status_code,
                  int (*param_handler)(struct xobs *pool, struct header *p));

char *hdrstore_load(struct hdrstore *store, char *buf, size_t size, void *data);


/* Used for debugging, hdrstore_dump() dumps the contents of the STORE
 * to the FILE, FP.  If FP is NULL, stderr is used by default. */
int hdrstore_dump(struct hdrstore *store, FILE *fp);

const char *statuscode2str(int statuscode);

#endif /* HDRSTORE_H__ */
